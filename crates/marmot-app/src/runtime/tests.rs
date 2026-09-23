use cgka_traits::TransportAdapterError;
use cgka_traits::transport_adapter::{
    TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportEndpointRejectionCategory, TransportPublishFailure,
};

use super::subscriptions::{chat_list_mute_expiries, message_kind_filter_allows};
use super::*;
use crate::AppMessageProjection;
use crate::publish_endpoints_from_bootstrap;
use crate::tests::{ScriptedPushRelayClient, remember_test_member_inbox};

#[tokio::test]
async fn worker_lookup_skips_reconcile() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    let account = app.account_home().create_account("alice").unwrap();
    let runtime = app.runtime();
    let manager = runtime.accounts();
    let (commands, received) = mpsc::channel(1);
    let (shutdown, stopped) = oneshot::channel();
    manager.workers.lock().await.insert(
        account.account_id_hex.clone(),
        ManagedAccountWorker {
            ready: true,
            handle: tokio::spawn(async move {
                let _ = stopped.await;
            }),
            commands: commands.clone(),
            media_admission: Arc::new(Semaphore::new(MEDIA_COMMAND_QUEUE_LIMIT)),
            shutdown,
        },
    );
    // A lifecycle transaction for another account must not hold up this worker.
    let transaction = manager.worker_transactions.lock().await;
    let found = timeout(Duration::from_millis(100), async {
        assert!(
            manager
                .worker_commands("alice")
                .await?
                .same_channel(&commands)
        );
        assert!(
            manager
                .worker_commands_for_setup("alice")
                .await?
                .same_channel(&commands)
        );
        manager.media_worker_commands("alice").await
    })
    .await
    .unwrap()
    .unwrap();
    assert!(found.0.same_channel(&commands));
    drop(found);

    for ready in [false, true] {
        manager
            .workers
            .lock()
            .await
            .get_mut(&account.account_id_hex)
            .unwrap()
            .ready = ready;
        manager.set_account_tearing_down(&account.account_id_hex, ready);
        assert!(
            timeout(Duration::from_millis(10), manager.worker_commands("alice"))
                .await
                .is_err()
        );
    }
    manager.set_account_tearing_down(&account.account_id_hex, false);
    drop(received);
    assert!(
        timeout(Duration::from_millis(10), manager.worker_commands("alice"))
            .await
            .is_err()
    );
    let worker = manager
        .workers
        .lock()
        .await
        .remove(&account.account_id_hex)
        .unwrap();
    assert!(
        timeout(Duration::from_millis(10), manager.worker_commands("alice"))
            .await
            .is_err()
    );
    drop(transaction);
    worker.shutdown().await;
    runtime.shutdown().await;
}

#[tokio::test]
async fn message_journey_early_errors() {
    let root = tempfile::tempdir().unwrap();
    let runtime = MarmotApp::with_relays(root.path(), vec![]).runtime();
    let group = GroupId::new(vec![1; 16]);

    for expected_failures in [2, 4] {
        assert!(
            runtime
                .send_message("missing", &group, vec![])
                .await
                .is_err()
        );
        assert!(
            runtime
                .accounts
                .send_app_event(
                    "missing",
                    &group,
                    AppMessageIntent::Chat {
                        content: String::new()
                    },
                )
                .await
                .is_err()
        );
        let snapshot = runtime.app_performance_snapshot();
        assert_eq!(
            snapshot.outbound_message_response.attempts,
            expected_failures
        );
        assert_eq!(
            snapshot.outbound_message_response.failures,
            expected_failures
        );
        assert_eq!(snapshot.outbound_message_response.successes, 0);
        assert_eq!(snapshot.outbound_message_queue_wait.attempts, 0);

        // Repeat after shutdown to cover lifecycle rejection before account lookup.
        runtime.shutdown().await;
    }
}

#[tokio::test]
async fn cast_poll_vote_rejects_unknown_closed_and_invalid_selections_before_send() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    let account = app.account_home().create_account("alice").unwrap();
    let runtime = app.runtime();
    let group = GroupId::new(vec![1; 16]);
    let group_id_hex = hex::encode(group.as_slice());

    let error = runtime
        .cast_poll_vote(&account.label, &group, "11".repeat(32), vec!["0".into()])
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidAppMessagePayload(message) if message.contains("valid locally accepted poll")),
        "unexpected error: {error:?}"
    );

    let now = crate::unix_now_seconds();
    let record_poll = |message_id_hex: String, created_at: u64, ends_at: u64| {
        app.record_account_app_event(
            &account.label,
            &AppMessageProjection {
                authority: None,
                message_id_hex,
                source_message_id_hex: None,
                direction: "received".into(),
                group_id_hex: group_id_hex.clone(),
                sender: "22".repeat(32),
                plaintext: "Drink?".into(),
                kind: cgka_traits::MARMOT_APP_EVENT_KIND_POLL,
                tags: cgka_traits::poll_tags(
                    created_at,
                    "Drink?",
                    &["Tea".into(), "Coffee".into()],
                    cgka_traits::PollType::SingleChoice,
                    Some(ends_at),
                )
                .unwrap(),
                source_epoch: Some(1),
                retention: None,
                recorded_at: Some(created_at),
                origin_commit_id: None,
                moderation_grant: false,
            },
        )
        .unwrap();
    };

    let closed_poll_id = "33".repeat(32);
    record_poll(
        closed_poll_id.clone(),
        now.saturating_sub(60),
        now.saturating_sub(1),
    );
    let error = runtime
        .cast_poll_vote(&account.label, &group, closed_poll_id, vec!["0".into()])
        .await
        .unwrap_err();
    assert!(
        matches!(&error, AppError::InvalidAppMessagePayload(message) if message == "poll is closed"),
        "unexpected error: {error:?}"
    );

    let open_poll_id = "44".repeat(32);
    record_poll(open_poll_id.clone(), now, now.saturating_add(60));
    let error = runtime
        .cast_poll_vote(&account.label, &group, open_poll_id, vec!["missing".into()])
        .await
        .unwrap_err();
    assert!(matches!(error, AppError::InvalidAppMessagePayload(_)));

    let sibling_poll_id = "66".repeat(32);
    record_poll(sibling_poll_id.clone(), now, now.saturating_add(60));
    app.record_account_app_event(
        &account.label,
        &AppMessageProjection {
            authority: None,
            message_id_hex: "77".repeat(32),
            source_message_id_hex: None,
            direction: "received".into(),
            group_id_hex: group_id_hex.clone(),
            sender: account.account_id_hex.clone(),
            plaintext: String::new(),
            kind: cgka_traits::MARMOT_APP_EVENT_KIND_POLL_RESPONSE,
            tags: cgka_traits::poll_response_tags(&sibling_poll_id, &["1".into()]).unwrap(),
            source_epoch: Some(1),
            retention: None,
            recorded_at: Some(now.saturating_add(1)),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();
    let projected = runtime
        .timeline_message(&account.label, &group_id_hex, &sibling_poll_id)
        .unwrap()
        .unwrap()
        .poll
        .unwrap();
    assert_eq!(projected.local_selection, ["1"]);

    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn poll_creation_uses_conversation_kind_and_existing_polls_remain_votable() {
    let root = tempfile::tempdir().unwrap();
    let home = marmot_account::AccountHome::open(root.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let carol = home.create_account("carol").unwrap();
    let dave = home.create_account("dave").unwrap();
    let erin = home.create_account("erin").unwrap();
    let app = MarmotApp::with_relay(root.path(), "wss://polls.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    for member in [&bob, &carol, &dave, &erin] {
        remember_test_member_inbox(&app, &member.account_id_hex, "wss://polls.example");
        app.client(&member.label)
            .await
            .unwrap()
            .publish_key_package()
            .await
            .unwrap();
    }
    let (direct, named_pair, group) = {
        let mut alice = app.client("alice").await.unwrap();
        let direct = alice
            .create_group("", &[bob.account_id_hex.as_str()])
            .await
            .unwrap();
        let named_pair = alice
            .create_group("Design", &[erin.account_id_hex.as_str()])
            .await
            .unwrap();
        let group = alice
            .create_group(
                "Poll group",
                &[carol.account_id_hex.as_str(), dave.account_id_hex.as_str()],
            )
            .await
            .unwrap();
        (direct, named_pair, group)
    };

    let runtime = app.runtime();
    let direct_error = runtime
        .create_poll(
            "alice",
            &direct,
            "Tea?".into(),
            vec!["Yes".into(), "No".into()],
            cgka_traits::PollType::SingleChoice,
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(&direct_error, AppError::InvalidAppMessagePayload(message) if message.contains("group conversation")),
        "unexpected error: {direct_error:?}"
    );
    let named_pair_poll = runtime
        .create_poll(
            "alice",
            &named_pair,
            "Tea?".into(),
            vec!["Yes".into(), "No".into()],
            cgka_traits::PollType::SingleChoice,
            None,
        )
        .await
        .unwrap();
    assert_eq!(named_pair_poll.message_ids.len(), 1);
    let direct_poll_id = "88".repeat(32);
    let now = crate::unix_now_seconds();
    app.record_account_app_event(
        "alice",
        &AppMessageProjection {
            authority: None,
            message_id_hex: direct_poll_id.clone(),
            source_message_id_hex: None,
            direction: "received".into(),
            group_id_hex: hex::encode(direct.as_slice()),
            sender: bob.account_id_hex.clone(),
            plaintext: "Tea?".into(),
            kind: cgka_traits::MARMOT_APP_EVENT_KIND_POLL,
            tags: cgka_traits::poll_tags(
                now,
                "Tea?",
                &["Yes".into(), "No".into()],
                cgka_traits::PollType::SingleChoice,
                None,
            )
            .unwrap(),
            source_epoch: Some(0),
            retention: None,
            recorded_at: Some(now),
            origin_commit_id: None,
            moderation_grant: false,
        },
    )
    .unwrap();
    let direct_vote = runtime
        .cast_poll_vote("alice", &direct, direct_poll_id, vec!["0".into()])
        .await
        .unwrap();
    assert_eq!(direct_vote.message_ids.len(), 1);

    let poll = runtime
        .create_poll(
            "alice",
            &group,
            "Tea?".into(),
            vec!["Yes".into(), "No".into()],
            cgka_traits::PollType::SingleChoice,
            None,
        )
        .await
        .unwrap();
    let poll_id = poll.message_ids[0].clone();
    runtime
        .cast_poll_vote("alice", &group, poll_id.clone(), vec!["1".into()])
        .await
        .unwrap();

    let projected = runtime
        .timeline_message("alice", &hex::encode(group.as_slice()), &poll_id)
        .unwrap()
        .unwrap()
        .poll
        .unwrap();
    assert_eq!(projected.local_selection, ["1"]);
    assert_eq!(projected.participants, 1);
    assert_eq!(projected.options[0].votes, 0);
    assert_eq!(projected.options[1].votes, 1);

    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn missing_diagnostics_executor_keeps_exporters_stopped() {
    let root = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(root.path(), vec![]);
    let runtime = app.runtime();
    runtime.start().await.unwrap();
    runtime.shared.diagnostics_executor.lock().unwrap().take();

    // A broken startup ordering must disable optional delivery, not panic in a host setter.
    runtime.set_usage_diagnostics_consent(true).unwrap();
    assert!(runtime.shared.product_worker.lock().unwrap().is_none());

    #[cfg(feature = "otlp-export")]
    {
        let config = RelayTelemetryExportConfig {
            authorization_bearer_token: Some("test-token".into()),
            resource: Some(crate::RelayTelemetryResource {
                service_version: "1.0".into(),
                service_instance_id: app.telemetry_install_id().unwrap(),
                deployment_environment: "test".into(),
                tenant: "test".into(),
                os_type: "test".into(),
                os_version: "1".into(),
                device_model_identifier: None,
            }),
            ..RelayTelemetryExportConfig::enabled("https://collector.example/v1/metrics")
        };
        assert!(config.export_allowed());
        runtime.shared.configure_relay_telemetry_exporter(config);
        assert!(
            runtime
                .shared
                .relay_telemetry_exporter
                .lock()
                .unwrap()
                .is_none()
        );
    }
    runtime.shutdown_and_close().await.unwrap();
}

fn profile_relay_status(
    publish_relays: &[&str],
    bootstrap_relays: &[&str],
) -> AccountRelayListStatus {
    let mut status = AccountRelayListStatus {
        complete: false,
        missing: Vec::new(),
        default_relays: Vec::new(),
        bootstrap_relays: bootstrap_relays
            .iter()
            .map(|relay| (*relay).to_owned())
            .collect(),
        nip65: crate::AccountRelayListState {
            kind: crate::KIND_NIP65_RELAY_LIST,
            created_at: 0,
            relays: publish_relays
                .iter()
                .map(|relay| (*relay).to_owned())
                .collect(),
            read_relays: Vec::new(),
            write_relays: publish_relays
                .iter()
                .map(|relay| (*relay).to_owned())
                .collect(),
        },
        inbox: crate::AccountRelayListState {
            kind: crate::KIND_MARMOT_INBOX_RELAY_LIST,
            created_at: 0,
            relays: Vec::new(),
            read_relays: Vec::new(),
            write_relays: Vec::new(),
        },
    };
    status.refresh();
    status
}

#[test]
fn account_profile_publish_endpoint_selection_centralizes_fallback_and_safety() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://configured.example");

    let populated = profile_relay_status(&["wss://publish.example"], &["wss://bootstrap.example"]);
    assert_eq!(
        app.account_profile_publish_endpoints(&populated).unwrap(),
        vec![TransportEndpoint("wss://publish.example".into())]
    );

    let empty_publish = profile_relay_status(&[], &["wss://bootstrap.example"]);
    assert_eq!(
        app.account_profile_publish_endpoints(&empty_publish)
            .unwrap(),
        vec![TransportEndpoint("wss://bootstrap.example".into())]
    );

    let retired = format!("wss://{}", crate::retired_relay_hosts()[0]);
    let unsafe_with_safe_sibling = profile_relay_status(
        &["not-a-relay", retired.as_str(), "wss://safe.example"],
        &["wss://bootstrap.example"],
    );
    assert_eq!(
        app.account_profile_publish_endpoints(&unsafe_with_safe_sibling)
            .unwrap(),
        vec![TransportEndpoint("wss://safe.example".into())]
    );

    let unsafe_publish_with_safe_bootstrap = profile_relay_status(
        &["not-a-relay", retired.as_str()],
        &["wss://bootstrap.example"],
    );
    assert_eq!(
        app.account_profile_publish_endpoints(&unsafe_publish_with_safe_bootstrap)
            .unwrap(),
        vec![TransportEndpoint("wss://bootstrap.example".into())]
    );

    let unusable = profile_relay_status(&[], &["not-a-relay", retired.as_str()]);
    assert!(matches!(
        app.account_profile_publish_endpoints(&unusable),
        Err(AppError::RelayDirectory(message))
            if message == "account relay configuration has no usable profile publication endpoints"
    ));
}

#[test]
fn account_profile_publish_endpoint_selection_matches_canonical_outbox_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://configured.example");
    // `refresh()` creates the production cache shape. A distinct default list
    // represents a compatibility snapshot from an older cache schema; when
    // both fallback lists exist, canonical publication still picks bootstrap.
    let mut status = profile_relay_status(&[], &["wss://bootstrap.example"]);
    status.default_relays = vec!["wss://default.example".into()];
    app.remember_directory_relay_lists(&account.account_id_hex, &status)
        .unwrap();

    let bootstrap = AccountRelayListBootstrap::new(
        status
            .default_relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect(),
        status
            .bootstrap_relays
            .iter()
            .cloned()
            .map(TransportEndpoint)
            .collect(),
    );
    let canonical = app.outbox_endpoints(
        &account.account_id_hex,
        publish_endpoints_from_bootstrap(&bootstrap),
    );

    assert_eq!(
        app.account_profile_publish_endpoints(&status).unwrap(),
        canonical
    );
    assert_eq!(
        canonical,
        vec![TransportEndpoint("wss://bootstrap.example".into())]
    );
}

#[tokio::test]
async fn account_owned_profile_publish_rejects_signed_out_and_stopped_accounts() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("alice").unwrap();
    home.set_account_signed_out(&account.label, true).unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app);

    let signed_out = runtime
        .publish_user_profile_using_account_relays(&account.label, UserProfileMetadata::default())
        .await
        .expect_err("signed-out account must not publish");
    assert!(
        matches!(
            signed_out,
            AppError::RelayDirectory(ref message) if message == "account is signed out"
        ),
        "unexpected signed-out error: {signed_out:?}"
    );

    runtime.shutdown().await;
    let stopped = runtime
        .publish_user_profile_using_account_relays(&account.label, UserProfileMetadata::default())
        .await
        .expect_err("stopped runtime must not publish");
    assert!(matches!(stopped, AppError::RuntimeStopping));
}

#[test]
fn default_directory_discovery_relays_use_live_indexers() {
    let relays = default_directory_discovery_relays();

    assert!(
        relays.iter().any(|relay| relay.0 == VERTEX_DIRECTORY_RELAY),
        "Vertex must remain available for directory bootstrap"
    );
    assert!(
        relays
            .iter()
            .all(|relay| !["wss://relay.nostr.band", "wss://relay.damus.io",]
                .contains(&relay.0.as_str())),
        "retired relays must never return to discovery defaults"
    );
}

#[test]
fn generated_account_birth_marks_cutover_scan_complete_before_session_open() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());

    let (account, private_key_import) = runtime
        .accounts
        .create_nostr_account_from_setup(&AccountSetupRequest::default())
        .unwrap();

    assert!(private_key_import.is_none());
    assert!(app.key_package_cutover_scan_complete(&account.label));
    assert!(
        !app.account_home()
            .account_dir(&account.label)
            .join(crate::SESSION_DB_FILE)
            .exists(),
        "the scan marker must be durable before any session can open"
    );
}

#[tokio::test]
async fn failed_import_relay_discovery_does_not_publish_default_lists() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let keys = nostr::Keys::generate();
    let imported = home
        .import_nostr_account_idempotent(&keys.secret_key().to_secret_hex())
        .unwrap();
    let account = imported.account().clone();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = MarmotAppRuntime::new(app);

    let error = runtime
        .accounts
        .setup_relay_lists_for_account(
            &account,
            &AccountSetupRequest {
                default_relays: vec![TransportEndpoint("wss://relay.example".into())],
                // A non-WebSocket bootstrap endpoint makes the bounded
                // fallback discovery fail before any dial.
                bootstrap_relays: vec![TransportEndpoint("https://directory.invalid".into())],
                publish_missing_relay_lists: true,
                ..AccountSetupRequest::default()
            },
            true,
            false,
            None,
        )
        .await
        .expect_err("failed discovery must not become a write of request defaults");

    // A failed lookup is retryable uncertainty, not confirmed missing lists.
    assert!(matches!(error, AppError::RelayDirectory(_)));
}

#[test]
fn message_subscription_seen_ids_are_bounded_to_recent_ids() {
    let mut seen =
        MessageSubscriptionSeenIds::from_ids((0..5).map(|index| format!("message-{index}")), 3);

    assert_eq!(seen.len(), 3);
    assert!(!seen.contains("message-0"));
    assert!(!seen.contains("message-1"));
    assert!(seen.contains("message-2"));
    assert!(seen.contains("message-4"));
    assert!(!seen.insert("message-2".to_owned()));
    assert!(seen.insert("message-5".to_owned()));
    assert_eq!(seen.len(), 3);
    assert!(!seen.contains("message-2"));
    assert!(seen.contains("message-3"));
    assert!(seen.contains("message-5"));
}

#[test]
fn live_message_subscription_emits_each_empty_id_without_storing_it() {
    let mut seen = MessageSubscriptionSeenIds::with_limit(1);

    // Both live updates must be emitted; the first empty id must not poison
    // dedupe state for the second. `subscribe_messages` routes its live and
    // recovery paths through this same decision.
    assert!(seen.should_emit(String::new()));
    assert!(seen.should_emit(String::new()));
    assert_eq!(seen.len(), 0);
    assert!(!seen.contains(""));
}

#[test]
fn message_kind_filter_treats_none_and_empty_as_unrestricted() {
    assert!(message_kind_filter_allows(None, 9));
    assert!(message_kind_filter_allows(Some(&[]), 9));
    assert!(message_kind_filter_allows(Some(&[30100]), 30100));
    assert!(!message_kind_filter_allows(Some(&[30100]), 9));
}

#[test]
fn parse_quic_candidate_ignores_path_query_and_fragment_after_authority() {
    // Per transports/quic.md a receiver MUST ignore any path, query, or
    // fragment after the authority. A spec-valid start payload from another
    // implementation that appends one of these must still be watchable: the
    // authority (and thus the resolvable port) stops at the first '/', '?',
    // or '#'.
    for (candidate, authority, server_name) in [
        (
            "quic://relay.example:443/path",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443?x=1",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443#frag",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://relay.example:443/p?x=1#frag",
            "relay.example:443",
            "relay.example",
        ),
        (
            "quic://[2001:db8::1]:443?x=1",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ),
        (
            "quic://[2001:db8::1]:443#frag",
            "[2001:db8::1]:443",
            "2001:db8::1",
        ),
    ] {
        let parsed = parse_quic_candidate(candidate)
            .unwrap_or_else(|_| panic!("candidate should parse: {candidate}"));
        assert_eq!(parsed.authority, authority, "authority for {candidate}");
        assert_eq!(
            parsed.server_name, server_name,
            "server name for {candidate}"
        );
    }
}

#[test]
fn stamp_published_profile_created_at_replaces_zero_with_now() {
    // FFI-published profiles arrive with created_at == 0; they must be
    // stamped so the cached own-account entry survives a directory refresh
    // that re-fetches a stale pre-edit kind-0 from a lagging relay.
    let mut profile = UserProfileMetadata {
        name: Some("edited".to_owned()),
        created_at: 0,
        ..UserProfileMetadata::default()
    };
    stamp_published_profile_created_at(&mut profile, 1_700_000_000);
    assert_eq!(profile.created_at, 1_700_000_000);
}

#[test]
fn stamp_published_profile_created_at_preserves_existing_stamp() {
    // Callers that already carry a real timestamp (e.g. the default-profile
    // setup path) must not have it clobbered.
    let mut profile = UserProfileMetadata {
        name: Some("preset".to_owned()),
        created_at: 42,
        ..UserProfileMetadata::default()
    };
    stamp_published_profile_created_at(&mut profile, 1_700_000_000);
    assert_eq!(profile.created_at, 42);
}

#[test]
fn stamped_profile_wins_over_stale_relay_copy_in_if_newer_check() {
    // Regression for mdk#206: model the exact comparison
    // remember_directory_profile_if_newer performs. A zero-stamped cache
    // loses to any fetched copy; a now-stamped cache beats an older one.
    let mut zero_cache = UserProfileMetadata {
        created_at: 0,
        ..UserProfileMetadata::default()
    };
    let stale_relay_copy = UserProfileMetadata {
        created_at: 1_699_999_900,
        ..UserProfileMetadata::default()
    };
    // Before the fix: cached(0) > fetched is false, so the stale copy wins.
    assert!(zero_cache.created_at <= stale_relay_copy.created_at);

    // After stamping the just-published edit with a fresh clock:
    stamp_published_profile_created_at(&mut zero_cache, 1_700_000_000);
    // The local edit now beats the older relay copy and is retained.
    assert!(zero_cache.created_at > stale_relay_copy.created_at);
}

#[test]
fn merge_user_profile_update_preserves_unknown_kind0_fields() {
    let current = UserProfileMetadata {
        name: Some("old-name".to_owned()),
        display_name: Some("Old Name".to_owned()),
        picture: Some("https://example.test/old.png".to_owned()),
        banner: Some("https://example.test/old-banner.png".to_owned()),
        created_at: 123,
        source_relays: vec!["wss://relay.example".to_owned()],
        extra: std::collections::BTreeMap::from([
            (
                "website".to_owned(),
                serde_json::json!("https://example.test"),
            ),
            ("bot".to_owned(), serde_json::json!(false)),
            (
                "custom".to_owned(),
                serde_json::json!({"source": "other-client"}),
            ),
        ]),
        ..UserProfileMetadata::default()
    };
    let update = UserProfileMetadata {
        name: Some("new-name".to_owned()),
        display_name: Some("New Name".to_owned()),
        about: Some("updated about".to_owned()),
        picture: None,
        banner: None,
        created_at: 0,
        source_relays: Vec::new(),
        ..UserProfileMetadata::default()
    };

    let merged = merge_user_profile_update(current, update);

    assert_eq!(merged.name.as_deref(), Some("new-name"));
    assert_eq!(merged.display_name.as_deref(), Some("New Name"));
    assert_eq!(merged.about.as_deref(), Some("updated about"));
    assert_eq!(merged.picture, None);
    assert_eq!(
        merged.banner.as_deref(),
        Some("https://example.test/old-banner.png")
    );
    assert_eq!(
        merged.extra.get("website"),
        Some(&serde_json::json!("https://example.test"))
    );
    assert_eq!(merged.extra.get("bot"), Some(&serde_json::json!(false)));
    assert_eq!(
        merged.extra.get("custom"),
        Some(&serde_json::json!({"source": "other-client"}))
    );
}

#[test]
fn merge_user_profile_update_replaces_banner_when_present() {
    let current = UserProfileMetadata {
        banner: Some("https://example.test/old-banner.png".to_owned()),
        ..UserProfileMetadata::default()
    };
    let update = UserProfileMetadata {
        banner: Some("https://example.test/new-banner.png".to_owned()),
        ..UserProfileMetadata::default()
    };

    assert_eq!(
        merge_user_profile_update(current, update).banner.as_deref(),
        Some("https://example.test/new-banner.png")
    );
}

#[test]
fn newest_user_profile_keeps_newer_cached_extra_fields() {
    let cached = UserProfileMetadata {
        created_at: 200,
        extra: std::collections::BTreeMap::from([(
            "website".to_owned(),
            serde_json::json!("https://new.example"),
        )]),
        ..UserProfileMetadata::default()
    };
    let fetched = UserProfileMetadata {
        created_at: 100,
        extra: std::collections::BTreeMap::new(),
        ..UserProfileMetadata::default()
    };

    let selected = newest_user_profile(Some(cached.clone()), Some(fetched)).unwrap();
    assert_eq!(selected, cached);
}

#[tokio::test]
async fn managed_account_worker_shutdown_aborts_unresponsive_task_after_timeout() {
    struct DropSignal(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let (commands, _commands_rx) = mpsc::channel(1);
    let (shutdown, _shutdown_rx) = oneshot::channel();
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drop_signal = DropSignal(dropped.clone());
    let handle = tokio::spawn(async move {
        let _drop_signal = drop_signal;
        std::future::pending::<()>().await;
    });
    let worker = ManagedAccountWorker {
        ready: true,
        media_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
            crate::runtime::MEDIA_COMMAND_QUEUE_LIMIT,
        )),
        handle,
        commands,
        shutdown,
    };

    let started = std::time::Instant::now();
    worker
        .shutdown_with_timeout(Duration::from_millis(10))
        .await;

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
}

#[tokio::test]
async fn message_subscription_recv_ends_when_runtime_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();
    let (updates_tx, updates) = mpsc::channel(1);
    let mut subscription = RuntimeMessagesSubscription {
        policy_storage: storage_sqlite::SqliteAccountStorage::in_memory().unwrap(),
        snapshot: Vec::new(),
        updates,
        stopping: lifecycle.subscribe_shutdown(),
    };

    lifecycle.begin_shutdown();

    assert!(subscription.recv().await.is_none());
    drop(updates_tx);
}

fn timeline_test_record(message_id_hex: &str, timeline_at: u64) -> TimelineMessageRecord {
    TimelineMessageRecord {
        client_token: None,
        has_reports: false,
        group_system: None,
        poll: None,
        edit: None,
        message_id_hex: message_id_hex.to_owned(),
        source_message_id_hex: None,
        source_epoch: None,
        retention_seconds: None,
        retention_expires_at: None,
        group_id_hex: "group-1".to_owned(),
        direction: "inbound".to_owned(),
        sender: "sender-1".to_owned(),
        plaintext: message_id_hex.to_owned(),
        kind: 9,
        tags: Vec::new(),
        timeline_at,
        received_at: timeline_at,
        deleted: false,
        deletion_source: Default::default(),
        deleted_by_message_id_hex: None,
        invalidation_status: None,
        reply_to_message_id_hex: None,
        reply_preview: None,
        media: None,
        agent_text_stream: None,
        reactions: Default::default(),
    }
}

#[test]
fn group_system_projection_advances_the_chat_list_like_a_new_message() {
    let mut record = timeline_test_record("role-change", 10);
    record.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    record.tags = vec![vec![
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_TAG.to_owned(),
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_ADDED.to_owned(),
    ]];
    let change = TimelineMessageChange::Upsert {
        trigger: crate::TimelineUpdateTrigger::GroupSystem,
        message: Box::new(record),
    };

    assert_eq!(
        ChatListUpdateTrigger::from_timeline_changes(&[change], true),
        ChatListUpdateTrigger::NewLastMessage,
    );
}

#[test]
fn direct_conversation_group_system_projection_does_not_claim_new_chat_list_activity() {
    let mut record = timeline_test_record("role-change", 10);
    record.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    record.tags = vec![vec![
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_TAG.to_owned(),
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_ADMIN_ADDED.to_owned(),
    ]];
    let change = TimelineMessageChange::Upsert {
        trigger: crate::TimelineUpdateTrigger::GroupSystem,
        message: Box::new(record),
    };

    assert_eq!(
        ChatListUpdateTrigger::from_timeline_changes(&[change], false),
        ChatListUpdateTrigger::SnapshotRefresh,
    );
}

#[test]
fn agent_stream_updates_still_advance_the_chat_list_like_new_messages() {
    for trigger in [
        crate::TimelineUpdateTrigger::AgentStreamStarted,
        crate::TimelineUpdateTrigger::AgentStreamFinished,
    ] {
        let change = TimelineMessageChange::Upsert {
            trigger,
            message: Box::new(timeline_test_record("agent-stream", 10)),
        };

        assert_eq!(
            ChatListUpdateTrigger::from_timeline_changes(&[change], false),
            ChatListUpdateTrigger::NewLastMessage,
        );
    }
}

#[test]
fn unrelated_group_system_projection_does_not_claim_new_chat_list_activity() {
    let mut record = timeline_test_record("rename", 10);
    record.kind = cgka_traits::app_event::MARMOT_APP_EVENT_KIND_GROUP_SYSTEM;
    record.tags = vec![vec![
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_TAG.to_owned(),
        cgka_traits::app_event::GROUP_SYSTEM_TYPE_GROUP_RENAMED.to_owned(),
    ]];
    let change = TimelineMessageChange::Upsert {
        trigger: crate::TimelineUpdateTrigger::GroupSystem,
        message: Box::new(record),
    };

    assert_eq!(
        ChatListUpdateTrigger::from_timeline_changes(&[change], true),
        ChatListUpdateTrigger::SnapshotRefresh,
    );
}

fn timeline_test_page(
    records: &[(&str, u64)],
    has_more_before: bool,
    has_more_after: bool,
) -> TimelinePage {
    TimelinePage {
        messages: records
            .iter()
            .map(|(id, at)| timeline_test_record(id, *at))
            .collect(),
        has_more_before,
        has_more_after,
    }
}

fn empty_timeline_page() -> TimelinePage {
    TimelinePage {
        messages: Vec::new(),
        has_more_before: false,
        has_more_after: false,
    }
}

fn timeline_ids(page: &TimelinePage) -> Vec<String> {
    page.messages
        .iter()
        .map(|message| message.message_id_hex.clone())
        .collect()
}

/// A fake store that hands out canned pages in order and records each query
/// it received, so tests can assert both the merge result and the cursor a
/// pagination/refresh call issued.
#[derive(Clone, Default)]
struct ScriptedTimelineStore {
    responses: Arc<StdMutex<std::collections::VecDeque<Result<TimelinePage, AppError>>>>,
    queries: Arc<StdMutex<Vec<TimelineMessageQuery>>>,
}

impl ScriptedTimelineStore {
    fn new(responses: Vec<TimelinePage>) -> Self {
        Self::new_results(responses.into_iter().map(Ok).collect())
    }

    fn new_results(responses: Vec<Result<TimelinePage, AppError>>) -> Self {
        Self {
            responses: Arc::new(StdMutex::new(responses.into_iter().collect())),
            queries: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    fn query_fn(&self) -> Arc<TimelineQueryFn> {
        let responses = self.responses.clone();
        let queries = self.queries.clone();
        Arc::new(move |query: TimelineMessageQuery| {
            queries.lock().expect("queries lock").push(query);
            responses
                .lock()
                .expect("responses lock")
                .pop_front()
                .expect("scripted timeline store exhausted")
        })
    }

    fn recorded_queries(&self) -> Vec<TimelineMessageQuery> {
        self.queries.lock().expect("queries lock").clone()
    }
}

fn timeline_window(
    store: &ScriptedTimelineStore,
    page: TimelinePage,
    window_limit: usize,
) -> TimelineWindow {
    TimelineWindow {
        query: store.query_fn(),
        base_query: TimelineMessageQuery::default(),
        page,
        window_limit,
        generation: 0,
    }
}

fn timeline_window_handle(
    store: &ScriptedTimelineStore,
    page: TimelinePage,
    window_limit: usize,
) -> TimelineWindowHandle {
    TimelineWindowHandle {
        inner: Arc::new(StdMutex::new(timeline_window(store, page, window_limit))),
    }
}

fn timeline_subscription_with(
    store: &ScriptedTimelineStore,
    window: TimelinePage,
    window_limit: usize,
    updates: mpsc::Receiver<TimelineSubscriptionSignal>,
    stopping: watch::Receiver<bool>,
) -> RuntimeTimelineMessagesSubscription {
    RuntimeTimelineMessagesSubscription {
        policy_window_size: window.messages.len().max(1),
        policy_storage: storage_sqlite::SqliteAccountStorage::in_memory().unwrap(),
        window: timeline_window_handle(store, window, window_limit),
        updates,
        stopping,
    }
}

#[tokio::test]
async fn timeline_subscription_recv_ends_when_runtime_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (updates_tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        empty_timeline_page(),
        TIMELINE_WINDOW_LIMIT,
        updates,
        lifecycle.subscribe_shutdown(),
    );

    lifecycle.begin_shutdown();

    assert!(subscription.recv().await.is_none());
    drop(updates_tx);
}

#[tokio::test]
async fn agent_stream_watch_recv_prioritizes_terminal_update() {
    let lifecycle = RuntimeLifecycle::new();
    let (updates_tx, updates) = mpsc::channel(1);
    updates_tx
        .try_send(RuntimeAgentStreamUpdate::Progress {
            seq: 1,
            text: "searching".to_owned(),
        })
        .expect("provisional queue should accept first update");
    let (terminal_tx, terminal) = oneshot::channel();
    let expected = RuntimeAgentStreamUpdate::Finished {
        text: "done".to_owned(),
        transcript_hash_hex: "00".to_owned(),
        chunk_count: 1,
    };
    terminal_tx
        .send(expected.clone())
        .expect("terminal receiver should be alive");
    let handle = tokio::spawn(async {});
    let mut watch = RuntimeAgentStreamWatch {
        stream_id_hex: "stream".to_owned(),
        updates,
        terminal: Some(terminal),
        abort: handle.abort_handle(),
        stopping: lifecycle.subscribe_shutdown(),
    };

    assert_eq!(watch.recv().await, Some(expected));
    assert!(watch.recv().await.is_none());
}

#[test]
fn timeline_subscription_take_snapshot_retains_window_for_pagination() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (_updates_tx, updates) = mpsc::channel(1);
    let subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("message-1", 1)], true, false),
        TIMELINE_WINDOW_LIMIT,
        updates,
        lifecycle.subscribe_shutdown(),
    );

    let snapshot = subscription.take_snapshot();

    assert_eq!(snapshot.messages.len(), 1);
    assert!(snapshot.has_more_before);
    // The window is retained (cloned, not drained) so pagination can extend
    // it; a second read returns the same window.
    let again = subscription.take_snapshot();
    assert_eq!(timeline_ids(&again), vec!["message-1".to_owned()]);
    assert!(again.has_more_before);
}

#[test]
fn merge_timeline_window_orders_epoch_boundaries_canonically() {
    let mut system_seven = timeline_test_record("system-7", 900);
    system_seven.source_epoch = Some(7);
    system_seven.kind = 1210;
    let mut message_seven = timeline_test_record("message-7", 200);
    message_seven.source_epoch = Some(7);
    let mut system_eight = timeline_test_record("system-8", 901);
    system_eight.source_epoch = Some(8);
    system_eight.kind = 1210;
    let mut message_eight = timeline_test_record("message-8", 150);
    message_eight.source_epoch = Some(8);
    let mut window = TimelinePage {
        messages: vec![message_eight, system_seven],
        has_more_before: false,
        has_more_after: false,
    };
    let incoming = TimelinePage {
        messages: vec![system_eight, message_seven],
        has_more_before: false,
        has_more_after: false,
    };

    merge_timeline_window_with_order(&mut window, incoming, TimelineWindowEdge::Newer, 300, true);

    assert_eq!(
        timeline_ids(&window),
        ["system-7", "message-7", "system-8", "message-8"]
    );
}

#[test]
fn merge_timeline_window_prepends_older_and_keeps_head_flag() {
    let mut window = timeline_test_page(&[("c", 30), ("d", 40)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], false, true);

    merge_timeline_window_with_order(&mut window, older, TimelineWindowEdge::Older, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c", "d"]);
    // The store reported no more history before; the head side is untouched.
    assert!(!window.has_more_before);
    assert!(!window.has_more_after);
}

#[test]
fn merge_timeline_window_older_caps_by_dropping_newest() {
    let mut window = timeline_test_page(&[("c", 30), ("d", 40)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], true, true);

    merge_timeline_window_with_order(&mut window, older, TimelineWindowEdge::Older, 3, true);

    // Cap forces dropping the newest row, opening a gap to the head.
    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
    assert!(window.has_more_before);
    assert!(window.has_more_after);
}

#[test]
fn merge_timeline_window_newer_caps_by_dropping_oldest() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let newer = timeline_test_page(&[("c", 30), ("d", 40)], true, false);

    merge_timeline_window_with_order(&mut window, newer, TimelineWindowEdge::Newer, 3, true);

    assert_eq!(timeline_ids(&window), vec!["b", "c", "d"]);
    assert!(window.has_more_before);
    // The store reported the head was reached.
    assert!(!window.has_more_after);
}

#[test]
fn merge_timeline_window_dedupes_overlap() {
    let mut window = timeline_test_page(&[("b", 20), ("c", 30)], true, false);
    let older = timeline_test_page(&[("a", 10), ("b", 20)], false, true);

    merge_timeline_window_with_order(&mut window, older, TimelineWindowEdge::Older, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
}

fn projection_for(messages: Vec<TimelineMessageRecord>) -> AppProjectionUpdate {
    AppProjectionUpdate {
        group_id_hex: "group-1".to_owned(),
        timeline_messages: messages,
        timeline_changes: Vec::new(),
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    }
}

#[test]
fn apply_projection_appends_new_message_when_anchored() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], false, false);
    let update = projection_for(vec![timeline_test_record("c", 30)]);

    apply_projection_to_window(&mut window, &update, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
    assert!(!window.has_more_after);
}

#[test]
fn apply_projection_suppresses_new_head_message_when_detached() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("c", 30)]);

    apply_projection_to_window(&mut window, &update, 300, true);

    // Detached window stays put; the new head message is dropped.
    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_applies_in_window_edit_when_detached() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let mut edited = timeline_test_record("b", 20);
    edited.plaintext = "edited".to_owned();
    let update = projection_for(vec![edited]);

    apply_projection_to_window(&mut window, &update, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert_eq!(window.messages[1].plaintext, "edited");
}

#[test]
fn apply_projection_suppresses_same_second_head_when_detached() {
    // Newest is ("b", 20); a brand-new message shares the second but sorts
    // after it by id. Timestamp-only comparison would admit it; canonical
    // `(timeline_at, message_id_hex)` comparison correctly suppresses it.
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("c", 20)]);

    apply_projection_to_window(&mut window, &update, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b"]);
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_applies_same_second_in_range_message_when_detached() {
    // Newest is ("c", 20); a same-second message that sorts *before* it is
    // genuinely inside the window and must be applied.
    let mut window = timeline_test_page(&[("a", 10), ("c", 20)], true, true);
    let update = projection_for(vec![timeline_test_record("b", 20)]);

    apply_projection_to_window(&mut window, &update, 300, true);

    assert_eq!(timeline_ids(&window), vec!["a", "b", "c"]);
}

#[test]
fn apply_projection_suppresses_new_message_when_detached_window_empty() {
    // An emptied detached window (every row removed) has nothing in range, so
    // a head message must be suppressed rather than absorbed.
    let mut window = timeline_test_page(&[], true, true);
    let update = projection_for(vec![timeline_test_record("a", 10)]);

    apply_projection_to_window(&mut window, &update, 300, true);

    assert!(window.messages.is_empty());
    assert!(window.has_more_after);
}

#[test]
fn apply_projection_removes_message() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20)], false, false);
    let update = AppProjectionUpdate {
        group_id_hex: "group-1".to_owned(),
        timeline_messages: Vec::new(),
        timeline_changes: vec![TimelineMessageChange::Remove {
            message_id_hex: "a".to_owned(),
            reason: crate::TimelineRemoveReason::Invalidated,
        }],
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };

    apply_projection_to_window(&mut window, &update, 300, true);

    assert_eq!(timeline_ids(&window), vec!["b"]);
}

#[test]
fn apply_projection_caps_anchored_window_by_dropping_oldest() {
    let mut window = timeline_test_page(&[("a", 10), ("b", 20), ("c", 30)], false, false);
    let update = projection_for(vec![timeline_test_record("d", 40)]);

    apply_projection_to_window(&mut window, &update, 3, true);

    assert_eq!(timeline_ids(&window), vec!["b", "c", "d"]);
    assert!(window.has_more_before);
    assert!(!window.has_more_after);
}

#[test]
fn apply_projection_preserves_wall_clock_order_for_global_windows() {
    let mut older_epoch = timeline_test_record("older-epoch", 200);
    older_epoch.source_epoch = Some(7);
    let mut newer_epoch = timeline_test_record("newer-epoch", 100);
    newer_epoch.source_epoch = Some(8);
    let mut window = TimelinePage {
        messages: vec![older_epoch, newer_epoch],
        has_more_before: false,
        has_more_after: false,
    };

    apply_projection_to_window(&mut window, &projection_for(Vec::new()), 300, false);

    assert_eq!(timeline_ids(&window), ["newer-epoch", "older-epoch"]);
}

#[test]
fn apply_projection_scopes_global_window_changes_by_group() {
    let mut group_a = timeline_test_record("shared-id", 10);
    group_a.group_id_hex = "group-a".to_owned();
    let mut group_b = timeline_test_record("shared-id", 20);
    group_b.group_id_hex = "group-b".to_owned();
    let mut window = TimelinePage {
        messages: vec![group_a, group_b],
        has_more_before: false,
        has_more_after: false,
    };

    let mut edited_group_a = timeline_test_record("shared-id", 30);
    edited_group_a.group_id_hex = "group-a".to_owned();
    edited_group_a.plaintext = "edited group A".to_owned();
    let edit = AppProjectionUpdate {
        group_id_hex: "group-a".to_owned(),
        timeline_messages: Vec::new(),
        timeline_changes: vec![TimelineMessageChange::Upsert {
            trigger: crate::TimelineUpdateTrigger::MessageEditedOrReprojected,
            message: Box::new(edited_group_a),
        }],
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };

    apply_projection_to_window(&mut window, &edit, 300, false);

    assert_eq!(window.messages.len(), 2);
    assert_eq!(
        window
            .messages
            .iter()
            .find(|message| message.group_id_hex == "group-a")
            .expect("group A row")
            .plaintext,
        "edited group A"
    );
    assert_eq!(
        window
            .messages
            .iter()
            .find(|message| message.group_id_hex == "group-b")
            .expect("group B row")
            .plaintext,
        "shared-id"
    );

    let remove = AppProjectionUpdate {
        group_id_hex: "group-a".to_owned(),
        timeline_messages: Vec::new(),
        timeline_changes: vec![TimelineMessageChange::Remove {
            message_id_hex: "shared-id".to_owned(),
            reason: crate::TimelineRemoveReason::Invalidated,
        }],
        chat_list_row: None,
        chat_list_trigger: Default::default(),
    };

    apply_projection_to_window(&mut window, &remove, 300, false);

    assert_eq!(window.messages.len(), 1);
    assert_eq!(window.messages[0].group_id_hex, "group-b");
    assert_eq!(window.messages[0].message_id_hex, "shared-id");
}

#[tokio::test]
async fn paginate_backwards_extends_window_and_clears_more_before() {
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
    );

    let page = handle.paginate_backwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);
    assert!(!page.has_more_before);
    assert!(!page.has_more_after);
    // The cursor was anchored at the previous oldest message.
    let queries = store.recorded_queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].pagination.before, Some(30));
    assert_eq!(
        queries[0].pagination.before_message_id.as_deref(),
        Some("c")
    );
    assert_eq!(queries[0].pagination.limit, Some(2));
}

#[tokio::test]
async fn paginate_backwards_is_noop_without_more_before() {
    // Empty response queue: a store call would panic, proving none is made.
    let store = ScriptedTimelineStore::new(Vec::new());
    let handle =
        timeline_window_handle(&store, timeline_test_page(&[("a", 10)], false, false), 300);

    let page = handle.paginate_backwards(10).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a"]);
    assert!(store.recorded_queries().is_empty());
}

#[tokio::test]
async fn paginate_forwards_reaching_head_reanchors() {
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("c", 30), ("d", 40)],
        true,
        false,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
    );

    let page = handle.paginate_forwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);
    assert!(page.has_more_before);
    // Head reached: the window is now anchored again.
    assert!(!page.has_more_after);
    let queries = store.recorded_queries();
    assert_eq!(queries[0].pagination.after, Some(20));
    assert_eq!(queries[0].pagination.after_message_id.as_deref(), Some("b"));
}

#[tokio::test]
async fn paginate_backwards_caps_window_and_opens_head_gap() {
    // A small window cap forces trimming the newest rows when older history
    // is loaded, opening a gap to the head (has_more_after).
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        3,
    );

    let page = handle.paginate_backwards(2).await.expect("paginate");

    assert_eq!(timeline_ids(&page), vec!["a", "b", "c"]);
    assert!(page.has_more_before);
    assert!(page.has_more_after);
}

#[tokio::test]
async fn paginate_does_not_block_on_a_parked_receiver() {
    // Regression for the FFI-equivalent contention: a subscription parked in
    // recv() (no live updates) must not block pagination through the handle.
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    let handle = subscription.window_handle();

    // recv() parks (no signal queued); pagination through the cloned handle
    // proceeds without waiting for a live update.
    let recv = tokio::spawn(async move { subscription.recv().await });
    let page = tokio::time::timeout(Duration::from_secs(2), handle.paginate_backwards(2))
        .await
        .expect("pagination must not block on the parked receiver")
        .expect("paginate");
    assert_eq!(timeline_ids(&page), vec!["a", "b", "c", "d"]);

    // Unblock and join the parked receiver.
    drop(tx);
    let _ = recv.await;
}

#[tokio::test]
async fn recv_projection_applies_to_window() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::default();
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10)], false, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Projection(Box::new(
        RuntimeProjectionUpdate {
            account_id_hex: "account".to_owned(),
            account_label: "label".to_owned(),
            update: projection_for(vec![timeline_test_record("b", 20)]),
        },
    )))
    .await
    .expect("send projection");

    let update = subscription.recv().await.expect("recv");

    assert!(matches!(
        update,
        RuntimeTimelineMessageUpdate::Projection(_)
    ));
    assert_eq!(timeline_ids(&subscription.take_snapshot()), vec!["a", "b"]);
}

#[tokio::test]
async fn recv_refresh_rematerializes_anchored_head() {
    let lifecycle = RuntimeLifecycle::new();
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        false,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10)], false, false),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Refresh)
        .await
        .expect("send refresh");

    let update = subscription.recv().await.expect("recv");

    match update {
        RuntimeTimelineMessageUpdate::Page { page } => {
            assert_eq!(timeline_ids(&page), vec!["a", "b"]);
        }
        other => panic!("expected refreshed page, got {other:?}"),
    }
    // Anchored refresh queries the head (no cursor).
    let queries = store.recorded_queries();
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].pagination.before, None);
    assert_eq!(queries[0].pagination.after, None);
}

#[tokio::test]
async fn recv_refresh_detached_issues_inclusive_upper_cursor() {
    let lifecycle = RuntimeLifecycle::new();
    // The store itself excludes newer same-second rows via the inclusive
    // bound (covered by storage-sqlite's
    // `before_inclusive_cursor_keeps_window_rows_over_newer_same_second_rows`);
    // here we assert the runtime issues that inclusive cursor and installs
    // the returned page verbatim (no post-fetch trimming).
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        true,
        true,
    )]);
    let (tx, updates) = mpsc::channel(1);
    let mut subscription = timeline_subscription_with(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
        updates,
        lifecycle.subscribe_shutdown(),
    );
    tx.send(TimelineSubscriptionSignal::Refresh)
        .await
        .expect("send refresh");

    let update = subscription.recv().await.expect("recv");

    match update {
        RuntimeTimelineMessageUpdate::Page { page } => {
            assert_eq!(timeline_ids(&page), vec!["a", "b"]);
        }
        other => panic!("expected refreshed page, got {other:?}"),
    }
    let queries = store.recorded_queries();
    assert_eq!(queries[0].pagination.before, Some(20));
    assert_eq!(
        queries[0].pagination.before_message_id.as_deref(),
        Some("b")
    );
    assert!(queries[0].pagination.before_inclusive);
}

#[tokio::test]
async fn pagination_refreshes_head_when_canonical_cursor_was_pruned() {
    let store = ScriptedTimelineStore::new_results(vec![
        Err(AppError::Storage(
            cgka_traits::storage::StorageError::TimelineCursorExpired,
        )),
        Ok(timeline_test_page(&[("x", 40), ("y", 50)], true, false)),
    ]);
    let mut handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
    );
    Arc::get_mut(&mut handle.inner)
        .expect("exclusive window")
        .get_mut()
        .expect("window lock")
        .base_query
        .group_id_hex = Some("group-a".to_owned());

    let page = handle
        .paginate_backwards(2)
        .await
        .expect("expired cursor refreshes the window");

    assert_eq!(timeline_ids(&page), vec!["x", "y"]);
    let queries = store.recorded_queries();
    assert_eq!(queries.len(), 2);
    assert_eq!(queries[0].group_id_hex.as_deref(), Some("group-a"));
    assert_eq!(queries[0].pagination.before, Some(10));
    assert_eq!(
        queries[0].pagination.before_message_id.as_deref(),
        Some("a")
    );
    assert_eq!(queries[1].group_id_hex.as_deref(), Some("group-a"));
    assert_eq!(queries[1].pagination.before, None);
    assert_eq!(queries[1].pagination.after, None);
    assert_eq!(queries[1].pagination.limit, Some(2));
}

#[tokio::test]
async fn refresh_install_is_dropped_when_window_paginated_during_query() {
    // Deterministic model of the P1(b) race: a refresh captures the window
    // generation before its store read; a pagination completes during that
    // read (bumping the generation); installing the now-stale refresh must
    // be a no-op so the paginated expansion is preserved.
    let store = ScriptedTimelineStore::new(vec![timeline_test_page(
        &[("a", 10), ("b", 20)],
        false,
        true,
    )]);
    let handle = timeline_window_handle(
        &store,
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        300,
    );

    // recv() captures the refresh request (a generation snapshot) before
    // awaiting the store.
    let (_query_fn, _query, _head_query, generation) = handle.refresh_request();

    // A concurrent pagination lands while the refresh query is "in flight".
    let paginated = handle.paginate_backwards(2).await.expect("paginate");
    assert_eq!(timeline_ids(&paginated), vec!["a", "b", "c", "d"]);

    // Installing the stale refresh is rejected; the paginated window stands.
    let installed = handle.install_refresh(
        timeline_test_page(&[("c", 30), ("d", 40)], true, false),
        generation,
    );
    assert_eq!(timeline_ids(&installed), vec!["a", "b", "c", "d"]);
    assert_eq!(timeline_ids(&handle.snapshot()), vec!["a", "b", "c", "d"]);
}

#[test]
fn refresh_query_for_detached_window_anchors_at_newest() {
    let store = ScriptedTimelineStore::default();
    let window = timeline_window(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, true),
        300,
    );

    let query = window.refresh_query();

    // Detached: an inclusive upper-bound cursor at the exact newest message,
    // so the descending LIMIT can't be starved by newer same-second rows.
    assert_eq!(query.pagination.before, Some(20));
    assert_eq!(query.pagination.before_message_id.as_deref(), Some("b"));
    assert!(query.pagination.before_inclusive);
    assert_eq!(query.pagination.limit, Some(2));
}

#[test]
fn refresh_query_for_anchored_window_targets_head() {
    let store = ScriptedTimelineStore::default();
    let window = timeline_window(
        &store,
        timeline_test_page(&[("a", 10), ("b", 20)], true, false),
        300,
    );

    let query = window.refresh_query();

    // Anchored: cursorless head refresh sized to the current window.
    assert_eq!(query.pagination.before, None);
    assert_eq!(query.pagination.after, None);
    assert_eq!(query.pagination.limit, Some(2));
}

#[tokio::test]
async fn chat_list_remove_update_is_sent_once_for_visible_rows() {
    let (updates_tx, mut updates_rx) = mpsc::channel(1);
    let visible_row = chat_list_test_row("group", "visible");
    let mut row_fingerprints = HashMap::from([(
        visible_row.group_id_hex.clone(),
        chat_list_row_fingerprint(&visible_row),
    )]);

    assert!(
        send_chat_list_remove_update(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::Removed,
            "group",
        )
        .await
    );
    assert_eq!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::RemoveRow {
            trigger: ChatListUpdateTrigger::Removed,
            group_id_hex: "group".to_owned()
        })
    );

    assert!(
        send_chat_list_remove_update(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::Removed,
            "group",
        )
        .await
    );
    assert!(updates_rx.try_recv().is_err());
}

#[tokio::test]
async fn chat_list_snapshot_reconciliation_updates_changed_rows_and_removes_missing_rows() {
    let (updates_tx, mut updates_rx) = mpsc::channel(2);
    let initial_row = chat_list_test_row("group", "before");
    let removed_row = chat_list_test_row("removed", "gone");
    let mut row_fingerprints = HashMap::from([
        (
            initial_row.group_id_hex.clone(),
            chat_list_row_fingerprint(&initial_row),
        ),
        (
            removed_row.group_id_hex.clone(),
            chat_list_row_fingerprint(&removed_row),
        ),
    ]);

    assert!(
        reconcile_chat_list_snapshot(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![chat_list_test_row("group", "after")],
        )
        .await
    );

    assert!(matches!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::RemoveRow {
            trigger: ChatListUpdateTrigger::SnapshotRefresh,
            group_id_hex,
        }) if group_id_hex == "removed"
    ));
    assert!(matches!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::Row {
            trigger: ChatListUpdateTrigger::SnapshotRefresh,
            row,
        }) if row.group_id_hex == "group" && row.title == "after"
    ));
}

#[tokio::test]
async fn pin_order_changes_are_sent_as_one_atomic_snapshot() {
    let (updates_tx, mut updates_rx) = mpsc::channel(1);
    let stale = chat_list_test_row("stale", "old");
    let mut row_fingerprints = HashMap::from([(
        stale.group_id_hex.clone(),
        chat_list_row_fingerprint(&stale),
    )]);
    let mut first = chat_list_test_row("first", "First");
    first.pinned = true;
    first.pinned_position = Some(0);
    let mut second = chat_list_test_row("second", "Second");
    second.pinned = true;
    second.pinned_position = Some(1);

    assert!(
        send_atomic_chat_list_snapshot(
            &updates_tx,
            &mut row_fingerprints,
            ChatListUpdateTrigger::PinOrderChanged,
            vec![first.clone(), second.clone()],
        )
        .await
    );
    assert_eq!(
        updates_rx.recv().await,
        Some(RuntimeChatListUpdate::Snapshot {
            trigger: ChatListUpdateTrigger::PinOrderChanged,
            rows: vec![first.clone(), second.clone()],
        })
    );
    assert_eq!(row_fingerprints.len(), 2);
    assert_eq!(
        row_fingerprints.get("first"),
        Some(&chat_list_row_fingerprint(&first))
    );
    assert_eq!(
        row_fingerprints.get("second"),
        Some(&chat_list_row_fingerprint(&second))
    );
}

#[test]
fn chat_list_fingerprint_preserves_serialized_deduplication_semantics() {
    let base = chat_list_test_row("group", "title");
    let mut refreshed = base.clone();
    refreshed.updated_at = base.updated_at.saturating_add(1);
    assert_eq!(
        chat_list_row_fingerprint(&base),
        chat_list_row_fingerprint(&refreshed),
        "projection maintenance timestamps must not wake chat-list subscribers"
    );

    let mut internal_media_changed = base.clone();
    internal_media_changed.last_message = Some(crate::ChatListMessagePreview {
        retention_seconds: None,
        retention_expires_at: None,
        group_system: None,
        message_id_hex: "message".to_owned(),
        sender: "sender".to_owned(),
        sender_display_name: None,
        plaintext: "hello".to_owned(),
        kind: 9,
        timeline_at: 1,
        deleted: false,
        deletion_source: Default::default(),
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: crate::ChatListMessageDeliveryState::NotApplicable,
        media_json: None,
    });
    let internal_media_baseline = internal_media_changed.clone();
    internal_media_changed
        .last_message
        .as_mut()
        .expect("test row has a last message")
        .media_json = Some("internal".to_owned());
    assert_eq!(
        chat_list_row_fingerprint(&internal_media_baseline),
        chat_list_row_fingerprint(&internal_media_changed),
        "internal non-serialized media must not wake chat-list subscribers"
    );

    let mut manual = base.clone();
    manual.manually_marked_unread = true;
    manual.has_unread = true;
    assert_ne!(
        chat_list_row_fingerprint(&base),
        chat_list_row_fingerprint(&manual)
    );
    let mut pinned = base.clone();
    pinned.pinned = true;
    pinned.pinned_position = Some(0);
    assert_ne!(
        chat_list_row_fingerprint(&base),
        chat_list_row_fingerprint(&pinned)
    );
    let mut disbanding = base.clone();
    disbanding.disbanding = true;
    assert_ne!(
        chat_list_row_fingerprint(&base),
        chat_list_row_fingerprint(&disbanding),
        "pending disband must wake chat-list subscribers so hosts can hide the composer"
    );
}

#[test]
fn chat_list_expiry_tracking_includes_new_interaction_state() {
    let base = chat_list_test_row("group", "title");

    let mut timed = base.clone();
    timed.muted = true;
    timed.muted_until_ms = Some(1_700_000_000_000);
    let expiries = chat_list_mute_expiries(&[timed]);
    assert_eq!(expiries.get("group"), Some(&1_700_000_000_000));

    let mut indefinite = base;
    indefinite.muted = true;
    assert!(chat_list_mute_expiries(&[indefinite]).is_empty());
}

#[test]
fn latest_agent_stream_start_accepts_mixed_case_filter() {
    let stream_id_hex = hex::encode([0xab; 32]);
    let (message_id_hex, start, sender) = latest_agent_stream_start(
        vec![AppMessageRecord {
            authority: None,
            message_id_hex: "11".repeat(32),
            direction: "inbound".to_owned(),
            group_id_hex: "22".repeat(32),
            sender: "33".repeat(32),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
            tags: vec![
                vec![STREAM_TAG.to_owned(), stream_id_hex.clone()],
                vec![STREAM_ROUTE_TAG.to_owned(), STREAM_ROUTE_QUIC.to_owned()],
            ],
            source_epoch: None,
            retention: None,
            recorded_at: 0,
            received_at: 0,
            insert_order: 0,
            invalidated: false,
            moderation_grant: false,
        }],
        Some(&stream_id_hex.to_uppercase()),
    )
    .unwrap();

    assert_eq!(message_id_hex, "11".repeat(32));
    assert_eq!(start.stream_id_hex, stream_id_hex);
    assert_eq!(sender, "33".repeat(32));
}

fn chat_list_test_row(group_id_hex: &str, title: &str) -> ChatListRow {
    ChatListRow {
        group_id_hex: group_id_hex.to_owned(),
        pinned: false,
        pinned_position: None,
        archived: false,
        pending_confirmation: false,
        disbanding: false,
        disband_request: None,
        title: title.to_owned(),
        group_name: title.to_owned(),
        avatar_url: None,
        avatar: None,
        last_message: None,
        unread_count: 0,
        has_unread: false,
        manually_marked_unread: false,
        unread_mention_count: 0,
        has_unread_mention: false,
        first_unread_message_id_hex: None,
        last_read_message_id_hex: None,
        last_read_timeline_at: None,
        conversation_created_at: 0,
        activity_sort_at: 0,
        updated_at: 0,
        self_membership: crate::SelfMembership::Member,
        conversation_kind: crate::ChatConversationKind::Unknown,
        lifecycle_state: cgka_traits::GroupLifecycleState::Stable,
        muted: false,
        muted_until_ms: None,
        leave_requested_at_ms: None,
    }
}

fn message_record(message_id_hex: &str, group_id_hex: &str, kind: u64) -> AppMessageRecord {
    AppMessageRecord {
        authority: None,
        message_id_hex: message_id_hex.to_owned(),
        direction: "received".to_owned(),
        group_id_hex: group_id_hex.to_owned(),
        sender: "ab".repeat(32),
        plaintext: "hello".to_owned(),
        kind,
        tags: Vec::new(),
        source_epoch: Some(7),
        retention: None,
        recorded_at: 11,
        received_at: 12,
        insert_order: 0,
        invalidated: false,
        moderation_grant: false,
    }
}

#[test]
fn recovery_record_maps_chat_message_to_message_update() {
    let group_id_hex = "cd".repeat(32);
    let record = message_record(&"11".repeat(32), &group_id_hex, 9);
    let mut display_names = HashMap::new();
    display_names.insert("ab".repeat(32), "Alice".to_owned());

    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &display_names,
    )
    .expect("update");

    match update {
        RuntimeMessageUpdate::Message(received) => {
            assert_eq!(received.account_id_hex, "ac".repeat(32));
            assert_eq!(received.account_label, "alice");
            assert_eq!(received.message.message_id_hex, "11".repeat(32));
            assert_eq!(
                received.message.sender_display_name.as_deref(),
                Some("Alice")
            );
            assert_eq!(received.message.source_epoch, 7);
            assert_eq!(
                hex::encode(received.message.group_id.as_slice()),
                group_id_hex
            );
        }
        other => panic!("expected Message update, got {other:?}"),
    }
}

#[test]
fn recovery_record_reclassifies_agent_stream_start() {
    let group_id_hex = "cd".repeat(32);
    let record = message_record(
        &"22".repeat(32),
        &group_id_hex,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
    );

    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &HashMap::new(),
    )
    .expect("update");

    match update {
        RuntimeMessageUpdate::AgentStreamStarted(received) => {
            assert_eq!(received.message.message_id_hex, "22".repeat(32));
            assert_eq!(received.message.sender_display_name, None);
        }
        other => panic!("expected AgentStreamStarted update, got {other:?}"),
    }
}

#[test]
fn recovery_record_drops_undecodable_group_id() {
    let record = message_record(&"33".repeat(32), "not-hex", 9);
    let update = received_message_update_from_record(
        "ac".repeat(32).as_str(),
        "alice",
        record,
        &HashMap::new(),
    );
    assert!(update.is_none());
}

#[test]
fn messages_recovery_query_drops_initial_replay_limit() {
    // Regression for mdk#180 follow-up: the caller's `limit` is an
    // initial-replay cap (latest N rows). Reusing it on lag recovery would
    // reload only the latest N stored rows, so a limited subscriber could
    // still permanently lose messages between the last delivered id and
    // that latest row after broadcast lag. Recovery must drop the limit and
    // lean on `seen_message_ids` to dedupe.
    let group_id_hex = "cd".repeat(32);
    let query = AppMessageQuery {
        group_id_hex: Some(group_id_hex.clone()),
        kinds: None,
        limit: Some(1),
    };
    let recovery = messages_recovery_query(&query);
    assert_eq!(
        recovery.limit, None,
        "lag recovery must not inherit the initial replay limit"
    );
    assert_eq!(
        recovery.group_id_hex,
        Some(group_id_hex),
        "lag recovery must keep the caller's group filter"
    );
}

#[test]
fn messages_recovery_query_preserves_absent_group_filter() {
    // An all-groups subscription (group_id_hex == None) must recover across
    // all groups, still without a limit.
    let query = AppMessageQuery {
        group_id_hex: None,
        kinds: None,
        limit: Some(10),
    };
    let recovery = messages_recovery_query(&query);
    assert_eq!(recovery.group_id_hex, None);
    assert_eq!(recovery.limit, None);
}

#[test]
fn limited_subscription_recovery_suppresses_pre_subscription_history() {
    // Regression for the limited-snapshot lag-replay bug: a caller using
    // `limit: Some(N)` to avoid full-history replay must NOT receive the entire
    // older history as live updates on the first broadcast lag. Recovery drops
    // the limit and reloads the full group history, so the watermark
    // (the newest row that existed at subscription time = the last row of the
    // ascending limited snapshot) is what distinguishes pre-existing history
    // (suppress) from genuinely-new post-subscription messages (emit).
    //
    // Scenario: full history is rows recorded_at 10,20,30,40,50; a `limit: 2`
    // snapshot holds 40,50, so the watermark is (50, "id50"). On lag, recovery
    // reloads ALL five rows. Rows 10-50 are at/below the watermark and must be
    // suppressed; a genuinely-new row (60) arriving after subscription must be
    // emitted.
    // #630/#736: the watermark and every compared row are the SAME
    // `AppEventReplayCursor` the store orders by — `(recorded_at, message_id_hex,
    // insert_order)` — so the suppression boundary can never disagree with the
    // recovery query order.
    use storage_sqlite::AppEventReplayCursor;
    fn cur(recorded_at: u64, message_id_hex: &str, insert_order: i64) -> AppEventReplayCursor {
        AppEventReplayCursor {
            recorded_at,
            message_id_hex: message_id_hex.to_owned(),
            insert_order,
        }
    }
    let watermark = Some(cur(50, "id50", 5));
    let wm = watermark.as_ref();

    // Every pre-subscription row (including the watermark row itself) is
    // suppressed — even the ones the limited snapshot never contained (10/20/30),
    // and a same-second row with a SMALLER id (existed at subscription time).
    for row in [
        cur(10, "id10", 1),
        cur(20, "id20", 2),
        cur(30, "id30", 3),
        cur(40, "id40", 4),
        cur(50, "id40", 4),
        cur(50, "id50", 5),
    ] {
        assert!(
            recovery_row_is_pre_subscription(wm, &row),
            "row {row:?} at/below the watermark must be suppressed on recovery"
        );
    }

    // Genuinely-new rows strictly greater than the watermark are emitted:
    // a later second, and a same-second row with a greater id.
    assert!(
        !recovery_row_is_pre_subscription(wm, &cur(60, "id60", 6)),
        "a later-second message must be emitted"
    );
    assert!(
        !recovery_row_is_pre_subscription(wm, &cur(50, "id99", 7)),
        "same-second row with a greater id sorts after the watermark and must be emitted"
    );

    // Unscoped (all-groups) case: the same `message_id_hex` can appear in two
    // groups at the same second (it is unique only per group). `insert_order`
    // then distinguishes them: a later-inserted duplicate (strictly greater
    // cursor) is emitted, an earlier one is suppressed. A two-field key could
    // not tell these apart.
    let dup_watermark = Some(cur(50, "dup", 5));
    assert!(
        !recovery_row_is_pre_subscription(dup_watermark.as_ref(), &cur(50, "dup", 8)),
        "a later-inserted same-(recorded_at,id) row is genuinely new and must be emitted"
    );
    assert!(
        recovery_row_is_pre_subscription(dup_watermark.as_ref(), &cur(50, "dup", 3)),
        "an earlier-inserted same-(recorded_at,id) row existed already and must be suppressed"
    );

    // An empty snapshot has no watermark, so recovery suppresses nothing
    // (unchanged behavior for unlimited / empty-history subscriptions).
    assert!(!recovery_row_is_pre_subscription(None, &cur(10, "id10", 1)));
}

#[test]
fn lifecycle_refuses_account_open_after_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();

    lifecycle.begin_shutdown();

    assert!(matches!(
        lifecycle.begin_account_open(),
        Err(AppError::RuntimeStopping)
    ));
}

#[tokio::test]
async fn member_key_package_prewarm_refuses_work_after_shutdown_begins() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("alice")
        .unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        directory.path(),
        "wss://relay.example",
    ));
    runtime.shared.lifecycle().begin_shutdown();

    assert!(matches!(
        runtime
            .prewarm_group_member_key_packages(&account.label, &[])
            .await,
        Err(AppError::RuntimeStopping)
    ));
}

#[tokio::test]
async fn lifecycle_waits_for_account_opens_to_drain() {
    let lifecycle = RuntimeLifecycle::new();
    let permit = lifecycle
        .begin_account_open()
        .expect("account open should start before shutdown");

    let waiter = {
        let lifecycle = lifecycle.clone();
        tokio::spawn(async move {
            lifecycle
                .wait_for_account_opens_to_drain(Duration::from_secs(1))
                .await
        })
    };
    tokio::task::yield_now().await;
    drop(permit);

    assert!(waiter.await.expect("drain waiter should complete"));
}

#[tokio::test]
async fn account_manager_shutdown_drains_worker_inserted_by_in_flight_catch_up() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let manager = runtime.accounts.clone();
    let release_insertion = Arc::new(Notify::new());
    let release_for_catch_up = release_insertion.clone();
    let (catch_up_waiting_tx, catch_up_waiting_rx) = oneshot::channel();
    let workers = manager.workers.clone();
    let (worker_exited_tx, worker_exited_rx) = oneshot::channel();

    let catch_up = tokio::spawn(async move {
        let insertion_released = release_for_catch_up.notified();
        tokio::pin!(insertion_released);
        insertion_released.as_mut().enable();
        let _ = catch_up_waiting_tx.send(());
        insertion_released.await;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (commands, _command_rx) = mpsc::channel(1);
        let handle = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            let _ = worker_exited_tx.send(());
        });
        workers.lock().await.insert(
            "replacement".to_owned(),
            ManagedAccountWorker {
                ready: true,
                media_admission: std::sync::Arc::new(tokio::sync::Semaphore::new(
                    crate::runtime::MEDIA_COMMAND_QUEUE_LIMIT,
                )),
                handle,
                commands,
                shutdown: shutdown_tx,
            },
        );
    });
    manager
        .invite_catch_up_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .handles
        .push(catch_up);
    catch_up_waiting_rx
        .await
        .expect("catch-up should register its release waiter");

    let shutdown_manager = manager.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_manager.shutdown().await;
    });
    loop {
        let accepting = manager
            .invite_catch_up_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting;
        if !accepting {
            break;
        }
        tokio::task::yield_now().await;
    }
    release_insertion.notify_waiters();

    shutdown.await.expect("manager shutdown should complete");
    worker_exited_rx
        .await
        .expect("replacement worker should be shut down");
    assert!(manager.workers.lock().await.is_empty());
}

#[test]
fn invite_catch_up_is_not_spawned_after_shutdown_stops_accepting_tasks() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let manager = runtime.accounts.clone();
    manager
        .invite_catch_up_tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .accepting = false;

    let (command, _receiver) = mpsc::channel(1);
    manager.spawn_invite_catch_up(command);

    assert!(
        manager
            .invite_catch_up_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .handles
            .is_empty()
    );
}

// Sender-controlled broker candidates must clear the shared dial-safety gate
// at resolve time: literal-IP authorities resolve without DNS, so these cover
// the canonical non-public classes end to end (issue #331).
#[tokio::test]
async fn broker_resolve_rejects_non_public_candidates_without_dev_opt_in() {
    for authority in [
        "10.0.0.5:4433",      // private
        "169.254.169.254:80", // link-local (cloud metadata)
        "100.64.0.1:4433",    // CGNAT
        "192.168.1.1:4433",   // private
        "127.0.0.1:4433",     // loopback
        "[::1]:4433",         // loopback v6
        "[fc00::1]:4433",     // unique-local
    ] {
        let result = agent_stream_watch::resolve_broker_addr(authority, false).await;
        assert!(
            matches!(result, Err(AppError::AgentStreamInvalidCandidate(_))),
            "{authority} must be rejected without the dev opt-in"
        );
    }
}

#[tokio::test]
async fn broker_resolve_dev_opt_in_admits_loopback_only() {
    let addr = agent_stream_watch::resolve_broker_addr("127.0.0.1:4433", true)
        .await
        .expect("loopback resolves under the dev opt-in");
    assert!(addr.ip().is_loopback());

    // The opt-in opens loopback only; private/link-local candidates stay
    // rejected even in dev mode.
    for authority in ["10.0.0.5:4433", "169.254.169.254:80", "[fc00::1]:4433"] {
        let result = agent_stream_watch::resolve_broker_addr(authority, true).await;
        assert!(
            matches!(result, Err(AppError::AgentStreamInvalidCandidate(_))),
            "{authority} must be rejected even with the dev opt-in"
        );
    }
}

/// A group speaks for who you know only while you are actually in it. Each
/// state here excludes membership for a different reason, and getting any of
/// them wrong leaks the wrong people into search: an unaccepted invite is not
/// a relationship yet, a group you left has stopped being one, and a frozen
/// group cannot answer for its membership at all.
mod co_member_eligibility {
    use super::*;
    use crate::groups::{AppGroupAdminPolicyComponent, AppGroupMessageRetentionComponent};
    use crate::{AppGroupImageInput, SelfMembership};

    fn group() -> AppGroupRecord {
        AppGroupRecord::new(
            hex::encode([1u8; 16]),
            crate::groups::AppGroupNostrRoutingComponent::new(cgka_traits::NostrRoutingV1 {
                nostr_group_id: [2u8; 32],
                relays: vec!["wss://relay.example".to_owned()],
            })
            .expect("routing component"),
            "group".to_owned(),
            String::new(),
            AppGroupImageInput::default(),
            AppGroupAdminPolicyComponent::new(Vec::new()),
            AppGroupMessageRetentionComponent::disabled(),
        )
    }

    #[test]
    fn an_active_membership_contributes() {
        assert!(group_contributes_co_members(&group()));
    }

    #[test]
    fn an_archived_group_still_contributes() {
        // Archival is a presentation choice, not a change in who you know.
        let mut archived = group();
        archived.archived = true;
        assert!(group_contributes_co_members(&archived));
    }

    #[test]
    fn an_unaccepted_invite_contributes_nobody() {
        let mut pending = group();
        pending.pending_confirmation = true;
        assert!(!group_contributes_co_members(&pending));
    }

    #[test]
    fn a_departed_group_contributes_nobody() {
        for membership in [SelfMembership::Left, SelfMembership::Removed] {
            let mut departed = group();
            departed.self_membership = membership;
            assert!(!group_contributes_co_members(&departed));
        }
    }

    #[test]
    fn a_frozen_group_contributes_nobody() {
        let mut frozen = group();
        frozen.unrecoverable = true;
        assert!(!group_contributes_co_members(&frozen));
    }
}

#[test]
fn account_setup_request_debug_redacts_import_nsec() {
    let request = AccountSetupRequest {
        import_nsec: Some(Zeroizing::new(
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_owned(),
        )),
        ..AccountSetupRequest::default()
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("nsec1j4"));
    assert!(debug.contains("redacted"));
}

#[test]
fn account_setup_request_debug_redacts_nsec_shaped_identity() {
    let nsec = "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99";
    let request = AccountSetupRequest {
        identity: Some(nsec.to_owned()),
        ..AccountSetupRequest::default()
    };
    let debug = format!("{request:?}");
    assert!(!debug.contains("nsec1j4"));
    assert!(debug.contains("redacted"));
}

#[test]
fn account_setup_request_rejects_and_redacts_uppercase_nsec_identity() {
    let nsec = "NSEC1J4C6269Y9W0Q2ER2XJW8SV2EHYRTFXQ3JWGDLXJ6QFN8Z4GJSQ5QFVFK99";
    let request = AccountSetupRequest {
        identity: Some(nsec.to_owned()),
        ..AccountSetupRequest::default()
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("NSEC1J4"));
    assert!(debug.contains("redacted"));
    let err = validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)
        .expect_err("uppercase nsec-shaped identity must be rejected");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

#[test]
fn account_setup_validation_rejects_import_nsec_for_login_operation() {
    let request = AccountSetupRequest {
        import_nsec: Some(Zeroizing::new(
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_owned(),
        )),
        ..AccountSetupRequest::default()
    };
    let err = validate_account_setup_request(&request, AccountSetupOperation::Login)
        .expect_err("login must not accept import_nsec");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

#[test]
fn account_setup_validation_reports_identity_key_mismatch_without_leaking_secrets() {
    use nostr::prelude::ToBech32;
    let keys = nostr::Keys::generate();
    let other = nostr::Keys::generate();
    let request = AccountSetupRequest {
        identity: Some(keys.public_key().to_bech32().unwrap()),
        import_nsec: Some(Zeroizing::new(other.secret_key().to_bech32().unwrap())),
        ..AccountSetupRequest::default()
    };
    let err = validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)
        .expect_err("mismatched keys");
    assert!(matches!(err, AppError::IdentityKeyMismatch));
    let debug = format!("{err:?}");
    assert!(!debug.contains("nsec"));
}

#[test]
fn account_setup_validation_rejects_nsec_in_identity_field() {
    let request = AccountSetupRequest {
        identity: Some(
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_owned(),
        ),
        ..AccountSetupRequest::default()
    };
    let err = validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)
        .expect_err("nsec-shaped identity must be rejected");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

#[tokio::test]
async fn account_setup_rejects_conflicting_identity_and_import_nsec_before_mutation() {
    use nostr::prelude::ToBech32;
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());
    let keys = nostr::Keys::generate();
    let other = nostr::Keys::generate();
    let request = AccountSetupRequest {
        identity: Some(keys.public_key().to_bech32().unwrap()),
        import_nsec: Some(Zeroizing::new(other.secret_key().to_bech32().unwrap())),
        ..AccountSetupRequest::default()
    };
    let err = runtime
        .create_or_import_account(request)
        .await
        .expect_err("mismatched identity and import_nsec must be rejected");
    assert!(matches!(err, AppError::IdentityKeyMismatch));
    assert!(
        app.account_home().accounts().unwrap().is_empty(),
        "validation must run before account creation or import"
    );
}

#[test]
fn account_setup_validation_accepts_matching_identity_and_import_nsec() {
    use nostr::prelude::ToBech32;
    let keys = nostr::Keys::generate();
    let request = AccountSetupRequest {
        identity: Some(keys.public_key().to_bech32().unwrap()),
        import_nsec: Some(Zeroizing::new(keys.secret_key().to_bech32().unwrap())),
        ..AccountSetupRequest::default()
    };
    validate_account_setup_request(&request, AccountSetupOperation::CreateOrImport)
        .expect("matching keys");
}

#[tokio::test]
async fn account_setup_login_rejects_import_nsec_sidecar() {
    use nostr::prelude::ToBech32;
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let keys = nostr::Keys::generate();
    let request = AccountSetupRequest {
        import_nsec: Some(Zeroizing::new(keys.secret_key().to_bech32().unwrap())),
        ..AccountSetupRequest::default()
    };
    let err = runtime
        .login(keys.public_key().to_bech32().unwrap(), request)
        .await
        .expect_err("login must not accept import_nsec");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

#[tokio::test]
async fn account_setup_login_rejects_nsec_shaped_identity_argument() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let err = runtime
        .login(
            "NSEC1J4C6269Y9W0Q2ER2XJW8SV2EHYRTFXQ3JWGDLXJ6QFN8Z4GJSQ5QFVFK99",
            AccountSetupRequest::default(),
        )
        .await
        .expect_err("login must reject nsec-shaped identity");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

#[tokio::test]
async fn account_setup_create_identity_rejects_import_nsec_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(dir.path(), "wss://relay.example"));
    let request = AccountSetupRequest {
        import_nsec: Some(Zeroizing::new(
            "nsec1j4c6269y9w0q2er2xjw8sv2ehyrtfxq3jwgdlxj6qfn8z4gjsq5qfvfk99".to_owned(),
        )),
        ..AccountSetupRequest::default()
    };
    let err = runtime
        .create_identity(request)
        .await
        .expect_err("create_identity must not accept import_nsec");
    assert!(matches!(err, AppError::UnexpectedPrivateKey));
}

fn install_local_open_gate(
    app: &MarmotApp,
    account_ref: &str,
) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let (reached_tx, reached_rx) = std::sync::mpsc::channel();
    let (proceed_tx, proceed_rx) = std::sync::mpsc::channel();
    app.install_local_open_gate(account_ref, reached_tx, proceed_rx)
        .expect("install local-open gate");
    (reached_rx, proceed_tx)
}

async fn wait_for_test_signal(receiver: std::sync::mpsc::Receiver<()>, signal: &'static str) {
    tokio::task::spawn_blocking(move || {
        receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|err| panic!("timed out waiting for {signal}: {err}"));
    })
    .await
    .expect("test signal waiter");
}

async fn open_runtime_local_test_client(
    app: &MarmotApp,
    runtime: &MarmotAppRuntime,
    account_ref: &str,
) -> crate::AppClient {
    let shared = runtime.shared_services();
    app.runtime_local_client(account_ref, shared.relay_plane(), shared.lifecycle())
        .await
        .expect("open local test client")
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_startup_is_reaped() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let account = app.account_home().create_account("alice").unwrap();
    let runtime = app.runtime();
    let manager = runtime.accounts();
    let (reached, proceed) = install_local_open_gate(&app, "alice");
    let starting = manager.clone();
    let reconcile = tokio::spawn(async move { starting.reconcile().await });
    wait_for_test_signal(reached, "account open before cancellation").await;
    reconcile.abort();
    assert!(reconcile.await.unwrap_err().is_cancelled());
    let old_commands = {
        let workers = manager.workers.lock().await;
        let worker = workers.get(&account.account_id_hex).unwrap();
        assert!(!worker.ready);
        worker.commands.clone()
    };

    // A cancelled startup remains fenced without holding the global worker
    // transaction while its old session is still open.
    let premature = timeout(Duration::from_secs(1), manager.worker_commands("alice"))
        .await
        .expect("lookup returns promptly")
        .expect_err("abandoned open must not admit a replacement");
    assert!(matches!(premature, AppError::BlockingTask(_)));
    proceed.send(()).unwrap();
    let commands = timeout(Duration::from_secs(10), async {
        loop {
            match manager.worker_commands("alice").await {
                Ok(commands) => break commands,
                Err(AppError::BlockingTask(_)) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected replacement error: {error}"),
            }
        }
    })
    .await
    .expect("replacement opens after the old session releases");
    assert!(!commands.same_channel(&old_commands));
    assert!(manager.workers.lock().await[&account.account_id_hex].ready);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn reconcile_failure_waits_for_sibling_and_preserves_its_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .expect("create alice");
    marmot_account::AccountHome::open(dir.path())
        .create_account("bob")
        .expect("create bob");
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());
    let alice_client = open_runtime_local_test_client(&app, &runtime, "alice").await;
    let (alice_reached, alice_proceed) = install_local_open_gate(&app, "alice");
    let (bob_reached, bob_proceed) = install_local_open_gate(&app, "bob");

    let reconcile_runtime = runtime.clone();
    let reconcile = tokio::spawn(async move { reconcile_runtime.reconcile_accounts().await });
    let ((), ()) = tokio::join!(
        wait_for_test_signal(alice_reached, "alice open result"),
        wait_for_test_signal(bob_reached, "bob open result"),
    );

    alice_proceed.send(()).expect("release alice open result");
    timeout(Duration::from_secs(5), async {
        loop {
            if runtime.app_performance_snapshot().account_open.attempts == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Alice's failure is observed before Bob is released");
    assert!(
        !reconcile.is_finished(),
        "reconcile must consume Bob's pending readiness result"
    );
    bob_proceed.send(()).expect("release bob open result");

    let err = reconcile
        .await
        .expect("reconcile task")
        .expect_err("reconcile should fail while alice is busy");
    assert!(matches!(err, AppError::AccountSessionBusy));
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 2);
    runtime
        .accounts()
        .worker_commands("bob")
        .await
        .expect("Bob remains ready");
    drop(alice_client);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_account_startup_preserves_ready_sibling() {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = marmot_account::AccountHome::open(dir.path());
    let alice = home.create_account("alice").expect("create alice");
    let bob = home.create_account("bob").expect("create bob");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let runtime = MarmotAppRuntime::new(app.clone());
    let alice_client = open_runtime_local_test_client(&app, &runtime, "alice").await;
    let (alice_reached, alice_proceed) = install_local_open_gate(&app, "alice");
    let (bob_reached, bob_proceed) = install_local_open_gate(&app, "bob");

    let manager = runtime.accounts();
    let starting = manager.clone();
    let reconcile = tokio::spawn(async move { starting.reconcile().await });
    let ((), ()) = tokio::join!(
        wait_for_test_signal(alice_reached, "alice open"),
        wait_for_test_signal(bob_reached, "bob open"),
    );
    bob_proceed.send(()).expect("release healthy bob");
    timeout(Duration::from_secs(5), async {
        loop {
            if manager.workers.lock().await[&bob.account_id_hex].ready {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Bob becomes ready while Alice still waits");
    let bob_commands = timeout(Duration::from_secs(1), manager.worker_commands("bob"))
        .await
        .expect("Bob must not wait for Alice's lifecycle transaction")
        .expect("Bob serves commands");
    alice_proceed.send(()).expect("release failing alice");
    assert!(matches!(
        reconcile.await.expect("reconcile task"),
        Err(AppError::AccountSessionBusy)
    ));

    let workers = manager.workers.lock().await;
    assert!(!workers.contains_key(&alice.account_id_hex));
    assert!(workers[&bob.account_id_hex].ready);
    drop(workers);
    let bob_after = manager
        .worker_commands("bob")
        .await
        .expect("bob remains usable");
    assert!(bob_after.same_channel(&bob_commands));
    drop(alice_client);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_worker_startup_is_suppressed_until_explicit_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let alice = app
        .account_home()
        .create_account("alice")
        .expect("create alice");
    let runtime = MarmotAppRuntime::new(app.clone());
    let manager = runtime.accounts();
    let alice_client = open_runtime_local_test_client(&app, &runtime, "alice").await;
    assert!(matches!(
        manager.reconcile().await,
        Err(AppError::AccountSessionBusy)
    ));
    manager
        .startup_retries
        .lock()
        .unwrap()
        .extend_deadline_for_test(&alice.account_id_hex, Duration::from_secs(60));
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 1);

    for _ in 0..3 {
        let error = manager
            .worker_commands("alice")
            .await
            .expect_err("retry deferred");
        assert!(matches!(error, AppError::BlockingTask(_)));
        assert!(manager.reconcile().await.is_err());
    }
    assert!(manager.worker_commands_for_setup("alice").await.is_err());
    assert!(manager.media_worker_commands("alice").await.is_err());
    let snapshot = runtime.app_performance_snapshot();
    assert_eq!(
        snapshot.account_open.attempts, 1,
        "cooldown must not spawn more workers"
    );
    let suppressed = snapshot
        .runtime_operations
        .iter()
        .find(|operation| operation.operation == RuntimeOp::AccountStartupRetrySuppressed)
        .expect("suppression operation");
    assert_eq!(suppressed.not_ready, 8);

    app.account_home()
        .create_account("bob")
        .expect("create healthy Bob");
    assert!(
        manager.reconcile().await.is_err(),
        "Alice is still cooling down"
    );
    manager
        .worker_commands("bob")
        .await
        .expect("Bob starts during Alice's cooldown");
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 2);

    drop(alice_client);
    manager
        .restart_account(&alice.account_id_hex)
        .await
        .expect("explicit restart");
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 3);
    manager
        .worker_commands("alice")
        .await
        .expect("ready fast path");
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 3);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn signed_out_account_stays_gated_until_explicit_sign_in() {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let alice = app
        .account_home()
        .create_account("alice")
        .expect("create alice");
    let runtime = MarmotAppRuntime::new(app.clone());
    let manager = runtime.accounts();
    let alice_client = open_runtime_local_test_client(&app, &runtime, "alice").await;
    assert!(matches!(
        manager.reconcile().await,
        Err(AppError::AccountSessionBusy)
    ));
    manager.deactivate_account("alice").await.expect("sign out");
    manager
        .restart_account(&alice.account_id_hex)
        .await
        .expect("signed-out restart is gated");
    assert!(
        !manager
            .workers
            .lock()
            .await
            .contains_key(&alice.account_id_hex)
    );
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 1);

    drop(alice_client);
    let signed_in = manager
        .sign_in_account("alice")
        .await
        .expect("explicit sign-in");
    assert!(signed_in.running);
    assert_eq!(runtime.app_performance_snapshot().account_open.attempts, 2);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn stuck_worker_reap_does_not_block_a_healthy_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let alice = app
        .account_home()
        .create_account("alice")
        .expect("create alice");
    let bob = app
        .account_home()
        .create_account("bob")
        .expect("create bob");
    let runtime = MarmotAppRuntime::new(app);
    let manager = runtime.accounts();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (shutdown, _shutdown_rx) = oneshot::channel();
    let (commands, _receiver) = mpsc::channel(1);
    manager.workers.lock().await.insert(
        alice.account_id_hex.clone(),
        ManagedAccountWorker {
            ready: false,
            handle: tokio::task::spawn_blocking(move || {
                let _ = release_rx.recv();
            }),
            commands,
            media_admission: Arc::new(Semaphore::new(MEDIA_COMMAND_QUEUE_LIMIT)),
            shutdown,
        },
    );

    let outcome = timeout(Duration::from_secs(12), manager.reconcile()).await;
    let bob_ready = manager
        .workers
        .lock()
        .await
        .get(&bob.account_id_hex)
        .is_some_and(|w| w.ready);
    let error = outcome
        .expect("unrelated cleanup must not hold the global transaction")
        .expect_err("Alice remains fenced while her worker exits");
    assert!(matches!(error, AppError::BlockingTask(_)));
    assert!(
        bob_ready,
        "Bob must start while Alice's cleanup is unfinished"
    );
    assert!(
        timeout(Duration::from_secs(1), manager.reconcile())
            .await
            .expect("later reconcile must not wait for Alice's cleanup")
            .is_err()
    );
    release_tx.send(()).expect("release stuck worker");
    manager
        .restart_account(&alice.account_id_hex)
        .await
        .expect("Alice starts after cleanup");
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn deactivation_waits_for_worker_abort_before_committing_sign_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let alice = app
        .account_home()
        .create_account("alice")
        .expect("create alice");
    let runtime = MarmotAppRuntime::new(app);
    let manager = runtime.accounts();
    let (shutdown, _shutdown_rx) = oneshot::channel();
    let (commands, _commands_rx) = mpsc::channel(1);
    manager.workers.lock().await.insert(
        alice.account_id_hex.clone(),
        ManagedAccountWorker {
            ready: true,
            handle: tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
            commands,
            media_admission: Arc::new(Semaphore::new(MEDIA_COMMAND_QUEUE_LIMIT)),
            shutdown,
        },
    );

    timeout(Duration::from_secs(8), manager.deactivate_account("alice"))
        .await
        .expect("abort and reaper must finish after the worker's grace period")
        .expect("ordinary slow shutdown must not fail deactivation");
    assert!(manager.resolve("alice").unwrap().signed_out);
    assert!(
        !manager
            .workers
            .lock()
            .await
            .contains_key(&alice.account_id_hex)
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_reconcile_keeps_ready_worker_and_suppresses_failed_account() {
    let dir = tempfile::tempdir().expect("tempdir");
    let alice = marmot_account::AccountHome::open(dir.path())
        .create_account("alice")
        .expect("create alice");
    marmot_account::AccountHome::open(dir.path())
        .create_account("bob")
        .expect("create bob");
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());
    let alice_client = open_runtime_local_test_client(&app, &runtime, "alice").await;
    let (alice_reached, alice_proceed) = install_local_open_gate(&app, "alice");
    let (bob_reached, bob_proceed) = install_local_open_gate(&app, "bob");

    let accounts_a = runtime.accounts();
    let reconcile_a = tokio::spawn(async move { accounts_a.reconcile().await });
    let ((), ()) = tokio::join!(
        wait_for_test_signal(alice_reached, "alice open result"),
        wait_for_test_signal(bob_reached, "bob open result"),
    );

    let accounts_b = runtime.accounts();
    let (b_started_tx, b_started_rx) = std::sync::mpsc::channel();
    let reconcile_b = tokio::spawn(async move {
        b_started_tx.send(()).expect("signal reconcile B start");
        accounts_b.reconcile().await
    });
    wait_for_test_signal(b_started_rx, "reconcile B start").await;
    tokio::task::yield_now().await;
    assert!(
        !reconcile_b.is_finished(),
        "reconcile B must wait for A to settle all attempted workers"
    );

    alice_proceed.send(()).expect("release alice open result");
    bob_proceed.send(()).expect("release bob open result");

    let err_a = reconcile_a
        .await
        .expect("reconcile A task")
        .expect_err("reconcile A should preserve Alice's captured busy error");
    assert!(matches!(err_a, AppError::AccountSessionBusy));
    let err_b = reconcile_b
        .await
        .expect("reconcile B task")
        .expect_err("Alice is cooling down");
    assert!(matches!(err_b, AppError::BlockingTask(_)));
    runtime
        .accounts()
        .worker_commands("bob")
        .await
        .expect("Bob remains ready");
    drop(alice_client);
    runtime
        .accounts()
        .restart_account(&alice.account_id_hex)
        .await
        .expect("explicit retry starts Alice");

    let managed = runtime
        .accounts()
        .managed_accounts()
        .expect("managed accounts");
    let tested = managed
        .iter()
        .filter(|account| account.label == "alice" || account.label == "bob")
        .collect::<Vec<_>>();
    assert_eq!(tested.len(), 2, "both test accounts must remain managed");
    assert!(
        tested.iter().all(|account| account.running),
        "successful reconcile B must retain both running workers"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn account_worker_response_deadline_reports_unknown_completion() {
    let (_respond, response) = tokio::sync::oneshot::channel::<Result<(), AppError>>();
    let error = account_worker_response_with_wait(response, Duration::from_millis(1))
        .await
        .expect_err("an open response channel must not wait forever");
    assert!(matches!(error, AppError::AccountWorkerResponseTimedOut));
}

fn transient_transport_catch_up_failure() -> AccountCatchUpFailure {
    AccountCatchUpFailure::new(
        "runtime catch-up failed: account_transport".into(),
        SyncFailureClassification::new(
            SyncFailureStage::TransportActivation,
            SyncErrorClass::Unknown,
        ),
    )
}

#[tokio::test]
async fn catch_up_retries_only_the_worker_with_a_transient_transport_failure() {
    let (flaky_tx, mut flaky_rx) = mpsc::channel(4);
    let flaky = tokio::spawn(async move {
        let mut attempts = 0;
        while let Some(command) = flaky_rx.recv().await {
            let AccountWorkerCommand::CatchUp { respond } = command else {
                panic!("unexpected worker command");
            };
            attempts += 1;
            let result = if attempts == 1 {
                Err(transient_transport_catch_up_failure())
            } else {
                Ok(())
            };
            let _ = respond.send(result);
            if attempts == 2 {
                return attempts;
            }
        }
        attempts
    });
    let (healthy_tx, mut healthy_rx) = mpsc::channel(4);
    let healthy = tokio::spawn(async move {
        let Some(AccountWorkerCommand::CatchUp { respond }) = healthy_rx.recv().await else {
            panic!("expected catch-up command");
        };
        let _ = respond.send(Ok(()));
        1
    });

    catch_up_account_commands_with_retry(
        vec![flaky_tx, healthy_tx],
        Duration::from_secs(1),
        &[Duration::ZERO],
    )
    .await
    .expect("the transient worker should recover");

    assert_eq!(flaky.await.unwrap(), 2);
    assert_eq!(healthy.await.unwrap(), 1);
}

#[tokio::test]
async fn catch_up_returns_after_transient_retry_budget_is_exhausted() {
    let (worker_tx, mut worker_rx) = mpsc::channel(8);
    let worker = tokio::spawn(async move {
        let mut attempts = 0;
        while let Some(command) = worker_rx.recv().await {
            let AccountWorkerCommand::CatchUp { respond } = command else {
                panic!("unexpected worker command");
            };
            attempts += 1;
            let _ = respond.send(Err(transient_transport_catch_up_failure()));
            if attempts == 3 {
                return attempts;
            }
        }
        attempts
    });

    let error = catch_up_account_commands_with_retry(
        vec![worker_tx],
        Duration::from_secs(1),
        &[Duration::ZERO, Duration::ZERO],
    )
    .await
    .expect_err("a permanently failing worker must still surface its error");

    assert!(matches!(error, AppError::AccountCatchUp(_)));
    assert_eq!(worker.await.unwrap(), 3);
}

#[tokio::test]
async fn catch_up_does_not_retry_a_closed_worker_response() {
    let (worker_tx, mut worker_rx) = mpsc::channel(2);
    let worker = tokio::spawn(async move {
        let Some(AccountWorkerCommand::CatchUp { respond }) = worker_rx.recv().await else {
            panic!("expected catch-up command");
        };
        drop(respond);

        if let Ok(Some(_)) = timeout(Duration::from_millis(50), worker_rx.recv()).await {
            panic!("a closed worker response cannot recover on the same channel");
        }
    });

    let error = catch_up_account_commands_with_retry(
        vec![worker_tx],
        Duration::from_secs(1),
        &[Duration::ZERO],
    )
    .await
    .expect_err("a closed worker response must remain terminal");

    assert!(matches!(error, AppError::TransportClosed));
    worker.await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn catch_up_error_from_ready_account_takes_precedence_over_sibling_backoff() {
    let dir = tempfile::tempdir().expect("tempdir");
    let app = MarmotApp::with_relays(dir.path(), vec![]);
    let alice = app
        .account_home()
        .create_account("alice")
        .expect("create alice");
    let bob = app
        .account_home()
        .create_account("bob")
        .expect("create bob");
    let runtime = MarmotAppRuntime::new(app);
    let manager = runtime.accounts();
    {
        let mut retries = manager.startup_retries.lock().unwrap();
        retries.fail(alice.account_id_hex.clone(), tokio::time::Instant::now());
        retries.extend_deadline_for_test(&alice.account_id_hex, Duration::from_secs(60));
    }

    let (shutdown, mut shutdown_rx) = oneshot::channel();
    let (commands, mut receiver) = mpsc::channel(1);
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                command = receiver.recv() => match command {
                    Some(AccountWorkerCommand::CatchUp { respond }) => drop(respond),
                    Some(_) => panic!("unexpected worker command"),
                    None => break,
                }
            }
        }
    });
    manager.workers.lock().await.insert(
        bob.account_id_hex,
        ManagedAccountWorker {
            ready: true,
            handle,
            commands,
            media_admission: Arc::new(Semaphore::new(MEDIA_COMMAND_QUEUE_LIMIT)),
            shutdown,
        },
    );

    let error = manager
        .catch_up_accounts()
        .await
        .expect_err("Bob's failed catch-up must surface");
    assert!(matches!(error, AppError::TransportClosed));
    runtime.shutdown().await;
}

#[test]
fn key_package_deletion_relay_failures_dedupe_privacy_safe_publish_endpoint_categories() {
    use crate::KeyPackageDeletionResult;

    let hostile_summary = "publish failed: https://evil.example/nip42";
    let hostile_reason = "blocked: attacker-controlled suffix at wss://leak.example";
    let transport_error =
        TransportAdapterError::PublishEndpoints(TransportPublishFailure::with_endpoint_failures(
            hostile_summary,
            vec![
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://relay-a.example".into()),
                    reason: hostile_reason.to_owned(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                },
                TransportEndpointFailure {
                    endpoint: TransportEndpoint("wss://relay-b.example".into()),
                    reason: hostile_reason.to_owned(),
                    kind: TransportEndpointFailureKind::TerminalRejected,
                    rejection_category: Some(TransportEndpointRejectionCategory::Blocked),
                },
            ],
        ));
    let err = AppError::Transport(transport_error);

    let wipe_reason = wipe_failure_reason(&err);
    assert_eq!(wipe_reason, "relay rejected event (blocked)");
    assert!(!wipe_reason.contains("evil.example"));

    let (deleted, failures) =
        relay_failures_from_key_package_deletion_results(vec![KeyPackageDeletionResult {
            event_id_hex: "11".repeat(32),
            result: Err(err),
        }]);
    assert_eq!(deleted, 0);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].reason, "relay rejected event (blocked)");
    assert!(!failures[0].reason.contains("evil.example"));
    assert!(!failures[0].reason.contains("leak.example"));
    assert!(!failures[0].reason.contains("attacker-controlled"));
}

#[tokio::test]
async fn message_journey_overflow() {
    let root = tempfile::tempdir().unwrap();
    let account = marmot_account::AccountHome::open(root.path())
        .create_account("sender")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(root.path(), "wss://journey.example").with_test_relay_client(relay);
    let mut client = app.client("sender").await.unwrap();
    let group = client.create_group("journey", &[]).await.unwrap();
    let runtime = app.runtime();
    let mut timeline = runtime
        .subscribe_timeline_messages(
            "sender",
            TimelineMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(timeline.take_snapshot().messages.is_empty());
    let sent = client
        .send(&group, b"recover missed projection")
        .await
        .unwrap();
    for _ in 0..2 {
        let mut observer = runtime.subscribe();
        // No await: the single-thread executor cannot drain the 1024-event ring.
        for _ in 0..2048 {
            runtime
                .events
                .send(MarmotAppEvent::GroupStateUpdated {
                    account_id_hex: account.account_id_hex.clone(),
                    account_label: account.label.clone(),
                    group_id: group.clone(),
                })
                .unwrap();
        }
        assert!(matches!(
            observer.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        let update = tokio::time::timeout(Duration::from_secs(5), timeline.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(update, RuntimeTimelineMessageUpdate::Page { .. }));
        let page = timeline.take_snapshot();
        assert_eq!(
            page.messages.len(),
            1,
            "each gap refreshes authoritative state without duplicates"
        );
        assert_eq!(page.messages[0].message_id_hex, sent.message_ids[0]);
        assert!(page.messages[0].source_message_id_hex.is_some());
    }
    drop(client);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn accepted_edit_emits_content_row_and_recovered_snapshot_without_activity() {
    let root = tempfile::tempdir().unwrap();
    let account = AccountHome::open(root.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(root.path(), "wss://test.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("edits", &[]).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let storage = app.account_storage("alice").unwrap();
    let original = storage_sqlite::StoredAppEvent {
        group_id_hex: group_hex.clone(),
        message_id_hex: "01".repeat(32),
        source_message_id_hex: Some("02".repeat(32)),
        source_epoch: Some(0),
        direction: "received".into(),
        sender: "ee".repeat(32),
        plaintext: "original".into(),
        kind: 9,
        tags: vec![],
        recorded_at: 1,
        received_at: 1,
        origin_commit_id: None,
        moderation_grant: false,
    };
    let update = storage.record_app_event(&original).unwrap();
    app.app_projection_update("alice", update).unwrap();
    let runtime = app.runtime();
    let mut subscription = runtime.subscribe_chat_list("alice", false).await.unwrap();
    let before = subscription
        .snapshot
        .iter()
        .find(|r| r.group_id_hex == group_hex)
        .unwrap()
        .clone();
    let mut edit = original.clone();
    edit.message_id_hex = "03".repeat(32);
    edit.source_message_id_hex = Some("04".repeat(32));
    edit.kind = 1009;
    edit.recorded_at = 2;
    edit.plaintext = "**edited**".into();
    edit.tags = vec![vec!["e".into(), original.message_id_hex.clone()]];
    let update = app
        .app_projection_update("alice", storage.record_app_event(&edit).unwrap())
        .unwrap();
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::LastMessageContentChanged
    );
    runtime
        .events
        .send(MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
            account_id_hex: account.account_id_hex.clone(),
            account_label: "alice".into(),
            update,
        }))
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(3), subscription.recv())
        .await
        .unwrap()
        .unwrap();
    let RuntimeChatListUpdate::Row { trigger, row } = event else {
        panic!("expected changed row")
    };
    assert_eq!(trigger, ChatListUpdateTrigger::LastMessageContentChanged);
    assert_eq!(row.last_message.as_ref().unwrap().plaintext, "**edited**");
    assert_eq!(row.unread_count, before.unread_count);
    assert_eq!(
        row.last_message.as_ref().unwrap().message_id_hex,
        before.last_message.as_ref().unwrap().message_id_hex
    );
    assert_eq!(
        row.last_message.as_ref().unwrap().timeline_at,
        before.last_message.as_ref().unwrap().timeline_at
    );
    let recovered = runtime.subscribe_chat_list("alice", false).await.unwrap();
    assert_eq!(
        recovered
            .snapshot
            .iter()
            .find(|r| r.group_id_hex == group_hex)
            .unwrap()
            .last_message,
        row.last_message
    );
    edit.message_id_hex = "05".repeat(32);
    edit.source_message_id_hex = Some("06".repeat(32));
    edit.recorded_at = 3;
    edit.plaintext = "after lag".into();
    let update = app
        .app_projection_update("alice", storage.record_app_event(&edit).unwrap())
        .unwrap();
    let event = MarmotAppEvent::ProjectionUpdated(RuntimeProjectionUpdate {
        account_id_hex: account.account_id_hex,
        account_label: "alice".into(),
        update,
    });
    // No await in this current-thread test: overflow before the subscriber can drain.
    for _ in 0..4096 {
        runtime.events.send(event.clone()).unwrap();
    }
    let recovered_event = tokio::time::timeout(Duration::from_secs(3), subscription.recv())
        .await
        .unwrap()
        .unwrap();
    let RuntimeChatListUpdate::Row {
        trigger,
        row: recovered,
    } = recovered_event
    else {
        panic!("expected row reconciled from lag recovery snapshot");
    };
    assert_eq!(trigger, ChatListUpdateTrigger::SnapshotRefresh);
    assert_eq!(
        recovered.last_message.as_ref().unwrap().plaintext,
        "after lag"
    );
    assert_eq!(recovered.unread_count, before.unread_count);
    let mut older = original.clone();
    older.message_id_hex = "07".repeat(32);
    older.source_message_id_hex = Some("08".repeat(32));
    older.recorded_at = 0;
    app.app_projection_update("alice", storage.record_app_event(&older).unwrap())
        .unwrap();
    let mut older_edit = edit.clone();
    older_edit.message_id_hex = "09".repeat(32);
    older_edit.source_message_id_hex = Some("0a".repeat(32));
    older_edit.tags[0][1] = older.message_id_hex;
    let update = app
        .app_projection_update("alice", storage.record_app_event(&older_edit).unwrap())
        .unwrap();
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::SnapshotRefresh,
        "older edits do not change the selected preview"
    );
    let mut retract = edit.clone();
    retract.message_id_hex = "0b".repeat(32);
    retract.source_message_id_hex = Some("0c".repeat(32));
    retract.kind = 5;
    retract.tags[0][1] = edit.message_id_hex;
    let update = app
        .app_projection_update("alice", storage.record_app_event(&retract).unwrap())
        .unwrap();
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::LastMessageContentChanged,
        "retracting the winner changes effective content"
    );
    assert_eq!(
        update
            .chat_list_row
            .unwrap()
            .last_message
            .unwrap()
            .plaintext,
        "**edited**"
    );
    // Catch-up can combine a backfilled message with an edit of the selection.
    // The content-only refinement must preserve the batch's stronger trigger.
    let mut backfill = original.clone();
    backfill.message_id_hex = "0d".repeat(32);
    backfill.source_message_id_hex = Some("0e".repeat(32));
    backfill.recorded_at = 0;
    let backfill_update = storage.record_app_event(&backfill).unwrap();
    let mut batch_edit = original.clone();
    batch_edit.message_id_hex = "0f".repeat(32);
    batch_edit.source_message_id_hex = Some("10".repeat(32));
    batch_edit.kind = 1009;
    batch_edit.recorded_at = 4;
    batch_edit.plaintext = "batch edit".into();
    batch_edit.tags = vec![vec!["e".into(), original.message_id_hex.clone()]];
    let mut batch = storage.record_app_event(&batch_edit).unwrap();
    batch.changes.extend(backfill_update.changes);
    let update = app.app_projection_update("alice", batch).unwrap();
    assert_eq!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::NewLastMessage
    );
    assert_eq!(
        update
            .chat_list_row
            .unwrap()
            .last_message
            .unwrap()
            .plaintext,
        "batch edit"
    );
    let update = app
        .invalidate_timeline_source_message(
            "alice",
            original.source_message_id_hex.as_ref().unwrap(),
            "losing branch",
        )
        .unwrap()
        .unwrap();
    assert_ne!(
        update.chat_list_trigger,
        ChatListUpdateTrigger::LastMessageContentChanged,
        "invalidation can replace the selected message"
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn recovery_preserves_persisted_authority_after_reopen() {
    use cgka_traits::app_event::{AppMessageAuthority, MARMOT_APP_EVENT_KIND_REVIEW};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    let key = storage_sqlite::SqlCipherKey::new("authority replay test key").unwrap();
    let evidence = [
        None,
        Some(AppMessageAuthority {
            source_context: [42; 32],
            moderation_grant: true,
        }),
        Some(AppMessageAuthority {
            source_context: [43; 32],
            moderation_grant: false,
        }),
        None,
    ];
    let storage = storage_sqlite::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    for (index, authority) in evidence.into_iter().enumerate() {
        let event = storage_sqlite::StoredAppEvent {
            group_id_hex: "aa".into(),
            message_id_hex: format!("{index:064x}"),
            source_message_id_hex: Some(format!("{:064x}", index + 100)),
            source_epoch: Some(7),
            direction: "received".into(),
            sender: "ab".repeat(32),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_REVIEW,
            tags: vec![],
            recorded_at: index as u64,
            received_at: index as u64,
            origin_commit_id: None,
            moderation_grant: index == 3,
        };
        if index == 3 {
            // Legacy grants alone are not reconstructed as source evidence.
            storage.record_app_event(&event).unwrap();
        } else {
            storage
                .record_app_event_with_source(&event, None, authority)
                .unwrap();
        }
    }
    storage.close().unwrap();
    let storage = storage_sqlite::SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let rows = storage
        .app_messages(storage_sqlite::StoredAppMessageQuery {
            group_id_hex: Some("aa".into()),
            kinds: None,
            limit: Some(4),
        })
        .unwrap();
    assert_eq!(rows.len(), 4);
    for (row, authority) in rows.into_iter().zip(evidence) {
        assert_eq!(row.authority, authority);
        assert_eq!(
            storage
                .app_message("aa", &row.message_id_hex)
                .unwrap()
                .unwrap()
                .authority,
            authority
        );
        let record = crate::conversions::app_message_record_from_stored(row);
        let record: AppMessageRecord =
            serde_json::from_value(serde_json::to_value(record).unwrap()).unwrap();
        let update =
            received_message_update_from_record("account", "alice", record, &HashMap::new())
                .unwrap();
        let RuntimeMessageUpdate::Message(received) = update else {
            panic!("expected message")
        };
        assert_eq!(received.message.source_epoch, 7);
        assert_eq!(received.message.authority, authority);
    }
}

#[tokio::test]
async fn system_reactions_update_live_timeline_through_existing_commands() {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, group_system_event_material};
    use cgka_traits::engine::{GroupEvent, GroupStateChange};
    let root = tempfile::tempdir().unwrap();
    let account = AccountHome::open(root.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(root.path(), "wss://test.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("system reactions", &[]).await.unwrap();
    let actor = cgka_traits::MemberId::new(hex::decode(&account.account_id_hex).unwrap());
    let change = GroupStateChange::GroupRenamed {
        name: "renamed".into(),
        previous_name: Some("system reactions".into()),
    };
    let material = group_system_event_material(&group, 0, Some(&actor), &change).unwrap();
    let event = GroupEvent::GroupStateChanged {
        group_id: group.clone(),
        epoch: cgka_traits::EpochId(0),
        actor: Some(actor),
        change,
        origin_commit_id: None,
    };
    assert_eq!(
        client
            .project_group_system_rows(std::slice::from_ref(&event), 1)
            .len(),
        1
    );
    // Deliberately replay the same authenticated change. The snapshot and
    // final history assertions below must still see exactly one original row.
    client.project_group_system_rows(&[event], 1);
    drop(client);
    let runtime = app.runtime();
    let mut timeline = runtime
        .subscribe_timeline_messages(
            "alice",
            TimelineMessageQuery {
                group_id_hex: Some(material.group_id_hex.clone()),
                pagination: storage_sqlite::TimelinePagination {
                    limit: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let baseline = timeline.take_snapshot();
    assert_eq!(baseline.messages.len(), 1);
    assert_eq!(baseline.messages[0].message_id_hex, material.message_id_hex);
    assert_eq!(
        baseline.messages[0].kind,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
    );
    let first = runtime
        .react_to_message("alice", &group, &material.message_id_hex, "👍")
        .await
        .unwrap();
    let duplicate = runtime
        .react_to_message("alice", &group, &material.message_id_hex, "👍")
        .await
        .unwrap();
    assert_eq!(first.message_ids, duplicate.message_ids);
    assert_eq!(duplicate.published, 0);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            timeline.recv().await.expect("live reaction update");
            let page = timeline.take_snapshot();
            assert_eq!(page.messages.len(), 1);
            if !page.messages[0].reactions.user_reactions.is_empty() {
                let mut row = page.messages[0].clone();
                assert_eq!(row.reactions.user_reactions.len(), 1);
                assert_eq!(
                    row.reactions.user_reactions[0].target_message_id_hex,
                    material.message_id_hex
                );
                row.reactions = baseline.messages[0].reactions.clone();
                assert_eq!(row, baseline.messages[0]);
                break;
            }
        }
    })
    .await
    .unwrap();
    runtime
        .unreact_from_message("alice", &group, &material.message_id_hex)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            timeline.recv().await.expect("live reaction removal");
            let page = timeline.take_snapshot();
            if page.messages[0].reactions.user_reactions.is_empty() {
                assert_eq!(page.messages, baseline.messages);
                break;
            }
        }
    })
    .await
    .unwrap();
    // The only transmitted application intents are kind 7 and kind 5. The
    // kind-1210 target remains the one locally synthesized row with no source.
    let records = app.messages("alice").unwrap();
    let system = records
        .iter()
        .filter(|r| r.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM)
        .collect::<Vec<_>>();
    assert_eq!(system.len(), 1);
    assert_eq!(system[0].direction, "system");
    assert!(baseline.messages[0].source_message_id_hex.is_none());
    let mut sent_kinds = records
        .iter()
        .filter(|r| r.direction == "sent")
        .map(|r| r.kind)
        .collect::<Vec<_>>();
    sent_kinds.sort_unstable();
    assert_eq!(sent_kinds, [5, 7]);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test]
async fn deletion_provenance_only_change_wakes_chat_list_subscribers() {
    let (tx, mut rx) = mpsc::channel(2);
    let mut row = chat_list_test_row("group", "title");
    row.last_message = Some(crate::ChatListMessagePreview {
        retention_seconds: None,
        retention_expires_at: None,
        group_system: None,
        message_id_hex: "message".into(),
        sender: "author".into(),
        sender_display_name: None,
        plaintext: String::new(),
        kind: 9,
        timeline_at: 1,
        deleted: true,
        deletion_source: crate::DeletionSource::Author,
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: crate::ChatListMessageDeliveryState::NotApplicable,
        media_json: None,
    });
    let mut fingerprints =
        HashMap::from([(row.group_id_hex.clone(), chat_list_row_fingerprint(&row))]);
    row.last_message.as_mut().unwrap().deletion_source = crate::DeletionSource::Admin;
    assert!(
        reconcile_chat_list_snapshot(
            &tx,
            &mut fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![row.clone()]
        )
        .await
    );
    assert!(
        matches!(rx.recv().await, Some(RuntimeChatListUpdate::Row { row, .. }) if row.last_message.as_ref().unwrap().deletion_source == crate::DeletionSource::Admin)
    );
    assert!(
        reconcile_chat_list_snapshot(
            &tx,
            &mut fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![row]
        )
        .await
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn chat_preview_retention_only_change_wakes_subscribers() {
    let (tx, mut rx) = mpsc::channel(2);
    let mut row = chat_list_test_row("group", "title");
    row.last_message = Some(crate::ChatListMessagePreview {
        group_system: None,
        message_id_hex: "message".to_owned(),
        sender: "author".to_owned(),
        sender_display_name: None,
        plaintext: "hello".to_owned(),
        kind: 9,
        timeline_at: 10,
        retention_seconds: None,
        retention_expires_at: None,
        deleted: false,
        deletion_source: Default::default(),
        attachment_kind: None,
        attachment_count: 0,
        delivery_state: crate::ChatListMessageDeliveryState::Pending,
        media_json: None,
    });
    let mut fingerprints =
        HashMap::from([(row.group_id_hex.clone(), chat_list_row_fingerprint(&row))]);
    let preview = row.last_message.as_mut().unwrap();
    preview.retention_seconds = Some(300);
    preview.retention_expires_at = Some(310);
    assert!(
        reconcile_chat_list_snapshot(
            &tx,
            &mut fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![row.clone()]
        )
        .await
    );
    let Some(RuntimeChatListUpdate::Row { row: updated, .. }) = rx.recv().await else {
        panic!("expected a row update for finalized retention");
    };
    let preview = updated.last_message.as_ref().unwrap();
    assert_eq!(preview.retention_seconds, Some(300));
    assert_eq!(preview.retention_expires_at, Some(310));
    assert!(
        reconcile_chat_list_snapshot(
            &tx,
            &mut fingerprints,
            ChatListUpdateTrigger::SnapshotRefresh,
            vec![row]
        )
        .await
    );
    assert!(rx.try_recv().is_err());
}
