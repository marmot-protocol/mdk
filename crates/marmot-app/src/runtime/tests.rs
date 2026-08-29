use cgka_traits::TransportAdapterError;
use cgka_traits::transport_adapter::{
    TransportEndpoint, TransportEndpointFailure, TransportEndpointFailureKind,
    TransportEndpointRejectionCategory, TransportPublishFailure,
};

use super::subscriptions::{chat_list_mute_expiries, message_kind_filter_allows};
use super::*;
use crate::tests::{ScriptedPushRelayClient, deletion_event_references};
use crate::{MarmotAppConfig, publish_endpoints_from_bootstrap};

#[derive(Default)]
struct SetupAuthorityDirectoryFetcher {
    events: std::sync::Mutex<Vec<transport_nostr_peeler::NostrTransportEvent>>,
    strict_error: std::sync::Mutex<Option<String>>,
    strict_requests: std::sync::atomic::AtomicUsize,
}

impl SetupAuthorityDirectoryFetcher {
    fn with_events(
        events: impl IntoIterator<Item = transport_nostr_peeler::NostrTransportEvent>,
    ) -> Self {
        Self {
            events: std::sync::Mutex::new(events.into_iter().collect()),
            ..Self::default()
        }
    }

    fn with_strict_error(error: &str) -> Self {
        Self {
            strict_error: std::sync::Mutex::new(Some(error.to_owned())),
            ..Self::default()
        }
    }

    fn records_for(
        &self,
        request: &crate::relay_plane::DirectoryFetchRequest,
    ) -> Vec<crate::relay_plane::DirectoryRelayEventRecord> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| {
                request
                    .queries
                    .iter()
                    .any(|query| query.kind == event.kind && query.authors.contains(&event.pubkey))
            })
            .cloned()
            .map(|event| crate::relay_plane::DirectoryRelayEventRecord {
                endpoints: request.endpoints.clone(),
                event,
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl crate::relay_plane::DirectoryRelayFetcher for SetupAuthorityDirectoryFetcher {
    async fn fetch_directory_events(
        &self,
        request: crate::relay_plane::DirectoryFetchRequest,
    ) -> Result<Vec<crate::relay_plane::DirectoryRelayEventRecord>, String> {
        Ok(self.records_for(&request))
    }

    async fn fetch_directory_events_strict(
        &self,
        request: crate::relay_plane::DirectoryFetchRequest,
    ) -> Result<Vec<crate::relay_plane::DirectoryRelayEventRecord>, String> {
        self.strict_requests
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(error) = self.strict_error.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(self.records_for(&request))
    }
}

fn signed_setup_relay_list_event(
    keys: &nostr::Keys,
    kind: u64,
    relay: &str,
    created_at: u64,
) -> transport_nostr_peeler::NostrTransportEvent {
    let tag = if kind == crate::KIND_NIP65_RELAY_LIST {
        nostr::Tag::parse(["r", relay]).unwrap()
    } else {
        nostr::Tag::parse(["relay", relay]).unwrap()
    };
    let event = nostr::EventBuilder::new(nostr::Kind::from(u16::try_from(kind).unwrap()), "")
        .tags([tag])
        .custom_created_at(nostr::Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .unwrap();
    transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event).unwrap()
}

#[tokio::test]
async fn setup_strict_nip65_installs_exact_generation_without_opening_a_worker() {
    let directory = tempfile::tempdir().unwrap();
    let keys = nostr::Keys::generate();
    let imported = AccountHome::open(directory.path())
        .import_nostr_account_idempotent(&keys.secret_key().to_secret_hex())
        .unwrap();
    let account = imported.account().clone();
    let route = "wss://authority.example";
    let event = signed_setup_relay_list_event(
        &keys,
        crate::KIND_NIP65_RELAY_LIST,
        route,
        unix_now_seconds(),
    );
    let fetcher = Arc::new(SetupAuthorityDirectoryFetcher::with_events([event.clone()]));
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), "wss://discovery.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(relay, fetcher.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let admission = runtime
        .accounts
        .account_setup_admission(&account.account_id_hex)
        .unwrap();

    runtime
        .accounts
        .establish_setup_nip65_authority(
            &account,
            admission,
            &[TransportEndpoint("wss://discovery.example".into())],
        )
        .await
        .unwrap();

    assert!(runtime.accounts.workers.lock().await.is_empty());
    let generation = app
        .read_nip65_route_generation_for_authoring(&account.label)
        .unwrap()
        .unwrap();
    assert_eq!(generation.event_id, event.id);
    assert_eq!(generation.created_at, event.created_at);
    assert_eq!(generation.nip65.relays, vec![route.to_owned()]);
    assert!(!app.pending_nip65_route_mutation(&account.label));
    assert_eq!(
        fetcher
            .strict_requests
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn directory_sync_cannot_install_self_nip65_for_a_signed_out_account() {
    let directory = tempfile::tempdir().unwrap();
    let keys = nostr::Keys::generate();
    let account = AccountHome::open(directory.path())
        .import_nostr_account_idempotent(&keys.secret_key().to_secret_hex())
        .unwrap()
        .account()
        .clone();
    AccountHome::open(directory.path())
        .set_account_signed_out(&account.label, true)
        .unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://discovery.example");
    let runtime = MarmotAppRuntime::new(app.clone());
    let event = signed_setup_relay_list_event(
        &keys,
        crate::KIND_NIP65_RELAY_LIST,
        "wss://late-authority.example",
        unix_now_seconds(),
    );

    runtime
        .accounts
        .ingest_directory_relay_event(crate::relay_plane::DirectoryRelayEventRecord {
            endpoints: vec![TransportEndpoint("wss://discovery.example".into())],
            event,
        })
        .await
        .unwrap();

    assert!(
        app.read_nip65_route_generation_for_authoring(&account.label)
            .unwrap()
            .is_none(),
        "an observational directory stream must not install signed-out route authority"
    );
    assert!(!app.pending_nip65_route_mutation(&account.label));
    assert!(
        !app.account_storage_cached_for_test(&account.label),
        "a late self NIP-65 event must not reopen signed-out account storage"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn incomplete_setup_nip65_discovery_cannot_publish_defaults_or_a_key_package() {
    let directory = tempfile::tempdir().unwrap();
    let keys = nostr::Keys::generate();
    let import_secret = zeroize::Zeroizing::new(keys.secret_key().to_secret_hex());
    assert!(
        !crate::is_nostr_secret(import_secret.as_str()),
        "the regression requires a compatible non-nsec secret encoding"
    );
    let fetcher = Arc::new(SetupAuthorityDirectoryFetcher::with_strict_error(
        "strict directory subscription closed before EOSE",
    ));
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane =
        MarmotRelayPlane::new_with_directory_fetcher_for_test(relay.clone(), fetcher.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    let error = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(import_secret),
            default_relays: vec![TransportEndpoint("wss://default.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            discovery_relays: vec![TransportEndpoint("wss://relay.example".into())],
            publish_missing_relay_lists: true,
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .expect_err("incomplete strict discovery must stop imported-account setup");

    assert!(matches!(error, AppError::RelayDirectory(_)));
    assert!(
        relay
            .publish_attempts_of_kind(crate::KIND_NIP65_RELAY_LIST)
            .is_empty()
    );
    assert!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty()
    );
    assert_eq!(
        fetcher
            .strict_requests
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn generated_local_preparation_binds_worker_key_package_to_requested_route() {
    let directory = tempfile::tempdir().unwrap();
    let requested = TransportEndpoint("wss://requested.example/".into());
    let fallback = TransportEndpoint("wss://fallback.example/".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), fallback.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    let prepared = runtime
        .prepare_generated_account_local_ready(AccountSetupRequest {
            default_relays: vec![requested.clone()],
            bootstrap_relays: vec![requested.clone()],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();

    assert!(
        relay.published_event_kinds().is_empty(),
        "local preparation may sign and journal route authority but must not perform relay I/O"
    );
    assert!(app.pending_nip65_route_mutation(&prepared.result.account.label));

    runtime.reconcile_accounts().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !relay
                .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
                .is_empty()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("setup-priority worker must publish the prepared KeyPackage");

    let kinds = relay.published_event_kinds();
    let nip65_index = kinds
        .iter()
        .position(|kind| *kind == crate::KIND_NIP65_RELAY_LIST)
        .expect("worker priority must first recover the staged NIP-65 route");
    let key_package_index = kinds
        .iter()
        .position(|kind| *kind == transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .expect("worker priority must publish the prepared KeyPackage");
    assert!(nip65_index < key_package_index);

    let generation = app
        .read_nip65_route_generation_for_authoring(&prepared.result.account.label)
        .unwrap()
        .unwrap();
    assert_eq!(generation.nip65.relays, vec![requested.0.clone()]);
    assert!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .iter()
            .all(|(endpoints, _)| endpoints == std::slice::from_ref(&requested)),
        "the app fallback must never become generated setup KeyPackage authority"
    );
    let lifecycle = app
        .account_storage(&prepared.result.account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert!(lifecycle.publication_targets.iter().any(|target| {
        target.endpoint == requested
            && target.state == cgka_traits::TransportFanoutAttemptState::Accepted
    }));
    assert!(
        lifecycle
            .publication_targets
            .iter()
            .all(|target| target.endpoint != fallback),
        "fallback endpoints must not enter the durable KeyPackage fanout journal"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn completed_empty_setup_nip65_discovery_can_author_explicit_missing_defaults() {
    let directory = tempfile::tempdir().unwrap();
    let keys = nostr::Keys::generate();
    let import_secret = zeroize::Zeroizing::new(keys.secret_key().to_secret_hex());
    assert!(
        !crate::is_nostr_secret(import_secret.as_str()),
        "the regression requires a compatible non-nsec secret encoding"
    );
    let fetcher = Arc::new(SetupAuthorityDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    app.relay_plane =
        MarmotRelayPlane::new_with_directory_fetcher_for_test(relay.clone(), fetcher.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    let setup = runtime
        .create_or_import_account(AccountSetupRequest {
            import_nsec: Some(import_secret),
            default_relays: vec![TransportEndpoint("wss://default.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://relay.example".into())],
            discovery_relays: vec![TransportEndpoint("wss://relay.example".into())],
            publish_missing_relay_lists: true,
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("completed absence may enter the explicitly authorized publish-missing path");

    let published = relay.published_events_of_kind(crate::KIND_NIP65_RELAY_LIST);
    assert_eq!(published.len(), 1);
    let generation = app
        .read_nip65_route_generation_for_authoring(&setup.account.label)
        .unwrap()
        .unwrap();
    assert_eq!(generation.event_id, published[0].id);
    assert_eq!(
        generation.nip65.relays,
        vec!["wss://default.example".to_owned()]
    );
    assert!(
        relay
            .published_events_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty()
    );
    runtime.shutdown().await;
}

#[test]
fn teardown_targets_a_durable_local_key_package_before_relay_discovery() {
    let event_id = "11".repeat(32);
    let targets = key_package_deletion_targets(vec![AccountKeyPackageRecord {
        account_label: Some("alice".into()),
        account_id_hex: "22".repeat(32),
        key_package_id: "stable-slot".into(),
        key_package_ref_hex: "33".repeat(32),
        key_package_event_id: event_id.clone(),
        published_at: 7,
        key_package_bytes: 42,
        source_relays: vec!["wss://keys.example".into()],
        local: true,
        relay: false,
    }]);

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].event_id_hex, event_id);
    assert_eq!(
        targets[0].source_relays,
        vec![TransportEndpoint("wss://keys.example".into())]
    );
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

#[test]
fn generated_account_resume_restores_lost_pre_session_cutover_proof() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());

    let (account, _) = runtime
        .accounts
        .create_nostr_account_from_setup(&AccountSetupRequest::default())
        .unwrap();
    std::fs::remove_file(app.key_package_cutover_scan_complete_path(&account.label)).unwrap();

    let (resumed, _) = runtime
        .accounts
        .create_nostr_account_from_setup(&AccountSetupRequest::default())
        .unwrap();

    assert_eq!(resumed.account_id_hex, account.account_id_hex);
    assert!(app.key_package_cutover_has_fresh_account_proof(&account.label));
    assert!(
        !app.account_storage_path(&account.label).exists(),
        "fresh proof recovery must still precede the first session database"
    );
}

#[test]
fn generated_account_resume_restores_lost_replacement_intent() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app.clone());
    let (account, _) = runtime
        .accounts
        .create_nostr_account_from_setup(&AccountSetupRequest::default())
        .unwrap();

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();
    std::fs::remove_file(app.key_package_cutover_replacement_pending_path(&account.label)).unwrap();
    assert!(!app.key_package_cutover_replacement_pending(&account.label));

    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();

    assert!(app.key_package_cutover_replacement_pending(&account.label));
    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked,
        "recovered intent must remain fail-closed until exact setup recovery"
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
    let admission = runtime
        .accounts
        .account_setup_admission(&account.account_id_hex)
        .unwrap();

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
            admission,
            true,
            false,
            None,
        )
        .await
        .expect_err("failed discovery must not become a write of request defaults");

    assert!(matches!(
        error,
        AppError::MissingRelayLists(missing)
            if missing
                == vec![
                    crate::MissingRelayListKind::Nip65,
                    crate::MissingRelayListKind::Inbox,
                ]
    ));
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
async fn sign_out_aborts_and_reaps_generated_setup_before_persisting_signed_out_state() {
    struct DropSignal(std::sync::Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let runtime = MarmotAppRuntime::new(app);
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let late_reactivation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();

    let task = {
        let release = release.clone();
        let late_reactivation = late_reactivation.clone();
        let dropped = dropped.clone();
        let home = home.clone();
        let account_label = account.label.clone();
        tokio::spawn(async move {
            let _drop_signal = DropSignal(dropped);
            let _ = started_tx.send(());
            release.notified().await;
            home.set_account_signed_out(&account_label, false).unwrap();
            late_reactivation.store(true, std::sync::atomic::Ordering::SeqCst);
        })
    };
    started_rx
        .await
        .expect("generated setup task must start before sign-out");
    runtime
        .accounts
        .generated_setup_tasks
        .lock()
        .unwrap()
        .handles
        .insert(account.account_id_hex.clone(), task);

    let outcome = runtime
        .sign_out(
            &account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.local_cleanup.completed);
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "sign-out must reap the generated setup future before returning"
    );
    assert!(
        runtime
            .accounts
            .generated_setup_tasks
            .lock()
            .unwrap()
            .handles
            .is_empty(),
        "the per-account setup task must leave no detached handle"
    );

    release.notify_waiters();
    tokio::task::yield_now().await;
    assert!(home.account(&account.label).unwrap().signed_out);
    assert!(
        !late_reactivation.load(std::sync::atomic::Ordering::SeqCst),
        "an aborted setup task must not clear signed-out state after teardown"
    );

    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_sign_out_keeps_admission_closed_until_generated_setup_is_reaped() {
    struct DropSignal(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        directory.path(),
        "wss://relay.example",
    ));
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_dropped = dropped.clone();
    let task = tokio::spawn(async move {
        let _drop_signal = DropSignal(task_dropped);
        let _ = started_tx.send(());
        // Model an abort-requested setup future whose synchronous boundary has
        // not returned yet. A second Tokio worker keeps the test itself live.
        let _ = release_rx.recv();
    });
    started_rx.await.unwrap();
    runtime
        .accounts
        .generated_setup_tasks
        .lock()
        .unwrap()
        .handles
        .insert(account.account_id_hex.clone(), task);

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.account_id_hex.clone();
    let sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let handle_removed = !runtime
                .accounts
                .generated_setup_tasks
                .lock()
                .unwrap()
                .handles
                .contains_key(&account.account_id_hex);
            if handle_removed
                && runtime
                    .accounts
                    .account_is_tearing_down(&account.account_id_hex)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("teardown must own the generated setup task before cancellation");

    sign_out.abort();
    assert!(sign_out.await.unwrap_err().is_cancelled());
    assert!(
        runtime
            .accounts
            .account_is_tearing_down(&account.account_id_hex),
        "caller cancellation must not reopen setup admission before reap"
    );

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(std::sync::atomic::Ordering::SeqCst)
            || runtime
                .accounts
                .account_is_tearing_down(&account.account_id_hex)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached teardown must reap setup and release admission");
    assert!(home.account(&account.label).unwrap().signed_out);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_sign_out_keeps_admission_closed_until_worker_is_reaped() {
    struct DropSignal(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        directory.path(),
        "wss://relay.example",
    ));
    let (commands, _commands_rx) = mpsc::channel(1);
    let (shutdown, shutdown_rx) = oneshot::channel();
    let (shutdown_entered_tx, shutdown_entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_dropped = dropped.clone();
    let handle = tokio::spawn(async move {
        let _drop_signal = DropSignal(worker_dropped);
        let _ = shutdown_rx.await;
        let _ = shutdown_entered_tx.send(());
        let _ = release_rx.recv();
    });
    runtime.accounts.workers.lock().await.insert(
        account.account_id_hex.clone(),
        ManagedAccountWorker {
            handle,
            commands,
            shutdown,
        },
    );

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.account_id_hex.clone();
    let sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    shutdown_entered_rx
        .await
        .expect("teardown must signal worker shutdown");
    assert!(
        runtime
            .accounts
            .account_is_tearing_down(&account.account_id_hex)
    );

    sign_out.abort();
    assert!(sign_out.await.unwrap_err().is_cancelled());
    assert!(
        runtime
            .accounts
            .account_is_tearing_down(&account.account_id_hex),
        "caller cancellation must not reopen worker admission before reap"
    );

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(std::sync::atomic::Ordering::SeqCst)
            || runtime
                .accounts
                .account_is_tearing_down(&account.account_id_hex)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached teardown must reap worker and release admission");
    assert!(home.account(&account.label).unwrap().signed_out);
    runtime.shutdown().await;
}

#[tokio::test]
async fn cancelling_sign_out_during_kind_five_keeps_admission_closed_until_cleanup_settles() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app);
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint],
            bootstrap_relays: vec![TransportEndpoint("wss://keys.example".into())],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");
    assert!(
        relay
            .published_event_kinds()
            .contains(&transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE),
        "setup must finish its KeyPackage publish before the cancellation seam is armed"
    );

    relay.block_next_publish();
    let signing_out_runtime = runtime.clone();
    let signing_out_account = created.account.account_id_hex.clone();
    let sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(&signing_out_account, SignOutOptions::default())
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .expect("sign-out must reach its blocked kind-5 publish");

    sign_out.abort();
    assert!(sign_out.await.unwrap_err().is_cancelled());
    assert!(
        runtime
            .accounts
            .account_is_tearing_down(&created.account.account_id_hex),
        "caller cancellation must leave the runtime-owned teardown barrier installed"
    );
    let busy = runtime
        .sign_in_account(&created.account.account_id_hex)
        .await;
    assert!(
        matches!(busy, Err(AppError::AccountWorkerBusy)),
        "sign-in must remain retryably busy while relay deletion is blocked: {busy:?}"
    );

    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime
            .accounts
            .account_is_tearing_down(&created.account.account_id_hex)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached relay cleanup must eventually release account admission");
    assert!(
        relay.published_event_kinds().contains(&5),
        "the blocked publish must have been the sign-out kind-5 deletion"
    );
    let signed_in = runtime
        .sign_in_account(&created.account.account_id_hex)
        .await
        .expect("the preserved account must sign in after cleanup settles");
    assert!(signed_in.running);
    assert!(!signed_in.signed_out);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_sign_in_restores_signed_out_and_keeps_late_open_epoch_closed() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let account = AccountHome::open(directory.path())
        .create_account("late-open-sign-in")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay,
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let (open_reached, release_open) = install_local_open_gate(&app, &account.label);
    let opening_app = app.clone();
    let opening_label = account.label.clone();
    let late_open = tokio::spawn(async move { opening_app.client(&opening_label).await });
    wait_for_test_signal(open_reached, "late direct-client open").await;

    runtime
        .sign_out(
            &account.label,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .expect("sign-out must revoke the withheld direct-client generation");
    assert!(
        !app.account_session_admission_is_open(&account.label, &account.account_id_hex),
        "sign-out must close session admission before waiting on other teardown work"
    );

    let failed_sign_in = runtime
        .sign_in_account(&account.label)
        .await
        .expect_err("the withheld old session owner must make worker reconcile fail");
    assert!(matches!(failed_sign_in, AppError::AccountSessionBusy));
    assert!(
        app.account_home()
            .account(&account.label)
            .unwrap()
            .signed_out,
        "failed sign-in must restore the durable signed-out marker"
    );
    assert!(
        !app.account_session_admission_is_open(&account.label, &account.account_id_hex),
        "failed sign-in must close the generation it briefly opened for reconcile"
    );

    release_open.send(()).unwrap();
    let late_result = late_open.await.unwrap();
    assert!(
        matches!(late_result, Err(AppError::AccountWorkerBusy)),
        "an open captured before sign-out must stay revoked after the failed sign-in ABA"
    );

    let signed_in = runtime
        .sign_in_account(&account.label)
        .await
        .expect("a fresh generation must reconcile after the stale owner drops");
    assert!(signed_in.running);
    assert!(!signed_in.signed_out);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_out_relay_and_deletion_mutations_reject_before_io_or_cache_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let account = AccountHome::open(directory.path())
        .create_account("signed-out-mutations")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let _ = app.account_relay_list_status(&account.label).unwrap();
    let _ = app.account_storage(&account.label).unwrap();
    assert!(app.directory_cache_cached_for_test(&account.label));
    assert!(app.account_storage_cached_for_test(&account.label));

    let outcome = runtime
        .sign_out(
            &account.label,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.local_cleanup.completed);
    assert!(!app.directory_cache_cached_for_test(&account.label));
    assert!(!app.account_storage_cached_for_test(&account.label));

    let nip65_attempts = relay
        .publish_attempts_of_kind(crate::KIND_NIP65_RELAY_LIST)
        .len();
    let inbox_attempts = relay
        .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
        .len();
    let deletion_attempts = relay.publish_attempts_of_kind(5).len();

    assert!(
        runtime
            .publish_account_nip65_relay_set(
                &account.label,
                vec![endpoint.clone()],
                vec![endpoint.clone()],
                vec![endpoint.clone()],
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .set_account_nip65_relays(
                &account.label,
                vec![endpoint.clone()],
                vec![endpoint.clone()],
            )
            .await
            .is_err(),
        "role-preserving NIP-65 edit must reject before its cache read"
    );
    assert!(
        runtime
            .set_account_inbox_relays(
                &account.label,
                vec![endpoint.clone()],
                vec![endpoint.clone()],
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .publish_account_relay_lists(
                &account.label,
                AccountRelayListBootstrap::new(vec![endpoint.clone()], vec![endpoint.clone()],),
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .delete_key_package(&account.label, &"ab".repeat(32), Vec::new())
            .await
            .is_err(),
        "empty-relay deletion must reject before resolving cached relay lists"
    );
    assert!(
        app.set_account_inbox_relays(
            &account.label,
            vec![endpoint.clone()],
            vec![endpoint.clone()],
        )
        .await
        .is_err(),
        "raw MarmotApp relay mutation must require a runtime/setup capability"
    );
    assert!(
        app.delete_key_package_event(&account.label, &"cd".repeat(32), vec![endpoint])
            .await
            .is_err(),
        "raw MarmotApp deletion must require durable runtime admission"
    );

    assert_eq!(
        relay
            .publish_attempts_of_kind(crate::KIND_NIP65_RELAY_LIST)
            .len(),
        nip65_attempts
    );
    assert_eq!(
        relay
            .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
            .len(),
        inbox_attempts
    );
    assert_eq!(relay.publish_attempts_of_kind(5).len(), deletion_attempts);
    assert!(
        !app.directory_cache_cached_for_test(&account.label)
            && !app.account_storage_cached_for_test(&account.label),
        "rejected signed-out mutations must not reopen account caches"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn imported_setup_losing_route_lock_to_sign_out_cannot_publish_relay_lists() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let keys = nostr::Keys::generate();
    let account_id_hex = keys.public_key().to_hex();
    let import_nsec = zeroize::Zeroizing::new(keys.secret_key().to_secret_hex());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let route_lock = app.key_package_route_lock(&account_id_hex);
    let route_guard = route_lock.lock().await;

    let setup_runtime = runtime.clone();
    let setup_endpoint = endpoint.clone();
    let setup = tokio::spawn(async move {
        setup_runtime
            .create_or_import_account(AccountSetupRequest {
                import_nsec: Some(import_nsec),
                default_relays: vec![setup_endpoint.clone()],
                bootstrap_relays: vec![setup_endpoint.clone()],
                discovery_relays: vec![setup_endpoint],
                publish_missing_relay_lists: true,
                publish_initial_key_package: false,
                ..AccountSetupRequest::default()
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match app.account_home().account_setup_state(&account_id_hex) {
                Ok(Some(state))
                    if {
                        state.phase
                            == marmot_account::AccountSetupPhase::BootstrapPublicationStarted
                    } =>
                {
                    break;
                }
                Ok(_) | Err(AccountHomeError::UnknownAccount(_)) => {}
                Err(error) => panic!("import setup state read failed: {error}"),
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("import setup must queue its admitted relay-list batch");

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account_id_hex.clone();
    let sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !runtime.accounts.account_is_tearing_down(&account_id_hex) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sign-out must supersede the imported setup before route release");
    drop(route_guard);

    let setup_result = setup.await.unwrap();
    assert!(
        matches!(setup_result, Err(AppError::AccountWorkerBusy)),
        "superseded import must fail its final setup proof: {setup_result:?}"
    );
    let sign_out = sign_out.await.unwrap().unwrap();
    assert!(sign_out.local_cleanup.completed);
    assert!(
        relay
            .publish_attempts_of_kind(crate::KIND_NIP65_RELAY_LIST)
            .is_empty(),
        "superseded import must not emit kind 10002"
    );
    assert!(
        relay
            .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
            .is_empty(),
        "superseded import must not emit the inbox relay list"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_active_deletion_publisher_losing_route_lock_to_sign_out_cannot_publish() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let account = AccountHome::open(directory.path())
        .create_account("stale-active-deletion")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let session_admission = app
        .capture_account_session_admission(&account.label, &account.account_id_hex)
        .unwrap();
    let publisher = crate::AppKeyPackagePublisher {
        app: app.clone(),
        account_label: account.label.clone(),
        signer: app.account_signer_for_summary(&account).unwrap(),
        session_admission: crate::AccountSessionAdmission::Active(session_admission.clone()),
    };
    let route_lock = app.key_package_route_lock(&account.label);
    let route_guard = route_lock.lock().await;
    let deletion_endpoint = endpoint.clone();
    let mut deleting = tokio::spawn(async move {
        marmot_account::KeyPackagePublisher::delete_key_package_revision(
            &publisher,
            &cgka_traits::MessageId::new(vec![7_u8; 32]),
            &[deletion_endpoint],
        )
        .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut deleting)
            .await
            .is_err(),
        "active deletion must wait at its final route-serialized proof"
    );

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.label.clone();
    let mut sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    let mut revocation = Box::pin(tokio::time::timeout(Duration::from_secs(5), async {
        while app.account_session_admission_is_current(&account.label, &session_admission) {
            tokio::task::yield_now().await;
        }
    }));
    tokio::select! {
        result = &mut sign_out => {
            panic!("sign-out finished before revoking the active deletion publisher: {result:?}");
        }
        result = &mut revocation => {
            result.expect("sign-out must revoke the active deletion publisher");
        }
    }
    drop(route_guard);

    let deletion = deleting.await.unwrap();
    assert!(deletion.is_err(), "stale active deletion must fail closed");
    let sign_out = sign_out.await.unwrap().unwrap();
    assert!(sign_out.local_cleanup.completed);
    assert!(
        relay.publish_attempts_of_kind(5).is_empty(),
        "the stale active publisher must fail before kind-5 relay I/O"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_active_inbox_mutation_losing_route_lock_cannot_publish_or_recache() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let account = AccountHome::open(directory.path())
        .create_account("stale-active-inbox")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let direct_client = app.client(&account.label).await.unwrap();
    let session_admission = match &direct_client.session_admission {
        crate::AccountSessionAdmission::Active(token) => token.clone(),
        crate::AccountSessionAdmission::Teardown(_) => unreachable!(),
    };
    let baseline_attempts = relay
        .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
        .len();
    let route_lock = app.key_package_route_lock(&account.label);
    let route_guard = route_lock.lock().await;
    let publishing_endpoint = endpoint.clone();
    let mut publishing = tokio::spawn(async move {
        let mut direct_client = direct_client;
        let result = direct_client
            .publish_account_inbox_relays(
                vec![publishing_endpoint.clone()],
                vec![publishing_endpoint],
            )
            .await;
        (direct_client, result)
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut publishing)
            .await
            .is_err(),
        "the inbox mutation must wait at its final route-serialized proof"
    );

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.label.clone();
    let mut sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    let mut revocation = Box::pin(tokio::time::timeout(Duration::from_secs(5), async {
        while app.account_session_admission_is_current(&account.label, &session_admission) {
            tokio::task::yield_now().await;
        }
    }));
    tokio::select! {
        result = &mut sign_out => {
            panic!("sign-out finished before revoking the queued inbox mutation: {result:?}");
        }
        result = &mut revocation => {
            result.expect("sign-out must revoke the active inbox mutation");
        }
    }
    drop(route_guard);

    let (direct_client, publication) = publishing.await.unwrap();
    assert!(
        publication.is_err(),
        "stale inbox mutation must fail closed"
    );
    let sign_out = sign_out.await.unwrap().unwrap();
    assert!(sign_out.local_cleanup.completed);
    assert_eq!(
        relay
            .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
            .len(),
        baseline_attempts,
        "the stale inbox mutation must fail before kind-10050 relay I/O"
    );
    assert!(!app.directory_cache_cached_for_test(&account.label));
    assert!(!app.account_storage_cached_for_test(&account.label));
    drop(direct_client);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_flight_inbox_publish_commits_before_sign_out_then_teardown_evicts_its_cache() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let account = AccountHome::open(directory.path())
        .create_account("in-flight-inbox-sign-out")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let direct_client = app.client(&account.label).await.unwrap();
    relay.block_next_publish_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST);

    let publishing_endpoint = endpoint.clone();
    let publishing = tokio::spawn(async move {
        let mut direct_client = direct_client;
        let result = direct_client
            .publish_account_inbox_relays(
                vec![publishing_endpoint.clone()],
                vec![publishing_endpoint],
            )
            .await;
        (direct_client, result)
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .expect("inbox publication must reach its blocked relay I/O");

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.label.clone();
    let mut sign_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !runtime
            .accounts
            .account_is_tearing_down(&account.account_id_hex)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sign-out must revoke admission while relay I/O is in flight");
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut sign_out)
            .await
            .is_err(),
        "sign-out must wait for the relay mutation's route-locked cache commit"
    );

    relay.release_publish();
    let (direct_client, publication) = publishing.await.unwrap();
    publication.expect("the already admitted in-flight publication must finish first");
    let sign_out = sign_out.await.unwrap().unwrap();
    assert!(sign_out.local_cleanup.completed);
    assert_eq!(
        relay
            .publish_attempts_of_kind(crate::KIND_MARMOT_INBOX_RELAY_LIST)
            .len(),
        1
    );
    assert!(
        !app.directory_cache_cached_for_test(&account.label)
            && !app.account_storage_cached_for_test(&account.label),
        "teardown must evict the cache committed before its signed-out boundary"
    );
    drop(direct_client);
    runtime.shutdown().await;
}

#[tokio::test]
async fn teardown_deletion_capability_does_not_recursively_acquire_the_owned_route_lock() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let event_id = cgka_traits::MessageId::new(vec![9_u8; 32]);
    let home = AccountHome::open(directory.path());
    let account = home.create_account("teardown-deletion-capability").unwrap();
    home.set_account_signed_out(&account.label, true).unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let mut lifecycle =
        cgka_traits::KeyPackageLifecycleState::slot_only("teardown-current-slot".into());
    lifecycle.authored_event_id = Some(event_id.clone());
    lifecycle.publication_targets = vec![cgka_traits::TransportFanoutTarget {
        endpoint: endpoint.clone(),
        state: cgka_traits::TransportFanoutAttemptState::Unattempted,
        attempt_count: 0,
        last_attempt_at: None,
        failure_code: None,
    }];
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();
    let deletion_admission = app
        .prepare_quiesced_key_package_deletion_recovery(
            &account.label,
            &[crate::KeyPackageDeletionTarget {
                event_id_hex: hex::encode(event_id.as_slice()),
                source_relays: vec![endpoint.clone()],
            }],
        )
        .unwrap();
    assert_eq!(deletion_admission.admitted.len(), 1);
    let journaled = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert!(
        journaled
            .deleted_live_revision_event_ids
            .contains(&event_id)
    );
    assert!(
        journaled
            .retired_publications_pending_deletion
            .iter()
            .any(|retired| retired.event_id == event_id
                && retired
                    .deletion_targets
                    .iter()
                    .any(|target| target.endpoint == endpoint))
    );
    app.close_account_session_admission(&account.label, &account.account_id_hex);
    let teardown_admission = app
        .open_account_teardown_session_admission(&account.label, &account.account_id_hex)
        .unwrap();
    let publisher = crate::AppKeyPackagePublisher {
        app: app.clone(),
        account_label: account.label.clone(),
        signer: app.account_signer_for_summary(&account).unwrap(),
        session_admission: crate::AccountSessionAdmission::Teardown(teardown_admission.clone()),
    };
    let route_lock = app.key_package_route_lock(&account.label);
    let route_guard = route_lock.lock().await;

    let receipt = tokio::time::timeout(
        Duration::from_secs(5),
        marmot_account::KeyPackagePublisher::delete_key_package_revision(
            &publisher,
            &event_id,
            std::slice::from_ref(&endpoint),
        ),
    )
    .await
    .expect("teardown deletion must not deadlock on its caller-owned route lock")
    .unwrap();
    assert_eq!(receipt.accepted, vec![endpoint.clone()]);
    assert_eq!(relay.publish_attempts_of_kind(5).len(), 1);

    drop(route_guard);
    app.close_account_teardown_session_admission(&account.label, &teardown_admission);
    let stale = marmot_account::KeyPackagePublisher::delete_key_package_revision(
        &publisher,
        &cgka_traits::MessageId::new(vec![10_u8; 32]),
        std::slice::from_ref(&endpoint),
    )
    .await;
    assert!(
        stale.is_err(),
        "a teardown deletion token must stop authorizing I/O once its barrier closes"
    );
    assert_eq!(
        relay.publish_attempts_of_kind(5).len(),
        1,
        "revoked teardown deletion capability must fail before kind-5 I/O"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_key_package_publish_linearizes_before_sign_out_and_cannot_resume_afterward() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let setup_endpoint = endpoint.clone();
    let creating = tokio::spawn(async move {
        creating_runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![setup_endpoint.clone()],
                bootstrap_relays: vec![setup_endpoint],
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated LocalReady setup must reach its pre-worker handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must expose its resumable account");

    let mut direct_client = app.client(&account.label).await.unwrap();
    direct_client
        .recover_generated_setup_nip65_authority()
        .await
        .expect("direct publisher must recover the exact generated route first");
    relay.block_next_publish_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE);
    let publishing = tokio::spawn(async move {
        let result = direct_client.publish_key_package().await;
        (direct_client, result)
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .expect("direct kind-30443 publication must reach the relay seam");
    assert_eq!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        1,
        "the blocked send must be the direct KeyPackage publication"
    );

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.account_id_hex.clone();
    let mut signing_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut signing_out)
            .await
            .is_err(),
        "sign-out must wait for a direct kind-30443 send that already owns the route lock"
    );
    assert!(
        !app.account_home()
            .account(&account.label)
            .unwrap()
            .signed_out,
        "the signed-out commit point must remain behind the in-flight relay send"
    );

    relay.release_publish();
    let outcome = tokio::time::timeout(Duration::from_secs(5), &mut signing_out)
        .await
        .expect("sign-out must finish after the direct publisher releases the route lock")
        .unwrap()
        .unwrap();
    assert!(outcome.local_cleanup.completed);
    let (mut direct_client, _first_result) = publishing.await.unwrap();
    assert!(
        app.account_home()
            .account(&account.label)
            .unwrap()
            .signed_out
    );
    assert!(
        relay.account_unsubscribe_count() >= 1,
        "sign-out must deactivate the retained direct client's standalone relay plane"
    );
    assert_eq!(
        relay
            .published_events_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        1,
        "the in-flight publication must be accepted before sign-out returns"
    );
    assert!(
        !app.account_storage_cached_for_test(&account.label),
        "sign-out must evict the app account-storage projection"
    );
    let subscriptions_after_sign_out = relay.subscription_count();
    let stale_activation = direct_client
        .adapter
        .activate_account(cgka_traits::TransportAccountActivation {
            account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
            inbox_endpoints: vec![endpoint],
            group_subscriptions: Vec::new(),
            since: None,
        })
        .await;
    assert!(
        matches!(
            stale_activation,
            Err(TransportAdapterError::AccountNotActive(_))
        ),
        "a stale direct adapter must not reactivate after teardown: {stale_activation:?}"
    );
    assert_eq!(relay.subscription_count(), subscriptions_after_sign_out);

    assert!(
        app.client(&account.label).await.is_err(),
        "the public direct-client entry point must reject a signed-out account before session open"
    );
    assert!(
        direct_client.rotate_key_package().await.is_err(),
        "a stale direct rotate must fail before route refresh or cache access"
    );
    assert!(
        runtime
            .publish_new_key_package(&account.account_id_hex)
            .await
            .is_err(),
        "the compatibility publish-new alias must not revive a signed-out account"
    );
    assert!(
        !app.account_storage_cached_for_test(&account.label),
        "rejected direct/runtime rotation must not reopen app account storage"
    );

    let attempts_before_retry = relay
        .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .len();
    assert!(
        direct_client.publish_key_package().await.is_err(),
        "a stale direct client must fail closed after the signed-out commit point"
    );
    assert_eq!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        attempts_before_retry,
        "no kind-30443 attempt may begin after sign-out returns"
    );
    assert!(
        !app.account_storage_cached_for_test(&account.label),
        "the rejected stale publisher must not reopen app account storage"
    );

    drop(direct_client);
    handoff.release();
    let superseded_setup = tokio::time::timeout(Duration::from_secs(5), creating)
        .await
        .expect("the superseded setup must leave its handoff")
        .unwrap();
    assert!(
        matches!(superseded_setup, Err(AppError::AccountWorkerBusy)),
        "sign-out must prevent the pre-worker setup from reopening admission: {superseded_setup:?}"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_direct_publisher_losing_route_lock_to_sign_out_cannot_replay_nip65_or_clear_hold() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let request = generated_setup_request(&endpoint);
    let creating =
        tokio::spawn(async move { creating_runtime.create_identity_local_ready(request).await });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated LocalReady setup must reach its handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must expose its resumable account");
    assert!(
        app.generated_initial_key_package_publication_held(&account.label)
            .unwrap()
    );

    let direct_client = app.client(&account.label).await.unwrap();
    let route_lock = app.key_package_route_lock(&account.label);
    let route_guard = route_lock.lock().await;
    let mut publishing = tokio::spawn(async move {
        let mut direct_client = direct_client;
        let result = direct_client.publish_key_package().await;
        (direct_client, result)
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(200), &mut publishing)
            .await
            .is_err(),
        "the direct publisher must be waiting at generated-route admission"
    );

    let signing_out_runtime = runtime.clone();
    let signing_out_account = account.account_id_hex.clone();
    let signing_out = tokio::spawn(async move {
        signing_out_runtime
            .sign_out(
                &signing_out_account,
                SignOutOptions {
                    delete_key_packages: false,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while app.account_session_admission_is_open(&account.label, &account.account_id_hex) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sign-out must synchronously close the direct publisher's epoch");
    drop(route_guard);

    let (direct_client, publish_result) = publishing.await.unwrap();
    assert!(
        matches!(publish_result, Err(AppError::AccountWorkerBusy)),
        "the route-locked final proof must reject the stale publisher: {publish_result:?}"
    );
    let outcome = signing_out.await.unwrap().unwrap();
    assert!(outcome.local_cleanup.completed);
    assert!(
        app.generated_initial_key_package_publication_held(&account.label)
            .unwrap(),
        "a stale explicit publisher must not clear generated publication consent"
    );
    assert!(
        relay.published_event_kinds().is_empty(),
        "a stale direct publisher must not replay NIP-65, publish inbox metadata, or emit kind 30443: {:?}",
        relay.published_event_kinds()
    );

    drop(direct_client);
    handoff.release();
    assert!(matches!(
        creating.await.unwrap(),
        Err(AppError::AccountWorkerBusy)
    ));
    runtime.shutdown().await;
}

#[tokio::test]
async fn sign_out_then_sign_in_publishes_a_strictly_newer_key_package_revision() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");
    let initial = relay
        .published_events_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .into_iter()
        .last()
        .expect("network-ready setup must publish a KeyPackage");
    let stale_lifecycle = app
        .account_storage(&created.account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .expect("network-ready setup must retain its KeyPackage lifecycle");
    let stale_artifact = stale_lifecycle
        .authored_signed_event
        .clone()
        .expect("network-ready setup must retain its signed event");
    let stale_publication = marmot_account::KeyPackagePublication {
        account_id: MemberId::new(hex::decode(&created.account.account_id_hex).unwrap()),
        key_package: stale_lifecycle
            .current_key_package
            .clone()
            .expect("network-ready setup must retain its current KeyPackage"),
        slot_id: stale_lifecycle.stable_slot_id.clone(),
        created_at: stale_artifact.created_at,
        endpoints: stale_lifecycle
            .publication_targets
            .iter()
            .map(|target| target.endpoint.clone())
            .collect(),
    };
    let stale_publisher = crate::AppKeyPackagePublisher {
        app: app.clone(),
        account_label: created.account.label.clone(),
        signer: app.account_signer_for_summary(&created.account).unwrap(),
        session_admission: crate::AccountSessionAdmission::Active(
            app.capture_account_session_admission(
                &created.account.label,
                &created.account.account_id_hex,
            )
            .unwrap(),
        ),
    };

    let signed_out = runtime
        .sign_out(&created.account.account_id_hex, SignOutOptions::default())
        .await
        .unwrap();
    assert!(signed_out.key_packages_deleted >= 1);
    assert!(
        relay.published_event_kinds().contains(&5),
        "sign-out must publish a tombstone for the initial revision"
    );
    runtime
        .sign_in_account(&created.account.account_id_hex)
        .await
        .unwrap();

    let replacement = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = relay
                .published_events_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
                .into_iter()
                .find(|event| event.id != initial.id)
            {
                break event;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("sign-in maintenance must publish a replacement signed revision");
    assert_eq!(replacement.pubkey, initial.pubkey);
    assert_eq!(replacement.kind, initial.kind);
    assert_eq!(replacement.tags, initial.tags);
    assert_eq!(replacement.content, initial.content);
    assert!(
        replacement.created_at > initial.created_at,
        "the replacement must be strictly newer than the tombstoned revision"
    );
    assert_ne!(
        replacement.id, initial.id,
        "the publisher must expose a new event id after sign-out deletion"
    );

    runtime
        .accounts
        .wait_for_account_network_startup_to_settle(&created.account.label)
        .await
        .expect("re-signed-in worker maintenance must settle");
    assert!(
        matches!(
            &stale_publisher.session_admission,
            crate::AccountSessionAdmission::Active(token)
                if !app.account_session_admission_is_current(&created.account.label, token)
        ),
        "explicit sign-in must use a generation distinct from the stale publisher"
    );
    let attempts_before_stale_publish = relay
        .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .len();
    let stale_result = marmot_account::KeyPackagePublisher::publish_prepared_key_package(
        &stale_publisher,
        &stale_publication,
        &stale_artifact,
    )
    .await;
    assert!(
        stale_result.is_err(),
        "a pre-sign-out final publisher must stay revoked after re-sign-in"
    );
    assert_eq!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        attempts_before_stale_publish,
        "the stale final publisher must fail before relay I/O"
    );

    runtime.shutdown().await;
}

#[tokio::test]
async fn no_group_sign_out_and_wipe_unconditionally_deactivate_relay_transport() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app);
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");
    assert_eq!(
        runtime
            .accounts
            .app
            .relay_telemetry()
            .await
            .metrics
            .active_accounts,
        1
    );

    let sign_out = runtime
        .sign_out(
            &created.account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .expect("no-group sign-out must succeed");
    assert!(sign_out.local_cleanup.completed);
    assert_eq!(
        runtime
            .accounts
            .app
            .relay_telemetry()
            .await
            .metrics
            .active_accounts,
        0,
        "sign-out must deactivate transport even when there is no group-leave client"
    );

    runtime
        .sign_in_account(&created.account.account_id_hex)
        .await
        .expect("signed-out account must reactivate");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .accounts
                .app
                .relay_telemetry()
                .await
                .metrics
                .active_accounts
                == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reactivated worker must restore transport activation");

    let wipe = runtime
        .sign_out_and_wipe(&created.account.account_id_hex)
        .await
        .expect("no-group wipe must succeed");
    assert!(wipe.local_cleanup.completed, "wipe outcome: {wipe:?}");
    assert_eq!(
        runtime
            .accounts
            .app
            .relay_telemetry()
            .await
            .metrics
            .active_accounts,
        0,
        "wipe must deactivate transport before removing a no-group account"
    );
    assert!(matches!(
        AccountHome::open(directory.path()).account(&created.account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    runtime.shutdown().await;
}

async fn assert_shutdown_waits_for_blocked_key_package_teardown(destructive: bool) {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app);
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");
    let deleted_live_event_id = runtime
        .accounts
        .app
        .account_storage(&created.account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .and_then(|lifecycle| lifecycle.authored_signed_event)
        .map(|artifact| artifact.id)
        .expect("network-ready setup must persist its signed revision");

    relay.block_next_publish();
    let teardown_runtime = runtime.clone();
    let teardown_account = created.account.account_id_hex.clone();
    let teardown = tokio::spawn(async move {
        if destructive {
            teardown_runtime
                .sign_out_and_wipe(&teardown_account)
                .await
                .map(|_| ())
        } else {
            teardown_runtime
                .sign_out(&teardown_account, SignOutOptions::default())
                .await
                .map(|_| ())
        }
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .expect("teardown must reach its blocked kind-5 publish");
    teardown.abort();
    assert!(teardown.await.unwrap_err().is_cancelled());

    let shutdown_runtime = runtime.clone();
    let shutdown = tokio::spawn(async move { shutdown_runtime.shutdown().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.shared.lifecycle().ensure_running().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown must close operation admission promptly");
    tokio::task::yield_now().await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must retain the admitted teardown while kind-5 is blocked"
    );

    relay.release_publish();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown must finish after relay cleanup releases")
        .expect("shutdown task must not panic");

    let home = AccountHome::open(directory.path());
    if destructive {
        assert!(
            matches!(
                home.account(&created.account.label),
                Err(AccountHomeError::UnknownAccount(_))
            ),
            "shutdown must let an admitted wipe reach its local removal commit"
        );
    } else {
        assert!(home.account(&created.account.label).unwrap().signed_out);
        let lifecycle = runtime
            .accounts
            .app
            .account_storage(&created.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .expect("non-destructive sign-out must retain KeyPackage lifecycle");
        assert!(
            lifecycle
                .deleted_live_revision_event_ids
                .contains(&deleted_live_event_id),
            "shutdown must preserve durable recovery intent for the deleted live revision"
        );
    }
}

#[tokio::test]
async fn shutdown_waits_for_cancelled_sign_out_blocked_on_kind_five() {
    assert_shutdown_waits_for_blocked_key_package_teardown(false).await;
}

#[tokio::test]
async fn shutdown_waits_for_cancelled_wipe_blocked_on_kind_five() {
    assert_shutdown_waits_for_blocked_key_package_teardown(true).await;
}

#[tokio::test]
async fn terminal_shutdown_bounds_blocked_teardown_before_releasing_storage() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        directory.path(),
        vec![endpoint.0.clone()],
        AccountHome::open(directory.path()),
        MarmotAppConfig::default(),
    )
    .unwrap()
    .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app);
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");

    relay.block_next_publish();
    let sign_out_runtime = runtime.clone();
    let account_id_hex = created.account.account_id_hex.clone();
    let sign_out = tokio::spawn(async move {
        sign_out_runtime
            .sign_out(&account_id_hex, SignOutOptions::default())
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_publish())
        .await
        .expect("sign-out must reach its blocked kind-5 publish");
    sign_out.abort();
    assert!(sign_out.await.unwrap_err().is_cancelled());

    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));
    let started_at = Instant::now();
    runtime.shutdown_and_close().await.unwrap();
    assert!(
        started_at.elapsed() < Duration::from_secs(2),
        "a blocked teardown must not escape the terminal shutdown budget"
    );
    assert!(runtime.storage_is_closed());
    drop(
        crate::MarmotRootRuntimeLease::try_acquire(directory.path())
            .expect("terminal close must release the root lease"),
    );

    // Let the detached teardown observe closed storage and release its bounded
    // activity slot rather than leaving a blocked task behind the test.
    relay.release_publish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_close_rejects_late_wipe_commits_after_root_ownership_transfers() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        directory.path(),
        vec!["wss://keys.example".into()],
        AccountHome::open(directory.path()),
        MarmotAppConfig::default(),
    )
    .unwrap();
    let account = app.account_home().create_account("late-wipe").unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let teardown_entered = Arc::new(Semaphore::new(0));
    let teardown_release = Arc::new(Semaphore::new(0));
    *runtime
        .wipe_before_teardown_test_hook
        .lock()
        .expect("wipe pre-teardown test-hook lock poisoned") = Some(WipeBeforeTeardownTestHook {
        entered: teardown_entered.clone(),
        release: teardown_release.clone(),
    });

    let wiping_runtime = runtime.clone();
    let account_ref = account.label.clone();
    let wipe = tokio::spawn(async move { wiping_runtime.sign_out_and_wipe(&account_ref).await });
    tokio::time::timeout(Duration::from_secs(5), teardown_entered.acquire())
        .await
        .expect("wipe must reach the pre-teardown stall")
        .expect("wipe pre-teardown semaphore must remain open")
        .forget();

    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));
    runtime.shutdown_and_close().await.unwrap();
    let new_owner = crate::MarmotRootRuntimeLease::try_acquire(directory.path())
        .expect("terminal close must transfer root ownership after its bounded wait");
    let new_owner_home = AccountHome::open(directory.path());
    let sentinel = new_owner_home.create_account("new-owner-sentinel").unwrap();
    assert!(!new_owner_home.account(&account.label).unwrap().signed_out);

    teardown_release.add_permits(1);
    let outcome = tokio::time::timeout(Duration::from_secs(5), wipe)
        .await
        .expect("late wipe must settle after its stall releases")
        .expect("wipe task must not panic")
        .expect("wipe API returns its partial cleanup report");
    assert!(!outcome.local_cleanup.completed);
    assert!(
        !new_owner_home.account(&account.label).unwrap().signed_out,
        "the old runtime must not persist a signed-out marker after lease transfer"
    );
    assert_eq!(
        new_owner_home
            .account(&sentinel.label)
            .unwrap()
            .account_id_hex,
        sentinel.account_id_hex,
        "the detached old owner must not mutate the new owner's root"
    );
    drop(new_owner);
}

#[tokio::test]
async fn cancelled_wipe_before_teardown_continues_group_leave_and_shutdown_waits_for_removal() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let runtime = MarmotAppRuntime::new(app);
    let created = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("network-ready setup must not stall")
    .expect("network-ready setup must succeed");
    let peer = tokio::time::timeout(
        Duration::from_secs(5),
        runtime.create_identity(AccountSetupRequest {
            default_relays: vec![TransportEndpoint("wss://keys.example".into())],
            bootstrap_relays: vec![TransportEndpoint("wss://keys.example".into())],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("peer network-ready setup must not stall")
    .expect("peer network-ready setup must succeed");
    let group_id = runtime
        .create_group(
            &created.account.account_id_hex,
            "owned wipe cancellation",
            std::slice::from_ref(&peer.account.account_id_hex),
            None,
        )
        .await
        .expect("two-member group creation must succeed");
    runtime
        .promote_admin(
            &created.account.account_id_hex,
            &group_id,
            &peer.account.account_id_hex,
        )
        .await
        .expect("peer promotion must make creator self-demotion legal");
    runtime
        .self_demote_admin(&created.account.account_id_hex, &group_id)
        .await
        .expect("wipe target must not remain the sole group admin");
    runtime
        .pause_maintenance(&created.account.account_id_hex)
        .await
        .expect("maintenance pause must serialize before the leave test");
    runtime
        .pause_maintenance(&peer.account.account_id_hex)
        .await
        .expect("peer maintenance pause must serialize before the leave test");
    assert_eq!(
        runtime
            .accounts
            .app
            .groups(&created.account.label)
            .unwrap()
            .len(),
        1,
        "wipe Stage 1 must discover the locally joined group"
    );
    let active_accounts_before_wipe = runtime
        .accounts
        .app
        .relay_telemetry()
        .await
        .metrics
        .active_accounts;
    assert!(
        active_accounts_before_wipe >= 2,
        "both test-account transports must be active before the wipe"
    );
    let group_publications_before = relay
        .published_events_of_kind(transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .len();
    let key_package_attempts_before = relay
        .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .len();
    let teardown_entered = Arc::new(Semaphore::new(0));
    let teardown_release = Arc::new(Semaphore::new(0));
    *runtime
        .wipe_before_teardown_test_hook
        .lock()
        .expect("wipe pre-teardown test-hook lock poisoned") = Some(WipeBeforeTeardownTestHook {
        entered: teardown_entered.clone(),
        release: teardown_release.clone(),
    });
    let wipe_runtime = runtime.clone();
    let wipe_account = created.account.account_id_hex.clone();
    let wipe = tokio::spawn(async move { wipe_runtime.sign_out_and_wipe(&wipe_account).await });
    tokio::time::timeout(Duration::from_secs(5), teardown_entered.acquire())
        .await
        .expect("wipe must register ownership before admitted teardown")
        .expect("wipe pre-teardown test-hook semaphore must remain open")
        .forget();
    wipe.abort();
    assert!(wipe.await.unwrap_err().is_cancelled());

    let relay_plane_shutdown = runtime.stall_shutdown_for_test(ShutdownTestPhase::RelayPlane);
    let shutdown_runtime = runtime.clone();
    let shutdown = tokio::spawn(async move { shutdown_runtime.shutdown().await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.shared.lifecycle().ensure_running().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown must close ordinary operation admission promptly");
    tokio::task::yield_now().await;
    assert!(
        !shutdown.is_finished(),
        "shutdown must retain the admitted wipe before account quiescence begins"
    );

    teardown_release.add_permits(1);
    tokio::time::timeout(
        Duration::from_secs(5),
        relay_plane_shutdown.wait_until_entered(),
    )
    .await
    .expect("shutdown must drain the owned wipe before reaching relay-plane shutdown");
    assert_eq!(
        runtime
            .accounts
            .app
            .relay_telemetry()
            .await
            .metrics
            .active_accounts,
        active_accounts_before_wipe.saturating_sub(1),
        "the teardown-scoped leave client must deactivate its transport before account removal"
    );
    relay_plane_shutdown.release();
    tokio::time::timeout(Duration::from_secs(5), shutdown)
        .await
        .expect("shutdown must finish after the owned wipe releases")
        .expect("shutdown task must not panic");

    assert!(
        relay
            .published_events_of_kind(transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
            .len()
            > group_publications_before,
        "the admitted wipe must publish its group leave after shutdown latches; published kinds: {:?}",
        relay.published_event_kinds()
    );
    assert!(
        relay.published_event_kinds().contains(&5),
        "the owned wipe must continue through KeyPackage deletion"
    );
    assert_eq!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        key_package_attempts_before,
        "the teardown-only cleanup client must never publish kind 30443"
    );
    assert!(
        matches!(
            AccountHome::open(directory.path()).account(&created.account.label),
            Err(AccountHomeError::UnknownAccount(_))
        ),
        "the owned wipe must reach the local account removal commit"
    );
}

#[test]
fn account_teardown_task_admission_is_bounded_and_reclaims_dropped_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
        directory.path(),
        "wss://relay.example",
    ));
    assert_eq!(ACCOUNT_TEARDOWN_TASK_LIMIT, 64);
    let mut guards = (0..ACCOUNT_TEARDOWN_TASK_LIMIT)
        .map(|_| {
            runtime
                .accounts
                .register_account_teardown_task()
                .expect("every slot through the teardown-task cap must be admitted")
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        runtime.accounts.register_account_teardown_task(),
        Err(AppError::AccountWorkerBusy)
    ));
    drop(guards.pop());
    guards.push(
        runtime
            .accounts
            .register_account_teardown_task()
            .expect("dropping one guard must immediately reclaim one admission slot"),
    );
    drop(guards);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn account_teardown_task_close_register_drop_and_drain_interleavings_do_not_lose_wakes() {
    const ROUNDS: usize = 24;
    const REGISTRARS: usize = 12;

    let directory = tempfile::tempdir().unwrap();
    for round in 0..ROUNDS {
        let runtime = MarmotAppRuntime::new(MarmotApp::with_relay(
            directory.path().join(format!("round-{round}")),
            "wss://relay.example",
        ));
        let start = Arc::new(tokio::sync::Barrier::new(REGISTRARS + 1));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();
        let mut registrars = Vec::with_capacity(REGISTRARS);
        for _ in 0..REGISTRARS {
            let manager = runtime.accounts.clone();
            let start = start.clone();
            let release = release.clone();
            let result_tx = result_tx.clone();
            registrars.push(tokio::spawn(async move {
                start.wait().await;
                match manager.register_account_teardown_task() {
                    Ok(guard) => {
                        result_tx.send(true).unwrap();
                        release.acquire().await.unwrap().forget();
                        drop(guard);
                    }
                    Err(AppError::RuntimeStopping) => result_tx.send(false).unwrap(),
                    Err(error) => panic!("unexpected teardown admission error: {error:?}"),
                }
            }));
        }
        drop(result_tx);

        let closing_manager = runtime.accounts.clone();
        let closing_start = start.clone();
        let drain = tokio::spawn(async move {
            closing_start.wait().await;
            closing_manager.close_teardown_admission();
            closing_manager.drain_teardown_tasks().await;
        });

        let mut admitted = 0;
        for _ in 0..REGISTRARS {
            admitted += usize::from(result_rx.recv().await.unwrap());
        }
        if admitted > 0 {
            assert!(
                !drain.is_finished(),
                "drain must retain every registration that won the close-admission race"
            );
            release.add_permits(admitted);
        }
        for registrar in registrars {
            registrar.await.unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), drain)
            .await
            .expect("dropping every admitted guard must wake the drain")
            .expect("drain task must not panic");
        assert!(matches!(
            runtime.accounts.register_account_teardown_task(),
            Err(AppError::RuntimeStopping)
        ));
        runtime.shutdown().await;
    }
}

#[tokio::test]
async fn quiesced_deletion_journal_cap_admits_deferred_pair_only_after_ack_frees_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("deletion-journal-cap")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://keys.example")
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let saturated_event_id = cgka_traits::MessageId::new(vec![0x71; 32]);
    let saturated_event_id_hex = hex::encode(saturated_event_id.as_slice());
    let existing_endpoint = TransportEndpoint("wss://liability-0.example".into());
    let shared_endpoint = TransportEndpoint("wss://shared-liability.example".into());
    let overflow_endpoint = TransportEndpoint("wss://overflow.example".into());
    let mut lifecycle = cgka_traits::KeyPackageLifecycleState::slot_only("stable-slot".into());
    lifecycle.retired_publications_pending_deletion.push(
        cgka_traits::RetiredKeyPackagePublication {
            event_id: saturated_event_id.clone(),
            authored_created_at: cgka_traits::Timestamp(0),
            key_package_ref: None,
            package_not_after: None,
            delete_without_successor: true,
            deletion_targets: vec![existing_endpoint.clone(), shared_endpoint.clone()]
                .into_iter()
                .map(|endpoint| cgka_traits::TransportFanoutTarget {
                    endpoint,
                    state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                    attempt_count: 0,
                    last_attempt_at: None,
                    failure_code: None,
                })
                .collect(),
        },
    );
    lifecycle.retired_publications_pending_deletion.extend(
        (0..cgka_traits::maintenance::MAX_KEY_PACKAGE_SIGNED_PUBLICATION_LIABILITIES - 2).map(
            |index| cgka_traits::RetiredKeyPackagePublication {
                event_id: cgka_traits::MessageId::new(
                    std::iter::once(index as u8)
                        .chain(std::iter::repeat_n(0x74, 31))
                        .collect::<Vec<_>>(),
                ),
                authored_created_at: cgka_traits::Timestamp(0),
                key_package_ref: None,
                package_not_after: None,
                delete_without_successor: true,
                deletion_targets: vec![cgka_traits::TransportFanoutTarget {
                    endpoint: shared_endpoint.clone(),
                    state: cgka_traits::TransportFanoutAttemptState::Unattempted,
                    attempt_count: 0,
                    last_attempt_at: None,
                    failure_code: None,
                }],
            },
        ),
    );
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&lifecycle)
        .unwrap();

    let deferred_event_id = cgka_traits::MessageId::new(vec![0x72; 32]);
    let deferred_event_id_hex = hex::encode(deferred_event_id.as_slice());
    relay.block_next_publishes(2);
    let deleting_runtime = runtime.clone();
    let deleting_account = account.label.clone();
    let existing_target_event_id = saturated_event_id_hex.clone();
    let deferred_target_event_id = deferred_event_id_hex.clone();
    let deleting_existing_endpoint = existing_endpoint.clone();
    let deleting_overflow_endpoint = overflow_endpoint.clone();
    let (_teardown_account, teardown_barrier) = runtime
        .accounts
        .begin_account_teardown(&account.label, true)
        .await
        .unwrap();
    let deletion = tokio::spawn(async move {
        deleting_runtime
            .delete_relay_key_packages(
                &deleting_account,
                vec![
                    KeyPackageDeletionTarget {
                        event_id_hex: existing_target_event_id,
                        source_relays: vec![deleting_existing_endpoint],
                    },
                    KeyPackageDeletionTarget {
                        event_id_hex: deferred_target_event_id,
                        source_relays: vec![deleting_overflow_endpoint],
                    },
                ],
                &teardown_barrier,
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), relay.wait_for_blocked_publishes(1))
        .await
        .expect("the already-journaled deletion must be admitted first");
    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != deferred_event_id),
        "the 257th pair must remain deferred while the exact-pair journal is full"
    );
    relay.release_publish();

    tokio::time::timeout(Duration::from_secs(2), relay.wait_for_blocked_publishes(2))
        .await
        .expect("the deferred deletion must be admitted after the first ACK is committed");
    let while_deferred_send_blocked = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap();
    assert!(
        while_deferred_send_blocked
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == saturated_event_id)
            .unwrap()
            .deletion_targets
            .iter()
            .all(|target| target.endpoint != existing_endpoint),
        "the terminal first ACK must free exactly one liability slot"
    );
    assert_eq!(
        while_deferred_send_blocked
            .retired_publications_pending_deletion
            .iter()
            .find(|retired| retired.event_id == deferred_event_id)
            .expect("the deferred pair must be journaled before its kind-5 can escape")
            .deletion_targets,
        vec![cgka_traits::TransportFanoutTarget {
            endpoint: overflow_endpoint.clone(),
            state: cgka_traits::TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        }]
    );
    relay.release_publish();

    let (deleted, failures) = tokio::time::timeout(Duration::from_secs(2), deletion)
        .await
        .expect("both bounded admission passes must finish after release")
        .expect("deletion task must not panic");
    assert_eq!(deleted, 2);
    assert!(failures.is_empty());
    let attempts = relay.publish_attempts_of_kind(5);
    assert_eq!(attempts.len(), 2);
    assert!(deletion_event_references(
        &attempts[0].1,
        &saturated_event_id_hex
    ));
    assert_eq!(attempts[0].0, vec![existing_endpoint]);
    assert!(deletion_event_references(
        &attempts[1].1,
        &deferred_event_id_hex
    ));
    assert_eq!(attempts[1].0, vec![overflow_endpoint]);
    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .iter()
            .all(|retired| retired.event_id != deferred_event_id),
        "the second ACK must prune the newly admitted liability"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn quiesced_deletion_reports_unsafe_sibling_while_sending_and_pruning_safe_alias() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("mixed-safe-unsafe-delete")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://safe.example")
        .with_test_relay_client(relay.clone());
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "stable-slot".into(),
        ))
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let event_id = cgka_traits::MessageId::new(vec![0x73; 32]);
    let event_id_hex = hex::encode(event_id.as_slice());
    let raw_safe = TransportEndpoint(" wss://SAFE.EXAMPLE/ ".into());
    let canonical_safe = TransportEndpoint("wss://safe.example/".into());
    let unsafe_endpoint = TransportEndpoint("wss://169.254.169.254".into());
    let (_teardown_account, teardown_barrier) = runtime
        .accounts
        .begin_account_teardown(&account.label, true)
        .await
        .unwrap();

    let (deleted, failures) = runtime
        .delete_relay_key_packages(
            &account.label,
            vec![KeyPackageDeletionTarget {
                event_id_hex: event_id_hex.clone(),
                source_relays: vec![raw_safe, unsafe_endpoint.clone()],
            }],
            &teardown_barrier,
        )
        .await;
    assert_eq!(deleted, 0, "the event remains only partially cleaned up");
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].event_id_hex, event_id_hex);
    assert!(!failures[0].reason.is_empty());
    assert_eq!(
        relay
            .publish_attempts_of_kind(5)
            .into_iter()
            .filter(|(_, event)| deletion_event_references(event, &event_id_hex))
            .map(|(endpoints, _)| endpoints)
            .collect::<Vec<_>>(),
        vec![vec![canonical_safe]],
        "only the canonical safe sibling may reach relay I/O"
    );
    let retained = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap()
        .retired_publications_pending_deletion;
    assert_eq!(retained.len(), 1);
    assert_eq!(
        retained[0].deletion_targets,
        vec![cgka_traits::TransportFanoutTarget {
            endpoint: unsafe_endpoint,
            state: cgka_traits::TransportFanoutAttemptState::Unattempted,
            attempt_count: 0,
            last_attempt_at: None,
            failure_code: None,
        }],
        "unsafe exact key must remain durably retryable after the safe ACK prunes"
    );
    drop(teardown_barrier);
    runtime.shutdown().await;
}

#[tokio::test]
async fn quiesced_deletion_keeps_pure_unsafe_target_durable_without_io() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("pure-unsafe-delete")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://safe.example")
        .with_test_relay_client(relay.clone());
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "stable-slot".into(),
        ))
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let event_id = cgka_traits::MessageId::new(vec![0x74; 32]);
    let unsafe_endpoint = TransportEndpoint("wss://169.254.169.254".into());
    let (_teardown_account, teardown_barrier) = runtime
        .accounts
        .begin_account_teardown(&account.label, true)
        .await
        .unwrap();

    let (deleted, failures) = runtime
        .delete_relay_key_packages(
            &account.label,
            vec![KeyPackageDeletionTarget {
                event_id_hex: hex::encode(event_id.as_slice()),
                source_relays: vec![unsafe_endpoint.clone()],
            }],
            &teardown_barrier,
        )
        .await;
    assert_eq!(deleted, 0);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].event_id_hex, hex::encode(event_id.as_slice()));
    assert!(!failures[0].reason.is_empty());
    assert!(relay.publish_attempts_of_kind(5).is_empty());
    let retained = app
        .account_storage(&account.label)
        .unwrap()
        .key_package_lifecycle()
        .unwrap()
        .unwrap()
        .retired_publications_pending_deletion;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].event_id, event_id);
    assert_eq!(retained[0].deletion_targets[0].endpoint, unsafe_endpoint);
    drop(teardown_barrier);
    runtime.shutdown().await;
}

#[tokio::test]
async fn quiesced_deletion_isolates_empty_malformed_target_from_valid_sibling() {
    let directory = tempfile::tempdir().unwrap();
    let account = AccountHome::open(directory.path())
        .create_account("invalid-and-valid-delete")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), "wss://safe.example")
        .with_test_relay_client(relay.clone());
    app.account_storage(&account.label)
        .unwrap()
        .put_key_package_lifecycle(&cgka_traits::KeyPackageLifecycleState::slot_only(
            "stable-slot".into(),
        ))
        .unwrap();
    let runtime = MarmotAppRuntime::new(app.clone());
    let invalid_event_id = "legacy-malformed-id".to_owned();
    let valid_event_id = cgka_traits::MessageId::new(vec![0x75; 32]);
    let valid_event_id_hex = hex::encode(valid_event_id.as_slice());
    let valid_endpoint = TransportEndpoint("wss://safe.example/".into());
    let (_teardown_account, teardown_barrier) = runtime
        .accounts
        .begin_account_teardown(&account.label, true)
        .await
        .unwrap();

    let (deleted, failures) = runtime
        .delete_relay_key_packages(
            &account.label,
            vec![
                KeyPackageDeletionTarget {
                    event_id_hex: invalid_event_id.clone(),
                    source_relays: Vec::new(),
                },
                KeyPackageDeletionTarget {
                    event_id_hex: valid_event_id_hex.clone(),
                    source_relays: vec![valid_endpoint.clone()],
                },
            ],
            &teardown_barrier,
        )
        .await;

    assert_eq!(deleted, 1);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].event_id_hex, invalid_event_id);
    let attempts = relay.publish_attempts_of_kind(5);
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].0, vec![valid_endpoint]);
    assert!(deletion_event_references(
        &attempts[0].1,
        &valid_event_id_hex
    ));
    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .retired_publications_pending_deletion
            .is_empty(),
        "the valid sibling ACK must prune its liability despite the malformed sibling"
    );
    drop(teardown_barrier);
    runtime.shutdown().await;
}

fn generated_setup_request(endpoint: &TransportEndpoint) -> AccountSetupRequest {
    AccountSetupRequest {
        default_relays: vec![endpoint.clone()],
        bootstrap_relays: vec![endpoint.clone()],
        publish_initial_key_package: true,
        ..AccountSetupRequest::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_local_ready_handoff_cannot_cross_completed_sign_out() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let request = generated_setup_request(&endpoint);
    let creating =
        tokio::spawn(async move { creating_runtime.create_identity_local_ready(request).await });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated LocalReady setup must reach its handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must durably expose its resumable account");

    let outcome = runtime
        .sign_out(
            &account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.local_cleanup.completed);
    handoff.release();

    let result = creating.await.expect("local-ready task must be reapable");
    assert!(matches!(result, Err(AppError::AccountWorkerBusy)));
    assert!(
        app.account_home()
            .account(&account.account_id_hex)
            .unwrap()
            .signed_out,
        "a stale LocalReady caller must not undo completed sign-out"
    );
    assert!(
        !runtime
            .accounts
            .generated_setup_tasks
            .lock()
            .unwrap()
            .handles
            .contains_key(&account.account_id_hex),
        "a superseded LocalReady caller must not register background setup"
    );
    assert!(
        !runtime
            .accounts
            .workers
            .lock()
            .await
            .contains_key(&account.account_id_hex),
        "a superseded LocalReady caller must not recreate its worker"
    );
    assert!(
        !relay
            .published_event_kinds()
            .contains(&transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE),
        "a superseded LocalReady caller must not publish its prepared KeyPackage"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_client_during_generated_handoff_cannot_wedge_setup_publication() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let request = generated_setup_request(&endpoint);
    let creating =
        tokio::spawn(async move { creating_runtime.create_identity_local_ready(request).await });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated LocalReady setup must reach its handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must durably expose its resumable account");

    // Generic direct-client maintenance cannot replay a generated bootstrap
    // intent without its durable setup context, so it fails closed and arms
    // the SQL gate. The specialized worker recovery must later re-prove and
    // reopen that gate instead of leaving setup permanently wedged.
    let direct_client = app.client(&account.label).await.unwrap();
    assert!(
        app.account_storage(&account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked
    );
    drop(direct_client);

    handoff.release();
    let local = creating
        .await
        .expect("local-ready task must be reapable")
        .expect("validated worker recovery must survive the direct-client race");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&local.account.account_id_hex)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("generated setup must reach NetworkReady after the direct-client race");
    assert_eq!(
        relay
            .published_events_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        1
    );
    assert!(
        !app.account_storage(&local.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_publish_during_generated_handoff_uses_context_route_not_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let requested = TransportEndpoint("wss://requested.example".into());
    let fallback = TransportEndpoint("wss://fallback.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), fallback.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let requested_for_setup = requested.clone();
    let creating = tokio::spawn(async move {
        creating_runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![requested_for_setup.clone()],
                bootstrap_relays: vec![requested_for_setup],
                publish_initial_key_package: false,
                ..AccountSetupRequest::default()
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated LocalReady setup must reach its handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must durably expose its resumable account");

    let mut direct_client = app.client(&account.label).await.unwrap();
    direct_client
        .publish_key_package()
        .await
        .expect("explicit publication may supersede setup opt-out after exact route recovery");
    let attempts = relay.publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE);
    assert!(!attempts.is_empty());
    assert!(
        attempts
            .iter()
            .all(|(endpoints, _)| endpoints == std::slice::from_ref(&requested)),
        "explicit handoff publication must remain bound to the persisted setup route: {attempts:?}"
    );
    assert!(
        attempts
            .iter()
            .all(|(endpoints, _)| !endpoints.contains(&fallback))
    );
    assert!(
        !app.generated_initial_key_package_publication_held(&account.label)
            .unwrap()
    );
    let attempts_before_resume = relay
        .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
        .len();
    runtime
        .prepare_generated_account_local_ready(AccountSetupRequest::default())
        .await
        .expect("resume after explicit consent must retain the prepared lifecycle");
    assert!(
        !app.generated_initial_key_package_publication_held(&account.label)
            .unwrap(),
        "resume must not recreate a hold once an explicit publisher cleared it"
    );
    assert_eq!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .len(),
        attempts_before_resume,
        "local resume must not republish or re-arm after explicit consent"
    );
    drop(direct_client);

    handoff.release();
    let local = creating
        .await
        .expect("local-ready task must be reapable")
        .expect("explicit publication must not invalidate generated setup");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&local.account.account_id_hex)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("background relay-list setup must finish after explicit publication");
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_hold_mirror_cannot_resurrect_an_explicit_release() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let runtime = MarmotAppRuntime::new(app.clone());
    let prepared = runtime
        .prepare_generated_account_local_ready(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint],
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .expect("generated local preparation must create its initial hold and lifecycle");
    let label = prepared.result.account.label;
    assert!(
        app.generated_initial_key_package_publication_held(&label)
            .unwrap()
    );

    let route_lock = app.key_package_route_lock(&label);
    let route_guard = route_lock.lock().await;
    let mirror_app = app.clone();
    let mirror_label = label.clone();
    let mirror = tokio::spawn(async move {
        mirror_app
            .mirror_generated_initial_key_package_publication_hold_into_lifecycle(&mirror_label)
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !mirror.is_finished(),
        "the mirror must serialize behind explicit release's route boundary"
    );

    app.clear_generated_initial_key_package_publication_hold(&label)
        .unwrap();
    let storage = app.account_storage(&label).unwrap();
    let mut lifecycle = storage.key_package_lifecycle().unwrap().unwrap();
    lifecycle.cutover_publication_blocked = false;
    storage.put_key_package_lifecycle(&lifecycle).unwrap();
    drop(route_guard);
    mirror.await.unwrap().unwrap();

    assert!(
        !app.generated_initial_key_package_publication_held(&label)
            .unwrap(),
        "a queued mirror must not recreate a hold cleared by explicit consent"
    );
    assert!(
        !app.account_storage(&label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked,
        "a queued mirror must not re-block SQL after explicit consent"
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_publication_opt_out_survives_network_ready_and_worker_startup() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let creating = tokio::spawn(async move {
        creating_runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![endpoint.clone()],
                bootstrap_relays: vec![endpoint],
                publish_initial_key_package: false,
                ..AccountSetupRequest::default()
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("opted-out generated setup must reach its handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must durably expose its resumable account");
    relay.block_account_inbox_subscribe(hex::decode(&account.account_id_hex).unwrap());
    handoff.release();

    let local = creating
        .await
        .expect("local-ready task must be reapable")
        .expect("opted-out generated setup must remain locally usable");
    tokio::time::timeout(Duration::from_secs(5), relay.wait_for_blocked_subscribe())
        .await
        .expect("worker initial sync must reach the injected stall");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if runtime
                .account_setup_readiness(&local.account.account_id_hex)
                .unwrap()
                == AccountSetupReadiness::NetworkReady
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay-list bootstrap may finish while initial sync remains stalled");
    assert!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty()
    );

    relay.release_subscribe();
    tokio::time::timeout(
        Duration::from_secs(5),
        runtime
            .accounts
            .wait_for_account_network_startup_to_settle(&local.account.account_id_hex),
    )
    .await
    .expect("worker startup must settle after the injected sync stall")
    .unwrap();
    assert!(
        relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty(),
        "background completion and the later worker finish hook must both retain the durable opt-out"
    );
    assert!(
        app.generated_initial_key_package_publication_held(&local.account.label)
            .unwrap()
    );
    assert!(
        app.account_storage(&local.account.label)
            .unwrap()
            .key_package_lifecycle()
            .unwrap()
            .unwrap()
            .cutover_publication_blocked
    );
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_publication_opt_out_survives_restart_until_explicit_publish() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let first_relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(first_relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());

    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint.clone()],
            bootstrap_relays: vec![endpoint.clone()],
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    runtime
        .accounts
        .wait_for_account_network_startup_to_settle(&created.account.account_id_hex)
        .await
        .unwrap();
    assert!(
        first_relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty()
    );
    assert!(
        app.generated_initial_key_package_publication_held(&created.account.label)
            .unwrap()
    );
    runtime.shutdown_and_close().await.unwrap();
    drop(runtime);
    drop(app);

    let restart_relay = Arc::new(ScriptedPushRelayClient::default());
    let mut reopened = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(restart_relay.clone());
    reopened.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        restart_relay.clone(),
        Arc::new(SetupAuthorityDirectoryFetcher::default()),
    );
    let restarted = MarmotAppRuntime::new(reopened.clone());
    restarted.reconcile_accounts().await.unwrap();
    restarted
        .accounts
        .wait_for_account_network_startup_to_settle(&created.account.account_id_hex)
        .await
        .unwrap();
    assert!(
        restart_relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty(),
        "restart maintenance must retain the durable initial-publication hold"
    );

    restarted
        .publish_key_package(&created.account.account_id_hex)
        .await
        .expect("an explicit later publish command must release the setup opt-out");
    assert!(
        !restart_relay
            .publish_attempts_of_kind(transport_nostr_adapter::KIND_MARMOT_KEY_PACKAGE)
            .is_empty()
    );
    assert!(
        !reopened
            .generated_initial_key_package_publication_held(&created.account.label)
            .unwrap()
    );
    restarted.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn generated_network_ready_reuses_original_admission_across_local_handoff() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(directory.path(), endpoint.0.clone())
        .with_test_relay_client(relay.clone());
    let runtime = MarmotAppRuntime::new(app.clone());
    let handoff = runtime.install_generated_setup_handoff_stall_for_test();

    let creating_runtime = runtime.clone();
    let request = generated_setup_request(&endpoint);
    let creating = tokio::spawn(async move { creating_runtime.create_identity(request).await });
    tokio::time::timeout(Duration::from_secs(5), handoff.wait_until_entered())
        .await
        .expect("generated NetworkReady setup must reach its local handoff");
    let account = app
        .account_home()
        .resumable_generated_account_setup()
        .unwrap()
        .expect("local preparation must durably expose its resumable account");

    let outcome = runtime
        .sign_out(
            &account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    assert!(outcome.local_cleanup.completed);
    handoff.release();

    let result = creating.await.expect("network-ready task must be reapable");
    assert!(matches!(result, Err(AppError::AccountWorkerBusy)));
    assert!(
        app.account_home()
            .account(&account.account_id_hex)
            .unwrap()
            .signed_out,
        "the foreground NetworkReady continuation must not reinterpret sign-out as explicit login"
    );
    assert!(
        !app.account_session_admission_is_open(&account.label, &account.account_id_hex),
        "the superseded resumable setup must leave ordinary session admission closed"
    );
    assert!(
        !runtime
            .accounts
            .workers
            .lock()
            .await
            .contains_key(&account.account_id_hex),
        "the stale foreground continuation must not recreate its worker"
    );
    assert!(
        relay.published_event_kinds().is_empty(),
        "the stale foreground continuation must perform no bootstrap or KeyPackage relay I/O: {:?}",
        relay.published_event_kinds()
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn generated_setup_resume_does_not_reactivate_an_already_signed_out_account() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = TransportEndpoint("wss://keys.example".into());
    let home = AccountHome::open(directory.path());
    let account = home.create_nostr_account_for_setup().unwrap();
    home.set_account_signed_out(&account.label, true).unwrap();
    let runtime =
        MarmotAppRuntime::new(MarmotApp::with_relay(directory.path(), endpoint.0.clone()));

    let result = runtime
        .create_identity_local_ready(generated_setup_request(&endpoint))
        .await;

    assert!(matches!(result, Err(AppError::AccountWorkerBusy)));
    assert!(
        home.account(&account.account_id_hex).unwrap().signed_out,
        "automatic generated-setup resume must preserve explicit sign-out"
    );
    assert!(
        runtime
            .accounts
            .generated_setup_tasks
            .lock()
            .unwrap()
            .handles
            .is_empty()
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn account_setup_completion_commits_only_while_admission_is_current() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let public_key = nostr::Keys::generate().public_key().to_hex();
    let account = app.account_home().add_public_account(&public_key).unwrap();
    app.account_home()
        .begin_account_setup_with(
            &account,
            false,
            AccountSetupKind::PublicIdentity,
            AccountSetupPhase::LocalStateCreated,
        )
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let admission = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .account_setup_admission(&account.account_id_hex)
            .unwrap()
    };
    let stale_publication = runtime
        .accounts
        .account_setup_publication_admission(&account.account_id_hex, admission)
        .unwrap();
    assert!(stale_publication.is_current());

    let completed = runtime
        .accounts
        .complete_account_setup_if_admitted(&account, admission)
        .await
        .unwrap();

    assert_eq!(completed.account_id_hex, account.account_id_hex);
    assert!(
        runtime
            .accounts
            .app
            .account_home()
            .account_setup_state(&account.label)
            .unwrap()
            .is_none(),
        "a current setup admission may commit NetworkReady state"
    );
    assert!(
        !stale_publication.is_current(),
        "NetworkReady completion must revoke every sibling publisher from the consumed setup generation"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn superseded_account_setup_cannot_reactivate_or_complete() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let account = app.account_home().create_nostr_account_for_setup().unwrap();
    let account = app
        .account_home()
        .set_account_signed_out(&account.label, true)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let admission = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .account_setup_admission(&account.account_id_hex)
            .unwrap()
    };
    assert!(admission.started_signed_out);
    {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .advance_setup_admission_generation(&account.account_id_hex);
    }

    assert!(matches!(
        runtime
            .accounts
            .reactivate_account_for_setup(&account, admission)
            .await,
        Err(AppError::AccountWorkerBusy)
    ));
    assert!(matches!(
        runtime
            .accounts
            .complete_account_setup_if_admitted(&account, admission)
            .await,
        Err(AppError::AccountWorkerBusy)
    ));
    let persisted = runtime
        .accounts
        .app
        .account_home()
        .account(&account.label)
        .unwrap();
    assert!(
        persisted.signed_out,
        "a setup superseded by teardown must not clear signed-out state"
    );
    assert!(
        runtime
            .accounts
            .app
            .account_home()
            .account_setup_state(&account.label)
            .unwrap()
            .is_some(),
        "a superseded setup must not falsely commit its setup journal"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn setup_admission_generation_is_account_scoped() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let first_public_key = nostr::Keys::generate().public_key().to_hex();
    let first = app
        .account_home()
        .add_public_account(&first_public_key)
        .unwrap();
    let second_public_key = nostr::Keys::generate().public_key().to_hex();
    let second = app
        .account_home()
        .add_public_account(&second_public_key)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let second_admission = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .account_setup_admission(&second.account_id_hex)
            .unwrap()
    };
    assert!(
        runtime
            .accounts
            .setup_admission_is_current(&second.account_id_hex, second_admission)
    );

    // Starting teardown for `first` must not supersede setup for an unrelated
    // account.
    let (_first, barrier) = runtime
        .accounts
        .begin_account_teardown(&first.account_id_hex, false)
        .await
        .unwrap();
    drop(barrier);

    assert!(
        runtime
            .accounts
            .setup_admission_is_current(&second.account_id_hex, second_admission)
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn incomplete_setup_reset_supersedes_older_setup_admission() {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let keys = nostr::Keys::generate();
    let secret = keys.secret_key().to_secret_hex();
    let account = home.import_nostr_account(&secret).unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    app.account_storage(&account.label).unwrap();
    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let admission = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .account_setup_admission(&account.account_id_hex)
            .unwrap()
    };
    let generation_before = runtime
        .accounts
        .setup_admission_generation(&account.account_id_hex);

    runtime
        .accounts
        .reset_incomplete_account_setup(&secret, true)
        .await
        .unwrap();

    assert!(
        runtime
            .accounts
            .setup_admission_generation(&account.account_id_hex)
            > generation_before,
        "recovery reset must permanently supersede foreground setup tokens"
    );
    assert!(
        !runtime
            .accounts
            .app
            .account_session_admission_is_open(&account.label, &account.account_id_hex),
        "credential-preserving reset must revoke the removed session generation"
    );
    assert!(
        !runtime
            .accounts
            .setup_admission_is_current(&account.account_id_hex, admission)
    );
    assert!(matches!(
        runtime
            .accounts
            .reactivate_account_for_setup(&account, admission)
            .await,
        Err(AppError::AccountWorkerBusy)
    ));
    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_incomplete_setup_reset_keeps_admission_closed_until_reap() {
    struct DropSignal(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let keys = nostr::Keys::generate();
    let secret = keys.secret_key().to_secret_hex();
    let account = home.import_nostr_account(&secret).unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    app.account_storage(&account.label).unwrap();
    app.ensure_strict_cutover_replacement_intent_before_session_open(&account.label)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_dropped = dropped.clone();
    let task = tokio::spawn(async move {
        let _drop_signal = DropSignal(task_dropped);
        let _ = started_tx.send(());
        let _ = release_rx.recv();
    });
    started_rx.await.unwrap();
    runtime
        .accounts
        .generated_setup_tasks
        .lock()
        .unwrap()
        .handles
        .insert(account.account_id_hex.clone(), task);

    let manager = runtime.accounts.clone();
    let reset_secret = secret.clone();
    let reset = tokio::spawn(async move {
        manager
            .reset_incomplete_account_setup(&reset_secret, true)
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let handle_removed = !runtime
                .accounts
                .generated_setup_tasks
                .lock()
                .unwrap()
                .handles
                .contains_key(&account.account_id_hex);
            if handle_removed
                && runtime
                    .accounts
                    .account_is_tearing_down(&account.account_id_hex)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reset must own the generated setup task before cancellation");

    reset.abort();
    assert!(reset.await.unwrap_err().is_cancelled());
    assert!(
        runtime
            .accounts
            .account_is_tearing_down(&account.account_id_hex),
        "caller cancellation must not reopen reset admission before reap"
    );

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !dropped.load(std::sync::atomic::Ordering::SeqCst)
            || runtime
                .accounts
                .account_is_tearing_down(&account.account_id_hex)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached reset must reap setup and release admission");
    assert!(matches!(
        home.account(&account.label),
        Err(AccountHomeError::UnknownAccount(_))
    ));
    runtime.shutdown().await;
}

#[tokio::test]
async fn superseded_account_setup_cannot_roll_back_account_state() {
    let directory = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay(directory.path(), "wss://relay.example");
    let public_key = nostr::Keys::generate().public_key().to_hex();
    let account = app.account_home().add_public_account(&public_key).unwrap();
    app.account_home()
        .begin_account_setup_with(
            &account,
            false,
            AccountSetupKind::PublicIdentity,
            AccountSetupPhase::LocalStateCreated,
        )
        .unwrap();
    let external_public_key = nostr::Keys::generate().public_key().to_hex();
    let tracked = app
        .account_home()
        .add_public_account(&external_public_key)
        .unwrap();
    let runtime = MarmotAppRuntime::new(app);

    let admission = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .account_setup_admission(&account.account_id_hex)
            .unwrap()
    };
    {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .advance_setup_admission_generation(&account.account_id_hex);
    }
    let import_rollback: Result<(), AppError> = runtime
        .accounts
        .rollback_import_after_setup_failure(
            &account,
            None,
            admission,
            AppError::MissingDefaultRelays,
        )
        .await;
    assert!(matches!(import_rollback, Err(AppError::AccountWorkerBusy)));
    assert!(
        runtime
            .accounts
            .app
            .account_home()
            .account(&account.label)
            .is_ok(),
        "a stale setup must not remove an account that teardown superseded"
    );

    let (external, external_admission) = {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        let admission = runtime
            .accounts
            .account_setup_admission(&tracked.account_id_hex)
            .unwrap();
        let external = runtime
            .accounts
            .app
            .account_home()
            .add_external_signer_account(&external_public_key)
            .unwrap();
        (external, admission)
    };
    {
        let _worker_transaction = runtime.accounts.worker_transactions.lock().await;
        runtime
            .accounts
            .advance_setup_admission_generation(&external.account_id_hex);
    }
    let external_rollback: Result<(), AppError> = runtime
        .accounts
        .rollback_external_signer_setup(
            &external,
            false,
            true,
            external_admission,
            AppError::MissingDefaultRelays,
        )
        .await;
    assert!(matches!(
        external_rollback,
        Err(AppError::AccountWorkerBusy)
    ));
    assert!(
        runtime
            .accounts
            .app
            .account_home()
            .account(&external.label)
            .unwrap()
            .external_signing,
        "a stale setup must not demote account state after teardown supersedes it"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn message_subscription_recv_ends_when_runtime_shutdown_begins() {
    let lifecycle = RuntimeLifecycle::new();
    let (updates_tx, updates) = mpsc::channel(1);
    let mut subscription = RuntimeMessagesSubscription {
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
    let mut row_fingerprints = HashMap::from([("group".to_owned(), "fingerprint".to_owned())]);

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
    let mut row_fingerprints = HashMap::from([("stale".to_owned(), "old".to_owned())]);
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
fn chat_list_fingerprint_and_expiry_tracking_include_new_interaction_state() {
    let base = chat_list_test_row("group", "title");
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

    manager.spawn_invite_catch_up();

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_close_releases_a_withheld_session_open_before_gate_release() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path();
    let home = AccountHome::open(root);
    let account = home
        .create_account("withheld-open")
        .expect("create account");
    let app = MarmotApp::try_with_relays_and_account_home_and_config(
        root,
        vec!["wss://relay.example".to_owned()],
        AccountHome::open(root),
        MarmotAppConfig::default(),
    )
    .expect("acquire root runtime lease");
    let runtime = app.runtime();
    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));
    let (open_reached, release_open) = install_local_open_gate(&app, &account.label);

    let opening_app = app.clone();
    let opening_runtime = runtime.clone();
    let account_label = account.label.clone();
    let opening = tokio::spawn(async move {
        let shared = opening_runtime.shared_services();
        opening_app
            .runtime_local_client(&account_label, shared.relay_plane(), shared.lifecycle())
            .await
    });
    wait_for_test_signal(open_reached, "withheld local account open").await;

    let session_storage = app
        .account_session_storages
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&account.label)
        .cloned()
        .expect("opened session storage must be registered before handoff");
    let session_path = app.account_storage_path(&account.label);
    let sidecars = [
        std::path::PathBuf::from(format!("{}-wal", session_path.display())),
        std::path::PathBuf::from(format!("{}-shm", session_path.display())),
    ];
    assert!(
        sidecars.iter().all(|path| path.exists()),
        "the withheld session must hold its WAL sidecars before terminal close"
    );
    assert!(matches!(
        crate::MarmotRootRuntimeLease::try_acquire(root),
        Err(AppError::RuntimeBusy)
    ));

    let closing_runtime = runtime.clone();
    tokio::time::timeout(Duration::from_secs(2), closing_runtime.shutdown_and_close())
        .await
        .expect("terminal close must not wait for the withheld result gate")
        .expect("terminal close must succeed");

    assert!(
        !opening.is_finished(),
        "the local-open result must still be withheld when terminal close returns"
    );
    assert!(app.storage_is_closed());
    assert!(session_storage.is_closed());
    for sidecar in sidecars {
        assert!(
            !sidecar.exists(),
            "{} must be released before the open gate is released",
            sidecar.display()
        );
    }
    drop(
        crate::MarmotRootRuntimeLease::try_acquire(root)
            .expect("terminal close must release the root lease before the open gate"),
    );

    release_open.send(()).expect("release local-open result");
    let open_result = opening.await.expect("reap withheld local-open task");
    assert!(matches!(open_result, Err(AppError::RuntimeStopping)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_close_timeout_detaches_instead_of_cancelling_graceful_shutdown() {
    let directory = tempfile::tempdir().expect("tempdir");
    let runtime = MarmotApp::with_relay(directory.path(), "wss://relay.example").runtime();
    runtime.set_shutdown_grace_wait_for_test(Duration::from_millis(50));
    let stall = runtime.stall_shutdown_for_test(ShutdownTestPhase::DirectorySync);

    let closing_runtime = runtime.clone();
    let closing = tokio::spawn(async move { closing_runtime.shutdown_and_close().await });
    stall.wait_until_entered().await;
    tokio::time::timeout(Duration::from_secs(2), closing)
        .await
        .expect("terminal close must retain its host-facing bound")
        .expect("terminal close task must be reapable")
        .expect("terminal close must succeed");
    assert!(
        runtime
            .accounts
            .invite_catch_up_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accepting,
        "the stalled graceful task must not have skipped ahead"
    );

    stall.release();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if !runtime
                .accounts
                .invite_catch_up_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .accepting
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("detached graceful shutdown must continue after its host wait expires");
}

#[tokio::test(flavor = "current_thread")]
async fn reconcile_failure_releases_spawned_worker_session_guards() {
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
    let (rollback_waiter, rollback_started) = std::sync::mpsc::channel();
    runtime
        .accounts()
        .register_reconcile_rollback_waiter(rollback_waiter);

    let reconcile_runtime = runtime.clone();
    let reconcile = tokio::spawn(async move { reconcile_runtime.reconcile_accounts().await });
    let ((), ()) = tokio::join!(
        wait_for_test_signal(alice_reached, "alice open result"),
        wait_for_test_signal(bob_reached, "bob open result"),
    );

    alice_proceed.send(()).expect("release alice open result");
    wait_for_test_signal(rollback_started, "failed-reconcile rollback").await;
    assert!(
        !reconcile.is_finished(),
        "rollback must wait for Bob's in-flight open to release its session guard"
    );
    bob_proceed.send(()).expect("release bob open result");

    let err = reconcile
        .await
        .expect("reconcile task")
        .expect_err("reconcile should fail while alice is busy");
    assert!(matches!(err, AppError::AccountSessionBusy));
    drop(open_runtime_local_test_client(&app, &runtime, "bob").await);
    drop(alice_client);
    runtime.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_reconcile_cannot_lose_workers_to_failed_rollback() {
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
        "reconcile B must not return while reconcile A can still roll back its workers"
    );

    // Alice's failed open result is already captured behind its gate. Releasing
    // the one-shot owner now lets B open Alice after A finishes rolling back.
    drop(alice_client);
    alice_proceed.send(()).expect("release alice open result");
    bob_proceed.send(()).expect("release bob open result");

    let err_a = reconcile_a
        .await
        .expect("reconcile A task")
        .expect_err("reconcile A should preserve Alice's captured busy error");
    assert!(matches!(err_a, AppError::AccountSessionBusy));
    reconcile_b
        .await
        .expect("reconcile B task")
        .expect("reconcile B should install fresh workers after A rolls back");

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
            accepted_endpoints: Vec::new(),
            confirmed_absent_endpoints: Vec::new(),
            failed_endpoints: Vec::new(),
        }]);
    assert_eq!(deleted, 0);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].reason, "relay rejected event (blocked)");
    assert!(!failures[0].reason.contains("evil.example"));
    assert!(!failures[0].reason.contains("leak.example"));
    assert!(!failures[0].reason.contains("attacker-controlled"));
}
