//! Real account-runtime membership changes through the app projection boundary.

use super::*;
use crate::conversation_presentation::ConversationAuthority;
use cgka_traits::engine::{GroupEvent, SendIntent};

fn app_at(dir: &tempfile::TempDir, relay: Arc<ScriptedPushRelayClient>) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        MarmotAppConfig::default()
            .with_dev_settlement_quiescence_ms(0)
            .with_dev_scheduled_convergence_delay_ms(0),
    )
    .with_test_relay_client(relay)
}

/// Deliver actual signed publications through the app's normal inbound seam.
async fn deliver_new(client: &mut AppClient, relay: &ScriptedPushRelayClient, cursor: &mut usize) {
    let events = relay.published_events.lock().unwrap().clone();
    let account = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap();
    for event in &events[*cursor..] {
        let plane = match event.kind {
            1059 if event.tags.iter().any(|tag| {
                tag.first().is_some_and(|v| v == "p") && tag.get(1) == Some(&account.account_id_hex)
            }) =>
            {
                cgka_traits::TransportDeliveryPlane::AccountInbox
            }
            transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE => {
                cgka_traits::TransportDeliveryPlane::Group
            }
            _ => continue,
        };
        client
            .ingest_received_delivery(cgka_traits::TransportDelivery {
                account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                group_id_hint: None,
                message: event.to_transport_message().unwrap(),
                received_at: cgka_traits::Timestamp(unix_now_seconds()),
                source: cgka_traits::TransportDeliverySource {
                    transport: cgka_traits::transport::TransportSource("nostr".into()),
                    plane,
                    endpoint: None,
                    subscription_id: None,
                    wire: None,
                },
            })
            .await
            .unwrap();
    }
    *cursor = events.len();
}

/// Attach the real published KeyPackage event needed by the Welcome wrapper.
async fn published_key_package(
    client: &mut AppClient,
    relay: &ScriptedPushRelayClient,
) -> cgka_traits::KeyPackage {
    let mut kp = client.publish_key_package().await.unwrap();
    let account = client
        .app
        .account_home()
        .account(&client.state.label)
        .unwrap();
    let event = relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event.kind == 30443 && event.pubkey == account.account_id_hex)
        .unwrap()
        .clone();
    kp.source = Some(cgka_traits::engine::KeyPackageSource {
        event_id: MessageId::new(hex::decode(event.id).unwrap()),
    });
    kp
}

/// Read the same stored membership and live authority inputs used by conversation capture.
fn can_send(client: &AppClient, group: &GroupId) -> bool {
    let authority = client.runtime.session().group_authority(group).unwrap();
    let facts = authority.facts;
    ConversationAuthority {
        is_member: facts.is_member,
        self_membership: client
            .app
            .stored_group_self_membership(&client.state.label, &hex::encode(group.as_slice()))
            .unwrap()
            .unwrap(),
        is_admin: facts.is_admin,
        admin_count: facts.admin_count,
        pending_confirmation: false,
        leave_request_pending: client.runtime.session().leave_in_progress(group).unwrap(),
        lifecycle: authority.lifecycle.into(),
        unrecoverable: facts.unrecoverable,
        disbanding: authority.disbanding,
        disbanding_enabled: facts.disbanding_enabled,
        has_disbanding_blockers: facts.has_disbanding_blockers,
    }
    .capabilities()
    .can_send
}

/// A real sibling SelfRemove must not terminate the surviving device's projection.
#[tokio::test]
async fn sibling_selfremove_preserves_surviving_app_device_after_reopen() {
    sibling_selfremove_through_author_command(false).await;
}

/// A group command can confirm a retained sibling departure before its own
/// profile update; the command must observe those native effects as well.
#[tokio::test]
async fn own_group_command_observes_retained_sibling_departure() {
    sibling_selfremove_through_author_command(true).await;
}

async fn sibling_selfremove_through_author_command(profile_command: bool) {
    let dir = tempfile::tempdir().unwrap();
    let sibling_dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let secret = home
        .load_signing_keys("bob")
        .unwrap()
        .secret_key()
        .to_secret_hex();
    AccountHome::open(sibling_dir.path())
        .import_account("bob", &secret)
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = app_at(&dir, relay.clone());
    let sibling_app = app_at(&sibling_dir, relay.clone());
    remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    let mut bob_client = app.client("bob").await.unwrap();
    bob_client.publish_key_package().await.unwrap();
    bob_client.sync().await.unwrap();
    let mut alice = app.client("alice").await.unwrap();
    let mut alice_cursor = 0;
    let mut bob_cursor = 0;
    let group = alice
        .create_group("sibling departure", &[&bob.account_id_hex])
        .await
        .unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.accept_group_invite(&group).unwrap();
    let mut sibling = sibling_app.client("bob").await.unwrap();
    sibling.sync().await.unwrap();
    let mut sibling_cursor = relay.published_events.lock().unwrap().len();
    let kp = published_key_package(&mut sibling, &relay).await;
    let effects = alice
        .runtime
        .send(SendIntent::Invite {
            group_id: group.clone(),
            key_packages: vec![kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    alice
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    deliver_new(&mut sibling, &relay, &mut sibling_cursor).await;
    sibling.sync().await.unwrap();
    sibling.accept_group_invite(&group).unwrap();
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.retry_group_convergence(&group).await.unwrap();
    let group_hex = hex::encode(group.as_slice());
    let surviving_leaf = bob_client.runtime.own_leaf_index(&group).unwrap();
    let departing_leaf = sibling.runtime.own_leaf_index(&group).unwrap();
    assert_ne!(surviving_leaf, departing_leaf);
    for leaf in [surviving_leaf, departing_leaf] {
        let mut token = drained_seam_push_token(&group_hex, &bob.account_id_hex, leaf);
        token.token_fingerprint = "same-device-token".into();
        app.upsert_group_push_token("bob", &token).unwrap();
        app.upsert_group_push_token("alice", &token).unwrap();
    }
    relay.fail_publishes_as_unavailable();
    bob_client
        .send(&group, b"retained sibling send")
        .await
        .unwrap();
    let mut fanout = bob_client
        .runtime
        .session()
        .outbound_fanouts_for_group(&group)
        .unwrap()
        .remove(0);
    for index in fanout.outstanding_target_indexes() {
        let failure = fanout.target_failure(index).unwrap().clone();
        for _ in 0..6 {
            fanout
                .mark_attempt_started_at(index, notifications::unix_now_ms().try_into().unwrap())
                .unwrap();
            fanout
                .record_target_failure(index, failure.clone())
                .unwrap();
        }
    }
    bob_client
        .runtime
        .session()
        .put_outbound_fanout(&fanout)
        .unwrap();
    relay.allow_publishes();
    sibling
        .app
        .upsert_push_registration(
            "bob",
            PushPlatform::Fcm,
            "departing-device-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .unwrap();
    sibling.leave_group(&group).await.unwrap();
    deliver_new(&mut alice, &relay, &mut alice_cursor).await;
    alice.sync().await.unwrap();
    let delay = alice
        .runtime
        .scheduled_self_remove_auto_commit_delay_ms(&group)
        .unwrap()
        .unwrap();
    tokio::time::sleep(Duration::from_millis(delay + 1)).await;
    if profile_command {
        alice
            .update_group_profile(&group, Some("after departure"), None)
            .await
            .unwrap();
    } else {
        alice.retry_group_convergence(&group).await.unwrap();
    }
    let author_tokens = app.group_push_tokens("alice", &group_hex).unwrap();
    assert_eq!(
        author_tokens.len(),
        1,
        "the public command must observe the author's leaf cleanup"
    );
    assert_eq!(author_tokens[0].leaf_index, surviving_leaf);
    deliver_new(&mut bob_client, &relay, &mut bob_cursor).await;
    bob_client.sync().await.unwrap();
    bob_client.retry_group_convergence(&group).await.unwrap();
    assert_eq!(
        app.stored_group_self_membership("bob", &group_hex).unwrap(),
        Some(SelfMembership::Member)
    );
    assert!(can_send(&bob_client, &group));
    let tokens = app.group_push_tokens("bob", &group_hex).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].leaf_index, surviving_leaf);
    let assert_held = |app: &MarmotApp| {
        let rows = app
            .timeline_messages_with_query(
                "bob",
                TimelineMessageQuery {
                    group_id_hex: Some(group_hex.clone()),
                    ..Default::default()
                },
            )
            .unwrap()
            .messages;
        let held = rows
            .iter()
            .find(|row| row.plaintext == "retained sibling send")
            .unwrap();
        assert_eq!(held.invalidation_status, None);
        assert!(!rows.iter().any(|row| {
            row.group_system
                .as_ref()
                .is_some_and(|event| event.system_type == "member_left")
        }));
    };
    deliver_new(&mut sibling, &relay, &mut sibling_cursor).await;
    sibling.sync().await.unwrap();
    sibling.retry_group_convergence(&group).await.unwrap();
    assert!(sibling.runtime.group_record(&group).unwrap().removed);
    assert!(!can_send(&sibling, &group));
    assert_eq!(
        sibling
            .app
            .stored_group_self_membership("bob", &group_hex)
            .unwrap(),
        Some(SelfMembership::Left)
    );
    assert!(!sibling.runtime.has_queued_outbound_intents(&group).unwrap());
    assert!(
        sibling
            .app
            .pending_push_registration_removals("bob")
            .unwrap()
            .is_empty(),
        "termination must not enqueue an unsendable removal rumor"
    );
    assert_held(&app);
    assert!(
        !bob_client
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .is_empty()
    );
    let registration = app
        .upsert_push_registration(
            "bob",
            PushPlatform::Fcm,
            "surviving-device-token",
            &nostr::prelude::Keys::generate().public_key().to_hex(),
            None,
        )
        .unwrap();
    assert!(
        app.pending_push_registration_shares(
            "bob",
            &registration.token_fingerprint,
            registration.updated_at_ms
        )
        .unwrap()
        .contains(&group_hex)
    );
    drop(bob_client);
    drop(alice);
    drop(app);
    let reopened = app_at(&dir, relay);
    let client = reopened.client("bob").await.unwrap();
    assert!(can_send(&client, &group));
    assert!(
        !client
            .runtime
            .session()
            .outbound_fanouts_for_group(&group)
            .unwrap()
            .is_empty()
    );
    assert!(
        reopened
            .pending_push_registration_shares(
                "bob",
                &registration.token_fingerprint,
                registration.updated_at_ms
            )
            .unwrap()
            .contains(&group_hex)
    );
    assert_eq!(
        reopened.group_push_tokens("bob", &group_hex).unwrap()[0].leaf_index,
        surviving_leaf
    );
    assert_held(&reopened);
}

/// Explicit projection-seam regression: a termination consumed after the engine
/// already restored its tree must still withdraw purged sends. This is not a
/// scheduler-driven rollback test; the engine retained-history test owns that proof.
#[tokio::test]
async fn termination_then_restoration_preserves_failed_sends_and_archive() {
    #[derive(Clone, Copy)]
    enum Observer {
        Drained,
        Retry,
        Command,
        Maintenance,
    }
    for (archived, seam, failed) in [
        (false, Observer::Drained, false),
        (true, Observer::Drained, false),
        (false, Observer::Retry, false),
        (true, Observer::Retry, false),
        (false, Observer::Command, false),
        (true, Observer::Command, false),
        (false, Observer::Maintenance, false),
        (true, Observer::Maintenance, false),
        (true, Observer::Drained, true),
        (true, Observer::Retry, true),
        (true, Observer::Command, true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let account = home.create_account("alice").unwrap();
        let app = app_at(&dir, Arc::new(ScriptedPushRelayClient::default()));
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("effect batch", &[]).await.unwrap();
        let group_hex = hex::encode(group.as_slice());
        client.set_group_archived(&group, archived).unwrap();
        app.record_account_app_event(
            "alice",
            &AppMessageProjection {
                authority: None,
                message_id_hex: "held".into(),
                source_message_id_hex: None,
                direction: "sent".into(),
                group_id_hex: group_hex.clone(),
                sender: account.account_id_hex.clone(),
                plaintext: "held send".into(),
                kind: MARMOT_APP_EVENT_KIND_CHAT,
                tags: Vec::new(),
                source_epoch: Some(1),
                retention: None,
                recorded_at: Some(11),
                origin_commit_id: None,
                moderation_grant: false,
            },
        )
        .unwrap();
        let mut effects = marmot_account::AccountDeviceEffects {
            events: vec![
                GroupEvent::LocalGroupCopyTerminated {
                    group_id: group.clone(),
                    voluntary: false,
                },
                GroupEvent::LocalGroupCopyRestored {
                    group_id: group.clone(),
                },
            ],
            ..Default::default()
        };
        if failed {
            effects.failures.push(marmot_account::PublishFailure {
                message_id: MessageId::new(vec![0xef; 32]),
                reason: "unrelated publication failed".into(),
            });
        }
        let result = match seam {
            Observer::Drained => client
                .observe_drained_session_events(&effects)
                .await
                .map(|_| ()),
            Observer::Retry => client
                .observe_convergence_retry_effects(&group, &effects)
                .await
                .map(|_| ()),
            Observer::Command => {
                client
                    .observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                    .await
            }
            Observer::Maintenance => client
                .finish_maintenance_effects(&effects)
                .await
                .map(|_| ()),
        };
        assert_eq!(result.is_err(), failed);
        assert_eq!(
            app.stored_group_self_membership("alice", &group_hex)
                .unwrap(),
            Some(SelfMembership::Member)
        );
        assert_eq!(
            app.group("alice", &group_hex).unwrap().unwrap().archived,
            archived
        );
        let row = app
            .timeline_messages_with_query(
                "alice",
                TimelineMessageQuery {
                    group_id_hex: Some(group_hex.clone()),
                    ..Default::default()
                },
            )
            .unwrap()
            .messages
            .into_iter()
            .find(|row| row.message_id_hex == "held")
            .unwrap();
        assert_eq!(
            row.invalidation_status.as_deref(),
            Some("local_publish_failed")
        );
        // Replay stays absolute and must not create any kind-1210 invitation.
        // The unrelated publication is not retried by this native-event replay.
        effects.failures.clear();
        client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        assert!(
            app.timeline_messages_with_query(
                "alice",
                TimelineMessageQuery {
                    group_id_hex: Some(group_hex),
                    ..Default::default()
                }
            )
            .unwrap()
            .messages
            .iter()
            .all(|row| row.group_system.is_none())
        );
    }
}

/// The maintenance boundary observes each native recovery transition once,
/// even though summary construction and membership projection are separate.
#[cfg(feature = "product-analytics-export")]
#[tokio::test]
async fn maintenance_counts_one_recovery_transition() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let mut app = app_at(&dir, Arc::new(ScriptedPushRelayClient::default()));
    app.product_analytics = crate::product_analytics::test_product_collector();
    let runtime = app.runtime();
    runtime.set_usage_diagnostics_consent(true).unwrap();
    let mut client = app.client("alice").await.unwrap();
    let group = client
        .create_group("maintenance observation", &[])
        .await
        .unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![GroupEvent::PendingCommitRecovered {
            group_id: group,
            recovered_epoch: cgka_traits::EpochId(1),
        }],
        ..Default::default()
    };
    client.finish_maintenance_effects(&effects).await.unwrap();
    let payloads = app.product_analytics.test_payloads();
    let transitions: Vec<_> = payloads
        .iter()
        .filter(|event| {
            event["eventName"] == "mdk_recovery_summary"
                && event["props"]["operation"] == "pending_commit"
        })
        .collect();
    assert_eq!(transitions.len(), 1);
    assert_eq!(transitions[0]["props"]["count_bucket"], "1");
}
