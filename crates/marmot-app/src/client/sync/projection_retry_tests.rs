//! Failure injection for resumable native projection and ordered subscribers.
use super::*;
use crate::tests::ScriptedPushRelayClient;
use crate::{AccountHome, MarmotApp};
use cgka_traits::engine::{GroupEvent, GroupStateChange, GroupStateInvalidationReason};
use std::sync::Arc;

fn rename(group: &GroupId, actor: &str, id: u8) -> GroupEvent {
    GroupEvent::GroupStateChanged {
        group_id: group.clone(),
        epoch: cgka_traits::EpochId(1),
        actor: Some(cgka_traits::MemberId::new(hex::decode(actor).unwrap())),
        change: GroupStateChange::GroupRenamed {
            name: format!("rename {id}"),
            previous_name: None,
        },
        origin_commit_id: Some(cgka_traits::MessageId::new(vec![id; 32])),
    }
}

fn timeline(app: &MarmotApp, group: &GroupId) -> crate::TimelinePage {
    app.timeline_messages_with_query(
        "alice",
        storage_sqlite::TimelineMessageQuery {
            group_id_hex: Some(hex::encode(group.as_slice())),
            ..Default::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn restored_copy_retry_preserves_a_new_pending_send() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retry", &[]).await.unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![
            GroupEvent::LocalGroupCopyTerminated {
                group_id: group.clone(),
                voluntary: false,
            },
            GroupEvent::LocalGroupCopyRestored {
                group_id: group.clone(),
            },
            rename(&group, &account.account_id_hex, 0x76),
        ],
        ..Default::default()
    };
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    assert_eq!(
        app.stored_group_self_membership("alice", &hex::encode(group.as_slice()))
            .unwrap(),
        Some(storage_sqlite::SelfMembership::Member)
    );
    relay.fail_publishes_as_unavailable();
    let sent = client.send(&group, b"after restoration").await.unwrap();
    assert_eq!(
        sent.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    let fanouts = client.runtime.session().outbound_fanouts().unwrap();
    assert_eq!(fanouts.len(), 1);
    connection
        .execute_batch("DROP TRIGGER fail_activity")
        .unwrap();
    client
        .retry_pending_runtime_group_subscription_refresh()
        .await
        .unwrap();
    assert_eq!(
        client.runtime.session().outbound_fanouts().unwrap(),
        fanouts
    );
    let row = timeline(&app, &group)
        .messages
        .into_iter()
        .find(|row| row.plaintext == "after restoration")
        .unwrap();
    assert!(row.source_message_id_hex.is_none());
    assert!(
        row.invalidation_status.is_none(),
        "an old termination must not fail a later send"
    );
}

#[tokio::test]
async fn repaired_activity_is_returned_before_its_newer_withdrawal() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retry", &[]).await.unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![rename(&group, &account.account_id_hex, 0x76)],
        ..Default::default()
    };
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER fail_activity")
        .unwrap();
    let newer = marmot_account::AccountDeviceEffects {
        events: vec![GroupEvent::GroupStateInvalidated {
            group_id: group.clone(),
            epoch: cgka_traits::EpochId(1),
            invalidated_commit_id: cgka_traits::MessageId::new(vec![0x76; 32]),
            reason: GroupStateInvalidationReason::SupersededByBranchSelection,
        }],
        ..Default::default()
    };
    let mut returned = SyncSummary::default();
    client
        .observe_account_device_effects(&newer, &mut returned, "newer", 123)
        .await
        .unwrap();
    let mut window = crate::TimelinePage {
        messages: vec![],
        has_more_before: false,
        has_more_after: false,
    };
    for update in &returned.projection_updates {
        crate::runtime::apply_projection_to_window(&mut window, update, 100, true);
    }
    let buffered = client.take_pending_applied_sync_summary();
    for update in &buffered.projection_updates {
        crate::runtime::apply_projection_to_window(&mut window, update, 100, true);
    }
    let stored = timeline(&app, &group);
    assert_eq!(stored.messages.len(), 1);
    assert!(stored.messages[0].invalidation_status.is_some());
    assert_eq!(
        window.messages, stored.messages,
        "subscriber order must agree with SQLite"
    );
    assert!(buffered.projection_updates.is_empty());
}

#[tokio::test]
async fn quiet_public_clients_return_repaired_activity_once() {
    for next_event in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("retry", &[]).await.unwrap();
        let connection =
            super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
        connection.execute_batch(&format!("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 AND NEW.origin_commit_id = '{}' BEGIN SELECT RAISE(FAIL, 'injected activity'); END;", "77".repeat(32))).unwrap();
        let effects = marmot_account::AccountDeviceEffects {
            events: vec![
                rename(&group, &account.account_id_hex, 0x76),
                rename(&group, &account.account_id_hex, 0x77),
            ],
            ..Default::default()
        };
        assert!(
            client
                .observe_drained_session_events(&effects)
                .await
                .is_err()
        );
        connection
            .execute_batch("DROP TRIGGER fail_activity")
            .unwrap();
        let summary = tokio::time::timeout(Duration::from_secs(5), async {
            if next_event {
                client.next_event().await
            } else {
                client.sync().await
            }
        })
        .await
        .expect("quiet repair cannot wait for a new delivery")
        .unwrap();
        let row_ids: Vec<_> = summary
            .projection_updates
            .iter()
            .flat_map(|update| &update.timeline_changes)
            .filter_map(|change| match change {
                crate::TimelineMessageChange::Upsert { message, .. } if message.kind == 1210 => {
                    Some(message.message_id_hex.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(row_ids.len(), 2, "each repaired activity is returned once");
        assert_ne!(row_ids[0], row_ids[1]);
        assert!(
            client
                .take_pending_applied_sync_summary()
                .projection_updates
                .is_empty()
        );
        let second = client
            .observe_drained_session_events(&Default::default())
            .await
            .unwrap();
        assert!(second.projection_updates.is_empty());
    }
}

#[tokio::test]
async fn cancelled_drain_checkpoint_retains_progress_and_notifications() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    client.prepare_transport().await.unwrap();
    let telemetry = AppPerformanceTelemetry::default();
    let group = client
        .create_group_with_options_and_telemetry("retry", &[], Default::default(), &telemetry)
        .await
        .unwrap()
        .group_id;
    client
        .create_group_with_options_and_telemetry(
            "pending route",
            &[],
            Default::default(),
            &telemetry,
        )
        .await
        .unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![
            GroupEvent::LocalGroupCopyTerminated {
                group_id: group.clone(),
                voluntary: false,
            },
            GroupEvent::LocalGroupCopyRestored {
                group_id: group.clone(),
            },
            rename(&group, &account.account_id_hex, 0x76),
        ],
        ..Default::default()
    };
    relay.block_next_subscribe();
    {
        let observe = client.observe_drained_session_events(&effects);
        tokio::pin!(observe);
        tokio::select! {
            result = &mut observe => panic!("checkpoint should block: {result:?}"),
            _ = relay.wait_for_blocked_subscribe() => {},
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("checkpoint never reached subscription"),
        }
        // Drop the future exactly as a maintenance timeout does.
    }
    assert_eq!(client.pending_applied_effects.len(), 1);
    assert!(
        client.pending_applied_effects[0]
            .progress
            .events
            .iter()
            .all(|event| event.completed)
    );
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER reject_repeated_cleanup BEFORE UPDATE OF self_membership ON account_groups WHEN NEW.self_membership = 'removed' BEGIN SELECT RAISE(FAIL, 'cleanup repeated'); END;").unwrap();
    let summary = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    assert!(client.pending_applied_effects.is_empty());
    assert_eq!(summary.projection_updates.iter().flat_map(|update| &update.timeline_changes).filter(|change| matches!(change, crate::TimelineMessageChange::Upsert { message, .. } if message.kind == 1210)).count(), 1);
    assert!(
        client
            .take_pending_applied_sync_summary()
            .projection_updates
            .is_empty()
    );
}

#[tokio::test]
async fn partial_sync_failure_transfers_the_committed_prefix_once() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retry", &[]).await.unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch(&format!("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 AND NEW.origin_commit_id = '{}' BEGIN SELECT RAISE(FAIL, 'injected activity'); END;", "77".repeat(32))).unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![
            rename(&group, &account.account_id_hex, 0x76),
            rename(&group, &account.account_id_hex, 0x77),
        ],
        ..Default::default()
    };
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    let failure = client.sync_with_partial_progress().await.unwrap_err();
    assert_eq!(failure.partial_summary.projection_updates.len(), 1);
    assert!(
        client
            .take_pending_applied_sync_summary()
            .projection_updates
            .is_empty()
    );
    connection
        .execute_batch("DROP TRIGGER fail_activity")
        .unwrap();
    let repaired = client.sync().await.unwrap();
    assert_eq!(repaired.projection_updates.len(), 1);
    assert_ne!(
        repaired.projection_updates[0],
        failure.partial_summary.projection_updates[0]
    );
    assert!(client.sync().await.unwrap().projection_updates.is_empty());
}
