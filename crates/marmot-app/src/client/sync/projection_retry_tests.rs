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
    assert_repaired_activity_precedes_withdrawal(false).await;
}

#[tokio::test]
async fn checkpoint_retry_returns_older_activity_before_retained_withdrawal() {
    assert_repaired_activity_precedes_withdrawal(true).await;
}

async fn assert_repaired_activity_precedes_withdrawal(checkpoint_retry: bool) {
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
    if checkpoint_retry {
        client
            .observe_account_device_effects(
                &marmot_account::AccountDeviceEffects::default(),
                &mut returned,
                "older",
                122,
            )
            .await
            .unwrap();
        // The real activity projection succeeded but its enclosing checkpoint
        // has not: this is the same ownership transfer as a failed drain save.
        let (unreported, _) = client.checkpoint_failure_summary(
            returned,
            SyncCheckpointError::BeforePersistence(AppError::BlockingTask(
                "injected checkpoint failure".into(),
            )),
        );
        assert!(unreported.projection_updates.is_empty());
        client.retain_applied_effects(&newer);
        client
            .retry_pending_runtime_group_subscription_refresh()
            .await
            .unwrap();
        returned = client.take_pending_applied_sync_summary();
    } else {
        client
            .observe_account_device_effects(&newer, &mut returned, "newer", 123)
            .await
            .unwrap();
    }
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

#[tokio::test]
async fn committed_cleanup_retries_conversion_without_sweeping_new_sends() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retry", &[]).await.unwrap();
    relay.fail_publishes_as_unavailable();
    client
        .send(&group, b"purged before restoration")
        .await
        .unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_cleanup_conversion BEFORE INSERT ON chat_list_rows WHEN EXISTS (SELECT 1 FROM app_events WHERE direction = 'sent' AND invalidated = 1) BEGIN SELECT RAISE(FAIL, 'injected cleanup conversion'); END;").unwrap();
    let effects = marmot_account::AccountDeviceEffects {
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
    let error = client
        .observe_drained_session_events(&effects)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected cleanup conversion"));
    assert!(
        timeline(&app, &group).messages[0]
            .invalidation_status
            .is_some()
    );
    connection
        .execute_batch("DROP TRIGGER fail_cleanup_conversion")
        .unwrap();
    let sent = client
        .send(&group, b"accepted after native restoration")
        .await
        .unwrap();
    assert_eq!(
        sent.accept_disposition,
        cgka_traits::SendAcceptDisposition::CompletionUnknown
    );
    // Every send drains older projection debt, even when its own publication
    // produced no native events. The repaired notification remains buffered.
    assert!(client.pending_applied_effects.is_empty());
    let summary = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    let stored = timeline(&app, &group);
    let old = stored
        .messages
        .iter()
        .find(|message| message.plaintext == "purged before restoration")
        .unwrap();
    let new = stored
        .messages
        .iter()
        .find(|message| message.plaintext == "accepted after native restoration")
        .unwrap();
    assert!(old.invalidation_status.is_some());
    assert!(new.invalidation_status.is_none());
    assert!(summary.projection_updates.iter().flat_map(|update| &update.timeline_changes).any(|change| matches!(change, crate::TimelineMessageChange::Upsert { message, .. } if message.message_id_hex == old.message_id_hex && message.invalidation_status.is_some())), "the original cleanup notification must survive conversion failure");
}

#[tokio::test]
async fn cancelling_public_waits_keeps_repaired_notifications() {
    for next_event in [false, true] {
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
        let connection =
            super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
        connection.execute_batch("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
        let mut events = vec![];
        if next_event {
            events.extend([
                GroupEvent::LocalGroupCopyTerminated {
                    group_id: group.clone(),
                    voluntary: false,
                },
                GroupEvent::LocalGroupCopyRestored {
                    group_id: group.clone(),
                },
            ]);
        }
        events.push(rename(&group, &account.account_id_hex, 0x76));
        let effects = marmot_account::AccountDeviceEffects {
            events,
            ..Default::default()
        };
        assert!(
            client
                .observe_account_device_effects(
                    &effects,
                    &mut SyncSummary::default(),
                    "source",
                    123
                )
                .await
                .is_err()
        );
        connection
            .execute_batch("DROP TRIGGER fail_activity")
            .unwrap();
        if next_event {
            relay.block_next_subscribe();
            let observe = client.next_event();
            tokio::pin!(observe);
            tokio::select! {
                result = &mut observe => panic!("subscription should block: {result:?}"),
                _ = relay.wait_for_blocked_subscribe() => {},
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("subscription never started"),
            }
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.sync_sdk_relay())
                    .await
                    .is_err()
            );
        }
        assert!(
            client.pending_applied_effects.is_empty(),
            "cancellation happened after repair"
        );
        let summary = if next_event {
            client.next_event().await.unwrap()
        } else {
            client.sync_sdk_relay().await.unwrap()
        };
        assert_eq!(summary.projection_updates.iter().flat_map(|update| &update.timeline_changes).filter(|change| matches!(change, crate::TimelineMessageChange::Upsert { message, .. } if message.kind == 1210)).count(), 1);
        assert!(
            client
                .take_pending_applied_sync_summary()
                .projection_updates
                .is_empty()
        );
    }
}

#[tokio::test]
async fn failed_message_projection_does_not_duplicate_its_deferred_summary() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("retry", &[]).await.unwrap();
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        account.account_id_hex.clone(),
        unix_now_seconds(),
        9,
        vec![],
        "one deferred message",
    )
    .encode()
    .unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![GroupEvent::MessageReceived {
            authority: None,
            group_id: group.clone(),
            message_id: cgka_traits::MessageId::new(vec![0x81; 32]),
            sender: cgka_traits::MemberId::new(hex::decode(account.account_id_hex).unwrap()),
            epoch: client.runtime.group_record(&group).unwrap().epoch,
            payload,
            retention: None,
            encrypted_media_secret: None,
        }],
        ..Default::default()
    };
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_message BEFORE INSERT ON app_events WHEN NEW.kind = 9 BEGIN SELECT RAISE(FAIL, 'injected message projection'); END;").unwrap();
    let mut failed = SyncSummary::default();
    assert!(
        client
            .observe_account_device_effects(&effects, &mut failed, "source", 123)
            .await
            .is_err()
    );
    assert!(failed.messages.is_empty());
    connection
        .execute_batch("DROP TRIGGER fail_message")
        .unwrap();
    let summary = client.next_event().await.unwrap();
    assert_eq!(summary.messages.len(), 1);
    assert_eq!(summary.messages[0].plaintext, "one deferred message");
    assert_eq!(timeline(&app, &group).messages.len(), 1);
    assert!(
        client.pending_application_event_acks.is_empty(),
        "direct next_event checkpoints the repaired acknowledgement"
    );
}

#[tokio::test]
async fn cancelling_public_sync_while_waiting_for_recovery_keeps_repaired_activity() {
    use crate::runtime::account_worker::recovery_credits;
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app =
        MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
    let mut client = crate::tests::client_on_app_relay_plane(&app, "alice").await;
    client.recovery_credits = recovery_credits::private_recovery_credit_pool_for_test();
    let group = client.create_group("retry", &[]).await.unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected activity'); END;").unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![rename(&group, &account.account_id_hex, 0x82)],
        ..Default::default()
    };
    assert!(
        client
            .observe_account_device_effects(&effects, &mut SyncSummary::default(), "source", 123)
            .await
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER fail_activity")
        .unwrap();
    assert!(client.recovery_pending().unwrap());
    assert!(client.recovery_endpoints_admitted());
    let comparison_before = app
        .account_storage("alice")
        .unwrap()
        .recovery_comparison()
        .unwrap()
        .revision;
    let held = recovery_credits::hold_all_credits_for_test(&client.recovery_credits);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), client.sync())
            .await
            .is_err()
    );
    assert!(
        client.pending_applied_effects.is_empty(),
        "repair completed before the credit wait"
    );
    assert!(
        app.account_storage("alice")
            .unwrap()
            .recovery_comparison()
            .unwrap()
            .revision
            > comparison_before,
        "the public call requested comparison after finishing its first drain"
    );
    assert_eq!(
        app.account_storage("alice")
            .unwrap()
            .recovery_retry_state()
            .unwrap()
            .attempt_serial,
        0,
        "held credits prevent recovery from starting"
    );
    drop(held);
    client.test_comparison_results = Some(ScriptedComparisons::by_route(|_| {
        Ok(Some((
            transport_nostr_adapter::NostrReconciliationSummary {
                relays_succeeded: 1,
                ..Default::default()
            },
            Vec::new(),
        )))
    }));
    let summary = tokio::time::timeout(Duration::from_secs(10), client.sync())
        .await
        .unwrap()
        .unwrap();
    let count_activity = |summary: &SyncSummary| {
        summary.projection_updates.iter().flat_map(|update| &update.timeline_changes).filter(|change| matches!(change, crate::TimelineMessageChange::Upsert { message, .. } if message.kind == 1210)).count()
    };
    assert_eq!(
        count_activity(&summary),
        1,
        "the cancelled call's repaired notification is returned once"
    );
    assert_eq!(count_activity(&client.sync().await.unwrap()), 0);
}

#[tokio::test]
async fn second_local_delete_discards_retry_that_crossed_the_old_frontier() {
    for drained in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let account = AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let relay = Arc::new(ScriptedPushRelayClient::default());
        let app =
            MarmotApp::with_relay(dir.path(), "wss://relay.example").with_test_relay_client(relay);
        let mut client = app.client("alice").await.unwrap();
        let group = client.create_group("deleted retry", &[]).await.unwrap();
        client.delete_group_local(&group).await.unwrap();
        let payload = cgka_traits::app_event::MarmotAppEvent::new(
            &account.account_id_hex,
            unix_now_seconds(),
            9,
            vec![],
            "new after first delete",
        )
        .encode()
        .unwrap();
        let sent = client
            .runtime
            .send(cgka_traits::engine::SendIntent::AppMessage {
                group_id: group.clone(),
                payload: payload.clone(),
                expected_epoch: None,
            })
            .await
            .unwrap();
        let effects = marmot_account::AccountDeviceEffects {
            events: vec![GroupEvent::MessageReceived {
                authority: None,
                group_id: group.clone(),
                message_id: sent.reports[0].message_id.clone(),
                sender: cgka_traits::MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
                epoch: client.runtime.group_record(&group).unwrap().epoch,
                payload,
                retention: None,
                encrypted_media_secret: None,
            }],
            ..Default::default()
        };
        let connection =
            super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
        connection.execute_batch("CREATE TRIGGER fail_new_chat BEFORE INSERT ON app_events WHEN NEW.kind = 9 BEGIN SELECT RAISE(FAIL, 'injected new chat'); END;").unwrap();
        let failed = if drained {
            client
                .observe_drained_session_events(&effects)
                .await
                .map(|_| ())
        } else {
            client
                .observe_account_device_effects(
                    &effects,
                    &mut SyncSummary::default(),
                    "source",
                    unix_now_seconds(),
                )
                .await
                .map(|_| ())
        };
        assert!(failed.is_err());
        assert_eq!(client.pending_applied_effects.len(), 1);
        assert_eq!(
            client.pending_applied_effects[0].progress.events[0].crosses_frontier,
            Some(true)
        );
        assert!(client.delete_group_local(&group).await.unwrap());
        connection
            .execute_batch("DROP TRIGGER fail_new_chat")
            .unwrap();
        let summary = client
            .observe_drained_session_events(&Default::default())
            .await
            .unwrap();
        assert!(summary.messages.is_empty());
        assert!(
            summary
                .projection_updates
                .iter()
                .all(|update| update.group_id_hex != hex::encode(group.as_slice()))
        );
        assert!(timeline(&app, &group).messages.is_empty());
        assert!(
            app.account_storage("alice")
                .unwrap()
                .local_group_deletion_frontier(&hex::encode(group.as_slice()))
                .unwrap()
                .is_some()
        );
        // Durable outbox replay is classified against the newer marker too.
        let replayed = client
            .observe_drained_session_events(&effects)
            .await
            .unwrap();
        assert!(replayed.messages.is_empty());
        assert!(timeline(&app, &group).messages.is_empty());
    }
}

/// A fresh winner may describe the same activity as a withdrawn sibling commit.
/// Its adoption and revival must be atomic, and stale loser replay is harmless.
#[tokio::test]
async fn identical_fork_activity_adopts_canonical_origin_atomically() {
    use cgka_traits::{MessageRecord, MessageState, MessageStorage};
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("fork", &[]).await.unwrap();
    let loser = rename(&group, &account.account_id_hex, 0x76);
    let mut winner = loser.clone();
    if let GroupEvent::GroupStateChanged {
        origin_commit_id, ..
    } = &mut winner
    {
        *origin_commit_id = Some(cgka_traits::MessageId::new(vec![0x77; 32]));
    }
    let storage = app.account_storage("alice").unwrap();
    client.project_group_system_rows(std::slice::from_ref(&loser), 10);
    let original_id = timeline(&app, &group).messages[0].message_id_hex.clone();
    app.invalidate_timeline_origin_commit("alice", &"76".repeat(32), "SupersededByBranchSelection")
        .unwrap();
    for (tag, state) in [
        (0x76, MessageState::ConvergenceDeferred),
        (0x77, MessageState::Processed),
    ] {
        storage
            .put_message(&MessageRecord {
                id: cgka_traits::MessageId::new(vec![tag; 32]),
                group_id: group.clone(),
                epoch: cgka_traits::EpochId(0),
                state,
                payload: vec![],
                deferred_peel: None,
            })
            .unwrap();
    }
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_revival BEFORE UPDATE OF invalidated ON app_events WHEN OLD.invalidated = 1 AND NEW.invalidated = 0 BEGIN SELECT RAISE(FAIL, 'injected revival'); END;").unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![winner],
        ..Default::default()
    };
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    let origin: String = connection
        .query_row(
            "SELECT origin_commit_id FROM app_events WHERE message_id_hex = ?1",
            [&original_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        origin,
        "76".repeat(32),
        "failed revival must roll back origin adoption"
    );
    assert!(
        timeline(&app, &group).messages[0]
            .invalidation_status
            .is_some()
    );
    connection
        .execute_batch("DROP TRIGGER fail_revival")
        .unwrap();
    client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    let current = timeline(&app, &group);
    assert_eq!(current.messages.len(), 1);
    assert_eq!(current.messages[0].message_id_hex, original_id);
    assert!(current.messages[0].invalidation_status.is_none());
    assert!(client.project_group_system_rows(&[loser], 20).is_empty());
    let origin: String = connection
        .query_row(
            "SELECT origin_commit_id FROM app_events WHERE message_id_hex = ?1",
            [&original_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(origin, "77".repeat(32));
    assert!(
        app.invalidate_timeline_origin_commit(
            "alice",
            &"76".repeat(32),
            "SupersededByBranchSelection"
        )
        .unwrap()
        .is_none()
    );
    assert!(
        timeline(&app, &group).messages[0]
            .invalidation_status
            .is_none()
    );
}

/// Metadata-only failures are queued too; conversion failure must not lose a
/// committed invalidation or repeat a previously returned prefix.
#[tokio::test]
async fn eventless_failed_messages_retry_committed_conversion_and_prefix_once() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("metadata retry", &[]).await.unwrap();
    let mut failed_app_messages = Vec::new();
    for (index, content) in ["first", "second"].iter().enumerate() {
        let event = cgka_traits::app_event::MarmotAppEvent::new(
            &account.account_id_hex,
            10,
            9,
            vec![],
            *content,
        );
        client
            .record_send_intent_projection(&group, &account.account_id_hex, &event)
            .unwrap();
        failed_app_messages.push(marmot_account::FailedApplicationMessage {
            group_id: group.clone(),
            app_event_id: event.id,
            message_id: cgka_traits::MessageId::new(vec![index as u8; 32]),
            reason: "test publish failure".into(),
        });
    }
    let second = failed_app_messages[1].app_event_id.clone();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch(&format!("CREATE TRIGGER fail_metadata_conversion BEFORE INSERT ON chat_list_rows WHEN EXISTS (SELECT 1 FROM app_events WHERE message_id_hex = '{second}' AND invalidated = 1) BEGIN SELECT RAISE(FAIL, 'injected metadata conversion'); END;")).unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        failed_app_messages,
        ..Default::default()
    };
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    assert!(
        timeline(&app, &group)
            .messages
            .iter()
            .all(|row| row.invalidation_status.is_some())
    );
    assert_eq!(client.pending_applied_effects.len(), 1);
    assert_eq!(client.pending_applied_effects[0].failed_message_cursor, 1);
    assert!(
        client.pending_applied_effects[0]
            .failed_message_update
            .is_some()
    );
    let first = client.take_pending_applied_sync_summary();
    assert_eq!(first.projection_updates.len(), 1);
    connection
        .execute_batch("DROP TRIGGER fail_metadata_conversion")
        .unwrap();
    let repaired = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    assert_eq!(repaired.projection_updates.len(), 1);
    assert!(client.pending_applied_effects.is_empty());
    assert!(
        client
            .observe_drained_session_events(&Default::default())
            .await
            .unwrap()
            .projection_updates
            .is_empty()
    );
}

#[tokio::test]
async fn never_projected_terminal_group_does_not_stall_live_effects() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let terminal = client.create_group("terminal", &[]).await.unwrap();
    let healthy = client.create_group("healthy", &[]).await.unwrap();
    crate::tests::make_group_terminal(&client, &terminal, true);
    // Model terminal MLS apply completing before the first app projection.
    let terminal_hex = hex::encode(terminal.as_slice());
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection
        .execute(
            "DELETE FROM account_groups WHERE group_id_hex = ?1",
            [&terminal_hex],
        )
        .unwrap();
    client
        .state
        .groups
        .retain(|group| group.group_id_hex != terminal_hex);
    assert!(app.group("alice", &terminal_hex).unwrap().is_none());
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![
            GroupEvent::GroupJoined {
                group_id: terminal.clone(),
                via_welcome: cgka_traits::MessageId::new(vec![0x75; 32]),
                welcomer: None,
                explicitly_confirmed: true,
            },
            GroupEvent::GroupStateChanged {
                group_id: terminal,
                epoch: cgka_traits::EpochId(1),
                actor: Some(client.runtime.session().self_id()),
                change: GroupStateChange::GroupDisbanded,
                origin_commit_id: None,
            },
            rename(&healthy, &account.account_id_hex, 0x76),
        ],
        ..Default::default()
    };
    let mut summary = SyncSummary::default();
    client
        .observe_account_device_effects(&effects, &mut summary, "batch", 10)
        .await
        .unwrap();
    assert!(client.pending_applied_effects.is_empty());
    assert_eq!(timeline(&app, &healthy).messages.len(), 1);
}

#[tokio::test]
async fn early_bookkeeping_failure_retains_native_effects() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("bookkeeping", &[]).await.unwrap();
    let effects = marmot_account::AccountDeviceEffects {
        events: vec![rename(&group, &account.account_id_hex, 0x76)],
        ..Default::default()
    };
    client.released_backfill_reload_pending = true;
    client.fail_next_released_backfill_reload = true;
    assert!(
        client
            .observe_drained_session_events(&effects)
            .await
            .is_err()
    );
    assert!(timeline(&app, &group).messages.is_empty());
    assert_eq!(client.pending_applied_effects.len(), 1);
    let repaired = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    assert_eq!(repaired.projection_updates.len(), 1);
    assert_eq!(timeline(&app, &group).messages.len(), 1);
}

#[tokio::test]
async fn accepted_own_group_command_retains_failed_activity_without_republishing() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("own activity", &[]).await.unwrap();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_own_activity BEFORE INSERT ON app_events WHEN NEW.kind = 1210 BEGIN SELECT RAISE(FAIL, 'injected own activity'); END;").unwrap();
    let result = client
        .update_group_profile(&group, Some("retained own rename"), None)
        .await
        .unwrap();
    assert_eq!(
        result.accept_disposition,
        cgka_traits::SendAcceptDisposition::Published
    );
    assert!(timeline(&app, &group).messages.is_empty());
    assert!(client.has_pending_effect_projections());
    let published = relay.published_event_ids().len();
    connection
        .execute_batch("DROP TRIGGER fail_own_activity")
        .unwrap();
    let repaired = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    assert_eq!(repaired.projection_updates.len(), 1);
    assert_eq!(timeline(&app, &group).messages.len(), 1);
    assert_eq!(relay.published_event_ids().len(), published);
}

/// A committed rename remains an activity even when the command's later local
/// profile refresh fails. Its canonical event will not be emitted again.
#[tokio::test]
async fn accepted_own_activity_survives_later_local_refresh_failure() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("before refresh", &[]).await.unwrap();
    client.take_pending_projection_updates();
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_own_refresh BEFORE INSERT ON account_groups WHEN NEW.profile_name = 'committed rename' BEGIN SELECT RAISE(FAIL, 'injected local refresh'); END;").unwrap();
    assert!(
        client
            .update_group_profile(&group, Some("committed rename"), None)
            .await
            .is_err()
    );
    assert_eq!(timeline(&app, &group).messages.len(), 1);
    assert_eq!(client.take_pending_projection_updates().len(), 1);
    let published = relay.published_event_ids().len();
    connection
        .execute_batch("DROP TRIGGER fail_own_refresh")
        .unwrap();
    client
        .save_state_with_pending_local_group_deletion_frontier_clears()
        .unwrap();
    let repaired = client
        .observe_drained_session_events(&Default::default())
        .await
        .unwrap();
    assert!(repaired.projection_updates.is_empty());
    assert_eq!(timeline(&app, &group).messages.len(), 1);
    assert_eq!(relay.published_event_ids().len(), published);
}

#[tokio::test]
async fn accepted_source_finalization_rolls_back_when_revival_conversion_fails() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()));
    let mut client = app.client("alice").await.unwrap();
    let group = client.create_group("source atomicity", &[]).await.unwrap();
    let event = cgka_traits::app_event::MarmotAppEvent::new(
        &account.account_id_hex,
        unix_now_seconds(),
        9,
        vec![],
        "revived send",
    );
    client
        .record_send_intent_projection(&group, &account.account_id_hex, &event)
        .unwrap();
    app.invalidate_timeline_app_event(
        "alice",
        &hex::encode(group.as_slice()),
        &event.id,
        crate::LOCAL_PUBLISH_FAILED_REASON,
    )
    .unwrap();
    let effects = client
        .runtime
        .send(cgka_traits::engine::SendIntent::AppMessage {
            group_id: group.clone(),
            payload: event.encode().unwrap(),
            expected_epoch: None,
        })
        .await
        .unwrap();
    assert_eq!(effects.published_app_messages.len(), 1);
    let connection =
        super::runtime_group_subscription_refresh_tests::projection_fault_connection(&app);
    connection.execute_batch("CREATE TRIGGER fail_source_revival BEFORE INSERT ON chat_list_rows WHEN EXISTS (SELECT 1 FROM app_events WHERE invalidated = 0 AND source_message_id_hex IS NOT NULL) BEGIN SELECT RAISE(FAIL, 'injected source revival'); END;").unwrap();
    assert!(
        client
            .finalize_published_app_message_source_retention(&effects)
            .unwrap()
            .is_empty()
    );
    let failed = timeline(&app, &group).messages.remove(0);
    assert!(failed.source_message_id_hex.is_none());
    assert!(failed.invalidation_status.is_some());
    connection
        .execute_batch("DROP TRIGGER fail_source_revival")
        .unwrap();
    assert!(
        !client
            .finalize_published_app_message_source_retention(&effects)
            .unwrap()
            .is_empty()
    );
    let repaired = timeline(&app, &group).messages.remove(0);
    assert!(repaired.source_message_id_hex.is_some());
    assert!(repaired.invalidation_status.is_none());
}
