use super::super::MAX_NATIVE_ADMISSION_PER_TURN;
use super::*;

fn fault_connection(client: &AppClient) -> rusqlite::Connection {
    let app = &client.app;
    let label = &client.state.label;
    let path = app.account_storage_path(label);
    let keys = app.account_home().load_signing_keys(label).unwrap();
    let key = app
        .sqlcipher_key(label, &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    storage_sqlite::expect_uncounted_writes_for_test(&path);
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

fn fail_message(connection: &rusqlite::Connection, group: &GroupId) {
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER fail_native_message BEFORE INSERT ON cgka_messages
             WHEN NEW.group_id = x'{}'
             BEGIN SELECT RAISE(FAIL, 'injected native backend failure'); END;",
            hex::encode(group.as_slice()),
        ))
        .unwrap();
}

fn visible_messages(client: &AppClient, group: &GroupId) -> Vec<crate::AppMessageRecord> {
    client
        .app
        .messages_with_query(
            "receiver",
            crate::AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: None,
            },
        )
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_cursor_save_retry() {
    let mut fixture = crypto_fixture().await;
    let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let event = events[0].clone();
    let baseline = unix_now_seconds().saturating_sub(600);
    let connection = fault_connection(&fixture.receiver);
    connection
        .execute(
            "UPDATE account_state SET last_transport_timestamp=?1 WHERE label='receiver'",
            [baseline as i64],
        )
        .unwrap();
    fixture.receiver.state.last_transport_timestamp = Some(baseline);
    fixture.receiver.checkpointed_transport_timestamp = Some(baseline);
    connection.execute_batch(
        "CREATE TRIGGER fail_native_cursor BEFORE UPDATE OF last_transport_timestamp ON account_state
         WHEN NEW.last_transport_timestamp > OLD.last_transport_timestamp
         BEGIN SELECT RAISE(FAIL, 'injected native cursor failure'); END;",
    ).unwrap();
    lease_native(&mut fixture.receiver, &fixture.group, vec![event.clone()]).await;
    assert!(
        fixture.receiver.next_event().await.is_err(),
        "the cursor save error remains observable"
    );
    assert_eq!(
        visible_messages(&fixture.receiver, &fixture.group).len(),
        1,
        "the MLS input was durable before its cursor save failed"
    );
    assert_eq!(
        fixture
            .receiver
            .app
            .load_state("receiver")
            .unwrap()
            .last_transport_timestamp,
        Some(baseline)
    );

    connection
        .execute_batch("DROP TRIGGER fail_native_cursor")
        .unwrap();
    let summary = timeout(Duration::from_secs(5), fixture.receiver.next_event())
        .await
        .expect("a cursor retry must not need another relay event")
        .unwrap();
    assert_eq!(summary.messages.len(), 1);
    assert_eq!(
        expected.get(&summary.messages[0].message_id_hex),
        Some(&summary.messages[0].plaintext)
    );
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
    assert!(
        fixture
            .receiver
            .app
            .load_state("receiver")
            .unwrap()
            .last_transport_timestamp
            .is_some_and(|cursor| cursor >= event.event.created_at)
    );
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty(),
        "cursor settlement must not publish duplicate plaintext"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_native_restores_cursor() {
    let mut fixture = crypto_fixture().await;
    let (events, _) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let event = events[0].clone();
    let baseline = unix_now_seconds().saturating_sub(600);
    let connection = fault_connection(&fixture.receiver);
    connection
        .execute(
            "UPDATE account_state SET last_transport_timestamp=?1 WHERE label='receiver'",
            [baseline as i64],
        )
        .unwrap();
    fixture.receiver.state.last_transport_timestamp = Some(baseline);
    fixture.receiver.checkpointed_transport_timestamp = Some(baseline);
    lease_native(&mut fixture.receiver, &fixture.group, vec![event.clone()]).await;
    // Stop after durable message admission and ACK, before the automatic
    // cursor save. Reopen loses the process-local cursor save intent.
    fixture.receiver.admit_native_frame().await.unwrap();
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
    let app = fixture.receiver.app.clone();
    assert_eq!(
        app.load_state("receiver").unwrap().last_transport_timestamp,
        Some(baseline)
    );
    drop(fixture.receiver);
    fixture.receiver = client_on_app_relay_plane(&app, "receiver").await;
    fixture.receiver.prepare_transport().await.unwrap();
    lease_native(&mut fixture.receiver, &fixture.group, vec![event.clone()]).await;
    // A turn defers the save it owes while the reopened plane's replay
    // admission settles, or while another plane task holds the state the
    // cursor seal reads without waiting. The intent survives the deferral, so
    // later turns save it without another delivery.
    timeout(Duration::from_secs(10), async {
        loop {
            fixture.receiver.admit_native_turn().await.unwrap();
            if app
                .load_state("receiver")
                .unwrap()
                .last_transport_timestamp
                .is_some_and(|cursor| cursor >= event.event.created_at)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the redelivered duplicate restores the cursor save");
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty(),
        "an already-held replay repairs its floor without duplicate plaintext notifications"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_spill_ack_is_durable() {
    let mut fixture = crypto_fixture().await;
    let (events, _) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let event = events[0].clone();
    let deliveries = fixture
        .receiver
        .adapter
        .recovered_deliveries(event.clone())
        .await
        .unwrap();
    let id = deliveries[0].message.id.clone();
    let storage = fixture
        .receiver
        .app
        .account_storage("receiver")
        .unwrap()
        .app_storage();
    storage
        .spill_account_deliveries(
            &deliveries,
            crate::client::delivery_spill::ACCOUNT_DELIVERY_SPILL_LIMITS,
            unix_now_seconds(),
        )
        .unwrap();
    let seq = storage
        .spilled_account_deliveries(8, i64::MAX as u64)
        .unwrap()
        .deliveries[0]
        .seq;
    lease_native(&mut fixture.receiver, &fixture.group, vec![event]).await;
    fixture
        .receiver
        .recovery_owner
        .retained_spill
        .insert(id.clone(), seq);
    let connection = fault_connection(&fixture.receiver);
    connection.execute_batch("CREATE TRIGGER fail_native_settlement BEFORE DELETE ON account_delivery_spill BEGIN SELECT RAISE(FAIL, 'injected native ACK failure'); END;").unwrap();
    for _ in 0..3 {
        assert!(fixture.receiver.next_event().await.is_err());
        assert_eq!(
            fixture.receiver.recovery_owner.retained_spill.get(&id),
            Some(&seq)
        );
        assert_eq!(
            fixture
                .receiver
                .recovery_owner
                .native_batch
                .as_ref()
                .unwrap()
                .delivery()
                .unwrap()
                .message
                .id,
            id
        );
        assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
    }
    connection
        .execute_batch("DROP TRIGGER fail_native_settlement")
        .unwrap();
    let summary = fixture.receiver.next_event().await.unwrap();
    assert_eq!(
        summary.messages.len(),
        1,
        "the committed plaintext is returned exactly once after settlement"
    );
    assert!(
        !fixture
            .receiver
            .recovery_owner
            .retained_spill
            .contains_key(&id)
    );
    assert!(
        storage
            .spilled_account_deliveries(8, i64::MAX as u64)
            .unwrap()
            .deliveries
            .is_empty()
    );
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty(),
        "an acknowledged spill must not publish duplicate plaintext"
    );
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_error_stays_visible() {
    let mut fixture = crypto_fixture().await;
    let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let event = events[0].clone();
    let connection = fault_connection(&fixture.receiver);
    fail_message(&connection, &fixture.group);
    lease_native(&mut fixture.receiver, &fixture.group, vec![event]).await;
    for _ in 0..3 {
        assert!(fixture.receiver.next_event().await.is_err());
        assert!(fixture.receiver.sync().await.is_err());
        assert!(visible_messages(&fixture.receiver, &fixture.group).is_empty());
    }
    connection
        .execute_batch("DROP TRIGGER fail_native_message")
        .unwrap();
    let summary = fixture.receiver.next_event().await.unwrap();
    assert_eq!(summary.messages.len(), 1);
    let message = &summary.messages[0];
    assert_eq!(
        expected.get(&message.message_id_hex),
        Some(&message.plaintext)
    );
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty(),
        "retrying a settled native input must not publish duplicate plaintext"
    );
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_receipts_yield() {
    let mut fixture = crypto_fixture().await;
    let (mut events, _) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    events.truncate(4 * MAX_NATIVE_ADMISSION_PER_TURN + 1);
    events.sort_by_key(|event| (event.event.created_at, event.event.id.clone()));
    let held = 3 * MAX_NATIVE_ADMISSION_PER_TURN;
    for event in &events[..held] {
        let deliveries = fixture
            .receiver
            .adapter
            .recovered_deliveries(event.clone())
            .await
            .unwrap();
        fixture
            .receiver
            .admit_recovered_delivery(
                &deliveries[0],
                crate::client::sync::InventoryWrite::Immediate,
            )
            .await
            .unwrap();
    }
    fixture.receiver.take_pending_applied_sync_summary();
    lease_native(&mut fixture.receiver, &fixture.group, events).await;
    for _ in 0..3 {
        assert!(fixture.receiver.admit_native_turn().await.unwrap());
        assert!(
            fixture
                .receiver
                .take_pending_applied_sync_summary()
                .messages
                .is_empty()
        );
        assert_eq!(
            visible_messages(&fixture.receiver, &fixture.group).len(),
            held
        );
    }
    assert!(fixture.receiver.admit_native_turn().await.unwrap());
    assert_eq!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .len(),
        MAX_NATIVE_ADMISSION_PER_TURN
    );
    assert!(fixture.receiver.admit_native_turn().await.unwrap());
    assert_eq!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .len(),
        1
    );
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty(),
        "settled receipts must not publish duplicate plaintext"
    );
    assert_eq!(
        visible_messages(&fixture.receiver, &fixture.group).len(),
        held + MAX_NATIVE_ADMISSION_PER_TURN + 1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_error_keeps_fairness() {
    let mut fixture = crypto_fixture().await;
    let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let event = events[0].clone();
    let receiver_id = fixture
        .receiver
        .app
        .account_home()
        .account("receiver")
        .unwrap()
        .account_id_hex;
    let healthy_group = fixture
        .sender
        .create_group("independent native backlog", &[&receiver_id])
        .await
        .unwrap();
    fixture.receiver.sync().await.unwrap();
    let (mut healthy_events, healthy_expected) =
        encrypted_texts(&mut fixture.sender, &healthy_group).await;
    // More than two turns must remain eligible independently of the failing
    // group. Whichever ready ticket wins first, it cannot drain this backlog
    // before the other group's first failed turn.
    let healthy_count = 2 * MAX_NATIVE_ADMISSION_PER_TURN + 1;
    healthy_events.truncate(healthy_count);
    let connection = fault_connection(&fixture.receiver);
    fail_message(&connection, &fixture.group);
    let mut deliveries = fixture
        .receiver
        .adapter
        .recovered_deliveries(event)
        .await
        .unwrap();
    for event in healthy_events {
        deliveries.extend(
            fixture
                .receiver
                .adapter
                .recovered_deliveries(event)
                .await
                .unwrap(),
        );
    }
    let storage = fixture
        .receiver
        .app
        .account_storage("receiver")
        .unwrap()
        .app_storage();
    assert_eq!(
        storage
            .spill_account_deliveries(
                &deliveries,
                crate::client::delivery_spill::ACCOUNT_DELIVERY_SPILL_LIMITS,
                unix_now_seconds(),
            )
            .unwrap(),
        vec![storage_sqlite::DeliverySpillDisposition::Stored; healthy_count + 1]
    );
    let app = fixture.receiver.app.clone();
    let group = fixture.group.clone();
    drop(fixture.receiver);
    drop(fixture.sender);
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let mut notices = runtime.subscribe();
    runtime.reconcile_accounts().await.unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            if let crate::MarmotAppEvent::AccountError(error) = notices.recv().await.unwrap()
                && error.account_label == "receiver"
                && error.message.starts_with("native replay admission failed")
            {
                break;
            }
        }
    })
    .await
    .expect("retained native backend failure is observable to runtime consumers");
    // reconcile_accounts acknowledges local readiness, not completion of the
    // sender's initial sync. PublishKeyPackage is a mutation on that startup
    // FIFO and may also generate keys; its latency is not an admission timer.
    // Exercise public serviceability separately from the error-rate window.
    timeout(Duration::from_secs(30), async {
        for _ in 0..4 {
            runtime
                .group_recovery_status("receiver", &group)
                .await
                .unwrap();
        }
        runtime.publish_key_package("sender").await.unwrap();
    })
    .await
    .expect("native failure backoff does not starve public commands or another account");

    // Subscribe afresh so startup/publication latency cannot turn legitimate
    // retries into an apparent flood. An arbitrary-phase window can include
    // one scheduled retry, plus one for each complete second if the executor
    // resumes late. The paused worker test pins the exact 1–60s deadlines.
    let mut paced_notices = runtime.subscribe();
    let pacing_started = std::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut failures = 0_u64;
    loop {
        match paced_notices.try_recv() {
            Ok(crate::MarmotAppEvent::AccountError(error))
                if error.account_label == "receiver"
                    && error.message.starts_with("native replay admission failed") =>
            {
                failures += 1;
                let allowed_failures = pacing_started.elapsed().as_secs().saturating_add(1);
                assert!(
                    failures <= allowed_failures,
                    "the same deterministic native failure must not exceed the one-second minimum retry spacing"
                );
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
            Err(error) => panic!("native pacing observation lost runtime events: {error}"),
        }
    }
    timeout(Duration::from_secs(20), async {
        loop {
            let visible = app
                .messages_with_query(
                    "receiver",
                    crate::AppMessageQuery {
                        group_id_hex: Some(hex::encode(healthy_group.as_slice())),
                        kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                        limit: None,
                    },
                )
                .unwrap();
            if visible.len() == healthy_count {
                for message in visible {
                    assert_eq!(
                        healthy_expected.get(&message.message_id_hex),
                        Some(&message.plaintext)
                    );
                }
                break;
            }
            assert!(visible.len() < healthy_count);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect(
        "a failed native group must rotate behind independent native backlog in the same account",
    );
    assert!(
        app.messages_with_query(
            "receiver",
            crate::AppMessageQuery {
                group_id_hex: Some(hex::encode(group.as_slice())),
                kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                limit: None,
            }
        )
        .unwrap()
        .is_empty(),
        "the failed group's backend fault remains active throughout independent progress"
    );
    assert!(
        runtime.catch_up_accounts().await.is_err(),
        "an explicit drain must still expose the retained failure"
    );
    connection
        .execute_batch("DROP TRIGGER fail_native_message")
        .unwrap();
    timeout(Duration::from_secs(30), async {
        loop {
            let visible = app
                .messages_with_query(
                    "receiver",
                    crate::AppMessageQuery {
                        group_id_hex: Some(hex::encode(group.as_slice())),
                        kinds: Some(vec![MARMOT_APP_EVENT_KIND_CHAT]),
                        limit: None,
                    },
                )
                .unwrap();
            if let [message] = visible.as_slice() {
                assert_eq!(
                    expected.get(&message.message_id_hex),
                    Some(&message.plaintext)
                );
                break;
            }
            assert!(visible.is_empty());
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("releasing the persistent fault lets the retained frame ingest exactly once");
    runtime.drain_in_flight_work().await.unwrap();
    assert!(
        storage
            .spilled_account_deliveries(8, i64::MAX as u64)
            .unwrap()
            .deliveries
            .is_empty()
    );
    drop(connection);
    runtime.shutdown_and_close().await.unwrap();
}

/// A real Welcome's post-join history prerequisite must progress under the
/// new owner once ordinary count/boundary evidence is settled. Cursor and
/// projection tests do not assert the engine maintenance/history-fetch handoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_owned_history_starts_grace_without_fabricating_coverage() {
    let mut fixture = crypto_fixture().await;
    fixture
        .receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    fixture.receiver.sync().await.unwrap();
    fixture
        .receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    let status = fixture.receiver.maintenance_status(&fixture.group).unwrap();
    let post_join = status
        .obligations
        .iter()
        .find(|job| job.trigger == cgka_traits::MaintenanceTrigger::PostJoin)
        .expect("real Welcome created the post-join obligation");
    assert_eq!(
        post_join.phase,
        cgka_traits::MaintenancePhase::Grace,
        "runner-owned history must supply the post-join boundary without an old comparison grant"
    );
    let fetch = fixture
        .receiver
        .runtime
        .post_join_history_fetch(&fixture.group)
        .unwrap()
        .expect("the joined copy owns its fetch");
    assert_eq!(
        fetch.completion.map(|value| value.outcome),
        None,
        "a scripted empty EOSE without a sweep backend cannot certify history"
    );
    let before = post_join.clone();
    let app = fixture.receiver.app.clone();
    drop(fixture.receiver);
    let mut receiver = client_on_app_relay_plane(&app, "receiver").await;
    receiver.prepare_transport().await.unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    let after = receiver
        .runtime
        .maintenance_obligations_for_group(&fixture.group)
        .unwrap()
        .into_iter()
        .find(|job| job.trigger == cgka_traits::MaintenanceTrigger::PostJoin)
        .unwrap();
    assert_eq!(
        after.eose_deadline_at, before.eose_deadline_at,
        "unfinished collection does not move maintenance's EOSE deadline on reopen"
    );
    assert_eq!(
        after.grace_until, before.grace_until,
        "unfinished collection does not restart grace on reopen"
    );
    assert_eq!(
        receiver
            .runtime
            .post_join_history_fetch(&fixture.group)
            .unwrap(),
        Some(fetch),
        "reopening an unfinished fetch preserves its durable identity and deadline"
    );
}

use crate::tests::limited_relay as post_join_relay;

/// Actual SDK acquisition, encrypted history admission, durable completion,
/// and client replacement at the app handoff. The capped relay supplies wire
/// evidence, not the asserted maintenance or fetched state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_owned_history_releases_post_join_maintenance() {
    let (_relay, url) = post_join_relay::mock_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let home = crate::AccountHome::open(dir.path());
    home.create_account("sender").unwrap();
    let recipient = home.create_account("receiver").unwrap();
    let config = crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true);
    let app = crate::MarmotApp::with_relay_and_config(dir.path(), &url, config);
    remember_test_member_inbox(&app, &recipient.account_id_hex, &url);
    let mut receiver = client_on_app_relay_plane(&app, "receiver").await;
    receiver.publish_key_package().await.unwrap();
    receiver.prepare_transport().await.unwrap();
    let mut sender = client_on_app_relay_plane(&app, "sender").await;
    let group = sender
        .create_group("runner post-join history", &[&recipient.account_id_hex])
        .await
        .unwrap();
    sender
        .send(&group, b"history before the join")
        .await
        .unwrap();
    timeout(Duration::from_secs(15), async {
        loop {
            receiver.sync().await.unwrap();
            receiver
                .advance_post_join_maintenance_subscriptions()
                .await
                .unwrap();
            if receiver
                .runtime
                .post_join_history_fetch(&group)
                .unwrap()
                .is_some_and(|fetch| fetch.completion.is_some())
            {
                break;
            }
        }
    })
    .await
    .expect("bounded new-owner collection finishes without a comparison grant");
    let fetch = receiver
        .runtime
        .post_join_history_fetch(&group)
        .unwrap()
        .unwrap();
    assert_eq!(
        fetch.completion.as_ref().map(|value| value.outcome),
        Some(cgka_traits::PostJoinHistoryFetchOutcome::Fetched)
    );
    assert!(
        app.messages("receiver")
            .unwrap()
            .iter()
            .any(|message| message.plaintext == "history before the join"),
        "fetched means the encrypted input was admitted and persisted"
    );
    let before = receiver
        .runtime
        .maintenance_obligations_for_group(&group)
        .unwrap()
        .into_iter()
        .find(|job| job.trigger == cgka_traits::MaintenanceTrigger::PostJoin)
        .unwrap();
    assert_eq!(before.phase, cgka_traits::MaintenancePhase::Grace);
    assert!(before.eose_deadline_at.is_some());
    let account = receiver.adapter.account_id().clone();
    drop(receiver);
    app.relay_plane
        .deactivate_account_context(&account)
        .await
        .unwrap();
    let mut receiver = client_on_app_relay_plane(&app, "receiver").await;
    receiver.prepare_transport().await.unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    assert_eq!(
        receiver.runtime.post_join_history_fetch(&group).unwrap(),
        Some(fetch),
        "reopen retains this copy's completed fetch"
    );
    let after = receiver
        .runtime
        .maintenance_obligations_for_group(&group)
        .unwrap()
        .into_iter()
        .find(|job| job.trigger == cgka_traits::MaintenanceTrigger::PostJoin)
        .unwrap();
    assert_eq!(
        after.eose_deadline_at, before.eose_deadline_at,
        "reopen does not move the EOSE deadline"
    );
    assert_eq!(
        after.grace_until, before.grace_until,
        "reopen does not restart grace"
    );
    assert!(
        receiver.runner_post_join.is_empty(),
        "a fetched copy in grace does not re-arm history on reopen"
    );
}

/// Retained-window coverage is valid evidence, but is not the whole range
/// requested by an older Welcome. A raw boundary may start grace without
/// turning that partial range into a fetched-history claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runner_post_join_retained_coverage_cannot_complete_an_older_welcome() {
    use cgka_traits::Timestamp;
    use cgka_traits::storage::{GroupStorage, MaintenanceStorage};
    use storage_sqlite::{
        RecoveryCoverageProof, RecoveryCoverageSlice, TransportReconciliationRoute,
    };
    let fixture = crypto_fixture().await;
    let app = fixture.receiver.app.clone();
    let storage = app.account_storage("receiver").unwrap();
    let now = unix_now_seconds();
    let retained = now.saturating_sub(storage_sqlite::TRANSPORT_RECONCILIATION_RETENTION_SECS);
    let mut record = storage.get_group(&fixture.group).unwrap();
    record.local_copy_welcome_created_at = Some(Timestamp(retained.saturating_sub(600)));
    storage.put_group(&record).unwrap();
    drop(fixture.receiver);
    let mut receiver = client_on_app_relay_plane(&app, "receiver").await;
    receiver.prepare_transport().await.unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    receiver.sync().await.unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    let route = receiver
        .recovery_runner_routes()
        .into_iter()
        .find(|route| {
            route.group_id.as_deref() == Some(fixture.group.as_slice())
                && route.goal_until.is_none()
        })
        .unwrap();
    assert!(matches!(
        route.route,
        TransportReconciliationRoute::Group(_)
    ));
    // Input to the completion owner: a real ledger certificate for exactly
    // the retained range, with no certificate for the older requested prefix.
    storage
        .app_storage()
        .record_recovery_coverage(
            &[RecoveryCoverageSlice {
                route: &route.route,
                relay: &route.required[0],
                since_seconds: retained,
                until_seconds: unix_now_seconds(),
                proof: RecoveryCoverageProof::SweepSlice,
            }],
            unix_now_seconds(),
        )
        .unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    assert!(
        receiver
            .runtime
            .post_join_history_fetch(&fixture.group)
            .unwrap()
            .unwrap()
            .completion
            .is_none(),
        "a retained-only proof must not certify the older Welcome's whole history"
    );
    let mut maintenance = storage.group_maintenance(&fixture.group).unwrap().unwrap();
    maintenance.post_join_history.as_mut().unwrap().deadline_at =
        Some(Timestamp(unix_now_seconds().saturating_sub(1)));
    storage.put_group_maintenance(&maintenance).unwrap();
    receiver
        .advance_post_join_maintenance_subscriptions()
        .await
        .unwrap();
    assert_eq!(
        receiver
            .runtime
            .post_join_history_fetch(&fixture.group)
            .unwrap()
            .unwrap()
            .completion
            .map(|value| value.outcome),
        Some(cgka_traits::PostJoinHistoryFetchOutcome::DeadlineExpired),
        "a raw partial boundary does not disable the unanswered whole-range deadline"
    );
}
