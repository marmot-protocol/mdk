use super::super::comparison_job::MAX_COMPARISON_ADMISSION_PER_TURN;
use super::*;

fn fault_connection(client: &AppClient) -> rusqlite::Connection {
    let app = &client.app;
    let label = &client.state.label;
    let path = app.account_storage_path(label);
    let keys = app.account_home().load_signing_keys(label).unwrap();
    let key = app
        .sqlcipher_key(label, &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
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
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        app.load_state("receiver")
            .unwrap()
            .last_transport_timestamp
            .is_some_and(|cursor| cursor >= event.event.created_at)
    );
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
async fn live_check_counts_ingest() {
    let mut fixture = crypto_fixture().await;
    let (events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    let app = fixture.receiver.app.clone();
    drop(fixture.receiver);
    fixture.receiver = client_on_app_relay_plane(&app, "receiver").await;
    fixture.receiver.set_audit_recording(true);
    // Start a real source generation without synchronizing its owner yet.
    // The first live ingest must checkpoint that generation after MLS commits.
    fixture.receiver.open_native_ingress().await.unwrap();
    fixture
        .receiver
        .runtime
        .activate_transport(None)
        .await
        .unwrap();
    let delivery = fixture
        .receiver
        .adapter
        .recovered_deliveries(events[0].clone())
        .await
        .unwrap()
        .pop()
        .unwrap();
    let routes_before = fixture.receiver.pending_runtime_group_subscription_refresh;
    let connection = fault_connection(&fixture.receiver);
    connection.execute_batch(
        "CREATE TRIGGER fail_live_check BEFORE UPDATE OF scope_payload ON account_recovery_scopes
         BEGIN SELECT RAISE(FAIL, 'injected live replay checkpoint failure'); END;",
    ).unwrap();

    let failure = fixture
        .receiver
        .ingest_received_delivery_with_partial(delivery.clone())
        .await
        .unwrap_err();
    assert!(
        failure
            .source
            .to_string()
            .contains("injected live replay checkpoint failure")
    );
    let messages = visible_messages(&fixture.receiver, &fixture.group);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        expected.get(&messages[0].message_id_hex),
        Some(&messages[0].plaintext)
    );
    assert_eq!(
        fixture.receiver.pending_runtime_group_subscription_refresh, routes_before,
        "a plaintext ingest does not dirty membership routes"
    );
    let drains = crate::client::audit_recovery::recorded_v5_rows(&app, "sync_drain");
    assert_eq!(drains.len(), 1);
    assert_eq!(
        drains[0]["event"]["deliveries"], 1,
        "the failed live cursor check must count the already-durable delivery"
    );

    connection
        .execute_batch("DROP TRIGGER fail_live_check")
        .unwrap();
    let retry = fixture
        .receiver
        .ingest_received_delivery_with_partial(delivery)
        .await
        .unwrap();
    assert!(retry.messages.is_empty());
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
}

async fn mixed_network(
    client: &mut AppClient,
    compared: Vec<NostrRelayEvent>,
) -> (
    AttemptGrant,
    super::super::comparison_job::ComparisonExecution,
    TransportReconciliationRoute,
    super::super::comparison_job::ComparisonNetworkResult,
) {
    client.request_bounded_comparison().unwrap();
    let mut permit = ExplicitRecoveryPermit::default();
    let grant = client
        .authorize_account_recovery(
            Some(&mut permit),
            EpochBackfillExecutionSeam::ExplicitCatchUp,
        )
        .await
        .unwrap()
        .unwrap();
    let route = grant
        .inventory
        .iter()
        .find_map(|item| match item.route {
            TransportReconciliationRoute::Group(_) => Some(item.route.clone()),
            TransportReconciliationRoute::Inbox => None,
        })
        .unwrap();
    script_subset(client, route.clone(), compared);
    let execution = client.begin_comparison_grant(&grant).await.unwrap();
    let credit = Arc::new(tokio::sync::Semaphore::new(1))
        .try_acquire_owned()
        .unwrap();
    let mut network = ComparisonNetworkJob::start(
        client,
        &grant,
        credit,
        tokio::time::Instant::now() + Duration::from_secs(30),
        None,
    )
    .unwrap();
    let (_credit, result) = timeout(Duration::from_secs(30), network.wait())
        .await
        .unwrap()
        .unwrap();
    (grant, execution, route, result)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_error_keeps_input() {
    let mut fixture = crypto_fixture().await;
    let (mut events, expected) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    events.truncate(2);
    events.sort_by_key(|event| (event.event.created_at, event.event.id.clone()));
    let (grant, execution, route, network) =
        mixed_network(&mut fixture.receiver, vec![events[1].clone()]).await;
    let storage = fixture
        .receiver
        .app
        .account_storage("receiver")
        .unwrap()
        .app_storage();
    let cursor = storage
        .transport_reconciliation_replay_cursor(&route)
        .unwrap();
    let connection = fault_connection(&fixture.receiver);
    fail_message(&connection, &fixture.group);
    lease_native(
        &mut fixture.receiver,
        &fixture.group,
        vec![events[0].clone()],
    )
    .await;
    assert!(
        fixture
            .receiver
            .admit_comparison_inline(None, grant, execution, network)
            .await
            .is_err()
    );
    assert_eq!(
        storage
            .transport_reconciliation_replay_cursor(&route)
            .unwrap(),
        cursor
    );
    assert!(
        fixture
            .receiver
            .recovery_owner
            .native_batch
            .as_ref()
            .unwrap()
            .delivery()
            .is_some()
    );
    assert!(fixture.receiver.next_event().await.is_err());
    assert!(visible_messages(&fixture.receiver, &fixture.group).is_empty());
    connection
        .execute_batch("DROP TRIGGER fail_native_message")
        .unwrap();
    let summary = fixture.receiver.next_event().await.unwrap();
    assert_eq!(summary.messages.len(), 1);
    assert_eq!(
        expected.get(&summary.messages[0].message_id_hex),
        Some(&summary.messages[0].plaintext)
    );
    fixture.receiver.admit_native_turn().await.unwrap();
    assert!(
        fixture
            .receiver
            .take_pending_applied_sync_summary()
            .messages
            .is_empty()
    );
    assert_eq!(visible_messages(&fixture.receiver, &fixture.group).len(), 1);
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
    events.truncate(4 * MAX_COMPARISON_ADMISSION_PER_TURN + 1);
    events.sort_by_key(|event| (event.event.created_at, event.event.id.clone()));
    let held = 3 * MAX_COMPARISON_ADMISSION_PER_TURN;
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
        MAX_COMPARISON_ADMISSION_PER_TURN
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
        held + MAX_COMPARISON_ADMISSION_PER_TURN + 1
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
    let healthy_count = 2 * MAX_COMPARISON_ADMISSION_PER_TURN + 1;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_receipts_yield() {
    let mut fixture = crypto_fixture().await;
    let (mut events, _) = encrypted_texts(&mut fixture.sender, &fixture.group).await;
    events.truncate(4 * MAX_COMPARISON_ADMISSION_PER_TURN + 1);
    events.sort_by_key(|event| (event.event.created_at, event.event.id.clone()));
    let held = 3 * MAX_COMPARISON_ADMISSION_PER_TURN;
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
    let (grant, mut execution, _, network) =
        mixed_network(&mut fixture.receiver, events[held..].to_vec()).await;
    lease_native(&mut fixture.receiver, &fixture.group, events).await;
    let mut admission = fixture
        .receiver
        .accept_comparison_network(&grant, &mut execution, network)
        .await
        .unwrap()
        .unwrap();
    for _ in 0..3 {
        assert!(
            !fixture
                .receiver
                .admit_comparison_turn(&grant, &mut execution, &mut admission)
                .await
                .unwrap()
        );
        assert!(admission.progressed);
        assert_eq!(
            visible_messages(&fixture.receiver, &fixture.group).len(),
            held,
            "a mixed turn yields after four native receipt skips instead of draining the prefix"
        );
    }
    let mut previous = held;
    let mut done = false;
    for _ in 0..8 {
        done = fixture
            .receiver
            .admit_comparison_turn(&grant, &mut execution, &mut admission)
            .await
            .unwrap();
        let count = visible_messages(&fixture.receiver, &fixture.group).len();
        assert!(
            count - previous <= MAX_COMPARISON_ADMISSION_PER_TURN,
            "native and comparison still share four actual ingests after the held prefix"
        );
        previous = count;
        if done {
            break;
        }
    }
    assert!(
        done,
        "native receipts must not inflate comparison remaining-attempt counts"
    );
    let outcome = fixture
        .receiver
        .finish_comparison_grant(grant, execution, Some(admission))
        .await
        .unwrap();
    let mut summary = match outcome {
        EpochBackfillRunOutcome::Completed(summary)
        | EpochBackfillRunOutcome::Incomplete(summary) => summary,
        _ => panic!("the comparison must settle its actual fetched events"),
    };
    while fixture.receiver.admit_native_turn().await.unwrap() {}
    summary.merge(fixture.receiver.take_pending_applied_sync_summary());
    assert_eq!(
        summary.messages.len(),
        MAX_COMPARISON_ADMISSION_PER_TURN + 1
    );
    assert_eq!(
        visible_messages(&fixture.receiver, &fixture.group).len(),
        held + MAX_COMPARISON_ADMISSION_PER_TURN + 1
    );
}
