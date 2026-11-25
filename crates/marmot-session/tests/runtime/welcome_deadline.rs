// An invite's Welcome has a delivery deadline, and nothing sends it once
// that passes (mdk#3589).

use cgka_engine::WELCOME_DELIVERY_WINDOW_SECS;
use cgka_traits::message::StoredMessagePayload;

/// The owed-invite fixture's account opened again on its database in `dir`,
/// as after a restart or an upgrade, with its runtime clock at `at`, its
/// relays answering through a fresh `adapter` and its v5 audit at `audit`.
fn reopened_owed_invite(
    dir: &std::path::Path,
    group_id: &GroupId,
    welcome: &TransportMessage,
    adapter: RecordingAdapter,
    at: u64,
    audit: &std::path::Path,
) -> WithdrawalRuntime {
    let TransportEnvelope::Welcome { recipient } = welcome.envelope.clone() else {
        unreachable!("the fixture's Welcome")
    };
    let key = SqlCipherKey::new("marmot welcome withdrawal key").unwrap();
    let policy =
        StaticTransportRouting::new(vec![TransportEndpoint("wss://alice-inbox.example".into())])
            .with_group_route(
                group_id.clone(),
                group_id.as_slice().to_vec(),
                vec![TransportEndpoint("wss://group.example".into())],
            )
            .with_inbox_route(
                recipient,
                vec![TransportEndpoint("wss://carol-inbox.example".into())],
            );
    let runtime = AccountDeviceRuntime::new(
        nostr_welcome_session(dir.join("alice.sqlite"), &key, b"alice-withdrawal"),
        adapter,
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        Arc::new(TestWallClock::new(at)),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    );
    runtime.audit_recorder().swap(v5_audit_recorder(audit));
    runtime
}

fn expired_rows(audit: &std::path::Path) -> Vec<serde_json::Value> {
    v5_audit_rows(audit)
        .into_iter()
        .filter(|row| row["event"]["type"] == "welcome_withdrawn")
        .collect()
}

/// Every path that publishes an owed Welcome, asked for `welcome`: the
/// startup pass, maintenance and an explicit redelivery.
async fn ask_every_publisher(runtime: &mut WithdrawalRuntime, welcome: &TransportMessage) {
    if let Some((_, task)) = runtime
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
    {
        runtime
            .finish_welcome_publish_task(task.run().await)
            .await
            .unwrap();
    }
    runtime.run_due_maintenance().await.unwrap();
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());
}

/// mdk#3589: an invite's Welcome that no inbox relay acknowledges is sent
/// until its delivery deadline, the window after it was staged, and never
/// after. It then settles as expired: audited once as `welcome_withdrawn`
/// (`expired`), out of the owed list, and read by the host as `Undeliverable`
/// with what its last attempt found, announced once. A restart publishes
/// nothing for it and changes none of that.
#[tokio::test]
async fn an_invite_welcome_no_relay_acknowledges_ends_at_its_deadline() {
    let dir = relaxed_storage_dir().unwrap();
    let staged_after = unix_now();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    let staged_before = unix_now();
    let TransportEnvelope::Welcome { recipient } = welcome.envelope.clone() else {
        unreachable!("the fixture's Welcome")
    };
    adapter.fail_endpoints_as(
        vec![TransportEndpoint("wss://carol-inbox.example".into())],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    // Retried, unanswered, until the deadline.
    wall.set(staged_before);
    runtime.run_due_maintenance().await.unwrap();
    let tried = welcome_publishes(&adapter).len();
    assert_eq!(tried, 2, "retried once its backoff passed");
    runtime.take_welcome_delivery_changes();

    wall.set(staged_before + WELCOME_DELIVERY_WINDOW_SECS);
    runtime.run_due_maintenance().await.unwrap();
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(
        welcome_publishes(&adapter).len(),
        tried,
        "nothing sends the Welcome past its deadline"
    );
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .expect("an invite's Welcome has a delivery deadline");
    assert!(
        (staged_after..=staged_before).contains(&(deadline.0 - WELCOME_DELIVERY_WINDOW_SECS)),
        "the window from its staging"
    );
    assert!(runtime.outstanding_welcome_deliveries().unwrap().is_empty());
    let index = runtime.welcome_delivery_index().unwrap();
    assert!(index.outstanding.is_empty());
    assert!(index.tracked_ids.contains(&welcome.id));
    assert_eq!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::Undeliverable {
            cause: WelcomeDeliveryProblem::RelaysUnreachable
        }
    );
    assert_eq!(
        runtime.take_welcome_delivery_changes(),
        vec![(group_id.clone(), recipient)]
    );
    assert!(
        runtime
            .session()
            .transport_fanout(&welcome.id)
            .unwrap()
            .is_none(),
        "maintenance drops the expired Welcome's retry record"
    );
    let audit = owed_invite_audit_path(dir.path());
    let rows = expired_rows(&audit);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["event"]["reason"], "expired");
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());
    assert_eq!(welcome_publishes(&adapter).len(), tried);
    drop(runtime);

    let adapter = RecordingAdapter::default();
    let restart_audit = dir.path().join("restart-audit-v5.jsonl");
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 + 60,
        &restart_audit,
    );
    ask_every_publisher(&mut restarted, &welcome).await;
    assert!(welcome_publishes(&adapter).is_empty());
    assert_eq!(
        delivery_of(&restarted, &welcome).state,
        WelcomeDeliveryState::Undeliverable {
            cause: WelcomeDeliveryProblem::RelaysUnreachable
        }
    );
    assert!(expired_rows(&restart_audit).is_empty(), "recorded once");
}

/// A relay that acknowledges the Welcome a second before its deadline
/// delivers it, and the deadline passing afterwards changes nothing.
#[tokio::test]
async fn an_acknowledgement_just_before_the_deadline_delivers_the_welcome() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .expect("an invite's Welcome has a delivery deadline");
    adapter.accept_only_endpoints(vec![TransportEndpoint("wss://carol-inbox.example".into())]);

    wall.set(deadline.0 - 1);
    runtime.run_due_maintenance().await.unwrap();
    wall.set(deadline.0 + 60);
    runtime.run_due_maintenance().await.unwrap();

    assert_eq!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::RelayAccepted
    );
    assert!(expired_rows(&owed_invite_audit_path(dir.path())).is_empty());
}

/// A Welcome owed before Welcomes kept a deadline (an upgrade: no deadline
/// stored and no delivery record) is held to the window from its transport
/// timestamp. On the first run after the upgrade past that, nothing sends
/// it and it leaves the owed list, and the host's invite list, which never
/// held it, stays without it.
#[tokio::test]
async fn a_welcome_owed_before_the_upgrade_ends_on_the_first_run_past_the_window() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    drop(runtime);
    // Put the Welcome back in the shape an older build stored.
    let database = owed_invite_database(dir.path());
    let stored: Vec<u8> = database
        .query_row(
            "SELECT payload FROM cgka_messages WHERE id = ?1",
            [welcome.id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let mut payload = StoredMessagePayload::decode(&stored).unwrap();
    let StoredMessagePayload::OutboundWelcome { deliver_until, .. } = &mut payload else {
        panic!("an owed Welcome")
    };
    *deliver_until = None;
    database
        .execute(
            "UPDATE cgka_messages SET payload = ?1 WHERE id = ?2",
            rusqlite::params![payload.encode().unwrap(), welcome.id.as_slice()],
        )
        .unwrap();
    database
        .execute(
            "DELETE FROM cgka_welcome_delivery_ledger WHERE welcome_id = ?1",
            [welcome.id.as_slice()],
        )
        .unwrap();
    drop(database);

    let adapter = RecordingAdapter::default();
    let mut upgraded = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        welcome.timestamp.0 + WELCOME_DELIVERY_WINDOW_SECS,
        &dir.path().join("upgraded-audit-v5.jsonl"),
    );
    assert_eq!(
        upgraded
            .session()
            .sent_welcome_deliver_until(&welcome.id)
            .unwrap(),
        Some(Timestamp(
            welcome.timestamp.0 + WELCOME_DELIVERY_WINDOW_SECS
        ))
    );
    ask_every_publisher(&mut upgraded, &welcome).await;

    assert!(welcome_publishes(&adapter).is_empty());
    assert!(upgraded.outstanding_welcome_deliveries().unwrap().is_empty());
    assert!(
        upgraded
            .welcome_delivery_outcomes(None, None)
            .unwrap()
            .is_empty()
    );
}

/// The startup pass asks a relay that already failed the Welcome again only
/// once its backoff has passed, as maintenance does; a Welcome no relay was
/// ever asked for is sent at once.
#[tokio::test]
async fn the_startup_pass_respects_a_relays_backoff() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    drop(runtime);
    let audit = dir.path().join("restart-audit-v5.jsonl");

    // The fixture's one attempt failed at 300_000; its backoff is 30 s.
    let adapter = RecordingAdapter::default();
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        300_010,
        &audit,
    );
    let (owed, task) = restarted
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the Welcome is owed");
    assert_eq!(owed, vec![welcome.id.clone()]);
    assert!(task.message_ids().is_empty(), "inside the relay's backoff");
    restarted
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    assert!(welcome_publishes(&adapter).is_empty());

    // With no attempt on record, the startup pass sends it at once.
    restarted
        .session()
        .delete_transport_fanout(&welcome.id)
        .unwrap();
    drop(restarted);
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        300_020,
        &audit,
    );
    let (_, task) = restarted
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the Welcome is owed");
    assert_eq!(task.message_ids(), std::slice::from_ref(&welcome.id));
    restarted
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    assert_eq!(welcome_publishes(&adapter), vec![welcome]);
}
