// An invite's Welcome has a delivery deadline, and nothing sends it once
// that passes (mdk#3589).

/// How long an invite's Welcome stays deliverable when its KeyPackage lasts
/// longer, stated here rather than read from the engine.
const SEVEN_DAYS: u64 = 7 * 24 * 60 * 60;
use cgka_traits::message::{StoredMessagePayload, WelcomeExpiry};

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
    let runtime = reopened_owed_invite_unaudited(dir, group_id, welcome, adapter, at);
    runtime.audit_recorder().swap(v5_audit_recorder(audit));
    runtime
}

/// [`reopened_owed_invite`] recording no v5 audit.
fn reopened_owed_invite_unaudited(
    dir: &std::path::Path,
    group_id: &GroupId,
    welcome: &TransportMessage,
    adapter: RecordingAdapter,
    at: u64,
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
    AccountDeviceRuntime::new(
        nostr_welcome_session(dir.join("alice.sqlite"), &key, b"alice-withdrawal"),
        adapter,
        policy,
        RecordingKeyPackages::default(),
    )
    .with_maintenance_sources(
        Arc::new(TestWallClock::new(at)),
        Arc::new(TestMonotonicClock::default()),
        Arc::new(TestRandom::new(0)),
    )
}

/// The owed-invite fixture with a second failed attempt at the real clock,
/// as the runtime keeps trying until the deadline, so the invite's last
/// activity is recent enough to stay listed after it.
async fn owed_invite_tried_now(dir: &std::path::Path) -> OwedInviteWelcome {
    let mut owed = owed_invite_welcome(dir).await;
    owed.adapter.fail_endpoints_as(
        vec![TransportEndpoint("wss://carol-inbox.example".into())],
        TransportEndpointFailureKind::RetryableUnavailable,
    );
    owed.wall.set(unix_now());
    owed.runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&owed.adapter).len(), 2, "retried now");
    owed
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
/// nothing for it and changes none of that, and announces nothing again,
/// with or without a v5 audit.
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

    wall.set(staged_before + SEVEN_DAYS);
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
        (staged_after..=staged_before).contains(&(deadline.0 - SEVEN_DAYS)),
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
    assert!(restarted.take_welcome_delivery_changes().is_empty());
    drop(restarted);

    let mut unaudited =
        reopened_owed_invite_unaudited(dir.path(), &group_id, &welcome, adapter.clone(), deadline.0 + 120);
    ask_every_publisher(&mut unaudited, &welcome).await;
    assert!(welcome_publishes(&adapter).is_empty());
    assert!(unaudited.take_welcome_delivery_changes().is_empty());
    drop(unaudited);

    // The expiry is durable: a clock set back before the deadline changes
    // none of it.
    let back_audit = dir.path().join("clock-back-audit-v5.jsonl");
    let mut set_back = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 - 3_600,
        &back_audit,
    );
    ask_every_publisher(&mut set_back, &welcome).await;
    assert!(welcome_publishes(&adapter).is_empty());
    assert!(set_back.outstanding_welcome_deliveries().unwrap().is_empty());
    assert_eq!(
        delivery_of(&set_back, &welcome).state,
        WelcomeDeliveryState::Undeliverable {
            cause: WelcomeDeliveryProblem::RelaysUnreachable
        }
    );
    assert!(expired_rows(&back_audit).is_empty());
    assert!(set_back.take_welcome_delivery_changes().is_empty());
}

/// The deadline passes while no runtime runs, as on a phone whose app is
/// closed (mdk#3589). The next start's startup pass marks the Welcome
/// expired with one `welcome_withdrawn` (`expired`) row and one delivery
/// notice, and the
/// host reads it `Undeliverable` with what its last attempt found. A start
/// after that, at a later clock or one set back before the deadline,
/// publishes nothing and records and announces nothing again.
#[tokio::test]
async fn a_deadline_that_passes_while_stopped_is_recorded_once_on_the_next_start() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_tried_now(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .unwrap();
    let ended = delivery_of(&runtime, &welcome).record.last_problem;
    drop(runtime);
    let TransportEnvelope::Welcome { recipient } = welcome.envelope.clone() else {
        unreachable!("the fixture's Welcome")
    };

    let adapter = RecordingAdapter::default();
    let audit = dir.path().join("next-start-audit-v5.jsonl");
    let mut next = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 + 60,
        &audit,
    );
    assert!(
        next.prepare_owed_welcome_retry_task_with_audit_context(Default::default())
            .unwrap()
            .is_none(),
        "nothing is owed"
    );
    // The startup pass itself marks and records it, so a clock set back
    // before the first maintenance pass cannot re-owe it.
    let rows = expired_rows(&audit);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["event"]["reason"], "expired");
    assert_eq!(
        next.session()
            .expire_sent_welcome(&welcome.id, Timestamp(0))
            .unwrap(),
        Some(WelcomeExpiry::Recorded)
    );
    next.run_due_maintenance().await.unwrap();
    next.run_due_maintenance().await.unwrap();
    assert_eq!(expired_rows(&audit).len(), 1);
    assert_eq!(
        next.take_welcome_delivery_changes(),
        vec![(group_id.clone(), recipient)]
    );
    let undeliverable = WelcomeDeliveryState::Undeliverable {
        cause: ended.expect("the fixture's attempt failed"),
    };
    assert_eq!(delivery_of(&next, &welcome).state, undeliverable);
    assert!(welcome_publishes(&adapter).is_empty());
    drop(next);

    for (at, name) in [(deadline.0 + 120, "later"), (deadline.0 - 3_600, "set back")] {
        let audit = dir.path().join(format!("{}-audit-v5.jsonl", name.replace(' ', "-")));
        let mut again =
            reopened_owed_invite(dir.path(), &group_id, &welcome, adapter.clone(), at, &audit);
        ask_every_publisher(&mut again, &welcome).await;
        assert!(welcome_publishes(&adapter).is_empty(), "{name}");
        assert_eq!(delivery_of(&again, &welcome).state, undeliverable, "{name}");
        assert!(expired_rows(&audit).is_empty(), "{name}");
        assert!(again.take_welcome_delivery_changes().is_empty(), "{name}");
    }
}

/// A stop after the expiry mark and before its record (the audit row, the
/// notice, the recorded flag) leaves the Welcome expired: never owed again,
/// whatever the clock. The next start records that expiry once, and a start
/// after that records nothing.
#[tokio::test]
async fn a_stop_between_the_expiry_mark_and_its_record_is_recorded_once_on_the_next_start() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_tried_now(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .unwrap();
    // All a stop right after the mark leaves.
    assert_eq!(
        runtime
            .session()
            .expire_sent_welcome(&welcome.id, deadline)
            .unwrap(),
        Some(WelcomeExpiry::Unrecorded)
    );
    drop(runtime);
    let TransportEnvelope::Welcome { recipient } = welcome.envelope.clone() else {
        unreachable!("the fixture's Welcome")
    };

    // The clock set back: the mark, not the clock, decides.
    let adapter = RecordingAdapter::default();
    let audit = dir.path().join("after-stop-audit-v5.jsonl");
    let mut next = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 - 3_600,
        &audit,
    );
    ask_every_publisher(&mut next, &welcome).await;
    assert!(welcome_publishes(&adapter).is_empty());
    let rows = expired_rows(&audit);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["event"]["reason"], "expired");
    assert_eq!(
        next.take_welcome_delivery_changes(),
        vec![(group_id.clone(), recipient)]
    );
    assert!(matches!(
        delivery_of(&next, &welcome).state,
        WelcomeDeliveryState::Undeliverable { .. }
    ));
    drop(next);

    let audit = dir.path().join("second-start-audit-v5.jsonl");
    let mut again = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 + 60,
        &audit,
    );
    ask_every_publisher(&mut again, &welcome).await;
    assert!(expired_rows(&audit).is_empty());
    assert!(again.take_welcome_delivery_changes().is_empty());
}

/// A relay acceptance received before the deadline whose delivered mark a
/// stop interrupted is reconciled before any expiry: the first start after
/// the deadline reads the Welcome `RelayAccepted` and records no expiry.
#[tokio::test]
async fn an_acceptance_saved_before_the_deadline_delivers_the_welcome_after_it() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_tried_now(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .unwrap();
    let mut fanout = runtime
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .expect("the failed attempt keeps a retry record");
    for target in &mut fanout.targets {
        target.state = cgka_traits::TransportFanoutAttemptState::Accepted;
    }
    runtime.session().put_transport_fanout(&fanout).unwrap();
    drop(runtime);

    let adapter = RecordingAdapter::default();
    let audit = dir.path().join("after-deadline-audit-v5.jsonl");
    let mut next = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        deadline.0 + 60,
        &audit,
    );
    assert!(
        next.prepare_owed_welcome_retry_task_with_audit_context(Default::default())
            .unwrap()
            .is_none(),
        "nothing is owed"
    );
    next.run_due_maintenance().await.unwrap();
    next.run_due_maintenance().await.unwrap();

    assert_eq!(
        delivery_of(&next, &welcome).state,
        WelcomeDeliveryState::RelayAccepted
    );
    assert!(expired_rows(&audit).is_empty());
    assert!(welcome_publishes(&adapter).is_empty());
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
/// it, it leaves the owed list and its expiry is recorded once, for good;
/// the host's invite list, which never held it, stays without it.
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
    let audit = dir.path().join("upgraded-audit-v5.jsonl");
    let mut upgraded = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        welcome.timestamp.0 + SEVEN_DAYS,
        &audit,
    );
    assert_eq!(
        upgraded
            .session()
            .sent_welcome_deliver_until(&welcome.id)
            .unwrap(),
        Some(Timestamp(
            welcome.timestamp.0 + SEVEN_DAYS
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
    let rows = expired_rows(&audit);
    assert_eq!(rows.len(), 1, "its expiry is recorded once: {rows:?}");
    assert_eq!(rows[0]["event"]["reason"], "expired");
    drop(upgraded);

    // Marked, so a clock set back inside the window sends it no more.
    let audit = dir.path().join("set-back-audit-v5.jsonl");
    let mut set_back = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        welcome.timestamp.0,
        &audit,
    );
    ask_every_publisher(&mut set_back, &welcome).await;
    assert!(welcome_publishes(&adapter).is_empty());
    assert!(set_back.outstanding_welcome_deliveries().unwrap().is_empty());
    assert!(expired_rows(&audit).is_empty());
}

/// The startup pass asks a relay that already failed the Welcome again only
/// once its backoff has passed, as maintenance does, while a relay of the
/// same retry record never asked is asked at once; a Welcome no relay was
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
    let finished = restarted
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    assert!(welcome_publishes(&adapter).is_empty());
    assert!(
        finished.welcome_failures.is_empty(),
        "no relay was asked, so nothing failed again"
    );

    // A retry record that also names a relay never asked: the startup pass
    // asks that one alone, still inside the other's backoff.
    let untried = TransportEndpoint("wss://carol-second-inbox.example".into());
    let mut fanout = restarted
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .expect("the retry record");
    let mut second = fanout.targets[0].clone();
    second.endpoint = untried.clone();
    second.state = cgka_traits::TransportFanoutAttemptState::Unattempted;
    second.attempt_count = 0;
    second.last_attempt_at = None;
    second.failure_code = None;
    fanout.targets.push(second);
    restarted.session().put_transport_fanout(&fanout).unwrap();
    drop(restarted);
    let mixed = RecordingAdapter::default();
    mixed.accept_only_endpoints(Vec::new());
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        mixed.clone(),
        300_015,
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
    let asked = mixed
        .publishes()
        .into_iter()
        .filter(|request| request.message.id == welcome.id)
        .flat_map(|request| request.target.endpoints().to_vec())
        .collect::<Vec<_>>();
    assert_eq!(asked, vec![untried], "only the relay never asked");

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

/// A host's redelivery that finds the deadline passed marks the Welcome
/// expired and records it, with no maintenance pass in between, so a clock
/// set back before the next pass does not let a second redelivery, or that
/// pass, publish it.
#[tokio::test]
async fn a_redelivery_past_the_deadline_marks_the_welcome_expired() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        welcome,
        ..
    } = owed_invite_tried_now(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .unwrap();
    let tried = welcome_publishes(&adapter).len();

    wall.set(deadline.0 + 1);
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());
    let audit = owed_invite_audit_path(dir.path());
    assert_eq!(expired_rows(&audit).len(), 1);

    wall.set(deadline.0 - 3_600);
    let redelivered = runtime.redeliver_welcome(&welcome.id).await.unwrap();
    assert!(redelivered.welcome_failures.is_empty());
    runtime.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter).len(), tried);
    assert!(matches!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::Undeliverable { .. }
    ));
    assert_eq!(expired_rows(&audit).len(), 1);
}

/// Put a `Failed` row the store cannot read (its deferred-peel record is not
/// a record) into `group_id`'s messages in the owed-invite fixture's
/// database, and return its id.
fn plant_unreadable_failed_row(dir: &std::path::Path, group_id: &GroupId) -> Vec<u8> {
    let id = vec![0xbd; 32];
    owed_invite_database(dir)
        .execute(
            "INSERT INTO cgka_messages
                 (id, group_id, epoch, state, storage_format, payload, deferred_peel, openmls_content)
             VALUES (?1, ?2, 0, 3, 2, x'00', x'ff', 0)",
            rusqlite::params![id, group_id.as_slice()],
        )
        .unwrap();
    id
}

/// One row the store cannot read stops the search for unrecorded expiries in
/// its own group only: another group's owed Welcome is still sent by the
/// startup pass, and maintenance runs on (mdk#3589).
#[tokio::test]
async fn an_unreadable_row_in_one_group_stops_no_other_groups_welcome() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    let (other, _) = runtime
        .create_group(CreateGroupRequest {
            name: "other".into(),
            description: String::new(),
            members: Vec::new(),
            required_features: Vec::new(),
            app_components: Vec::new(),
            initial_admins: Vec::new(),
        })
        .await
        .unwrap();
    assert_ne!(other, group_id);
    drop(runtime);
    plant_unreadable_failed_row(dir.path(), &other);

    let adapter = RecordingAdapter::default();
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        adapter.clone(),
        300_100,
        &dir.path().join("restart-audit-v5.jsonl"),
    );
    let (_, task) = restarted
        .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
        .unwrap()
        .expect("the healthy group's Welcome is owed");
    assert_eq!(task.message_ids(), std::slice::from_ref(&welcome.id));
    restarted
        .finish_welcome_publish_task(task.run().await)
        .await
        .unwrap();
    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(welcome_publishes(&adapter), vec![welcome]);
}

/// A group whose rows could not be read when the startup pass searched it is
/// searched again on each maintenance pass, so the expiry a stop left
/// unrecorded there is recorded, once, as soon as the group reads again.
#[tokio::test]
async fn an_unrecorded_expiry_in_a_group_that_reads_again_is_recorded_then() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime,
        group_id,
        welcome,
        ..
    } = owed_invite_tried_now(dir.path()).await;
    let deadline = runtime
        .session()
        .sent_welcome_deliver_until(&welcome.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .session()
            .expire_sent_welcome(&welcome.id, deadline)
            .unwrap(),
        Some(WelcomeExpiry::Unrecorded)
    );
    drop(runtime);
    let unreadable = plant_unreadable_failed_row(dir.path(), &group_id);

    let audit = dir.path().join("unreadable-audit-v5.jsonl");
    let mut restarted = reopened_owed_invite(
        dir.path(),
        &group_id,
        &welcome,
        RecordingAdapter::default(),
        deadline.0 + 60,
        &audit,
    );
    assert!(
        restarted
            .prepare_owed_welcome_retry_task_with_audit_context(Default::default())
            .unwrap()
            .is_none()
    );
    restarted.run_due_maintenance().await.unwrap();
    assert!(expired_rows(&audit).is_empty(), "its group cannot be read");

    owed_invite_database(dir.path())
        .execute("DELETE FROM cgka_messages WHERE id = ?1", [unreadable])
        .unwrap();
    restarted.run_due_maintenance().await.unwrap();
    restarted.run_due_maintenance().await.unwrap();
    assert_eq!(expired_rows(&audit).len(), 1);
}
