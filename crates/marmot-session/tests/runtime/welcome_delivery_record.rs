// The sender's view of each outbound Welcome's delivery (mdk#1706).

use cgka_traits::maintenance::{
    WelcomeCancelReason, WelcomeDeliveryProblem, WelcomeDeliveryState, WelcomeRelayCounts,
};

/// `welcome`'s delivery as the owed-invite fixture's runtime reads it now.
fn delivery_of(
    runtime: &WithdrawalRuntime,
    welcome: &TransportMessage,
) -> marmot_session::WelcomeDeliveryOutcome {
    runtime
        .welcome_delivery_outcomes(None, None)
        .unwrap()
        .into_iter()
        .flatten()
        .find(|outcome| outcome.record.welcome_id == welcome.id)
        .expect("the Welcome's delivery is listed")
}

/// An invite's Welcome is listed from its first attempt: whom it is for, the
/// commit that added them, and how its relays answered, by count. A retry a
/// relay stores reads as `RelayAccepted`, and each attempt queues its group
/// and recipient once for the host to read again.
#[tokio::test]
async fn a_welcome_delivery_follows_its_attempts_until_a_relay_stores_it() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        group_id,
        welcome,
    } = owed_invite_welcome(dir.path()).await;
    let TransportEnvelope::Welcome { recipient } = welcome.envelope.clone() else {
        unreachable!("the fixture's Welcome")
    };

    let delivery = delivery_of(&runtime, &welcome);
    assert_eq!(delivery.record.group_id, group_id);
    assert_eq!(delivery.record.recipient, recipient);
    assert!(delivery.record.origin_commit_id.is_some(), "an invite's commit");
    assert_eq!(delivery.record.attempts, 1);
    assert_eq!(
        delivery.state,
        WelcomeDeliveryState::Sending {
            last_problem: Some(WelcomeDeliveryProblem::RelaysUnreachable)
        }
    );
    assert_eq!(
        delivery.record.relays,
        WelcomeRelayCounts {
            total: 1,
            unreachable: 1,
            ..WelcomeRelayCounts::default()
        }
    );
    assert_eq!(
        runtime.take_welcome_delivery_changes(),
        vec![(group_id.clone(), recipient.clone())]
    );
    assert!(runtime.take_welcome_delivery_changes().is_empty());

    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);
    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    let delivery = delivery_of(&runtime, &welcome);
    assert_eq!(delivery.state, WelcomeDeliveryState::RelayAccepted);
    assert_eq!(delivery.record.attempts, 2);
    assert_eq!(delivery.record.accepted_at, Some(Timestamp(300_100)));
    assert_eq!(
        delivery.record.relays,
        WelcomeRelayCounts {
            total: 1,
            accepted: 1,
            ..WelcomeRelayCounts::default()
        }
    );
    assert_eq!(
        runtime.take_welcome_delivery_changes(),
        vec![(group_id, recipient)]
    );
}

/// A relay that refuses the Welcome reads as a refusal, not as a relay that
/// gave no answer, whether it refuses for good or for now.
#[tokio::test]
async fn a_relay_that_refuses_a_welcome_is_counted_as_refused() {
    for (kind, category) in [
        (
            TransportEndpointFailureKind::TerminalRejected,
            TransportEndpointRejectionCategory::Blocked,
        ),
        (
            TransportEndpointFailureKind::RetryableUnavailable,
            TransportEndpointRejectionCategory::RateLimited,
        ),
    ] {
        let dir = relaxed_storage_dir().unwrap();
        let adapter = RecordingAdapter::default();
        adapter.refuse_at_endpoints(
            vec![TransportEndpoint("wss://carol-inbox.example".into())],
            kind,
            category,
        );
        let OwedInviteWelcome {
            runtime, welcome, ..
        } = owed_invite_welcome_through(dir.path(), adapter).await;

        let delivery = delivery_of(&runtime, &welcome);
        assert_eq!(
            delivery.state,
            WelcomeDeliveryState::Sending {
                last_problem: Some(WelcomeDeliveryProblem::RefusedByRelays)
            },
            "{category:?}"
        );
        assert_eq!(
            delivery.record.relays,
            WelcomeRelayCounts {
                total: 1,
                refused: 1,
                ..WelcomeRelayCounts::default()
            },
            "{category:?}"
        );
    }
}

/// The state is read from the engine's Welcome row, never stored: a Welcome
/// withdrawn, or marked delivered behind the runtime's back, reads so at
/// once, with no update in between.
#[tokio::test]
async fn a_welcome_delivery_state_is_read_from_the_engines_row() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime, welcome, ..
    } = owed_invite_welcome(dir.path()).await;
    runtime
        .session()
        .mark_sent_welcome_delivered(&welcome.id)
        .unwrap();
    assert_eq!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::RelayAccepted
    );

    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        runtime, welcome, ..
    } = owed_invite_welcome(dir.path()).await;
    runtime.withdraw_welcome(&welcome.id).unwrap();
    assert_eq!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::Cancelled {
            reason: WelcomeCancelReason::Withdrawn
        }
    );
}

/// A raw connection to the owed-invite fixture's database in `dir`, for
/// putting it in a state no runtime call makes.
fn owed_invite_database(dir: &std::path::Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(dir.join("alice.sqlite")).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &SqlCipherKey::new("marmot welcome withdrawal key").unwrap(),
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// A relay acceptance saved before its delivered mark landed (the mark
/// failed, or the process stopped between them) reads as `Sending` with an
/// accepted relay counted, which is true: the engine may still send it. The
/// next maintenance pass marks it delivered from the saved acceptance, and
/// the change is queued for the host.
#[tokio::test]
async fn a_saved_acceptance_reads_as_sending_until_maintenance_marks_it_delivered() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        wall,
        group_id,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    let mut fanout = runtime
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .unwrap();
    for target in &mut fanout.targets {
        target.state = cgka_traits::maintenance::TransportFanoutAttemptState::Accepted;
    }
    let mut record = delivery_of(&runtime, &welcome).record;
    record.relays = WelcomeRelayCounts {
        total: 1,
        accepted: 1,
        ..WelcomeRelayCounts::default()
    };
    runtime.session().put_transport_fanout(&fanout).unwrap();
    runtime.session().put_welcome_delivery_record(&record).unwrap();
    let delivery = delivery_of(&runtime, &welcome);
    assert!(
        matches!(delivery.state, WelcomeDeliveryState::Sending { .. }),
        "{delivery:?}"
    );
    assert_eq!(delivery.record.relays.accepted, 1);
    runtime.take_welcome_delivery_changes();

    wall.set(300_100);
    runtime.run_due_maintenance().await.unwrap();

    assert_eq!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::RelayAccepted
    );
    assert_eq!(
        runtime.take_welcome_delivery_changes(),
        vec![(group_id, record.recipient)]
    );
}

/// A pass whose Welcome's delivery record cannot be read saves nothing: the
/// retry record never moves ahead of the counts it is saved with.
#[tokio::test]
async fn a_pass_whose_delivery_record_cannot_be_read_leaves_its_retry_record_alone() {
    let dir = relaxed_storage_dir().unwrap();
    let OwedInviteWelcome {
        mut runtime,
        adapter,
        wall,
        welcome,
        ..
    } = owed_invite_welcome(dir.path()).await;
    let before = runtime
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .unwrap();
    owed_invite_database(dir.path())
        .execute_batch("UPDATE cgka_welcome_delivery_ledger SET record = x'00';")
        .unwrap();
    adapter.accept_only_endpoints(vec![
        TransportEndpoint("wss://group.example".into()),
        TransportEndpoint("wss://carol-inbox.example".into()),
    ]);

    wall.set(300_100);
    let _ = runtime.run_due_maintenance().await;

    assert_eq!(
        runtime.session().transport_fanout(&welcome.id).unwrap(),
        Some(before),
        "the retry record is not saved without its counts"
    );
}

/// A device link's Welcome past its deadline reads as undeliverable only
/// once nothing can still close it: while its relays' saved acceptance
/// awaits its delivered mark it still reads as being sent.
#[tokio::test]
async fn a_welcome_past_its_deadline_is_undeliverable_only_once_nothing_can_close_it() {
    let dir = relaxed_storage_dir().unwrap();
    let LinkWelcome {
        mut runtime,
        wall,
        welcome,
        ..
    } = link_welcome(dir.path(), false).await;
    // The fixture's session made the Welcome before the runtime ran, so the
    // runtime keeps no record of it; give it one as a runtime-made invite has.
    let facts = runtime
        .session()
        .outbound_welcome_audit_facts(&welcome.id)
        .unwrap()
        .unwrap();
    runtime
        .session()
        .put_welcome_delivery_record(&cgka_traits::maintenance::WelcomeDeliveryRecord {
            welcome_id: welcome.id.clone(),
            group_id: facts.group_id,
            recipient: facts.recipient,
            origin_commit_id: facts.origin_commit_id,
            created_at: Timestamp(300_000),
            attempts: 0,
            last_attempt_at: None,
            accepted_at: None,
            relays: WelcomeRelayCounts::default(),
            last_problem: None,
        })
        .unwrap();
    // The first pass fails, leaving a retry record.
    runtime.run_due_maintenance().await.unwrap();
    wall.set(300_200);
    assert!(matches!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::Undeliverable { .. }
    ));

    let mut fanout = runtime
        .session()
        .transport_fanout(&welcome.id)
        .unwrap()
        .expect("the failed pass keeps a retry record");
    for target in &mut fanout.targets {
        target.state = cgka_traits::TransportFanoutAttemptState::Accepted;
    }
    runtime.session().put_transport_fanout(&fanout).unwrap();
    assert!(matches!(
        delivery_of(&runtime, &welcome).state,
        WelcomeDeliveryState::Sending { .. }
    ));
}

/// The delivery of `welcome`, as the runtime reads it now.
fn delivery_of_id(
    runtime: &WithdrawalRuntime,
    welcome: &MessageId,
) -> marmot_session::WelcomeDeliveryOutcome {
    runtime
        .welcome_delivery_outcomes(None, None)
        .unwrap()
        .into_iter()
        .flatten()
        .find(|outcome| &outcome.record.welcome_id == welcome)
        .expect("the Welcome's delivery is listed")
}

/// Carol's Welcome after its wave returned at the fast relay's acceptance and
/// was finished, with the slow relay's request held by `gate` as the
/// `remaining` pass.
struct SlowRelay {
    runtime: WithdrawalRuntime,
    wall: Arc<TestWallClock>,
    audit: std::path::PathBuf,
    welcome: MessageId,
    gate: Arc<tokio::sync::Semaphore>,
    remaining: marmot_session::PreparedWelcomePublishTask,
}

/// [`SlowRelay`] for `invite`, whose first pass's record is saved.
async fn slow_relay_still_answering(invite: TwoInboxInvite) -> SlowRelay {
    let TwoInboxInvite {
        mut runtime,
        adapter,
        wall,
        audit,
    } = invite;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *adapter.inner.endpoint_gate.lock().unwrap() =
        Some((TransportEndpoint(SLOW_INBOX.into()), gate.clone()));
    let task = the_wave(&mut runtime);
    let welcome = task.message_ids()[0].clone();
    let mut completed = tokio::time::timeout(Duration::from_secs(5), task.run())
        .await
        .expect("the wave returns at the fast relay's acceptance");
    let remaining = completed.take_remaining().unwrap();
    runtime.finish_welcome_publish_task(completed).await.unwrap();
    SlowRelay {
        runtime,
        wall,
        audit,
        welcome,
        gate,
        remaining,
    }
}

/// A raw connection to the detached fixture's database in `dir`.
fn detached_database(dir: &std::path::Path) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(dir.join("alice.sqlite")).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &SqlCipherKey::new(DETACHED_KEY).unwrap(),
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

/// A slow relay's late acceptance is counted on the invite's delivery in the
/// same write as on its retry record, beside what the first pass's relays
/// answered: one that refused stays refused. It ends the first attempt, so
/// the attempt count and time stay the first pass's, and the change is
/// queued for the host.
#[tokio::test]
async fn a_slow_relays_late_acceptance_is_counted_on_the_invites_delivery() {
    const REFUSING_INBOX: &str = "wss://carol-refusing.example";
    let dir = relaxed_storage_dir().unwrap();
    let invite = inbox_invite(dir.path(), &[FAST_INBOX, REFUSING_INBOX, SLOW_INBOX]).await;
    invite.adapter.refuse_at_endpoints(
        vec![TransportEndpoint(REFUSING_INBOX.into())],
        TransportEndpointFailureKind::TerminalRejected,
        TransportEndpointRejectionCategory::Blocked,
    );
    let SlowRelay {
        mut runtime,
        wall,
        welcome,
        gate,
        remaining,
        ..
    } = slow_relay_still_answering(invite).await;
    let first = delivery_of_id(&runtime, &welcome);
    assert_eq!(first.state, WelcomeDeliveryState::RelayAccepted);
    assert_eq!(first.record.attempts, 1);
    assert_eq!(
        first.record.relays,
        WelcomeRelayCounts {
            total: 3,
            accepted: 1,
            refused: 1,
            unreachable: 1,
            ..WelcomeRelayCounts::default()
        },
        "the slow relay has not answered yet"
    );
    runtime.take_welcome_delivery_changes();

    wall.set(300_050);
    gate.add_permits(1);
    runtime
        .finish_welcome_publish_task(remaining.run().await)
        .await
        .unwrap();

    let late = delivery_of_id(&runtime, &welcome);
    assert_eq!(
        late.record.relays,
        WelcomeRelayCounts {
            total: 3,
            accepted: 2,
            refused: 1,
            ..WelcomeRelayCounts::default()
        }
    );
    assert_eq!(late.record.attempts, 1, "no new attempt");
    assert_eq!(late.record.last_attempt_at, first.record.last_attempt_at);
    assert_eq!(
        runtime.take_welcome_delivery_changes(),
        vec![(late.record.group_id, late.record.recipient)]
    );
}

/// A remaining pass whose delivery record cannot be read writes neither
/// record: the retry record and the delivery record stay as the first pass
/// left them, and no change is queued. Its finished row still reports the
/// late acceptance.
#[tokio::test]
async fn a_remaining_pass_whose_delivery_record_cannot_be_read_writes_neither_record() {
    let dir = relaxed_storage_dir().unwrap();
    let SlowRelay {
        mut runtime,
        audit,
        welcome,
        gate,
        remaining,
        ..
    } = slow_relay_still_answering(two_inbox_invite(dir.path()).await).await;
    let before = runtime
        .session()
        .transport_fanout(&welcome)
        .unwrap()
        .unwrap();
    let database = detached_database(dir.path());
    database
        .execute_batch("UPDATE cgka_welcome_delivery_ledger SET record = x'00';")
        .unwrap();
    runtime.take_welcome_delivery_changes();

    gate.add_permits(1);
    let _ = runtime
        .finish_welcome_publish_task(remaining.run().await)
        .await;

    assert_eq!(
        runtime.session().transport_fanout(&welcome).unwrap(),
        Some(before),
        "the retry record is not saved without its counts"
    );
    let stored: Vec<u8> = database
        .query_row("SELECT record FROM cgka_welcome_delivery_ledger", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(stored, vec![0], "the delivery record is not written");
    assert!(runtime.take_welcome_delivery_changes().is_empty());
    let rows = publish_rows(&audit, &welcome);
    let finished = &rows.last().unwrap()["event"];
    assert_eq!(finished["type"], "welcome_publish_finished", "{finished}");
    assert_eq!(finished["accepted_this_attempt_count"], 1, "{finished}");
    assert_eq!(finished["results"][0]["status"], "acknowledged", "{finished}");
    assert!(
        finished["accepted_total_count"].is_null(),
        "no stored total: {finished}"
    );
}

/// A remaining pass cut short writes nothing: the delivery stays as its
/// first pass left it.
#[tokio::test]
async fn a_remaining_pass_cut_short_leaves_the_delivery_as_its_first_pass_did() {
    let dir = relaxed_storage_dir().unwrap();
    let SlowRelay {
        mut runtime,
        welcome,
        remaining,
        ..
    } = slow_relay_still_answering(two_inbox_invite(dir.path()).await).await;
    let first = delivery_of_id(&runtime, &welcome);
    runtime.take_welcome_delivery_changes();

    runtime.abandon_welcome_publish_task(remaining.message_ids());
    drop(remaining);

    assert_eq!(delivery_of_id(&runtime, &welcome), first);
    assert!(runtime.take_welcome_delivery_changes().is_empty());
}

/// A Welcome with no delivery record, as one sent before the upgrade, gets
/// none from a late acceptance, which still lands on its retry record.
#[tokio::test]
async fn a_late_acceptance_of_a_welcome_with_no_delivery_record_makes_none() {
    let dir = relaxed_storage_dir().unwrap();
    let SlowRelay {
        mut runtime,
        welcome,
        gate,
        remaining,
        ..
    } = slow_relay_still_answering(two_inbox_invite(dir.path()).await).await;
    detached_database(dir.path())
        .execute_batch("DELETE FROM cgka_welcome_delivery_ledger;")
        .unwrap();
    runtime.take_welcome_delivery_changes();

    gate.add_permits(1);
    runtime
        .finish_welcome_publish_task(remaining.run().await)
        .await
        .unwrap();

    assert_eq!(
        inbox_target(&runtime, &welcome, SLOW_INBOX),
        (cgka_traits::TransportFanoutAttemptState::Accepted, 1)
    );
    assert_eq!(
        runtime.session().welcome_delivery_record(&welcome).unwrap(),
        None
    );
    assert!(runtime.take_welcome_delivery_changes().is_empty());
}
