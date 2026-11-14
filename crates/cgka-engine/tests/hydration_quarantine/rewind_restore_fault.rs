//! A committing rewind whose restore fails (mdk#3272).
//!
//! The pass, the deferred-peel sweep and their resumable slices rewind live
//! group state onto a retained anchor outside any transaction. When their
//! restore fails, the group is
//! quarantined for `RewindRestoreFailed` for the rest of the session, with its
//! input retained, and the next open restores the live image the window
//! snapshotted. Historical peel uses a contained transaction instead.
//!
//! A backend without atomic group savepoints commits a contained window as it
//! goes too, so the window must leave only what that open restores, and fail
//! as a committing window does (mdk#3278).

use super::*;
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::GroupHydrationQuarantineReason;
use cgka_traits::ingest::{IngestOutcome, LocalIngestState};
use cgka_traits::storage::{DeferredPeelGeneration, DeferredPeelGenerationStorage};
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicUsize;

/// Carol observes a group Alice and Bob administer.
struct Fork {
    alice: Engine<SqliteAccountStorage>,
    carol: Engine<SqliteAccountStorage>,
    storage: SqliteAccountStorage,
    group: GroupId,
    alice_commit: TransportMessage,
    alice_pending: cgka_traits::engine_state::PendingStateRef,
    bob_commit: TransportMessage,
}

const CAROL: &[u8] = b"carol-rewind-fault";

fn carol_builder(storage: SqliteAccountStorage) -> EngineBuilder<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(CAROL))
        .account_identity_proof_signer(proof_signer(CAROL))
}

fn build_carol(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    carol_builder(storage)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build carol")
}

/// Reads no group message with any context: only past-epoch peel can try
/// a row, so a sweep reaches its rewind.
#[derive(Default)]
struct UnreadablePeeler {
    epochs: Option<Arc<Mutex<Vec<EpochId>>>>,
}

#[async_trait]
impl TransportPeeler for UnreadablePeeler {
    async fn wrap_group_recovery(
        &self,
        message: &cgka_traits::GroupRecoveryMessage,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_group_recovery(message, recipient).await
    }

    async fn peel_group_message(
        &self,
        _msg: &cgka_traits::peeler::PreparedGroupMessage<'_>,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if let Some(epochs) = &self.epochs {
            epochs.lock().unwrap().push(ctx.epoch());
        }
        Err(PeelerError::DecryptFailed)
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_welcome(payload, recipient).await
    }
}

async fn invite(
    admin: &mut Engine<SqliteAccountStorage>,
    group: &GroupId,
    name: &[u8],
) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    let (mut invitee, _) = build_named_client(name);
    let kp = invitee
        .fresh_key_package()
        .await
        .expect("invitee key package");
    let (commit, pending) = evolution(
        admin
            .send(SendIntent::Invite {
                group_id: group.clone(),
                key_packages: vec![kp],
                initial_admins: vec![],
            })
            .await
            .expect("invite"),
    );
    (route(commit, group), pending)
}

/// Alice and Bob each invite someone from epoch 1; Carol holds neither yet.
async fn rival_invites() -> Fork {
    rival_invites_with_storage(SqliteAccountStorage::in_memory_for_test().expect("carol storage"))
        .await
}

async fn rival_invites_with_storage(storage: SqliteAccountStorage) -> Fork {
    let (mut alice, _) = build_named_client(b"alice-rewind-fault");
    let (mut bob, _) = build_named_client(b"bob-rewind-fault");
    let mut carol = build_carol(storage.clone());
    let bob_kp = bob.fresh_key_package().await.expect("bob key package");
    let carol_kp = carol.fresh_key_package().await.expect("carol key package");
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "rewind fault".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .expect("create group");
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("legacy fixture creates through a pending publish");
    };
    alice
        .confirm_published(pending)
        .await
        .expect("confirm create");
    bob.join_welcome(welcome_for(&welcomes, b"bob-rewind-fault"))
        .await
        .expect("bob joins");
    carol
        .join_welcome(welcome_for(&welcomes, CAROL))
        .await
        .expect("carol joins");
    let (alice_commit, alice_pending) = invite(&mut alice, &group, b"david-rewind-fault").await;
    let (bob_commit, _) = invite(&mut bob, &group, b"eve-rewind-fault").await;
    Fork {
        alice,
        carol,
        storage,
        group,
        alice_commit,
        alice_pending,
        bob_commit,
    }
}

/// Carol has applied Alice's invite (epoch 1 to 2) and holds Bob's rival
/// from epoch 1, so her next pass or sweep rewinds onto her epoch-1 anchor.
async fn carol_with_a_late_rival() -> Fork {
    let mut fork = rival_invites().await;
    fork.carol
        .buffer_openmls_convergence_message_at(&fork.group, fork.alice_commit.clone(), 1_000)
        .expect("buffer incumbent");
    fork.carol
        .converge_stored_openmls_messages_at(&fork.group, 1_000_000)
        .expect("settle incumbent");
    assert_eq!(
        fork.storage.get_group(&fork.group).unwrap().epoch,
        EpochId(2)
    );
    fork.carol
        .buffer_openmls_convergence_message_at(&fork.group, fork.bob_commit.clone(), 2_000)
        .expect("buffer late rival");
    fork
}

fn defer_unreadable_row(fork: &Fork) {
    let deferred = TransportMessage {
        id: MessageId::new(b"rewind-fault-deferred".to_vec()),
        payload: b"opaque post-fork traffic".to_vec(),
        timestamp: Timestamp(2_200),
        causal_deps: vec![],
        source: TransportSource("rewind-fault".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: fork.group.as_slice().to_vec(),
        },
    };
    fork.storage
        .put_message(&MessageRecord {
            id: deferred.id.clone(),
            group_id: fork.group.clone(),
            epoch: EpochId(2),
            state: MessageState::PeelDeferred,
            payload: cgka_traits::message::StoredMessagePayload::raw_transport(deferred)
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
    fork.storage
        .put_deferred_peel_generation(&DeferredPeelGeneration {
            group_id: fork.group.clone(),
            context_fingerprint: [0; 32],
        })
        .unwrap();
}

fn opaque_input(group: &GroupId, id: &[u8]) -> TransportMessage {
    TransportMessage {
        id: MessageId::new(id.to_vec()),
        payload: b"opaque historical traffic".to_vec(),
        timestamp: Timestamp(2_200),
        causal_deps: vec![],
        source: TransportSource("rewind-fault".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group.as_slice().to_vec(),
        },
    }
}

/// A rewind window and the entry point that opens it.
#[derive(Clone, Copy, Debug)]
enum Window {
    /// The convergence pass, whole.
    Pass,
    /// The convergence pass in resumable slices.
    PassSlice,
    /// The deferred-peel sweep's candidate-branch enumeration.
    Sweep,
    /// Past-epoch peel of a row the live context cannot read.
    PastPeel,
}

impl Window {
    /// The name prefix of this window's guard snapshot.
    fn prefix(self) -> &'static str {
        match self {
            Self::Pass | Self::PassSlice => "openmls-retained-probe-",
            Self::Sweep => "openmls-branch-probe-",
            Self::PastPeel => "peel-restore-",
        }
    }

    /// Carol with a late rival, reopened for this window. The open settles
    /// hydration's own writes, so the image taken next is the one a later
    /// open must reproduce.
    async fn fixture(self) -> Fork {
        let mut fork = carol_with_a_late_rival().await;
        if matches!(self, Self::Sweep | Self::PastPeel) {
            defer_unreadable_row(&fork);
        }
        let builder = carol_builder(fork.storage.clone());
        let builder = match self {
            Self::PastPeel => builder.peeler(Box::new(UnreadablePeeler::default())),
            _ => builder.peeler(Box::new(MockPeeler)),
        };
        // A reopen rebases the pass's monotonic cutoff onto the new engine's
        // clock, and slices take their deadline from it: hold that clock past
        // the cutoff so the pass comes due.
        let builder = builder.convergence_clock(Arc::new(
            cgka_engine::convergence_clock::ManualConvergenceClock::new(
                3_000_000,
                1_800_000_000_000,
            ),
        ));
        fork.carol = builder.build().expect("reopen carol");
        fork.carol.hydrate_all_stored_groups().expect("hydrate");
        fork
    }

    /// Run the entry point once. Its result is beside the point: the fault
    /// fails it.
    async fn open(self, fork: &mut Fork) {
        match self {
            Self::Pass => {
                let _ = fork
                    .carol
                    .converge_stored_openmls_messages_at(&fork.group, 3_000_000);
            }
            Self::PassSlice => {
                let _ = fork.carol.advance_convergence_inputs(&fork.group).await;
            }
            Self::Sweep | Self::PastPeel => {
                let _ = fork.carol.retry_deferred_peels(&fork.group).await;
            }
        }
    }
}

/// How the window exits before its failed restore.
#[derive(Clone, Copy, Debug)]
enum Exit {
    /// `commit` restores; the fault fails it and `Drop` retries.
    Commit,
    /// A panic inside the window unwinds through the guard, so only `Drop`
    /// restores. Injected at the first restore of a contained replay window
    /// nested inside it.
    Unwind,
}

/// Arm the fault: every restore of `window`'s guard snapshot fails, and under
/// [`Exit::Unwind`] the first nested contained restore panics.
fn arm(storage: &SqliteAccountStorage, window: Window, exit: Exit) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    let unwind = Arc::new(AtomicBool::new(matches!(exit, Exit::Unwind)));
    storage.fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
        if in_transaction
            && name.starts_with("openmls-probe-")
            && unwind.swap(false, Ordering::SeqCst)
        {
            panic!("injected panic inside a committing window");
        }
        if !in_transaction && name.starts_with(window.prefix()) {
            counted.fetch_add(1, Ordering::SeqCst);
            return Err(StorageError::Busy("injected restore fault".into()));
        }
        Ok(())
    })));
    hits
}

/// The durable state a reopen must reproduce.
#[derive(Debug, PartialEq)]
struct Image {
    group: Group,
    /// Group record, OpenMLS state, policy and every retained snapshot.
    state: Option<[u8; 32]>,
    ledger: Vec<(MessageId, EpochId, MessageState)>,
}

fn image(storage: &SqliteAccountStorage, group: &GroupId) -> Image {
    Image {
        group: storage.get_group(group).unwrap(),
        state: storage.group_replay_state_fingerprint(group).unwrap(),
        ledger: ledger(storage, group),
    }
}

fn guard_snapshots(storage: &SqliteAccountStorage, group: &GroupId) -> Vec<String> {
    storage
        .list_group_snapshots(group)
        .expect("list snapshots")
        .into_iter()
        .filter(|name| !name.starts_with("openmls-retained-anchor-"))
        .collect()
}

fn ledger(
    storage: &SqliteAccountStorage,
    group: &GroupId,
) -> Vec<(MessageId, EpochId, MessageState)> {
    let mut rows: Vec<_> = storage
        .list_messages(group, EpochId(0))
        .unwrap()
        .into_iter()
        .map(|record| (record.id, record.epoch, record.state))
        .collect();
    rows.sort_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()));
    rows
}

async fn alice_app_message(fork: &mut Fork) -> TransportMessage {
    fork.alice
        .confirm_published(fork.alice_pending)
        .await
        .expect("alice confirms her invite");
    let payload = MarmotAppEvent::new(
        hex::encode(fork.alice.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "after the fault",
    )
    .encode()
    .unwrap();
    match fork
        .alice
        .send(SendIntent::AppMessage {
            group_id: fork.group.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .expect("alice sends")
    {
        SendResult::ApplicationMessage { msg, .. } => route(msg, &fork.group),
        other => panic!("expected app message, got {other:?}"),
    }
}

fn unknown<T: std::fmt::Debug>(result: Result<T, EngineError>, surface: &str, group: &GroupId) {
    assert!(
        matches!(&result, Err(EngineError::UnknownGroup(id)) if id == group),
        "{surface} must refuse the group, got {result:?}"
    );
}

/// Fail `window`'s restore through `exit`, then run every live path the
/// session still has against the group. Returns the retained input.
async fn fail_then_use_the_session(window: Window, exit: Exit) -> (Fork, Image, MessageId) {
    let mut fork = window.fixture().await;
    let before = image(&fork.storage, &fork.group);
    let hits = arm(&fork.storage, window, exit);
    // The first sweep may only normalize its rows; the second enumerates.
    for _ in 0..2 {
        let opened = AssertUnwindSafe(window.open(&mut fork))
            .catch_unwind()
            .await;
        assert_eq!(
            opened.is_err(),
            matches!(exit, Exit::Unwind) && hits.load(Ordering::SeqCst) > 0
        );
        if hits.load(Ordering::SeqCst) > 0 {
            break;
        }
    }
    fork.storage.fail_snapshot_restores_for_test(None);
    let label = format!("{window:?}/{exit:?}");
    let expected_hits = match exit {
        Exit::Commit => 2,
        Exit::Unwind => 1,
    };
    assert_eq!(
        hits.load(Ordering::SeqCst),
        expected_hits,
        "{label}: restore attempts"
    );
    let kept = guard_snapshots(&fork.storage, &fork.group);
    assert!(
        kept.len() == 1 && kept[0].starts_with(window.prefix()),
        "{label}: the only copy of the live state is kept, got {kept:?}"
    );
    let anchor_state = image(&fork.storage, &fork.group);
    assert_ne!(
        anchor_state.state, before.state,
        "{label}: the fault left anchor state"
    );

    // The group is quarantined for the failed restore, announced once.
    let quarantined = vec![(
        fork.group.clone(),
        GroupHydrationQuarantineReason::RewindRestoreFailed,
    )];
    assert_eq!(fork.carol.quarantined_groups(), quarantined, "{label}");
    let announced = fork
        .carol
        .drain_events()
        .into_iter()
        .filter(|event| {
            matches!(
                event,
                GroupEvent::GroupHydrationQuarantined { group_id, reason }
                    if *group_id == fork.group
                        && *reason == GroupHydrationQuarantineReason::RewindRestoreFailed
            )
        })
        .count();
    assert_eq!(announced, 1, "{label}: quarantine events");

    // Reads, sends and the live listing treat the group as unknown, and a
    // retry leaves it quarantined.
    unknown(fork.carol.epoch(&fork.group), "epoch", &fork.group);
    unknown(
        fork.carol.group_context(&fork.group).map(drop),
        "group_context",
        &fork.group,
    );
    assert!(
        !fork
            .carol
            .retry_hydrate_quarantined_group(&fork.group)
            .expect("retry answers"),
        "{label}: a retry cannot clear it"
    );
    assert_eq!(fork.carol.quarantined_groups(), quarantined, "{label}");
    assert!(!fork.carol.live_group_ids().unwrap().contains(&fork.group));
    let payload = MarmotAppEvent::new(
        hex::encode(pad32(CAROL)),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "from carol",
    )
    .encode()
    .unwrap();
    unknown(
        fork.carol
            .send(SendIntent::AppMessage {
                group_id: fork.group.clone(),
                payload,
                expected_epoch: None,
            })
            .await,
        "send",
        &fork.group,
    );

    // Ingest retains its input for the next open.
    let app = alice_app_message(&mut fork).await;
    let retained = app.id.clone();
    let outcome = fork.carol.ingest(app).await.expect("ingest classifies");
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Quarantined
            }
        ),
        "{label}: ingest retains, got {outcome:?}"
    );
    // A host's scheduler still gets an answer for the group.
    assert!(
        fork.carol
            .has_pending_convergence_inputs(&fork.group)
            .is_ok(),
        "{label}: pending inputs answer"
    );

    // The pass, its slices and the sweep run nothing, and nothing commits.
    let _ = fork
        .carol
        .converge_stored_openmls_messages_at(&fork.group, 4_000_000);
    unknown(
        fork.carol.advance_convergence_inputs(&fork.group).await,
        "advance_convergence_inputs",
        &fork.group,
    );
    unknown(
        fork.carol
            .advance_convergence_inputs_until_settled(&fork.group, 4_000_000)
            .await,
        "advance_convergence_inputs_until_settled",
        &fork.group,
    );
    let _ = fork.carol.retry_deferred_peels(&fork.group).await;
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group, anchor_state.group, "{label}");
    assert_eq!(
        after.state, anchor_state.state,
        "{label}: nothing committed on the anchor"
    );
    let mut expected_ledger = anchor_state.ledger.clone();
    expected_ledger.push((retained.clone(), EpochId(0), MessageState::PeelDeferred));
    expected_ledger.sort_by(|a, b| a.0.as_slice().cmp(b.0.as_slice()));
    assert_eq!(
        after.ledger, expected_ledger,
        "{label}: only the input was added"
    );
    assert_eq!(
        guard_snapshots(&fork.storage, &fork.group),
        kept,
        "{label}: no second guard"
    );
    assert!(
        fork.carol
            .drain_events()
            .iter()
            .all(|event| !matches!(event, GroupEvent::GroupHydrationQuarantined { .. })),
        "{label}: announced once"
    );
    (fork, before, retained)
}

/// The next open restores the kept snapshot before it hydrates: the live
/// image is back, nothing was applied on the anchor, and the retained input
/// replays.
async fn reopen_restores_the_live_image(
    fork: &Fork,
    before: &Image,
    retained: &MessageId,
    label: &str,
) {
    let mut reopened = build_carol(fork.storage.clone());
    reopened.hydrate_all_stored_groups().expect("hydrate");
    assert!(reopened.quarantined_groups().is_empty(), "{label}");
    assert!(
        guard_snapshots(&fork.storage, &fork.group).is_empty(),
        "{label}"
    );
    assert_eq!(
        reopened.epoch(&fork.group).unwrap(),
        before.group.epoch,
        "{label}"
    );
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group, before.group, "{label}: group record");
    assert_eq!(
        after.state, before.state,
        "{label}: OpenMLS state and snapshots"
    );
    let (input, rest): (Vec<_>, Vec<_>) = after
        .ledger
        .into_iter()
        .partition(|(id, _, _)| id == retained);
    assert_eq!(
        input,
        vec![(retained.clone(), EpochId(0), MessageState::PeelDeferred)],
        "{label}: retained input"
    );
    // Every row the fault found is still owed: none was applied, failed or
    // invalidated against anchor state. A peel that failed with the restore
    // may leave its row `Retryable`.
    assert_eq!(rest.len(), before.ledger.len(), "{label}: ledger rows");
    for ((id, epoch, state), (was_id, was_epoch, was)) in rest.iter().zip(&before.ledger) {
        assert_eq!((id, epoch), (was_id, was_epoch), "{label}");
        assert!(
            state == was || *state == MessageState::Retryable,
            "{label}: {was:?} became {state:?} on anchor state"
        );
    }

    reopened
        .retry_deferred_peels(&fork.group)
        .await
        .expect("sweep after reopen");
    let replayed = fork.storage.get_message(retained).unwrap().state;
    assert_ne!(
        replayed,
        MessageState::PeelDeferred,
        "{label}: retained input replays"
    );
}

async fn fail_refuse_and_reopen(window: Window, exit: Exit) {
    let (fork, before, retained) = fail_then_use_the_session(window, exit).await;
    reopen_restores_the_live_image(&fork, &before, &retained, &format!("{window:?}/{exit:?}"))
        .await;
}

#[tokio::test]
async fn a_failed_pass_restore_quarantines_the_group_until_the_next_open() {
    for exit in [Exit::Commit, Exit::Unwind] {
        fail_refuse_and_reopen(Window::Pass, exit).await;
    }
}

#[tokio::test]
async fn a_failed_pass_slice_restore_quarantines_the_group_until_the_next_open() {
    for exit in [Exit::Commit, Exit::Unwind] {
        fail_refuse_and_reopen(Window::PassSlice, exit).await;
    }
}

#[tokio::test]
async fn a_failed_sweep_restore_quarantines_the_group_until_the_next_open() {
    for exit in [Exit::Commit, Exit::Unwind] {
        fail_refuse_and_reopen(Window::Sweep, exit).await;
    }
}

#[tokio::test]
async fn past_peel_failure_is_atomic() {
    let mut fork = Window::PastPeel.fixture().await;
    let before = image(&fork.storage, &fork.group);
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    fork.storage
        .fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
            if name.starts_with(Window::PastPeel.prefix()) {
                assert!(
                    in_transaction,
                    "historical context derivation must be contained"
                );
                counted.fetch_add(1, Ordering::SeqCst);
                return Err(StorageError::Busy(
                    "injected contained peel restore fault".into(),
                ));
            }
            Ok(())
        })));
    for _ in 0..2 {
        let result = fork.carol.retry_deferred_peels(&fork.group).await;
        if hits.load(Ordering::SeqCst) > 0 {
            assert!(
                matches!(&result, Err(EngineError::Storage(StorageError::Busy(detail)))
            if detail == "injected contained peel restore fault"),
                "surface the contained restore fault, got {result:?}"
            );
            break;
        }
    }
    fork.storage.fail_snapshot_restores_for_test(None);
    assert!(
        hits.load(Ordering::SeqCst) > 0,
        "the contained restore was reached"
    );
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group, before.group, "exact live group record");
    assert_eq!(
        after.state, before.state,
        "exact native state and retained snapshots"
    );
    assert!(guard_snapshots(&fork.storage, &fork.group).is_empty());
    assert!(fork.carol.quarantined_groups().is_empty());
    assert_eq!(fork.carol.epoch(&fork.group).unwrap(), EpochId(2));

    // A healed derive must run again, rather than reuse a context from the rolled-back window.
    let retries = Arc::new(AtomicUsize::new(0));
    let counted = retries.clone();
    fork.storage
        .fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
            if name.starts_with(Window::PastPeel.prefix()) {
                assert!(in_transaction);
                counted.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        })));
    fork.carol
        .ingest(opaque_input(&fork.group, b"healed-past-peel"))
        .await
        .expect("retry historical peel");
    fork.storage.fail_snapshot_restores_for_test(None);
    assert!(retries.load(Ordering::SeqCst) > 0);
    assert!(guard_snapshots(&fork.storage, &fork.group).is_empty());
    fork.carol = build_carol(fork.storage.clone());
    fork.carol
        .hydrate_all_stored_groups()
        .expect("reopen contained failure");
    let app = alice_app_message(&mut fork).await;
    assert!(matches!(
        fork.carol.ingest(app).await.unwrap(),
        IngestOutcome::Processed
    ));
}

#[tokio::test]
async fn past_peel_excludes_writers() {
    use std::sync::mpsc;
    use std::time::Duration;
    use storage_sqlite::{SqlCipherHardening, SqlCipherKey, open_hardened_sqlcipher};

    static BUSY_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn on_busy(_: i32) -> bool {
        BUSY_CALLS.fetch_add(1, Ordering::SeqCst);
        false
    }

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("atomic-historical-peel.sqlite");
    let key = SqlCipherKey::raw([0x49; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let mut fork = rival_invites_with_storage(storage).await;
    fork.carol
        .buffer_openmls_convergence_message_at(&fork.group, fork.alice_commit.clone(), 1_000)
        .unwrap();
    fork.carol
        .converge_stored_openmls_messages_at(&fork.group, 1_000_000)
        .unwrap();
    let epochs = Arc::new(Mutex::new(Vec::new()));
    fork.carol = carol_builder(fork.storage.clone())
        .peeler(Box::new(UnreadablePeeler {
            epochs: Some(epochs.clone()),
        }))
        .build()
        .unwrap();
    fork.carol.hydrate_all_stored_groups().unwrap();
    let before = image(&fork.storage, &fork.group);
    let writer = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
    let observer = rusqlite::Connection::open(&database).unwrap();
    open_hardened_sqlcipher(&observer, &key, SqlCipherHardening::live_cache()).unwrap();
    observer.busy_handler(Some(on_busy)).unwrap();
    let (attempt, start) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let completion = Mutex::new(completion);
    let group = fork.group.clone();
    let worker = std::thread::spawn(move || {
        start
            .recv_timeout(Duration::from_secs(30))
            .expect("derive reaches its restore");
        for sql in [
            "UPDATE openmls_values SET value = zeroblob(length(value))",
            "UPDATE cgka_group_snapshots SET snapshot = zeroblob(length(snapshot)) WHERE group_id = ?1",
        ] {
            let result = if sql.contains("?1") {
                observer.execute(sql, [group.as_slice()])
            } else {
                observer.execute(sql, [])
            };
            assert!(
                matches!(&result, Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy),
                "foreign writes must contend, got {result:?}"
            );
        }
        assert_eq!(
            BUSY_CALLS.load(Ordering::SeqCst),
            2,
            "both writes reached SQLite's busy handler"
        );
        completed.send(()).unwrap();
    });
    let armed = AtomicBool::new(true);
    let derives = Arc::new(AtomicUsize::new(0));
    let counted = derives.clone();
    fork.storage
        .fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
            if name.starts_with(Window::PastPeel.prefix()) {
                assert!(in_transaction, "rewind and restore share the write lock");
                counted.fetch_add(1, Ordering::SeqCst);
                if armed.swap(false, Ordering::SeqCst) {
                    attempt.send(()).unwrap();
                    completion
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(30))
                        .expect("foreign writes finish while the restore is paused");
                }
            }
            Ok(())
        })));

    fork.carol
        .ingest(opaque_input(&fork.group, b"atomic-cache-fill"))
        .await
        .unwrap();
    worker.join().unwrap();
    assert_eq!(*epochs.lock().unwrap(), vec![EpochId(2), EpochId(1)]);
    assert_eq!(derives.load(Ordering::SeqCst), 1);
    assert_eq!(image(&fork.storage, &fork.group).state, before.state);
    assert_eq!(fork.storage.get_group(&fork.group).unwrap(), before.group);
    epochs.lock().unwrap().clear();
    fork.carol
        .ingest(opaque_input(&fork.group, b"atomic-cache-hit"))
        .await
        .unwrap();
    assert_eq!(*epochs.lock().unwrap(), vec![EpochId(2), EpochId(1)]);
    assert_eq!(
        derives.load(Ordering::SeqCst),
        1,
        "the retained context is warm"
    );

    // Replacement from a second connection must invalidate the old epoch-1 context.
    writer
        .create_group_state_snapshot(&fork.group, "openmls-retained-anchor-1")
        .unwrap();
    epochs.lock().unwrap().clear();
    fork.carol
        .ingest(opaque_input(&fork.group, b"atomic-cache-replaced"))
        .await
        .unwrap();
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_eq!(*epochs.lock().unwrap(), vec![EpochId(2), EpochId(2)]);
    assert_eq!(derives.load(Ordering::SeqCst), 2);
    assert!(fork.carol.quarantined_groups().is_empty());
    assert!(guard_snapshots(&fork.storage, &fork.group).is_empty());
}

/// Fail the pass's restore and leave the fault disarmed.
async fn fail_the_pass() -> (Fork, Image) {
    let mut fork = Window::Pass.fixture().await;
    let before = image(&fork.storage, &fork.group);
    let hits = arm(&fork.storage, Window::Pass, Exit::Commit);
    Window::Pass.open(&mut fork).await;
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    (fork, before)
}

// The anchor's record is not live state. Here it reads removed while the
// kept live state does not (a copy removed at the anchor's epoch and added
// back since): ingest still retains the input as for any quarantined group,
// not in a removed copy's ring.
#[tokio::test]
async fn a_failed_restore_retains_input_whatever_the_anchor_record_reads() {
    let (mut fork, before) = fail_the_pass().await;
    let mut anchor = fork.storage.get_group(&fork.group).unwrap();
    anchor.removed = true;
    fork.storage.put_group(&anchor).unwrap();
    let app = alice_app_message(&mut fork).await;
    let retained = app.id.clone();
    let outcome = fork.carol.ingest(app).await.expect("ingest classifies");
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Quarantined
            }
        ),
        "ingest retains, got {outcome:?}"
    );
    reopen_restores_the_live_image(&fork, &before, &retained, "removed anchor").await;
}

/// Alice removes Carol and adds her back: the Welcome a re-join answers.
async fn readd_welcome(fork: &mut Fork) -> TransportMessage {
    let (_, removal) = evolution(
        fork.alice
            .send(SendIntent::RemoveMembers {
                group_id: fork.group.clone(),
                members: vec![MemberId::new(pad32(CAROL))],
            })
            .await
            .expect("alice removes carol"),
    );
    fork.alice
        .confirm_published(removal)
        .await
        .expect("alice confirms the removal");
    let kp = fork.carol.fresh_key_package().await.expect("key package");
    let readd = fork
        .alice
        .send(SendIntent::Invite {
            group_id: fork.group.clone(),
            key_packages: vec![kp],
            initial_admins: vec![],
        })
        .await
        .expect("alice adds carol back");
    let SendResult::GroupEvolution {
        pending, welcomes, ..
    } = readd
    else {
        panic!("expected a staged evolution, got {readd:?}");
    };
    fork.alice
        .confirm_published(pending)
        .await
        .expect("alice confirms the re-add");
    welcome_for(&welcomes, CAROL)
}

// A re-join would build on anchor state the next open replaces, so the
// Welcome is refused and stays joinable.
#[tokio::test]
async fn a_failed_restore_refuses_a_rejoin_until_the_next_open() {
    let (mut fork, _) = fail_the_pass().await;
    fork.alice
        .confirm_published(fork.alice_pending)
        .await
        .expect("alice confirms her invite");
    let welcome = readd_welcome(&mut fork).await;
    let anchor_state = image(&fork.storage, &fork.group);
    let joined = fork.carol.join_welcome(welcome).await;
    assert!(
        matches!(&joined, Err(EngineError::InvalidTransition(refused))
            if refused.from == "RewindRestoreFailed"),
        "a re-join is refused, got {joined:?}"
    );
    assert_eq!(image(&fork.storage, &fork.group), anchor_state);
    assert_eq!(
        fork.carol.quarantined_groups(),
        vec![(
            fork.group.clone(),
            GroupHydrationQuarantineReason::RewindRestoreFailed
        )]
    );
}

// An offer stored before the fault carries a consent token for the local
// branch, which after it is the anchor's. The offer is hidden and its confirm
// refused until the next open, which offers it again against live state.
#[tokio::test]
async fn a_failed_restore_hides_a_rejoin_offer_until_the_next_open() {
    let mut fork = Window::Pass.fixture().await;
    fork.alice
        .confirm_published(fork.alice_pending)
        .await
        .expect("alice confirms her invite");
    let welcome = readd_welcome(&mut fork).await;
    let held = fork.carol.join_welcome(welcome).await;
    assert!(
        matches!(&held, Err(EngineError::InvalidTransition(refused))
            if refused.from == "ActiveMember"),
        "a re-add over a live member copy is an offer, got {held:?}"
    );
    let offer = fork
        .carol
        .pending_group_rejoins_for(Some(&fork.group))
        .unwrap()
        .remove(0);
    let live_token = offer.rejoin.expect("a rejoin offer").local_state_token;

    let hits = arm(&fork.storage, Window::Pass, Exit::Commit);
    Window::Pass.open(&mut fork).await;
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        fork.carol.quarantined_groups(),
        vec![(
            fork.group.clone(),
            GroupHydrationQuarantineReason::RewindRestoreFailed
        )]
    );
    assert!(
        fork.carol
            .pending_group_rejoins_for(None)
            .unwrap()
            .is_empty(),
        "no offer carries an anchor token"
    );
    let anchor_state = image(&fork.storage, &fork.group);
    unknown(
        fork.carol
            .confirm_group_rejoin(&offer.message_id, &live_token)
            .await,
        "confirm_group_rejoin",
        &fork.group,
    );
    assert_eq!(image(&fork.storage, &fork.group), anchor_state);

    let mut reopened = build_carol(fork.storage.clone());
    reopened.hydrate_all_stored_groups().expect("hydrate");
    let offers = reopened
        .pending_group_rejoins_for(Some(&fork.group))
        .unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(
        offers[0].rejoin.as_ref().unwrap().local_state_token,
        live_token,
        "the next open offers the live branch again"
    );
}

// The pass restores its live state but cannot release the snapshot. That
// snapshot refuses every later committing window and the next open restores
// it, so the group is quarantined until then and nothing advances past it.
#[tokio::test]
async fn a_failed_release_after_a_restore_quarantines_the_group_until_the_next_open() {
    let mut fork = Window::Pass.fixture().await;
    let before = image(&fork.storage, &fork.group);
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = hits.clone();
    fork.storage
        .fail_snapshot_releases_for_test(Some(Arc::new(move |_, name, _| {
            if name.starts_with(Window::Pass.prefix()) {
                counted.fetch_add(1, Ordering::SeqCst);
                return Err(StorageError::Busy("injected release fault".into()));
            }
            Ok(())
        })));
    Window::Pass.open(&mut fork).await;
    fork.storage.fail_snapshot_releases_for_test(None);
    assert_eq!(hits.load(Ordering::SeqCst), 2, "commit and Drop releases");
    assert_eq!(guard_snapshots(&fork.storage, &fork.group).len(), 1);
    let live = image(&fork.storage, &fork.group);
    assert_eq!(live.group, before.group, "the restore succeeded");
    assert_eq!(
        fork.carol.quarantined_groups(),
        vec![(
            fork.group.clone(),
            GroupHydrationQuarantineReason::RewindRestoreFailed
        )]
    );
    let app = alice_app_message(&mut fork).await;
    let retained = app.id.clone();
    let outcome = fork.carol.ingest(app).await.expect("ingest classifies");
    assert!(
        matches!(
            outcome,
            IngestOutcome::LocalState {
                state: LocalIngestState::Quarantined
            }
        ),
        "ingest retains, got {outcome:?}"
    );
    reopen_restores_the_live_image(&fork, &before, &retained, "release").await;
}

/// How the last session left the group on its retained anchor.
#[derive(Clone, Copy, Debug)]
enum Stranded {
    /// The pass's restore failed, and the session kept the group quarantined.
    FailedRestore,
    /// The process died inside the pass, after its rewind.
    Crash,
}

/// Carol's group stored on her epoch-1 anchor with the pass's guard snapshot
/// holding her live state, and the anchor's record reading removed (a copy
/// removed at that epoch) while her live copy is a member. Returns the live
/// image the snapshot holds.
async fn stranded(how: Stranded) -> (Fork, Image) {
    let (fork, before) = match how {
        Stranded::FailedRestore => fail_the_pass().await,
        Stranded::Crash => {
            let fork = Window::Pass.fixture().await;
            let before = image(&fork.storage, &fork.group);
            // What a process killed inside the pass leaves on disk, as
            // `crash_recovery_sqlite`'s kill tests show: the guard's snapshot
            // of live state, and the group rewound onto the retained anchor.
            let anchor = fork
                .storage
                .list_group_snapshots(&fork.group)
                .unwrap()
                .into_iter()
                .find(|name| name == "openmls-retained-anchor-1")
                .expect("the epoch-1 anchor is retained");
            fork.storage
                .create_group_state_snapshot(
                    &fork.group,
                    &format!("{}crash", Window::Pass.prefix()),
                )
                .unwrap();
            fork.storage
                .rollback_group_state_keeping_live_records(&fork.group, &anchor)
                .unwrap();
            (fork, before)
        }
    };
    let carol = fork.carol.self_id();
    let mut anchor = fork.storage.get_group(&fork.group).unwrap();
    assert_eq!(anchor.epoch, EpochId(1), "{how:?}: stored on the anchor");
    anchor.removed = true;
    anchor.members.retain(|member| member.id != carol);
    fork.storage.put_group(&anchor).unwrap();
    assert_eq!(guard_snapshots(&fork.storage, &fork.group).len(), 1);
    (fork, before)
}

/// Reopen as the app does, seeding without hydrating, so entry points run
/// before any group's full hydration.
fn reopen_without_hydrating(fork: &Fork) -> Engine<SqliteAccountStorage> {
    let mut reopened = build_carol(fork.storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("seed stored groups");
    reopened
}

// The first input after a reopen must meet live state. Read from the anchor's
// record, it would be kept in a removed copy's ring and stamped at the
// anchor's epoch, rows the restore would never undo.
async fn ingest_before_hydration_reads_live_state(how: Stranded) {
    let (mut fork, before) = stranded(how).await;
    let app = alice_app_message(&mut fork).await;
    let mut reopened = reopen_without_hydrating(&fork);
    let outcome = reopened.ingest(app.clone()).await.expect("ingest");
    assert!(
        matches!(outcome, IngestOutcome::Processed),
        "{how:?}: ingest on live state, got {outcome:?}"
    );
    reopened.hydrate_all_stored_groups().expect("hydrate");
    assert!(reopened.quarantined_groups().is_empty(), "{how:?}");
    assert!(guard_snapshots(&fork.storage, &fork.group).is_empty());
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group.epoch, before.group.epoch, "{how:?}");
    assert!(!after.group.removed, "{how:?}");
    let added: Vec<_> = after
        .ledger
        .iter()
        .filter(|row| !before.ledger.iter().any(|was| was.0 == row.0))
        .map(|(_, epoch, state)| (*epoch, *state))
        .collect();
    assert_eq!(
        added,
        vec![(before.group.epoch, MessageState::Processed)],
        "{how:?}: the input's one row agrees with the live image"
    );
}

// A Welcome after a reopen must meet live state too. Read from the anchor's
// record, a copy this device was removed from, the re-join would commit on
// the anchor, release the guard snapshot and leave the live state lost.
// Against the live copy, still a member, it is an offer that changes nothing.
async fn a_welcome_before_hydration_reads_live_state(how: Stranded) {
    let (mut fork, before) = stranded(how).await;
    fork.alice
        .confirm_published(fork.alice_pending)
        .await
        .expect("alice confirms her invite");
    let welcome = readd_welcome(&mut fork).await;
    let mut reopened = reopen_without_hydrating(&fork);
    let joined = reopened.join_welcome(welcome).await;
    assert!(
        matches!(&joined, Err(EngineError::InvalidTransition(refused))
            if refused.from == "ActiveMember"),
        "{how:?}: the live copy is a member, got {joined:?}"
    );
    reopened.hydrate_all_stored_groups().expect("hydrate");
    assert!(reopened.quarantined_groups().is_empty(), "{how:?}");
    assert!(guard_snapshots(&fork.storage, &fork.group).is_empty());
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group, before.group, "{how:?}: group record");
    assert_eq!(after.state, before.state, "{how:?}: OpenMLS state");
}

#[tokio::test]
async fn ingest_before_hydration_after_a_failed_restore_reads_live_state() {
    ingest_before_hydration_reads_live_state(Stranded::FailedRestore).await;
}

#[tokio::test]
async fn ingest_before_hydration_after_a_crash_in_a_rewind_reads_live_state() {
    ingest_before_hydration_reads_live_state(Stranded::Crash).await;
}

#[tokio::test]
async fn a_welcome_before_hydration_after_a_failed_restore_reads_live_state() {
    a_welcome_before_hydration_reads_live_state(Stranded::FailedRestore).await;
}

#[tokio::test]
async fn a_welcome_before_hydration_after_a_crash_in_a_rewind_reads_live_state() {
    a_welcome_before_hydration_reads_live_state(Stranded::Crash).await;
}

/// Fail every restore outside a transaction whose name starts with `prefix`,
/// or every one inside a transaction.
fn fail_restores(storage: &SqliteAccountStorage, prefix: &'static str, in_tx: bool) {
    storage.fail_snapshot_restores_for_test(Some(Arc::new(move |_, name, in_transaction| {
        if in_transaction == in_tx && name.starts_with(prefix) {
            return Err(StorageError::Busy("injected restore fault".into()));
        }
        Ok(())
    })));
}

fn assert_live_and_unchanged(fork: &Fork, before: &Image, label: &str) {
    assert!(
        guard_snapshots(&fork.storage, &fork.group).is_empty(),
        "{label}"
    );
    assert_eq!(image(&fork.storage, &fork.group), *before, "{label}");
    assert_eq!(
        fork.carol.epoch(&fork.group).unwrap(),
        before.group.epoch,
        "{label}"
    );
}

// The rewind is a window's first step and commits nothing when it fails, so
// the guard releases its snapshot and the group stays live.
#[tokio::test]
async fn a_rewind_that_fails_leaves_the_group_live() {
    let mut fork = carol_with_a_late_rival().await;
    let before = image(&fork.storage, &fork.group);
    fail_restores(&fork.storage, "openmls-retained-anchor-", false);
    assert!(
        fork.carol
            .converge_stored_openmls_messages_at(&fork.group, 3_000_000)
            .is_err()
    );
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_live_and_unchanged(&fork, &before, "failed rewind");
    fork.carol
        .converge_stored_openmls_messages_at(&fork.group, 3_000_000)
        .expect("the next pass runs");
}

/// Carol holds both rival commits unsettled at epoch 1 and a row no live
/// context reads, so the sweep replays candidate paths from the live epoch,
/// each in a contained window with no outer guard.
async fn carol_with_unsettled_rivals(storage: SqliteAccountStorage) -> Fork {
    let mut fork = rival_invites_with_storage(storage).await;
    fork.carol
        .buffer_openmls_convergence_message_at(&fork.group, fork.alice_commit.clone(), 1_000)
        .expect("buffer alice");
    fork.carol
        .buffer_openmls_convergence_message_at(&fork.group, fork.bob_commit.clone(), 1_100)
        .expect("buffer bob");
    defer_unreadable_row(&fork);
    fork
}

// A contained window's restore runs inside its savepoint, so a failed restore
// undoes the whole window: alone on live state, or nested in a pass.
#[tokio::test]
async fn a_failed_contained_restore_leaves_live_state_unchanged() {
    // Alone.
    let mut fork =
        carol_with_unsettled_rivals(SqliteAccountStorage::in_memory_for_test().unwrap()).await;
    let before = image(&fork.storage, &fork.group);
    fail_restores(&fork.storage, "openmls-probe-", true);
    let _ = fork.carol.retry_deferred_peels(&fork.group).await;
    let _ = fork.carol.retry_deferred_peels(&fork.group).await;
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_eq!(
        image(&fork.storage, &fork.group).state,
        before.state,
        "alone"
    );
    assert!(
        guard_snapshots(&fork.storage, &fork.group).is_empty(),
        "alone"
    );
    assert_eq!(fork.carol.epoch(&fork.group).unwrap(), EpochId(1), "alone");

    // Nested in the pass's committing window.
    let mut fork = carol_with_a_late_rival().await;
    let before = image(&fork.storage, &fork.group);
    fail_restores(&fork.storage, "openmls-probe-", true);
    assert!(
        fork.carol
            .converge_stored_openmls_messages_at(&fork.group, 3_000_000)
            .is_err()
    );
    fork.storage.fail_snapshot_restores_for_test(None);
    assert_live_and_unchanged(&fork, &before, "nested");
}

/// Carol reopened on a backend without atomic group savepoints, where every
/// write commits as it is made, with the pass due as in [`Window::fixture`].
/// Not hydrated.
fn carol_without_savepoints(
    storage: SqliteAccountStorage,
) -> (Engine<FlakyGroupRecordStorage>, FlakyGroupRecordStorage) {
    let flaky = FlakyGroupRecordStorage::new(storage);
    let carol = EngineBuilder::new(flaky.clone())
        .legacy_compatibility_profile()
        .identity(pad32(CAROL))
        .account_identity_proof_signer(proof_signer(CAROL))
        .peeler(Box::new(MockPeeler))
        .convergence_clock(Arc::new(
            cgka_engine::convergence_clock::ManualConvergenceClock::new(
                3_000_000,
                1_800_000_000_000,
            ),
        ))
        .build()
        .expect("open carol without savepoints");
    (carol, flaky)
}

fn one_replay_snapshot(storage: &SqliteAccountStorage, group: &GroupId, label: &str) {
    let left = guard_snapshots(storage, group);
    assert!(
        matches!(left.as_slice(), [name] if name.starts_with("openmls-probe-")),
        "{label}: one guard snapshot, the replay's, holds the live state: {left:?}"
    );
}

// Without atomic group savepoints a contained window commits as it goes, so a
// process that dies inside one leaves the group on a candidate's state. It
// must leave one guard snapshot beside it, which the next open restores; a
// second would make that open refuse to guess and quarantine the group
// (mdk#3278).
#[tokio::test]
async fn a_crash_inside_a_contained_window_without_savepoints_is_restored_at_the_next_open() {
    use storage_sqlite::SqlCipherKey;

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("contained-without-savepoints.sqlite");
    let key = SqlCipherKey::raw([0x78; 32]);
    let fork =
        carol_with_unsettled_rivals(SqliteAccountStorage::open_encrypted(&database, &key).unwrap())
            .await;
    let group = fork.group.clone();
    let (mut carol, flaky) = carol_without_savepoints(fork.storage.clone());
    carol.hydrate_all_stored_groups().expect("hydrate");
    let before = image(&fork.storage, &group);

    flaky.crash_at_restore_of("openmls-probe-");
    let _ = carol.retry_deferred_peels(&group).await;
    assert!(
        flaky.crashed(),
        "the sweep reached a contained replay's restore"
    );
    drop((carol, fork));

    let storage =
        SqliteAccountStorage::open_encrypted(&database, &key).expect("open after the crash");
    one_replay_snapshot(&storage, &group, "after the crash");
    assert!(
        recovery_observation(&storage, &group).native_epoch > 1,
        "the process died inside the window, on a candidate's state"
    );
    let (mut reopened, _) = carol_without_savepoints(storage.clone());
    assert!(
        reopened.quarantined_groups().is_empty(),
        "the open restored the window's snapshot"
    );
    reopened
        .hydrate_all_stored_groups()
        .expect("hydrate after the crash");
    assert!(reopened.quarantined_groups().is_empty());
    assert!(guard_snapshots(&storage, &group).is_empty());
    let after = image(&storage, &group);
    assert_eq!(after.group, before.group, "live group record");
    assert_eq!(
        after.state, before.state,
        "live OpenMLS state and snapshots"
    );
    assert_eq!(reopened.epoch(&group).unwrap(), EpochId(1));
}

/// Carol on a backend without atomic group savepoints, hydrated, with both
/// rivals unsettled at her live epoch, so the sweep replays candidate paths
/// in contained windows with no outer guard. Returns her live image.
async fn alone_without_savepoints() -> (Fork, Engine<FlakyGroupRecordStorage>, Image) {
    let fork =
        carol_with_unsettled_rivals(SqliteAccountStorage::in_memory_for_test().unwrap()).await;
    let (mut carol, _) = carol_without_savepoints(fork.storage.clone());
    carol.hydrate_all_stored_groups().expect("hydrate");
    let before = image(&fork.storage, &fork.group);
    (fork, carol, before)
}

fn fail_releases(storage: &SqliteAccountStorage, prefix: &'static str) {
    storage.fail_snapshot_releases_for_test(Some(Arc::new(move |_, name, _| {
        if name.starts_with(prefix) {
            return Err(StorageError::Busy("injected release fault".into()));
        }
        Ok(())
    })));
}

/// The session refuses the group, as it does after a committing window's
/// failed restore.
fn refused_until_the_next_open(
    carol: &mut Engine<FlakyGroupRecordStorage>,
    group: &GroupId,
    label: &str,
) {
    assert_eq!(
        carol.quarantined_groups(),
        vec![(
            group.clone(),
            GroupHydrationQuarantineReason::RewindRestoreFailed
        )],
        "{label}"
    );
    unknown(carol.epoch(group), "epoch", group);
    unknown(carol.group_context(group).map(drop), "group_context", group);
}

/// The next open on the same storage restores `before` and leaves no guard
/// snapshot or quarantine behind.
fn reopen_restores_without_savepoints(fork: &Fork, before: &Image, label: &str) {
    let (mut reopened, _) = carol_without_savepoints(fork.storage.clone());
    assert!(reopened.quarantined_groups().is_empty(), "{label}");
    reopened.hydrate_all_stored_groups().expect("hydrate");
    assert!(
        guard_snapshots(&fork.storage, &fork.group).is_empty(),
        "{label}"
    );
    let after = image(&fork.storage, &fork.group);
    assert_eq!(after.group, before.group, "{label}");
    assert_eq!(after.state, before.state, "{label}");
}

// Without atomic group savepoints nothing undoes a contained window whose
// restore fails, and with no enclosing window its snapshot is the only copy of
// the live state. It fails as a committing window does: the snapshot stays,
// the session refuses the group and every window that would write over the
// snapshot, and the next open restores it (mdk#3278).
#[tokio::test]
async fn a_failed_contained_restore_without_savepoints_refuses_the_group_until_the_next_open() {
    let (fork, mut carol, before) = alone_without_savepoints().await;
    fail_restores(&fork.storage, "openmls-probe-", false);
    assert!(carol.retry_deferred_peels(&fork.group).await.is_err());
    fork.storage.fail_snapshot_restores_for_test(None);
    one_replay_snapshot(&fork.storage, &fork.group, "restore");
    refused_until_the_next_open(&mut carol, &fork.group, "restore");
    // The same sweep would write the same replay snapshot over the kept one,
    // from the candidate's state.
    let _ = carol.retry_deferred_peels(&fork.group).await;
    one_replay_snapshot(&fork.storage, &fork.group, "swept again");
    reopen_restores_without_savepoints(&fork, &before, "restore");
}

// A restored window whose snapshot cannot be released leaves a copy of the
// live state that the next open restores. The session refuses the group
// meanwhile, or the next open would undo whatever it did after the window.
#[tokio::test]
async fn a_failed_contained_release_without_savepoints_refuses_the_group_until_the_next_open() {
    let (fork, mut carol, before) = alone_without_savepoints().await;
    fail_releases(&fork.storage, "openmls-probe-");
    let _ = carol.retry_deferred_peels(&fork.group).await;
    fork.storage.fail_snapshot_releases_for_test(None);
    one_replay_snapshot(&fork.storage, &fork.group, "release");
    let live = image(&fork.storage, &fork.group);
    assert_eq!(live.group, before.group, "the restore succeeded");
    refused_until_the_next_open(&mut carol, &fork.group, "release");
    reopen_restores_without_savepoints(&fork, &before, "release");
}

// Nested in the pass's committing window, the pass's snapshot holds the live
// state: a replay whose restore fails releases its own, and the pass's restore
// brings the live state back with nothing left over. When the replay's
// snapshot cannot be released, the pass keeps its own beside it, because the
// next open would otherwise find the replay's alone and restore a candidate's
// state; with both, it restores the pass's (mdk#3278).
#[tokio::test]
async fn a_failed_nested_restore_without_savepoints_is_answered_by_the_enclosing_pass() {
    // The replay's snapshot goes.
    let fork = carol_with_a_late_rival().await;
    let (mut carol, _) = carol_without_savepoints(fork.storage.clone());
    carol.hydrate_all_stored_groups().expect("hydrate");
    let before = image(&fork.storage, &fork.group);
    fail_restores(&fork.storage, "openmls-probe-", false);
    assert!(
        carol
            .converge_stored_openmls_messages_at(&fork.group, 3_000_000)
            .is_err()
    );
    fork.storage.fail_snapshot_restores_for_test(None);
    assert!(
        guard_snapshots(&fork.storage, &fork.group).is_empty(),
        "released"
    );
    assert_eq!(image(&fork.storage, &fork.group), before, "released");
    assert!(carol.quarantined_groups().is_empty(), "released");
    assert_eq!(carol.epoch(&fork.group).unwrap(), EpochId(2), "released");

    // The replay's snapshot stays.
    let fork = carol_with_a_late_rival().await;
    let (mut carol, _) = carol_without_savepoints(fork.storage.clone());
    carol.hydrate_all_stored_groups().expect("hydrate");
    let before = image(&fork.storage, &fork.group);
    fail_restores(&fork.storage, "openmls-probe-", false);
    fail_releases(&fork.storage, "openmls-probe-");
    assert!(
        carol
            .converge_stored_openmls_messages_at(&fork.group, 3_000_000)
            .is_err()
    );
    fork.storage.fail_snapshot_restores_for_test(None);
    fork.storage.fail_snapshot_releases_for_test(None);
    let mut kept = guard_snapshots(&fork.storage, &fork.group);
    kept.sort();
    assert!(
        matches!(kept.as_slice(), [replay, pass]
            if replay.starts_with("openmls-probe-")
                && pass.starts_with("openmls-retained-probe-")),
        "the pass kept its snapshot beside the replay's: {kept:?}"
    );
    refused_until_the_next_open(&mut carol, &fork.group, "kept");
    reopen_restores_without_savepoints(&fork, &before, "kept");
}
