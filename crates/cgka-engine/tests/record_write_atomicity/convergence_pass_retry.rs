//! A frozen convergence batch whose attempt fails after its decision (mdk#2684).
//!
//! Carol catches up on Alice's invite through a stored convergence pass whose
//! apply keeps failing on an injected record write. Each failure is charged to
//! the pass: the next attempt waits out a doubling delay, and the pass parks
//! once its budget is spent. New selection input or an explicit retry wakes
//! it, and the count, delay and park all survive a restart.

use super::*;
use cgka_engine::canonicalization::{CanonicalizationResult, ConvergenceStatus};
use cgka_engine::distributed_convergence::{
    CONVERGENCE_PASS_PARK_AFTER_FAILURES, CONVERGENCE_PASS_RETRY_BASE_MS,
    CONVERGENCE_PASS_RETRY_MAX_MS,
};
use cgka_engine::{ConvergenceClock, ManualConvergenceClock};
use cgka_traits::{ConvergencePassPhase, ConvergencePassRetry, ConvergencePassStep};
use marmot_forensics::{AuditEvent, AuditEventKind, ConvergencePhase, JsonlRecorder};
use std::path::{Path, PathBuf};

/// Far more `put_group` failures than any test consumes.
const ALWAYS: usize = 1_000;

/// Past the pinned pass cutoff (quiescence 1 s, absolute 5 s).
const PAST_CUTOFF_MS: u64 = 10_000;

impl PutGroupFault {
    fn remaining(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

fn retry_storage(
    inner: SqliteAccountStorage,
    fault: PutGroupFault,
    preparation_delay: PreparationDelay,
) -> FaultStorage {
    FaultStorage {
        inner,
        fault,
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: LeaveWriteFault::default(),
        failed_state_fault: FailedStateWriteFault::default(),
        release_fault: LeaveWriteFault::default(),
        preparation_delay,
        retained_anchor_rewinds: RetainedAnchorRewindCounter::default(),
        apply_snapshots: ApplySnapshotCounter::default(),
        termination_fault: LeaveWriteFault::default(),
        post_commit_disband_read_fault: LeaveWriteFault::default(),
    }
}

fn build_carol(
    label: &str,
    inner: SqliteAccountStorage,
    fault: PutGroupFault,
    preparation: PreparationDelay,
    clock: ManualConvergenceClock,
    audit_path: &Path,
) -> cgka_engine::Engine<FaultStorage> {
    let id = format!("carol-{label}");
    EngineBuilder::new(retry_storage(inner, fault, preparation))
        .legacy_compatibility_profile()
        .identity(pad32(id.as_bytes()))
        .account_identity_proof_signer(proof_signer(id.as_bytes()))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .convergence_clock(Arc::new(clock))
        .recorder(Box::new(
            JsonlRecorder::open(audit_path, id.clone()).expect("open audit log"),
        ))
        .build()
        .expect("build carol")
}

/// `msg`'s unpeeled bytes stored under its content id at epoch 1, as the
/// direct path, where a wrapper and its content share one id, leaves them.
fn deferred_row_under_content_id(msg: &TransportMessage, group_id: &GroupId) -> MessageRecord {
    use cgka_traits::message::{DeferredPeelLifecycle, StoredMessagePayload};
    use sha2::{Digest, Sha256};
    MessageRecord {
        id: MessageId::new(Sha256::digest(&msg.payload).to_vec()),
        group_id: group_id.clone(),
        epoch: EpochId(1),
        state: MessageState::PeelDeferred,
        payload: StoredMessagePayload::raw_transport(msg.clone())
            .encode()
            .unwrap(),
        // Held well past the test, so no residence sweep retires it.
        deferred_peel: Some(DeferredPeelLifecycle {
            first_observed_wall_ms: 1_700_000_000_000,
            wall_high_water_ms: 1_700_000_000_000,
            clock_instance_id: 0,
            residence_deadline_monotonic_ms: u64::MAX,
            residence_deadline_wall_ms: u64::MAX,
            distinct_context_attempts: 0,
            last_context_fingerprint: None,
            live_context_attempts: 0,
            last_live_context_fingerprint: None,
        }),
    }
}

/// The deferred row's content as the direct path rewrites it in place once
/// the bytes peel: the same id, now a stored proposal awaiting processing.
fn peeled_in_place(deferred: &MessageRecord, msg: &TransportMessage) -> MessageRecord {
    use cgka_traits::message::StoredMessagePayload;
    MessageRecord {
        state: MessageState::Created,
        payload: StoredMessagePayload::openmls_wire(msg.clone())
            .encode()
            .unwrap(),
        deferred_peel: None,
        ..deferred.clone()
    }
}

fn routed(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

/// When Carol hears that Frank, a third member at epoch 1, is leaving.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FrankLeaves {
    /// Before her batch opens, so the batch holds his SelfRemove proposal and
    /// she schedules its auto-commit.
    BeforeTheBatch,
    /// Whenever the test delivers [`FailingCatchUp::frank_leave`].
    Later,
    /// As [`Self::Later`], but Carol asked to leave before her batch opened,
    /// so she schedules no auto-commit of her own for Frank's proposal.
    LaterWhileCarolLeaves,
    /// As [`Self::Later`], but his proposal's bytes reached Carol before her
    /// batch opened and wait unpeeled under its content id, where the direct
    /// path later rewrites that row in place.
    LaterUnderAnOlderDeferredRow,
}

/// Carol at epoch 1 holds Alice's epoch-1 invite in a frozen pass whose next
/// attempt is due. Alice has moved on: an application at epoch 2 and a second
/// invite built on the first are not yet delivered.
struct FailingCatchUp {
    label: String,
    carol: cgka_engine::Engine<FaultStorage>,
    handle: SqliteAccountStorage,
    fault: PutGroupFault,
    /// Counts Carol's reseeds and her full graph listings.
    preparation: PreparationDelay,
    clock: ManualConvergenceClock,
    audit_path: PathBuf,
    _audit_dir: tempfile::TempDir,
    group_id: GroupId,
    alice: cgka_engine::Engine<SqliteAccountStorage>,
    invite_david: TransportMessage,
    app_at_two: TransportMessage,
    invite_eve: TransportMessage,
    /// Frank's epoch-1 SelfRemove proposal, for [`FrankLeaves::Later`].
    frank_leave: Option<TransportMessage>,
}

async fn failing_catch_up(label: &str) -> FailingCatchUp {
    failing_catch_up_with(label, None).await
}

async fn failing_catch_up_with(label: &str, frank_leaves: Option<FrankLeaves>) -> FailingCatchUp {
    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("carol.jsonl");
    let fault = PutGroupFault::default();
    let preparation = PreparationDelay::default();
    let clock = ManualConvergenceClock::new(1_000_000, 1_700_000_000_000);
    let handle = SqliteAccountStorage::in_memory().unwrap();
    let mut carol = build_carol(
        label,
        handle.clone(),
        fault.clone(),
        preparation.clone(),
        clock.clone(),
        &audit_path,
    );
    let mut alice = build_selfremove_client(format!("alice-{label}").as_bytes());
    let mut david = build_selfremove_client(format!("david-{label}").as_bytes());
    let mut eve = build_selfremove_client(format!("eve-{label}").as_bytes());
    let mut frank =
        frank_leaves.map(|_| build_selfremove_client(format!("frank-{label}").as_bytes()));

    let mut members = vec![carol.fresh_key_package().await.unwrap()];
    if let Some(frank) = frank.as_mut() {
        members.push(frank.fresh_key_package().await.unwrap());
    }
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: label.into(),
            description: String::new(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcome, frank_welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            let frank_welcome = (welcomes.len() > 1).then(|| welcomes.remove(1));
            (welcomes.remove(0), frank_welcome)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    carol.join_welcome(welcome).await.unwrap();
    let mut frank_leave = None;
    if let (Some(frank), Some(welcome)) = (frank.as_mut(), frank_welcome) {
        frank.join_welcome(welcome).await.unwrap();
        frank_leave = match frank
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        {
            SendResult::Proposal { msg } => Some(routed(msg, &group_id)),
            other => panic!("expected Proposal, got {other:?}"),
        };
    }
    if frank_leaves == Some(FrankLeaves::LaterWhileCarolLeaves) {
        let sent = carol
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap();
        assert!(matches!(sent, SendResult::Proposal { .. }), "got {sent:?}");
    }
    if frank_leaves == Some(FrankLeaves::BeforeTheBatch) {
        let outcome = carol.ingest(frank_leave.take().unwrap()).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::Processed),
            "got {outcome:?}"
        );
    }
    if frank_leaves == Some(FrankLeaves::LaterUnderAnOlderDeferredRow) {
        let leave = frank_leave.clone().unwrap();
        handle
            .put_message(&deferred_row_under_content_id(&leave, &group_id))
            .unwrap();
    }

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = routed(
        published_invite(&mut alice, &group_id, david_kp).await,
        &group_id,
    );
    let app_at_two = send_chat(&mut alice, &group_id, "after david").await;
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = routed(
        published_invite(&mut alice, &group_id, eve_kp).await,
        &group_id,
    );

    let ingested = carol.ingest(invite_david.clone()).await.unwrap();
    assert!(
        matches!(ingested, IngestOutcome::Buffered { .. }),
        "the invite must enter convergence, got {ingested:?}"
    );
    clock.advance_ms(PAST_CUTOFF_MS);
    FailingCatchUp {
        label: label.to_string(),
        carol,
        handle,
        fault,
        preparation,
        clock,
        audit_path,
        _audit_dir: audit_dir,
        group_id,
        alice,
        invite_david,
        app_at_two,
        invite_eve,
        frank_leave,
    }
}

impl FailingCatchUp {
    /// One scheduler-shaped attempt at the installed clock's time.
    fn attempt(&mut self) -> Result<CanonicalizationResult, String> {
        let now = self.clock.now().monotonic_ms;
        self.carol
            .converge_stored_openmls_messages_at(&self.group_id, now)
            .map_err(|error| format!("{error:?}"))
    }

    fn retry(&self) -> Option<ConvergencePassRetry> {
        self.handle
            .convergence_pass(&self.group_id)
            .unwrap()
            .expect("the failed pass stays stored")
            .retry
    }

    /// Full graph listings Carol has made: one per reseed, among others.
    fn graph_listings(&self) -> usize {
        self.preparation.graph_calls.load(Ordering::SeqCst)
    }

    /// Reseeds Carol has started, including ones that find nothing to open.
    fn reseeds(&self) -> usize {
        self.preparation
            .disband_candidate_reads
            .load(Ordering::SeqCst)
    }

    fn pass_generation(&self) -> u64 {
        self.handle
            .convergence_pass(&self.group_id)
            .unwrap()
            .expect("a pass is stored")
            .generation
    }

    /// Delay the host is told to wait before its next advance.
    fn scheduled_delay_ms(&mut self) -> Option<u64> {
        self.carol
            .prepare_convergence_cutoff_delay_ms(&self.group_id)
            .unwrap()
    }

    /// Fail attempts until the pass parks, waiting out each backoff.
    fn fail_until_parked(&mut self) {
        while !self.carol.convergence_pass_parked(&self.group_id).unwrap() {
            if let Some(retry) = self.retry() {
                let wait = retry
                    .next_attempt_monotonic_ms
                    .saturating_sub(self.clock.now().monotonic_ms);
                self.clock.advance_ms(wait);
            }
            assert!(self.attempt().is_err(), "every armed attempt fails");
        }
    }

    /// Drop Carol's engine and open a new one on the same storage, on a new
    /// process-local clock whose wall time has moved on by `elapsed_wall_ms`.
    fn restart(&mut self, elapsed_wall_ms: u64) {
        let wall_ms = self.clock.now().wall_ms.saturating_add(elapsed_wall_ms);
        self.restart_at_wall(wall_ms);
    }

    /// [`Self::restart`] onto an arbitrary wall time, earlier ones included.
    fn restart_at_wall(&mut self, wall_ms: u64) {
        // Hydration writes no failed batch; keep its record writes out of
        // the attempt count.
        let armed = self.fault.remaining();
        self.fault.arm(0);
        self.clock = ManualConvergenceClock::new(7_000, wall_ms);
        self.carol = build_carol(
            &self.label,
            self.handle.clone(),
            self.fault.clone(),
            self.preparation.clone(),
            self.clock.clone(),
            &self.audit_path,
        );
        self.carol
            .hydrate_stable_groups_from_storage()
            .expect("restart hydrates carol's group");
        self.fault.arm(armed);
    }
}

#[tokio::test]
async fn a_failing_convergence_pass_backs_off_then_parks_after_its_budget() {
    let mut case = failing_catch_up("retry-park").await;
    case.fault.arm(ALWAYS);

    let mut expected_delay = CONVERGENCE_PASS_RETRY_BASE_MS;
    for failed_attempts in 1..=CONVERGENCE_PASS_PARK_AFTER_FAILURES {
        assert!(case.attempt().is_err(), "attempt {failed_attempts} fails");
        assert_eq!(
            ALWAYS - case.fault.remaining(),
            failed_attempts as usize,
            "each attempt reaches the apply once"
        );
        let retry = case.retry().expect("the failure is recorded on the pass");
        assert_eq!(retry.failed_attempts, failed_attempts);
        assert_eq!(retry.failed_step, ConvergencePassStep::Apply);
        assert_eq!(
            case.carol.epoch(&case.group_id).unwrap(),
            EpochId(1),
            "a failed apply leaves canonical state alone"
        );
        if failed_attempts == CONVERGENCE_PASS_PARK_AFTER_FAILURES {
            assert!(retry.is_parked());
            break;
        }
        assert!(!retry.is_parked());
        assert_eq!(
            retry.next_attempt_monotonic_ms - case.clock.now().monotonic_ms,
            expected_delay
        );
        assert_eq!(case.scheduled_delay_ms(), Some(expected_delay));
        assert_eq!(
            case.carol
                .deferred_peel_cutoff_delay_ms(&case.group_id)
                .unwrap(),
            None,
            "deferred rows must not wake the host ahead of the backoff"
        );

        // Nothing runs the batch before its delay is up: not a scheduled
        // advance, and not a send's foreground preflight.
        case.clock.advance_ms(expected_delay - 1);
        let waited = case.attempt().expect("an early advance waits");
        assert_eq!(waited.convergence_status, ConvergenceStatus::Syncing);
        assert!(
            case.carol
                .advance_convergence_inputs(&case.group_id)
                .await
                .is_ok()
        );
        assert_eq!(case.scheduled_delay_ms(), Some(1));
        if failed_attempts == 1 {
            let payload = cgka_traits::app_event::MarmotAppEvent::new(
                hex::encode(case.carol.self_id().as_slice()),
                1_700_000_000,
                cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
                vec![],
                "queued behind the batch",
            )
            .encode()
            .unwrap();
            let sent = case
                .carol
                .send(SendIntent::AppMessage {
                    group_id: case.group_id.clone(),
                    payload,
                    expected_epoch: None,
                })
                .await
                .expect("a send during backoff queues");
            assert!(
                matches!(sent, SendResult::Queued { .. }),
                "the batch still gates sends, got {sent:?}"
            );
        }
        assert_eq!(
            ALWAYS - case.fault.remaining(),
            failed_attempts as usize,
            "no attempt runs during the backoff"
        );
        case.clock.advance_ms(1);
        expected_delay = (expected_delay * 2).min(CONVERGENCE_PASS_RETRY_MAX_MS);
    }

    // Parked: the pass reports no wake, and no entry point attempts it.
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(case.scheduled_delay_ms(), None);
    case.clock.advance_ms(24 * 60 * 60 * 1_000);
    case.attempt().expect("a parked pass waits");
    case.carol
        .advance_convergence_inputs(&case.group_id)
        .await
        .expect("a parked pass waits");
    assert_eq!(
        ALWAYS - case.fault.remaining(),
        CONVERGENCE_PASS_PARK_AFTER_FAILURES as usize
    );
    let stored = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.phase, ConvergencePassPhase::Resolving);

    drop(case.carol);
    let reasons: Vec<(ConvergencePhase, String, Option<String>)> =
        std::fs::read_to_string(&case.audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<AuditEvent>(line).unwrap())
            .filter_map(|event| match event.kind {
                AuditEventKind::ConvergenceRunState {
                    phase,
                    reason: Some(reason),
                    error_kind,
                    ..
                } if reason.starts_with("pass_") => Some((phase, reason, error_kind)),
                _ => None,
            })
            .collect();
    let failed = (ConvergencePhase::Failed, "pass_failed:apply".to_string());
    let parked = (ConvergencePhase::Blocked, "pass_parked:apply".to_string());
    let mut expected: Vec<_> =
        std::iter::repeat_n(failed, CONVERGENCE_PASS_PARK_AFTER_FAILURES as usize - 1).collect();
    expected.push(parked);
    assert_eq!(
        reasons
            .iter()
            .map(|(phase, reason, _)| (*phase, reason.clone()))
            .collect::<Vec<_>>(),
        expected
    );
    assert!(
        reasons
            .iter()
            .all(|(_, _, error_kind)| error_kind.as_deref() == Some("storage"))
    );
}

#[tokio::test]
async fn new_commit_input_reopens_a_parked_pass_and_an_application_does_not() {
    let mut case = failing_catch_up("retry-reopen").await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();
    let parked_generation = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .unwrap()
        .generation;
    case.fault.arm(0);

    // Live traffic is not new selection input: a busy group must not keep
    // re-arming a batch that fails.
    case.carol.ingest(case.app_at_two.clone()).await.unwrap();
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(
        case.retry().unwrap().failed_attempts,
        CONVERGENCE_PASS_PARK_AFTER_FAILURES
    );

    // A commit the batch does not hold reopens it with a fresh budget.
    case.carol.ingest(case.invite_eve.clone()).await.unwrap();
    assert!(!case.carol.convergence_pass_parked(&case.group_id).unwrap());
    let reopened = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .expect("the reopened pass is stored");
    assert_eq!(reopened.phase, ConvergencePassPhase::Collecting);
    assert_eq!(reopened.generation, parked_generation + 1);
    assert_eq!(reopened.retry, None);
    assert!(case.scheduled_delay_ms().is_some_and(|delay| delay > 0));

    case.clock.advance_ms(PAST_CUTOFF_MS);
    let result = case.attempt().expect("the reopened pass applies");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(
        result.accepted_commits,
        vec![
            content_hex(&case.invite_david),
            content_hex(&case.invite_eve)
        ]
    );
    assert_eq!(case.carol.epoch(&case.group_id).unwrap(), EpochId(3));
}

/// Every runtime load of a failed pass checks for new selection input, so a
/// proposal processed at the current epoch, which no convergence admission
/// sees, still reopens a parked batch at its next schedule read. Loads that
/// find every commit and proposal of the horizon in the batch pay for no
/// reseed.
#[tokio::test]
async fn a_current_epoch_proposal_reopens_a_parked_pass_and_idle_loads_reseed_nothing() {
    current_epoch_proposal_reopens_a_parked_pass("retry-proposal", FrankLeaves::Later).await;
}

/// Frank's proposal schedules the load itself: Carol, leaving too, schedules
/// no auto-commit for it, and that schedule is no longer what wakes her.
#[tokio::test]
async fn a_current_epoch_proposal_schedules_its_own_load_of_a_parked_pass() {
    current_epoch_proposal_reopens_a_parked_pass(
        "retry-proposal-leaving",
        FrankLeaves::LaterWhileCarolLeaves,
    )
    .await;
}

async fn current_epoch_proposal_reopens_a_parked_pass(label: &str, frank_leaves: FrankLeaves) {
    let mut case = failing_catch_up_with(label, Some(frank_leaves)).await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();
    case.fault.arm(0);
    let parked_generation = case.pass_generation();

    // Neither the schedule read, nor the gate, nor live application traffic
    // reseeds a batch that holds every stored commit and proposal it could.
    let (listings, reseeds) = (case.graph_listings(), case.reseeds());
    for _ in 0..3 {
        assert_eq!(case.scheduled_delay_ms(), None);
        case.attempt().expect("a parked pass waits");
    }
    case.carol.ingest(case.app_at_two.clone()).await.unwrap();
    assert_eq!(case.scheduled_delay_ms(), None);
    assert_eq!(
        (case.graph_listings(), case.reseeds()),
        (listings, reseeds),
        "no load reseeded the batch"
    );
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());

    // Frank's leave is processed on arrival, outside convergence admission.
    // It schedules a load, and the load reopens the batch with a fresh budget.
    case.carol.drain_pending_convergence_groups();
    let outcome = case
        .carol
        .ingest(case.frank_leave.clone().unwrap())
        .await
        .unwrap();
    assert!(
        matches!(outcome, IngestOutcome::Processed),
        "got {outcome:?}"
    );
    assert!(
        case.carol
            .drain_pending_convergence_groups()
            .contains(&case.group_id)
    );
    // The simulator reads that load as runnable work before it happens.
    #[cfg(feature = "test-conformance-snapshot")]
    {
        case.carol.drain_events();
        case.carol.drain_valid_proposal_groups();
        let pending = case
            .carol
            .conformance_structural_progress_snapshot(&case.group_id)
            .unwrap();
        assert!(pending.runnable_work > 0, "{pending:?}");
    }
    let (listings, reseeds) = (case.graph_listings(), case.reseeds());
    assert!(case.scheduled_delay_ms().is_some_and(|delay| delay > 0));
    assert_eq!(
        case.reseeds(),
        reseeds + 1,
        "the proposal paid for one reseed"
    );
    assert!(case.graph_listings() > listings);
    let reopened = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .expect("the reopened pass is stored");
    assert_eq!(reopened.phase, ConvergencePassPhase::Collecting);
    assert_eq!(reopened.generation, parked_generation + 1);
    assert_eq!(reopened.retry, None);
    assert!(!case.carol.convergence_pass_parked(&case.group_id).unwrap());
}

/// A row rewritten in place keeps its storage position. Frank's proposal
/// waited unpeeled under its content id since before Carol's batch opened,
/// so the batch's own commits were stored after it and every load has read
/// them. When the direct path rewrites that older row into the stored
/// proposal, the next load still reopens the batch.
#[tokio::test]
async fn a_proposal_rewritten_into_an_older_row_reopens_a_parked_pass() {
    let mut case = failing_catch_up_with(
        "retry-rewrite",
        Some(FrankLeaves::LaterUnderAnOlderDeferredRow),
    )
    .await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();
    case.fault.arm(0);
    let parked_generation = case.pass_generation();
    let reseeds = case.reseeds();
    for _ in 0..2 {
        assert_eq!(case.scheduled_delay_ms(), None);
    }
    assert_eq!(case.reseeds(), reseeds, "an unpeeled row is no input");

    let leave = case.frank_leave.clone().unwrap();
    let deferred = case
        .handle
        .get_message(&deferred_row_under_content_id(&leave, &case.group_id).id)
        .unwrap();
    assert_eq!(
        deferred.state,
        MessageState::PeelDeferred,
        "nothing peeled it"
    );
    case.handle
        .put_message(&peeled_in_place(&deferred, &leave))
        .unwrap();

    assert!(case.scheduled_delay_ms().is_some_and(|delay| delay > 0));
    let reopened = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .expect("the reopened pass is stored");
    assert_eq!(reopened.phase, ConvergencePassPhase::Collecting);
    assert_eq!(reopened.generation, parked_generation + 1);
    assert_eq!(reopened.retry, None);
}

/// The park and the explicit retry pass the engine's liveness gate. A group
/// only seeded at open reports no park until a schedule read hydrates it;
/// a quarantined group reports none and its stored pass takes no retry.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn an_unvalidated_group_reports_no_park_and_takes_no_retry() {
    let mut case = failing_catch_up("retry-liveness").await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();
    case.fault.arm(0);

    case.restart(0);
    assert!(!case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(case.scheduled_delay_ms(), None);
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());

    // A wire profile that no longer matches the stored group fails its
    // validation at the next hydration, which quarantines it.
    let mut mismatched = case.handle.get_group(&case.group_id).unwrap();
    mismatched.protocol_profile = cgka_traits::group::ProtocolProfile::Current;
    case.handle.put_group(&mismatched).unwrap();
    case.restart(0);
    let parked = case.retry();
    assert!(
        !case
            .carol
            .retry_failed_convergence_pass(&case.group_id)
            .unwrap()
    );
    assert!(case.carol.check_group_live(&case.group_id).is_err());
    assert!(!case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(case.retry(), parked, "the stored pass is left as it was");
}

#[tokio::test]
async fn input_beyond_the_pass_horizon_leaves_a_parked_pass_parked() {
    let mut case = failing_catch_up("retry-horizon").await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();
    case.fault.arm(0);

    // Alice is at epoch 3. Her commit from epoch 7 lies past the horizon of
    // Carol's epoch-1 batch, so a reseed would leave it out and rebuild the
    // same failing batch.
    let mut far_commit = None;
    for _ in 3..=7 {
        far_commit = Some(next_routed_commit(&mut case.alice, &case.group_id).await);
    }
    let far_commit = far_commit.unwrap();
    case.carol.ingest(far_commit).await.unwrap();

    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());
    let retry = case.retry().unwrap();
    assert_eq!(retry.failed_attempts, CONVERGENCE_PASS_PARK_AFTER_FAILURES);
    assert!(retry.is_parked());
}

#[tokio::test]
async fn an_explicit_retry_grants_one_attempt_and_a_failure_parks_again() {
    let mut case = failing_catch_up("retry-explicit").await;
    case.fault.arm(ALWAYS);
    case.fail_until_parked();

    assert!(
        case.carol
            .retry_failed_convergence_pass(&case.group_id)
            .unwrap()
    );
    assert!(!case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(case.scheduled_delay_ms(), Some(0));
    assert!(case.attempt().is_err());
    let retry = case.retry().unwrap();
    assert_eq!(
        retry.failed_attempts,
        CONVERGENCE_PASS_PARK_AFTER_FAILURES + 1,
        "the retry keeps the count"
    );
    assert!(retry.is_parked(), "one more failure parks it again at once");

    case.fault.arm(0);
    assert!(
        case.carol
            .retry_failed_convergence_pass(&case.group_id)
            .unwrap()
    );
    let result = case.attempt().expect("the retried pass applies");
    assert_eq!(result.convergence_status, ConvergenceStatus::Settled);
    assert_eq!(case.carol.epoch(&case.group_id).unwrap(), EpochId(2));
    let completed = case
        .handle
        .convergence_pass(&case.group_id)
        .unwrap()
        .unwrap();
    assert_eq!(completed.phase, ConvergencePassPhase::Completed);
    assert_eq!(completed.retry, None);
    assert!(
        !case
            .carol
            .retry_failed_convergence_pass(&case.group_id)
            .unwrap(),
        "a completed pass has nothing to retry"
    );
}

#[tokio::test]
async fn a_failed_pass_keeps_its_backoff_and_park_across_a_restart() {
    let mut case = failing_catch_up("retry-restart").await;
    case.fault.arm(ALWAYS);
    assert!(case.attempt().is_err());
    case.clock.advance_ms(CONVERGENCE_PASS_RETRY_BASE_MS);
    assert!(case.attempt().is_err());
    let second_delay = 2 * CONVERGENCE_PASS_RETRY_BASE_MS;
    assert_eq!(case.retry().unwrap().failed_attempts, 2);

    // Half the delay passes on the wall clock while the device is closed; the
    // new process's monotonic clock starts elsewhere.
    case.restart(second_delay / 2);
    let remaining = second_delay - second_delay / 2;
    assert_eq!(case.scheduled_delay_ms(), Some(remaining));
    let rebased = case.retry().unwrap();
    assert_eq!(rebased.failed_attempts, 2);
    assert_eq!(
        rebased.next_attempt_monotonic_ms,
        case.clock.now().monotonic_ms + remaining
    );
    case.attempt().expect("the rebased backoff still holds");
    assert_eq!(ALWAYS - case.fault.remaining(), 2);
    case.clock.advance_ms(remaining);
    assert!(case.attempt().is_err());
    assert_eq!(case.retry().unwrap().failed_attempts, 3);

    // A wall clock stepped back an hour across a restart waits no longer than
    // the delay the failure was granted.
    let third_delay = 4 * CONVERGENCE_PASS_RETRY_BASE_MS;
    let wall_ms = case.clock.now().wall_ms - 60 * 60 * 1_000;
    case.restart_at_wall(wall_ms);
    assert_eq!(case.scheduled_delay_ms(), Some(third_delay));
    case.clock.advance_ms(third_delay);
    assert!(case.attempt().is_err());
    assert_eq!(case.retry().unwrap().failed_attempts, 4);

    case.fail_until_parked();
    let failures = ALWAYS - case.fault.remaining();
    case.restart(60 * 60 * 1_000);
    assert_eq!(case.scheduled_delay_ms(), None);
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());
    case.attempt()
        .expect("a parked pass stays parked after restart");
    assert_eq!(ALWAYS - case.fault.remaining(), failures);
}

/// The simulator's structural progress reads a failed batch the way the
/// runtime's readiness does: a backing-off pass is a wake at its retry time, a
/// parked one is idle, and neither the send nor the due SelfRemove auto-commit
/// it holds back is runnable meanwhile.
#[cfg(feature = "test-conformance-snapshot")]
#[tokio::test]
async fn structural_progress_waits_out_a_failed_pass_and_idles_a_parked_one() {
    let mut case = failing_catch_up_with("retry-progress", Some(FrankLeaves::BeforeTheBatch)).await;
    // The session drains these edges on every ingest.
    case.carol.drain_valid_proposal_groups();
    case.carol.drain_pending_convergence_groups();
    case.fault.arm(ALWAYS);
    assert!(case.attempt().is_err());
    let payload = cgka_traits::app_event::MarmotAppEvent::new(
        hex::encode(case.carol.self_id().as_slice()),
        1_700_000_000,
        cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "queued behind the batch",
    )
    .encode()
    .unwrap();
    let sent = case
        .carol
        .send(SendIntent::AppMessage {
            group_id: case.group_id.clone(),
            payload,
            expected_epoch: None,
        })
        .await
        .expect("a send during backoff queues");
    assert!(matches!(sent, SendResult::Queued { .. }), "got {sent:?}");
    case.carol.drain_events();

    let retry = case.retry().expect("the failure is recorded on the pass");
    let waiting = case
        .carol
        .conformance_structural_progress_snapshot(&case.group_id)
        .unwrap();
    assert_eq!(waiting.pending_work.queued_outbound_intents, 1);
    assert_eq!(
        waiting.pending_work.scheduled_self_remove_auto_commits, 1,
        "Frank's removal is due behind the batch"
    );
    assert_eq!(
        waiting.earliest_next_wake_monotonic_ms,
        Some(retry.next_attempt_monotonic_ms)
    );
    assert_eq!(
        waiting.runnable_work, 0,
        "nothing behind a backing-off batch can run before its retry: {waiting:?}"
    );

    case.clock.advance_ms(CONVERGENCE_PASS_RETRY_BASE_MS);
    let due = case
        .carol
        .conformance_structural_progress_snapshot(&case.group_id)
        .unwrap();
    assert!(due.runnable_work > 0, "the retry is due: {due:?}");

    case.fail_until_parked();
    case.carol.drain_events();
    let parked = case
        .carol
        .conformance_structural_progress_snapshot(&case.group_id)
        .unwrap();
    assert_eq!(parked.pending_work.queued_outbound_intents, 1);
    assert_eq!(
        (parked.runnable_work, parked.earliest_next_wake_monotonic_ms),
        (0, None),
        "a parked batch waits for new input, not for time: {parked:?}"
    );
}
