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

fn retry_storage(inner: SqliteAccountStorage, fault: PutGroupFault) -> FaultStorage {
    FaultStorage {
        inner,
        fault,
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: LeaveWriteFault::default(),
        failed_state_fault: FailedStateWriteFault::default(),
        release_fault: LeaveWriteFault::default(),
        preparation_delay: PreparationDelay::default(),
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
    clock: ManualConvergenceClock,
    audit_path: &Path,
) -> cgka_engine::Engine<FaultStorage> {
    let id = format!("carol-{label}");
    EngineBuilder::new(retry_storage(inner, fault))
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

fn routed(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

/// Carol at epoch 1 holds Alice's epoch-1 invite in a frozen pass whose next
/// attempt is due. Alice has moved on: an application at epoch 2 and a second
/// invite built on the first are not yet delivered.
struct FailingCatchUp {
    label: String,
    carol: cgka_engine::Engine<FaultStorage>,
    handle: SqliteAccountStorage,
    fault: PutGroupFault,
    clock: ManualConvergenceClock,
    audit_path: PathBuf,
    _audit_dir: tempfile::TempDir,
    group_id: GroupId,
    alice: cgka_engine::Engine<SqliteAccountStorage>,
    invite_david: TransportMessage,
    app_at_two: TransportMessage,
    invite_eve: TransportMessage,
}

async fn failing_catch_up(label: &str) -> FailingCatchUp {
    let audit_dir = tempfile::tempdir().unwrap();
    let audit_path = audit_dir.path().join("carol.jsonl");
    let fault = PutGroupFault::default();
    let clock = ManualConvergenceClock::new(1_000_000, 1_700_000_000_000);
    let handle = SqliteAccountStorage::in_memory().unwrap();
    let mut carol = build_carol(
        label,
        handle.clone(),
        fault.clone(),
        clock.clone(),
        &audit_path,
    );
    let mut alice = build_selfremove_client(format!("alice-{label}").as_bytes());
    let mut david = build_selfremove_client(format!("david-{label}").as_bytes());
    let mut eve = build_selfremove_client(format!("eve-{label}").as_bytes());

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: label.into(),
            description: String::new(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    carol.join_welcome(welcome).await.unwrap();

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
        clock,
        audit_path,
        _audit_dir: audit_dir,
        group_id,
        alice,
        invite_david,
        app_at_two,
        invite_eve,
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
        // Hydration writes no failed batch; keep its record writes out of
        // the attempt count.
        let armed = self.fault.remaining();
        self.fault.arm(0);
        let wall_ms = self.clock.now().wall_ms.saturating_add(elapsed_wall_ms);
        self.clock = ManualConvergenceClock::new(7_000, wall_ms);
        self.carol = build_carol(
            &self.label,
            self.handle.clone(),
            self.fault.clone(),
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

    case.fail_until_parked();
    let failures = ALWAYS - case.fault.remaining();
    case.restart(60 * 60 * 1_000);
    assert!(case.carol.convergence_pass_parked(&case.group_id).unwrap());
    assert_eq!(case.scheduled_delay_ms(), None);
    case.attempt()
        .expect("a parked pass stays parked after restart");
    assert_eq!(ALWAYS - case.fault.remaining(), failures);
}
