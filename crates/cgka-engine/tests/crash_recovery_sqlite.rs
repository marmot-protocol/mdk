#![cfg(all(feature = "test-crash-hooks", debug_assertions))]

//! Process-kill coverage for convergence rewrite durability (#1025).
//!
//! The ignored child test drives the real retained-anchor late-commit and
//! deferred candidate-branch paths over encrypted file-backed SQLite. Parent
//! tests stop it at fixed debug-only crash points, then reopen and hydrate the
//! database without running child destructors.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cgka_engine::canonicalization::{CanonicalizationPolicy, CanonicalizationState};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{
    apply_openmls_canonicalization_result, canonicalize_stored_openmls_messages,
};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::group_recovery::{
    GroupMemberRecovery, GroupRecoveryBody, GroupRecoveryMessage, group_recovery_grant_bytes,
};
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::maintenance::{
    DurableGroupEvolution, GroupEvolutionPhase, GroupEvolutionSemantic,
};
use cgka_traits::message::{MessageRecord, MessageState, StoredMessagePayload};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerStorage, ConvergencePassStorage, GroupStorage, MaintenanceStorage,
    MessageStorage, OutboundFanoutStorage, OutboundIntentStorage, QueuedOutboundIntent,
    StorageProvider,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    GroupRecoveryPhase, GroupRecoveryRecord, GroupRecoveryRole, SqlCipherKey, SqliteAccountStorage,
};

mod support;
use support::proof_signer;

const CHILD_ENV: &str = "MDK_CGKA_CRASH_CHILD";
const DATABASE_ENV: &str = "MDK_CGKA_CRASH_DATABASE";
const CRASH_POINT_ENV: &str = "MDK_CGKA_TEST_CRASH_POINT";
const CRASH_OCCURRENCE_ENV: &str = "MDK_CGKA_TEST_CRASH_OCCURRENCE";
const DATABASE_KEY: &str = "cgka convergence crash recovery key";
const READY_PREFIX: &str = "MDK_CGKA_TEST_CRASH_READY:";
const H5_POINT: &str = "historical-apply-before-commit";
const H6_POINT: &str = "retained-anchor-after-rewind";
const CANDIDATE_BRANCH_POINT: &str = "candidate-branch-after-rewind";
const PAST_PEEL_POINT: &str = "past-peel-after-rewind";
const DURABLE_TRANSITION_POINTS: &[&str] = &[
    "convergence-pass-collecting-durable",
    "convergence-pass-frozen-durable",
    "convergence-pass-resolving-durable",
    "convergence-pass-completed-durable",
];
const CAROL_SEED: &[u8] = b"carol-crash";
const QUEUED_INTENT_ID: &[u8] = b"crash-queued-intent";

struct MockPeeler;

#[async_trait]
impl TransportPeeler for MockPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::MlsMessage {
                bytes: msg.payload.clone(),
            },
            origin: msg.clone(),
        })
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        Ok(PeeledMessage {
            id: msg.id.clone(),
            group_id: None,
            sender: None,
            content: PeeledContent::Welcome {
                created_at: None,
                bytes: msg.payload.clone(),
                key_package_event_id: None,
            },
            origin: msg.clone(),
        })
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("crash-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: vec![],
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("crash-test".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

/// Models the production shape the retained-anchor fallback exists for: traffic
/// sealed under a past epoch's exporter secret, which the live context cannot
/// read.
struct UnreadablePeeler;

#[async_trait]
impl TransportPeeler for UnreadablePeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
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

// The historical apply is one transaction (a savepoint, mdk#2326), so a kill
// before it commits strands no pre-apply snapshot: the reopened database is
// already the pre-apply state.
#[test]
fn h5_kill_before_historical_apply_commit_preserves_live_inputs() {
    run_parent_case(H5_POINT, EpochId(2), None);
}

#[test]
fn h6_kill_after_retained_anchor_rewind_recovers_live_snapshot() {
    run_parent_case(H6_POINT, EpochId(1), Some("openmls-retained-probe-"));
}

#[test]
fn candidate_branch_kill_after_rewind_recovers_live_state_and_work_rows() {
    run_parent_case(
        CANDIDATE_BRANCH_POINT,
        EpochId(1),
        Some("openmls-branch-probe-"),
    );
}

// The deferred-peel sweep rewinds live state onto a retained anchor once per
// anchor to derive the exporter context that reads a late message. A kill
// inside that window leaves the anchor's epoch as this device's durable state
// while the guard snapshot holds the real tip, so reopening must restore the
// tip instead of accepting the rollback as its own.
#[test]
fn past_peel_kill_after_rewind_recovers_the_committed_tip() {
    run_parent_case(PAST_PEEL_POINT, EpochId(1), Some("peel-restore-"));
}

#[test]
fn kill_at_every_durable_convergence_phase_reopens_and_finishes() {
    for point in DURABLE_TRANSITION_POINTS {
        run_transition_parent_case(point);
    }
}

#[tokio::test]
#[ignore = "spawned by the parent crash-recovery tests"]
async fn crash_child_runs_late_commit_convergence() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path"));
    if std::env::var(CRASH_POINT_ENV).is_ok_and(|point| point.starts_with("recovery_")) {
        run_recovery_child(&path).await;
    } else if std::env::var(CRASH_POINT_ENV)
        .is_ok_and(|point| point.starts_with("canonical-application-"))
    {
        run_application_child(&path).await;
    } else if std::env::var(CRASH_POINT_ENV)
        .is_ok_and(|point| point.starts_with("candidate-replay-"))
    {
        run_probe_child(&path).await;
    } else {
        run_child_case(&path).await;
    }
    panic!("selected crash point was not reached");
}

/// Default bound on how long a parent waits for its child's ready marker.
///
/// A child reaches its pause point in one to two seconds in a local debug
/// build, but partitioned CI runs it beside 30-50 s cgka-engine convergence
/// tests on shared runners, where a child has needed more than 30 s. The
/// bound only catches a child wedged before its pause point: one that misses
/// the point panics and closes stdout, which fails at once.
const DEFAULT_CRASH_READY_TIMEOUT: Duration = Duration::from_secs(120);
/// Overrides [`DEFAULT_CRASH_READY_TIMEOUT`] with a whole number of seconds.
const CRASH_READY_TIMEOUT_ENV: &str = "MDK_CGKA_CRASH_READY_TIMEOUT_SECS";

fn crash_ready_timeout() -> Duration {
    let Ok(value) = std::env::var(CRASH_READY_TIMEOUT_ENV) else {
        return DEFAULT_CRASH_READY_TIMEOUT;
    };
    let timeout = value
        .trim()
        .parse()
        .ok()
        .map(Duration::from_secs)
        // The wait adds the bound to `Instant::now()`; reject one that
        // cannot be represented rather than overflow there.
        .filter(|timeout| Instant::now().checked_add(*timeout).is_some());
    timeout.unwrap_or_else(|| {
        panic!("{CRASH_READY_TIMEOUT_ENV} must be a representable number of seconds, got {value:?}")
    })
}

/// A child test process running toward one crash point.
struct CrashChild {
    point: String,
    ready_timeout: Duration,
    /// The point plus any extra child environment, for failure messages.
    label: String,
    child: Child,
    lines: mpsc::Receiver<std::io::Result<String>>,
    stdout_reader: JoinHandle<()>,
    stderr_reader: JoinHandle<String>,
}

fn spawn_crash_child(database: &Path, point: &str, extra_env: &[(&str, &str)]) -> CrashChild {
    // Resolve the bound first: a bad override must not panic with a child
    // already running.
    let ready_timeout = crash_ready_timeout();
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--ignored",
            "--exact",
            "crash_child_runs_late_commit_convergence",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(DATABASE_ENV, database)
        .env(CRASH_POINT_ENV, point)
        .envs(extra_env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn crash child");
    let stdout = child.stdout.take().expect("child stdout");
    let (line_tx, lines) = mpsc::channel();
    let stdout_reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line).is_err() {
                return;
            }
        }
    });
    // Drain stderr concurrently so a chatty child can never block on a full
    // pipe before it reaches its pause point.
    let mut stderr = child.stderr.take().expect("child stderr");
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let label = std::iter::once(point.to_owned())
        .chain(
            extra_env
                .iter()
                .map(|(name, value)| format!("{name}={value}")),
        )
        .collect::<Vec<_>>()
        .join(" ");
    CrashChild {
        point: point.to_owned(),
        ready_timeout,
        label,
        child,
        lines,
        stdout_reader,
        stderr_reader,
    }
}

impl CrashChild {
    /// Waits for the ready marker, kills the paused child, and returns its
    /// stderr. Panics with the elapsed time and the child's output if the
    /// child exits or the ready bound passes first.
    fn kill_when_ready(self) -> String {
        let Self {
            point,
            ready_timeout: timeout,
            label,
            mut child,
            lines,
            stdout_reader,
            stderr_reader,
        } = self;
        let expected_ready = format!("{READY_PREFIX}{point}");
        let started = Instant::now();
        let deadline = started + timeout;
        let mut stdout = Vec::new();
        let mut stdout_closed = false;
        let timed_out =
            || format!("ready bound {timeout:?} passed (override with {CRASH_READY_TIMEOUT_ENV})");
        let failure = loop {
            match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(Ok(line)) if line == expected_ready => break None,
                Ok(Ok(line)) => {
                    stdout.push(line);
                    // `recv_timeout` still returns queued output once no time
                    // remains, so a child that keeps printing would outrun
                    // the bound without this check. Checking after the
                    // marker test keeps a marker that arrives at the edge.
                    if Instant::now() >= deadline {
                        break Some(timed_out());
                    }
                }
                Ok(Err(error)) => break Some(format!("stdout read failed: {error}")),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    stdout_closed = true;
                    break Some("child closed stdout without the ready marker".to_owned());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    break Some(timed_out());
                }
            }
        };
        let elapsed = started.elapsed();
        // A child that closed stdout is exiting by itself; wait for its own
        // status rather than racing a kill against it.
        if !stdout_closed {
            let _ = child.kill();
        }
        let status = child.wait().expect("wait for crash child");
        drop(lines);
        stdout_reader.join().expect("crash child stdout reader");
        let stderr = stderr_reader.join().expect("crash child stderr reader");
        if let Some(reason) = failure {
            let exit = if stdout_closed {
                format!("child exited with {status}")
            } else {
                "killed by the parent".to_owned()
            };
            panic!(
                "crash child did not reach {label} after {elapsed:.1?}: {reason}; {exit}\n\
                 stdout:\n{}\nstderr:\n{stderr}",
                stdout.join("\n")
            );
        }
        assert!(
            !status.success(),
            "child killed at {label} must not exit successfully; stderr:\n{stderr}"
        );
        stderr
    }
}

/// `stranded_snapshot` is the prefix of the snapshot the kill must strand for
/// hydration to restore, or `None` when the kill must strand none.
fn run_parent_case(point: &str, stranded_epoch: EpochId, stranded_snapshot: Option<&str>) {
    let dir = tempfile::tempdir().expect("parent temp directory");
    let database = dir.path().join("carol.sqlite3");
    let stderr = spawn_crash_child(&database, point, &[]).kill_when_ready();
    assert!(
        database.exists(),
        "child database missing after kill; stderr:\n{stderr}"
    );
    assert!(
        wal_path(&database).exists(),
        "WAL must survive the abrupt process stop"
    );

    let key = SqlCipherKey::new(DATABASE_KEY).expect("parent SQLCipher key");
    let storage =
        SqliteAccountStorage::open_encrypted(&database, &key).expect("reopen killed database");
    let group_ids = storage.list_groups().expect("list persisted groups");
    assert_eq!(group_ids.len(), 1, "crash fixture owns one group");
    let group_id = group_ids[0].clone();
    let stranded_group = storage.get_group(&group_id).expect("stranded group");
    assert_eq!(stranded_group.epoch, stranded_epoch);
    if matches!(point, H6_POINT | CANDIDATE_BRANCH_POINT | PAST_PEEL_POINT) {
        assert!(
            !stranded_group
                .members
                .iter()
                .any(|member| member.id == MemberId::new(identity(b"david-crash"))),
            "retained-anchor crash must expose the historical membership before hydration"
        );
    }
    let snapshot_prefix = stranded_snapshot.unwrap_or("openmls-apply-");
    assert_eq!(
        storage
            .list_group_snapshots(&group_id)
            .expect("list stranded snapshots")
            .iter()
            .any(|name| name.starts_with(snapshot_prefix)),
        stranded_snapshot.is_some(),
        "stranded snapshot with prefix {snapshot_prefix}"
    );
    if matches!(point, H5_POINT | CANDIDATE_BRANCH_POINT | PAST_PEEL_POINT) {
        assert_eq!(
            storage
                .list_queued_outbound_intents(&group_id)
                .expect("list stranded queued work")
                .len(),
            1,
            "the uncommitted historical rewrite must not discard queued work"
        );
        assert!(
            storage
                .list_messages(&group_id, EpochId(0))
                .expect("list stranded convergence inputs")
                .iter()
                .any(|record| record.state == MessageState::Created),
            "the uncommitted historical rewrite must not discard its convergence input"
        );
    }

    let mut reopened = build_client_with_storage(CAROL_SEED, storage.clone());
    reopened
        .hydrate_all_stored_groups()
        .expect("hydrate killed database");

    assert_eq!(
        reopened.epoch(&group_id).expect("recovered epoch"),
        EpochId(2)
    );
    let events = reopened.drain_events();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GroupEvent::PendingCommitRecovered { .. })),
        "a recovered rewind must not be mistaken for a crashed publish; got {events:?}"
    );
    let recovered_group = storage.get_group(&group_id).expect("recovered group");
    assert_eq!(recovered_group.name, "crash-recovery");
    assert!(
        recovered_group
            .members
            .iter()
            .any(|member| member.id == MemberId::new(identity(b"david-crash"))),
        "hydration must restore the live incumbent membership"
    );
    assert!(
        !recovered_group
            .members
            .iter()
            .any(|member| member.id == MemberId::new(identity(b"eve-crash"))),
        "the uncommitted late rewrite must not replace the live membership"
    );
    assert!(
        storage
            .list_group_snapshots(&group_id)
            .expect("list recovered snapshots")
            .iter()
            .all(|name| !name.starts_with(snapshot_prefix)),
        "hydrate must release the interrupted snapshot"
    );
    let queued = storage
        .list_queued_outbound_intents(&group_id)
        .expect("list recovered queued work");
    assert_eq!(queued.len(), 1, "queued work must survive the crash");
    assert_eq!(queued[0].id, MessageId::new(QUEUED_INTENT_ID.to_vec()));
    assert!(
        storage
            .list_messages(&group_id, EpochId(0))
            .expect("list recovered convergence inputs")
            .iter()
            .any(|record| record.state == MessageState::Created),
        "the late convergence input must remain durable for replay"
    );
}

fn run_transition_parent_case(point: &str) {
    let dir = tempfile::tempdir().expect("transition temp directory");
    let database = dir.path().join("carol.sqlite3");
    // The incumbent pass exercises each phase once while building the durable
    // fixture. Kill the second occurrence, in the late competing pass whose
    // state must survive restart.
    let stderr =
        spawn_crash_child(&database, point, &[(CRASH_OCCURRENCE_ENV, "2")]).kill_when_ready();
    assert!(
        database.exists(),
        "database missing after kill at {point}; stderr:\n{stderr}"
    );

    let key = SqlCipherKey::new(DATABASE_KEY).expect("transition SQLCipher key");
    let storage =
        SqliteAccountStorage::open_encrypted(&database, &key).expect("reopen transition database");
    let group_ids = storage.list_groups().expect("list transition groups");
    assert_eq!(group_ids.len(), 1, "transition fixture owns one group");
    let group_id = group_ids[0].clone();
    assert_eq!(
        storage
            .list_queued_outbound_intents(&group_id)
            .expect("queued intents before transition hydration")
            .len(),
        1,
        "kill at {point} must leave the durable queued intent intact"
    );
    let mut reopened = build_client_with_storage(CAROL_SEED, storage.clone());
    reopened
        .hydrate_all_stored_groups()
        .unwrap_or_else(|error| panic!("hydrate after {point}: {error}"));
    assert_eq!(
        storage
            .list_queued_outbound_intents(&group_id)
            .expect("queued intents after transition hydration")
            .len(),
        1,
        "hydrate after {point} must preserve queued work"
    );
    // A collecting pass rebases its process-local monotonic cutoff from the
    // durable wall deadline on first use after restart. Drive once to perform
    // that rebase, then beyond the v1 absolute deadline; frozen/resolving
    // phases finish on the first call and make the second a harmless no-op.
    for now_ms in [4_000_000, 4_010_000] {
        reopened
            .converge_stored_openmls_messages_at(&group_id, now_ms)
            .unwrap_or_else(|error| panic!("resume after {point} at {now_ms}: {error}"));
    }
    assert_eq!(
        reopened
            .epoch(&group_id)
            .expect("epoch after transition repair"),
        EpochId(2),
        "kill at {point} must reopen to a complete epoch"
    );
    let recovered = storage
        .get_group(&group_id)
        .expect("group after transition repair");
    let completed_pass = storage
        .convergence_pass(&group_id)
        .expect("pass after transition repair")
        .expect("transition fixture retains the completed pass");
    assert_eq!(
        completed_pass.phase,
        cgka_traits::ConvergencePassPhase::Completed,
        "kill at {point} must finish the interrupted durable pass"
    );
    assert!(
        recovered
            .members
            .iter()
            .any(|member| member.id == MemberId::new(identity(b"eve-crash"))),
        "kill at {point} must preserve and finish the interrupted winning branch"
    );
    assert!(
        !recovered
            .members
            .iter()
            .any(|member| member.id == MemberId::new(identity(b"david-crash"))),
        "kill at {point} must not expose the losing incumbent branch"
    );
    assert!(
        storage
            .list_messages(&group_id, EpochId(1))
            .expect("late convergence inputs after transition repair")
            .iter()
            .all(|record| {
                !matches!(
                    record.state,
                    MessageState::Created | MessageState::Retryable
                )
            }),
        "kill at {point} must terminalize or defer every input from the interrupted pass"
    );
    let queued = storage
        .list_queued_outbound_intents(&group_id)
        .expect("queued intents after transition repair");
    assert_eq!(queued.len(), 1, "kill at {point} must preserve queued work");
    assert_eq!(queued[0].id, MessageId::new(QUEUED_INTENT_ID.to_vec()));
}

async fn run_child_case(database: &Path) {
    let (first, _first_storage) = build_memory_client(b"admin-a");
    let (second, _second_storage) = build_memory_client(b"admin-b");
    let ((mut alice, alice_seed), (mut bob, bob_seed)) =
        if first.self_id().as_slice() > second.self_id().as_slice() {
            (
                (first, b"admin-a".as_slice()),
                (second, b"admin-b".as_slice()),
            )
        } else {
            (
                (second, b"admin-b".as_slice()),
                (first, b"admin-a".as_slice()),
            )
        };
    assert!(
        bob.self_id().as_slice() < alice.self_id().as_slice(),
        "late challenger must exercise the lower-committer side of the deterministic tiebreak"
    );
    let (mut david, _david_storage) = build_memory_client(b"david-crash");
    let (mut eve, _eve_storage) = build_memory_client(b"eve-crash");

    let key = SqlCipherKey::new(DATABASE_KEY).expect("child SQLCipher key");
    let carol_storage =
        SqliteAccountStorage::open_encrypted(database, &key).expect("open child database");
    let mut carol = build_client_with_storage(CAROL_SEED, carol_storage.clone());

    let bob_kp = bob.fresh_key_package().await.expect("bob key package");
    let carol_kp = carol.fresh_key_package().await.expect("carol key package");
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "crash-recovery".into(),
            description: String::new(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .expect("create crash group");
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice
        .confirm_published(pending)
        .await
        .expect("confirm group");
    bob.join_welcome(welcome_for(&welcomes, bob_seed))
        .await
        .expect("bob joins");
    carol
        .join_welcome(welcome_for(&welcomes, CAROL_SEED))
        .await
        .expect("carol joins");

    let david_kp = david.fresh_key_package().await.expect("david key package");
    let (alice_commit, _) = evolution(
        alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![david_kp],
                initial_admins: vec![],
            })
            .await
            .expect("alice invite"),
    );
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(alice_commit, &group_id), 1_000)
        .expect("buffer incumbent commit");
    carol
        .converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("settle incumbent branch");
    assert_eq!(carol.epoch(&group_id).expect("live epoch"), EpochId(2));
    assert_eq!(
        carol_storage
            .get_group(&group_id)
            .expect("persisted live group")
            .epoch,
        EpochId(2)
    );

    let eve_kp = eve.fresh_key_package().await.expect("eve key package");
    let (bob_commit, _) = evolution(
        bob.send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .expect("bob invite"),
    );
    carol_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(QUEUED_INTENT_ID.to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, b"queued across crash"),
                expected_epoch: None,
            },
            created_at_ms: 2_100,
            reissue_attempts: 0,
        })
        .expect("persist queued work");
    // Persist the independent outbound obligation before admitting the late
    // convergence input: the collecting-phase hook fires during admission, so
    // the opposite order never actually exercised queued-intent durability at
    // that earliest kill point.
    carol
        .buffer_openmls_convergence_message_at(&group_id, route(bob_commit, &group_id), 2_000)
        .expect("buffer late competing commit");

    let _ = alice_seed;
    let crash_point = std::env::var(CRASH_POINT_ENV).ok();
    #[cfg(feature = "test-policy-overrides")]
    if crash_point
        .as_deref()
        .is_some_and(|p| p.contains("-slice-"))
    {
        carol.set_replay_slice_probe_limit_for_tests(1);
        if crash_point
            .as_deref()
            .is_some_and(|p| p.starts_with("candidate-peel-slice-"))
        {
            let deferred = TransportMessage {
                id: MessageId::new(b"slice-deferred".to_vec()),
                payload: b"opaque retained traffic".to_vec(),
                timestamp: Timestamp(2_200),
                causal_deps: vec![],
                source: TransportSource("crash-test".into()),
                envelope: TransportEnvelope::GroupMessage {
                    transport_group_id: group_id.as_slice().to_vec(),
                },
            };
            carol_storage
                .put_message(&MessageRecord {
                    id: deferred.id.clone(),
                    group_id: group_id.clone(),
                    epoch: EpochId(2),
                    state: MessageState::PeelDeferred,
                    payload: StoredMessagePayload::raw_transport(deferred)
                        .encode()
                        .unwrap(),
                    deferred_peel: None,
                })
                .unwrap();
            cgka_traits::storage::DeferredPeelGenerationStorage::put_deferred_peel_generation(
                &carol_storage,
                &cgka_traits::storage::DeferredPeelGeneration {
                    group_id: group_id.clone(),
                    context_fingerprint: [0; 32],
                },
            )
            .unwrap();
        }
        write_slice_expected(database, &carol_storage, &group_id);
        for _ in 0..8 {
            carol.advance_convergence_inputs(&group_id).await.unwrap();
        }
        panic!("resumable crash point not reached");
    }

    if crash_point.as_deref() == Some(H5_POINT) {
        let policy = CanonicalizationPolicy::default();
        let state = CanonicalizationState {
            current_tip_epoch: 2,
            retained_anchor_epoch: 0,
            last_convergence_relevant_input_ms: 3_000_000 - policy.settlement_quiescence_ms,
            seen_message_ids: BTreeSet::new(),
        };
        let result = canonicalize_stored_openmls_messages(
            &carol_storage,
            &group_id,
            state,
            vec![],
            policy.clone(),
            3_000_000,
        )
        .expect("canonicalize late historical branch");
        apply_openmls_canonicalization_result(
            &carol_storage,
            &group_id,
            &result,
            policy.convergence.max_rewind_commits,
        )
        .expect("historical apply reaches selected crash point");
    } else if let Some(point @ (CANDIDATE_BRANCH_POINT | PAST_PEEL_POINT)) = crash_point.as_deref()
    {
        let deferred = TransportMessage {
            id: MessageId::new(b"candidate-branch-deferred".to_vec()),
            payload: b"opaque candidate-branch traffic".to_vec(),
            timestamp: Timestamp(2_200),
            causal_deps: Vec::new(),
            source: TransportSource("crash-test".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
        };
        carol_storage
            .put_message(&MessageRecord {
                id: deferred.id.clone(),
                group_id: group_id.clone(),
                epoch: EpochId(2),
                state: MessageState::PeelDeferred,
                payload: StoredMessagePayload::raw_transport(deferred)
                    .encode()
                    .expect("encode deferred crash input"),
                deferred_peel: None,
            })
            .expect("persist deferred crash input");
        // The past-peel rewind is only reached by a row the LIVE context cannot
        // read, which is the production shape of post-fork traffic. Reopen the
        // same database behind a peeler that models it.
        if point == PAST_PEEL_POINT {
            carol = build_client_with_peeler(
                CAROL_SEED,
                carol_storage.clone(),
                Box::new(UnreadablePeeler),
            );
            carol
                .hydrate_all_stored_groups()
                .expect("hydrate before the past-peel sweep");
        }
        carol
            .retry_deferred_peels(&group_id)
            .await
            .expect("normalize deferred crash input");
        carol
            .retry_deferred_peels(&group_id)
            .await
            .expect("deferred-peel sweep reaches selected crash point");
    } else {
        carol
            .converge_stored_openmls_messages_at(&group_id, 3_000_000)
            .expect("late branch convergence reaches selected crash point");
    }
}

fn build_memory_client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    // The peers are plain fixtures; the file-backed database is what crashes.
    // Copying a migrated template keeps their setup from dominating the time a
    // child needs to reach its pause point.
    let storage = SqliteAccountStorage::in_memory_from_migrated_template(Default::default())
        .expect("in-memory storage");
    let engine = build_client_with_storage(seed, storage.clone());
    (engine, storage)
}

fn build_client_with_storage(
    seed: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    build_client_with_peeler(seed, storage, Box::new(MockPeeler))
}

fn build_client_with_peeler(
    seed: &[u8],
    storage: SqliteAccountStorage,
    peeler: Box<dyn TransportPeeler>,
) -> Engine<SqliteAccountStorage> {
    let builder = EngineBuilder::new(storage);
    #[cfg(feature = "test-policy-overrides")]
    let builder = if std::env::var(CRASH_POINT_ENV).is_ok_and(|p| p.contains("-slice-")) {
        builder.convergence_clock(std::sync::Arc::new(
            cgka_engine::convergence_clock::ManualConvergenceClock::new(
                3_000_000,
                1_800_000_000_000,
            ),
        ))
    } else {
        builder
    };
    builder
        .legacy_compatibility_profile()
        .identity(identity(seed))
        .account_identity_proof_signer(proof_signer(seed))
        .feature_registry(self_remove_registry())
        .peeler(peeler)
        .build()
        .expect("build crash-test engine")
}

fn self_remove_registry() -> FeatureRegistry {
    let mut registry = FeatureRegistry::new();
    registry.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    registry
}

fn identity(seed: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;

    let mut counter = 0_u64;
    loop {
        let mut material = [0_u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(key) = SigningKey::from_slice(&material) {
            return key.verifying_key().to_bytes().to_vec();
        }
        counter = counter.checked_add(1).expect("identity search exhausted");
    }
}

fn hash_id(bytes: &[u8]) -> MessageId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    MessageId::new(hasher.finish().to_be_bytes().to_vec())
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    match msg.envelope {
        TransportEnvelope::Welcome { .. } => msg,
        TransportEnvelope::GroupMessage { .. } => TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..msg
        },
    }
}

fn evolution(result: SendResult) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    match result {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    }
}

fn welcome_for(welcomes: &[TransportMessage], seed: &[u8]) -> TransportMessage {
    let recipient = MemberId::new(identity(seed));
    welcomes
        .iter()
        .find(|message| {
            matches!(
                &message.envelope,
                TransportEnvelope::Welcome { recipient: actual } if *actual == recipient
            )
        })
        .expect("welcome exists")
        .clone()
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, payload: &[u8]) -> Vec<u8> {
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        String::from_utf8(payload.to_vec()).expect("test payload is UTF-8"),
    )
    .encode()
    .expect("encode app event")
}

fn wal_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push("-wal");
    PathBuf::from(path)
}

fn probe_state(storage: &SqliteAccountStorage, group: &GroupId) -> serde_json::Value {
    use cgka_traits::storage::StorageProvider;
    let mls = openmls::group::MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group.as_slice()),
    )
    .unwrap()
    .unwrap();
    serde_json::json!({
        "group": storage.get_group(group).unwrap(),
        "epoch_authenticator": hex::encode(mls.epoch_authenticator().as_slice()),
        "snapshots": storage.list_group_snapshots(group).unwrap(),
        "messages": storage.list_messages(group, EpochId(0)).unwrap(),
        "queue": storage.list_queued_outbound_intents(group).unwrap(),
    })
}

#[test]
fn candidate_replay_kill_restores_preprobe_state_without_hydration() {
    for point in [
        "candidate-replay-after-processing",
        "candidate-replay-after-restoration",
    ] {
        for nested in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let database = dir.path().join("probe.sqlite3");
            spawn_crash_child(
                &database,
                point,
                &[("MDK_CGKA_REPLAY_NESTED", if nested { "1" } else { "0" })],
            )
            .kill_when_ready();
            let key = SqlCipherKey::new(DATABASE_KEY).unwrap();
            let storage = SqliteAccountStorage::open_encrypted(&database, &key).unwrap();
            let group = storage.list_groups().unwrap().pop().unwrap();
            let expected: serde_json::Value = serde_json::from_slice(
                &std::fs::read(database.with_extension("expected.json")).unwrap(),
            )
            .unwrap();
            assert!(
                probe_state(&storage, &group) == expected,
                "crash changed live state or work at {point}, nested={nested}"
            );
            let mut engine = build_client_with_storage(CAROL_SEED, storage.clone());
            engine.hydrate_all_stored_groups().unwrap();
            assert_eq!(engine.epoch(&group).unwrap(), EpochId(1));
        }
    }
}

async fn run_probe_child(database: &Path) {
    use cgka_engine::openmls_projection::replay_openmls_messages;
    use cgka_traits::storage::StorageProvider;
    let (mut alice, _) = build_memory_client(b"probe-alice");
    let storage =
        SqliteAccountStorage::open_encrypted(database, &SqlCipherKey::new(DATABASE_KEY).unwrap())
            .unwrap();
    let mut carol = build_client_with_storage(CAROL_SEED, storage.clone());
    let kp = carol.fresh_key_package().await.unwrap();
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "transaction crash".into(),
            description: String::new(),
            members: vec![kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("legacy fixture");
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcomes.into_iter().next().unwrap())
        .await
        .unwrap();
    let (commit, _) = evolution(
        alice
            .send(SendIntent::SelfUpdate {
                group_id: group.clone(),
            })
            .await
            .unwrap(),
    );
    storage
        .put_message(&MessageRecord {
            id: commit.id.clone(),
            group_id: group.clone(),
            epoch: EpochId(1),
            state: MessageState::Created,
            payload: StoredMessagePayload::openmls_wire(commit.clone())
                .encode()
                .unwrap(),
            deferred_peel: None,
        })
        .unwrap();
    storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(QUEUED_INTENT_ID.to_vec()),
            group_id: group.clone(),
            intent: SendIntent::AppMessage {
                expected_epoch: None,
                group_id: group.clone(),
                payload: app_payload_for(&carol, b"retained work"),
            },
            created_at_ms: 1,
            reissue_attempts: 0,
        })
        .unwrap();
    // The parent-owned temp directory is private; create the evidence file
    // owner-only too, before entering the transaction selected for termination.
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut expected = options
        .open(database.with_extension("expected.json"))
        .unwrap();
    expected
        .write_all(&serde_json::to_vec(&probe_state(&storage, &group)).unwrap())
        .unwrap();
    expected.sync_all().unwrap();
    let probe = || replay_openmls_messages(&storage, &group, std::slice::from_ref(&commit));
    if std::env::var("MDK_CGKA_REPLAY_NESTED").as_deref() == Ok("1") {
        storage.with_transaction(|_| probe()).unwrap();
    } else {
        probe().unwrap();
    }
}

#[cfg(feature = "test-policy-overrides")]
fn slice_state(storage: &SqliteAccountStorage, group: &GroupId) -> serde_json::Value {
    let mut state = probe_state(storage, group);
    // Normalizing a retained raw row's clock is legitimate durable progress
    // before the first peel slice. Its payload, disposition, and presence must
    // still survive exactly; no actual row attempt has started at this pause.
    for row in state["messages"].as_array_mut().unwrap() {
        row.as_object_mut().unwrap().remove("deferred_peel");
    }
    state
}

#[cfg(feature = "test-policy-overrides")]
fn write_slice_expected(database: &Path, storage: &SqliteAccountStorage, group: &GroupId) {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(database.with_extension("slice-expected.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&slice_state(storage, group)).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

#[cfg(feature = "test-policy-overrides")]
#[test]
fn resumable_slices_kill_with_live_state_restored_and_restart_from_durable_inputs() {
    for point in [
        "canonical-replay-slice-restored",
        "candidate-peel-slice-restored",
        "canonical-replay-slice-rewound",
        "candidate-peel-slice-rewound",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("slice.sqlite3");
        spawn_crash_child(&database, point, &[]).kill_when_ready();
        let storage = SqliteAccountStorage::open_encrypted(
            &database,
            &SqlCipherKey::new(DATABASE_KEY).unwrap(),
        )
        .unwrap();
        let group = storage.list_groups().unwrap().pop().unwrap();
        let expected: serde_json::Value = serde_json::from_slice(
            &std::fs::read(database.with_extension("slice-expected.json")).unwrap(),
        )
        .unwrap();
        if point.ends_with("-restored") {
            assert!(
                slice_state(&storage, &group) == expected,
                "slice exposed speculative state or changed retained work before hydration"
            );
        } else {
            assert_eq!(
                storage.get_group(&group).unwrap().epoch,
                EpochId(1),
                "kill must actually strand the historical rewind"
            );
        }
        let mut restarted = build_client_with_storage(CAROL_SEED, storage.clone());
        restarted.hydrate_all_stored_groups().unwrap();
        assert!(
            slice_state(&storage, &group) == expected,
            "hydration must restore the pre-slice live state and retained work"
        );
        assert_eq!(restarted.epoch(&group).unwrap(), EpochId(2));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for _ in 0..16 {
                restarted
                    .advance_convergence_inputs_until_settled(&group, 4_000_000)
                    .await
                    .unwrap();
            }
        });
        let result = restarted
            .converge_stored_openmls_messages_at(&group, 4_000_000)
            .unwrap();
        assert!(result.errors.is_empty());
        let final_group = storage.get_group(&group).unwrap();
        assert!(
            final_group
                .members
                .iter()
                .any(|m| m.id == MemberId::new(identity(b"eve-crash")))
        );
        assert!(
            !final_group
                .members
                .iter()
                .any(|m| m.id == MemberId::new(identity(b"david-crash")))
        );
        assert_eq!(
            storage.list_queued_outbound_intents(&group).unwrap().len(),
            1
        );
    }
}

#[test]
fn canonical_application_kill_keeps_ratchet_disposition_and_outbox_atomic() {
    use cgka_traits::engine::GroupEvent;
    for point in [
        "canonical-application-before-commit",
        "canonical-application-completed-durable",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("application.sqlite3");
        spawn_crash_child(&database, point, &[]).kill_when_ready();
        let storage = SqliteAccountStorage::open_encrypted(
            &database,
            &SqlCipherKey::new(DATABASE_KEY).unwrap(),
        )
        .unwrap();
        let group = storage.list_groups().unwrap().pop().unwrap();
        let app = storage
            .list_messages(&group, EpochId(7))
            .unwrap()
            .into_iter()
            .find(|row| matches!(row.state, MessageState::Created | MessageState::Processed))
            .unwrap();
        let committed = point.ends_with("completed-durable");
        assert_eq!(
            app.state,
            if committed {
                MessageState::Processed
            } else {
                MessageState::Created
            }
        );
        let outbox = || {
            storage
                .list_pending_application_events()
                .unwrap()
                .into_iter()
                .filter(|event| matches!(event, GroupEvent::MessageReceived { .. }))
                .collect::<Vec<_>>()
        };
        assert_eq!(outbox().len(), usize::from(committed));
        let mut restarted = build_client_with_storage(CAROL_SEED, storage.clone());
        restarted.hydrate_all_stored_groups().unwrap();
        assert_eq!(restarted.epoch(&group).unwrap(), EpochId(7));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            for _ in 0..3 {
                assert!(
                    restarted
                        .advance_convergence_inputs_until_settled(&group, 3_000_000)
                        .await
                        .unwrap()
                );
            }
        });
        assert_eq!(
            storage.get_message(&app.id).unwrap().state,
            MessageState::Processed
        );
        let events = outbox();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], GroupEvent::MessageReceived { message_id, payload, .. }
            if message_id == &app.id && MarmotAppEvent::decode(payload).unwrap().content == "crash application")
        );
        // Acknowledgement represents a committed app projection. Restarting
        // once more must not recreate its output from the processed input.
        storage
            .delete_pending_application_events(std::slice::from_ref(&app.id))
            .unwrap();
        drop(restarted);
        let mut restarted = build_client_with_storage(CAROL_SEED, storage.clone());
        restarted.hydrate_all_stored_groups().unwrap();
        runtime
            .block_on(restarted.advance_convergence_inputs_until_settled(&group, 4_000_000))
            .unwrap();
        assert!(outbox().is_empty());
    }
}

async fn run_application_child(database: &Path) {
    let (mut alice, _) = build_memory_client(b"alice-app-crash");
    let storage =
        SqliteAccountStorage::open_encrypted(database, &SqlCipherKey::new(DATABASE_KEY).unwrap())
            .unwrap();
    let mut carol = build_client_with_storage(CAROL_SEED, storage.clone());
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group, created) = alice
        .create_group(CreateGroupRequest {
            name: "application crash".into(),
            description: String::new(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("group creation")
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, CAROL_SEED))
        .await
        .unwrap();
    for index in 0..6 {
        let (commit, pending) = evolution(
            alice
                .send(SendIntent::UpdateGroupData {
                    group_id: group.clone(),
                    name: Some(format!("step-{index}")),
                    description: None,
                })
                .await
                .unwrap(),
        );
        alice.confirm_published(pending).await.unwrap();
        carol
            .buffer_openmls_convergence_message_at(&group, route(commit, &group), 1_000)
            .unwrap();
    }
    let payload = app_payload_for(&alice, b"crash application");
    let sent = alice
        .send(SendIntent::AppMessage {
            expected_epoch: None,
            group_id: group.clone(),
            payload,
        })
        .await
        .unwrap();
    let SendResult::ApplicationMessage { msg, .. } = sent else {
        panic!("application send")
    };
    carol
        .buffer_openmls_convergence_message_at(&group, route(msg, &group), 1_000)
        .unwrap();
    carol
        .converge_stored_openmls_messages_at(&group, 1_000_000)
        .unwrap();
    assert_eq!(carol.epoch(&group).unwrap(), EpochId(7));
    for _ in 0..3 {
        carol
            .advance_convergence_inputs_until_settled(&group, 2_000_000)
            .await
            .unwrap();
    }
}

const RECOVERY_COORDINATOR: &[u8] = b"recovery-crash-coordinator";
const RECOVERY_TARGET: &[u8] = b"recovery-crash-target";
const RECOVERY_SENT_POINT: &str = "recovery_send_before_parent_journal";
const RECOVERY_PUBLISHING_POINT: &str = "recovery_parent_publishing_before_fanout";
const PENDING_REF_RESTART_ENV: &str = "MDK_CGKA_PENDING_REF_RESTART";

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryCrashExpected {
    group_id: GroupId,
    grant: GroupMemberRecovery,
    group_before: serde_json::Value,
    authenticator_before: Vec<u8>,
    prepared: Option<RecoveryPreparedExpected>,
    ordinary: Option<(GroupId, TransportMessage)>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RecoveryPreparedExpected {
    descriptor: DurableGroupEvolution,
    msg: TransportMessage,
    pending: cgka_traits::engine_state::PendingStateRef,
    welcomes: Vec<TransportMessage>,
}

#[test]
fn recovery_send_crash() {
    run_recovery_parent(RECOVERY_SENT_POINT);
}

#[test]
fn recovery_publishing_crash() {
    run_recovery_parent(RECOVERY_PUBLISHING_POINT);
}

#[test]
fn recovery_staging_crash() {
    run_recovery_parent("recovery_after_staging");
}

#[test]
fn recovery_preparing_crash() {
    run_recovery_parent("recovery_after_preparing");
}

#[tokio::test]
async fn recovery_ref_eager_reopen() {
    run_pending_ref_restart("eager").await;
}

#[tokio::test]
async fn recovery_ref_deferred_reopen() {
    run_pending_ref_restart("deferred").await;
}

#[tokio::test]
async fn recovery_ref_before_staging() {
    run_pending_ref_restart("direct").await;
}

#[tokio::test]
async fn recovery_ref_frozen_reopen() {
    run_pending_ref_restart("fanout").await;
}

async fn stage_ordinary_restart_group(
    engine: &mut Engine<SqliteAccountStorage>,
) -> (GroupId, TransportMessage) {
    let (group_id, created) = engine
        .create_group(CreateGroupRequest {
            name: "ordinary publication before recovery hydration".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(matches!(created, SendResult::FoundingGroupCreated { .. }));
    let (msg, _) = evolution(
        engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    (group_id, msg)
}

async fn run_pending_ref_restart(mode: &str) {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("pending-refs.sqlite3");
    spawn_crash_child(
        &database,
        RECOVERY_SENT_POINT,
        &[(PENDING_REF_RESTART_ENV, mode)],
    )
    .kill_when_ready();
    let expected: RecoveryCrashExpected =
        serde_json::from_slice(&std::fs::read(database.with_extension("expected.json")).unwrap())
            .unwrap();
    let prepared = expected.prepared.as_ref().unwrap();
    assert_eq!(prepared.pending.as_u64(), 1);
    let storage =
        SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::new(DATABASE_KEY).unwrap())
            .unwrap();
    assert_recovery_pending(&storage, &expected);
    let frozen_before = storage.list_outbound_fanouts().unwrap();
    let mut restarted = build_recovery_client(RECOVERY_COORDINATOR, storage.clone());
    let (ordinary_group, ordinary_msg) = if mode == "direct" {
        // No seeding or hydration has run: construction itself must reserve
        // the saved recovery handle before a new group can allocate one.
        stage_ordinary_restart_group(&mut restarted).await
    } else {
        expected.ordinary.clone().unwrap()
    };
    let ordinary_authenticator = recovery_mls_group(&storage, &ordinary_group)
        .epoch_authenticator()
        .as_slice()
        .to_vec();
    restarted.hydrate_stable_groups_from_storage().unwrap();
    if mode == "eager" {
        assert_eq!(restarted.unhydrated_group_ids()[0], ordinary_group);
        restarted.hydrate_all_stored_groups().unwrap();
    } else {
        restarted.ensure_hydrated(&ordinary_group).unwrap();
        restarted.ensure_hydrated(&expected.group_id).unwrap();
    }
    assert!(restarted.quarantined_groups().is_empty());
    let work = restarted.drain_auto_publish();
    let ordinary_pending = if mode == "direct" {
        storage
            .list_group_evolutions_for_group(&ordinary_group)
            .unwrap()[0]
            .pending_ref
            .unwrap()
    } else {
        let ordinary = work.iter().find(|item| item.msg == ordinary_msg).unwrap();
        assert!(ordinary.welcomes.is_empty());
        ordinary.pending
    };
    let recovery_pending = if mode == "fanout" {
        let frozen_after = restarted.outbound_fanouts().unwrap();
        assert_eq!(frozen_after, frozen_before);
        assert_eq!(frozen_after.len(), 1);
        assert_eq!(
            frozen_after[0].pending_origin_message_id(),
            Some(&prepared.msg.id)
        );
        assert_eq!(
            frozen_after[0].pending_post_confirmation_welcomes(),
            prepared.welcomes
        );
        assert!(!work.iter().any(|item| item.msg == prepared.msg));
        frozen_after[0].pending_ref().unwrap()
    } else {
        let recovery = work.iter().find(|item| item.msg == prepared.msg).unwrap();
        assert_eq!(recovery.welcomes, prepared.welcomes);
        recovery.pending
    };
    assert_eq!(recovery_pending, prepared.pending);
    assert_ne!(ordinary_pending, recovery_pending);
    assert!(restarted.outstanding_sent_welcomes().unwrap().is_empty());
    restarted.confirm_published(ordinary_pending).await.unwrap();
    let ordinary = recovery_mls_group(&storage, &ordinary_group);
    assert!(ordinary.pending_commit().is_none());
    assert_ne!(
        ordinary.epoch_authenticator().as_slice(),
        ordinary_authenticator
    );
    assert_recovery_pending(&storage, &expected);
    assert_eq!(
        storage.group_evolution(&prepared.descriptor.id).unwrap(),
        Some(prepared.descriptor.clone()),
        "acknowledging A must not confirm or rebind B's evolution"
    );
    assert!(restarted.outstanding_sent_welcomes().unwrap().is_empty());
    for welcome in &prepared.welcomes {
        assert!(restarted.stored_sent_welcome(&welcome.id).is_err());
    }
    restarted.confirm_published(recovery_pending).await.unwrap();
    assert!(
        recovery_mls_group(&storage, &expected.group_id)
            .pending_commit()
            .is_none()
    );
    assert_eq!(
        storage
            .group_evolution(&prepared.descriptor.id)
            .unwrap()
            .unwrap()
            .phase,
        GroupEvolutionPhase::Confirmed
    );
    assert_eq!(
        restarted.outstanding_sent_welcomes().unwrap(),
        vec![(expected.group_id.clone(), prepared.welcomes[0].clone())]
    );
    let target_storage = SqliteAccountStorage::open_encrypted(
        database.with_extension("target.sqlite3"),
        &SqlCipherKey::new(DATABASE_KEY).unwrap(),
    )
    .unwrap();
    let mut target = build_recovery_client(RECOVERY_TARGET, target_storage.clone());
    target.hydrate_all_stored_groups().unwrap();
    assert!(
        target
            .join_welcome(prepared.welcomes[0].clone())
            .await
            .is_err()
    );
    let offer = target
        .pending_group_rejoins_for(Some(&expected.group_id))
        .unwrap()
        .pop()
        .unwrap();
    target
        .confirm_group_rejoin(&offer.message_id, &offer.rejoin.unwrap().local_state_token)
        .await
        .unwrap();
    assert_eq!(
        recovery_mls_group(&target_storage, &expected.group_id)
            .epoch_authenticator()
            .as_slice(),
        recovery_mls_group(&storage, &expected.group_id)
            .epoch_authenticator()
            .as_slice()
    );
}

fn build_recovery_client(
    seed: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(identity(seed))
        .account_identity_proof_signer(proof_signer(seed))
        .feature_registry(self_remove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn recovery_mls_group(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
) -> openmls::group::MlsGroup {
    openmls::group::MlsGroup::load(
        storage.mls_storage(),
        &openmls::group::GroupId::from_slice(group_id.as_slice()),
    )
    .unwrap()
    .unwrap()
}

fn assert_recovery_pending(storage: &SqliteAccountStorage, expected: &RecoveryCrashExpected) {
    let group = recovery_mls_group(storage, &expected.group_id);
    assert_eq!(group.epoch().as_u64(), expected.grant.source.epoch.0);
    assert_eq!(
        group.epoch_authenticator().as_slice(),
        expected.authenticator_before
    );
    let pending = group
        .pending_commit()
        .expect("actual MLS pending recovery commit");
    assert_eq!(
        pending
            .remove_proposals()
            .map(|proposal| proposal.remove_proposal().removed().u32())
            .collect::<Vec<_>>(),
        vec![expected.grant.source.leaf_index],
        "the crash fixture must carry an actual exact-leaf removal, not an add-only invite"
    );
    assert_eq!(pending.add_proposals().count(), 1);
}

fn run_recovery_parent(point: &str) {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("recovery.sqlite3");
    spawn_crash_child(&database, point, &[]).kill_when_ready();
    let expected: RecoveryCrashExpected =
        serde_json::from_slice(&std::fs::read(database.with_extension("expected.json")).unwrap())
            .unwrap();
    let storage =
        SqliteAccountStorage::open_encrypted(&database, &SqlCipherKey::new(DATABASE_KEY).unwrap())
            .unwrap();
    let group_id = &expected.group_id;
    let descriptors = storage.list_group_evolutions_for_group(group_id).unwrap();
    assert_eq!(descriptors.len(), 1);
    let descriptor = &descriptors[0];
    assert_eq!(descriptor.source_epoch, expected.grant.source.epoch);
    assert_eq!(
        descriptor.semantic,
        GroupEvolutionSemantic::RecoverMembers {
            request_ids: vec![expected.grant.request_id],
            source_authenticator_hash: expected.grant.source.epoch_authenticator_hash,
        }
    );
    assert!(
        storage.list_transport_fanouts().unwrap().is_empty(),
        "the crash precedes frozen fanout"
    );
    let parent_records = storage.list_group_recoveries().unwrap();
    if point == RECOVERY_PUBLISHING_POINT {
        assert_eq!(parent_records.len(), 1);
        let parent = &parent_records[0];
        assert_eq!(parent.phase, GroupRecoveryPhase::Publishing);
        assert_eq!(parent.request_id, expected.grant.request_id);
        assert_eq!(parent.commit_id, descriptor.signed_message_id);
    } else {
        assert!(
            parent_records.is_empty(),
            "engine durability must not depend on a parent journal"
        );
    }
    let staged_welcomes = storage
        .list_messages(group_id, EpochId(0))
        .unwrap()
        .into_iter()
        .filter(|record| {
            StoredMessagePayload::decode(&record.payload)
                .unwrap()
                .as_staged_invite_welcome()
                .is_some()
        })
        .collect::<Vec<_>>();
    if point == "recovery_after_preparing" {
        assert!(
            recovery_mls_group(&storage, group_id)
                .pending_commit()
                .is_none()
        );
        assert!(staged_welcomes.is_empty());
    } else {
        assert_recovery_pending(&storage, &expected);
        assert_eq!(staged_welcomes.len(), 1);
    }

    let mut restarted = build_recovery_client(RECOVERY_COORDINATOR, storage.clone());
    restarted.hydrate_all_stored_groups().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    if let Some(prepared) = &expected.prepared {
        assert_eq!(descriptor, &prepared.descriptor);
        assert_eq!(descriptor.phase, GroupEvolutionPhase::Prepared);
        assert_eq!(descriptor.pending_ref, Some(prepared.pending));
        assert_eq!(
            descriptor.signed_message_id.as_ref(),
            Some(&prepared.msg.id)
        );
        assert_recovery_pending(&storage, &expected);
        assert_eq!(
            storage.group_evolution(&descriptor.id).unwrap().as_ref(),
            Some(descriptor)
        );
        assert_eq!(storage.list_group_recoveries().unwrap(), parent_records);
        assert!(
            !restarted
                .drain_events()
                .iter()
                .any(|event| matches!(event, GroupEvent::PendingCommitRecovered { .. }))
        );
        let mut restored = restarted.drain_auto_publish();
        assert_eq!(
            restored.len(),
            1,
            "one exact commit is resumed without a parent fanout"
        );
        let work = restored.pop().unwrap();
        assert_eq!(
            work.pending, prepared.pending,
            "the original publication handle survives reopen"
        );
        assert_eq!(
            work.msg, prepared.msg,
            "never regenerate an ambiguous signed commit"
        );
        assert_eq!(
            work.welcomes, prepared.welcomes,
            "resumed publication carries the exact staged Welcome fanout artifacts"
        );
        let signed = storage.get_message(&prepared.msg.id).unwrap();
        let payload = StoredMessagePayload::decode(&signed.payload).unwrap();
        assert_eq!(payload.as_exact_transport(), Some(&prepared.msg));
        assert!(payload.as_openmls_wire().is_some());
        assert!(restarted.outstanding_sent_welcomes().unwrap().is_empty());
        assert_eq!(staged_welcomes.len(), prepared.welcomes.len());
        for (row, welcome) in staged_welcomes.iter().zip(&prepared.welcomes) {
            assert_eq!(storage.get_message(&row.id).unwrap().payload, row.payload);
            let payload = StoredMessagePayload::decode(&row.payload).unwrap();
            assert_eq!(
                payload.as_staged_invite_welcome(),
                Some((welcome, &prepared.msg.id))
            );
            assert!(
                restarted.stored_sent_welcome(&welcome.id).is_err(),
                "a staged Welcome cannot escape before confirmation"
            );
        }
        runtime.block_on(async {
            restarted.confirm_published(work.pending).await.unwrap();
            assert!(
                recovery_mls_group(&storage, group_id)
                    .pending_commit()
                    .is_none()
            );
            assert_eq!(
                storage
                    .group_evolution(&descriptor.id)
                    .unwrap()
                    .unwrap()
                    .phase,
                GroupEvolutionPhase::Confirmed
            );
            assert_eq!(
                restarted.outstanding_sent_welcomes().unwrap(),
                vec![(group_id.clone(), prepared.welcomes[0].clone())]
            );

            // This fixture raw-signs with a healthy target only to isolate
            // engine durability. Its Welcome must STILL require active-copy
            // consent; restoring publication is not authorization to replace it.
            let target_storage = SqliteAccountStorage::open_encrypted(
                database.with_extension("target.sqlite3"),
                &SqlCipherKey::new(DATABASE_KEY).unwrap(),
            )
            .unwrap();
            let mut target = build_recovery_client(RECOVERY_TARGET, target_storage.clone());
            target.hydrate_all_stored_groups().unwrap();
            let target_before = target_storage.get_group(group_id).unwrap();
            assert!(matches!(
                &target.join_welcome(prepared.welcomes[0].clone()).await,
                Err(cgka_traits::EngineError::InvalidTransition(error))
                    if error.from == "ActiveMember" && error.to == "JoinWelcome"
            ));
            assert_eq!(target_storage.get_group(group_id).unwrap(), target_before);
            let mut offers = target.pending_group_rejoins_for(Some(group_id)).unwrap();
            assert_eq!(offers.len(), 1);
            let offer = offers.pop().unwrap();
            target
                .confirm_group_rejoin(&offer.message_id, &offer.rejoin.unwrap().local_state_token)
                .await
                .unwrap();
            assert_eq!(target.epoch(group_id).unwrap(), descriptor.target_epoch);
            assert_eq!(
                recovery_mls_group(&target_storage, group_id)
                    .epoch_authenticator()
                    .as_slice(),
                recovery_mls_group(&storage, group_id)
                    .epoch_authenticator()
                    .as_slice(),
                "the resumed exact Welcome joins the confirmed MLS state"
            );
            restarted
                .mark_sent_welcome_delivered(&prepared.welcomes[0].id)
                .unwrap();
            assert!(restarted.outstanding_sent_welcomes().unwrap().is_empty());
            let SendResult::ApplicationMessage { msg, .. } = restarted
                .send(SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    expected_epoch: None,
                    payload: app_payload_for(&restarted, b"resumed recovery delivers"),
                })
                .await
                .unwrap()
            else {
                panic!("post-recovery application")
            };
            assert!(matches!(
                target.ingest(route(msg, group_id)).await.unwrap(),
                cgka_traits::IngestOutcome::Processed
            ));
        });
    } else {
        assert_eq!(descriptor.phase, GroupEvolutionPhase::Preparing);
        assert!(descriptor.pending_ref.is_none());
        if point == "recovery_after_staging" {
            let abandoned_commit = descriptor
                .signed_message_id
                .as_ref()
                .expect("staged commit is linked before the crash");
            assert_eq!(
                storage.get_message(abandoned_commit).unwrap().state,
                MessageState::Failed
            );
        } else {
            assert!(descriptor.signed_message_id.is_none());
        }
        assert!(
            storage
                .list_group_evolutions_for_group(group_id)
                .unwrap()
                .is_empty()
        );
        let restored = recovery_mls_group(&storage, group_id);
        assert!(
            restored.pending_commit().is_none(),
            "even a remove-bearing unexposed pending commit must be abandoned"
        );
        assert_eq!(
            restored.epoch_authenticator().as_slice(),
            expected.authenticator_before
        );
        assert_eq!(
            serde_json::to_value(storage.get_group(group_id).unwrap()).unwrap(),
            expected.group_before
        );
        assert!(restarted.drain_auto_publish().is_empty());
        assert!(restarted.outstanding_sent_welcomes().unwrap().is_empty());
        for row in staged_welcomes {
            let retired = storage.get_message(&row.id).unwrap();
            assert_eq!(retired.state, MessageState::Failed);
            assert!(
                StoredMessagePayload::decode(&retired.payload)
                    .unwrap()
                    .as_outbound_welcome()
                    .is_some()
            );
            assert!(restarted.stored_sent_welcome(&row.id).is_err());
        }
        // No send returned and no transport/fanout was invoked in this child.
        // A fresh request/package must complete after atomic abandonment;
        // the failed unexposed commit must not become a convergence barrier.
        runtime.block_on(async {
            let target_storage = SqliteAccountStorage::open_encrypted(
                database.with_extension("target.sqlite3"),
                &SqlCipherKey::new(DATABASE_KEY).unwrap(),
            )
            .unwrap();
            let mut target = build_recovery_client(RECOVERY_TARGET, target_storage.clone());
            target.hydrate_all_stored_groups().unwrap();
            let mut fresh = expected.grant.clone();
            fresh.request_id = [42; 32];
            fresh.key_package = target.fresh_key_package().await.unwrap();
            let fresh =
                sign_recovery_crash_grant(&target_storage, group_id, &restarted.self_id(), fresh);
            let SendResult::GroupEvolution {
                pending, welcomes, ..
            } = restarted
                .send(SendIntent::RecoverMembers {
                    group_id: group_id.clone(),
                    members: vec![fresh],
                })
                .await
                .unwrap()
            else {
                panic!("recovery retries after unexposed preparation")
            };
            let retry = storage.list_group_evolutions_for_group(group_id).unwrap();
            assert_eq!(retry.len(), 1);
            assert_ne!(
                retry[0].id, descriptor.id,
                "new grant payloads cannot reuse an old descriptor identity"
            );
            assert_recovery_pending(&storage, &expected);
            restarted.confirm_published(pending).await.unwrap();
            assert!(
                recovery_mls_group(&storage, group_id)
                    .pending_commit()
                    .is_none()
            );
            assert_eq!(restarted.epoch(group_id).unwrap(), descriptor.target_epoch);
            assert_eq!(welcomes.len(), 1);
            assert_eq!(
                restarted.outstanding_sent_welcomes().unwrap(),
                vec![(group_id.clone(), welcomes[0].clone())]
            );
        });
    }
}

fn sign_recovery_crash_grant(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    coordinator: &MemberId,
    mut grant: GroupMemberRecovery,
) -> GroupMemberRecovery {
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::signatures::Signer as _;

    let binding = storage
        .account_device_signer(&grant.member)
        .unwrap()
        .unwrap();
    let signer = SignatureKeyPair::read(
        storage.mls_storage(),
        &binding.mls_signature_public_key,
        cgka_engine::DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .unwrap();
    let preimage = group_recovery_grant_bytes(
        group_id,
        coordinator,
        &grant.request_id,
        grant.expires_at,
        &grant.source,
        &grant.key_package,
    )
    .unwrap();
    grant.device_signature = signer.sign(&preimage).unwrap();
    grant
}

async fn run_recovery_child(database: &Path) {
    let key = SqlCipherKey::new(DATABASE_KEY).unwrap();
    let pending_ref_restart = std::env::var(PENDING_REF_RESTART_ENV).ok();
    let storage = SqliteAccountStorage::open_encrypted(database, &key).unwrap();
    let target_storage =
        SqliteAccountStorage::open_encrypted(database.with_extension("target.sqlite3"), &key)
            .unwrap();
    let mut coordinator = build_recovery_client(RECOVERY_COORDINATOR, storage.clone());
    let mut target = build_recovery_client(RECOVERY_TARGET, target_storage.clone());
    let (group_id, created) = coordinator
        .create_group(CreateGroupRequest {
            name: "durable recovery crash".into(),
            description: String::new(),
            members: vec![target.fresh_key_package().await.unwrap()],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { mut welcomes } = created else {
        panic!("current-profile founding group")
    };
    let founding = welcomes.remove(0);
    target.join_welcome(founding.clone()).await.unwrap();
    coordinator
        .mark_sent_welcome_delivered(&founding.id)
        .unwrap();
    // Make the recovery handle nontrivial: an implementation that allocates
    // a fresh first handle on hydration must not accidentally pass this test.
    for _ in 0..if pending_ref_restart.is_some() { 0 } else { 2 } {
        let (_, pending) = evolution(
            coordinator
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap(),
        );
        coordinator.publish_failed(pending).await.unwrap();
    }
    let source = coordinator
        .group_recovery_source(
            &group_id,
            &target.self_id(),
            &target.own_recovery_key_hash(&group_id).unwrap(),
        )
        .unwrap();
    let key_package = target.fresh_key_package().await.unwrap();
    let request_id = [41; 32];
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let grant = sign_recovery_crash_grant(
        &target_storage,
        &group_id,
        &coordinator.self_id(),
        GroupMemberRecovery {
            member: target.self_id(),
            source,
            key_package,
            request_id,
            expires_at,
            device_signature: vec![],
        },
    );
    coordinator
        .validate_member_recovery(&group_id, &grant)
        .unwrap();
    let mut expected = RecoveryCrashExpected {
        group_id: group_id.clone(),
        grant: grant.clone(),
        group_before: serde_json::to_value(storage.get_group(&group_id).unwrap()).unwrap(),
        authenticator_before: recovery_mls_group(&storage, &group_id)
            .epoch_authenticator()
            .as_slice()
            .to_vec(),
        prepared: None,
        ordinary: None,
    };
    std::fs::write(
        database.with_extension("expected.json"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    let SendResult::GroupEvolution {
        msg,
        pending,
        welcomes,
    } = coordinator
        .send(SendIntent::RecoverMembers {
            group_id: group_id.clone(),
            members: vec![grant.clone()],
        })
        .await
        .unwrap()
    else {
        panic!("remove-and-add recovery evolution")
    };
    if pending_ref_restart.is_some() {
        assert_eq!(pending.as_u64(), 1);
    } else {
        assert!(pending.as_u64() > 1);
    }
    let mut descriptors = storage.list_group_evolutions_for_group(&group_id).unwrap();
    assert_eq!(descriptors.len(), 1);
    expected.prepared = Some(RecoveryPreparedExpected {
        descriptor: descriptors.pop().unwrap(),
        msg: msg.clone(),
        pending,
        welcomes,
    });
    if let Some(mode) = pending_ref_restart.as_deref() {
        if mode != "direct" {
            let ordinary = stage_ordinary_restart_group(&mut coordinator).await;
            // Backfill-first hydration has a deterministic first group even
            // though the remaining group set is deliberately unordered.
            storage
                .delete_transport_group_routes_for_group(&ordinary.0)
                .unwrap();
            let route = storage
                .list_transport_group_routes()
                .unwrap()
                .into_iter()
                .find(|route| route.group_id == group_id)
                .unwrap();
            storage
                .put_transport_group_route(
                    &route.transport_group_id,
                    &group_id,
                    storage.get_group(&group_id).unwrap().epoch,
                )
                .unwrap();
            expected.ordinary = Some(ordinary);
        }
        if mode == "fanout" {
            use cgka_traits::{OutboundFanout, TransportPublishRequest, TransportPublishTarget};
            let TransportEnvelope::GroupMessage { transport_group_id } = &msg.envelope else {
                panic!("recovery commit envelope")
            };
            let fanout = OutboundFanout::stage_with_post_confirmation_welcomes(
                TransportPublishRequest {
                    account_id: coordinator.self_id(),
                    message: msg.clone(),
                    target: TransportPublishTarget::Group {
                        group_id: group_id.clone(),
                        transport_group_id: transport_group_id.clone(),
                        endpoints: vec![],
                    },
                    required_acks: 1,
                },
                Some(pending),
                Some(group_id.clone()),
                0,
                Some(msg.id.clone()),
                Some(cgka_traits::FanoutPendingKind::GroupEvolution),
                expected.prepared.as_ref().unwrap().welcomes.clone(),
            )
            .unwrap();
            storage.put_outbound_fanout(&fanout).unwrap();
        }
    }
    std::fs::write(
        database.with_extension("expected.json"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    let point = std::env::var(CRASH_POINT_ENV).unwrap();
    if point == RECOVERY_PUBLISHING_POINT {
        storage
            .put_group_recovery(&GroupRecoveryRecord {
                group_id: group_id.clone(),
                request_id,
                role: GroupRecoveryRole::Coordinator,
                peer: target.self_id(),
                leaf_index: grant.source.leaf_index,
                local_state_token: None,
                expires_at,
                retry_at: 0,
                attempts: 0,
                phase: GroupRecoveryPhase::Publishing,
                total_attempts: 0,
                candidate_set_hash: None,
                native_epoch: None,
                observed_epoch: None,
                remote_rearmed: false,
                commit_started_at: Some(0),
                message: GroupRecoveryMessage {
                    group_id,
                    request_id,
                    expires_at,
                    body: GroupRecoveryBody::Grant {
                        source: grant.source,
                        key_package: grant.key_package,
                        device_signature: grant.device_signature,
                    },
                },
                outbound: None,
                commit_id: Some(msg.id),
            })
            .unwrap();
    } else {
        assert_eq!(point, RECOVERY_SENT_POINT);
    }
    // Only these two application-owned windows get a test-local pause. The
    // Preparing windows stop inside the production send path, before return.
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{READY_PREFIX}{point}").unwrap();
    stdout.flush().unwrap();
    drop(stdout);
    loop {
        std::thread::park();
    }
}
