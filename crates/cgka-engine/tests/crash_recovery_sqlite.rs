#![cfg(all(feature = "test-crash-hooks", debug_assertions))]

//! Process-kill coverage for convergence rewrite durability (#1025).
//!
//! The ignored child test drives the real retained-anchor late-commit path over
//! encrypted file-backed SQLite. Parent tests stop it at fixed debug-only crash
//! points, then reopen and hydrate the database without running child
//! destructors.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use async_trait::async_trait;
use cgka_engine::canonicalization::{CanonicalizationPolicy, CanonicalizationState};
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::openmls_projection::{
    apply_openmls_canonicalization_result, canonicalize_stored_openmls_messages,
};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    GroupStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

mod support;
use support::proof_signer;

const CHILD_ENV: &str = "MDK_CGKA_CRASH_CHILD";
const DATABASE_ENV: &str = "MDK_CGKA_CRASH_DATABASE";
const CRASH_POINT_ENV: &str = "MDK_CGKA_TEST_CRASH_POINT";
const DATABASE_KEY: &str = "cgka convergence crash recovery key";
const READY_PREFIX: &str = "MDK_CGKA_TEST_CRASH_READY:";
const H5_POINT: &str = "historical-apply-before-commit";
const H6_POINT: &str = "retained-anchor-after-rewind";
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
                bytes: msg.payload.clone(),
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

#[test]
fn h5_kill_before_historical_apply_commit_preserves_live_inputs() {
    run_parent_case(H5_POINT, EpochId(2), "openmls-apply-");
}

#[test]
fn h6_kill_after_retained_anchor_rewind_recovers_live_snapshot() {
    run_parent_case(H6_POINT, EpochId(1), "openmls-retained-probe-");
}

#[tokio::test]
#[ignore = "spawned by the parent crash-recovery tests"]
async fn crash_child_runs_late_commit_convergence() {
    if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
        return;
    }
    let path = PathBuf::from(std::env::var_os(DATABASE_ENV).expect("child database path"));
    run_child_case(&path).await;
    panic!("selected crash point was not reached");
}

fn run_parent_case(point: &str, stranded_epoch: EpochId, snapshot_prefix: &str) {
    let dir = tempfile::tempdir().expect("parent temp directory");
    let database = dir.path().join("carol.sqlite3");
    let mut child = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--ignored",
            "--exact",
            "crash_child_runs_late_commit_convergence",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .env(DATABASE_ENV, &database)
        .env(CRASH_POINT_ENV, point)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn crash child");

    let stdout = child.stdout.take().expect("child stdout");
    let (line_tx, line_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line).is_err() {
                return;
            }
        }
    });

    let expected_ready = format!("{READY_PREFIX}{point}");
    let mut child_output = Vec::new();
    let ready = loop {
        match line_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(line)) => {
                let is_ready = line == expected_ready;
                child_output.push(line);
                if is_ready {
                    break true;
                }
            }
            Ok(Err(err)) => {
                child_output.push(format!("stdout error: {err}"));
                break false;
            }
            Err(_) => break false,
        }
    };
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        drop(line_rx);
        let _ = reader.join();
        panic!(
            "child did not reach {point}; stdout:\n{}",
            child_output.join("\n")
        );
    }

    child.kill().expect("kill child at crash point");
    let status = child.wait().expect("wait for killed child");
    assert!(!status.success(), "killed child must not exit successfully");
    drop(line_rx);
    reader.join().expect("stdout reader exits");

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("child stderr")
        .read_to_string(&mut stderr)
        .expect("read child stderr");
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
    if point == H6_POINT {
        assert!(
            !stranded_group
                .members
                .iter()
                .any(|member| member.id == MemberId::new(identity(b"david-crash"))),
            "retained-anchor crash must expose the historical membership before hydration"
        );
    }
    assert!(
        storage
            .list_group_snapshots(&group_id)
            .expect("list stranded snapshots")
            .iter()
            .any(|name| name.starts_with(snapshot_prefix)),
        "expected stranded snapshot prefix {snapshot_prefix}"
    );
    if point == H5_POINT {
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
        .hydrate_stable_groups_from_storage()
        .expect("hydrate killed database");

    assert_eq!(
        reopened.epoch(&group_id).expect("recovered epoch"),
        EpochId(2)
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
        "late challenger must win the deterministic tiebreak"
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
            })
            .await
            .expect("alice invite"),
    );
    carol
        .buffer_openmls_convergence_message(&group_id, route(alice_commit, &group_id), 1_000)
        .expect("buffer incumbent commit");
    carol
        .converge_stored_openmls_messages(&group_id, 1_000_000)
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
        })
        .await
        .expect("bob invite"),
    );
    carol
        .buffer_openmls_convergence_message(&group_id, route(bob_commit, &group_id), 2_000)
        .expect("buffer late winning commit");
    carol_storage
        .put_queued_outbound_intent(&QueuedOutboundIntent {
            id: MessageId::new(QUEUED_INTENT_ID.to_vec()),
            group_id: group_id.clone(),
            intent: SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, b"queued across crash"),
            },
            created_at_ms: 2_100,
        })
        .expect("persist queued work");

    let _ = alice_seed;
    if std::env::var(CRASH_POINT_ENV).as_deref() == Ok(H5_POINT) {
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
    } else {
        carol
            .converge_stored_openmls_messages(&group_id, 3_000_000)
            .expect("late branch convergence reaches selected crash point");
    }
}

fn build_memory_client(seed: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().expect("in-memory storage");
    let engine = build_client_with_storage(seed, storage.clone());
    (engine, storage)
}

fn build_client_with_storage(
    seed: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(identity(seed))
        .account_identity_proof_signer(proof_signer(seed))
        .feature_registry(self_remove_registry())
        .peeler(Box::new(MockPeeler))
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
        if let Ok(key) = SigningKey::from_bytes(&material) {
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
