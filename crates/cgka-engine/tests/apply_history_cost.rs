//! Regression benchmark (ignored by default): how the cost of one canonical
//! convergence apply grows with the group's stored message history (mdk#2326).
//!
//! The apply used to copy the group's whole message ledger into a full
//! pre-apply snapshot (about 570 bytes per stored message) before every
//! commit; it now uses a storage savepoint. This test grows Alice's
//! file-backed SQLCipher ledger with application messages from Bob, then times
//! Alice ingesting and converging Bob's self-update commits at each history
//! size. The "probe full snapshot" columns time a full snapshot taken outside
//! the apply, to show what the apply no longer copies.
//!
//! Run:
//! `cargo test -p cgka-engine --release --test apply_history_cost -- --ignored --nocapture`
//!
//! `APPLY_HISTORY_SIZES=0,200` overrides the history sizes for a quick run.
//! `APPLY_AGE_COMMITS=6` first applies untimed commits so the history falls
//! below the retained-anchor rewind horizon, the common case for a long-lived
//! group.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{GroupStorage, MessageStorage};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::audit::{AuditEventKind, AuditRecord, ConvergencePhase, ForensicRecorder};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

mod support;
use support::proof_signer;

const HISTORY_SIZES: &[usize] = &[0, 1_000, 5_000, 20_000, 50_000];
const COMMITS_PER_SIZE: usize = 5;
const PROBE_SNAPSHOT: &str = "apply-history-probe-full-snapshot";

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;
    use sha2::{Digest, Sha256};
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(name);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk.verifying_key().to_bytes().to_vec();
        }
        counter += 1;
    }
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use sha2::{Digest, Sha256};
    MessageId::new(Sha256::digest(bytes)[..16].to_vec())
}

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
            source: TransportSource("apply-history-bench".into()),
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
            source: TransportSource("apply-history-bench".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

/// Counts `ConvergenceRunState { phase: Applied }` audit rows: the engine emits
/// one only after `apply_openmls_canonicalization_result_with_profile_policy`
/// returned Ok for a selected tip.
struct AppliedCounter(Arc<AtomicU64>);

impl ForensicRecorder for AppliedCounter {
    fn record(&self, record: AuditRecord) {
        if matches!(
            record.kind,
            AuditEventKind::ConvergenceRunState {
                phase: ConvergencePhase::Applied,
                ..
            }
        ) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_client(
    storage: SqliteAccountStorage,
    id: &[u8],
    applied: Option<Arc<AtomicU64>>,
) -> Engine<SqliteAccountStorage> {
    let mut builder = EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler));
    if let Some(applied) = applied {
        builder = builder.recorder(Box::new(AppliedCounter(applied)));
    }
    builder.build().unwrap()
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, i: usize) -> Vec<u8> {
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000 + i as u64,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        format!("history message {i}: a typical short chat line of modest length"),
    )
    .encode()
    .expect("test app event encodes")
}

fn route(msg: TransportMessage, group_id: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..msg
    }
}

fn db_bytes(path: &Path) -> (u64, u64) {
    let main = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut wal_path = path.as_os_str().to_owned();
    wal_path.push("-wal");
    let wal = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    (main, wal)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    values[values.len() / 2]
}

/// Size and creation time of a full group snapshot, the copy the apply used to
/// take, plus the largest retained snapshot (the state-scoped anchors).
fn probe_full_snapshot(store: &SqliteAccountStorage, group_id: &GroupId) -> (u64, u64, f64) {
    let anchor_id = store
        .list_messages(group_id, EpochId(0))
        .unwrap()
        .first()
        .map(|m| m.id.clone())
        .expect("group has at least one stored message after a commit");
    let anchor_max = store
        .storage_format_bench_sizes(group_id, &anchor_id)
        .map(|s| s.largest_snapshot_bytes)
        .unwrap_or(0);
    let t = Instant::now();
    store
        .create_group_snapshot(group_id, PROBE_SNAPSHOT)
        .unwrap();
    let create_ms = t.elapsed().as_secs_f64() * 1e3;
    let full = store
        .storage_format_bench_sizes(group_id, &anchor_id)
        .unwrap()
        .largest_snapshot_bytes;
    store
        .release_group_snapshot(group_id, PROBE_SNAPSHOT)
        .unwrap();
    (full, anchor_max, create_ms)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "regression benchmark; run explicitly with --release -- --ignored --nocapture"]
async fn canonical_apply_cost_with_stored_history() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("apply history cost key").unwrap();
    let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let inspect = alice_store.clone();
    let applied = Arc::new(AtomicU64::new(0));
    let mut alice = build_client(alice_store, b"alice", Some(applied.clone()));
    // Bob is only a message source; keep his store in memory so setup time is
    // spent on Alice's file-backed SQLCipher ledger.
    let mut bob = build_client(SqliteAccountStorage::in_memory().unwrap(), b"bob", None);

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    // Release builds only construct the current protocol profile, whose
    // founding create needs no publish confirmation.
    let welcome = match result {
        SendResult::FoundingGroupCreated { mut welcomes } => welcomes.remove(0),
        other => panic!("expected FoundingGroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();
    bob.drain_events();
    alice.drain_events();

    let mut sent = 0usize;
    let mut rows_out = Vec::new();
    let sizes: Vec<usize> = std::env::var("APPLY_HISTORY_SIZES")
        .ok()
        .map(|v| v.split(',').map(|n| n.trim().parse().unwrap()).collect())
        .unwrap_or_else(|| HISTORY_SIZES.to_vec());
    for &target in &sizes {
        let fill_start = Instant::now();
        while sent < target {
            let msg = match bob
                .send(SendIntent::AppMessage {
                    group_id: group_id.clone(),
                    payload: app_payload_for(&bob, sent),
                    expected_epoch: None,
                })
                .await
                .unwrap()
            {
                SendResult::ApplicationMessage { msg, .. } => msg,
                other => panic!("expected application message, got {other:?}"),
            };
            let outcome = alice.ingest(route(msg, &group_id)).await.unwrap();
            assert!(
                matches!(outcome, IngestOutcome::Processed),
                "history message must apply, got {outcome:?}"
            );
            sent += 1;
            if sent.is_multiple_of(256) {
                alice.drain_events();
                bob.drain_events();
            }
        }
        alice.drain_events();
        bob.drain_events();
        let fill_secs = fill_start.elapsed().as_secs_f64();

        // Untimed commits that age the history below the retained-anchor
        // horizon, where horizon-bounded scans stop seeing it.
        let age_commits: usize = std::env::var("APPLY_AGE_COMMITS")
            .ok()
            .map(|v| v.parse().unwrap())
            .unwrap_or(0);
        for _ in 0..age_commits {
            let (commit, pending) = match bob
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap()
            {
                SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
                other => panic!("expected GroupEvolution, got {other:?}"),
            };
            bob.confirm_published(pending).await.unwrap();
            bob.drain_events();
            let target_epoch = bob.epoch(&group_id).unwrap();
            alice.ingest(route(commit, &group_id)).await.unwrap();
            while alice.epoch(&group_id).unwrap() != target_epoch {
                let delay = CgkaEngine::prepare_convergence_cutoff_delay_ms(&mut alice, &group_id)
                    .unwrap()
                    .unwrap_or(50);
                tokio::time::sleep(Duration::from_millis(delay.max(1))).await;
                alice.advance_convergence(&group_id).await.unwrap();
            }
            alice.drain_events();
        }

        let mut apply_ms = Vec::new();
        let mut ingest_ms = Vec::new();
        let mut wait_ms = Vec::new();
        let mut apply_pass_ms = Vec::new();
        let mut probe_ms = Vec::new();
        let mut full_bytes = Vec::new();
        let mut anchor_bytes = 0u64;
        let mut advance_calls_total = 0usize;
        for _ in 0..COMMITS_PER_SIZE {
            let (commit, pending) = match bob
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap()
            {
                SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
                other => panic!("expected GroupEvolution, got {other:?}"),
            };
            bob.confirm_published(pending).await.unwrap();
            bob.drain_events();
            let target_epoch = bob.epoch(&group_id).unwrap();
            let pre_epoch = alice.epoch(&group_id).unwrap();
            let snapshots_before = inspect.list_group_snapshots(&group_id).unwrap();
            let applied_before = applied.load(Ordering::Relaxed);

            // Time only engine work: ingest plus the host-timer advance calls,
            // never the settlement sleeps between them. The host pattern is to
            // sleep for the engine-reported cutoff delay, then advance.
            let t = Instant::now();
            alice.ingest(route(commit, &group_id)).await.unwrap();
            let ingest_dt = t.elapsed();
            let mut wait_dt = Duration::ZERO;
            let mut apply_dt = Duration::ZERO;
            let mut advance_calls = 0usize;
            while alice.epoch(&group_id).unwrap() != target_epoch {
                assert!(advance_calls < 200, "Alice never converged the commit");
                let delay = CgkaEngine::prepare_convergence_cutoff_delay_ms(&mut alice, &group_id)
                    .unwrap()
                    .unwrap_or(50);
                tokio::time::sleep(Duration::from_millis(delay.max(1))).await;
                let t = Instant::now();
                alice.advance_convergence(&group_id).await.unwrap();
                let dt = t.elapsed();
                advance_calls += 1;
                if alice.epoch(&group_id).unwrap() == target_epoch {
                    apply_dt = dt;
                } else {
                    wait_dt += dt;
                }
            }
            advance_calls_total += advance_calls;
            alice.drain_events();
            ingest_ms.push(ingest_dt.as_secs_f64() * 1e3);
            wait_ms.push(wait_dt.as_secs_f64() * 1e3);
            apply_pass_ms.push(apply_dt.as_secs_f64() * 1e3);
            apply_ms.push((ingest_dt + wait_dt + apply_dt).as_secs_f64() * 1e3);

            let applied_after = applied.load(Ordering::Relaxed);
            assert!(
                applied_after > applied_before,
                "the commit must reach the canonical convergence apply"
            );
            let snapshots_after = inspect.list_group_snapshots(&group_id).unwrap();
            assert!(
                snapshots_after
                    .iter()
                    .any(|name| !snapshots_before.contains(name)),
                "canonical apply retains a new epoch anchor ({pre_epoch:?} -> {target_epoch:?})"
            );
            assert!(
                !snapshots_after
                    .iter()
                    .any(|name| name.starts_with("openmls-apply-")),
                "a completed apply leaves no pre-apply snapshot: {snapshots_after:?}"
            );

            let (full, anchor, create_ms) = probe_full_snapshot(&inspect, &group_id);
            full_bytes.push(full as f64);
            probe_ms.push(create_ms);
            anchor_bytes = anchor;
        }

        let message_rows = inspect.list_messages(&group_id, EpochId(0)).unwrap().len();
        let (db_main, db_wal) = db_bytes(&alice_path);
        let snapshot_names = inspect.list_group_snapshots(&group_id).unwrap();
        let row = format!(
            "N={target:>6} | apply median {:>9.2} ms (min {:>8.2}, max {:>8.2}) | probe full snapshot create {:>8.2} ms | full snapshot {:>11} B | retained anchor max {:>8} B ({} snapshots kept) | message rows {:>6} | db {:>11} B + wal {:>10} B | advance calls {} | fill {:.1}s",
            median(&mut apply_ms.clone()),
            apply_ms.iter().cloned().fold(f64::INFINITY, f64::min),
            apply_ms.iter().cloned().fold(0.0, f64::max),
            median(&mut probe_ms),
            median(&mut full_bytes) as u64,
            anchor_bytes,
            snapshot_names.len(),
            message_rows,
            db_main,
            db_wal,
            advance_calls_total,
            fill_secs,
        );
        println!("{row}");
        println!(
            "  medians: ingest {:.2} ms | pre-cutoff advance passes {:.2} ms | applying advance pass {:.2} ms",
            median(&mut ingest_ms.clone()),
            median(&mut wait_ms.clone()),
            median(&mut apply_pass_ms.clone()),
        );
        println!("  raw total ms: {apply_ms:.2?}");
        println!("  raw ingest ms: {ingest_ms:.2?}");
        println!("  raw pre-cutoff ms: {wait_ms:.2?}");
        println!("  raw applying pass ms: {apply_pass_ms:.2?}");
        rows_out.push(row);
    }
    println!("\n=== summary ===");
    for row in rows_out {
        println!("{row}");
    }
    let _ = inspect.get_group(&group_id).unwrap();
}
