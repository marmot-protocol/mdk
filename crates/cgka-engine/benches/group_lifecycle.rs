//! Criterion benchmarks for group creation, Welcome joins, and canonical
//! state advances.
//!
//! These benches drive the real OpenMLS-backed engine over in-memory SQLite
//! storage with the same pass-through peeler style the Tier-2 tests use, so
//! the measured work is the engine's own CPU + storage cost: KeyPackage
//! parsing/validation, commit/welcome production, per-invitee wrapping, and
//! the join transaction. Transport crypto is deliberately excluded.
//!
//! Run:
//!
//! ```sh
//! cargo bench -p cgka-engine --bench group_lifecycle
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use cgka_engine::account_identity_proof::{
    AccountIdentityProofRequest, AccountIdentityProofSigner,
};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::MessageStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use k256::schnorr::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;

// ── Deterministic identities (mirrors tests/support) ────────────────────────

fn proof_signer(seed: &[u8]) -> Arc<dyn AccountIdentityProofSigner> {
    Arc::new(TestAccountIdentityProofSigner(signing_key(seed)))
}

fn signing_key(seed: &[u8]) -> SigningKey {
    let mut counter = 0u64;
    loop {
        let mut material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"cgka-engine-test-identity-v1");
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        material.copy_from_slice(&hasher.finalize());
        if let Ok(sk) = SigningKey::from_bytes(&material) {
            return sk;
        }
        counter += 1;
    }
}

struct TestAccountIdentityProofSigner(SigningKey);

impl AccountIdentityProofSigner for TestAccountIdentityProofSigner {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; 64], String> {
        if self.0.verifying_key().to_bytes().as_slice() != request.account_identity.as_slice() {
            return Err("request account identity does not match test key".into());
        }
        let signature = self
            .0
            .sign_prehash(&request.proof_event_id()?)
            .map_err(|e| e.to_string())?;
        Ok(signature.to_bytes())
    }
}

fn pad32(name: &[u8]) -> Vec<u8> {
    signing_key(name).verifying_key().to_bytes().to_vec()
}

// ── Pass-through peeler (no transport crypto) ───────────────────────────────

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

struct BenchPeeler;

#[async_trait]
impl TransportPeeler for BenchPeeler {
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
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        Ok(TransportMessage {
            id: hash_id(&payload.ciphertext),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("bench".into()),
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: ctx.transport_group_id().unwrap_or_default().to_vec(),
            },
        })
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        let mut id_material = payload.ciphertext.clone();
        id_material.extend_from_slice(recipient.as_slice());
        Ok(TransportMessage {
            id: hash_id(&id_material),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("bench".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

// ── Engine construction ─────────────────────────────────────────────────────

fn build_client(identity: &[u8]) -> Engine<SqliteAccountStorage> {
    build_client_with_storage(identity, SqliteAccountStorage::in_memory().unwrap())
}

fn build_client_with_storage(
    identity: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .protocol_profile(ProtocolProfile::Current)
        .peeler(Box::new(BenchPeeler))
        .build()
        .expect("build bench engine")
}

// ── retained-anchor snapshot capture ───────────────────────────────────────

fn bench_retained_anchor_snapshot(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("retained_anchor_snapshot");
    for invitees in [0_usize, 32] {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let mut alice = build_client_with_storage(
            format!("bench-alice-snapshot-{invitees}").as_bytes(),
            storage.clone(),
        );
        let key_packages = invitee_key_packages(invitees);
        let (group_id, _) = rt
            .block_on(alice.create_group(create_request(key_packages)))
            .expect("create_group succeeds");

        group.bench_function(
            BenchmarkId::from_parameter(format!("{invitees} invitees")),
            |b| {
                b.iter(|| {
                    storage
                        .create_group_state_snapshot(&group_id, "bench-retained-anchor")
                        .expect("snapshot capture succeeds")
                });
            },
        );
        group.bench_function(
            BenchmarkId::from_parameter(format!("{invitees} invitees, full rollback")),
            |b| {
                b.iter(|| {
                    storage
                        .create_group_snapshot(&group_id, "bench-full-rollback")
                        .expect("full snapshot capture succeeds")
                });
            },
        );
    }
    group.finish();
}

/// Mint one fresh KeyPackage per invitee identity. Each identity gets its own
/// throwaway engine because a KeyPackage binds the identity's MLS signer.
fn invitee_key_packages(count: usize) -> Vec<KeyPackage> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut out = Vec::with_capacity(count);
    for index in 0..count {
        let identity = format!("bench-invitee-{index}");
        let mut engine = build_client(identity.as_bytes());
        out.push(
            rt.block_on(engine.fresh_key_package())
                .expect("mint invitee key package"),
        );
    }
    out
}

fn create_request(members: Vec<KeyPackage>) -> CreateGroupRequest {
    CreateGroupRequest {
        name: "bench".into(),
        description: "bench".into(),
        members,
        required_features: vec![],
        app_components: vec![],
        initial_admins: vec![],
    }
}

/// Emit stable logical-size anchors alongside Criterion's timing output. The
/// Welcome value counts the byte-bearing normalized row columns; SQLite page
/// overhead is captured separately by the startup-scaling database footprint.
fn report_storage_format_sizes(_: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_client_with_storage(b"bench-alice-format-sizes", storage.clone());
    let (group_id, result) = rt
        .block_on(alice.create_group(create_request(invitee_key_packages(32))))
        .expect("create_group succeeds");
    let SendResult::FoundingGroupCreated { welcomes } = result else {
        panic!("expected FoundingGroupCreated");
    };
    let welcome = welcomes.first().expect("32-member group has Welcomes");
    let sizes = storage
        .storage_format_bench_sizes(&group_id, &welcome.id)
        .expect("read storage-format size anchors");
    let welcome_record_bytes = sizes.message_value_bytes;
    let founding_snapshot_bytes = sizes.largest_snapshot_bytes;
    println!(
        "MDK_BENCH storage_format_sizes members=32 welcome_record_bytes={welcome_record_bytes} \
         founding_snapshot_bytes={founding_snapshot_bytes}"
    );
}

fn confirm_group_evolution(
    rt: &tokio::runtime::Runtime,
    engine: &mut Engine<SqliteAccountStorage>,
    result: SendResult,
) -> TransportMessage {
    let SendResult::GroupEvolution { msg, pending, .. } = result else {
        panic!("expected GroupEvolution");
    };
    rt.block_on(engine.confirm_published(pending))
        .expect("confirm_published succeeds");
    msg
}

fn update_group_data(
    rt: &tokio::runtime::Runtime,
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    sequence: usize,
) -> TransportMessage {
    let result = rt
        .block_on(engine.send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some(format!("bench-{sequence}")),
            description: None,
        }))
        .expect("UpdateGroupData succeeds");
    confirm_group_evolution(rt, engine, result)
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>) -> Vec<u8> {
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        "storage-format benchmark",
    )
    .encode()
    .expect("benchmark app event encodes")
}

// ── create_group ────────────────────────────────────────────────────────────

fn bench_create_group(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("create_group");
    for invitees in [1_usize, 8, 32] {
        let key_packages = invitee_key_packages(invitees);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{invitees} invitees")),
            &key_packages,
            |b, key_packages| {
                let alice = std::sync::Arc::new(tokio::sync::Mutex::new(build_client(
                    b"bench-alice-create",
                )));
                b.to_async(&rt).iter(|| {
                    let alice = alice.clone();
                    async move {
                        let request = create_request(key_packages.clone());
                        let (group_id, result) = alice
                            .lock()
                            .await
                            .create_group(request)
                            .await
                            .expect("create_group succeeds");
                        // Sanity: founding creation returns one Welcome per invitee.
                        debug_assert!(matches!(result, SendResult::FoundingGroupCreated { .. }));
                        group_id
                    }
                });
            },
        );
    }
    group.finish();
}

// ── join_welcome ────────────────────────────────────────────────────────────

fn bench_join_welcome(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("join_welcome");
    // A join consumes its Welcome, so every iteration needs a fresh one.
    // Warm-up and measurement both draw from the same pre-generated pool;
    // keep the pool comfortably larger than the iteration count, and keep
    // the iteration count bounded so the joining engine does not accumulate
    // an unrealistic number of groups.
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    const PREGENERATED_WELCOMES: usize = 800;
    for stored_key_packages in [1_usize, 8, 32] {
        let mut bob = build_client(b"bench-bob-join");
        // Persist `stored_key_packages` last-resort bundles for bob; the join
        // path must locate the one a Welcome references among them. Keep the
        // final one as the invite target.
        let mut bob_kp = None;
        for _ in 0..stored_key_packages {
            bob_kp = Some(
                rt.block_on(bob.fresh_key_package())
                    .expect("mint bob key package"),
            );
        }
        let bob_kp = bob_kp.expect("at least one key package");
        let mut alice = build_client(b"bench-alice-join");
        // Untimed setup: alice founds a fresh group inviting bob per Welcome.
        let mut welcomes = Vec::with_capacity(PREGENERATED_WELCOMES);
        for _ in 0..PREGENERATED_WELCOMES {
            let (_group_id, result) = rt
                .block_on(alice.create_group(create_request(vec![bob_kp.clone()])))
                .expect("create_group succeeds");
            match result {
                SendResult::FoundingGroupCreated {
                    welcomes: mut wrapped,
                } => {
                    welcomes.push(wrapped.remove(0));
                }
                other => panic!("expected FoundingGroupCreated, got {other:?}"),
            }
        }
        let bob = std::sync::Arc::new(tokio::sync::Mutex::new(bob));
        group.bench_function(
            BenchmarkId::from_parameter(format!("{stored_key_packages} stored key packages")),
            |b| {
                b.to_async(&rt).iter_batched(
                    || welcomes.pop().expect("pre-generated welcome pool"),
                    |welcome| {
                        let bob = bob.clone();
                        async move {
                            bob.lock()
                                .await
                                .join_welcome(welcome)
                                .await
                                .expect("join succeeds")
                        }
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

/// Joining a larger group: every join ends with a buffered-message replay
/// scan over the group's stored messages.
fn bench_join_welcome_large_group(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("join_welcome_large_group");
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    const PREGENERATED_WELCOMES: usize = 400;
    const OTHER_MEMBERS: usize = 31;
    let mut bob = build_client(b"bench-bob-join-large");
    let bob_kp = rt
        .block_on(bob.fresh_key_package())
        .expect("mint bob key package");
    let other_key_packages = invitee_key_packages(OTHER_MEMBERS);
    let mut alice = build_client(b"bench-alice-join-large");
    let mut welcomes = Vec::with_capacity(PREGENERATED_WELCOMES);
    for _ in 0..PREGENERATED_WELCOMES {
        let mut members = other_key_packages.clone();
        members.push(bob_kp.clone());
        let (_group_id, result) = rt
            .block_on(alice.create_group(create_request(members)))
            .expect("create_group succeeds");
        match result {
            SendResult::FoundingGroupCreated {
                welcomes: mut wrapped,
            } => {
                // bob's KeyPackage was last, so his Welcome is last.
                welcomes.push(wrapped.remove(wrapped.len() - 1));
            }
            other => panic!("expected FoundingGroupCreated, got {other:?}"),
        }
    }
    let bob = std::sync::Arc::new(tokio::sync::Mutex::new(bob));
    group.bench_function("32 members", |b| {
        b.to_async(&rt).iter_batched(
            || welcomes.pop().expect("pre-generated welcome pool"),
            |welcome| {
                let bob = bob.clone();
                async move {
                    bob.lock()
                        .await
                        .join_welcome(welcome)
                        .await
                        .expect("join succeeds")
                }
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn prepare_app_send(
    rt: &tokio::runtime::Runtime,
) -> (Engine<SqliteAccountStorage>, GroupId, Vec<u8>) {
    let mut alice = build_client(b"bench-alice-app-send");
    let (group_id, create) = rt
        .block_on(alice.create_group(create_request(vec![])))
        .expect("create_group succeeds");
    assert!(matches!(create, SendResult::FoundingGroupCreated { .. }));
    let payload = app_payload_for(&alice);
    (alice, group_id, payload)
}

/// Pure application-message encryption and normalized-row persistence.
fn bench_app_message_send(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("send_app_message");
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    group.bench_function("current profile", |b| {
        b.iter_batched(
            || prepare_app_send(&rt),
            |(mut alice, group_id, payload)| {
                let result = rt
                    .block_on(alice.send(SendIntent::AppMessage { group_id, payload }))
                    .expect("app send succeeds");
                assert!(matches!(result, SendResult::ApplicationMessage { .. }));
            },
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn prepare_app_ingest(
    rt: &tokio::runtime::Runtime,
) -> (Engine<SqliteAccountStorage>, TransportMessage) {
    let mut alice = build_client(b"bench-alice-app-ingest");
    let mut bob = build_client(b"bench-bob-app-ingest");
    let bob_kp = rt
        .block_on(bob.fresh_key_package())
        .expect("mint bob key package");
    let (group_id, create) = rt
        .block_on(alice.create_group(create_request(vec![bob_kp])))
        .expect("create_group succeeds");
    let SendResult::FoundingGroupCreated { mut welcomes } = create else {
        panic!("expected FoundingGroupCreated");
    };
    rt.block_on(bob.join_welcome(welcomes.remove(0)))
        .expect("bob joins");
    let result = rt
        .block_on(alice.send(SendIntent::AppMessage {
            group_id,
            payload: app_payload_for(&alice),
        }))
        .expect("app send succeeds");
    let SendResult::ApplicationMessage { msg, .. } = result else {
        panic!("expected ApplicationMessage");
    };
    (bob, msg)
}

/// Peeling, MLS decryption, validation, and normalized-row persistence for an
/// inbound application message.
fn bench_app_message_ingest(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("ingest_app_message");
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    group.bench_function("current profile", |b| {
        b.iter_batched(
            || prepare_app_ingest(&rt),
            |(mut bob, message)| rt.block_on(bob.ingest(message)).expect("ingest succeeds"),
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

fn prepare_rejoin_with_history(
    rt: &tokio::runtime::Runtime,
    retained_commits: usize,
) -> (Engine<SqliteAccountStorage>, TransportMessage) {
    let mut alice = build_client(b"bench-alice-rejoin");
    let bob_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut bob = build_client_with_storage(b"bench-bob-rejoin", bob_storage.clone());
    let bob_id = bob.self_id().clone();
    let bob_kp = rt
        .block_on(bob.fresh_key_package())
        .expect("mint initial bob key package");
    let (group_id, create) = rt
        .block_on(alice.create_group(create_request(vec![bob_kp])))
        .expect("create_group succeeds");
    let SendResult::FoundingGroupCreated { mut welcomes } = create else {
        panic!("expected FoundingGroupCreated");
    };
    rt.block_on(bob.join_welcome(welcomes.remove(0)))
        .expect("initial join succeeds");

    // Build real canonical history on both peers. These commits become the
    // rows and retained checkpoints that the rejoin path must reconcile.
    for sequence in 0..retained_commits {
        let commit = update_group_data(rt, &mut alice, &group_id, sequence);
        rt.block_on(bob.ingest(commit))
            .expect("bob ingests retained commit");
        bob.converge_stored_openmls_messages_at(&group_id, 1_000_000)
            .expect("retained commit converges");
    }
    assert!(
        bob_storage
            .list_messages(&group_id, EpochId(0))
            .expect("list retained rejoin history")
            .len()
            >= retained_commits,
        "fixture must retain the requested canonical history"
    );

    let removal = rt
        .block_on(alice.send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_id],
        }))
        .expect("remove succeeds");
    let removal_commit = confirm_group_evolution(rt, &mut alice, removal);
    rt.block_on(bob.ingest(removal_commit))
        .expect("bob ingests removal");
    bob.converge_stored_openmls_messages_at(&group_id, 1_000_000)
        .expect("removal converges");

    let rejoin_kp = rt
        .block_on(bob.fresh_key_package())
        .expect("mint rejoin key package");
    let rejoin = rt
        .block_on(alice.send(SendIntent::Invite {
            group_id,
            key_packages: vec![rejoin_kp],
        }))
        .expect("re-invite succeeds");
    let SendResult::GroupEvolution {
        mut welcomes,
        pending,
        ..
    } = rejoin
    else {
        panic!("expected GroupEvolution");
    };
    rt.block_on(alice.confirm_published(pending))
        .expect("confirm re-invite succeeds");
    (bob, welcomes.remove(0))
}

/// Same-group rejoin after removal, scaled by the canonical commit history
/// retained by the joining device. Fixture construction is excluded from the
/// timed interval; only the second `join_welcome` call is measured.
fn bench_rejoin_welcome_with_history(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("rejoin_welcome_with_history");
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    for retained_commits in [0_usize, 8, 32] {
        group.bench_function(
            BenchmarkId::from_parameter(format!("{retained_commits} retained commits")),
            |b| {
                b.iter_batched(
                    || prepare_rejoin_with_history(&rt, retained_commits),
                    |(mut bob, welcome)| {
                        rt.block_on(bob.join_welcome(welcome))
                            .expect("rejoin succeeds")
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

fn prepare_canonical_advance(
    rt: &tokio::runtime::Runtime,
    retained_commits: usize,
) -> (Engine<SqliteAccountStorage>, GroupId, usize) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_client_with_storage(b"bench-alice-canonical-advance", storage.clone());
    let (group_id, create) = rt
        .block_on(alice.create_group(create_request(vec![])))
        .expect("create_group succeeds");
    assert!(matches!(create, SendResult::FoundingGroupCreated { .. }));
    for sequence in 0..retained_commits {
        update_group_data(rt, &mut alice, &group_id, sequence);
    }
    assert!(
        storage
            .list_messages(&group_id, EpochId(0))
            .expect("list retained canonical history")
            .len()
            >= retained_commits,
        "fixture must retain the requested canonical history"
    );
    (alice, group_id, retained_commits)
}

/// One canonical commit preparation + confirmation at fixed retained-history
/// depths. The setup commits are real state advances but are excluded from the
/// timed interval.
fn bench_canonical_advance_with_history(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("bench runtime");
    let mut group = c.benchmark_group("canonical_advance_with_history");
    group.warm_up_time(std::time::Duration::from_millis(200));
    group.measurement_time(std::time::Duration::from_millis(300));
    group.sample_size(10);
    for retained_commits in [0_usize, 8, 32] {
        group.bench_function(
            BenchmarkId::from_parameter(format!("{retained_commits} retained commits")),
            |b| {
                b.iter_batched(
                    || prepare_canonical_advance(&rt, retained_commits),
                    |(mut alice, group_id, sequence)| {
                        update_group_data(&rt, &mut alice, &group_id, sequence)
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    report_storage_format_sizes,
    bench_create_group,
    bench_retained_anchor_snapshot,
    bench_join_welcome,
    bench_join_welcome_large_group,
    bench_app_message_send,
    bench_app_message_ingest,
    bench_rejoin_welcome_with_history,
    bench_canonical_advance_with_history
);
criterion_main!(benches);
