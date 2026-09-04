//! Deferred-peel retry lifecycle (mdk#339): event-driven retries via
//! the peel-context fingerprint gate, the per-row retry budget, the per-group
//! flood cap on retained `PeelDeferred` rows, and post-peel pre-membership
//! classification against `Group::join_epoch`.

use async_trait::async_trait;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP;
use cgka_engine::openmls_projection::project_mls_message;
use cgka_engine::{Engine, EngineBuilder, ManualConvergenceClock};
use cgka_traits::app_components::{
    AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
    encode_nostr_routing_v1,
};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{
    InboundResourceLimit, IngestOutcome, PeeledContent, PeeledMessage, StaleReason,
};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    DeferredPeelGeneration, DeferredPeelGenerationStorage, MessageStorage, OutboundIntentStorage,
    StorageError,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::epoch_sealed_peeler::EpochSealedPeeler;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    use k256::schnorr::SigningKey;

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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

fn content_id(msg: &TransportMessage) -> MessageId {
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
}

fn epoch_gated_group_message(
    msg: &TransportMessage,
    ctx: &GroupContextSnapshot,
) -> Result<PeeledMessage, PeelerError> {
    if let Ok(projection) = project_mls_message(&msg.payload)
        && let Some(source_epoch) = projection.source_epoch
        && ctx.epoch().0 < source_epoch
    {
        return Err(PeelerError::DecryptFailed);
    }
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

fn passthrough_welcome(msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
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

fn wrapped_group_message(payload: &EncryptedPayload) -> Result<TransportMessage, PeelerError> {
    Ok(TransportMessage {
        id: hash_id(&payload.ciphertext),
        payload: payload.ciphertext.clone(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: vec![],
        },
    })
}

fn wrapped_welcome(
    payload: &EncryptedPayload,
    recipient: &MemberId,
) -> Result<TransportMessage, PeelerError> {
    Ok(TransportMessage {
        id: hash_id(&payload.ciphertext),
        payload: payload.ciphertext.clone(),
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("mock".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: recipient.clone(),
        },
    })
}

/// Pass-through peeler that fails `DecryptFailed` for messages wrapped at an
/// epoch beyond the receiver's context — the same gate as the
/// `EpochGatePeeler` in `distributed_convergence.rs` — while counting every
/// peel attempt per raw transport message id, so tests can assert exactly
/// when the engine re-peels a deferred row.
#[derive(Clone)]
struct CountingEpochGatePeeler {
    peel_attempts: Arc<Mutex<HashMap<MessageId, u64>>>,
}

impl CountingEpochGatePeeler {
    fn new() -> Self {
        Self {
            peel_attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn attempts_for(&self, id: &MessageId) -> u64 {
        self.peel_attempts
            .lock()
            .unwrap()
            .get(id)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl TransportPeeler for CountingEpochGatePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        *self
            .peel_attempts
            .lock()
            .unwrap()
            .entry(msg.id.clone())
            .or_insert(0) += 1;
        epoch_gated_group_message(msg, ctx)
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        passthrough_welcome(msg)
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        wrapped_group_message(payload)
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        wrapped_welcome(payload, recipient)
    }
}

/// Epoch-gated peeler whose foreground retry attempt can be held indefinitely.
/// Initial ingest remains fast; tests arm the gate only after the deferred
/// backlog is durable.
#[derive(Clone)]
struct NotifyEpochGatePeeler {
    gated: Arc<AtomicBool>,
    gated_attempts: Arc<AtomicU64>,
    block_on_attempt: Arc<AtomicU64>,
}

/// Epoch-faithful peeler that can suspend before any supplied context is
/// attempted. Used to cancel a sweep after candidate enumeration but before a
/// deferred row receives a definitive result.
#[derive(Clone)]
struct CancellableEpochSealedPeeler {
    blocked: Arc<AtomicBool>,
    blocked_attempts: Arc<AtomicU64>,
}

impl CancellableEpochSealedPeeler {
    fn new() -> Self {
        Self {
            blocked: Arc::new(AtomicBool::new(false)),
            blocked_attempts: Arc::new(AtomicU64::new(0)),
        }
    }

    fn block(&self) {
        self.blocked_attempts.store(0, Ordering::SeqCst);
        self.blocked.store(true, Ordering::SeqCst);
    }

    fn unblock(&self) {
        self.blocked.store(false, Ordering::SeqCst);
    }

    fn blocked_attempts(&self) -> u64 {
        self.blocked_attempts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TransportPeeler for CancellableEpochSealedPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if self.blocked.load(Ordering::SeqCst) {
            self.blocked_attempts.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        EpochSealedPeeler.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        EpochSealedPeeler.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        EpochSealedPeeler.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        EpochSealedPeeler.wrap_welcome(payload, recipient).await
    }
}

impl NotifyEpochGatePeeler {
    fn new() -> Self {
        Self {
            gated: Arc::new(AtomicBool::new(false)),
            gated_attempts: Arc::new(AtomicU64::new(0)),
            block_on_attempt: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }

    fn block_on_attempt(&self, attempt: u64) {
        self.gated_attempts.store(0, Ordering::SeqCst);
        self.block_on_attempt.store(attempt, Ordering::SeqCst);
        self.gated.store(true, Ordering::SeqCst);
    }

    fn gated_attempts(&self) -> u64 {
        self.gated_attempts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TransportPeeler for NotifyEpochGatePeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if self.gated.load(Ordering::SeqCst) {
            let attempt = self.gated_attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt >= self.block_on_attempt.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
        }
        epoch_gated_group_message(msg, ctx)
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        passthrough_welcome(msg)
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        wrapped_group_message(payload)
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        wrapped_welcome(payload, recipient)
    }
}

fn build_client(name: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(name))
        .account_identity_proof_signer(proof_signer(name))
        .peeler(Box::new(CountingEpochGatePeeler::new()))
        .build()
        .unwrap();
    (engine, storage)
}

fn build_counting_client(
    name: &[u8],
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    CountingEpochGatePeeler,
) {
    let peeler = CountingEpochGatePeeler::new();
    build_gated_client(name, peeler)
}

fn build_gated_client<P>(
    name: &[u8],
    peeler: P,
) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage, P)
where
    P: TransportPeeler + Clone + 'static,
{
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(name))
        .account_identity_proof_signer(proof_signer(name))
        .peeler(Box::new(peeler.clone()))
        .build()
        .unwrap();
    engine
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    (engine, storage, peeler)
}

fn build_counting_client_with_storage_and_clock(
    name: &[u8],
    storage: SqliteAccountStorage,
    clock: ManualConvergenceClock,
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    CountingEpochGatePeeler,
) {
    let peeler = CountingEpochGatePeeler::new();
    let mut engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(name))
        .account_identity_proof_signer(proof_signer(name))
        .peeler(Box::new(peeler.clone()))
        .convergence_clock(Arc::new(clock))
        .build()
        .unwrap();
    engine
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    (engine, storage, peeler)
}

fn build_notify_client(
    name: &[u8],
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    NotifyEpochGatePeeler,
) {
    let peeler = NotifyEpochGatePeeler::new();
    build_gated_client(name, peeler)
}

fn build_epoch_sealed_client_with_storage(
    name: &[u8],
    storage: SqliteAccountStorage,
) -> Engine<SqliteAccountStorage> {
    build_epoch_sealed_client_with_storage_and_peeler(name, storage, EpochSealedPeeler)
}

fn build_epoch_sealed_client_with_storage_and_peeler<P>(
    name: &[u8],
    storage: SqliteAccountStorage,
    peeler: P,
) -> Engine<SqliteAccountStorage>
where
    P: TransportPeeler + 'static,
{
    let mut supported_components: Vec<_> = default_group_components().into_iter().collect();
    supported_components.push(NOSTR_ROUTING_COMPONENT_ID);
    let mut engine = EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(name))
        .account_identity_proof_signer(proof_signer(name))
        .supported_app_components(supported_components)
        .peeler(Box::new(peeler))
        .build()
        .unwrap();
    engine
        .set_convergence_policy(CanonicalizationPolicy {
            settlement_quiescence_ms: 0,
            ..CanonicalizationPolicy::default()
        })
        .expect("convergence policy accepted");
    engine
}

fn build_epoch_sealed_client(name: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = build_epoch_sealed_client_with_storage(name, storage.clone());
    (engine, storage)
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

fn welcome_for(welcomes: &[TransportMessage], name: &[u8]) -> TransportMessage {
    let recipient = MemberId::new(pad32(name));
    welcomes
        .iter()
        .find(|welcome| {
            matches!(&welcome.envelope, TransportEnvelope::Welcome { recipient: r } if *r == recipient)
        })
        .cloned()
        .expect("welcome for recipient")
}

fn evolution(result: SendResult) -> (TransportMessage, cgka_traits::engine_state::PendingStateRef) {
    match result {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected group evolution, got {other:?}"),
    }
}

fn app_payload_for(engine: &Engine<SqliteAccountStorage>, content: &str) -> Vec<u8> {
    MarmotAppEvent::new(
        hex::encode(engine.self_id().as_slice()),
        1_700_000_000,
        MARMOT_APP_EVENT_KIND_CHAT,
        vec![],
        content,
    )
    .encode()
    .expect("test app event encodes")
}

async fn send_app(
    engine: &mut Engine<SqliteAccountStorage>,
    group_id: &GroupId,
    content: &str,
) -> TransportMessage {
    let result = engine
        .send(SendIntent::AppMessage {
            group_id: group_id.clone(),
            payload: app_payload_for(engine, content),
        })
        .await
        .expect("send app");
    match result {
        SendResult::ApplicationMessage { msg, .. } => route(msg, group_id),
        other => panic!("expected app message, got {other:?}"),
    }
}

/// Common scaffold: alice owns the group; carol (counting epoch-gate peeler)
/// joins at epoch 1. Alice then advances to epoch 2 (invite david) and 3
/// (invite eve) without delivering those commits. Returns the two withheld
/// commits so tests choose what carol sees.
async fn carol_behind_two_epochs() -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    CountingEpochGatePeeler,
    GroupId,
    TransportMessage,
    TransportMessage,
) {
    carol_behind_two_epochs_with(build_counting_client(b"carol")).await
}

async fn carol_behind_two_epochs_with<P>(
    carol: (Engine<SqliteAccountStorage>, SqliteAccountStorage, P),
) -> (
    Engine<SqliteAccountStorage>,
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    P,
    GroupId,
    TransportMessage,
    TransportMessage,
) {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage, carol_peeler) = carol;
    let (mut david, _david_storage) = build_client(b"david");
    let (mut eve, _eve_storage) = build_client(b"eve");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "deferred-peel-lifecycle".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    let david_kp = david.fresh_key_package().await.unwrap();
    let invite_david = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (commit_to_epoch2, pending) = evolution(invite_david);
    let commit_to_epoch2 = route(commit_to_epoch2, &group_id);
    alice.confirm_published(pending).await.unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let invite_eve = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (commit_to_epoch3, pending) = evolution(invite_eve);
    let commit_to_epoch3 = route(commit_to_epoch3, &group_id);
    alice.confirm_published(pending).await.unwrap();

    (
        alice,
        carol,
        carol_storage,
        carol_peeler,
        group_id,
        commit_to_epoch2,
        commit_to_epoch3,
    )
}

async fn add_group_two_epochs_ahead(
    alice: &mut Engine<SqliteAccountStorage>,
    carol: &mut Engine<SqliteAccountStorage>,
) -> GroupId {
    let (mut david, _david_storage) = build_client(b"david-second-group");
    let (mut eve, _eve_storage) = build_client(b"eve-second-group");
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "second-deferred-peel-group".into(),
            description: String::new(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    carol.drain_events();

    for key_package in [
        david.fresh_key_package().await.unwrap(),
        eve.fresh_key_package().await.unwrap(),
    ] {
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![key_package],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let (_withheld_commit, pending) = evolution(invite);
        alice.confirm_published(pending).await.unwrap();
    }

    group_id
}

/// Build a deterministic two-branch graph and retain `backlog` wrappers of one
/// rival-branch application message. Peeling any wrapper adds no commit digest,
/// so every background slice observes the exact same context fingerprint.
async fn contested_rival_app_backlog(
    backlog: usize,
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
    Engine<SqliteAccountStorage>,
) {
    contested_rival_app_backlog_with_peeler(backlog, EpochSealedPeeler).await
}

async fn contested_rival_app_backlog_with_peeler<P>(
    backlog: usize,
    incumbent_peeler: P,
) -> (
    Engine<SqliteAccountStorage>,
    SqliteAccountStorage,
    GroupId,
    Engine<SqliteAccountStorage>,
)
where
    P: TransportPeeler + 'static,
{
    let incumbent_storage = SqliteAccountStorage::in_memory().unwrap();
    let mut incumbent = build_epoch_sealed_client_with_storage_and_peeler(
        b"candidate-cache-incumbent",
        incumbent_storage.clone(),
        incumbent_peeler,
    );
    let (mut rival, _rival_storage) = build_epoch_sealed_client(b"candidate-cache-rival");
    let (mut david, _david_storage) = build_epoch_sealed_client(b"candidate-cache-david");
    let (mut eve, _eve_storage) = build_epoch_sealed_client(b"candidate-cache-eve");

    let rival_kp = rival.fresh_key_package().await.unwrap();
    let routing = NostrRoutingV1::new([0x43; 32], vec!["wss://relay.example".into()]).unwrap();
    let (group_id, create) = incumbent
        .create_group(CreateGroupRequest {
            name: "candidate-cache".into(),
            description: String::new(),
            members: vec![rival_kp],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(&routing).unwrap(),
            }],
            initial_admins: vec![rival.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    incumbent.confirm_published(pending).await.unwrap();
    rival
        .join_welcome(welcome_for(&welcomes, b"candidate-cache-rival"))
        .await
        .unwrap();

    let david_kp = david.fresh_key_package().await.unwrap();
    let (incumbent_commit, incumbent_pending, incumbent_welcomes) = match incumbent
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution {
            msg,
            pending,
            welcomes,
            ..
        } => (msg, pending, welcomes),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    incumbent
        .confirm_published(incumbent_pending)
        .await
        .unwrap();
    david
        .join_welcome(welcome_for(&incumbent_welcomes, b"candidate-cache-david"))
        .await
        .unwrap();

    let eve_kp = eve.fresh_key_package().await.unwrap();
    let (rival_root, rival_pending) = evolution(
        rival
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![eve_kp],
                initial_admins: vec![],
            })
            .await
            .unwrap(),
    );
    rival.confirm_published(rival_pending).await.unwrap();

    // The own commit is already durably stamped by confirm. Retain its wire
    // value too so the setup is explicit about both sides of the contested
    // graph and cannot be optimized into an unused local evolution.
    let _ = incumbent_commit;
    let TransportEnvelope::GroupMessage {
        transport_group_id: rival_route,
    } = &rival_root.envelope
    else {
        panic!("rival root must be a routed group message");
    };
    assert_ne!(
        rival_route.as_slice(),
        group_id.as_slice(),
        "transport routing id must stay distinct from the MLS group id"
    );
    assert!(matches!(
        incumbent.ingest(rival_root).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    let rival_app = send_app(&mut rival, &group_id, "rival branch witness").await;
    for index in 0..backlog {
        let wrapper = TransportMessage {
            id: MessageId::new(format!("candidate-cache-wrapper-{index}").into_bytes()),
            ..rival_app.clone()
        };
        assert!(matches!(
            incumbent.ingest(wrapper).await.unwrap(),
            IngestOutcome::TransportDeferred { .. }
        ));
    }
    assert_eq!(
        incumbent_storage
            .list_messages_in_states(&group_id, &[MessageState::PeelDeferred], EpochId(0),)
            .unwrap()
            .len(),
        backlog
    );

    (incumbent, incumbent_storage, group_id, david)
}

#[tokio::test]
async fn unchanged_192_row_contested_backlog_enumerates_candidates_once() {
    let (mut incumbent, storage, group_id, _same_branch_peer) =
        contested_rival_app_backlog(192).await;

    let mut handled = 0usize;
    for _ in 0..3 {
        let progressed = incumbent.retry_deferred_peels(&group_id).await.unwrap();
        assert_eq!(progressed, 64, "background work must stay slice-bounded");
        handled += progressed;
    }

    assert_eq!(handled, 192);
    assert!(
        storage
            .list_messages_in_states(&group_id, &[MessageState::PeelDeferred], EpochId(0),)
            .unwrap()
            .is_empty(),
        "every raw wrapper must leave the deferred lifecycle"
    );
    let metrics = incumbent.engine_metrics();
    assert_eq!(metrics.deferred_peel_candidate_enumerations, 1);
    assert_eq!(metrics.deferred_peel_candidate_cache_misses, 1);
    assert_eq!(metrics.deferred_peel_candidate_cache_hits, 2);
    assert_eq!(metrics.deferred_peel_candidate_cache_invalidations, 1);
    assert_eq!(metrics.deferred_peel_candidate_contexts, 2);
    assert_eq!(
        metrics.deferred_peel_candidate_context_depth.sample_count(),
        2
    );
    assert_eq!(
        metrics
            .deferred_peel_candidate_context_depth
            .approx_percentile(1.0),
        Some(1)
    );
    assert_eq!(
        metrics.deferred_peel_candidate_replay_probes, 4,
        "candidate replay work must be independent of the number of slices"
    );
    assert_eq!(
        metrics
            .deferred_peel_candidate_enumeration_ms
            .sample_count(),
        1
    );
    assert_eq!(
        metrics.deferred_peel_sweeps, 4,
        "three work slices plus the generation-completion empty sweep"
    );
}

#[tokio::test]
async fn group_policy_change_invalidates_cached_candidate_enumeration() {
    let (mut incumbent, _storage, group_id, _same_branch_peer) =
        contested_rival_app_backlog(192).await;

    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    let before_change = incumbent.engine_metrics();
    assert_eq!(before_change.deferred_peel_candidate_enumerations, 1);
    assert_eq!(before_change.deferred_peel_candidate_cache_misses, 1);

    let mut policy = CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    };
    policy.convergence.max_rewind_commits = 1;
    incumbent
        .set_group_convergence_policy(&group_id, policy)
        .expect("test policy override accepted");

    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    let after_change = incumbent.engine_metrics();
    assert_eq!(
        after_change.deferred_peel_candidate_enumerations, 2,
        "a changed replay horizon must not reuse the prior enumeration"
    );
    assert_eq!(after_change.deferred_peel_candidate_cache_misses, 2);
    assert_eq!(after_change.deferred_peel_candidate_cache_hits, 0);
    assert_eq!(after_change.deferred_peel_candidate_cache_invalidations, 1);
}

#[tokio::test]
async fn changed_fingerprint_enumerates_exactly_one_new_candidate_generation() {
    let (mut incumbent, storage, group_id, mut same_branch_peer) =
        contested_rival_app_backlog(256).await;

    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    let before_change = incumbent.engine_metrics();
    assert_eq!(before_change.deferred_peel_candidate_enumerations, 1);
    assert_eq!(before_change.deferred_peel_candidate_cache_hits, 1);

    // A valid commit on the incumbent lineage adds one stored convergence
    // input without adopting the rival branch. The commit digest is part of
    // the existing fingerprint semantics, so the remaining rows form one new
    // exact generation.
    let (new_input, pending) = evolution(
        same_branch_peer
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap(),
    );
    same_branch_peer.confirm_published(pending).await.unwrap();
    assert!(matches!(
        incumbent.ingest(new_input).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));

    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    assert!(
        storage
            .list_messages_in_states(&group_id, &[MessageState::PeelDeferred], EpochId(0),)
            .unwrap()
            .is_empty()
    );
    let after_change = incumbent.engine_metrics();
    assert_eq!(
        after_change.deferred_peel_candidate_enumerations,
        before_change.deferred_peel_candidate_enumerations + 1,
        "one changed fingerprint must cause exactly one new enumeration"
    );
    assert_eq!(after_change.deferred_peel_candidate_cache_misses, 2);
    assert_eq!(after_change.deferred_peel_candidate_cache_hits, 2);
    assert!(after_change.deferred_peel_candidate_cache_invalidations >= 2);
}

#[tokio::test]
async fn restart_discards_candidate_context_cache_and_recomputes_once() {
    let (mut incumbent, storage, group_id, _same_branch_peer) =
        contested_rival_app_backlog(192).await;
    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    assert_eq!(
        incumbent
            .engine_metrics()
            .deferred_peel_candidate_enumerations,
        1
    );
    drop(incumbent);

    let mut restarted =
        build_epoch_sealed_client_with_storage(b"candidate-cache-incumbent", storage.clone());
    restarted.hydrate_all_stored_groups().unwrap();
    let mut progressed = 0usize;
    for _ in 0..3 {
        progressed += restarted.retry_deferred_peels(&group_id).await.unwrap();
        if restarted
            .engine_metrics()
            .deferred_peel_candidate_enumerations
            > 0
        {
            break;
        }
    }
    assert_eq!(progressed, 64);
    let metrics = restarted.engine_metrics();
    assert_eq!(
        metrics.deferred_peel_candidate_enumerations, 1,
        "a restarted engine must enumerate instead of loading secret contexts"
    );
    assert_eq!(metrics.deferred_peel_candidate_cache_misses, 1);
    assert_eq!(metrics.deferred_peel_candidate_cache_hits, 0);
}

#[tokio::test]
async fn cancelled_sweep_keeps_untried_rows_eligible_and_reuses_enumeration() {
    let peeler = CancellableEpochSealedPeeler::new();
    let (mut incumbent, storage, group_id, _same_branch_peer) =
        contested_rival_app_backlog_with_peeler(192, peeler.clone()).await;

    peeler.block();
    let cancelled = tokio::time::timeout(
        std::time::Duration::from_millis(25),
        incumbent.retry_deferred_peels(&group_id),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the blocked peel must exhaust the caller budget"
    );
    assert_eq!(peeler.blocked_attempts(), 1);
    let deferred = storage
        .list_messages_in_states(&group_id, &[MessageState::PeelDeferred], EpochId(0))
        .unwrap();
    assert_eq!(deferred.len(), 192);
    assert!(deferred.iter().all(|record| {
        record
            .deferred_peel
            .as_ref()
            .and_then(|lifecycle| lifecycle.last_context_fingerprint)
            .is_none()
    }));
    assert_eq!(
        incumbent
            .engine_metrics()
            .deferred_peel_candidate_enumerations,
        1
    );

    peeler.unblock();
    assert_eq!(incumbent.retry_deferred_peels(&group_id).await.unwrap(), 64);
    let metrics = incumbent.engine_metrics();
    assert_eq!(
        metrics.deferred_peel_candidate_enumerations, 1,
        "cancellation retains the safe memory-only enumeration"
    );
    assert_eq!(metrics.deferred_peel_candidate_cache_hits, 1);
}

#[tokio::test]
async fn foreground_send_budget_queues_47_and_64_row_notify_gated_backlogs() {
    assert_eq!(
        cgka_engine::message_processor::FOREGROUND_DEFERRED_PEEL_BUDGET_MS,
        250
    );
    assert_eq!(
        cgka_engine::message_processor::MAX_FOREGROUND_DEFERRED_ROWS,
        4
    );

    for backlog in [47_usize, 64] {
        let client = build_notify_client(b"carol");
        let (mut alice, mut carol, storage, peeler, group_id, _commit2, _commit3) =
            carol_behind_two_epochs_with(client).await;

        let template = send_app(&mut alice, &group_id, "foreground deferred backlog").await;
        for index in 0..backlog {
            let wrapped = TransportMessage {
                id: MessageId::new(format!("foreground-{backlog}-{index}").into_bytes()),
                ..template.clone()
            };
            assert!(matches!(
                carol.ingest(wrapped).await.unwrap(),
                IngestOutcome::TransportDeferred { .. }
            ));
        }
        assert_eq!(
            storage
                .list_messages(&group_id, EpochId(0))
                .unwrap()
                .into_iter()
                .filter(|record| record.state == MessageState::PeelDeferred)
                .count(),
            backlog
        );

        carol.set_foreground_deferred_peel_budget(25, 4);
        peeler.block_on_attempt(1);

        let result = carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, "queued application"),
            })
            .await
            .unwrap();
        let app_intent_id = match result {
            SendResult::Queued { intent_id, .. } => intent_id,
            other => panic!("expected queued application, got {other:?}"),
        };
        assert_eq!(peeler.gated_attempts(), 1);
        assert_eq!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
        // Isolate each intent class while retaining the same deferred backlog.
        storage
            .delete_queued_outbound_intent(&app_intent_id)
            .unwrap();

        // The same shared preflight queues proposal- and commit-producing
        // requests without constructing either wire artifact.
        peeler.block_on_attempt(1);
        let leave = carol
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap();
        let leave_intent_id = match leave {
            SendResult::Queued { intent_id, .. } => intent_id,
            other => panic!("expected queued proposal, got {other:?}"),
        };
        storage
            .delete_queued_outbound_intent(&leave_intent_id)
            .unwrap();
        peeler.block_on_attempt(1);
        assert!(matches!(
            carol
                .send(SendIntent::SelfUpdate {
                    group_id: group_id.clone(),
                })
                .await
                .unwrap(),
            SendResult::Queued { .. }
        ));
        assert_eq!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .len(),
            1
        );

        let metrics = carol.engine_metrics();
        assert_eq!(metrics.foreground_deferred_budget_exhausted, 3);
        assert_eq!(metrics.outbound_wire_prepare_ms.sample_count(), 0);
        assert_eq!(metrics.outbound_queue_accept_ms.sample_count(), 3);
    }
}

/// The core #339 fix: a deferred row is not re-peeled while the
/// (epoch, snapshot-set) peel context is unchanged — after one unproductive
/// full cycle over the backlog, whole sweeps are skipped.
#[tokio::test]
async fn deferred_peel_new_row_invalidates_unchanged_fast_path() {
    let (_alice, mut carol, carol_storage, carol_peeler, group_id, _commit2, commit3) =
        carol_behind_two_epochs().await;

    // The epoch-3 commit does not peel at carol's epoch 1: deferred.
    assert!(matches!(
        carol.ingest(commit3.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert_eq!(
        carol_storage.get_message(&commit3.id).unwrap().state,
        MessageState::PeelDeferred
    );

    // First drain performs one sweep (one re-peel attempt), makes no
    // progress, and arms the context gate.
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    let attempts_after_first_sweep = carol_peeler.attempts_for(&commit3.id);

    // Nothing changed: subsequent drains must not re-peel the row at all.
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001)
        .await
        .unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_002)
        .await
        .unwrap();

    assert_eq!(
        carol_peeler.attempts_for(&commit3.id),
        attempts_after_first_sweep,
        "unchanged peel context must skip deferred-peel sweeps entirely"
    );
    assert_eq!(
        carol_storage.get_message(&commit3.id).unwrap().state,
        MessageState::PeelDeferred,
        "row stays retained while the context is unchanged"
    );

    // A newly retained wrapper has not been examined with candidate branch
    // contexts merely because older rows completed this fingerprint. It must
    // invalidate the historical-only fast path and receive one sweep attempt.
    let new_wrapper = TransportMessage {
        id: MessageId::new(b"new-wrapper-same-context".to_vec()),
        ..commit3.clone()
    };
    assert!(matches!(
        carol.ingest(new_wrapper.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let after_live_attempt = carol_peeler.attempts_for(&new_wrapper.id);
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_003)
        .await
        .unwrap();
    assert_eq!(
        carol_peeler.attempts_for(&new_wrapper.id),
        after_live_attempt + 1,
        "new row must be examined under the current full peel context"
    );
}

#[tokio::test]
async fn deferred_lifecycle_normalization_is_pending_not_budget_exhaustion() {
    let (_alice, mut carol, storage, _peeler, group_id, _commit2, commit3) =
        carol_behind_two_epochs().await;
    for index in 0..5 {
        let wrapper = TransportMessage {
            id: MessageId::new(format!("legacy-lifecycle-{index}").into_bytes()),
            ..commit3.clone()
        };
        assert!(matches!(
            carol.ingest(wrapper.clone()).await.unwrap(),
            IngestOutcome::TransportDeferred { .. }
        ));
        let mut legacy = storage.get_message(&wrapper.id).unwrap();
        legacy.deferred_peel = None;
        storage.put_message(&legacy).unwrap();
    }
    assert!(matches!(
        carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, "send after lifecycle normalization"),
            })
            .await
            .unwrap(),
        SendResult::Queued { .. }
    ));
    let metrics = carol.engine_metrics();
    assert_eq!(metrics.foreground_deferred_normalization_pending, 1);
    assert_eq!(
        metrics.foreground_deferred_budget_exhausted, 1,
        "the later four-attempt slice, not normalization, exhausts the budget"
    );
    assert_eq!(
        metrics
            .foreground_deferred_rows_attempted
            .approx_percentile(1.0),
        Some(4)
    );
}

#[tokio::test]
async fn queued_intent_drains_before_historical_only_maintenance() {
    let (_alice, mut carol, storage, peeler, group_id, _commit2, commit3) =
        carol_behind_two_epochs().await;

    assert!(matches!(
        carol.ingest(commit3.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    let historical_attempts = peeler.attempts_for(&commit3.id);

    assert!(matches!(
        carol
            .queue_app_message(
                group_id.clone(),
                app_payload_for(&carol, "queued before historical maintenance"),
            )
            .await
            .unwrap(),
        SendResult::Queued { .. }
    ));
    assert_eq!(
        storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1
    );

    // The existing row is historical-only under an unchanged fingerprint, so
    // it neither blocks a newer direct send nor repeats ahead of queued work.
    assert!(matches!(
        carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, "later direct send"),
            })
            .await
            .unwrap(),
        SendResult::ApplicationMessage { .. }
    ));
    assert_eq!(peeler.attempts_for(&commit3.id), historical_attempts);

    // A newly retained row is current-generation work, even with a queue. It
    // receives a definitive foreground attempt before any wire is prepared.
    let fresh = TransportMessage {
        id: MessageId::new(b"fresh-row-ahead-of-queue".to_vec()),
        ..commit3
    };
    assert!(matches!(
        carol.ingest(fresh.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let fresh_attempts = peeler.attempts_for(&fresh.id);
    assert!(matches!(
        carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, "send after fresh row"),
            })
            .await
            .unwrap(),
        SendResult::ApplicationMessage { .. }
    ));
    assert_eq!(peeler.attempts_for(&fresh.id), fresh_attempts + 1);

    let completed_attempts = peeler.attempts_for(&fresh.id);
    let drained = carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001)
        .await
        .unwrap();
    assert!(matches!(
        drained.as_slice(),
        [SendResult::ApplicationMessage { .. }]
    ));
    assert_eq!(
        peeler.attempts_for(&fresh.id),
        completed_attempts,
        "the queued drain skips rows now historical under the same fingerprint"
    );
    assert_eq!(peeler.attempts_for(&commit3.id), historical_attempts);
}

#[tokio::test]
async fn deferred_peel_restart_resumes_first_uncompleted_row_not_numeric_offset() {
    let client = build_notify_client(b"carol");
    let (mut alice, mut carol, storage, peeler, group_id, _commit2, _commit3) =
        carol_behind_two_epochs_with(client).await;
    let template = send_app(&mut alice, &group_id, "restart resume backlog").await;
    let mut ids = Vec::new();
    for index in 0..64 {
        let id = MessageId::new(format!("restart-resume-{index}").into_bytes());
        ids.push(id.clone());
        assert!(matches!(
            carol
                .ingest(TransportMessage {
                    id,
                    ..template.clone()
                })
                .await
                .unwrap(),
            IngestOutcome::TransportDeferred { .. }
        ));
    }
    carol.set_foreground_deferred_peel_budget(25, 4);
    peeler.block_on_attempt(4);
    assert!(matches!(
        carol
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload: app_payload_for(&carol, "restart queued"),
            })
            .await
            .unwrap(),
        SendResult::Queued { .. }
    ));
    assert!((1..=4).contains(&peeler.gated_attempts()));
    let deferred_after_send = storage
        .list_messages(&group_id, EpochId(0))
        .unwrap()
        .into_iter()
        .filter(|record| record.state == MessageState::PeelDeferred)
        .collect::<Vec<_>>();
    let completed_ids = deferred_after_send
        .iter()
        .take_while(|record| {
            record
                .deferred_peel
                .as_ref()
                .and_then(|lifecycle| lifecycle.last_context_fingerprint)
                .is_some()
        })
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    let first_uncompleted_id = deferred_after_send
        .get(completed_ids.len())
        .expect("foreground slice leaves an uncompleted row")
        .id
        .clone();
    drop(carol);

    let clock = ManualConvergenceClock::new(2_000, 20_000);
    let (mut restarted, _, restarted_peeler) =
        build_counting_client_with_storage_and_clock(b"carol", storage.clone(), clock);
    restarted.hydrate_all_stored_groups().unwrap();
    restarted.retry_deferred_peels(&group_id).await.unwrap();

    for id in &completed_ids {
        assert_eq!(
            restarted_peeler.attempts_for(id),
            0,
            "definitively completed rows must not repeat after restart"
        );
    }
    assert_eq!(
        restarted_peeler.attempts_for(&first_uncompleted_id),
        1,
        "the timed-out row must be the first resumed attempt"
    );
    assert_eq!(
        restarted_peeler.attempts_for(ids.last().unwrap()),
        1,
        "later rows must not be stranded behind an in-memory cursor"
    );
    assert_eq!(
        storage
            .list_queued_outbound_intents(&group_id)
            .unwrap()
            .len(),
        1,
        "accepted-pending intent survives the same restart"
    );
}

#[tokio::test]
async fn contested_generation_barrier_survives_restart_and_blocks_prefix_convergence() {
    let (_alice, mut carol, storage, _peeler, group_id, commit2, _commit3) =
        carol_behind_two_epochs().await;
    storage
        .put_deferred_peel_generation(&DeferredPeelGeneration {
            group_id: group_id.clone(),
            context_fingerprint: [9; 32],
        })
        .unwrap();

    assert!(matches!(
        carol.ingest(commit2).await.unwrap(),
        IngestOutcome::Buffered { .. }
    ));
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
    drop(carol);

    let clock = ManualConvergenceClock::new(3_000, 30_000);
    let (mut restarted, _, _) =
        build_counting_client_with_storage_and_clock(b"carol", storage.clone(), clock);
    restarted.hydrate_all_stored_groups().unwrap();
    let blocked = restarted
        .converge_stored_openmls_messages(&group_id)
        .unwrap();
    assert_eq!(
        blocked.convergence_status,
        cgka_engine::canonicalization::ConvergenceStatus::Syncing
    );
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(1));
    assert!(
        storage
            .deferred_peel_generation(&group_id)
            .unwrap()
            .is_some(),
        "restart must retain the prefix-adjudication barrier"
    );

    // With no raw rows remaining, deferred maintenance closes the generation
    // and drains the complete durable content set.
    restarted.retry_deferred_peels(&group_id).await.unwrap();
    assert!(
        storage
            .deferred_peel_generation(&group_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(restarted.epoch(&group_id).unwrap(), EpochId(2));
}

/// The gate must not block legitimate retries: once the epoch advances, the
/// deferred row is re-attempted and applies.
#[tokio::test]
async fn deferred_peel_retries_after_epoch_advance() {
    let (_alice, mut carol, carol_storage, carol_peeler, group_id, commit2, commit3) =
        carol_behind_two_epochs().await;

    carol.ingest(commit3.clone()).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    let gated_attempts = carol_peeler.attempts_for(&commit3.id);

    // The epoch-2 commit arrives: the peel context changes, the gate opens,
    // and the deferred epoch-3 commit replays to the tip.
    carol.ingest(commit2.clone()).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001)
        .await
        .unwrap();

    assert!(
        carol_peeler.attempts_for(&commit3.id) > gated_attempts,
        "changed peel context must re-attempt the deferred row"
    );
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(3));
    assert_eq!(
        carol_storage.get_message(&commit3.id).unwrap().state,
        MessageState::Processed
    );
}

/// A row that exhausts its retry budget is resource-refused and released
/// without poisoning same-id redelivery as a terminal duplicate.
#[tokio::test]
async fn deferred_peel_retry_budget_refuses_without_terminal_dedup() {
    let (mut alice, mut carol, carol_storage, carol_peeler, group_id, commit2, commit3) =
        carol_behind_two_epochs().await;
    carol.set_deferred_peel_retry_budget(1);

    // An application message at epoch 3 can never peel while carol never
    // sees the epoch-3 commit.
    let stuck_app = send_app(&mut alice, &group_id, "forever ahead").await;
    assert!(matches!(
        carol.ingest(stuck_app.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));

    // Sweep 1 (context: epoch 1) consumes the single budgeted attempt.
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    assert_eq!(
        carol_storage.get_message(&stuck_app.id).unwrap().state,
        MessageState::PeelDeferred
    );

    // The epoch-2 commit changes the context; the next sweep finds the row
    // over budget and releases it without another peel attempt.
    carol.ingest(commit2.clone()).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001)
        .await
        .unwrap();
    assert!(
        matches!(
            carol_storage.get_message(&stuck_app.id),
            Err(StorageError::NotFound)
        ),
        "budget-exhausted deferred row must be released, not terminally retained"
    );

    // The same transport id remains eligible and is retained again rather
    // than short-circuiting as a duplicate.
    let attempts_at_refusal = carol_peeler.attempts_for(&stuck_app.id);
    assert!(matches!(
        carol.ingest(stuck_app.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert!(
        carol_peeler.attempts_for(&stuck_app.id) > attempts_at_refusal,
        "same-id redelivery must reach the peeler again"
    );

    // Once the missing commit arrives, the redelivered row peels and applies.
    carol.ingest(commit3).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_002)
        .await
        .unwrap();
    assert_eq!(
        carol_storage.get_message(&stuck_app.id).unwrap().state,
        MessageState::Processed
    );
}

/// The residence budget is durable across engine reconstruction, distinct
/// context attempts do not reset, and a backwards wall-clock jump cannot make
/// the row expire before its rebased monotonic remainder.
#[tokio::test]
async fn deferred_peel_residence_survives_restart_and_backward_clock() {
    let clock = ManualConvergenceClock::new(1_000, 10_000);
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let carol_client =
        build_counting_client_with_storage_and_clock(b"carol", storage.clone(), clock.clone());
    let (mut alice, mut carol, carol_storage, _peeler, group_id, commit2, commit3) =
        carol_behind_two_epochs_with(carol_client).await;
    carol.set_deferred_peel_residence_ms(1_000);

    let stuck_app = send_app(&mut alice, &group_id, "durable residence").await;
    assert!(matches!(
        carol.ingest(stuck_app.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert!(
        carol.drain_pending_convergence_groups().contains(&group_id),
        "first deferral must arm the scheduler even if peel context stays stable"
    );
    assert_eq!(
        carol.deferred_peel_cutoff_delay_ms(&group_id).unwrap(),
        Some(1_000)
    );
    carol.retry_deferred_peels(&group_id).await.unwrap();
    let before_restart = carol_storage.get_message(&stuck_app.id).unwrap();
    let lifecycle = before_restart
        .deferred_peel
        .as_ref()
        .expect("deferred lifecycle persisted");
    assert_eq!(lifecycle.distinct_context_attempts, 1);
    assert!(lifecycle.last_context_fingerprint.is_some());

    clock.advance_ms(400);
    drop(carol);
    let (mut restarted, _, _) = build_counting_client_with_storage_and_clock(
        b"carol",
        carol_storage.clone(),
        clock.clone(),
    );
    restarted.hydrate_all_stored_groups().unwrap();
    restarted.set_deferred_peel_residence_ms(1_000);
    assert_eq!(
        restarted.deferred_peel_cutoff_delay_ms(&group_id).unwrap(),
        Some(600)
    );
    assert_eq!(
        carol_storage
            .get_message(&stuck_app.id)
            .unwrap()
            .deferred_peel
            .unwrap()
            .distinct_context_attempts,
        1,
        "restart must preserve the consumed distinct-context budget"
    );

    // Reconstruct once more in a wall-clock domain that moved backwards.
    clock.set_wall_ms(9_000);
    drop(restarted);
    let (mut backwards, _, _) = build_counting_client_with_storage_and_clock(
        b"carol",
        carol_storage.clone(),
        clock.clone(),
    );
    backwards.hydrate_all_stored_groups().unwrap();
    backwards.set_deferred_peel_residence_ms(1_000);
    assert_eq!(
        backwards.deferred_peel_cutoff_delay_ms(&group_id).unwrap(),
        Some(600),
        "backwards wall movement must preserve, not shorten, the remainder"
    );

    clock.advance_monotonic_ms(599);
    backwards.retry_deferred_peels(&group_id).await.unwrap();
    assert_eq!(
        carol_storage.get_message(&stuck_app.id).unwrap().state,
        MessageState::PeelDeferred
    );

    clock.advance_monotonic_ms(1);
    backwards.retry_deferred_peels(&group_id).await.unwrap();
    assert!(matches!(
        carol_storage.get_message(&stuck_app.id),
        Err(StorageError::NotFound)
    ));
    assert!(backwards.drain_events().iter().any(|event| {
        matches!(
            event,
            GroupEvent::TransportObjectResourceRefused {
                message_id,
                resource:
                    cgka_traits::ingest::InboundResourceLimit::TransportDeferredResidenceBudget,
                ..
            } if message_id == &stuck_app.id
        )
    }));

    // Resource release is not terminal dedup: the same exact transport id
    // reaches the peeler and becomes locally retryable again.
    assert!(matches!(
        backwards.ingest(stuck_app.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    backwards.ingest(commit2).await.unwrap();
    backwards.ingest(commit3).await.unwrap();
    backwards.retry_deferred_peels(&group_id).await.unwrap();
    assert_eq!(
        carol_storage.get_message(&stuck_app.id).unwrap().state,
        MessageState::Processed,
        "same-id redelivery must process once the missing commits arrive"
    );
}

/// A flood of undecryptable group-routed input (fresh transport id per
/// re-wrap is attacker-controllable) must not grow the durable store past
/// the per-group cap. Overflow remains retryable by same-id redelivery once
/// the retained backlog drains.
#[tokio::test]
async fn peel_deferred_rows_capped_per_group_under_flood() {
    let (mut alice, mut carol, carol_storage, carol_peeler, group_id, commit2, commit3) =
        carol_behind_two_epochs().await;

    // One real epoch-3 app message, re-wrapped under distinct transport ids —
    // exactly the re-wrap flood a malicious peer can produce for free.
    let template = send_app(&mut alice, &group_id, "flood payload").await;
    let flood = MAX_PEEL_DEFERRED_ROWS_PER_GROUP;
    for i in 0..flood {
        let wrapped = TransportMessage {
            id: MessageId::new(format!("flood-{i}").into_bytes()),
            ..template.clone()
        };
        let outcome = carol.ingest(wrapped.clone()).await.unwrap();
        assert!(
            matches!(outcome, IngestOutcome::TransportDeferred { .. }),
            "flood message {i} classified unexpectedly: {outcome:?}"
        );
    }

    let legitimate_template = send_app(&mut alice, &group_id, "cap overflow legitimate").await;
    let overflow = TransportMessage {
        id: MessageId::new(b"cap-overflow-legitimate".to_vec()),
        ..legitimate_template.clone()
    };
    assert!(matches!(
        carol.ingest(overflow.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    let capacity_metrics = carol.engine_metrics();
    assert_eq!(capacity_metrics.deferred_peel_row_capacity_refusals, 1);
    assert_eq!(
        capacity_metrics.deferred_peel_peak_rows_per_group,
        MAX_PEEL_DEFERRED_ROWS_PER_GROUP as u64
    );

    let retained = carol_storage
        .list_messages(&group_id, EpochId(0))
        .unwrap()
        .into_iter()
        .filter(|record| record.state == MessageState::PeelDeferred)
        .count();
    assert_eq!(
        retained, MAX_PEEL_DEFERRED_ROWS_PER_GROUP,
        "durable PeelDeferred rows must be capped per group"
    );
    assert!(
        matches!(
            carol_storage.get_message(&overflow.id),
            Err(StorageError::NotFound)
        ),
        "overflow input must not be persisted"
    );

    // While the cap remains full, same-id redelivery re-attempts the peel and
    // is cap-dropped again; it is not poisoned as terminal AlreadySeen.
    let attempts_before_redelivery = carol_peeler.attempts_for(&overflow.id);
    assert!(matches!(
        carol.ingest(overflow.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    assert_eq!(
        carol_peeler.attempts_for(&overflow.id),
        attempts_before_redelivery + 1
    );

    // Catch up to the sender epoch and drain the retained backlog. The exact
    // same overflow id can then be redelivered and processed successfully.
    carol.ingest(commit2).await.unwrap();
    carol.ingest(commit3).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    assert!(matches!(
        carol.ingest(overflow).await.unwrap(),
        IngestOutcome::Processed
    ));
}

/// If account accounting was initialized by group A, a later deferral in
/// group B is charged incrementally. Group B's first sweep must reconcile that
/// contribution rather than adding the same durable bytes again.
#[tokio::test]
async fn later_deferring_group_first_sweep_keeps_exact_account_byte_total() {
    let (mut alice, mut carol, storage, _peeler, group_a, _commit2, _commit3) =
        carol_behind_two_epochs().await;

    let deferred_a = send_app(&mut alice, &group_a, "group A deferred bytes").await;
    assert!(matches!(
        carol.ingest(deferred_a.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let bytes_a = storage.get_message(&deferred_a.id).unwrap().payload.len();

    // Account reconstruction has now run without group B in storage. Creating
    // B after that boundary is what exercises the original double-count path.
    let group_b = add_group_two_epochs_ahead(&mut alice, &mut carol).await;
    let deferred_b = send_app(&mut alice, &group_b, "group B deferred bytes").await;
    assert!(matches!(
        carol.ingest(deferred_b.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let bytes_b = storage.get_message(&deferred_b.id).unwrap().payload.len();

    carol.retry_deferred_peels(&group_b).await.unwrap();
    assert_eq!(
        carol.engine_metrics().deferred_peel_peak_bytes_per_account,
        (bytes_a + bytes_b) as u64
    );
}

/// A transport object outside the bounded stored-message representation is a
/// typed, same-id-retryable resource refusal. It must not abort a relay drain
/// as an internal serialization error.
#[tokio::test]
async fn unencodable_deferred_transport_is_resource_refused() {
    let (mut alice, mut carol, storage, carol_peeler, group_id, _commit2, _commit3) =
        carol_behind_two_epochs().await;
    let template = send_app(&mut alice, &group_id, "unencodable deferred payload").await;
    let oversized = TransportMessage {
        id: MessageId::new(b"unencodable-deferred".to_vec()),
        // StoredMessagePayload bounds causal dependency lists at 2^20 items.
        // The codec rejects this before encoding individual entries.
        causal_deps: vec![MessageId::new(Vec::new()); (1 << 20) + 1],
        ..template
    };

    assert!(matches!(
        carol.ingest(oversized.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    assert!(matches!(
        storage.get_message(&oversized.id),
        Err(StorageError::NotFound)
    ));

    let attempts = carol_peeler.attempts_for(&oversized.id);
    assert!(matches!(
        carol.ingest(oversized.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    assert_eq!(carol_peeler.attempts_for(&oversized.id), attempts + 1);
}

/// The test-only override can isolate the per-group byte budget independently
/// of the row and account bounds.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn peel_deferred_group_byte_budget_refuses_growth_without_persisting_it() {
    let (mut alice, mut carol, storage, _peeler, group_id, _commit2, _commit3) =
        carol_behind_two_epochs().await;
    carol.set_deferred_peel_limits_for_tests(512, usize::MAX, usize::MAX);

    let template = send_app(&mut alice, &group_id, "group byte budget").await;
    let first = TransportMessage {
        id: MessageId::new(b"group-byte-0001".to_vec()),
        ..template.clone()
    };
    assert!(matches!(
        carol.ingest(first.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let first_bytes = storage.get_message(&first.id).unwrap().payload.len();
    carol.set_deferred_peel_limits_for_tests(512, first_bytes.saturating_mul(2), usize::MAX);

    let second = TransportMessage {
        id: MessageId::new(b"group-byte-0002".to_vec()),
        ..template.clone()
    };
    assert!(matches!(
        carol.ingest(second).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));

    let overflow = TransportMessage {
        id: MessageId::new(b"group-byte-0003".to_vec()),
        ..template
    };
    assert!(matches!(
        carol.ingest(overflow.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    assert!(matches!(
        storage.get_message(&overflow.id),
        Err(StorageError::NotFound)
    ));
    let metrics = carol.engine_metrics();
    assert_eq!(metrics.deferred_peel_row_capacity_refusals, 0);
    assert_eq!(metrics.deferred_peel_group_byte_capacity_refusals, 1);
    assert_eq!(metrics.deferred_peel_account_byte_capacity_refusals, 0);
    assert_eq!(
        metrics.deferred_peel_peak_bytes_per_group,
        first_bytes.saturating_mul(2) as u64
    );
}

/// Account-wide byte accounting is reconstructed from durable deferred rows
/// after restart before a new row can be admitted.
#[cfg(feature = "test-policy-overrides")]
#[tokio::test]
async fn peel_deferred_account_byte_budget_is_restart_safe() {
    let (mut alice, mut carol, storage, _peeler, group_id, _commit2, _commit3) =
        carol_behind_two_epochs().await;
    let template = send_app(&mut alice, &group_id, "account byte budget").await;
    let first = TransportMessage {
        id: MessageId::new(b"account-byte-0001".to_vec()),
        ..template.clone()
    };
    assert!(matches!(
        carol.ingest(first.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    let first_bytes = storage.get_message(&first.id).unwrap().payload.len();
    drop(carol);

    let clock = ManualConvergenceClock::new(2_000, 20_000);
    let (mut restarted, _, _) =
        build_counting_client_with_storage_and_clock(b"carol", storage.clone(), clock);
    restarted.hydrate_all_stored_groups().unwrap();
    restarted.set_deferred_peel_limits_for_tests(512, usize::MAX, first_bytes.saturating_mul(2));

    let second = TransportMessage {
        id: MessageId::new(b"account-byte-0002".to_vec()),
        ..template.clone()
    };
    assert!(matches!(
        restarted.ingest(second).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));

    let overflow = TransportMessage {
        id: MessageId::new(b"account-byte-0003".to_vec()),
        ..template
    };
    assert!(matches!(
        restarted.ingest(overflow.clone()).await.unwrap(),
        IngestOutcome::ResourceRefused {
            resource: cgka_traits::ingest::InboundResourceLimit::TransportDeferredCapacity,
            ..
        }
    ));
    assert!(matches!(
        storage.get_message(&overflow.id),
        Err(StorageError::NotFound)
    ));
    let metrics = restarted.engine_metrics();
    assert_eq!(metrics.deferred_peel_row_capacity_refusals, 0);
    assert_eq!(metrics.deferred_peel_group_byte_capacity_refusals, 0);
    assert_eq!(metrics.deferred_peel_account_byte_capacity_refusals, 1);
    assert_eq!(
        metrics.deferred_peel_peak_bytes_per_account,
        first_bytes.saturating_mul(2) as u64
    );
}

/// An application message from before this device joined is terminal on
/// first classification — no deferral, no retry (mdk#339 acceptance
/// criterion).
#[tokio::test]
async fn pre_membership_application_message_is_terminal_not_deferred() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut bob, _bob_storage) = build_client(b"bob");
    let (mut carol, carol_storage, carol_peeler) = build_counting_client(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "pre-membership-terminal".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, _welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    // History carol can never decrypt: sent before she was invited.
    let pre_membership_app = send_app(&mut alice, &group_id, "before carol").await;

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcomes, pending) = match invite {
        SendResult::GroupEvolution {
            welcomes, pending, ..
        } => (welcomes, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();
    let join_epoch = carol.epoch(&group_id).unwrap();
    assert_eq!(
        carol.group_record(&group_id).unwrap().join_epoch,
        join_epoch,
        "welcome join must record the join epoch"
    );

    // The pre-membership message peels (pass-through) but classifies
    // terminal before any OpenMLS processing or deferral.
    let outcome = carol.ingest(pre_membership_app.clone()).await.unwrap();
    assert!(matches!(
        outcome,
        IngestOutcome::Stale {
            reason: StaleReason::PreMembership
        }
    ));
    let record = carol_storage
        .get_message(&content_id(&pre_membership_app))
        .expect("terminal classification persists the content row");
    assert_eq!(record.state, MessageState::Failed);
    assert!(
        matches!(
            carol_storage.get_message(&pre_membership_app.id),
            Err(StorageError::NotFound)
        ),
        "a peelable pre-membership message must not leave a PeelDeferred row"
    );

    // Terminal means terminal: convergence drains never re-peel it.
    let attempts = carol_peeler.attempts_for(&pre_membership_app.id);
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
        .await
        .unwrap();
    assert_eq!(carol_peeler.attempts_for(&pre_membership_app.id), attempts);
}

/// A rejoin replaces a prior local membership interval. Without durable
/// interval history, the latest Welcome epoch must not be used as a blanket
/// lower bound that terminalizes messages authored while the earlier interval
/// was active.
#[tokio::test]
async fn rejoin_does_not_generalize_latest_welcome_into_pre_membership() {
    let (mut alice, _alice_storage) = build_client(b"alice-rejoin-history");
    let (mut bob, _bob_storage, _bob_peeler) = build_counting_client(b"bob-rejoin-history");
    let bob_id = bob.self_id().clone();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "rejoin-history".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob-rejoin-history"))
        .await
        .unwrap();

    let prior_membership_app = send_app(&mut alice, &group_id, "earlier membership").await;

    let (remove, pending) = evolution(
        alice
            .send(SendIntent::RemoveMembers {
                group_id: group_id.clone(),
                members: vec![bob_id],
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(pending).await.unwrap();
    bob.ingest(route(remove, &group_id)).await.unwrap();

    let rejoin_kp = bob.fresh_key_package().await.unwrap();
    let rejoin = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![rejoin_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (welcomes, pending) = match rejoin {
        SendResult::GroupEvolution {
            welcomes, pending, ..
        } => (welcomes, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob-rejoin-history"))
        .await
        .unwrap();
    assert_eq!(
        bob.group_record(&group_id).unwrap().join_epoch,
        EpochId(0),
        "a single lower bound cannot safely represent multiple membership intervals"
    );

    let outcome = bob.ingest(prior_membership_app).await.unwrap();
    assert!(
        !matches!(
            outcome,
            IngestOutcome::Stale {
                reason: StaleReason::PreMembership
            }
        ),
        "earlier-membership traffic must not be terminalized from the latest Welcome alone"
    );
}

/// `join_epoch` bookkeeping: welcome joins record the join epoch; a group's
/// creator records `EpochId(0)` — no bound, nothing predates the creator.
#[tokio::test]
async fn join_epoch_recorded_on_welcome_join() {
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, _carol_storage, _peeler) = build_counting_client(b"carol");

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "join-epoch-recorded".into(),
            description: "".into(),
            members: vec![carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol"))
        .await
        .unwrap();

    assert_eq!(
        carol.group_record(&group_id).unwrap().join_epoch,
        carol.epoch(&group_id).unwrap(),
        "welcome join records the post-welcome epoch"
    );
    assert_eq!(
        alice.group_record(&group_id).unwrap().join_epoch,
        EpochId(0),
        "creator records no pre-membership bound"
    );
}

/// Seam parity with `replay_buffered_messages` (5ae9a440): the deferred-peel
/// sweep must NOT relabel `Processed` a `PeelDeferred` row that
/// `ingest_group_message` terminalized during the sweep. The reachable case is
/// `SelfEvicted`: a future-epoch commit sits `PeelDeferred`; once our own leaf
/// is removed the group is `!is_active` (still `Stable`, not quarantined), so
/// re-ingesting the deferred row hits the `!is_active` gate, which persists it
/// `Failed`. That ingest-committed verdict is authoritative — sweeping it back
/// to `Processed` would feed a row we were evicted on into canonicalization
/// (`openmls_projection` / `distributed_convergence` select on `Processed`).
#[tokio::test]
async fn deferred_peel_self_evicted_row_stays_failed_not_swept_processed() {
    // alice (admin) removes carol; bob keeps the group non-trivial afterwards.
    let (mut alice, _alice_storage) = build_client(b"alice-deferred-self-evict");
    let (mut bob, _bob_storage) = build_client(b"bob-deferred-self-evict");
    let (mut carol, carol_storage, _carol_peeler) =
        build_counting_client(b"carol-deferred-self-evict");
    let carol_id = carol.self_id().clone();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "deferred-self-evict".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![alice.self_id()],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    bob.join_welcome(welcome_for(&welcomes, b"bob-deferred-self-evict"))
        .await
        .unwrap();
    carol
        .join_welcome(welcome_for(&welcomes, b"carol-deferred-self-evict"))
        .await
        .unwrap();
    carol.drain_events();
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));

    // Alice removes carol at epoch 1 (source epoch 1) → advances to epoch 2.
    // Carol can peel & apply this at epoch 1; hold it back for now.
    let (msg, pending) = evolution(
        alice
            .send(SendIntent::RemoveMembers {
                group_id: group_id.clone(),
                members: vec![carol_id.clone()],
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(pending).await.unwrap();
    let remove_carol = route(msg, &group_id);

    // Alice, now at epoch 2, produces a future commit (source epoch 2) that
    // carol at epoch 1 cannot peel — it is retained `PeelDeferred`.
    let (msg, pending) = evolution(
        alice
            .send(SendIntent::UpdateGroupData {
                group_id: group_id.clone(),
                name: Some("post-remove".into()),
                description: None,
            })
            .await
            .unwrap(),
    );
    alice.confirm_published(pending).await.unwrap();
    let future_commit = route(msg, &group_id);

    // Carol (epoch 1) ingests the future commit: undecryptable → PeelDeferred.
    assert!(matches!(
        carol.ingest(future_commit.clone()).await.unwrap(),
        IngestOutcome::TransportDeferred { .. }
    ));
    assert_eq!(
        carol_storage.get_message(&future_commit.id).unwrap().state,
        MessageState::PeelDeferred,
        "the future-epoch commit is retained pending a later peel"
    );

    // Carol applies the removal: her leaf is gone and the group goes inactive
    // (still `Stable`, not quarantined), so the deferred row will re-ingest
    // against an inactive group.
    carol.ingest(remove_carol).await.unwrap();
    assert!(
        !carol
            .members(&group_id)
            .unwrap()
            .iter()
            .any(|member| member.id == carol_id),
        "carol must have been evicted by the removal"
    );

    // The deferred future-commit row re-ingests against the inactive group →
    // `SelfEvicted`, so ingest persists it `Failed`. Regression: the sweep must
    // not clobber that `Failed` back to `Processed`.
    carol.retry_deferred_peels(&group_id).await.unwrap();
    assert_eq!(
        carol_storage.get_message(&future_commit.id).unwrap().state,
        MessageState::Failed,
        "a row we were evicted on must stay Failed after the deferred-peel \
         sweep, not be swept into canonicalization as Processed"
    );
}
