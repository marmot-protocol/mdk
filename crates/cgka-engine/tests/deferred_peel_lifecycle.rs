//! Deferred-peel retry lifecycle (mdk#339): event-driven retries via
//! the peel-context fingerprint gate, the per-row retry budget, the per-group
//! flood cap on retained `PeelDeferred` rows, and post-peel pre-membership
//! classification against `Group::join_epoch`.

use async_trait::async_trait;
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::message_processor::MAX_PEEL_DEFERRED_ROWS_PER_GROUP;
use cgka_engine::openmls_projection::project_mls_message;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, StaleReason};
use cgka_traits::message::MessageState;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{MessageStorage, StorageError};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use storage_sqlite::SqliteAccountStorage;

mod support;
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
            source: TransportSource("mock".into()),
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
            source: TransportSource("mock".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
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
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let peeler = CountingEpochGatePeeler::new();
    let mut engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(name))
        .account_identity_proof_signer(proof_signer(name))
        .peeler(Box::new(peeler.clone()))
        .build()
        .unwrap();
    engine.set_convergence_policy(CanonicalizationPolicy {
        settlement_quiescence_ms: 0,
        ..CanonicalizationPolicy::default()
    });
    (engine, storage, peeler)
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
    let (mut alice, _alice_storage) = build_client(b"alice");
    let (mut carol, carol_storage, carol_peeler) = build_counting_client(b"carol");
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

/// The core #339 fix: a deferred row is not re-peeled while the
/// (epoch, snapshot-set) peel context is unchanged — after one unproductive
/// full cycle over the backlog, whole sweeps are skipped.
#[tokio::test]
async fn deferred_peel_not_retried_while_context_unchanged() {
    let (_alice, mut carol, carol_storage, carol_peeler, group_id, _commit2, commit3) =
        carol_behind_two_epochs().await;

    // The epoch-3 commit does not peel at carol's epoch 1: deferred.
    assert!(matches!(
        carol.ingest(commit3.clone()).await.unwrap(),
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
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
    assert_eq!(carol.epoch(&group_id).unwrap(), EpochId(1));
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

/// A row that exhausts its retry budget without ever peeling goes terminal
/// `Failed` (`permanently_undecryptable`) and is never attempted again.
#[tokio::test]
async fn deferred_peel_terminal_after_attempt_budget() {
    let (mut alice, mut carol, carol_storage, carol_peeler, group_id, commit2, _commit3) =
        carol_behind_two_epochs().await;
    carol.set_deferred_peel_retry_budget(1);

    // An application message at epoch 3 can never peel while carol never
    // sees the epoch-3 commit.
    let stuck_app = send_app(&mut alice, &group_id, "forever ahead").await;
    assert!(matches!(
        carol.ingest(stuck_app.clone()).await.unwrap(),
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
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
    // over budget and goes terminal without another peel attempt.
    carol.ingest(commit2.clone()).await.unwrap();
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001)
        .await
        .unwrap();
    assert_eq!(
        carol_storage.get_message(&stuck_app.id).unwrap().state,
        MessageState::Failed,
        "budget-exhausted deferred row must go terminal"
    );

    // Terminal rows are out of the lifecycle: further context changes do not
    // re-peel them.
    let attempts_at_terminal = carol_peeler.attempts_for(&stuck_app.id);
    carol
        .converge_and_drain_queued_outbound_intents(&group_id, 1_000_002)
        .await
        .unwrap();
    assert_eq!(
        carol_peeler.attempts_for(&stuck_app.id),
        attempts_at_terminal
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
            matches!(
                outcome,
                IngestOutcome::Stale {
                    reason: StaleReason::PeelFailed
                }
            ),
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
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
    ));

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
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
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
            reason: StaleReason::PeelFailed
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
        IngestOutcome::Stale {
            reason: StaleReason::PeelFailed
        }
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
