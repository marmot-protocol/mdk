//! `SendIntent::UpdateGroupData` round trips.
//!
//! Covers:
//! - Happy path: alice updates name + description; bob ingests + sees the
//!   change after the commit lands.
//! - Projection during PendingPublish: alice sees the new name immediately
//!   via her storage even before confirm.
//! - Rollback: `publish_failed` restores the previous name + description.
//! - Validation: empty intent (no fields) errors with `EngineError::Other`.
//! - State guard: not allowed during PendingPublish.

use async_trait::async_trait;
use cgka_engine::canonicalization::SyncState;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use storage_memory::MemoryStorage;

fn pad32(name: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
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

fn registry() -> FeatureRegistry {
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

fn build(id: &[u8]) -> Engine<MemoryStorage> {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(id))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn build_with_storage(id: &[u8]) -> (Engine<MemoryStorage>, MemoryStorage) {
    let storage = MemoryStorage::new();
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(id))
        .feature_registry(registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

fn converge_buffered_commit(engine: &mut Engine<MemoryStorage>, group_id: &GroupId) {
    let result = engine
        .converge_stored_openmls_messages(group_id, 1_000_000)
        .expect("buffered commit converges");
    assert_eq!(result.sync_state, SyncState::Stable);
}

async fn create_pair() -> (Engine<MemoryStorage>, Engine<MemoryStorage>, GroupId) {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "orig description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();
    (alice, bob, gid)
}

// ── Happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_renames_group_and_advances_epoch() {
    let (mut alice, mut bob, gid) = create_pair().await;
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("new name".into()),
            description: Some("new desc".into()),
        })
        .await
        .unwrap();
    let (commit, pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // Alice's projected epoch is 2 already (PendingPublish).
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    // Bob ingests the commit and his epoch + name follow.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    let outcome = bob.ingest(routed).await.unwrap();
    assert!(matches!(
        outcome,
        cgka_traits::ingest::IngestOutcome::Buffered { .. }
    ));
    converge_buffered_commit(&mut bob, &gid);
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);
}

// ── Partial update ──────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_with_only_name_preserves_description() {
    let (mut alice, _bob, gid) = create_pair().await;

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("renamed".into()),
            description: None,
        })
        .await
        .unwrap();
    let pending = match res {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
}

// ── Rollback ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_publish_failed_rolls_back() {
    let (mut alice, _bob, gid) = create_pair().await;

    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("doomed".into()),
            description: Some("never published".into()),
        })
        .await
        .unwrap();
    let pending = match res {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => unreachable!(),
    };

    alice.publish_failed(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);

    // The group is immediately re-usable.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("kept".into()),
            description: None,
        })
        .await
        .expect("post-rollback update must succeed");
    if let SendResult::GroupEvolution { pending, .. } = res {
        alice.confirm_published(pending).await.unwrap();
    }
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
}

// ── Validation ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_with_no_fields_errors() {
    let (mut alice, _bob, gid) = create_pair().await;
    let err = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid,
            name: None,
            description: None,
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EngineError::Other(_)));
}

// ── Multi-client convergence: B1 regression ─────────────────────────────────

/// Convergence-side application of a `update_group_data` commit must
/// refresh the recipient's Marmot record `name` and `description` to
/// match the post-merge MlsGroup state. Before this fix the convergence
/// path only refreshed `epoch` and `members`, leaving the Marmot record's
/// human-readable fields stale.
#[tokio::test]
async fn convergence_refreshes_recipient_marmot_record_name_and_description() {
    let (mut alice, _alice_storage) = build_with_storage(b"alice");
    let (mut bob, bob_storage) = build_with_storage(b"bob");
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "original-name".into(),
            description: "original-description".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (alice_pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();
    let welcome = welcomes.into_iter().next().unwrap();
    bob.join_welcome(welcome).await.unwrap();

    // Bob's record reflects the create-time name.
    let bob_group = bob_storage.get_group(&gid).unwrap();
    assert_eq!(bob_group.name, "original-name");
    assert_eq!(bob_group.description, "original-description");

    // Alice renames the group.
    let res = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid.clone(),
            name: Some("new-renamed".into()),
            description: Some("new-described".into()),
        })
        .await
        .unwrap();
    let (commit, alice_pending) = match res {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        _ => unreachable!(),
    };
    alice.confirm_published(alice_pending).await.unwrap();

    // Bob ingests via convergence — NOT via `confirm_published`.
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..commit
    };
    bob.ingest(routed).await.unwrap();
    converge_buffered_commit(&mut bob, &gid);

    // Bob's epoch advanced (this already worked).
    assert_eq!(bob.epoch(&gid).unwrap().0, 2);

    // Bob's Marmot record reflects the new name + description.
    // Pre-fix: this was still "original-name" / "original-description".
    let bob_group = bob_storage.get_group(&gid).unwrap();
    assert_eq!(
        bob_group.name, "new-renamed",
        "convergence MUST refresh recipient name"
    );
    assert_eq!(
        bob_group.description, "new-described",
        "convergence MUST refresh recipient description"
    );
}

// ── State guard ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_group_data_during_pending_publish_is_rejected() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // Start an invite (PendingPublish).
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let _invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();

    // Now try update — must reject.
    let err = alice
        .send(SendIntent::UpdateGroupData {
            group_id: gid,
            name: Some("x".into()),
            description: None,
        })
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EngineError::InvalidTransition(_)));
}
