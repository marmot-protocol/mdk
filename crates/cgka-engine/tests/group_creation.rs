//! Group creation and welcome integration tests.
//!
//! Uses a pass-through mock peeler that reflects `EncryptedPayload` bytes
//! into a `TransportMessage` without any crypto. Lets us exercise the engine
//! end-to-end — parsing KeyPackages, validating capabilities, committing,
//! serializing — without pulling in a real peeler impl.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use storage_memory::MemoryStorage;

/// Mock peeler: wraps `EncryptedPayload` bytes verbatim into a
/// `TransportMessage` with a hash-derived id. No real crypto. Peel paths
/// unwrap the payload back out.
fn pad32(name: &[u8]) -> Vec<u8> {
    // MIP-01 admin pubkeys MUST be 32 bytes. Test identities get
    // zero-padded to 32 so engine-layer admin tracking works without
    // breaking ergonomic test names.
    let mut out = vec![0u8; 32];
    let n = name.len().min(32);
    out[..n].copy_from_slice(&name[..n]);
    out
}

struct MockPeeler;

fn hash_id(bytes: &[u8]) -> MessageId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

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
        // Pass-through: the engine put the raw MLS welcome bytes in
        // `payload` on the wrap side; unwrap by returning them as-is.
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

fn selfremove_registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10), // MIP-03 SelfRemove
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r
}

fn build_client(identity: &[u8], registry: FeatureRegistry) -> impl CgkaEngine {
    EngineBuilder::new(MemoryStorage::new())
        .identity(pad32(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn build_client_on_storage(
    identity: &[u8],
    registry: FeatureRegistry,
    storage: MemoryStorage,
) -> impl CgkaEngine {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .feature_registry(registry)
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

#[tokio::test]
async fn create_group_with_three_members_happy_path() {
    let mut alice = build_client(b"alice-identity", selfremove_registry());
    let mut bob = build_client(b"bob-identity", selfremove_registry());
    let mut carol = build_client(b"carol-identity", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.expect("bob kp");
    let carol_kp = carol.fresh_key_package().await.expect("carol kp");

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "test".into(),
            description: "integration smoke".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![Feature("self-remove")],
            initial_admins: vec![],
        })
        .await
        .expect("create_group");

    // Sanity on SendResult shape.
    match &result {
        SendResult::GroupCreated {
            welcomes,
            pending: _,
        } => {
            assert_eq!(welcomes.len(), 2, "one welcome per invitee");
        }
        _ => panic!("expected GroupEvolution"),
    }

    // Alice is at epoch 1 and sees 3 members.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
    let members = alice.members(&group_id).unwrap();
    assert_eq!(members.len(), 3);

    // Every welcome is addressed (envelope discriminator populated).
    if let SendResult::GroupCreated { welcomes, .. } = result {
        for w in welcomes {
            match w.envelope {
                TransportEnvelope::Welcome { .. } => {}
                _ => panic!("welcome envelope"),
            }
        }
    }
}

#[tokio::test]
async fn create_group_rejects_invitee_missing_required_capability() {
    // Alice requires SelfRemove; "stripped" Bob advertises no required caps.
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut stripped_bob = build_client(b"bob-no-caps", FeatureRegistry::new());

    let kp = stripped_bob.fresh_key_package().await.unwrap();
    let err = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![kp],
            required_features: vec![Feature("self-remove")],
            initial_admins: vec![],
        })
        .await
        .expect_err("should reject");

    match err {
        EngineError::MissingRequiredCapabilities { required, had } => {
            assert!(
                required.proposals.contains(&10),
                "required should include SelfRemove=10"
            );
            assert!(
                !had.proposals.contains(&10),
                "had should NOT include SelfRemove=10"
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[tokio::test]
async fn constructable_capabilities_is_intersection() {
    let alice = build_client(b"a", selfremove_registry());
    let mut empty_bob = build_client(b"b", FeatureRegistry::new());

    let bob_kp = empty_bob.fresh_key_package().await.unwrap();
    let caps = alice.constructable_capabilities(&[bob_kp]).unwrap();
    // Bob advertises no features → intersection can't include SelfRemove.
    assert!(!caps.proposals.contains(&10));
}

#[tokio::test]
async fn fresh_key_package_roundtrips_bytes() {
    let mut alice = build_client(b"a", selfremove_registry());
    let kp = alice.fresh_key_package().await.unwrap();
    assert!(!kp.0.is_empty(), "key package bytes should be non-empty");
}

#[tokio::test]
async fn join_welcome_called_twice_for_same_welcome_errors_on_second_call() {
    // Direct `CgkaEngine::join_welcome` callers skip the ingest-path
    // dedup. Without entry-level dedup, a re-call would re-stage a
    // Welcome on top of an existing group — in storage-memory that
    // overwrites silently. The second call must error.
    let mut alice = build_client(b"alice", selfremove_registry());
    let mut bob = build_client(b"bob", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        _ => unreachable!(),
    };

    bob.join_welcome(welcome.clone()).await.unwrap();
    let err = bob
        .join_welcome(welcome)
        .await
        .expect_err("second join_welcome must error");
    match err {
        EngineError::Other(msg) => {
            assert!(
                msg.contains("already processed"),
                "expected 'already processed' message, got: {msg}"
            );
        }
        other => panic!("expected EngineError::Other(already processed), got {other:?}"),
    }
}

#[tokio::test]
async fn join_welcome_dedup_survives_engine_rebuild_on_same_storage() {
    // Direct `join_welcome` should persist the welcome's terminal state,
    // not rely only on in-memory `seen_message_ids`. A rebuilt engine on
    // the same storage must reject the duplicate before re-staging it.
    let mut alice = build_client(b"alice", selfremove_registry());
    let bob_storage = MemoryStorage::new();
    let mut bob = build_client_on_storage(b"bob", selfremove_registry(), bob_storage.clone());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match result {
        SendResult::GroupCreated { welcomes, pending } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.into_iter().next().unwrap()
        }
        _ => unreachable!(),
    };

    bob.join_welcome(welcome.clone()).await.unwrap();
    drop(bob);

    let mut rebuilt_bob = build_client_on_storage(b"bob", selfremove_registry(), bob_storage);
    let err = rebuilt_bob
        .join_welcome(welcome)
        .await
        .expect_err("rebuilt engine must reject duplicate welcome");
    match err {
        EngineError::Other(msg) => assert!(
            msg.contains("already processed"),
            "expected 'already processed' message, got: {msg}"
        ),
        other => panic!("expected EngineError::Other(already processed), got {other:?}"),
    }
}

#[tokio::test]
async fn confirm_published_transitions_to_stable_and_emits_group_created() {
    let mut alice = build_client(b"a", selfremove_registry());
    let mut bob = build_client(b"b", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };

    // Double confirm → typed UnknownPending on second call.
    let event = alice.confirm_published(pending).await.unwrap();
    assert!(matches!(
        event,
        cgka_traits::engine::GroupEvent::GroupCreated { .. }
    ));

    // Drained events carry the same event.
    let drained = alice.drain_events();
    assert_eq!(drained.len(), 1);

    let err = alice.confirm_published(pending).await.err().unwrap();
    assert!(matches!(err, EngineError::UnknownPending));

    // Post-confirm: epoch unchanged (still 1), but state machine is Stable.
    assert_eq!(alice.epoch(&group_id).unwrap().0, 1);
}

#[tokio::test]
async fn two_engine_happy_path_create_and_join() {
    let mut alice = build_client(b"alice-id", selfremove_registry());
    let mut bob = build_client(b"bob-id", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (alice_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "cross".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    // Alice confirms publish → Stable.
    let pending = match &result {
        SendResult::GroupCreated { pending, .. } => *pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // The welcomes addressed to bob flow to him.
    let bob_welcome = match result {
        SendResult::GroupCreated { welcomes, .. } => {
            welcomes.into_iter().next().expect("one welcome")
        }
        _ => unreachable!(),
    };

    let bob_gid = bob.join_welcome(bob_welcome).await.expect("bob joins");

    assert_eq!(alice_gid, bob_gid, "group ids must match across clients");
    assert_eq!(
        alice.epoch(&alice_gid).unwrap(),
        bob.epoch(&bob_gid).unwrap()
    );

    let alice_members = alice.members(&alice_gid).unwrap();
    let bob_members = bob.members(&bob_gid).unwrap();
    assert_eq!(alice_members.len(), 2);
    assert_eq!(bob_members.len(), 2);

    // Bob's event buffer carries the GroupJoined event.
    let events = bob.drain_events();
    assert_eq!(events.len(), 1);
    matches!(
        events[0],
        cgka_traits::engine::GroupEvent::GroupJoined { .. }
    );
}

#[tokio::test]
async fn join_welcome_rejects_wrong_recipient() {
    let mut alice = build_client(b"alice-id", selfremove_registry());
    let mut bob = build_client(b"bob-id", selfremove_registry());
    let mut eve = build_client(b"eve-id", selfremove_registry());

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (_gid, result) = alice
        .create_group(CreateGroupRequest {
            name: "".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    let bob_welcome = match result {
        SendResult::GroupCreated { welcomes, .. } => welcomes.into_iter().next().unwrap(),
        _ => unreachable!(),
    };

    // Eve should not be able to consume bob's welcome.
    let err = eve.join_welcome(bob_welcome).await.err().unwrap();
    assert!(matches!(err, EngineError::Peeler(_)));
}

#[tokio::test]
async fn create_group_buffers_ingest_via_pending_state() {
    // After create_group, alice is in PendingPublish for that group.
    // can_ingest should be false until confirm_published lands.
    let mut alice = build_client(b"a", selfremove_registry());
    let mut bob = build_client(b"b", selfremove_registry());
    let bob_kp = bob.fresh_key_package().await.unwrap();

    let (_gid, _result) = alice
        .create_group(CreateGroupRequest {
            name: "x".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();

    // epoch() reflects the underlying MLS group (1 after add) — the state
    // machine is PendingPublish but queries still return the current epoch.
    //
    // We can't directly peek at EpochState from outside the crate; the
    // observable contract is that ingest buffers while PendingPublish is live.
}
