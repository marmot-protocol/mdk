//! Publish-before-apply round trips.
//!
//! Covers the four shapes the new `confirm_published` / `publish_failed`
//! contract introduces:
//!
//! 1. `do_send_invite` + `publish_failed` rolls back the projected member
//!    set so the group is immediately re-usable for a fresh invite.
//! 2. `do_upgrade_group_capabilities` + `publish_failed` rolls back the
//!    projected `RequiredCapabilities`.
//! 3. `do_create_group` + `publish_failed` discards the staged add and
//!    leaves the group at solo.
//! 4. Double-confirm and confirm-after-fail both error with
//!    `EngineError::UnknownPending`.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::EngineError;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{MemberId, MessageId};
use std::sync::atomic::{AtomicUsize, Ordering};
use storage_sqlite::SqliteAccountStorage;

mod support;
use support::proof_signer;

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label so admin/member tracking stays stable across a
    // run while the engine accepts the identity.
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
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    bytes.hash(&mut h);
    MessageId::new(h.finish().to_be_bytes().to_vec())
}

struct MockPeeler;

struct FailFirstGroupWrapPeeler {
    inner: MockPeeler,
    remaining_failures: AtomicUsize,
}

impl FailFirstGroupWrapPeeler {
    fn new() -> Self {
        Self {
            inner: MockPeeler,
            remaining_failures: AtomicUsize::new(1),
        }
    }
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

#[async_trait]
impl TransportPeeler for FailFirstGroupWrapPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        self.inner.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        self.inner.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        if self
            .remaining_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(PeelerError::WrapFailed(
                "injected group-wrap failure".into(),
            ));
        }
        self.inner.wrap_group_message(payload, ctx).await
    }

    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        self.inner.wrap_welcome(payload, recipient).await
    }
}

fn registry_with_reactions() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "MIP-03",
        },
    );
    r.register(
        Feature("reactions"),
        CapabilityRequirement {
            requires: Capability::Proposal(0xF210),
            level: RequirementLevel::Optional,
            description: "test-only",
        },
    );
    r
}

fn build(id: &[u8]) -> impl CgkaEngine {
    build_with_peeler(id, Box::new(MockPeeler))
}

fn build_with_peeler(id: &[u8], peeler: Box<dyn TransportPeeler>) -> impl CgkaEngine {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry_with_reactions())
        .peeler(peeler)
        .build()
        .unwrap()
}

// ── 1. Invite + publish_failed → projected member rolls back ───────────────

#[tokio::test]
async fn invite_publish_failed_rolls_back_projected_member_set() {
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
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.members(&gid).unwrap().len(), 2, "alice + bob");
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);

    // Invite carol — projection puts her in the member list immediately.
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let inv_pending = match invite {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    assert_eq!(
        alice.members(&gid).unwrap().len(),
        3,
        "carol projected into member list pre-confirm"
    );
    // EpochState reports the projected new epoch.
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);

    // Transport publish "fails" — engine rolls back.
    alice.publish_failed(inv_pending).await.unwrap();

    // Alice is back at epoch 1 with just alice + bob.
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
    let members = alice.members(&gid).unwrap();
    assert_eq!(members.len(), 2, "carol dropped on rollback: {members:?}");

    // Group is immediately re-usable for a fresh invite.
    let carol_kp2 = carol.fresh_key_package().await.unwrap();
    let retry = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp2],
        })
        .await
        .expect("post-rollback invite must succeed");
    let retry_pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(alice.members(&gid).unwrap().len(), 3);
}

#[tokio::test]
async fn invite_wrap_failure_clears_staged_pending_commit_before_retry() {
    let mut alice = build_with_peeler(b"alice", Box::new(FailFirstGroupWrapPeeler::new()));
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
    assert_eq!(alice.members(&gid).unwrap().len(), 2);

    let carol_kp = carol.fresh_key_package().await.unwrap();
    let err = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .expect_err("first invite should fail at transport wrapping");
    assert!(
        matches!(err, EngineError::Peeler(PeelerError::WrapFailed(_))),
        "unexpected error: {err:?}"
    );
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
    assert_eq!(alice.members(&gid).unwrap().len(), 2);

    let carol_kp2 = carol.fresh_key_package().await.unwrap();
    let retry = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp2],
        })
        .await
        .expect("retry after wrap failure must not hit orphaned OpenMLS PendingCommit");
    let retry_pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(alice.members(&gid).unwrap().len(), 3);
}

// ── 2. Upgrade + publish_failed → required caps roll back ──────────────────

#[tokio::test]
async fn upgrade_publish_failed_rolls_back_required_capabilities() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    alice.confirm_published(pending).await.unwrap();

    // Reactions is upgradeable (both members support it; not required).
    let upgradeable = alice.upgradeable_capabilities(&gid).unwrap();
    assert!(
        upgradeable.proposals.contains(&0xF210),
        "reactions should be upgradeable: {upgradeable:?}"
    );

    let upgrade = alice.upgrade_group_capabilities(&gid).await.unwrap();
    let up_pending = match upgrade {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };

    // Reaction is in EpochState's projected epoch (2). Roll back.
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    alice.publish_failed(up_pending).await.unwrap();

    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
    let still_upgradeable = alice.upgradeable_capabilities(&gid).unwrap();
    assert!(
        still_upgradeable.proposals.contains(&0xF210),
        "reactions should still be upgradeable after rollback: {still_upgradeable:?}"
    );

    // Re-issue the upgrade — must succeed because we're back to Stable.
    let retry = alice.upgrade_group_capabilities(&gid).await.unwrap();
    let retry_pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert!(
        alice
            .upgradeable_capabilities(&gid)
            .unwrap()
            .proposals
            .is_empty(),
        "reactions now Required, no longer upgradeable"
    );
}

// ── 3. Create + publish_failed → group rolls back to solo creator ──────────

#[tokio::test]
async fn create_publish_failed_drops_invitee_and_keeps_solo_alice() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };
    assert_eq!(alice.members(&gid).unwrap().len(), 2, "projected alice+bob");

    alice.publish_failed(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 0);
    assert_eq!(
        alice.members(&gid).unwrap().len(),
        1,
        "post-rollback alice is solo"
    );

    // Alice can immediately re-invite bob via SendIntent::Invite.
    let bob_kp2 = bob.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![bob_kp2],
        })
        .await
        .expect("post-rollback invite must succeed");
    let inv_pending = match invite {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(inv_pending).await.unwrap();
    assert_eq!(alice.members(&gid).unwrap().len(), 2);
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
}

// ── 4. Double-confirm + confirm-after-fail → typed UnknownPending ──────────

#[tokio::test]
async fn double_confirm_and_confirm_after_fail_both_error_unknown_pending() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        _ => unreachable!(),
    };

    // First confirm: ok.
    alice.confirm_published(pending).await.unwrap();
    // Second confirm: typed error.
    let err = alice.confirm_published(pending).await.err().unwrap();
    assert!(matches!(err, EngineError::UnknownPending));

    // Now do an invite + fail it; subsequent confirm on the same ref errors.
    let mut carol = build(b"carol");
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let invite = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .unwrap();
    let inv_pending = match invite {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!(),
    };
    alice.publish_failed(inv_pending).await.unwrap();
    let err = alice.confirm_published(inv_pending).await.err().unwrap();
    assert!(matches!(err, EngineError::UnknownPending));
    let err = alice.publish_failed(inv_pending).await.err().unwrap();
    assert!(matches!(err, EngineError::UnknownPending));
}

// ── 5. Welcome derived during PendingPublish actually works on receiver ────

/// Critical correctness check: the welcome wrapped under publish-before-
/// apply (without merge) carries the post-stage state, so a recipient who
/// joins via that welcome lands at the projected epoch with the same
/// member set the sender expects post-confirm.
#[tokio::test]
async fn welcome_wrapped_pre_merge_lands_recipient_at_post_stage_epoch() {
    let mut alice = build(b"alice");
    let mut bob = build(b"bob");

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (gid, create) = alice
        .create_group(CreateGroupRequest {
            name: "g".into(),
            description: "".into(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcomes) = match create {
        SendResult::GroupCreated { pending, welcomes } => (pending, welcomes),
        _ => unreachable!(),
    };

    // Bob joins via the welcome BEFORE alice confirms.
    let welcome = welcomes.into_iter().next().unwrap();
    let bob_gid = bob.join_welcome(welcome).await.unwrap();
    assert_eq!(bob_gid, gid);
    assert_eq!(bob.epoch(&gid).unwrap().0, 1);
    assert_eq!(bob.members(&gid).unwrap().len(), 2);

    // Alice confirms after bob has already joined — fully legal.
    alice.confirm_published(pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 1);
}
