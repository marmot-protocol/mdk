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
use cgka_engine::canonicalization::CanonicalizationPolicy;
use cgka_engine::convergence::ConvergencePolicy;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::EngineError;
use cgka_traits::capabilities::GroupCapabilities;
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, AccountDeviceSignerStorage, CapabilityStorage,
    ConvergencePolicyStorage, GroupStorage, LeaveRequest, LeaveRequestStorage,
    MemberValidationCacheStorage, MessageStorage, OutboundIntentStorage, QueuedOutboundIntent,
    StorageError, StorageProvider, StorageResult, WelcomeStorage,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{Backend, EpochId, GroupId, MemberId, MessageId};
use cgka_traits::welcome::PendingWelcome;
use std::sync::Arc;
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

fn build_with_peeler_and_storage(
    id: &[u8],
    peeler: Box<dyn TransportPeeler>,
    storage: SqliteAccountStorage,
) -> impl CgkaEngine {
    EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry_with_reactions())
        .peeler(peeler)
        .build()
        .unwrap()
}

fn build_engine_with_storage(
    id: &[u8],
    storage: SqliteAccountStorage,
) -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry_with_reactions())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap()
}

fn fork_snapshot_names(
    storage: &SqliteAccountStorage,
    gid: &cgka_traits::types::GroupId,
) -> Vec<String> {
    let mut names = storage
        .list_group_snapshots(gid)
        .unwrap()
        .into_iter()
        .filter(|name| name.starts_with("fork-"))
        .collect::<Vec<_>>();
    names.sort();
    names
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

// ── Regression #332: guard releases the pre-commit fork-recovery snapshot ──
//
// The orphan-window cleanup guard (#331 / #149) clears the staged OpenMLS
// pending commit on a failed send, but the invite / auto-commit / upgrade /
// group-data-update paths also create a `fork-{epoch}-{n}-{hash}` recovery
// snapshot *before* the send can fail. The normal `publish_failed` path
// releases that snapshot via `forget_pending_commit_for_recovery`; the guard
// must mirror that so a send that fails inside the armed window does not leak
// a snapshot row. These pre-commit snapshots are not in the retained-anchor
// set, so epoch advancement never GCs them.
#[tokio::test]
async fn invite_wrap_failure_releases_pre_commit_recovery_snapshot() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_with_peeler_and_storage(
        b"alice",
        Box::new(FailFirstGroupWrapPeeler::new()),
        storage.clone(),
    );
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

    // Baseline snapshot rows after a clean group is established. The invite
    // that fails below must not grow this set once the guard fires.
    let baseline = storage.list_group_snapshots(&gid).unwrap().len();

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

    // The pre-commit fork-recovery snapshot created in the armed window must
    // have been released by the guard's Drop — no orphaned snapshot row.
    let after_failure = storage.list_group_snapshots(&gid).unwrap().len();
    assert_eq!(
        after_failure, baseline,
        "failed invite leaked a pre-commit fork-recovery snapshot: \
         baseline={baseline}, after_failure={after_failure}"
    );

    // And the group is still usable: a retry succeeds and converges.
    let carol_kp2 = carol.fresh_key_package().await.unwrap();
    let retry = alice
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp2],
        })
        .await
        .expect("retry after wrap failure must succeed");
    let retry_pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        _ => panic!("expected GroupEvolution"),
    };
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(alice.members(&gid).unwrap().len(), 3);
}

#[tokio::test]
async fn confirmed_commits_prune_fork_recovery_snapshots_to_rewind_horizon() {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut alice = build_engine_with_storage(b"alice", storage.clone());
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

    let policy = CanonicalizationPolicy {
        convergence: ConvergencePolicy {
            max_rewind_commits: 1,
            ..ConvergencePolicy::default()
        },
        ..CanonicalizationPolicy::default()
    };
    alice.set_group_convergence_policy(&gid, policy).unwrap();

    for i in 0..3 {
        let update = alice
            .send(SendIntent::UpdateGroupData {
                group_id: gid.clone(),
                name: Some(format!("g-{i}")),
                description: None,
            })
            .await
            .unwrap();
        let pending = match update {
            SendResult::GroupEvolution { pending, .. } => pending,
            _ => panic!("expected GroupEvolution"),
        };
        alice.confirm_published(pending).await.unwrap();

        let snapshots = fork_snapshot_names(&storage, &gid);
        assert!(
            snapshots.len() <= 1,
            "fork snapshots exceeded max_rewind_commits=1 after update {i}: {snapshots:?}"
        );
    }

    assert_eq!(alice.epoch(&gid).unwrap().0, 4);
    let snapshots = fork_snapshot_names(&storage, &gid);
    assert!(
        !snapshots.is_empty()
            && snapshots
                .iter()
                .all(|snapshot| snapshot.starts_with("fork-3-")),
        "only the current rewind horizon's source epoch should remain: {snapshots:?}"
    );
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

// ── 5. Transient backend lock during confirm is retry-safe ─────────────────
//
// Regression for the "DB-locked-during-commit leaves fork chances" seam: under
// publish-before-apply, `confirm_published` runs after the commit is already on
// the wire. If a storage write during confirm hits `SQLITE_BUSY`, the confirm
// must roll back as a unit and stay *retryable* — the in-memory state-machine
// transition that consumes the pending entry may not run before the durable
// writes commit. Before the fix, the `Processed` message-state write ran AFTER
// `epoch_manager.confirm_publish` had already consumed the pending slot, so a
// lock there advanced the epoch durably yet made a retry fail with
// `UnknownPending` — a half-applied, unrecoverable confirm.

/// Shared, arm-able fault switch: while armed, the next `update_message_state`
/// to `Processed` returns `StorageError::Busy` once, then disarms.
#[derive(Clone, Default)]
struct ProcessedFault(Arc<AtomicUsize>);

impl ProcessedFault {
    fn arm(&self, times: usize) {
        self.0.store(times, Ordering::SeqCst);
    }

    /// True (consuming one armed count) if this call should fail.
    fn should_fail(&self) -> bool {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

/// `SqliteAccountStorage` wrapper that injects a transient `Busy` on the
/// confirm-path `Processed` write. Every other call delegates unchanged.
struct FaultStorage {
    inner: SqliteAccountStorage,
    fault: ProcessedFault,
}

impl GroupStorage for FaultStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        self.inner.put_group(group)
    }
    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        self.inner.get_group(id)
    }
    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        self.inner.delete_group(id)
    }
    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        self.inner.list_groups()
    }
}

impl MessageStorage for FaultStorage {
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        self.inner.put_message(record)
    }
    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        self.inner.get_message(id)
    }
    fn update_message_state(&self, id: &MessageId, new_state: MessageState) -> StorageResult<()> {
        if new_state == MessageState::Processed && self.fault.should_fail() {
            return Err(StorageError::Busy("injected confirm-path lock".into()));
        }
        self.inner.update_message_state(id, new_state)
    }
    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        self.inner.list_messages(group_id, at_or_after_epoch)
    }
    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.inner.create_group_snapshot(group_id, name)
    }
    fn list_group_snapshots(&self, group_id: &GroupId) -> StorageResult<Vec<String>> {
        self.inner.list_group_snapshots(group_id)
    }
    fn rollback_group_to_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.inner.rollback_group_to_snapshot(group_id, name)
    }
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str) -> StorageResult<()> {
        self.inner.release_group_snapshot(group_id, name)
    }
}

impl OutboundIntentStorage for FaultStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()> {
        self.inner.put_queued_outbound_intent(record)
    }
    fn list_queued_outbound_intents(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<QueuedOutboundIntent>> {
        self.inner.list_queued_outbound_intents(group_id)
    }
    fn delete_queued_outbound_intent(&self, id: &MessageId) -> StorageResult<()> {
        self.inner.delete_queued_outbound_intent(id)
    }
}

impl LeaveRequestStorage for FaultStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()> {
        self.inner.put_leave_request(request)
    }
    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>> {
        self.inner.leave_request(group_id)
    }
    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.clear_leave_request(group_id)
    }
}

impl WelcomeStorage for FaultStorage {
    fn put_welcome(&self, welcome: &PendingWelcome) -> StorageResult<()> {
        self.inner.put_welcome(welcome)
    }
    fn take_welcome(&self, id: &MessageId) -> StorageResult<PendingWelcome> {
        self.inner.take_welcome(id)
    }
    fn list_welcomes(&self) -> StorageResult<Vec<PendingWelcome>> {
        self.inner.list_welcomes()
    }
}

impl CapabilityStorage for FaultStorage {
    fn register_feature(&self, feature: Feature, req: CapabilityRequirement) -> StorageResult<()> {
        self.inner.register_feature(feature, req)
    }
    fn feature_requirement(
        &self,
        feature: &Feature,
    ) -> StorageResult<Option<CapabilityRequirement>> {
        self.inner.feature_requirement(feature)
    }
    fn save_member_capabilities(
        &self,
        group_id: &GroupId,
        member: &Member,
        capabilities: GroupCapabilities,
    ) -> StorageResult<()> {
        self.inner
            .save_member_capabilities(group_id, member, capabilities)
    }
    fn member_capabilities(
        &self,
        group_id: &GroupId,
        member_id: &MemberId,
    ) -> StorageResult<Option<GroupCapabilities>> {
        self.inner.member_capabilities(group_id, member_id)
    }
}

impl ConvergencePolicyStorage for FaultStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.inner.put_convergence_policy(group_id, policy)
    }
    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.inner.convergence_policy(group_id)
    }
}

impl MemberValidationCacheStorage for FaultStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.inner.put_validated_tree_marker(group_id, marker)
    }
    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.inner.validated_tree_marker(group_id)
    }
}

impl AccountDeviceSignerStorage for FaultStorage {
    fn put_account_device_signer(&self, binding: &AccountDeviceSignerBinding) -> StorageResult<()> {
        self.inner.put_account_device_signer(binding)
    }
    fn account_device_signer(
        &self,
        marmot_identity: &MemberId,
    ) -> StorageResult<Option<AccountDeviceSignerBinding>> {
        self.inner.account_device_signer(marmot_identity)
    }
}

impl StorageProvider for FaultStorage {
    type Mls = <SqliteAccountStorage as StorageProvider>::Mls;

    fn mls_storage(&self) -> &Self::Mls {
        self.inner.mls_storage()
    }

    fn with_transaction<T, E, F>(&self, f: F) -> Result<T, E>
    where
        Self: Sized,
        E: From<StorageError>,
        F: FnOnce(&Self) -> Result<T, E>,
    {
        // Drive the real SQLite BEGIN/COMMIT on the inner connection, but run
        // the closure against the wrapper so its (delegating, fault-injecting)
        // writes join the same transaction and roll back together.
        self.inner.with_transaction(|_inner| f(self))
    }

    fn backend(&self) -> Backend {
        self.inner.backend()
    }
}

/// Returns the engine plus a storage handle that shares the same underlying
/// connection (`SqliteAccountStorage` is `Clone` over a shared connection), so
/// the test can read durable state out-of-band to assert the rollback invariant.
fn build_fault_engine(
    id: &[u8],
    fault: ProcessedFault,
) -> (cgka_engine::Engine<FaultStorage>, SqliteAccountStorage) {
    let inner = SqliteAccountStorage::in_memory().unwrap();
    let handle = inner.clone();
    let engine = EngineBuilder::new(FaultStorage { inner, fault })
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(registry_with_reactions())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, handle)
}

#[tokio::test]
async fn confirm_published_recovers_from_transient_lock_on_processed_write() {
    let fault = ProcessedFault::default();
    let (mut alice, storage) = build_fault_engine(b"alice", fault.clone());
    let mut bob = build(b"bob");
    let mut carol = build(b"carol");

    // Bootstrap a 2-member group (fault disarmed).
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

    // Invite carol — staged, on the wire, awaiting confirm.
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

    // Durable baseline before the confirm: the invite is staged but unmerged, so
    // the persisted Marmot record still sits at the pre-merge epoch. (`epoch()`
    // reports the *projected* epoch during pending, so it can't witness the
    // rollback — the persisted record can.)
    let persisted_epoch_before = storage.get_group(&gid).unwrap().epoch.0;
    assert_eq!(persisted_epoch_before, 1, "record unmerged before confirm");

    // Arm the lock for the confirm's `Processed` write, then confirm.
    fault.arm(1);
    let first = alice.confirm_published(inv_pending).await;
    let err = first.expect_err("confirm must surface the injected lock, not swallow it");
    assert!(
        err.is_transient(),
        "lock must surface as a transient error, got {err:?}"
    );

    // The durable transaction (merge + record mirror + `Processed` write) rolled
    // back as a unit: the persisted record is still at the pre-merge epoch, so no
    // partial write survived the injected lock. This is the rollback invariant —
    // without it, a half-applied merge could persist while the slot stayed
    // retryable, diverging the record from the MLS state.
    assert_eq!(
        storage.get_group(&gid).unwrap().epoch.0,
        persisted_epoch_before,
        "rolled-back confirm must leave the persisted record unchanged"
    );
    // The pending slot was never consumed either, so the retry below converges.

    // Retrying the SAME pending must now succeed — this is the orphan check.
    // Before the fix, the pending slot was already consumed and this returned
    // `EngineError::UnknownPending`.
    alice
        .confirm_published(inv_pending)
        .await
        .expect("retry after a transient lock must converge, not orphan the commit");

    assert_eq!(alice.epoch(&gid).unwrap().0, 2);
    assert_eq!(
        alice.members(&gid).unwrap().len(),
        3,
        "alice + bob + carol after retried confirm"
    );

    // The slot is now genuinely consumed: a further confirm is UnknownPending.
    let third = alice.confirm_published(inv_pending).await;
    assert!(matches!(third, Err(EngineError::UnknownPending)));
}
