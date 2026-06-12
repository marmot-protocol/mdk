//! Crash-during-publish recovery at session open (darkmatter#150).
//!
//! The publish-before-apply contract durably persists a staged commit
//! (`MlsGroupState::PendingCommit`) at send time and resolves it only when the
//! application calls `confirm_published` / `publish_failed`. A crash between
//! transport publish and that resolution leaves the staged commit on disk while
//! the in-memory `PendingStateRef` is gone — so without recovery the group is
//! stranded: every later commit-creating operation fails on the leftover
//! pending commit forever.
//!
//! `hydrate_stable_groups_from_storage` (called by `AccountDeviceSession::open`)
//! must detect that surviving pending commit, clear it (treating it as
//! publish-failed), re-derive the Marmot record, and surface a typed
//! `GroupEvent::PendingCommitRecovered` so the app can resync.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, GroupEvent, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

mod support;
use support::proof_signer;

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
            source: TransportSource("pending-commit-recovery".into()),
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
            source: TransportSource("pending-commit-recovery".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn build_client(
    storage: SqliteAccountStorage,
    identity: &[u8],
) -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

/// Feature registry that advertises MIP-03 SelfRemove support so the
/// auto-committer fires on a peer's leave proposal.
fn selfremove_registry() -> FeatureRegistry {
    use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
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

fn build_selfremove_client(
    storage: SqliteAccountStorage,
    identity: &[u8],
) -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

/// Crash after staging an invite (publish-before-apply leaves a persisted
/// `PendingCommit`), then reopen: hydrate must clear the staged commit, roll
/// the Marmot record back to the pre-stage epoch + member set, emit
/// `PendingCommitRecovered`, and leave the group usable for a fresh commit.
#[tokio::test]
async fn reopen_after_crash_during_publish_recovers_stranded_pending_commit() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("pending commit recovery key").unwrap();

    let group_id;

    // ── Phase 1: create + confirm a group, then stage an invite and "crash"
    //    before resolving the publish. ───────────────────────────────────────
    {
        let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
        let bob_store = SqliteAccountStorage::in_memory().unwrap();
        let carol_store = SqliteAccountStorage::in_memory().unwrap();
        let mut alice = build_client(alice_store, b"alice-pcr");
        let mut bob = build_client(bob_store, b"bob-pcr");
        let mut carol = build_client(carol_store, b"carol-pcr");

        let bob_kp = bob.fresh_key_package().await.unwrap();
        let (gid, create) = alice
            .create_group(CreateGroupRequest {
                name: "pcr".into(),
                description: "".into(),
                members: vec![bob_kp],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        group_id = gid.clone();
        let pending = match create {
            SendResult::GroupCreated { pending, .. } => pending,
            other => panic!("expected GroupCreated, got {other:?}"),
        };
        alice.confirm_published(pending).await.unwrap();
        assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
        assert_eq!(alice.members(&group_id).unwrap().len(), 2);

        // Stage an invite of carol. This persists the staged commit to MLS
        // storage but does NOT merge it; the projection puts carol in the
        // member list immediately.
        let carol_kp = carol.fresh_key_package().await.unwrap();
        let invite = alice
            .send(SendIntent::Invite {
                group_id: group_id.clone(),
                key_packages: vec![carol_kp],
            })
            .await
            .unwrap();
        assert!(matches!(invite, SendResult::GroupEvolution { .. }));
        assert_eq!(
            alice.members(&group_id).unwrap().len(),
            3,
            "carol projected pre-confirm"
        );

        // "Crash": drop the engine without calling confirm_published /
        // publish_failed. The pending commit is now stranded on disk.
        drop(alice);
    }

    // ── Phase 2: reopen the same encrypted storage and hydrate. ──────────────
    let reopened_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    // Sanity: the Marmot record still carries the projected (pre-merge) member
    // set written at send time.
    assert_eq!(
        reopened_store.get_group(&group_id).unwrap().members.len(),
        3,
        "stranded projection persisted across the crash"
    );

    let mut alice = build_client(reopened_store, b"alice-pcr");
    alice
        .hydrate_stable_groups_from_storage()
        .expect("hydrate must recover, not error");

    // The recovery event was surfaced so the app can resync.
    let events = alice.drain_events();
    let recovered = events.iter().find_map(|e| match e {
        GroupEvent::PendingCommitRecovered {
            group_id: g,
            recovered_epoch,
        } if g == &group_id => Some(*recovered_epoch),
        _ => None,
    });
    assert_eq!(
        recovered,
        Some(EpochId(1)),
        "expected PendingCommitRecovered at the pre-stage epoch, got events: {events:?}"
    );

    // The group is back at the pre-stage epoch with the staged invite dropped.
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(
        alice.members(&group_id).unwrap().len(),
        2,
        "carol dropped after recovery"
    );

    // The group is no longer wedged: a fresh commit-creating operation must
    // succeed rather than failing on the leftover pending commit.
    let mut carol = build_client(SqliteAccountStorage::in_memory().unwrap(), b"carol-pcr-2");
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let retry = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![carol_kp],
        })
        .await
        .expect("post-recovery invite must succeed");
    let retry_pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(retry_pending).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);
}

/// Regression for the auto-commit leave path (darkmatter#150 follow-up).
///
/// A deferred SelfRemove auto-commit legitimately persists a staged commit
/// across a process boundary: the proposer's device stages the lowest-index
/// commit, projects the departing member out of the Marmot record *forward*,
/// and a later run publishes + confirms it. The crash-recovery clear at
/// hydrate must NOT fire on this surviving commit — rolling it back re-derives
/// the record from the pre-stage MLS state and re-adds the member who already
/// left, forking convergence (the CLI `groups_leave_publishes_self_remove`
/// failure). Hydrate must leave a member-removing staged commit untouched.
#[tokio::test]
async fn reopen_preserves_deferred_selfremove_auto_commit() {
    use cgka_traits::ingest::IngestOutcome;

    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let key = SqlCipherKey::new("deferred selfremove key").unwrap();

    let group_id;
    let bob_member_id;

    // ── Phase 1: create + confirm a 3-member group, then ingest bob's
    //    SelfRemove so alice stages an auto-commit, and "crash" before
    //    resolving the publish. ─────────────────────────────────────────────
    {
        let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
        let bob_store = SqliteAccountStorage::in_memory().unwrap();
        let carol_store = SqliteAccountStorage::in_memory().unwrap();
        let mut alice = build_selfremove_client(alice_store, b"alice-dsr");
        let mut bob = build_selfremove_client(bob_store, b"bob-dsr");
        let mut carol = build_selfremove_client(carol_store, b"carol-dsr");
        bob_member_id = bob.self_id();

        let bob_kp = bob.fresh_key_package().await.unwrap();
        let carol_kp = carol.fresh_key_package().await.unwrap();
        let (gid, create) = alice
            .create_group(CreateGroupRequest {
                name: "dsr".into(),
                description: "".into(),
                members: vec![bob_kp, carol_kp],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        group_id = gid.clone();
        let (welcome_for_bob, _welcome_for_carol) = match create {
            SendResult::GroupCreated {
                pending,
                mut welcomes,
            } => {
                alice.confirm_published(pending).await.unwrap();
                (welcomes.remove(0), welcomes.remove(0))
            }
            other => panic!("expected GroupCreated, got {other:?}"),
        };
        bob.join_welcome(welcome_for_bob).await.unwrap();
        assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
        assert_eq!(alice.members(&group_id).unwrap().len(), 3);

        // Bob (non-admin) leaves → SelfRemove proposal.
        let proposal = match bob
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        {
            SendResult::Proposal { msg } => msg,
            other => panic!("expected Proposal, got {other:?}"),
        };

        // Alice ingests it — she is the lowest-index non-target admin, so the
        // auto-committer stages a commit and projects bob out of the record
        // immediately (epoch advances to the projected value, bob dropped).
        let routed = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: group_id.as_slice().to_vec(),
            },
            ..proposal
        };
        let outcome = alice.ingest(routed).await.unwrap();
        assert!(matches!(outcome, IngestOutcome::Processed));
        assert_eq!(
            alice.members(&group_id).unwrap().len(),
            2,
            "bob projected out at auto-commit stage time"
        );
        // The staged auto-commit exists but has NOT been resolved
        // (confirm/fail). "Crash" by dropping alice with it still pending.
        assert_eq!(alice.drain_auto_publish().len(), 1);
        drop(alice);
    }

    // ── Phase 2: reopen and hydrate. The staged SelfRemove commit must
    //    survive untouched — bob stays removed, no PendingCommitRecovered. ───
    let reopened_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    assert_eq!(
        reopened_store.get_group(&group_id).unwrap().members.len(),
        2,
        "forward-projected leave persisted across the crash"
    );

    let mut alice = build_selfremove_client(reopened_store, b"alice-dsr");
    alice
        .hydrate_stable_groups_from_storage()
        .expect("hydrate must not error on a deferred selfremove");

    let events = alice.drain_events();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, GroupEvent::PendingCommitRecovered { .. })),
        "hydrate must NOT treat a deferred selfremove as a crash strand; got {events:?}"
    );

    // The departing member stays gone — the leave is not rewound.
    let members = alice.members(&group_id).unwrap();
    assert_eq!(members.len(), 2, "bob must remain removed after reopen");
    assert!(
        !members.iter().any(|m| m.id == bob_member_id),
        "bob must not be re-added by recovery; got {members:?}"
    );
}
