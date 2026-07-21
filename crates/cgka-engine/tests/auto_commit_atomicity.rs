//! Auto-commit staging atomicity (mdk#333).
//!
//! `stage_auto_commit_for_queued_proposal` projects the post-merge group
//! record (epoch N+1, leaver dropped) as part of staging. If any fallible
//! staging step fails after durable state has advanced, the record must not
//! be left torn — epoch/membership disagreeing with the MLS group and the
//! epoch state machine strands auto-commit replay (which bails on any epoch
//! mismatch) and forks the rendered member list from reality.
//!
//! The staging path orders the record write after `begin_pending` and
//! compensates a failed `put_group` by rewinding the state machine, with the
//! armed `PendingCommitCleanupGuard` clearing the staged OpenMLS commit on
//! the early return. This test injects a one-shot `put_group` failure at
//! exactly that point and asserts nothing is torn and the group stays usable.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage};
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
            source: TransportSource("auto-commit-atomicity".into()),
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
            source: TransportSource("auto-commit-atomicity".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

/// Feature registry advertising MIP-03 SelfRemove so the auto-committer fires
/// on a peer's leave proposal.
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

/// Shared, arm-able fault switch: while armed, the next `put_group` fails
/// with `StorageError::Busy` once per armed count, then disarms.
#[derive(Clone, Default)]
struct PutGroupFault(Arc<AtomicUsize>);

impl PutGroupFault {
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

/// `SqliteAccountStorage` wrapper that injects a transient `Busy` on
/// `put_group`. Every other call delegates unchanged.
struct FaultStorage {
    inner: SqliteAccountStorage,
    fault: PutGroupFault,
}

impl GroupStorage for FaultStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        if self.fault.should_fail() {
            return Err(StorageError::Busy("injected put_group failure".into()));
        }
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
        self.inner.update_message_state(id, new_state)
    }
    fn list_messages(
        &self,
        group_id: &GroupId,
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        self.inner.list_messages(group_id, at_or_after_epoch)
    }
    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()> {
        self.inner.put_ingress_dedup_marker(id)
    }
    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool> {
        self.inner.has_ingress_dedup_marker(id)
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

/// Returns the engine plus a storage handle sharing the same underlying
/// connection, so the test can read durable state out-of-band.
fn build_fault_selfremove_client(
    id: &[u8],
    fault: PutGroupFault,
) -> (cgka_engine::Engine<FaultStorage>, SqliteAccountStorage) {
    let inner = SqliteAccountStorage::in_memory().unwrap();
    let handle = inner.clone();
    let engine = EngineBuilder::new(FaultStorage { inner, fault })
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, handle)
}

fn build_selfremove_client(identity: &[u8]) -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

/// A `put_group` failure during auto-commit staging must leave no torn group
/// record (mdk#333): the record stays at the pre-stage epoch with all members,
/// no orphaned pending publish or leaked snapshot survives, and the group
/// remains usable for a fresh commit.
#[tokio::test]
async fn auto_commit_record_write_failure_leaves_no_torn_group_record() {
    let fault = PutGroupFault::default();
    let (mut alice, handle) = build_fault_selfremove_client(b"alice-aca", fault.clone());
    let mut bob = build_selfremove_client(b"bob-aca");
    let mut carol = build_selfremove_client(b"carol-aca");
    let bob_member_id = bob.self_id();

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let carol_kp = carol.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "aca".into(),
            description: "".into(),
            members: vec![bob_kp, carol_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome_for_bob = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome_for_bob).await.unwrap();
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(alice.members(&group_id).unwrap().len(), 3);

    // Bob (non-admin) leaves → SelfRemove proposal; alice (remaining
    // non-target member) schedules the delayed auto-commit on ingest.
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
    let routed = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..proposal
    };
    let outcome = alice.ingest(routed).await.unwrap();
    assert!(matches!(outcome, IngestOutcome::Processed));
    assert!(alice.drain_auto_publish().is_empty());
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;

    let snapshot_baseline = handle.list_group_snapshots(&group_id).unwrap().len();

    // The due auto-commit stages on the convergence tick; fail exactly the
    // record projection's `put_group` (every staging step before it has
    // succeeded by then, including `begin_pending`).
    fault.arm(1);
    let staged = alice.advance_convergence(&group_id).await;
    assert!(
        staged.is_err(),
        "injected put_group failure must surface, got {staged:?}"
    );

    // No torn record: epoch and membership are unchanged...
    let record = handle.get_group(&group_id).unwrap();
    assert_eq!(record.epoch, EpochId(1), "record epoch must not advance");
    assert_eq!(record.members.len(), 3, "no member may be dropped");
    assert!(
        record.members.iter().any(|m| m.id == bob_member_id),
        "bob must survive the failed staging"
    );

    // ...no orphaned pending publish escaped, and the cleanup guard released
    // the pre-commit recovery snapshot (fault is one-shot, so the guard's own
    // cleanup writes succeed).
    assert!(alice.drain_auto_publish().is_empty());
    assert_eq!(
        handle.list_group_snapshots(&group_id).unwrap().len(),
        snapshot_baseline,
        "recovery snapshot must be released on the failed staging"
    );

    // The group stays fully usable: the state machine rewound to Stable, the
    // staged OpenMLS commit was cleared, AND the stored SelfRemove proposal
    // was removed from the proposal store (left behind, OpenMLS 0.8.1 panics
    // when this remove_members filters it against the Remove for bob's
    // leaf). A fresh commit stages, confirms, and lands. (The failed attempt
    // consumed bob's scheduled auto-commit — schedule removal precedes
    // replay by design — so the admin completes the removal explicitly.)
    let evolution = alice
        .send(SendIntent::RemoveMembers {
            group_id: group_id.clone(),
            members: vec![bob_member_id.clone()],
        })
        .await
        .unwrap();
    let pending = match evolution {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let record = handle.get_group(&group_id).unwrap();
    assert_eq!(record.epoch, EpochId(2));
    assert_eq!(record.members.len(), 2);
    assert!(!record.members.iter().any(|m| m.id == bob_member_id));
}
