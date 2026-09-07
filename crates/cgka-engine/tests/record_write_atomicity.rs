//! Storage transaction atomicity under injected faults (mdk#333, mdk#1354).
//!
//! Group-projection tests prove that every seam advancing durable group state
//! projects the Marmot record as part of the same logical step. Leave-proposal
//! tests prove that the sent message, pending leave request, and distinct
//! content marker commit together. In either case, an injected storage failure
//! must not leave durable or in-memory state torn across a session restart.
//!
//! Tests arm one-shot `put_group`, `put_message`, or `put_leave_request`
//! failures at the relevant write seam and assert that nothing is torn, retries
//! remain possible, and the group stays usable.

use async_trait::async_trait;
use cgka_engine::EngineBuilder;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_traits::OutboundFanout;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest, SendIntent,
    SendResult,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, InputRejectionCategory, PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, AccountDeviceSignerStorage, CapabilityStorage,
    ConvergencePassStorage, ConvergencePolicyStorage, DisbandCandidate, DisbandCandidateStorage,
    DisbandRequest, DisbandRequestStorage, DisbandTombstoneStorage, GroupStateCheckpointRef,
    GroupStorage, KeyPackageBundleStorage, LeaveRequest, LeaveRequestStorage,
    MemberValidationCacheStorage, MessageStorage, OutboundFanoutStorage, OutboundIntentStorage,
    QueuedOutboundIntent, StorageError, StorageProvider, StorageResult, StoredKeyPackageBundle,
    WelcomeStorage,
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

/// Hex form of a group message's content-derived dedup id, for comparing
/// against canonicalization-result message ids. Under the pass-through
/// `MockPeeler` the recovered MLS bytes are exactly `msg.payload`.
fn content_hex(msg: &TransportMessage) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(&msg.payload))
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
            source: TransportSource("record-write-atomicity".into()),
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
            source: TransportSource("record-write-atomicity".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

/// Outbound peeler whose transport id is already the content-derived id.
/// This exercises the single-row idempotency path in sent-message persistence.
struct ContentIdPeeler;

#[async_trait]
impl TransportPeeler for ContentIdPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_group_message(msg, ctx).await
    }

    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_welcome(msg).await
    }

    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        _ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        use sha2::{Digest, Sha256};

        Ok(TransportMessage {
            id: MessageId::new(Sha256::digest(&payload.ciphertext).to_vec()),
            payload: payload.ciphertext.clone(),
            timestamp: Timestamp(0),
            causal_deps: vec![],
            source: TransportSource("leave-content-id".into()),
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
        MockPeeler.wrap_welcome(payload, recipient).await
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

/// One-shot fault that fails the Nth capability-cache write after arming.
///
/// Inbound Add commits write the added member first and refresh self second,
/// which lets the regression fail specifically at the post-merge self-cache
/// refresh.
#[derive(Clone, Default)]
struct CapabilityWriteFault(Arc<AtomicUsize>);

impl CapabilityWriteFault {
    fn arm_on_call(&self, call: usize) {
        assert!(call > 0);
        self.0.store(call, Ordering::SeqCst);
    }

    fn should_fail(&self) -> bool {
        matches!(
            self.0
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                }),
            Ok(1)
        )
    }
}

/// One-shot fault that fails the Nth leave-persistence write after arming.
/// The counter is shared by proposal rows, leave requests, and content-marker
/// rows so tests can target every write in their required transaction order.
#[derive(Clone, Default)]
struct LeaveWriteFault(Arc<AtomicUsize>);

impl LeaveWriteFault {
    fn arm_on_write(&self, write: usize) {
        assert!(write > 0);
        self.0.store(write, Ordering::SeqCst);
    }

    fn should_fail(&self) -> bool {
        matches!(
            self.0
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    (remaining > 0).then(|| remaining - 1)
                }),
            Ok(1)
        )
    }

    fn remaining(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

/// `SqliteAccountStorage` wrapper that injects a transient `Busy` on
/// selected record/cache writes. Every other call delegates unchanged.
struct FaultStorage {
    inner: SqliteAccountStorage,
    fault: PutGroupFault,
    capability_fault: CapabilityWriteFault,
    leave_write_fault: LeaveWriteFault,
    intent_write_fault: LeaveWriteFault,
    preparation_delay: PreparationDelay,
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

#[derive(Clone, Default)]
struct PreparationDelay {
    metadata_ms: Arc<AtomicUsize>,
    graph_ms: Arc<AtomicUsize>,
    metadata_calls: Arc<AtomicUsize>,
    graph_calls: Arc<AtomicUsize>,
}

impl MessageStorage for FaultStorage {
    fn list_deferred_message_metadata(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<cgka_traits::message::DeferredMessageMetadata>> {
        self.preparation_delay
            .metadata_calls
            .fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(
            self.preparation_delay.metadata_ms.load(Ordering::SeqCst) as u64,
        ));
        self.inner.list_deferred_message_metadata(group_id)
    }

    fn list_messages_in_states(
        &self,
        group_id: &GroupId,
        states: &[MessageState],
        at_or_after_epoch: EpochId,
    ) -> StorageResult<Vec<MessageRecord>> {
        if states.contains(&MessageState::Processed) {
            self.preparation_delay
                .graph_calls
                .fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(
                self.preparation_delay.graph_ms.load(Ordering::SeqCst) as u64,
            ));
        }
        self.inner
            .list_messages_in_states(group_id, states, at_or_after_epoch)
    }
    fn put_message(&self, record: &MessageRecord) -> StorageResult<()> {
        if self.leave_write_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected leave-persistence write failure".into(),
            ));
        }
        self.inner.put_message(record)
    }
    fn get_message(&self, id: &MessageId) -> StorageResult<MessageRecord> {
        self.inner.get_message(id)
    }
    fn delete_message(&self, id: &MessageId) -> StorageResult<()> {
        self.inner.delete_message(id)
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
    fn put_pending_application_event(
        &self,
        event: &cgka_traits::engine::GroupEvent,
    ) -> StorageResult<()> {
        self.inner.put_pending_application_event(event)
    }
    fn list_pending_application_events(
        &self,
    ) -> StorageResult<Vec<cgka_traits::engine::GroupEvent>> {
        self.inner.list_pending_application_events()
    }
    fn delete_pending_application_events(&self, ids: &[MessageId]) -> StorageResult<()> {
        self.inner.delete_pending_application_events(ids)
    }
    fn put_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<()> {
        self.inner.put_ingress_dedup_marker(id)
    }
    fn has_ingress_dedup_marker(&self, id: &MessageId) -> StorageResult<bool> {
        self.inner.has_ingress_dedup_marker(id)
    }
    fn put_processed_transport_id(
        &self,
        group_id: &GroupId,
        transport_id: &MessageId,
    ) -> StorageResult<()> {
        self.inner
            .put_processed_transport_id(group_id, transport_id)
    }
    fn has_processed_transport_id(&self, transport_id: &MessageId) -> StorageResult<bool> {
        self.inner.has_processed_transport_id(transport_id)
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
    fn create_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint: &GroupStateCheckpointRef,
    ) -> StorageResult<()> {
        self.inner
            .create_group_state_checkpoint(group_id, checkpoint)
    }
    fn restore_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.inner
            .restore_group_state_checkpoint(group_id, checkpoint_id)
    }
    fn list_group_state_checkpoints(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<GroupStateCheckpointRef>> {
        self.inner.list_group_state_checkpoints(group_id)
    }
    fn release_group_state_checkpoint(
        &self,
        group_id: &GroupId,
        checkpoint_id: &str,
    ) -> StorageResult<()> {
        self.inner
            .release_group_state_checkpoint(group_id, checkpoint_id)
    }
}

impl OutboundIntentStorage for FaultStorage {
    fn put_queued_outbound_intent(&self, record: &QueuedOutboundIntent) -> StorageResult<()> {
        if self.intent_write_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected queued intent write failure".into(),
            ));
        }
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
    fn put_own_commit_intent(
        &self,
        record: &cgka_traits::storage::OwnCommitIntent,
    ) -> StorageResult<()> {
        if self.intent_write_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected own intent write failure".into(),
            ));
        }
        self.inner.put_own_commit_intent(record)
    }
    fn own_commit_intent(
        &self,
        commit_id: &MessageId,
    ) -> StorageResult<Option<cgka_traits::storage::OwnCommitIntent>> {
        self.inner.own_commit_intent(commit_id)
    }
    fn list_own_commit_intents(
        &self,
        group_id: Option<&GroupId>,
    ) -> StorageResult<Vec<cgka_traits::storage::OwnCommitIntent>> {
        self.inner.list_own_commit_intents(group_id)
    }
    fn delete_own_commit_intent(&self, commit_id: &MessageId) -> StorageResult<()> {
        if self.intent_write_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected own intent delete failure".into(),
            ));
        }
        self.inner.delete_own_commit_intent(commit_id)
    }
}

impl OutboundFanoutStorage for FaultStorage {
    fn put_outbound_fanout(&self, fanout: &OutboundFanout) -> StorageResult<()> {
        self.inner.put_outbound_fanout(fanout)
    }
    fn outbound_fanout(&self, id: &MessageId) -> StorageResult<Option<OutboundFanout>> {
        self.inner.outbound_fanout(id)
    }
    fn list_outbound_fanouts(&self) -> StorageResult<Vec<OutboundFanout>> {
        self.inner.list_outbound_fanouts()
    }
    fn list_outbound_fanouts_for_group(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Vec<OutboundFanout>> {
        self.inner.list_outbound_fanouts_for_group(group_id)
    }
    fn delete_outbound_fanout(&self, id: &MessageId) -> StorageResult<()> {
        self.inner.delete_outbound_fanout(id)
    }
}

impl LeaveRequestStorage for FaultStorage {
    fn put_leave_request(&self, request: &LeaveRequest) -> StorageResult<()> {
        if self.leave_write_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected leave-persistence write failure".into(),
            ));
        }
        self.inner.put_leave_request(request)
    }
    fn leave_request(&self, group_id: &GroupId) -> StorageResult<Option<LeaveRequest>> {
        self.inner.leave_request(group_id)
    }
    fn clear_leave_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.clear_leave_request(group_id)
    }
}

impl DisbandRequestStorage for FaultStorage {
    fn put_disband_request(&self, request: &DisbandRequest) -> StorageResult<()> {
        self.inner.put_disband_request(request)
    }
    fn disband_request(&self, group_id: &GroupId) -> StorageResult<Option<DisbandRequest>> {
        self.inner.disband_request(group_id)
    }
    fn clear_disband_request(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.clear_disband_request(group_id)
    }
}

impl DisbandCandidateStorage for FaultStorage {
    fn put_disband_candidate(&self, candidate: &DisbandCandidate) -> StorageResult<()> {
        self.inner.put_disband_candidate(candidate)
    }
    fn disband_candidate(
        &self,
        group_id: &GroupId,
        commit_id: &MessageId,
    ) -> StorageResult<Option<DisbandCandidate>> {
        self.inner.disband_candidate(group_id, commit_id)
    }
    fn list_disband_candidates(&self, group_id: &GroupId) -> StorageResult<Vec<DisbandCandidate>> {
        self.inner.list_disband_candidates(group_id)
    }
    fn clear_disband_candidates(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.clear_disband_candidates(group_id)
    }
}

impl DisbandTombstoneStorage for FaultStorage {
    fn put_disband_tombstone(
        &self,
        group_id: &GroupId,
        tombstone: &cgka_traits::DisbandTombstone,
    ) -> StorageResult<()> {
        self.inner.put_disband_tombstone(group_id, tombstone)
    }
    fn disband_tombstone(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<cgka_traits::DisbandTombstone>> {
        self.inner.disband_tombstone(group_id)
    }
    fn list_disband_tombstones(
        &self,
    ) -> StorageResult<Vec<(GroupId, cgka_traits::DisbandTombstone)>> {
        self.inner.list_disband_tombstones()
    }

    fn mark_disband_tombstone_announced(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.mark_disband_tombstone_announced(group_id)
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
        if self.capability_fault.should_fail() {
            return Err(StorageError::Busy(
                "injected capability-cache write failure".into(),
            ));
        }
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

impl KeyPackageBundleStorage for FaultStorage {
    fn stored_key_package_bundles(&self) -> StorageResult<Vec<StoredKeyPackageBundle>> {
        self.inner.stored_key_package_bundles()
    }

    fn delete_stored_key_package_bundle(&self, storage_key: &[u8]) -> StorageResult<()> {
        self.inner.delete_stored_key_package_bundle(storage_key)
    }
}

impl ConvergencePassStorage for FaultStorage {
    fn convergence_pass(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<cgka_traits::DurableConvergencePass>> {
        self.inner.convergence_pass(group_id)
    }

    fn put_convergence_pass(
        &self,
        pass: &cgka_traits::DurableConvergencePass,
    ) -> StorageResult<()> {
        self.inner.put_convergence_pass(pass)
    }

    fn list_convergence_passes(&self) -> StorageResult<Vec<cgka_traits::DurableConvergencePass>> {
        self.inner.list_convergence_passes()
    }

    fn delete_convergence_pass(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.delete_convergence_pass(group_id)
    }
}

impl cgka_traits::storage::DeferredPeelGenerationStorage for FaultStorage {
    fn deferred_peel_generation(
        &self,
        group_id: &GroupId,
    ) -> StorageResult<Option<cgka_traits::storage::DeferredPeelGeneration>> {
        self.inner.deferred_peel_generation(group_id)
    }

    fn put_deferred_peel_generation(
        &self,
        generation: &cgka_traits::storage::DeferredPeelGeneration,
    ) -> StorageResult<()> {
        self.inner.put_deferred_peel_generation(generation)
    }

    fn delete_deferred_peel_generation(&self, group_id: &GroupId) -> StorageResult<()> {
        self.inner.delete_deferred_peel_generation(group_id)
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
    let engine = EngineBuilder::new(FaultStorage {
        inner,
        fault,
        capability_fault: CapabilityWriteFault::default(),
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: LeaveWriteFault::default(),
        preparation_delay: PreparationDelay::default(),
    })
    .legacy_compatibility_profile()
    .identity(pad32(id))
    .account_identity_proof_signer(proof_signer(id))
    .feature_registry(selfremove_registry())
    .peeler(Box::new(MockPeeler))
    .build()
    .unwrap();
    (engine, handle)
}

fn build_capability_fault_client(
    id: &[u8],
    capability_fault: CapabilityWriteFault,
) -> (cgka_engine::Engine<FaultStorage>, SqliteAccountStorage) {
    let inner = SqliteAccountStorage::in_memory().unwrap();
    let handle = inner.clone();
    let engine = EngineBuilder::new(FaultStorage {
        inner,
        fault: PutGroupFault::default(),
        capability_fault,
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: LeaveWriteFault::default(),
        preparation_delay: PreparationDelay::default(),
    })
    .legacy_compatibility_profile()
    .identity(pad32(id))
    .account_identity_proof_signer(proof_signer(id))
    .feature_registry(selfremove_registry())
    .peeler(Box::new(MockPeeler))
    .build()
    .unwrap();
    (engine, handle)
}

fn build_leave_write_fault_client(
    identity: &[u8],
    leave_write_fault: LeaveWriteFault,
    peeler: Box<dyn TransportPeeler>,
) -> (cgka_engine::Engine<FaultStorage>, SqliteAccountStorage) {
    let inner = SqliteAccountStorage::in_memory().unwrap();
    let handle = inner.clone();
    let engine = EngineBuilder::new(FaultStorage {
        inner,
        fault: PutGroupFault::default(),
        capability_fault: CapabilityWriteFault::default(),
        leave_write_fault,
        intent_write_fault: LeaveWriteFault::default(),
        preparation_delay: PreparationDelay::default(),
    })
    .legacy_compatibility_profile()
    .identity(pad32(identity))
    .account_identity_proof_signer(proof_signer(identity))
    .feature_registry(selfremove_registry())
    .peeler(peeler)
    .build()
    .expect("build fault-injecting engine");
    (engine, handle)
}

fn build_selfremove_client_on_storage(
    identity: &[u8],
    storage: SqliteAccountStorage,
) -> cgka_engine::Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn build_selfremove_client(identity: &[u8]) -> cgka_engine::Engine<SqliteAccountStorage> {
    build_selfremove_client_on_storage(identity, SqliteAccountStorage::in_memory().unwrap())
}

async fn setup_leave_fault_case(
    identity: &[u8],
    fault: LeaveWriteFault,
    peeler: Box<dyn TransportPeeler>,
) -> (
    cgka_engine::Engine<FaultStorage>,
    SqliteAccountStorage,
    GroupId,
) {
    let mut alice = build_selfremove_client(b"alice-leave-write-atomic");
    let (mut bob, bob_storage) = build_leave_write_fault_client(identity, fault, peeler);
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "leave write atomicity".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();
    (bob, bob_storage, group_id)
}

/// The proposal row, durable leave request, and distinct content marker are one
/// transaction. A fault at any write leaves both durable and hot leave state
/// untouched, and the same epoch remains retryable after reopening.
#[tokio::test]
async fn leave_persistence_failure_rolls_back_every_transactional_write() {
    for fail_on_write in 1..=3 {
        let identity = format!("bob-leave-write-{fail_on_write}");
        let fault = LeaveWriteFault::default();
        let (mut bob, bob_storage, group_id) =
            setup_leave_fault_case(identity.as_bytes(), fault.clone(), Box::new(MockPeeler)).await;
        let epoch = bob.epoch(&group_id).unwrap();
        let rows_before = bob_storage.list_messages(&group_id, EpochId(0)).unwrap();

        fault.arm_on_write(fail_on_write);
        let failed = bob
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await;
        assert!(
            matches!(failed, Err(EngineError::Storage(StorageError::Busy(_)))),
            "write {fail_on_write} must surface its storage fault, got {failed:?}"
        );
        assert_eq!(
            bob_storage.list_messages(&group_id, EpochId(0)).unwrap(),
            rows_before,
            "write {fail_on_write} must not leave a proposal or content marker"
        );
        assert!(
            bob_storage.leave_request(&group_id).unwrap().is_none(),
            "write {fail_on_write} must not leave last_proposed_epoch"
        );

        // The hot leave gate is seeded only after the complete transaction.
        // Reopening from the same storage must therefore see no leave state and
        // accept a same-epoch retry.
        drop(bob);
        let mut reopened =
            build_selfremove_client_on_storage(identity.as_bytes(), bob_storage.clone());
        reopened.hydrate_all_stored_groups().unwrap();
        assert_eq!(reopened.epoch(&group_id).unwrap(), epoch);
        let retry = reopened
            .send(SendIntent::Leave {
                group_id: group_id.clone(),
            })
            .await;
        assert!(
            matches!(retry, Ok(SendResult::Proposal { .. })),
            "write {fail_on_write} must leave the same epoch retryable, got {retry:?}"
        );
    }
}

/// When the transport id already equals the content-derived id, persistence
/// writes one proposal row rather than trying to insert a duplicate marker.
#[tokio::test]
async fn leave_persistence_skips_duplicate_content_marker_write() {
    let fault = LeaveWriteFault::default();
    let (mut bob, bob_storage, group_id) = setup_leave_fault_case(
        b"bob-leave-content-id",
        fault.clone(),
        Box::new(ContentIdPeeler),
    )
    .await;
    let rows_before = bob_storage.list_messages(&group_id, EpochId(0)).unwrap();

    fault.arm_on_write(3);
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
    assert_eq!(
        proposal.id,
        MessageId::new(<sha2::Sha256 as sha2::Digest>::digest(&proposal.payload).to_vec())
    );
    assert_eq!(
        fault.remaining(),
        1,
        "equal transport/content ids must skip the third marker write"
    );
    assert_eq!(
        bob_storage
            .list_messages(&group_id, EpochId(0))
            .unwrap()
            .len(),
        rows_before.len() + 1,
        "successful leave should add one canonical proposal row"
    );
}

/// A backend failure after OpenMLS consumes the joining KeyPackage must roll
/// the complete Welcome attempt back. The identical transport object remains
/// retryable and no terminal ingress marker may escape the failed attempt.
#[tokio::test]
async fn welcome_record_failure_restores_key_package_for_retry() {
    let mut alice = build_selfremove_client(b"alice-welcome-atomic");
    let fault = PutGroupFault::default();
    let (mut bob, bob_storage) =
        build_fault_selfremove_client(b"bob-welcome-atomic", fault.clone());

    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "welcome atomicity".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let (pending, welcome) = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => (pending, welcomes.remove(0)),
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    fault.arm(1);
    let failed = bob
        .join_welcome(welcome.clone())
        .await
        .expect_err("injected group-record write must fail the join");
    assert!(
        matches!(failed, EngineError::Storage(StorageError::Busy(_))),
        "storage fault must stay retryable, got {failed:?}"
    );
    assert!(
        !bob_storage.has_ingress_dedup_marker(&welcome.id).unwrap(),
        "failed attempt must not leave a terminal transport marker"
    );
    assert!(
        matches!(
            bob_storage.get_group(&group_id),
            Err(StorageError::NotFound)
        ),
        "failed attempt must not leave a discoverable group"
    );

    let joined = bob
        .join_welcome(welcome.clone())
        .await
        .expect("the identical Welcome must succeed after the transient fault");
    assert_eq!(joined, group_id);
    assert!(
        bob_storage.has_ingress_dedup_marker(&welcome.id).unwrap(),
        "successful attempt must commit its transport marker"
    );
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

/// A same-epoch rival that wins branch selection is applied by the
/// convergence pass, which mirrors the selected epoch into the durable group
/// record. A storage fault at that mirror must not leave the engine reporting
/// one epoch while the record holds another: hydration seeds the in-memory
/// epoch FROM that record, so an in-process split becomes a wrong epoch on
/// the next session open.
///
/// The winning commit stays durably retained across the failure, so a later
/// pass (the fault is transient) must still reorg the loser onto the winning
/// branch, after which redelivery is a plain duplicate — never a `Buffered`
/// promise of a replay that would never come.
#[tokio::test]
async fn inbound_apply_record_mirror_failure_does_not_split_epoch_state() {
    let alice_fault = PutGroupFault::default();
    let bob_fault = PutGroupFault::default();
    let (mut alice, alice_handle) =
        build_fault_selfremove_client(b"alice-mirror", alice_fault.clone());
    let (mut bob, bob_handle) = build_fault_selfremove_client(b"bob-mirror", bob_fault.clone());
    let mut david = build_selfremove_client(b"david-mirror");
    let mut eve = build_selfremove_client(b"eve-mirror");

    // Alice and bob are co-admins at epoch 1, so both can publish a privileged
    // invite commit from the same epoch.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "mirror".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(welcome).await.unwrap();

    // Concurrent invites at epoch 1: neither admin has seen the other's commit.
    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let alice_commit = match alice_invite {
        SendResult::GroupEvolution { msg, pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let bob_commit = match bob_invite {
        SendResult::GroupEvolution { msg, pending, .. } => {
            bob.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    // The authenticated ordering key decides which side rolls back; both sides
    // are fault-injectable so the test never depends on which one that is.
    let ordering_key = |committer: MemberId, commit: &TransportMessage| {
        CommitOrderingKey::from_commit_bytes(
            EpochId(1),
            CommitOrderingPriority::Privileged,
            committer,
            &commit.payload,
        )
    };
    let bob_wins =
        ordering_key(bob.self_id(), &bob_commit) < ordering_key(alice.self_id(), &alice_commit);
    let (loser, loser_handle, loser_fault, winning_commit) = if bob_wins {
        (&mut alice, &alice_handle, &alice_fault, bob_commit)
    } else {
        (&mut bob, &bob_handle, &bob_fault, alice_commit)
    };
    assert_eq!(loser.epoch(&group_id).unwrap(), EpochId(2));

    // The winning rival routes into distributed convergence like any other
    // same-epoch fork commit.
    let routed_winner = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..winning_commit
    };
    let ingested = loser.ingest(routed_winner.clone()).await.unwrap();
    assert!(
        matches!(ingested, IngestOutcome::Buffered { .. }),
        "the winning rival must enter convergence, got {ingested:?}"
    );

    // Fail exactly the epoch mirror's record write inside the settling pass's
    // apply of the selected branch.
    loser_fault.arm(1);
    let faulted = loser.converge_stored_openmls_messages_at(&group_id, u64::MAX);
    assert!(
        faulted.is_err(),
        "the storage fault must surface from the settling pass, got {faulted:?}"
    );

    // Both stores stay consistent across the failed apply: engine and durable
    // record agree on epoch and roster (the loser keeps its own branch until
    // a pass actually lands the winner).
    let record = loser_handle.get_group(&group_id).unwrap();
    assert_eq!(
        loser.epoch(&group_id).unwrap(),
        record.epoch,
        "the engine's epoch and the durable record must never split"
    );
    assert_eq!(
        loser
            .members(&group_id)
            .expect("group must stay live")
            .len(),
        record.members.len(),
        "the engine's roster and the durable record must never split"
    );

    // The fault is transient and one-shot: the retained winner must still
    // land on the next pass.
    let recovered = loser
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the retry pass settles after the transient fault");
    assert!(
        recovered
            .accepted_commits
            .contains(&content_hex(&routed_winner)),
        "convergence must accept the retained winning commit, got {:?}",
        recovered.accepted_commits
    );
    assert_eq!(
        loser.epoch(&group_id).unwrap(),
        EpochId(2),
        "the convergence pass must eventually apply the winner"
    );
    let record = loser_handle.get_group(&group_id).unwrap();
    assert_eq!(record.epoch, EpochId(2));
    assert_eq!(
        loser.members(&group_id).expect("group stays live").len(),
        3,
        "the winner's invitee joins the roster"
    );
    assert_eq!(record.members.len(), 3);

    // With the winner applied, redelivery is a plain duplicate — not a
    // `Buffered` promise of a replay that would never come.
    let redelivered = loser.ingest(routed_winner).await;
    assert!(
        matches!(
            redelivered,
            Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate
            })
        ),
        "redelivery after recovery must be a duplicate, got {redelivered:?}"
    );
}

/// A failure refreshing self capabilities occurs after the MLS merge and group
/// record write. All inbound projections must roll back together, and the
/// retained commit must be handed to stored convergence for retry (mdk#794).
#[tokio::test]
async fn inbound_self_capability_mirror_failure_rolls_back_and_reschedules() {
    let alice_fault = CapabilityWriteFault::default();
    let bob_fault = CapabilityWriteFault::default();
    let (mut alice, alice_storage) =
        build_capability_fault_client(b"alice-inbound-cap-atomic", alice_fault.clone());
    let (mut bob, bob_storage) =
        build_capability_fault_client(b"bob-inbound-cap-atomic", bob_fault.clone());
    let mut david = build_selfremove_client(b"david-inbound-cap-atomic");
    let mut eve = build_selfremove_client(b"eve-inbound-cap-atomic");
    let david_id = david.self_id();
    let eve_id = eve.self_id();

    // Alice and Bob are co-admins at epoch 1, so they can publish competing
    // privileged invite commits from the same source epoch.
    let bob_kp = bob.fresh_key_package().await.unwrap();
    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "inbound capability atomicity".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![bob.self_id()],
        })
        .await
        .unwrap();
    let bob_welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            alice.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    bob.join_welcome(bob_welcome).await.unwrap();
    alice.drain_pending_convergence_groups();
    bob.drain_pending_convergence_groups();

    let david_kp = david.fresh_key_package().await.unwrap();
    let eve_kp = eve.fresh_key_package().await.unwrap();
    let alice_invite = alice
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![david_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let bob_invite = bob
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![eve_kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let alice_commit = match alice_invite {
        SendResult::GroupEvolution { msg, pending, .. } => {
            alice.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let bob_commit = match bob_invite {
        SendResult::GroupEvolution { msg, pending, .. } => {
            bob.confirm_published(pending).await.unwrap();
            msg
        }
        other => panic!("expected GroupEvolution, got {other:?}"),
    };

    let ordering_key = |committer: MemberId, commit: &TransportMessage| {
        CommitOrderingKey::from_commit_bytes(
            EpochId(1),
            CommitOrderingPriority::Privileged,
            committer,
            &commit.payload,
        )
    };
    let bob_wins =
        ordering_key(bob.self_id(), &bob_commit) < ordering_key(alice.self_id(), &alice_commit);
    let (loser, loser_storage, loser_fault, winning_commit, winning_invitee) = if bob_wins {
        (&mut alice, &alice_storage, &alice_fault, bob_commit, eve_id)
    } else {
        (&mut bob, &bob_storage, &bob_fault, alice_commit, david_id)
    };
    let routed_winner = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..winning_commit
    };

    assert_eq!(loser.epoch(&group_id).unwrap(), EpochId(2));
    assert!(
        loser_storage
            .member_capabilities(&group_id, &winning_invitee)
            .unwrap()
            .is_none()
    );

    // The winning rival routes into distributed convergence like any other
    // same-epoch fork commit.
    let ingested = loser.ingest(routed_winner.clone()).await.unwrap();
    assert!(
        matches!(ingested, IngestOutcome::Buffered { .. }),
        "the winning rival must enter convergence, got {ingested:?}"
    );

    // The added-member cache write is first; fail the self refresh after the
    // merge and group-record write have both run inside the settling pass's
    // apply transaction.
    loser_fault.arm_on_call(2);
    let faulted = loser.converge_stored_openmls_messages_at(&group_id, u64::MAX);
    assert!(
        faulted.is_err(),
        "self-capability mirror failure must surface from the settling pass, got {faulted:?}"
    );

    // All inbound projections roll back together: engine and record agree,
    // and the added-member cache write did not outlive the failed self
    // refresh.
    let record = loser_storage.get_group(&group_id).unwrap();
    assert_eq!(loser.epoch(&group_id).unwrap(), record.epoch);
    assert_eq!(
        loser.members(&group_id).unwrap().len(),
        record.members.len()
    );
    assert!(
        loser_storage
            .member_capabilities(&group_id, &winning_invitee)
            .unwrap()
            .is_none(),
        "the added-member cache write must roll back with the failed self refresh"
    );

    // The fault is transient and one-shot: the retained winner lands on the
    // next pass.
    loser
        .converge_stored_openmls_messages_at(&group_id, u64::MAX)
        .expect("the retry pass settles after the transient fault");

    let record = loser_storage.get_group(&group_id).unwrap();
    assert_eq!(loser.epoch(&group_id).unwrap(), EpochId(2));
    assert_eq!(record.epoch, EpochId(2));
    assert_eq!(loser.members(&group_id).unwrap().len(), 3);
    assert_eq!(record.members.len(), 3);
    assert!(
        loser_storage
            .member_capabilities(&group_id, &winning_invitee)
            .unwrap()
            .is_some(),
        "stored convergence must rebuild the added member's capability cache"
    );

    let redelivered = loser.ingest(routed_winner).await;
    assert!(
        matches!(
            redelivered,
            Ok(IngestOutcome::Ignored {
                category: InputRejectionCategory::Duplicate
            })
        ),
        "redelivery after convergence recovery must be a duplicate, got {redelivered:?}"
    );
}

/// A profile projection failure occurs after the MLS commit is staged. It must
/// rewind the pending state and clear the staged commit rather than leaving a
/// projected record that no caller can confirm or roll back (mdk#824).
#[tokio::test]
async fn update_group_data_record_write_failure_leaves_group_stable() {
    let fault = PutGroupFault::default();
    let (mut alice, handle) = build_fault_selfremove_client(b"alice-ugd", fault.clone());

    let (group_id, create) = alice
        .create_group(CreateGroupRequest {
            name: "original".into(),
            description: "preserve me".into(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let pending = match create {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();
    let snapshot_baseline = handle.list_group_snapshots(&group_id).unwrap().len();

    fault.arm(1);
    let failed = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("failed rename".into()),
            description: None,
        })
        .await;
    assert!(failed.is_err(), "injected projection failure must surface");

    let record = handle.get_group(&group_id).unwrap();
    assert_eq!(record.name, "original");
    assert_eq!(record.description, "preserve me");
    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(0));
    assert_eq!(
        handle.list_group_snapshots(&group_id).unwrap().len(),
        snapshot_baseline,
        "failed staging must release its recovery snapshot"
    );

    let retry = alice
        .send(SendIntent::UpdateGroupData {
            group_id: group_id.clone(),
            name: Some("successful rename".into()),
            description: None,
        })
        .await
        .expect("group must remain usable after compensation");
    let pending = match retry {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    alice.confirm_published(pending).await.unwrap();

    let record = handle.get_group(&group_id).unwrap();
    assert_eq!(record.name, "successful rename");
    assert_eq!(record.description, "preserve me");
}

/// Opaque input remains retryable; it lets this test distinguish a completed
/// failed peel (durable attempt) from a slice that never reaches the peeler.
struct OpaquePeeler;

#[async_trait]
impl TransportPeeler for OpaquePeeler {
    async fn peel_group_message(
        &self,
        _msg: &TransportMessage,
        _ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        Err(PeelerError::DecryptFailed)
    }
    async fn peel_welcome(&self, msg: &TransportMessage) -> Result<PeeledMessage, PeelerError> {
        MockPeeler.peel_welcome(msg).await
    }
    async fn wrap_group_message(
        &self,
        payload: &EncryptedPayload,
        ctx: &GroupContextSnapshot,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_group_message(payload, ctx).await
    }
    async fn wrap_welcome(
        &self,
        payload: &EncryptedPayload,
        recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        MockPeeler.wrap_welcome(payload, recipient).await
    }
}

async fn slow_preparation_case(
    backlog: usize,
) -> (
    cgka_engine::Engine<FaultStorage>,
    SqliteAccountStorage,
    GroupId,
    Vec<MessageId>,
    PreparationDelay,
) {
    let delay = PreparationDelay::default();
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut bob = EngineBuilder::new(FaultStorage {
        inner: storage.clone(),
        fault: PutGroupFault::default(),
        capability_fault: CapabilityWriteFault::default(),
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: LeaveWriteFault::default(),
        preparation_delay: delay.clone(),
    })
    .legacy_compatibility_profile()
    .identity(pad32(b"slow-preparation"))
    .account_identity_proof_signer(proof_signer(b"slow-preparation"))
    .peeler(Box::new(OpaquePeeler))
    .build()
    .unwrap();
    let (group_id, created) = bob
        .create_group(CreateGroupRequest {
            name: "slow preparation".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = created else {
        panic!("group creation");
    };
    bob.confirm_published(pending).await.unwrap();
    let message = TransportMessage {
        id: MessageId::new(b"slow-preparation-opaque".to_vec()),
        payload: vec![42; 32],
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("test".into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
    };
    let mut ids = Vec::new();
    for index in 0..backlog {
        let message = TransportMessage {
            id: MessageId::new(format!("slow-preparation-{index}").into_bytes()),
            ..message.clone()
        };
        assert!(matches!(
            bob.ingest(message.clone()).await.unwrap(),
            IngestOutcome::TransportDeferred { .. }
        ));
        ids.push(message.id);
    }
    (bob, storage, group_id, ids, delay)
}

fn deferred_attempts(storage: &SqliteAccountStorage, ids: &[MessageId]) -> u32 {
    ids.iter()
        .map(|id| {
            storage
                .get_message(id)
                .unwrap()
                .deferred_peel
                .unwrap()
                .distinct_context_attempts
        })
        .sum()
}

async fn assert_slow_preparation_makes_durable_progress(metadata: bool) {
    let (mut bob, storage, group_id, ids, delay) = slow_preparation_case(4).await;
    let before = deferred_attempts(&storage, &ids);
    delay.metadata_calls.store(0, Ordering::SeqCst);
    delay.graph_calls.store(0, Ordering::SeqCst);
    let selected = if metadata {
        &delay.metadata_ms
    } else {
        &delay.graph_ms
    };
    selected.store(600, Ordering::SeqCst);
    for _ in 0..3 {
        bob.advance_convergence(&group_id).await.unwrap();
    }
    let attempts = deferred_attempts(&storage, &ids);
    eprintln!(
        "slow preparation: metadata={metadata}, attempts_before={before}, attempts_after={attempts}, metadata_calls={}, graph_calls={}",
        delay.metadata_calls.load(Ordering::SeqCst),
        delay.graph_calls.load(Ordering::SeqCst)
    );
    // Positive control: identical durable work succeeds through the explicit-time
    // API. Its deterministic row allowance still applies, but it has no deadline.
    bob.advance_convergence_inputs_until_settled(&group_id, 1_000_000)
        .await
        .unwrap();
    let control = deferred_attempts(&storage, &ids);
    assert!(
        control > before,
        "control must perform real decryption work"
    );
    assert_eq!(
        attempts, 3,
        "each expired slice must finish exactly one row"
    );
}

#[tokio::test]
async fn slow_metadata_preparation_does_not_starve_background_retries() {
    assert_slow_preparation_makes_durable_progress(true).await;
}

#[tokio::test]
async fn slow_fingerprint_preparation_does_not_starve_background_retries() {
    assert_slow_preparation_makes_durable_progress(false).await;
}

/// Restart/legacy normalization is a durable work unit, so a slow read must
/// neither prevent it nor cause the same call to exceed its 64-row allowance.
#[tokio::test]
async fn slow_preparation_normalizes_bounded_slices_before_peeling() {
    let (mut bob, storage, group_id, ids, delay) = slow_preparation_case(96).await;
    for id in &ids {
        let mut row = storage.get_message(id).unwrap();
        row.deferred_peel = None;
        storage.put_message(&row).unwrap();
    }
    delay.metadata_ms.store(600, Ordering::SeqCst);
    bob.advance_convergence(&group_id).await.unwrap();
    let normalized = ids
        .iter()
        .filter(|id| storage.get_message(id).unwrap().deferred_peel.is_some())
        .count();
    assert_eq!(normalized, 64, "normalization must obey the row allowance");
    bob.advance_convergence(&group_id).await.unwrap();
    assert_eq!(
        deferred_attempts(&storage, &ids),
        0,
        "normalization consumes the expired slice"
    );
    bob.advance_convergence(&group_id).await.unwrap();
    assert_eq!(
        deferred_attempts(&storage, &ids),
        1,
        "the next slice must reach a peel"
    );
}

/// Due rows spend the one progress allowance on release, rather than being
/// retried after expiry or all released in a single already-expired quantum.
#[tokio::test]
async fn slow_preparation_releases_exactly_one_expired_row() {
    let (mut bob, storage, group_id, ids, delay) = slow_preparation_case(4).await;
    for id in &ids {
        let mut row = storage.get_message(id).unwrap();
        row.deferred_peel
            .as_mut()
            .unwrap()
            .residence_deadline_monotonic_ms = 0;
        storage.put_message(&row).unwrap();
    }
    delay.metadata_ms.store(600, Ordering::SeqCst);
    bob.advance_convergence(&group_id).await.unwrap();
    let remaining = storage.list_deferred_message_metadata(&group_id).unwrap();
    assert_eq!(remaining.len(), 3);
    assert!(remaining.iter().all(|row| {
        row.deferred_peel
            .as_ref()
            .unwrap()
            .distinct_context_attempts
            == 0
    }));
}

/// Queued output must not turn background recovery into a four-row foreground
/// send attempt. The frozen raw generation still completes before output drains.
#[tokio::test]
#[cfg(feature = "test-policy-overrides")]
async fn queued_output_preserves_background_recovery_allowance() {
    use cgka_traits::app_event::{MARMOT_APP_EVENT_KIND_CHAT, MarmotAppEvent};
    use cgka_traits::storage::DeferredPeelGenerationStorage;

    for explicit_time in [false, true] {
        let (mut engine, storage, group_id, ids, _delay) = slow_preparation_case(96).await;
        // Keep the production four-row foreground limit. Its independent time
        // budget is enlarged only to make this row-accounting test deterministic.
        engine.set_foreground_deferred_peel_budget(5_000, 4);
        let payload = MarmotAppEvent::new(
            hex::encode(engine.self_id().as_slice()),
            1_700_000_000,
            MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "queued during opaque recovery",
        )
        .encode()
        .unwrap();
        let result = engine
            .send(SendIntent::AppMessage {
                group_id: group_id.clone(),
                payload,
            })
            .await
            .unwrap();
        let SendResult::Queued { intent_id, .. } = result else {
            panic!("foreground send must queue behind a partial generation");
        };
        assert_eq!(
            deferred_attempts(&storage, &ids),
            4,
            "actual foreground send retains its four-row allowance"
        );
        let advanced = if explicit_time {
            engine
                .converge_and_drain_queued_outbound_intents(&group_id, 1_000_000)
                .await
                .unwrap()
        } else {
            engine.advance_convergence(&group_id).await.unwrap()
        };
        let background_attempts = deferred_attempts(&storage, &ids) - 4;
        eprintln!(
            "queued background recovery: explicit_time={explicit_time}, attempts={background_attempts}"
        );
        assert!(
            (1..=64).contains(&background_attempts),
            "wall-clock recovery must make progress within its row allowance: {background_attempts}"
        );
        if explicit_time {
            assert_eq!(
                background_attempts, 64,
                "explicit-time recovery keeps its deterministic row slice"
            );
        }
        assert!(
            advanced.is_empty(),
            "queued output must wait for the whole frozen generation"
        );
        assert!(
            storage
                .deferred_peel_generation(&group_id)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .len(),
            1
        );

        // Complete with deterministic row slices. Wall-clock throughput is
        // host-dependent; the public entry point was exercised above.
        let mut drained = Vec::new();
        for pass in 0..8 {
            drained.extend(
                engine
                    .converge_and_drain_queued_outbound_intents(&group_id, 1_000_001 + pass)
                    .await
                    .unwrap(),
            );
            if !drained.is_empty() {
                break;
            }
        }
        assert!(matches!(
            drained.as_slice(),
            [SendResult::ApplicationMessage { .. }]
        ));
        assert_eq!(
            deferred_attempts(&storage, &ids),
            96,
            "every opaque row gets one definitive attempt before output"
        );
        assert!(
            storage
                .deferred_peel_generation(&group_id)
                .unwrap()
                .is_none()
        );
        assert!(
            engine
                .advance_convergence(&group_id)
                .await
                .unwrap()
                .is_empty(),
            "an in-flight queued result must not regenerate twice"
        );
        engine.confirm_queued_outbound_intent(&intent_id).unwrap();
        assert!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .is_empty()
        );
    }
}

async fn setup_own_intent_fault_case(
    fault: LeaveWriteFault,
) -> (
    cgka_engine::Engine<FaultStorage>,
    SqliteAccountStorage,
    GroupId,
) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut engine = EngineBuilder::new(FaultStorage {
        inner: storage.clone(),
        fault: PutGroupFault::default(),
        capability_fault: CapabilityWriteFault::default(),
        leave_write_fault: LeaveWriteFault::default(),
        intent_write_fault: fault,
        preparation_delay: PreparationDelay::default(),
    })
    .legacy_compatibility_profile()
    .identity(pad32(b"own-intent-fault"))
    .account_identity_proof_signer(proof_signer(b"own-intent-fault"))
    .peeler(Box::new(MockPeeler))
    .build()
    .unwrap();
    let (group_id, result) = engine
        .create_group(CreateGroupRequest {
            name: "intent retention".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, .. } = result else {
        panic!("create")
    };
    engine.confirm_published(pending).await.unwrap();
    (engine, storage, group_id)
}

#[tokio::test]
async fn own_intent_record_failure_releases_the_unreturned_pending_commit() {
    let fault = LeaveWriteFault::default();
    let (mut engine, storage, group_id) = setup_own_intent_fault_case(fault.clone()).await;
    let epoch = engine.epoch(&group_id).unwrap();
    let intent = SendIntent::UpdateGroupData {
        group_id: group_id.clone(),
        name: Some("retained edit".into()),
        description: None,
    };
    fault.arm_on_write(1);
    assert!(matches!(
        engine.send(intent.clone()).await,
        Err(EngineError::Storage(StorageError::Busy(_)))
    ));
    assert!(
        storage
            .list_own_commit_intents(Some(&group_id))
            .unwrap()
            .is_empty()
    );
    assert_eq!(engine.epoch(&group_id).unwrap(), epoch);
    let result = engine
        .send(intent)
        .await
        .expect("the failed staging must remain retryable");
    let SendResult::GroupEvolution { pending, .. } = result else {
        panic!("retry stages immediately: {result:?}")
    };
    engine.confirm_published(pending).await.unwrap();
    assert!(engine.epoch(&group_id).unwrap() > epoch);
}

#[tokio::test]
async fn superseded_own_intent_transfer_is_atomic_on_each_storage_failure() {
    for fail_on_write in 1..=2 {
        let fault = LeaveWriteFault::default();
        let (mut engine, storage, group_id) = setup_own_intent_fault_case(fault.clone()).await;
        // Persist an independently evidenced superseded edit against the current
        // baseline. This targets the recovery transfer, not branch selection.
        let commit_id = MessageId::new(vec![42; 32]);
        storage
            .put_own_commit_intent(&cgka_traits::storage::OwnCommitIntent {
                commit_id: commit_id.clone(),
                group_id: group_id.clone(),
                source_epoch: engine.epoch(&group_id).unwrap(),
                intent: SendIntent::UpdateGroupData {
                    group_id: group_id.clone(),
                    name: Some("retry edit".into()),
                    description: None,
                },
                baseline: cgka_traits::storage::OwnCommitBaseline::GroupProfile {
                    name: "intent retention".into(),
                    description: String::new(),
                },
                reissue_attempts: 0,
                created_at_ms: 0,
            })
            .unwrap();
        fault.arm_on_write(fail_on_write);
        assert!(matches!(
            engine.reissue_superseded_own_commit(&commit_id),
            Err(EngineError::Storage(StorageError::Busy(_)))
        ));
        assert!(
            storage.own_commit_intent(&commit_id).unwrap().is_some(),
            "failed transfer must retain the source"
        );
        assert!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .is_empty(),
            "failed source deletion must roll back the queue write"
        );
        let report = engine
            .reissue_superseded_own_commit(&commit_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            report.outcome,
            cgka_traits::engine::SupersededIntentOutcome::Reissued
        );
        assert!(storage.own_commit_intent(&commit_id).unwrap().is_none());
        let queued = storage.list_queued_outbound_intents(&group_id).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].reissue_attempts, 1);
        assert!(
            engine
                .reissue_superseded_own_commit(&commit_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            storage
                .list_queued_outbound_intents(&group_id)
                .unwrap()
                .len(),
            1
        );
    }
}
