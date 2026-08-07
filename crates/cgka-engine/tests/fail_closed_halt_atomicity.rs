//! Durability of the missing-anchor fail-closed halt under an injected storage
//! fault.
//!
//! When an in-horizon same-epoch rival arrives with no fork-source anchor, the
//! engine halts the group: it parks the rival reconsiderable, writes the
//! durable `unrecoverable` marker, and retires the raw transport wrapper that
//! carried the rival here. Those writes are one logical transition.
//! A `ConvergenceDeferred` row is admitted to a convergence pass but cannot
//! *open* one (`convergence_input::can_start_pass`), so a park that survives a
//! failed marker write is the worst of both: the group is not halted, it keeps
//! committing on a possibly-losing branch, redelivery dedups against the parked
//! row, and stale-deferred retirement eventually terminalizes it. Permanent
//! divergence produced by the halt's own error path. A wrapper retirement that
//! survives the same failure is that failure through the other input source:
//! the retry lifecycle drops the wrapper that redelivers the rival to a group
//! that never halted.
//!
//! The invariant these tests pin, at the widest fault window: after the halt
//! path fails, EITHER the group is durably unrecoverable, OR its inputs still
//! carry the rival back — the content row in a pass-opening state, the raw
//! wrapper still awaiting retry. Never neither.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::OutboundFanout;
use cgka_traits::capabilities::{
    Capability, CapabilityRequirement, Feature, GroupCapabilities, RequirementLevel,
};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingKey, CommitOrderingPriority, CreateGroupRequest, GroupEvent,
    SendIntent, SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
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
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

fn content_id(msg: &TransportMessage) -> MessageId {
    use sha2::{Digest, Sha256};
    MessageId::new(Sha256::digest(&msg.payload).to_vec())
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
            source: TransportSource("fail-closed-halt-atomicity".into()),
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
            source: TransportSource("fail-closed-halt-atomicity".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

/// Peeler that refuses every group-message peel while armed, so an ingested
/// rival is retained as a raw `PeelDeferred` wrapper. Disarming it lets the
/// same transport message peel on a later live ingest — the direct-seam
/// re-entry `PeelDeferred` rows exist for (`recorded_message_outcome` returns
/// no recorded outcome for them, unlike every other retained state).
#[derive(Clone, Default)]
struct DeferringPeeler(Arc<AtomicBool>);

impl DeferringPeeler {
    fn arm(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn disarm(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[async_trait]
impl TransportPeeler for DeferringPeeler {
    async fn peel_group_message(
        &self,
        msg: &TransportMessage,
        ctx: &GroupContextSnapshot,
    ) -> Result<PeeledMessage, PeelerError> {
        if self.0.load(Ordering::SeqCst) {
            return Err(PeelerError::DecryptFailed);
        }
        MockPeeler.peel_group_message(msg, ctx).await
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

fn build_client(id: &[u8]) -> Engine<SqliteAccountStorage> {
    build_client_with_storage(id).0
}

fn build_client_with_storage(id: &[u8]) -> (Engine<SqliteAccountStorage>, SqliteAccountStorage) {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let engine = EngineBuilder::new(storage.clone())
        .legacy_compatibility_profile()
        .identity(pad32(id))
        .account_identity_proof_signer(proof_signer(id))
        .feature_registry(selfremove_registry())
        .peeler(Box::new(MockPeeler))
        .build()
        .unwrap();
    (engine, storage)
}

/// One-shot fault that fails the `put_group` carrying the durable halt marker.
///
/// Predicate-keyed rather than call-counted so it fires at exactly the write
/// under test — hydration and commit-apply record writes pass through.
#[derive(Clone, Default)]
struct HaltMarkerFault(Arc<AtomicUsize>);

/// One-shot fault that fails the `put_message` that parks the rival
/// `ConvergenceDeferred`.
#[derive(Clone, Default)]
struct ParkWriteFault(Arc<AtomicUsize>);

impl HaltMarkerFault {
    fn arm(&self) {
        self.0.store(1, Ordering::SeqCst);
    }

    fn should_fail(&self, group: &Group) -> bool {
        group.unrecoverable && self.consume()
    }

    fn consume(&self) -> bool {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

impl ParkWriteFault {
    fn arm(&self) {
        self.0.store(1, Ordering::SeqCst);
    }

    fn should_fail(&self, record: &MessageRecord) -> bool {
        record.state == MessageState::ConvergenceDeferred && self.consume()
    }

    fn consume(&self) -> bool {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
    }
}

/// `SqliteAccountStorage` wrapper that injects a transient `Busy` on the two
/// writes the halt performs. Every other call delegates unchanged.
struct FaultStorage {
    inner: SqliteAccountStorage,
    halt_marker_fault: HaltMarkerFault,
    park_fault: ParkWriteFault,
}

impl GroupStorage for FaultStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        if self.halt_marker_fault.should_fail(group) {
            return Err(StorageError::Busy("injected halt-marker failure".into()));
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
        if self.park_fault.should_fail(record) {
            return Err(StorageError::Busy("injected park-write failure".into()));
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

/// A device holding its own epoch-1 commit, an in-horizon rival for the same
/// epoch it has never adjudicated, and no epoch-1 anchor to adjudicate with.
struct StrandedRivalFixture {
    group_id: GroupId,
    local_storage: SqliteAccountStorage,
    local_seed: Vec<u8>,
    competing: TransportMessage,
    own_invitee: MemberId,
    sibling_invitee: MemberId,
}

/// Two admins concurrently invite from epoch 1 and both confirm publish; the
/// device under test is the joiner. Seeds are assigned so the creator's identity
/// sorts FIRST, making the inbound sibling commit the deterministic ordering
/// winner — i.e. the branch this device would lose if it silently kept its own.
/// The epoch-1 anchor is then released (pre-mechanism database, storage loss),
/// which is what strands the rival: neither resolution route can admit it.
async fn stranded_rival_fixture(tag: &str) -> StrandedRivalFixture {
    let a = format!("fch-a-{tag}").into_bytes();
    let b = format!("fch-b-{tag}").into_bytes();
    let (creator_seed, joiner_seed) = if pad32(&a) < pad32(&b) {
        (a, b)
    } else {
        (b, a)
    };
    let own_seed = format!("fch-own-invitee-{tag}").into_bytes();
    let sibling_seed = format!("fch-sibling-invitee-{tag}").into_bytes();

    let (mut creator, _creator_storage) = build_client_with_storage(&creator_seed);
    let (mut joiner, joiner_storage) = build_client_with_storage(&joiner_seed);
    let mut own_invitee = build_client(&own_seed);
    let mut sibling_invitee = build_client(&sibling_seed);

    let joiner_kp = joiner.fresh_key_package().await.unwrap();
    let (group_id, create) = creator
        .create_group(CreateGroupRequest {
            name: "fail-closed halt".into(),
            description: String::new(),
            members: vec![joiner_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![joiner.self_id()],
        })
        .await
        .unwrap();
    let welcome = match create {
        SendResult::GroupCreated {
            pending,
            mut welcomes,
        } => {
            creator.confirm_published(pending).await.unwrap();
            welcomes.remove(0)
        }
        other => panic!("expected GroupCreated, got {other:?}"),
    };
    joiner.join_welcome(welcome).await.unwrap();

    let own_kp = own_invitee.fresh_key_package().await.unwrap();
    let sibling_kp = sibling_invitee.fresh_key_package().await.unwrap();
    let (own_commit, own_pending) = match joiner
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![own_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    let (sibling_commit, sibling_pending) = match creator
        .send(SendIntent::Invite {
            group_id: group_id.clone(),
            key_packages: vec![sibling_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { msg, pending, .. } => (msg, pending),
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    joiner.confirm_published(own_pending).await.unwrap();
    creator.confirm_published(sibling_pending).await.unwrap();
    assert_eq!(joiner.epoch(&group_id).unwrap(), EpochId(2));

    let own_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        joiner.self_id(),
        &own_commit.payload,
    );
    let sibling_key = CommitOrderingKey::from_commit_bytes(
        EpochId(1),
        CommitOrderingPriority::Privileged,
        creator.self_id(),
        &sibling_commit.payload,
    );
    assert!(
        sibling_key < own_key,
        "fixture must make the inbound sibling commit the ordering winner"
    );

    let competing = TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: group_id.as_slice().to_vec(),
        },
        ..sibling_commit
    };

    // Restart erases in-memory `committed_from`; releasing the anchor erases
    // the convergence route's admission material.
    drop(joiner);
    joiner_storage
        .release_group_snapshot(&group_id, "openmls-retained-anchor-1")
        .expect("release the source-epoch anchor");

    StrandedRivalFixture {
        group_id,
        local_storage: joiner_storage,
        local_seed: joiner_seed,
        competing,
        own_invitee: MemberId::new(pad32(&own_seed)),
        sibling_invitee: MemberId::new(pad32(&sibling_seed)),
    }
}

fn reopen_over_fault_storage(
    f: &StrandedRivalFixture,
    storage: FaultStorage,
) -> Engine<FaultStorage> {
    reopen_over_fault_storage_with_peeler(f, storage, Box::new(MockPeeler))
}

fn reopen_over_fault_storage_with_peeler(
    f: &StrandedRivalFixture,
    storage: FaultStorage,
    peeler: Box<dyn TransportPeeler>,
) -> Engine<FaultStorage> {
    let mut engine = EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(&f.local_seed))
        .account_identity_proof_signer(proof_signer(&f.local_seed))
        .feature_registry(selfremove_registry())
        .peeler(peeler)
        .build()
        .unwrap();
    engine.hydrate_all_stored_groups().unwrap();
    engine
}

fn is_halted(f: &StrandedRivalFixture) -> bool {
    f.local_storage
        .get_group(&f.group_id)
        .unwrap()
        .unrecoverable
}

fn rival_state(f: &StrandedRivalFixture) -> MessageState {
    f.local_storage
        .get_message(&content_id(&f.competing))
        .unwrap()
        .state
}

/// State of the raw transport wrapper that carried the rival — the row keyed
/// by the outer transport id, not the content-derived one.
fn raw_wrapper_state(f: &StrandedRivalFixture) -> MessageState {
    f.local_storage.get_message(&f.competing.id).unwrap().state
}

/// Whether this device is still sitting on its own epoch-1 branch — i.e. the
/// branch deterministic ordering says it must eventually leave.
fn still_on_own_branch(engine: &Engine<FaultStorage>, f: &StrandedRivalFixture) -> bool {
    let members = engine.members(&f.group_id).unwrap();
    let has_own = members.iter().any(|m| m.id == f.own_invitee);
    let has_sibling = members.iter().any(|m| m.id == f.sibling_invitee);
    assert_ne!(
        has_own, has_sibling,
        "exactly one of the two forked invitees must be present"
    );
    has_own
}

/// Drive convergence like a runtime scheduler, letting the real quiescence
/// window elapse, until the group halts. Returns whether it halted.
async fn drive_convergence_until_halted(
    engine: &mut Engine<FaultStorage>,
    f: &StrandedRivalFixture,
) -> bool {
    for _ in 0..40 {
        let _ = engine.converge_stored_openmls_messages(&f.group_id);
        if is_halted(f) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn halt_marker_write_failure_leaves_the_rival_able_to_reopen_the_halt() {
    let f = stranded_rival_fixture("marker").await;
    let halt_marker_fault = HaltMarkerFault::default();
    let mut local = reopen_over_fault_storage(
        &f,
        FaultStorage {
            inner: f.local_storage.clone(),
            halt_marker_fault: halt_marker_fault.clone(),
            park_fault: ParkWriteFault::default(),
        },
    );

    halt_marker_fault.arm();
    let result = local.ingest(f.competing.clone()).await;
    assert!(
        result.is_err(),
        "the failed halt-marker write must propagate, got {result:?}"
    );

    // The halt's own error path must not manufacture silent divergence. A
    // `ConvergenceDeferred` rival cannot open a convergence pass, so parking it
    // without the durable marker leaves the group Stable, committing on a
    // possibly-losing branch, with redelivery dedup'd against the parked row.
    assert!(
        is_halted(&f) || rival_state(&f) == MessageState::Created,
        "after a failed halt the group must be durably unrecoverable or the \
         rival must still hold a pass-opening state; got unrecoverable={} \
         rival={:?}",
        is_halted(&f),
        rival_state(&f)
    );

    // Canonical state is untouched either way: the fault must not adjudicate.
    assert!(still_on_own_branch(&local, &f));
    assert_eq!(local.epoch(&f.group_id).unwrap(), EpochId(2));

    // And the promise the retained state makes must be redeemable: a follow-up
    // convergence run reaches the same halt, with the event the app needs.
    assert!(
        drive_convergence_until_halted(&mut local, &f).await,
        "a retained pass-opening rival must let a later run reach the halt"
    );
    assert!(
        local.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "the halt must reach the app so it can surface repair"
    );
    assert!(still_on_own_branch(&local, &f));
}

#[tokio::test]
async fn direct_ingest_keeps_the_raw_wrapper_replayable_when_the_halt_write_fails() {
    // The rival can reach the halt through a live ingest of a wrapper that is
    // already in the retry lifecycle, and that seam has no compensating error
    // arm: `do_ingest` propagates the halt's failure untouched. So the
    // wrapper's retirement is safe only as part of the halt's own transaction.
    // Retiring it before the marker+park leaves a group that never halted with
    // the redelivery source of the only input that can re-derive the halt
    // already out of the retry lifecycle.
    let f = stranded_rival_fixture("direct").await;
    let halt_marker_fault = HaltMarkerFault::default();
    let peeler = DeferringPeeler::default();
    let mut local = reopen_over_fault_storage_with_peeler(
        &f,
        FaultStorage {
            inner: f.local_storage.clone(),
            halt_marker_fault: halt_marker_fault.clone(),
            park_fault: ParkWriteFault::default(),
        },
        Box::new(peeler.clone()),
    );

    // An arrival this context cannot peel is retained as a raw wrapper.
    peeler.arm();
    local.ingest(f.competing.clone()).await.unwrap();
    assert_eq!(
        raw_wrapper_state(&f),
        MessageState::PeelDeferred,
        "an unpeelable arrival must be retained for retry"
    );

    // Redelivery under a peelable context reaches the fail-closed halt through
    // the direct seam, with the halt's durable marker write faulted.
    peeler.disarm();
    halt_marker_fault.arm();
    let result = local.ingest(f.competing.clone()).await;
    assert!(
        result.is_err(),
        "the failed halt-marker write must propagate, got {result:?}"
    );

    assert_ne!(
        raw_wrapper_state(&f),
        MessageState::Processed,
        "a halt that did not commit must not retire the wrapper that carried \
         the rival to it"
    );
    assert_eq!(
        raw_wrapper_state(&f),
        MessageState::PeelDeferred,
        "the wrapper must stay exactly as replayable as it was before the \
         rolled-back halt"
    );

    // Same no-silent-divergence invariant as the other halt fault windows.
    assert!(
        is_halted(&f) || rival_state(&f) == MessageState::Created,
        "after a failed halt the group must be durably unrecoverable or the \
         rival must still hold a pass-opening state; got unrecoverable={} \
         rival={:?}",
        is_halted(&f),
        rival_state(&f)
    );
    assert!(still_on_own_branch(&local, &f));
    assert!(
        drive_convergence_until_halted(&mut local, &f).await,
        "a retained pass-opening rival must let a later run reach the halt"
    );
    assert!(
        local.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "the halt must reach the app so it can surface repair"
    );
}

#[tokio::test]
async fn replayed_raw_wrapper_is_not_retired_when_the_halt_write_fails() {
    // The rival can also reach the halt through the replay seam rather than a
    // live ingest. That seam retires the raw transport wrapper `Processed` on a
    // successful outcome, which takes it out of the retry lifecycle for good. A
    // halt that failed its durable write must never look successful to it —
    // guarded here twice over, by the halt's own transaction and by the seam's
    // error arm, so removing either one is visible.
    let f = stranded_rival_fixture("replay").await;
    let halt_marker_fault = HaltMarkerFault::default();
    let mut local = reopen_over_fault_storage(
        &f,
        FaultStorage {
            inner: f.local_storage.clone(),
            halt_marker_fault: halt_marker_fault.clone(),
            park_fault: ParkWriteFault::default(),
        },
    );

    // Stage a local commit so the group leaves `Stable` and refuses ingest;
    // the rival is then buffered `Retryable` as a genuine raw wrapper.
    let mut third = build_client(b"fch-replay-third");
    let third_kp = third.fresh_key_package().await.unwrap();
    let pending = match local
        .send(SendIntent::Invite {
            group_id: f.group_id.clone(),
            key_packages: vec![third_kp],
        })
        .await
        .unwrap()
    {
        SendResult::GroupEvolution { pending, .. } => pending,
        other => panic!("expected GroupEvolution, got {other:?}"),
    };
    local.ingest(f.competing.clone()).await.unwrap();
    assert_eq!(
        f.local_storage.get_message(&f.competing.id).unwrap().state,
        MessageState::Retryable,
        "a group that cannot ingest must buffer the raw wrapper for replay"
    );

    // Abandoning the publication replays the buffered wrapper, which reaches
    // the fail-closed halt — with its durable marker write faulted.
    halt_marker_fault.arm();
    let result = local.publish_failed(pending).await;
    assert!(
        result.is_err(),
        "the failed halt-marker write must propagate through the replay seam, \
         got {result:?}"
    );

    assert_ne!(
        raw_wrapper_state(&f),
        MessageState::Processed,
        "the raw wrapper must not be retired while the halt it triggered failed"
    );
    assert_eq!(
        raw_wrapper_state(&f),
        MessageState::Retryable,
        "the wrapper stays replayable twice over: the halt's transaction rolls \
         its retirement back, and the seam's error path hands it back for retry"
    );

    // Same no-silent-divergence invariant as the direct-ingest seam.
    assert!(
        is_halted(&f) || rival_state(&f) == MessageState::Created,
        "after a failed halt the group must be durably unrecoverable or the \
         rival must still hold a pass-opening state; got unrecoverable={} \
         rival={:?}",
        is_halted(&f),
        rival_state(&f)
    );
    assert!(
        drive_convergence_until_halted(&mut local, &f).await,
        "a retained pass-opening rival must let a later run reach the halt"
    );
    assert!(
        local.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "the halt must reach the app so it can surface repair"
    );
}

#[tokio::test]
async fn park_write_failure_rolls_back_the_halt_marker_and_the_retry_still_halts() {
    let f = stranded_rival_fixture("park").await;
    let park_fault = ParkWriteFault::default();
    let mut local = reopen_over_fault_storage(
        &f,
        FaultStorage {
            inner: f.local_storage.clone(),
            halt_marker_fault: HaltMarkerFault::default(),
            park_fault: park_fault.clone(),
        },
    );

    park_fault.arm();
    let result = local.ingest(f.competing.clone()).await;
    assert!(
        result.is_err(),
        "the failed park write must propagate, got {result:?}"
    );

    // Marker and park are one durable unit: neither survives alone.
    assert!(
        !is_halted(&f),
        "a halt marker must not commit without the park that keeps the rival \
         reconsiderable"
    );
    assert_eq!(
        rival_state(&f),
        MessageState::Created,
        "the rolled-back park must leave the rival able to open a pass"
    );
    assert!(still_on_own_branch(&local, &f));

    assert!(
        drive_convergence_until_halted(&mut local, &f).await,
        "the retry must still reach the halt"
    );
    assert!(
        local.drain_events().iter().any(|event| matches!(
            event,
            GroupEvent::GroupUnrecoverable { group_id } if group_id == &f.group_id
        )),
        "the halt must reach the app so it can surface repair"
    );
}
