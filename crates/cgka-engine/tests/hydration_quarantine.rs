use async_trait::async_trait;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::Backend;
use cgka_traits::capabilities::{CapabilityRequirement, Feature, GroupCapabilities};
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason, SendResult,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group::{Group, Member};
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::message::{MessageRecord, MessageState};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, AccountDeviceSignerStorage, CapabilityStorage,
    ConvergencePolicyStorage, GroupStorage, MemberValidationCacheStorage, MessageStorage,
    OutboundIntentStorage, QueuedOutboundIntent, StorageError, StorageProvider, StorageResult,
    WelcomeStorage,
};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use cgka_traits::welcome::PendingWelcome;
use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

fn group_digest(group_id: &GroupId) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"marmot-hydration-quarantine-group/v1");
    hasher.update(group_id.as_slice());
    hex::encode(hasher.finalize())
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

fn build_engine(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(b"alice-hydration"))
        .account_identity_proof_signer(proof_signer(b"alice-hydration"))
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

async fn create_confirmed_group(engine: &mut Engine<SqliteAccountStorage>) -> GroupId {
    let (group_id, send_result) = engine
        .create_group(CreateGroupRequest {
            name: "healthy".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");
    let SendResult::GroupCreated { pending, .. } = send_result else {
        panic!("expected group-created send result");
    };
    engine.confirm_published(pending).await.expect("confirm");
    group_id
}

fn insert_marmot_group_without_openmls_state(
    storage: &SqliteAccountStorage,
    group_id: &GroupId,
    name: &str,
    epoch: u64,
) {
    storage
        .put_group(&Group {
            id: group_id.clone(),
            name: name.into(),
            description: String::new(),
            members: Vec::new(),
            epoch: EpochId(epoch),
            required_capabilities: GroupCapabilities::default(),
        })
        .expect("insert marmot group record without openmls state");
}

#[tokio::test]
async fn hydration_quarantines_bad_group_and_keeps_healthy_groups_available() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_engine(storage.clone());
    let healthy_group = create_confirmed_group(&mut initial).await;
    let healthy_epoch = storage.get_group(&healthy_group).unwrap().epoch;
    initial.drain_events();

    let broken_group = GroupId::new(b"missing-openmls-state".to_vec());
    insert_marmot_group_without_openmls_state(&storage, &broken_group, "broken", 9);
    drop(initial);

    let dir = tempfile::TempDir::new().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let recorder = JsonlRecorder::open(&audit_path, "hydration-test-engine".to_string()).unwrap();
    let mut reopened = EngineBuilder::new(storage.clone())
        .identity(pad32(b"alice-hydration"))
        .account_identity_proof_signer(proof_signer(b"alice-hydration"))
        .peeler(Box::new(MockPeeler))
        .recorder(Box::new(recorder))
        .build()
        .expect("build reopened engine");

    reopened
        .hydrate_stable_groups_from_storage()
        .expect("hydration skips bad group instead of aborting account open");

    assert_eq!(reopened.epoch(&healthy_group).unwrap(), healthy_epoch);
    assert!(matches!(
        reopened.epoch(&broken_group),
        Err(EngineError::UnknownGroup(id)) if id == broken_group
    ));

    let events = reopened.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationQuarantined {
                group_id,
                reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
            } if group_id == &broken_group
        )),
        "quarantine event missing: {events:?}"
    );
    drop(reopened);

    let audit_events: Vec<AuditEvent> = std::fs::read_to_string(&audit_path)
        .expect("read audit log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse audit event"))
        .collect();
    assert!(
        audit_events.iter().any(|event| matches!(
            &event.kind,
            AuditEventKind::GroupHydrationQuarantined { group_digest: digest, reason }
                if digest == &group_digest(&broken_group)
                    && reason == "openmls_group_missing"
                    && event.group_ref.is_none()
        )),
        "quarantine audit event missing: {audit_events:?}"
    );
}

#[tokio::test]
async fn hydration_quarantines_first_bad_group_and_continues_to_later_healthy_group() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let broken_group = GroupId::new(vec![0]);
    insert_marmot_group_without_openmls_state(&storage, &broken_group, "broken-first", 3);

    let mut initial = build_engine(storage.clone());
    let healthy_group = create_confirmed_group(&mut initial).await;
    let healthy_epoch = storage.get_group(&healthy_group).unwrap().epoch;
    initial.drain_events();

    let listed_groups = storage.list_groups().expect("list groups");
    assert_eq!(
        listed_groups.first(),
        Some(&broken_group),
        "test setup must put the broken group before the healthy group: {listed_groups:?}"
    );
    drop(initial);

    let mut reopened = build_engine(storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("hydration skips the first bad group and continues");

    assert_eq!(reopened.epoch(&healthy_group).unwrap(), healthy_epoch);
    assert!(matches!(
        reopened.epoch(&broken_group),
        Err(EngineError::UnknownGroup(id)) if id == broken_group
    ));

    let events = reopened.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationQuarantined {
                group_id,
                reason: GroupHydrationQuarantineReason::OpenMlsGroupMissing,
            } if group_id == &broken_group
        )),
        "quarantine event missing: {events:?}"
    );
}

// ── Re-hydration retry (darkmatter#426) ─────────────────────────────────────

/// Storage wrapper that delegates everything to an inner
/// [`SqliteAccountStorage`] but can be told to fail `get_group` once, to
/// simulate a transiently-unreadable Marmot record at session open that later
/// becomes readable. OpenMLS state is left intact, so once `get_group`
/// succeeds the group is fully recoverable — exactly the partial-restore case
/// the retry path targets.
#[derive(Clone)]
struct FlakyGroupRecordStorage {
    inner: SqliteAccountStorage,
    fail_get_group: Arc<AtomicBool>,
}

impl FlakyGroupRecordStorage {
    fn new(inner: SqliteAccountStorage) -> Self {
        Self {
            inner,
            fail_get_group: Arc::new(AtomicBool::new(false)),
        }
    }

    fn set_fail_get_group(&self, fail: bool) {
        self.fail_get_group.store(fail, Ordering::SeqCst);
    }
}

impl GroupStorage for FlakyGroupRecordStorage {
    fn put_group(&self, group: &Group) -> StorageResult<()> {
        self.inner.put_group(group)
    }
    fn get_group(&self, id: &GroupId) -> StorageResult<Group> {
        if self.fail_get_group.load(Ordering::SeqCst) {
            return Err(StorageError::Backend("injected get_group failure".into()));
        }
        self.inner.get_group(id)
    }
    fn delete_group(&self, id: &GroupId) -> StorageResult<()> {
        self.inner.delete_group(id)
    }
    fn list_groups(&self) -> StorageResult<Vec<GroupId>> {
        self.inner.list_groups()
    }
}

impl MessageStorage for FlakyGroupRecordStorage {
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

impl OutboundIntentStorage for FlakyGroupRecordStorage {
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

impl WelcomeStorage for FlakyGroupRecordStorage {
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

impl CapabilityStorage for FlakyGroupRecordStorage {
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

impl ConvergencePolicyStorage for FlakyGroupRecordStorage {
    fn put_convergence_policy(&self, group_id: &GroupId, policy: &[u8]) -> StorageResult<()> {
        self.inner.put_convergence_policy(group_id, policy)
    }
    fn convergence_policy(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.inner.convergence_policy(group_id)
    }
}

impl MemberValidationCacheStorage for FlakyGroupRecordStorage {
    fn put_validated_tree_marker(&self, group_id: &GroupId, marker: &[u8]) -> StorageResult<()> {
        self.inner.put_validated_tree_marker(group_id, marker)
    }
    fn validated_tree_marker(&self, group_id: &GroupId) -> StorageResult<Option<Vec<u8>>> {
        self.inner.validated_tree_marker(group_id)
    }
}

impl AccountDeviceSignerStorage for FlakyGroupRecordStorage {
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

impl StorageProvider for FlakyGroupRecordStorage {
    type Mls = <SqliteAccountStorage as StorageProvider>::Mls;

    fn mls_storage(&self) -> &Self::Mls {
        self.inner.mls_storage()
    }

    fn backend(&self) -> Backend {
        self.inner.backend()
    }
}

fn build_flaky_engine(storage: FlakyGroupRecordStorage) -> Engine<FlakyGroupRecordStorage> {
    EngineBuilder::new(storage)
        .identity(pad32(b"alice-hydration"))
        .account_identity_proof_signer(proof_signer(b"alice-hydration"))
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build flaky engine")
}

async fn create_confirmed_group_flaky(engine: &mut Engine<FlakyGroupRecordStorage>) -> GroupId {
    let (group_id, send_result) = engine
        .create_group(CreateGroupRequest {
            name: "healthy".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");
    let SendResult::GroupCreated { pending, .. } = send_result else {
        panic!("expected group-created send result");
    };
    engine.confirm_published(pending).await.expect("confirm");
    group_id
}

#[tokio::test]
async fn retry_recovers_a_transiently_quarantined_group() {
    let storage = FlakyGroupRecordStorage::new(SqliteAccountStorage::in_memory().expect("storage"));
    let mut initial = build_flaky_engine(storage.clone());
    let group_id = create_confirmed_group_flaky(&mut initial).await;
    let group_epoch = initial.group_record(&group_id).unwrap().epoch;
    drop(initial);

    // Reopen with the Marmot record transiently unreadable: the group is
    // quarantined (GroupRecordLoadFailed) instead of aborting account open.
    storage.set_fail_get_group(true);
    let mut reopened = build_flaky_engine(storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("hydration quarantines the unreadable group, does not abort");

    assert!(matches!(
        reopened.epoch(&group_id),
        Err(EngineError::UnknownGroup(id)) if id == group_id
    ));
    let quarantined = reopened.quarantined_groups();
    assert_eq!(quarantined.len(), 1);
    assert_eq!(quarantined[0].0, group_id);
    assert_eq!(
        quarantined[0].1,
        GroupHydrationQuarantineReason::GroupRecordLoadFailed
    );
    reopened.drain_events();

    // The record becomes readable again (e.g. a completed DB restore). Retry
    // recovers the group: it is now live and leaves the quarantine list.
    storage.set_fail_get_group(false);
    let recovered = reopened
        .retry_hydrate_quarantined_group(&group_id)
        .expect("retry must not error for a quarantined id");
    assert!(recovered, "retry should report recovery");
    assert!(reopened.quarantined_groups().is_empty());
    assert_eq!(reopened.epoch(&group_id).unwrap(), group_epoch);

    let events = reopened.drain_events();
    // The recovery event must carry the real recovered epoch — not 0. Finding 3
    // (darkmatter#441): the engine previously re-read storage.get_group() and
    // unwrap_or_default()'d the epoch on error, which could silently emit
    // epoch 0. It now uses the epoch hydration established.
    assert!(
        events.iter().any(|event| matches!(
            event,
            GroupEvent::GroupHydrationRecovered { group_id: gid, recovered_epoch }
                if gid == &group_id && *recovered_epoch == group_epoch
        )),
        "recovery event missing or carried the wrong epoch (expected {group_epoch:?}): {events:?}"
    );
}

#[tokio::test]
async fn retry_keeps_group_quarantined_when_still_unhealthy() {
    let storage = FlakyGroupRecordStorage::new(SqliteAccountStorage::in_memory().expect("storage"));
    let mut initial = build_flaky_engine(storage.clone());
    let group_id = create_confirmed_group_flaky(&mut initial).await;
    drop(initial);

    storage.set_fail_get_group(true);
    let mut reopened = build_flaky_engine(storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("hydration quarantines the unreadable group");
    reopened.drain_events();

    // Still unhealthy at retry time: stays quarantined, returns Ok(false), and
    // emits no recovery event.
    let recovered = reopened
        .retry_hydrate_quarantined_group(&group_id)
        .expect("retry on a still-broken group is Ok(false), not Err");
    assert!(!recovered);
    assert_eq!(reopened.quarantined_groups().len(), 1);
    assert!(matches!(
        reopened.epoch(&group_id),
        Err(EngineError::UnknownGroup(_))
    ));
    let events = reopened.drain_events();
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, GroupEvent::GroupHydrationRecovered { .. })),
        "no recovery event should be emitted on a failed retry: {events:?}"
    );
}

#[tokio::test]
async fn retry_for_unknown_group_errors() {
    let storage = FlakyGroupRecordStorage::new(SqliteAccountStorage::in_memory().expect("storage"));
    let mut engine = build_flaky_engine(storage);
    let unknown = GroupId::new(b"never-quarantined".to_vec());
    assert!(matches!(
        engine.retry_hydrate_quarantined_group(&unknown),
        Err(EngineError::UnknownGroup(id)) if id == unknown
    ));
}

// darkmatter#152: session open must not re-verify an unchanged group's
// account-identity proofs on every open. After a successful hydration the
// engine persists a content-bound validation marker; reopening an unchanged
// group finds the marker already set so the per-leaf schnorr re-verification is
// skipped, and the group still hydrates to the same epoch.
#[tokio::test]
async fn hydration_persists_validation_marker_and_unchanged_group_reopens() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_engine(storage.clone());
    let group = create_confirmed_group(&mut initial).await;
    let epoch = storage.get_group(&group).unwrap().epoch;
    drop(initial);

    // No marker before the first hydration.
    assert_eq!(
        storage.validated_tree_marker(&group).expect("read marker"),
        None,
        "marker should not exist before any hydration"
    );

    let mut first = build_engine(storage.clone());
    first
        .hydrate_stable_groups_from_storage()
        .expect("first hydration");
    assert_eq!(first.epoch(&group).unwrap(), epoch);

    // First open validated the tree and persisted a marker.
    let marker = storage
        .validated_tree_marker(&group)
        .expect("read marker")
        .expect("marker should be persisted after a validating hydration");
    drop(first);

    // Reopening an unchanged group hydrates fine; the marker is unchanged
    // because the tree bytes are identical.
    let mut second = build_engine(storage.clone());
    second
        .hydrate_stable_groups_from_storage()
        .expect("second hydration of unchanged group");
    assert_eq!(second.epoch(&group).unwrap(), epoch);
    assert_eq!(
        storage.validated_tree_marker(&group).expect("read marker"),
        Some(marker),
        "marker for an unchanged group must be stable across opens"
    );
}

// A stale/garbage marker must never let a tampered group through: marker
// mismatch forces full validation. A healthy group with a mismatched marker
// still hydrates (full validation passes) and the marker is refreshed.
#[tokio::test]
async fn stale_validation_marker_forces_revalidation_and_refresh() {
    let storage = SqliteAccountStorage::in_memory().expect("storage");
    let mut initial = build_engine(storage.clone());
    let group = create_confirmed_group(&mut initial).await;
    let epoch = storage.get_group(&group).unwrap().epoch;
    drop(initial);

    // Plant a bogus marker that cannot match the real tree.
    storage
        .put_validated_tree_marker(&group, b"stale-marker-does-not-match")
        .expect("plant stale marker");

    let mut reopened = build_engine(storage.clone());
    reopened
        .hydrate_stable_groups_from_storage()
        .expect("hydration revalidates and accepts the healthy group");
    assert_eq!(reopened.epoch(&group).unwrap(), epoch);

    // Full validation ran and refreshed the marker to the real value.
    let refreshed = storage
        .validated_tree_marker(&group)
        .expect("read marker")
        .expect("marker should be refreshed after revalidation");
    assert_ne!(
        refreshed, b"stale-marker-does-not-match",
        "stale marker must be overwritten with the real content-bound marker"
    );
}
