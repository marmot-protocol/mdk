use async_trait::async_trait;
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::capabilities::GroupCapabilities;
use cgka_traits::engine::{
    CgkaEngine, CreateGroupRequest, GroupEvent, GroupHydrationQuarantineReason, SendResult,
};
use cgka_traits::error::{EngineError, PeelerError};
use cgka_traits::group::Group;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::GroupStorage;
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, GroupId, MemberId, MessageId};
use marmot_forensics::{AuditEvent, AuditEventKind, JsonlRecorder};
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
