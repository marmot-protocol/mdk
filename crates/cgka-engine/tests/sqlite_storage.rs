//! SQLite-backed engine integration smoke.
//!
//! This keeps encrypted file-backed SQLite on the same engine test rail as the
//! in-memory SQLite cases without turning this crate into a full persistence
//! reload suite. The behavior under test is: a real OpenMLS engine can create
//! and confirm a group while all Marmot + OpenMLS state is backed by an
//! encrypted SQLite database.

use async_trait::async_trait;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::wire_format::{
    DEFAULT_MAX_PAST_EPOCHS, DEFAULT_MAXIMUM_FORWARD_DISTANCE, DEFAULT_OUT_OF_ORDER_TOLERANCE,
    PURE_PLAINTEXT_WIRE_FORMAT_POLICY, join_config,
};
use cgka_engine::{Engine, EngineBuilder};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{PeeledContent, PeeledMessage};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{GroupStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{EpochId, MemberId, MessageId};
use openmls::group::{MlsGroup, MlsGroupJoinConfig};
use openmls::prelude::SenderRatchetConfiguration;
use storage_sqlite::{SqlCipherKey, SqliteAccountStorage};

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
            source: TransportSource("sqlite-smoke".into()),
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
            source: TransportSource("sqlite-smoke".into()),
            envelope: TransportEnvelope::Welcome {
                recipient: recipient.clone(),
            },
        })
    }
}

fn build_client(storage: SqliteAccountStorage, identity: &[u8]) -> Engine<SqliteAccountStorage> {
    EngineBuilder::new(storage)
        .legacy_compatibility_profile()
        .identity(pad32(identity))
        .account_identity_proof_signer(proof_signer(identity))
        .feature_registry(FeatureRegistry::new())
        .peeler(Box::new(MockPeeler))
        .build()
        .expect("build engine")
}

fn load_openmls_group(
    storage: &SqliteAccountStorage,
    group_id: &cgka_traits::types::GroupId,
) -> MlsGroup {
    let mls_group_id = openmls::group::GroupId::from_slice(group_id.as_slice());
    MlsGroup::load(storage.mls_storage(), &mls_group_id)
        .expect("load OpenMLS group")
        .expect("stored OpenMLS group exists")
}

#[tokio::test]
async fn create_group_confirm_and_reopen_with_encrypted_sqlite_storage() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice.sqlite");
    let bob_path = dir.path().join("bob.sqlite");
    let key = SqlCipherKey::new("sqlite engine smoke key").unwrap();

    let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let bob_store = SqliteAccountStorage::open_encrypted(&bob_path, &key).unwrap();
    let mut alice = build_client(alice_store, b"alice-sqlite");
    let mut bob = build_client(bob_store, b"bob-sqlite");

    let bob_key_package = bob.fresh_key_package().await.expect("bob key package");
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "sqlite-backed".into(),
            description: "engine integration smoke".into(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");

    let pending = match result {
        SendResult::GroupCreated { pending, welcomes } => {
            assert_eq!(welcomes.len(), 1);
            pending
        }
        other => panic!("expected group creation result, got {other:?}"),
    };
    alice.confirm_published(pending).await.expect("confirm");

    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);

    drop(alice);
    drop(bob);

    let file_bytes = std::fs::read(&alice_path).unwrap();
    assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

    let reopened = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let reopened_group = reopened.get_group(&group_id).unwrap();
    assert_eq!(reopened_group.epoch, EpochId(1));
    assert_eq!(
        reopened_group.protocol_profile,
        ProtocolProfile::Legacy,
        "the persisted application-profile classification must survive an engine reopen"
    );
}

#[tokio::test]
async fn hydration_migrates_and_persists_existing_sender_ratchet_policy() {
    let dir = tempfile::tempdir().unwrap();
    let alice_path = dir.path().join("alice-ratchet.sqlite");
    let bob_path = dir.path().join("bob-ratchet.sqlite");
    let key = SqlCipherKey::new("sqlite sender ratchet migration key").unwrap();

    let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let alice_inspection = alice_store.clone();
    let bob_store = SqliteAccountStorage::open_encrypted(&bob_path, &key).unwrap();
    let mut alice = build_client(alice_store, b"alice-ratchet");
    let mut bob = build_client(bob_store, b"bob-ratchet");

    let bob_key_package = bob.fresh_key_package().await.expect("bob key package");
    let (group_id, result) = alice
        .create_group(CreateGroupRequest {
            name: "sender-ratchet-migration".into(),
            description: String::new(),
            members: vec![bob_key_package],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .expect("create group");
    let pending = match result {
        SendResult::GroupCreated { pending, .. } => pending,
        other => panic!("expected group creation result, got {other:?}"),
    };
    alice.confirm_published(pending).await.expect("confirm");

    let mut stored_group = load_openmls_group(&alice_inspection, &group_id);
    assert_eq!(
        stored_group.configuration(),
        &join_config(DEFAULT_MAX_PAST_EPOCHS),
        "group creation and Welcome join must share the complete engine-owned runtime config"
    );
    let openmls_default = SenderRatchetConfiguration::default();
    assert_eq!(openmls_default.out_of_order_tolerance(), 5);
    assert_eq!(openmls_default.maximum_forward_distance(), 1_000);
    let accidentally_inherited_config = MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(DEFAULT_MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            openmls_default.out_of_order_tolerance(),
            DEFAULT_MAXIMUM_FORWARD_DISTANCE - 1,
        ))
        .build();
    stored_group
        .set_configuration(
            alice_inspection.mls_storage(),
            &accidentally_inherited_config,
        )
        .expect("install pre-migration sender ratchet policy");
    drop(stored_group);
    drop(alice);
    drop(bob);
    drop(alice_inspection);

    let reopened = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let reopened_inspection = reopened.clone();
    let mut reopened_engine = build_client(reopened, b"alice-ratchet");
    reopened_engine
        .hydrate_all_stored_groups()
        .expect("hydrate stored group");

    let migrated = load_openmls_group(&reopened_inspection, &group_id);
    assert_eq!(
        migrated
            .configuration()
            .sender_ratchet_configuration()
            .out_of_order_tolerance(),
        DEFAULT_OUT_OF_ORDER_TOLERANCE
    );
    assert_eq!(
        migrated
            .configuration()
            .sender_ratchet_configuration()
            .maximum_forward_distance(),
        DEFAULT_MAXIMUM_FORWARD_DISTANCE
    );
    drop(migrated);
    drop(reopened_engine);
    drop(reopened_inspection);

    let persisted = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let persisted_group = load_openmls_group(&persisted, &group_id);
    assert_eq!(
        persisted_group
            .configuration()
            .sender_ratchet_configuration()
            .out_of_order_tolerance(),
        DEFAULT_OUT_OF_ORDER_TOLERANCE,
        "migration must survive another process restart"
    );
    assert_eq!(
        persisted_group
            .configuration()
            .sender_ratchet_configuration()
            .maximum_forward_distance(),
        DEFAULT_MAXIMUM_FORWARD_DISTANCE,
        "maximum forward-distance migration must survive another process restart"
    );
}
