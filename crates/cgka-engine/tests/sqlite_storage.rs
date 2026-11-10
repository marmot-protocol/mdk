//! SQLite-backed engine integration smoke.
//!
//! This keeps encrypted file-backed SQLite on the same engine test rail as the
//! in-memory SQLite cases without turning this crate into a full persistence
//! reload suite. The behavior under test is: a real OpenMLS engine can create
//! and confirm a group while all Marmot + OpenMLS state is backed by an
//! encrypted SQLite database.

// Tests read stored records directly (see the crate clippy.toml).
#![allow(clippy::disallowed_methods)]

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
        if let Ok(sk) = SigningKey::from_slice(&material) {
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
    async fn wrap_group_recovery(
        &self,
        _message: &cgka_traits::GroupRecoveryMessage,
        _recipient: &MemberId,
    ) -> Result<TransportMessage, PeelerError> {
        Err(PeelerError::Malformed(
            "pass-through fixture has no authenticated account channel".into(),
        ))
    }

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
                created_at: None,
                bytes: msg.payload.clone(),
                key_package_event_id: None,
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
    let key = SqlCipherKey::raw([0x42; 32]);

    let alice_store = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    let alice_inspection = alice_store.clone();
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
    // Fault the actual new admission write inside the founding confirmation,
    // after its earlier MLS and group writes, through an independent connection.
    let before = alice_inspection.get_group(&group_id).unwrap();
    let fault = rusqlite::Connection::open(&alice_path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &fault,
        &key,
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    fault.execute_batch("CREATE TRIGGER refuse_invitation_admission BEFORE INSERT ON cgka_invitation_admissions BEGIN SELECT RAISE(ABORT, 'invitation admission fault'); END;").unwrap();
    let error = alice.confirm_published(pending).await.unwrap_err();
    assert!(error.to_string().contains("invitation admission fault"));
    assert_eq!(alice_inspection.get_group(&group_id).unwrap(), before);
    assert!(
        alice_inspection
            .invitation_admission(&group_id)
            .unwrap()
            .is_none()
    );
    assert!(
        load_openmls_group(&alice_inspection, &group_id)
            .pending_commit()
            .is_some()
    );
    fault
        .execute_batch("DROP TRIGGER refuse_invitation_admission")
        .unwrap();
    drop(fault);
    alice
        .confirm_published(pending)
        .await
        .expect("healed confirm retry");
    let admission = alice_inspection
        .invitation_admission(&group_id)
        .unwrap()
        .unwrap();
    assert!(admission.created_locally);
    assert!(admission.via_welcome.is_none());

    assert_eq!(alice.epoch(&group_id).unwrap(), EpochId(1));
    assert_eq!(alice.members(&group_id).unwrap().len(), 2);

    drop(alice);
    drop(bob);
    drop(alice_inspection);

    let file_bytes = std::fs::read(&alice_path).unwrap();
    assert!(!file_bytes.starts_with(b"SQLite format 3\0"));

    let reopened = SqliteAccountStorage::open_encrypted(&alice_path, &key).unwrap();
    assert_eq!(
        reopened.invitation_admission(&group_id).unwrap(),
        Some(admission)
    );
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
    let key = SqlCipherKey::raw([0x42; 32]);

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

/// A device's history key (mdk#2628 4.1) is generated once, on first use,
/// and kept with the rest of its state: a reopened engine reads the same
/// public half and opens what a sibling sealed to it.
#[tokio::test]
async fn the_history_key_survives_reopen_and_opens_what_a_sibling_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let laptop_path = dir.path().join("laptop.sqlite");
    let key = SqlCipherKey::raw([0x42; 32]);

    let laptop = build_client(
        SqliteAccountStorage::open_encrypted(&laptop_path, &key).unwrap(),
        b"alice-sqlite",
    );
    assert_eq!(laptop.open_history(b"context", b"sealed").unwrap(), None);
    let history_key = laptop.history_public_key().unwrap();
    assert_eq!(history_key.len(), 32);
    assert_eq!(laptop.history_public_key().unwrap(), history_key);
    drop(laptop);

    let phone = build_client(SqliteAccountStorage::in_memory().unwrap(), b"alice-sqlite");
    assert_ne!(phone.history_public_key().unwrap(), history_key);
    let sealed = phone
        .seal_history(&history_key, b"context", b"history")
        .unwrap();

    let reopened = build_client(
        SqliteAccountStorage::open_encrypted(&laptop_path, &key).unwrap(),
        b"alice-sqlite",
    );
    assert_eq!(reopened.history_public_key().unwrap(), history_key);
    assert_eq!(
        reopened.open_history(b"context", &sealed).unwrap(),
        Some(b"history".to_vec())
    );
    assert_eq!(reopened.open_history(b"other", &sealed).unwrap(), None);
    // The sealing device's own key does not open it.
    assert_eq!(phone.open_history(b"context", &sealed).unwrap(), None);
}

#[tokio::test]
async fn safe_exports_keep_their_source_and_puncturing_across_reopen() {
    use cgka_traits::EngineError;
    use cgka_traits::app_components::{
        GROUP_ADMIN_POLICY_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    };
    use cgka_traits::engine::SendIntent;
    const COMPONENT: u16 = GROUP_PROFILE_COMPONENT_ID;
    const OTHER: u16 = GROUP_ADMIN_POLICY_COMPONENT_ID;
    fn build(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
        EngineBuilder::new(storage)
            .identity(pad32(b"safe-export-source"))
            .account_identity_proof_signer(proof_signer(b"safe-export-source"))
            .peeler(Box::new(MockPeeler))
            .build()
            .unwrap()
    }
    fn primitive(
        storage: &SqliteAccountStorage,
        group_id: &cgka_traits::GroupId,
        component: u16,
        pending: bool,
    ) -> Vec<u8> {
        let mut expected = None;
        let rolled_back = storage.with_transaction(|_| {
            let mut group = MlsGroup::load(
                storage.mls_storage(),
                &openmls::group::GroupId::from_slice(group_id.as_slice()),
            )
            .unwrap()
            .unwrap();
            let crypto = openmls_rust_crypto::RustCrypto::default();
            expected = Some(if pending {
                group
                    .safe_export_secret_from_pending(&crypto, storage.mls_storage(), component)
                    .unwrap()
            } else {
                group
                    .safe_export_secret(&crypto, storage.mls_storage(), component)
                    .unwrap()
            });
            Err::<(), EngineError>(EngineError::Other(
                "restore independent exporter oracle".into(),
            ))
        });
        assert!(
            matches!(rolled_back, Err(EngineError::Other(reason)) if reason == "restore independent exporter oracle")
        );
        expected.unwrap()
    }
    fn punctured(engine: &mut Engine<SqliteAccountStorage>, group_id: &cgka_traits::GroupId) {
        assert!(
            matches!(engine.safe_export_secret_with_epoch(group_id, COMPONENT),
            Err(EngineError::Backend(reason)) if reason.contains("PuncturedInput"))
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("safe-export.sqlite");
    let key = SqlCipherKey::raw([0x44; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = build(storage.clone());
    let (group_id, created) = alice
        .create_group(CreateGroupRequest {
            name: "safe exporter".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    assert!(
        matches!(created, SendResult::FoundingGroupCreated { welcomes } if welcomes.is_empty())
    );
    for _ in 0..2 {
        assert_eq!(
            alice
                .current_safe_export_epoch(&group_id, COMPONENT)
                .unwrap(),
            EpochId(0)
        );
    }
    for refused in [
        alice.current_safe_export_epoch(&group_id, 0xfefe).map(drop),
        alice
            .safe_export_secret_with_epoch(&group_id, 0xfefe)
            .map(drop),
    ] {
        assert!(
            matches!(refused, Err(EngineError::Other(reason)) if reason == "group does not require app component 0xfefe")
        );
    }
    let expected = primitive(&storage, &group_id, COMPONENT, false);
    let (epoch, original) = alice
        .safe_export_secret_with_epoch(&group_id, COMPONENT)
        .unwrap();
    assert_eq!(epoch, EpochId(0));
    assert_eq!(original.len(), 32);
    assert!(original.as_slice() == expected);
    let expected = primitive(&storage, &group_id, OTHER, false);
    let (epoch, other_original) = alice
        .safe_export_secret_with_epoch(&group_id, OTHER)
        .unwrap();
    assert_eq!(epoch, EpochId(0));
    assert!(other_original.as_slice() == expected);
    assert!(other_original.as_slice() != original.as_slice());

    // A new connection must see the puncture while the original engine lives.
    let foreign = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut observer = build(foreign.clone());
    observer.hydrate_all_stored_groups().unwrap();
    punctured(&mut observer, &group_id);
    assert_eq!(
        observer
            .current_safe_export_epoch(&group_id, COMPONENT)
            .unwrap(),
        EpochId(0)
    );
    drop(observer);
    drop(foreign);
    drop(alice);
    drop(storage);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = build(reopened.clone());
    alice.hydrate_all_stored_groups().unwrap();
    punctured(&mut alice, &group_id);
    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("rotation must stage a commit");
    };
    assert_eq!(
        alice
            .current_safe_export_epoch(&group_id, COMPONENT)
            .unwrap(),
        EpochId(1)
    );
    let expected = primitive(&reopened, &group_id, COMPONENT, true);
    let (epoch, abandoned) = alice
        .safe_export_secret_with_epoch(&group_id, COMPONENT)
        .unwrap();
    assert_eq!(epoch, EpochId(1));
    assert!(abandoned.as_slice() == expected);
    assert!(abandoned.as_slice() != original.as_slice());
    alice.publish_failed(pending).await.unwrap();
    assert_eq!(
        alice
            .current_safe_export_epoch(&group_id, COMPONENT)
            .unwrap(),
        EpochId(0)
    );
    punctured(&mut alice, &group_id);

    let SendResult::GroupEvolution { pending, .. } = alice
        .send(SendIntent::SelfUpdate {
            group_id: group_id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("the replacement rotation must stage a commit");
    };
    let expected = primitive(&reopened, &group_id, COMPONENT, true);
    let (epoch, confirmed) = alice
        .safe_export_secret_with_epoch(&group_id, COMPONENT)
        .unwrap();
    assert_eq!(epoch, EpochId(1));
    assert!(confirmed.as_slice() == expected);
    assert!(confirmed.as_slice() != abandoned.as_slice());
    alice.confirm_published(pending).await.unwrap();
    punctured(&mut alice, &group_id);
    drop(alice);
    drop(reopened);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = build(reopened.clone());
    alice.hydrate_all_stored_groups().unwrap();
    assert_eq!(
        alice
            .current_safe_export_epoch(&group_id, COMPONENT)
            .unwrap(),
        EpochId(1)
    );
    punctured(&mut alice, &group_id);
    let expected = primitive(&reopened, &group_id, OTHER, false);
    let (epoch, other_confirmed) = alice
        .safe_export_secret_with_epoch(&group_id, OTHER)
        .unwrap();
    assert_eq!(epoch, EpochId(1));
    assert!(other_confirmed.as_slice() == expected);
    assert!(other_confirmed.as_slice() != other_original.as_slice());
}

#[tokio::test]
async fn local_forget_commits_before_dropping_pending_work_and_survives_reopen() {
    use cgka_traits::app_components::{
        AppComponentData, NOSTR_ROUTING_COMPONENT_ID, NostrRoutingV1, default_group_components,
        encode_nostr_routing_v1,
    };
    use cgka_traits::engine::{GroupEvent, SendIntent};
    use cgka_traits::storage::{OutboundIntentStorage, StorageError};
    use cgka_traits::{EngineError, GroupId};
    fn build(storage: SqliteAccountStorage) -> Engine<SqliteAccountStorage> {
        EngineBuilder::new(storage)
            .identity(pad32(b"forget-local"))
            .account_identity_proof_signer(proof_signer(b"forget-local"))
            .supported_app_components(
                default_group_components()
                    .into_iter()
                    .chain([NOSTR_ROUTING_COMPONENT_ID])
                    .collect::<Vec<_>>(),
            )
            .peeler(Box::new(MockPeeler))
            .build()
            .unwrap()
    }
    fn request(route_byte: u8) -> CreateGroupRequest {
        CreateGroupRequest {
            name: "local reset".into(),
            description: String::new(),
            members: vec![],
            required_features: vec![],
            app_components: vec![AppComponentData {
                component_id: NOSTR_ROUTING_COMPONENT_ID,
                data: encode_nostr_routing_v1(
                    &NostrRoutingV1::new([route_byte; 32], vec!["wss://relay.example".into()])
                        .unwrap(),
                )
                .unwrap(),
            }],
            initial_admins: vec![],
        }
    }
    async fn stage(
        engine: &mut Engine<SqliteAccountStorage>,
        group_id: &GroupId,
    ) -> cgka_traits::PendingStateRef {
        let SendResult::GroupEvolution { pending, .. } = engine
            .send(SendIntent::SelfUpdate {
                group_id: group_id.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("rotation must stage a commit");
        };
        pending
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forget.sqlite");
    let key = SqlCipherKey::raw([0x45; 32]);
    let storage = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = build(storage.clone());
    let forgotten = GroupId::new(vec![0xa1; 3]);
    let retained = GroupId::new(vec![0xb2; 48]);
    for id in [&forgotten, &retained] {
        let (created_id, created) = alice
            .create_group_with_chosen_id_and_audit_context(
                request(id.as_slice()[0]),
                id.clone(),
                None,
                Timestamp(u64::MAX),
                None,
            )
            .await
            .unwrap();
        assert_eq!(&created_id, id);
        assert!(
            matches!(created, SendResult::FoundingGroupCreated { welcomes } if welcomes.is_empty())
        );
    }
    let forgotten_route = alice
        .group_context(&forgotten)
        .unwrap()
        .transport_group_id()
        .unwrap();
    let retained_route = alice
        .group_context(&retained)
        .unwrap()
        .transport_group_id()
        .unwrap();
    assert_eq!(forgotten_route.len(), 32);
    assert_eq!(retained_route.len(), 32);
    assert_ne!(forgotten_route, retained_route);
    let first_forgotten = stage(&mut alice, &forgotten).await;
    let first_retained = stage(&mut alice, &retained).await;
    let before_failed = GroupContextSnapshot::from_context(
        alice.group_context(&forgotten).unwrap().as_ref(),
        &[
            "marmot/group-event",
            "marmot/encrypted-media",
            "marmot/agent-text-stream-quic",
        ],
    );
    // A real second connection aborts the durable delete. No mock decides
    // whether the engine's pending references or emitted events survive it.
    let fault = rusqlite::Connection::open(&path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &fault,
        &key,
        storage_sqlite::SqlCipherHardening::live_cache(),
    )
    .unwrap();
    assert_eq!(
        fault
            .query_row(
                "SELECT COUNT(*) FROM cgka_groups WHERE id = ?1",
                [forgotten.as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    fault.execute_batch("CREATE TRIGGER refuse_local_forget BEFORE DELETE ON cgka_groups WHEN OLD.id = X'a1a1a1' BEGIN SELECT RAISE(ABORT, 'local forget fault'); END;").unwrap();
    assert!(
        matches!(alice.forget_group_local(&forgotten), Err(EngineError::Storage(StorageError::Backend(reason))) if reason.contains("local forget fault"))
    );
    assert_eq!(
        GroupContextSnapshot::from_context(
            alice.group_context(&forgotten).unwrap().as_ref(),
            &[
                "marmot/group-event",
                "marmot/encrypted-media",
                "marmot/agent-text-stream-quic"
            ]
        ),
        before_failed
    );
    assert!(!storage.is_group_forgotten(&forgotten).unwrap());
    let mut created = alice
        .drain_events()
        .into_iter()
        .map(|event| match event {
            GroupEvent::GroupCreated { group_id } => group_id,
            other => panic!("unexpected creation event: {other:?}"),
        })
        .collect::<Vec<_>>();
    created.sort_by(|a, b| a.as_slice().cmp(b.as_slice()));
    assert_eq!(created, vec![forgotten.clone(), retained.clone()]);
    fault
        .execute_batch("DROP TRIGGER refuse_local_forget;")
        .unwrap();
    drop(fault);
    alice.confirm_published(first_forgotten).await.unwrap();
    alice.confirm_published(first_retained).await.unwrap();
    let pending_forgotten = stage(&mut alice, &forgotten).await;
    let pending_retained = stage(&mut alice, &retained).await;
    for id in [&forgotten, &retained] {
        let payload = cgka_traits::app_event::MarmotAppEvent::new(
            hex::encode(alice.self_id().as_slice()),
            1_700_000_000,
            cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT,
            vec![],
            "queued during rotation",
        )
        .encode()
        .unwrap();
        assert!(
            matches!(alice.queue_app_message(id.clone(), payload).await.unwrap(), SendResult::Queued { group_id, .. } if &group_id == id)
        );
        assert_eq!(storage.list_queued_outbound_intents(id).unwrap().len(), 1);
    }
    let retained_queue = storage.list_queued_outbound_intents(&retained).unwrap();
    let retained_context = GroupContextSnapshot::from_context(
        alice.group_context(&retained).unwrap().as_ref(),
        &[
            "marmot/group-event",
            "marmot/encrypted-media",
            "marmot/agent-text-stream-quic",
        ],
    );
    assert!(alice.forget_group_local(&forgotten).unwrap());
    assert!(storage.is_group_forgotten(&forgotten).unwrap());
    assert!(
        storage
            .group_local_reset_cutoff(&forgotten)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .list_queued_outbound_intents(&forgotten)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        storage.list_queued_outbound_intents(&retained).unwrap(),
        retained_queue
    );
    assert_eq!(
        GroupContextSnapshot::from_context(
            alice.group_context(&retained).unwrap().as_ref(),
            &[
                "marmot/group-event",
                "marmot/encrypted-media",
                "marmot/agent-text-stream-quic"
            ]
        ),
        retained_context
    );
    assert_eq!(alice.epoch_state(&forgotten), None);
    assert!(
        matches!(alice.group_context(&forgotten), Err(EngineError::UnknownGroup(id)) if id == forgotten)
    );
    assert!(matches!(
        alice.confirm_published(pending_forgotten).await,
        Err(EngineError::UnknownPending)
    ));
    assert_eq!(
        alice.drain_events(),
        vec![GroupEvent::EpochChanged {
            group_id: retained.clone(),
            from: EpochId(0),
            to: EpochId(1)
        }]
    );
    alice.confirm_published(pending_retained).await.unwrap();
    assert_eq!(alice.group_context(&retained).unwrap().epoch(), EpochId(2));
    drop(alice);
    drop(storage);

    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let mut alice = build(reopened.clone());
    alice.hydrate_all_stored_groups().unwrap();
    assert_eq!(alice.live_group_ids().unwrap(), vec![retained.clone()]);
    assert_eq!(alice.group_context(&retained).unwrap().epoch(), EpochId(2));
    assert_eq!(
        alice.group_context(&retained).unwrap().transport_group_id(),
        Some(retained_route)
    );
    assert!(matches!(
        reopened.get_group(&forgotten),
        Err(StorageError::NotFound)
    ));
    assert!(reopened.is_group_forgotten(&forgotten).unwrap());
    assert_eq!(
        reopened.list_queued_outbound_intents(&retained).unwrap(),
        retained_queue
    );
    let cutoff = reopened.group_local_reset_cutoff(&forgotten).unwrap();
    assert!(
        matches!(alice.create_group_with_chosen_id_and_audit_context(request(0xa1), forgotten.clone(), None, Timestamp(u64::MAX), None).await, Err(EngineError::Other(reason)) if reason == "the chosen id names a group this device forgot")
    );
    assert!(!alice.forget_group_local(&forgotten).unwrap());
    assert_eq!(
        reopened.group_local_reset_cutoff(&forgotten).unwrap(),
        cutoff
    );
}
