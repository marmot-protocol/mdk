//! `marmot.group.account-devices.v1` (0x800d) resulting-state rules
//! (account-devices-v1.md; mdk#2628 item 2.1b).
//!
//! Covers, for a group whose GroupContext `app_components` list requires
//! 0x800d:
//! - No data: no 0x800d entry in the GroupContext, in any leaf, or in an added
//!   KeyPackage, and no AppDataUpdate for it.
//! - Support: every leaf advertises 0x800d.
//! - Leaf limit: at most `MAX_LEAVES_PER_ACCOUNT` leaves per account.
//! - Never un-require: no Commit or standalone proposal drops 0x800d from the
//!   required list.
//!
//! Each rule is shown from the committer's side (the engine refuses to send)
//! and the receiver's side (a commit crafted with raw OpenMLS is dropped by
//! replay, and a crafted standalone proposal is rejected at ingest). Before a
//! group requires 0x800d, its data is accepted like any unknown component's.
//! The builder only lets these tests advertise 0x800d through the test-only
//! escape hatch, so the file needs one of the test features.
#![cfg(any(
    feature = "test-policy-overrides",
    feature = "test-conformance-snapshot"
))]

use async_trait::async_trait;
use cgka_engine::account_identity_proof::account_identity_proof_component;
use cgka_engine::canonicalization::DroppedMessageReason;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID,
    AppComponentData, AppComponentSet, MAX_LEAVES_PER_ACCOUNT, SAFE_AAD_COMPONENT_ID,
    default_group_components, encode_components_list,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, KeyPackage, SendIntent, SendResult};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{IngestOutcome, PeeledContent, PeeledMessage, ProposalRejectionCategory};
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{AccountDeviceSignerStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::extensions::{AppDataDictionaryExtension, Extension, ExtensionValidator, Extensions};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    CredentialWithKey, KeyPackage as MlsKeyPackage, LeafNode, LeafNodeParameters, MlsMessageBodyIn,
    MlsMessageIn, MlsMessageOut, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

mod support;
use support::proof_signer;

const ACCOUNT_DEVICES: Feature = Feature("account-devices");

fn pad32(name: &[u8]) -> Vec<u8> {
    // Marmot credential identities MUST be a valid 32-byte x-only secp256k1
    // public key (spec/foundation/identity.md). Derive one deterministically
    // from the ergonomic label, matching `support::proof_signer`.
    use k256::schnorr::SigningKey;
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
    MessageId::new(Sha256::digest(bytes).to_vec())
}

/// Pass-through peeler. Every Welcome gets its own id, as the Nostr adapter's
/// gift wraps do: one founding Welcome goes to several devices of one account.
#[derive(Default)]
struct MockPeeler(std::sync::atomic::AtomicU64);

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
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(TransportMessage {
            id: hash_id(&[payload.ciphertext.as_slice(), &n.to_be_bytes()].concat()),
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

fn registry() -> FeatureRegistry {
    let mut r = FeatureRegistry::new();
    r.register(
        Feature("self-remove"),
        CapabilityRequirement {
            requires: Capability::Proposal(10),
            level: RequirementLevel::Required,
            description: "self-remove",
        },
    );
    r.register(
        ACCOUNT_DEVICES,
        CapabilityRequirement {
            requires: Capability::AppComponent(ACCOUNT_DEVICES_COMPONENT_ID),
            level: RequirementLevel::Optional,
            description: "account-devices",
        },
    );
    r
}

struct Device {
    engine: Engine<SqliteAccountStorage>,
    storage: SqliteAccountStorage,
}

/// A current-profile device of `account`. Devices built from one label share
/// the account identity and differ in their MLS signature keys.
fn device(account: &[u8], advertises_account_devices: bool) -> Device {
    let storage = SqliteAccountStorage::in_memory().unwrap();
    let mut supported: Vec<_> = default_group_components().into_iter().collect();
    if advertises_account_devices {
        supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
    }
    let engine = EngineBuilder::new(storage.clone())
        .identity(pad32(account))
        .account_identity_proof_signer(proof_signer(account))
        .protocol_profile(ProtocolProfile::Current)
        .feature_registry(registry())
        .supported_app_components(supported)
        .allow_account_devices_advertising_for_tests()
        .peeler(Box::<MockPeeler>::default())
        .build()
        .unwrap();
    Device { engine, storage }
}

fn route_to_group(msg: &TransportMessage, gid: &GroupId) -> TransportMessage {
    TransportMessage {
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
        ..msg.clone()
    }
}

fn required(engine: &Engine<SqliteAccountStorage>, gid: &GroupId) -> AppComponentSet {
    engine
        .group_record(gid)
        .unwrap()
        .required_capabilities
        .app_components
}

fn requires_account_devices(engine: &Engine<SqliteAccountStorage>, gid: &GroupId) -> bool {
    required(engine, gid).contains(ACCOUNT_DEVICES_COMPONENT_ID)
}

/// `alice` founds a group with `members`, requiring 0x800d when `require` is
/// set, and each of `joiners` joins from the Welcome at the same index.
async fn found_group(
    alice: &mut Device,
    members: Vec<KeyPackage>,
    require: bool,
    joiners: &mut [&mut Device],
) -> GroupId {
    let (gid, created) = alice
        .engine
        .create_group(CreateGroupRequest {
            name: "account-devices".into(),
            description: String::new(),
            members,
            required_features: if require {
                vec![ACCOUNT_DEVICES]
            } else {
                vec![]
            },
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
        joiner.engine.join_welcome(welcome).await.unwrap();
    }
    assert_eq!(requires_account_devices(&alice.engine, &gid), require);
    gid
}

/// Publish one of `sender`'s commits and return it routed to the group.
async fn send_commit(sender: &mut Device, intent: SendIntent, gid: &GroupId) -> TransportMessage {
    let SendResult::GroupEvolution { msg, pending, .. } = sender.engine.send(intent).await.unwrap()
    else {
        panic!("expected GroupEvolution")
    };
    sender.engine.confirm_published(pending).await.unwrap();
    route_to_group(&msg, gid)
}

fn update_required(gid: &GroupId, ids: &AppComponentSet) -> SendIntent {
    SendIntent::UpdateAppComponents {
        group_id: gid.clone(),
        updates: vec![AppComponentData {
            component_id: APP_COMPONENTS_COMPONENT_ID,
            data: encode_components_list(&ids.ids),
        }],
    }
}

fn with_account_devices(mut ids: AppComponentSet) -> AppComponentSet {
    ids.insert(ACCOUNT_DEVICES_COMPONENT_ID);
    ids
}

fn without_account_devices(mut ids: AppComponentSet) -> AppComponentSet {
    ids.ids.remove(&ACCOUNT_DEVICES_COMPONENT_ID);
    ids
}

/// Activate 0x800d in an existing group through the admin's ordinary
/// required-list update, delivering the commit to `members`.
async fn activate(alice: &mut Device, gid: &GroupId, members: &mut [&mut Device]) {
    let ids = with_account_devices(required(&alice.engine, gid));
    let commit = send_commit(alice, update_required(gid, &ids), gid).await;
    for member in members.iter_mut() {
        assert_accepted(member, &commit, gid).await;
    }
    assert!(requires_account_devices(&alice.engine, gid));
}

async fn assert_accepted(receiver: &mut Device, commit: &TransportMessage, gid: &GroupId) {
    let before = receiver.engine.epoch(gid).unwrap().0;
    receiver.engine.ingest(commit.clone()).await.unwrap();
    let result = receiver
        .engine
        .converge_stored_openmls_messages_at(gid, 1_000_000)
        .unwrap();
    assert_eq!(
        result.accepted_commits,
        vec![hex::encode(hash_id(&commit.payload).as_slice())],
        "dropped: {:?}",
        result.dropped_messages
    );
    assert_eq!(receiver.engine.epoch(gid).unwrap().0, before + 1);
}

/// Replay drops `commit` as invalid against its candidate parent, so it never
/// becomes an edge: the receiver stays at its epoch and keeps the parent open.
async fn assert_rejected_on_replay(
    receiver: &mut Device,
    commit: &TransportMessage,
    gid: &GroupId,
) {
    let before = receiver.engine.epoch(gid).unwrap().0;
    let required_before = required(&receiver.engine, gid);
    receiver
        .engine
        .ingest(commit.clone())
        .await
        .expect("commit is retained for convergence");
    let result = receiver
        .engine
        .converge_stored_openmls_messages_at(gid, 1_000_000)
        .expect("invalid commit receives a terminal disposition");
    assert!(result.accepted_commits.is_empty(), "{result:?}");
    let commit_id = hex::encode(hash_id(&commit.payload).as_slice());
    assert!(
        result.dropped_messages.iter().any(|dropped| {
            dropped.message_id == commit_id
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        }),
        "dropped: {:?}",
        result.dropped_messages
    );
    assert_eq!(receiver.engine.epoch(gid).unwrap().0, before);
    assert_eq!(required(&receiver.engine, gid), required_before);
}

fn assert_refused(result: Result<SendResult, EngineError>, reason: &str) {
    let error = result.expect_err("the committer refuses the commit");
    assert!(
        error.to_string().contains(reason),
        "expected {reason:?}, got: {error}"
    );
}

async fn assert_rejected_at_ingest(receiver: &mut Device, proposal: &TransportMessage) {
    let outcome = receiver.engine.ingest(proposal.clone()).await.unwrap();
    assert!(
        matches!(
            outcome,
            IngestOutcome::Rejected {
                category: ProposalRejectionCategory::InvalidEncoding
            }
        ),
        "expected rejection at ingest, got {outcome:?}"
    );
}

// ── Raw OpenMLS crafting ────────────────────────────────────────────────────

fn device_signer(device: &Device) -> SignatureKeyPair {
    let binding = device
        .storage
        .account_device_signer(&device.engine.self_id())
        .expect("load signer binding")
        .expect("signer binding exists");
    SignatureKeyPair::read(
        device.storage.mls_storage(),
        &binding.mls_signature_public_key,
        DEFAULT_CIPHERSUITE.signature_algorithm(),
    )
    .expect("MLS signer exists")
}

fn load_group(device: &Device, gid: &GroupId) -> MlsGroup {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, device.storage.mls_storage());
    MlsGroup::load(
        provider.storage(),
        &openmls::group::GroupId::from_slice(gid.as_slice()),
    )
    .expect("load MLS group")
    .expect("device is a member")
}

fn parse_key_package(kp: &KeyPackage) -> MlsKeyPackage {
    let MlsMessageBodyIn::KeyPackage(kp) = MlsMessageIn::tls_deserialize_exact(kp.bytes())
        .unwrap()
        .extract()
    else {
        panic!("expected a KeyPackage")
    };
    kp.validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .unwrap()
}

fn group_transport(message: MlsMessageOut, gid: &GroupId, source: &str) -> TransportMessage {
    let payload = message.tls_serialize_detached().unwrap();
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource(source.into()),
        envelope: TransportEnvelope::GroupMessage {
            transport_group_id: gid.as_slice().to_vec(),
        },
    }
}

/// `extensions` with an `app_data_dictionary` entry under 0x800d.
fn with_account_devices_entry<T: ExtensionValidator>(mut extensions: Extensions<T>) -> Extensions<T>
where
    openmls::prelude::InvalidExtensionError: From<T::Error>,
{
    let mut dictionary = extensions
        .app_data_dictionary()
        .map(|extension| extension.dictionary().clone())
        .unwrap_or_default();
    dictionary.insert(ACCOUNT_DEVICES_COMPONENT_ID, vec![1]);
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    extensions
}

/// A fresh KeyPackage of `device` that also carries 0x800d data in its leaf,
/// at KeyPackage level, or both. It keeps the device's signature key, so the
/// account identity proof copied from the engine's own KeyPackage still holds.
async fn key_package_with_account_devices_data(
    device: &mut Device,
    in_leaf: bool,
    in_key_package: bool,
) -> KeyPackage {
    let original = parse_key_package(&device.engine.fresh_key_package().await.unwrap());
    let leaf = original.leaf_node();
    let leaf_extensions = if in_leaf {
        with_account_devices_entry(leaf.extensions().clone())
    } else {
        leaf.extensions().clone()
    };
    let mut builder = MlsKeyPackage::builder()
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(leaf_extensions);
    if in_key_package {
        builder = builder.key_package_extensions(with_account_devices_entry(Extensions::empty()));
    }
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, device.storage.mls_storage());
    let bundle = builder
        .mark_as_last_resort()
        .build(
            DEFAULT_CIPHERSUITE,
            &provider,
            &device_signer(device),
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: leaf.signature_key().clone(),
            },
        )
        .unwrap();
    let bytes = MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap();
    KeyPackage::new(bytes).with_protocol_profile(ProtocolProfile::Current)
}

/// A KeyPackage of another device of `account`, minted without building its
/// engine: `template`'s credential, capabilities and support list, with a
/// fresh signature key and its own account identity proof.
fn sibling_key_package(template: &KeyPackage, account: &[u8]) -> KeyPackage {
    let template = parse_key_package(template);
    let leaf = template.leaf_node();
    let scheme = DEFAULT_CIPHERSUITE.signature_algorithm();
    let signer = SignatureKeyPair::new(scheme).unwrap();
    let mut dictionary = leaf
        .extensions()
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    let template_proof = dictionary
        .get(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
        .unwrap();
    let created_at = u64::from_be_bytes(template_proof[32..40].try_into().unwrap());
    let proof = account_identity_proof_component(
        &pad32(account),
        signer.public(),
        DEFAULT_CIPHERSUITE,
        scheme,
        created_at,
        proof_signer(account).as_ref(),
    )
    .unwrap();
    dictionary.insert(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, proof);
    let mut extensions = leaf.extensions().clone();
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    let bundle = MlsKeyPackage::builder()
        .leaf_node_capabilities(leaf.capabilities().clone())
        .leaf_node_extensions(extensions)
        .mark_as_last_resort()
        .build(
            DEFAULT_CIPHERSUITE,
            &OpenMlsRustCrypto::default(),
            &signer,
            CredentialWithKey {
                credential: leaf.credential().clone(),
                signature_key: signer.public().into(),
            },
        )
        .unwrap();
    let bytes = MlsMessageOut::from(bundle.key_package().clone())
        .tls_serialize_detached()
        .unwrap();
    KeyPackage::new(bytes).with_protocol_profile(ProtocolProfile::Current)
}

/// A Commit `sender` builds with raw OpenMLS, bypassing the engine's checks:
/// it adds `adds`, carries `app_data` by value, and replaces the sender's leaf
/// with `leaf_extensions` when given.
fn crafted_commit(
    sender: &Device,
    gid: &GroupId,
    adds: Vec<KeyPackage>,
    app_data: Vec<AppDataUpdateProposal>,
    leaf_extensions: Option<Extensions<LeafNode>>,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, sender.storage.mls_storage());
    let mut group = load_group(sender, gid);
    let mut builder = group
        .commit_builder()
        .propose_adds(adds.iter().map(parse_key_package))
        .add_proposals(
            app_data
                .into_iter()
                .map(|proposal| Proposal::AppDataUpdate(Box::new(proposal))),
        );
    if let Some(extensions) = leaf_extensions {
        builder = builder.force_self_update(true).leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_extensions(extensions)
                .build(),
        );
    }
    let mut builder = builder.load_psks(provider.storage()).unwrap();
    let mut updater = builder.app_data_dictionary_updater();
    for proposal in builder.app_data_update_proposals() {
        match proposal.operation() {
            AppDataUpdateOperation::Update(data) => {
                updater.set(ComponentData::from_parts(
                    proposal.component_id(),
                    data.clone(),
                ));
            }
            AppDataUpdateOperation::Remove => {
                updater.remove(&proposal.component_id());
            }
        }
    }
    builder.with_app_data_dictionary_updates(updater.changes());
    let bundle = builder
        .build(
            provider.rand(),
            provider.crypto(),
            &device_signer(sender),
            |_| true,
        )
        .expect("raw OpenMLS builds the commit")
        .stage_commit(&provider)
        .expect("raw OpenMLS stages the commit");
    // Leave the sender's engine as it was, so it can still commit.
    group.clear_pending_commit(provider.storage()).unwrap();
    group_transport(bundle.into_commit(), gid, "crafted-commit")
}

fn required_list_update(ids: &AppComponentSet) -> AppDataUpdateProposal {
    AppDataUpdateProposal::update(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&ids.ids),
    )
}

fn standalone_app_data_update(
    sender: &Device,
    gid: &GroupId,
    component_id: u16,
    operation: AppDataUpdateOperation,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, sender.storage.mls_storage());
    let (message, _) = load_group(sender, gid)
        .propose_app_data_update(&provider, &device_signer(sender), component_id, operation)
        .expect("raw OpenMLS builds the proposal");
    group_transport(message, gid, "standalone-app-data-update")
}

/// A standalone GroupContextExtensions proposal that keeps every extension
/// but sets the `app_components` required list to `ids`.
fn standalone_required_list_extensions(
    sender: &Device,
    gid: &GroupId,
    ids: &AppComponentSet,
) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, sender.storage.mls_storage());
    let mut group = load_group(sender, gid);
    let mut extensions = group.extensions().clone();
    let mut dictionary = extensions
        .app_data_dictionary()
        .unwrap()
        .dictionary()
        .clone();
    dictionary.insert(
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&ids.ids),
    );
    extensions
        .add_or_replace(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ))
        .unwrap();
    let (message, _) = group
        .propose_group_context_extensions(&provider, extensions, &device_signer(sender))
        .expect("raw OpenMLS builds the proposal");
    group_transport(message, gid, "standalone-group-context-extensions")
}

// ── Builder ─────────────────────────────────────────────────────────────────

fn try_build(supported: Vec<u16>) -> Result<Engine<SqliteAccountStorage>, EngineError> {
    EngineBuilder::new(SqliteAccountStorage::in_memory().unwrap())
        .identity(pad32(b"builder"))
        .account_identity_proof_signer(proof_signer(b"builder"))
        .feature_registry(registry())
        .supported_app_components(supported)
        .peeler(Box::<MockPeeler>::default())
        .build()
}

#[test]
fn builder_refuses_protocol_components_the_engine_does_not_implement() {
    let defaults: Vec<_> = default_group_components().into_iter().collect();
    for unimplemented in [ACCOUNT_DEVICES_COMPONENT_ID, SAFE_AAD_COMPONENT_ID] {
        let mut supported = defaults.clone();
        supported.push(unimplemented);
        let error = try_build(supported).err().expect("the builder refuses");
        assert!(
            error.to_string().contains("does not implement it"),
            "unexpected error: {error}"
        );
    }
    // App-owned ids are the host's to advertise.
    let mut supported = defaults;
    supported.push(0xf001);
    try_build(supported).expect("app-owned ids are accepted");
}

// ── Before activation ───────────────────────────────────────────────────────

#[tokio::test]
async fn account_devices_data_is_unknown_data_before_activation() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", false);
    let mut carol = device(b"carol", false);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], false, &mut [&mut bob]).await;

    // GroupContext data through the engine's own send path.
    let write = send_commit(
        &mut alice,
        SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: ACCOUNT_DEVICES_COMPONENT_ID,
                data: vec![1],
            }],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &write, &gid).await;
    assert_eq!(
        bob.engine
            .app_component(&gid, ACCOUNT_DEVICES_COMPONENT_ID)
            .unwrap(),
        Some(vec![1])
    );

    // KeyPackage-level and leaf data on an invited KeyPackage.
    let carol_kp = key_package_with_account_devices_data(&mut carol, true, true).await;
    let invite = send_commit(
        &mut alice,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![carol_kp],
            initial_admins: vec![],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &invite, &gid).await;

    // A standalone AppDataUpdate for it is admitted like any other.
    let proposal = standalone_app_data_update(
        &alice,
        &gid,
        ACCOUNT_DEVICES_COMPONENT_ID,
        AppDataUpdateOperation::Remove,
    );
    let outcome = bob.engine.ingest(proposal).await.unwrap();
    assert!(
        !matches!(outcome, IngestOutcome::Rejected { .. }),
        "unexpected rejection: {outcome:?}"
    );
}

// ── Activation and support ──────────────────────────────────────────────────

#[tokio::test]
async fn creation_requires_account_devices_only_when_every_founder_advertises_it() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    assert!(requires_account_devices(&bob.engine, &gid));

    let mut carol = device(b"carol", false);
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let refused = alice
        .engine
        .create_group(CreateGroupRequest {
            name: "unsupported".into(),
            description: String::new(),
            members: vec![carol_kp],
            required_features: vec![ACCOUNT_DEVICES],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await;
    assert!(refused.is_err(), "a non-advertising founder is refused");
}

#[tokio::test]
async fn upgrade_never_requires_account_devices() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], false, &mut [&mut bob]).await;

    let upgradeable = alice.engine.upgradeable_capabilities(&gid).unwrap();
    assert!(
        !upgradeable
            .app_components
            .contains(ACCOUNT_DEVICES_COMPONENT_ID),
        "every member advertises 0x800d, yet an upgrade must not require it"
    );
}

#[tokio::test]
async fn activation_and_adds_need_every_leaf_to_advertise_account_devices() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", false);
    let mut carol = device(b"carol", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let gid = found_group(
        &mut alice,
        vec![carol_kp, bob_kp],
        false,
        &mut [&mut carol, &mut bob],
    )
    .await;

    // Committer: bob's leaf does not advertise 0x800d.
    let ids = with_account_devices(required(&alice.engine, &gid));
    assert!(
        alice
            .engine
            .send(update_required(&gid, &ids))
            .await
            .is_err()
    );

    // Receiver: the same activation, crafted.
    let crafted = crafted_commit(&alice, &gid, vec![], vec![required_list_update(&ids)], None);
    assert_rejected_on_replay(&mut carol, &crafted, &gid).await;

    // Once bob leaves, the group can activate; then a non-advertising
    // device cannot be added.
    let remove = send_commit(
        &mut alice,
        SendIntent::RemoveMembers {
            group_id: gid.clone(),
            members: vec![bob.engine.self_id()],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut carol, &remove, &gid).await;
    activate(&mut alice, &gid, &mut [&mut carol]).await;

    let mut dave = device(b"dave", false);
    let dave_kp = dave.engine.fresh_key_package().await.unwrap();
    assert!(
        alice
            .engine
            .send(SendIntent::Invite {
                group_id: gid.clone(),
                key_packages: vec![dave_kp.clone()],
                initial_admins: vec![],
            })
            .await
            .is_err()
    );
    let crafted = crafted_commit(&alice, &gid, vec![dave_kp], vec![], None);
    assert_rejected_on_replay(&mut carol, &crafted, &gid).await;
}

// ── No data ─────────────────────────────────────────────────────────────────

async fn requiring_group() -> (Device, Device, GroupId) {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], true, &mut [&mut bob]).await;
    (alice, bob, gid)
}

#[tokio::test]
async fn group_context_data_is_rejected_once_required() {
    let (mut alice, mut bob, gid) = requiring_group().await;

    assert_refused(
        alice
            .engine
            .send(SendIntent::UpdateAppComponents {
                group_id: gid.clone(),
                updates: vec![AppComponentData {
                    component_id: ACCOUNT_DEVICES_COMPONENT_ID,
                    data: vec![1],
                }],
            })
            .await,
        "AppDataUpdate targets account-devices",
    );

    for operation in [
        AppDataUpdateProposal::update(ACCOUNT_DEVICES_COMPONENT_ID, vec![1]),
        AppDataUpdateProposal::remove(ACCOUNT_DEVICES_COMPONENT_ID),
    ] {
        let crafted = crafted_commit(&alice, &gid, vec![], vec![operation], None);
        assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
    }

    // The committer's state is unchanged, so its next valid commit is the
    // child of the same parent the rejected commits named.
    let ids = required(&alice.engine, &gid);
    let commit = send_commit(&mut alice, update_required(&gid, &ids), &gid).await;
    assert_accepted(&mut bob, &commit, &gid).await;
}

#[tokio::test]
async fn activation_with_group_context_data_must_remove_it() {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut alice, vec![bob_kp], false, &mut [&mut bob]).await;
    let write = send_commit(
        &mut alice,
        SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![AppComponentData {
                component_id: ACCOUNT_DEVICES_COMPONENT_ID,
                data: vec![1],
            }],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &write, &gid).await;

    let ids = with_account_devices(required(&alice.engine, &gid));
    assert_refused(
        alice.engine.send(update_required(&gid, &ids)).await,
        "GroupContext carries account-devices data",
    );
    let keeps_entry = crafted_commit(&alice, &gid, vec![], vec![required_list_update(&ids)], None);
    assert_rejected_on_replay(&mut bob, &keeps_entry, &gid).await;

    let removes_entry = crafted_commit(
        &alice,
        &gid,
        vec![],
        vec![
            required_list_update(&ids),
            AppDataUpdateProposal::remove(ACCOUNT_DEVICES_COMPONENT_ID),
        ],
        None,
    );
    assert_accepted(&mut bob, &removes_entry, &gid).await;
    assert!(requires_account_devices(&bob.engine, &gid));
}

#[tokio::test]
async fn added_key_package_data_is_rejected_once_required() {
    let (mut alice, mut bob, gid) = requiring_group().await;
    let mut carol = device(b"carol", true);

    for (in_leaf, in_key_package, reason) in [
        (true, false, "a leaf carries account-devices data"),
        (
            false,
            true,
            "an added KeyPackage carries account-devices data",
        ),
    ] {
        let kp = key_package_with_account_devices_data(&mut carol, in_leaf, in_key_package).await;
        assert_refused(
            alice
                .engine
                .send(SendIntent::Invite {
                    group_id: gid.clone(),
                    key_packages: vec![kp.clone()],
                    initial_admins: vec![],
                })
                .await,
            reason,
        );
        let crafted = crafted_commit(&alice, &gid, vec![kp], vec![], None);
        assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
    }
}

#[tokio::test]
async fn leaf_data_from_an_update_path_is_rejected_once_required() {
    let (alice, mut bob, gid) = requiring_group().await;
    let own_leaf = load_group(&alice, &gid)
        .own_leaf_node()
        .unwrap()
        .extensions()
        .clone();
    let crafted = crafted_commit(
        &alice,
        &gid,
        vec![],
        vec![],
        Some(with_account_devices_entry(own_leaf)),
    );
    assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
}

// ── Leaf limit ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_account_holds_at_most_the_leaf_limit() {
    let mut alice = device(b"alice", true);
    let mut carol = device(b"carol", true);
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let bob_kp = device(b"bob", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    // KeyPackages are last-resort, so the same ones found both groups below.
    let over_limit: Vec<_> = [carol_kp, bob_kp.clone()]
        .into_iter()
        .chain((0..MAX_LEAVES_PER_ACCOUNT).map(|_| sibling_key_package(&bob_kp, b"bob")))
        .collect();
    let (at_limit, extra_bob) = over_limit.split_at(over_limit.len() - 1);
    let limit_error = format!("an account holds more than {MAX_LEAVES_PER_ACCOUNT} leaves");

    // Founding one leaf over the limit is refused.
    let refused = alice
        .engine
        .create_group(CreateGroupRequest {
            name: "over the limit".into(),
            description: String::new(),
            members: over_limit.clone(),
            required_features: vec![ACCOUNT_DEVICES],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await;
    assert!(refused.unwrap_err().to_string().contains(&limit_error));

    // At the limit the group is valid; one more leaf is not.
    let gid = found_group(&mut alice, at_limit.to_vec(), true, &mut [&mut carol]).await;
    assert_refused(
        alice
            .engine
            .send(SendIntent::Invite {
                group_id: gid.clone(),
                key_packages: extra_bob.to_vec(),
                initial_admins: vec![],
            })
            .await,
        &limit_error,
    );
    let crafted = crafted_commit(&alice, &gid, extra_bob.to_vec(), vec![], None);
    assert_rejected_on_replay(&mut carol, &crafted, &gid).await;

    // Without the requirement the limit does not apply, and activation is
    // refused while an account is over it.
    let gid = found_group(&mut alice, over_limit, false, &mut [&mut carol]).await;
    let ids = with_account_devices(required(&alice.engine, &gid));
    assert_refused(
        alice.engine.send(update_required(&gid, &ids)).await,
        &limit_error,
    );
    let crafted = crafted_commit(&alice, &gid, vec![], vec![required_list_update(&ids)], None);
    assert_rejected_on_replay(&mut carol, &crafted, &gid).await;
}

// ── Never un-require ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_requiring_group_never_stops_requiring_account_devices() {
    let (mut alice, mut bob, gid) = requiring_group().await;
    let ids = without_account_devices(required(&alice.engine, &gid));

    assert_refused(
        alice.engine.send(update_required(&gid, &ids)).await,
        "account-devices cannot be un-required",
    );
    let crafted = crafted_commit(&alice, &gid, vec![], vec![required_list_update(&ids)], None);
    assert_rejected_on_replay(&mut bob, &crafted, &gid).await;
    assert!(requires_account_devices(&bob.engine, &gid));
}

#[tokio::test]
async fn standalone_proposals_breaking_the_rules_are_rejected_at_ingest() {
    let (alice, mut bob, gid) = requiring_group().await;
    let ids = without_account_devices(required(&alice.engine, &gid));

    for proposal in [
        standalone_app_data_update(
            &alice,
            &gid,
            ACCOUNT_DEVICES_COMPONENT_ID,
            AppDataUpdateOperation::Update(vec![1].into()),
        ),
        standalone_app_data_update(
            &alice,
            &gid,
            ACCOUNT_DEVICES_COMPONENT_ID,
            AppDataUpdateOperation::Remove,
        ),
        standalone_app_data_update(
            &alice,
            &gid,
            APP_COMPONENTS_COMPONENT_ID,
            AppDataUpdateOperation::Update(encode_components_list(&ids.ids).into()),
        ),
        standalone_required_list_extensions(&alice, &gid, &ids),
    ] {
        assert_rejected_at_ingest(&mut bob, &proposal).await;
    }
}

// ── Legacy profile ──────────────────────────────────────────────────────────

/// Legacy groups never require 0x800d: even when one lists it, none of the
/// rules applies there. 0x800d stays an opaque id that needs GroupContext data
/// while required, as on the clients those groups were deployed with.
#[tokio::test]
async fn legacy_groups_are_not_subject_to_the_rules() {
    let legacy_device = |account: &[u8]| {
        let storage = SqliteAccountStorage::in_memory().unwrap();
        let mut supported: Vec<_> = default_group_components().into_iter().collect();
        supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
        let engine = EngineBuilder::new(storage.clone())
            .legacy_compatibility_profile()
            .identity(pad32(account))
            .account_identity_proof_signer(proof_signer(account))
            .feature_registry(registry())
            .supported_app_components(supported)
            .allow_account_devices_advertising_for_tests()
            .peeler(Box::<MockPeeler>::default())
            .build()
            .unwrap();
        Device { engine, storage }
    };
    let mut alice = legacy_device(b"alice");
    let mut bob = legacy_device(b"bob");
    let bob_kp = bob.engine.fresh_key_package().await.unwrap();
    let (gid, created) = alice
        .engine
        .create_group(CreateGroupRequest {
            name: "legacy".into(),
            description: String::new(),
            members: vec![bob_kp],
            required_features: vec![],
            app_components: vec![],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let SendResult::GroupCreated { pending, welcomes } = created else {
        panic!("legacy founding group")
    };
    alice.engine.confirm_published(pending).await.unwrap();
    bob.engine
        .join_welcome(welcomes.into_iter().next().unwrap())
        .await
        .unwrap();

    // On the legacy profile 0x800d is an opaque id: requiring it takes
    // GroupContext data, which stays while it is required.
    let ids = with_account_devices(required(&alice.engine, &gid));
    let require_with_data = send_commit(
        &mut alice,
        SendIntent::UpdateAppComponents {
            group_id: gid.clone(),
            updates: vec![
                AppComponentData {
                    component_id: APP_COMPONENTS_COMPONENT_ID,
                    data: encode_components_list(&ids.ids),
                },
                AppComponentData {
                    component_id: ACCOUNT_DEVICES_COMPONENT_ID,
                    data: vec![1],
                },
            ],
        },
        &gid,
    )
    .await;
    assert_accepted(&mut bob, &require_with_data, &gid).await;
    assert!(requires_account_devices(&alice.engine, &gid));
    let removes_entry = crafted_commit(
        &alice,
        &gid,
        vec![],
        vec![AppDataUpdateProposal::remove(ACCOUNT_DEVICES_COMPONENT_ID)],
        None,
    );
    assert_rejected_on_replay(&mut bob, &removes_entry, &gid).await;
    let ids = without_account_devices(required(&alice.engine, &gid));
    let unrequire = send_commit(&mut alice, update_required(&gid, &ids), &gid).await;
    assert_accepted(&mut bob, &unrequire, &gid).await;
}
