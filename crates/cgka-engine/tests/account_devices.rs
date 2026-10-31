//! `marmot.group.account-devices.v1` (0x800d) resulting-state rules
//! (account-devices-v1.md; mdk#2628 items 2.1b, 2.1c, 2.1d and 2.4).
//!
//! Covers, for a group whose GroupContext `app_components` list requires
//! 0x800d:
//! - No data: no 0x800d entry in the GroupContext, in any leaf, in an added
//!   KeyPackage, or in a Welcome's GroupInfo, and no AppDataUpdate for it.
//! - Support: every leaf advertises 0x800d.
//! - Leaf limit: at most `MAX_LEAVES_PER_ACCOUNT` leaves per account.
//! - Never un-require: no Commit or standalone proposal drops 0x800d from the
//!   required list.
//! - Welcome acceptance: a device joins through a Welcome from a device of its
//!   own account, as through an admin's.
//! - Same-account Commits (mdk#2628 item 2.1c): a non-admin may add and remove
//!   leaves of its own account, by value and with nothing else in the Commit.
//!   One classifier decides authority and branch priority; a same-account
//!   Commit is `ordinary` whoever commits it.
//!
//! Each rule is shown from the committer's side (the engine refuses to send)
//! and the receiver's side (a commit crafted with raw OpenMLS is dropped by
//! replay, a crafted standalone proposal is rejected at ingest, and a joiner
//! refuses a crafted Welcome). Before a group requires 0x800d, its data is
//! accepted like any unknown component's, and only an admin's Welcome joins.

use async_trait::async_trait;
use cgka_engine::account_identity_proof::account_identity_proof_component;
use cgka_engine::canonicalization::{CanonicalizationResult, DroppedMessageReason};
use cgka_engine::commit_class::{CommitAuthorityError, CommitClass, authorize_staged_commit};
use cgka_engine::convergence::BranchSelectionTrace;
use cgka_engine::feature_registry::FeatureRegistry;
use cgka_engine::provider::EngineOpenMlsProvider;
use cgka_engine::{DEFAULT_CIPHERSUITE, Engine, EngineBuilder};
use cgka_traits::EngineError;
use cgka_traits::app_components::{
    ACCOUNT_DEVICES_COMPONENT_ID, ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, APP_COMPONENTS_COMPONENT_ID,
    AppComponentData, AppComponentSet, GROUP_PROFILE_COMPONENT_ID, GroupProfileV1,
    MAX_LEAVES_PER_ACCOUNT, SAFE_AAD_COMPONENT_ID, default_group_components,
    encode_components_list, encode_group_profile_v1,
};
use cgka_traits::capabilities::{Capability, CapabilityRequirement, Feature, RequirementLevel};
use cgka_traits::engine::{
    CgkaEngine, CommitOrderingPriority, CreateGroupRequest, GroupEvent, KeyPackage, SendIntent,
    SendResult,
};
use cgka_traits::error::PeelerError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::group_context::GroupContextSnapshot;
use cgka_traits::ingest::{
    IngestOutcome, InputRejectionCategory, PeeledContent, PeeledMessage, ProposalRejectionCategory,
};
use cgka_traits::message::StoredMessagePayload;
use cgka_traits::peeler::TransportPeeler;
use cgka_traits::storage::{AccountDeviceSignerStorage, MessageStorage, StorageProvider};
use cgka_traits::transport::{
    EncryptedPayload, Timestamp, TransportEnvelope, TransportMessage, TransportSource,
};
use cgka_traits::types::{GroupId, MemberId, MessageId};
use openmls::component::ComponentData;
use openmls::extensions::{
    AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionValidator, Extensions,
};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{
    CommitMessageBundle, CredentialWithKey, KeyPackage as MlsKeyPackage, LeafNode,
    LeafNodeParameters, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
};
use openmls::prelude::{LeafNodeIndex, ProcessedMessageContent};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::OpenMlsProvider as _;
use sha2::{Digest, Sha256};
use storage_sqlite::SqliteAccountStorage;
use tls_codec::{Deserialize as _, Serialize as _};

mod support;
use support::proof_signer;

#[path = "account_devices/send_intents.rs"]
mod send_intents;

#[path = "account_devices/creation.rs"]
mod creation;

#[path = "account_devices/activation.rs"]
mod activation;

#[path = "account_devices/private_key_packages.rs"]
mod private_key_packages;

// The device roster's wire format is unreleased, so only test-policy builds
// may advertise it (mdk#2628 3.1).
#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/device_roster.rs"]
mod device_roster;

// The link Commit writes the roster, so it is test-policy only too
// (mdk#2628 3.3b).
#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/link_device.rs"]
mod link_device;

// A device group joins only through the Welcome its link expects
// (mdk#2628 D28, D30).
#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/device_group_welcome.rs"]
mod device_group_welcome;

#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/device_tag.rs"]
mod device_tag;

// Whether a recovery key may still be the account's (mdk#2628 4.4a).
#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/recovery_key_in_use.rs"]
mod recovery_key_in_use;

// The rosters a device applied record what they announced (mdk#2628 D31
// item 7).
#[cfg(feature = "test-policy-overrides")]
#[path = "account_devices/announced_key_packages.rs"]
mod announced_key_packages;

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
    let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
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

/// `creator` founds a group with `members` through the engine alone: no
/// required feature or component from the host decides whether it requires
/// 0x800d. Returns the founding Welcomes, one per KeyPackage in order.
async fn create(
    creator: &mut Device,
    members: Vec<KeyPackage>,
    initial_admins: Vec<MemberId>,
) -> Result<(GroupId, Vec<TransportMessage>), EngineError> {
    let (gid, created) = creator
        .engine
        .create_group(CreateGroupRequest {
            name: "account-devices".into(),
            description: String::new(),
            members,
            required_features: vec![],
            app_components: vec![],
            initial_admins,
        })
        .await?;
    let SendResult::FoundingGroupCreated { welcomes } = created else {
        panic!("current-profile founding group")
    };
    Ok((gid, welcomes))
}

/// `alice` founds a group with `members` and each of `joiners` joins from the
/// Welcome at the same index. The group requires 0x800d when `require` is set;
/// see [`found_group_with_admins`].
async fn found_group(
    alice: &mut Device,
    members: Vec<KeyPackage>,
    require: bool,
    joiners: &mut [&mut Device],
) -> GroupId {
    found_group_with_admins(alice, members, require, vec![], joiners).await
}

/// [`found_group`] with `initial_admins` besides `alice`.
///
/// Creation requires 0x800d by itself when `alice` and every founder advertise
/// it (mdk#2628 item 2.3), so `require` needs every founder to. Without
/// `require`, a device that does not advertise it is founded with the others
/// and removed right after, which is how a group whose members all advertise
/// 0x800d comes not to require it.
async fn found_group_with_admins(
    alice: &mut Device,
    mut members: Vec<KeyPackage>,
    require: bool,
    initial_admins: Vec<MemberId>,
    joiners: &mut [&mut Device],
) -> GroupId {
    let mut outsider = None;
    if !require {
        let mut device = device(b"outsider", false);
        members.push(device.engine.fresh_key_package().await.unwrap());
        outsider = Some(device.engine.self_id());
    }
    let (gid, welcomes) = create(alice, members, initial_admins).await.unwrap();
    for (joiner, welcome) in joiners.iter_mut().zip(welcomes) {
        joiner.engine.join_welcome(welcome).await.unwrap();
    }
    if let Some(outsider) = outsider {
        let remove = send_commit(
            alice,
            SendIntent::RemoveMembers {
                group_id: gid.clone(),
                members: vec![outsider],
            },
            &gid,
        )
        .await;
        for joiner in joiners.iter_mut() {
            assert_accepted(joiner, &remove, &gid).await;
        }
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

async fn assert_accepted(
    receiver: &mut Device,
    commit: &TransportMessage,
    gid: &GroupId,
) -> CanonicalizationResult {
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
    result
}

/// Replay drops `commit` as invalid against its candidate parent, so it never
/// becomes an edge: the receiver stays at its epoch and keeps the parent open.
/// Returns the rejection category replay reported.
async fn assert_rejected_on_replay(
    receiver: &mut Device,
    commit: &TransportMessage,
    gid: &GroupId,
) -> Option<ProposalRejectionCategory> {
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
    let dropped = result
        .dropped_messages
        .iter()
        .find(|dropped| {
            dropped.message_id == commit_id
                && dropped.reason == DroppedMessageReason::InvalidAgainstCandidateState
        })
        .unwrap_or_else(|| panic!("dropped: {:?}", result.dropped_messages));
    assert_eq!(receiver.engine.epoch(gid).unwrap().0, before);
    assert_eq!(required(&receiver.engine, gid), required_before);
    dropped.rejection_category
}

fn assert_refused(result: Result<SendResult, EngineError>, reason: &str) {
    let error = result.expect_err("the committer refuses the commit");
    assert!(
        error.to_string().contains(reason),
        "expected {reason:?}, got: {error}"
    );
}

/// The refusal of a same-account intent in a group that does not require
/// account-devices.
#[track_caller]
fn assert_not_required(result: Result<SendResult, EngineError>) {
    assert!(
        matches!(
            &result,
            Err(EngineError::InvalidTransition(transition))
                if transition.from == "AccountDevicesNotRequired"
        ),
        "expected the account-devices requirement refusal, got {result:?}"
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

/// The parts of a Commit [`craft`] builds with raw OpenMLS.
#[derive(Default)]
struct Parts {
    adds: Vec<KeyPackage>,
    removes: Vec<u32>,
    app_data: Vec<AppDataUpdateProposal>,
    /// A replacement for the committer's leaf, carried in its update path.
    leaf_extensions: Option<Extensions<LeafNode>>,
    /// Proposal messages the committer stores and commits by reference.
    by_reference: Vec<TransportMessage>,
    /// Extensions for the Welcome's GroupInfo, beside the ratchet tree.
    group_info_extensions: Vec<Extension>,
    /// Resulting GroupContext bytes the committer writes for a component in
    /// place of its update's bytes, as a client that resolves the update its
    /// own way would.
    app_data_state: Vec<(u16, Vec<u8>)>,
}

/// A Commit `sender` builds with raw OpenMLS, bypassing the engine's send
/// paths, with the committer's verdict on it: the check every send path runs
/// before it publishes, against the same parent. The sender's group is left as
/// it was, so it can still commit.
fn craft(
    sender: &Device,
    gid: &GroupId,
    parts: Parts,
) -> (Result<CommitClass, CommitAuthorityError>, TransportMessage) {
    let (verdict, bundle) = craft_bundle(sender, gid, parts);
    (
        verdict,
        group_transport(bundle.into_commit(), gid, "crafted-commit"),
    )
}

/// The Welcome of a Commit `sender` builds as [`crafted_commit`] does, for
/// `recipient`'s account. `group_info_extensions` go into its GroupInfo
/// beside the ratchet tree. The Commit itself reaches nobody.
fn crafted_welcome(
    sender: &Device,
    gid: &GroupId,
    adds: &[KeyPackage],
    app_data: Vec<AppDataUpdateProposal>,
    group_info_extensions: Vec<Extension>,
    recipient: &Device,
) -> TransportMessage {
    let (_, bundle) = craft_bundle(
        sender,
        gid,
        Parts {
            adds: adds.to_vec(),
            app_data,
            group_info_extensions,
            ..Parts::default()
        },
    );
    let payload = bundle
        .into_welcome_msg()
        .expect("a Commit that adds members has a Welcome")
        .tls_serialize_detached()
        .unwrap();
    TransportMessage {
        id: hash_id(&payload),
        payload,
        timestamp: Timestamp(0),
        causal_deps: vec![],
        source: TransportSource("crafted-welcome".into()),
        envelope: TransportEnvelope::Welcome {
            recipient: recipient.engine.self_id(),
        },
    }
}

/// A GroupInfo `app_data_dictionary` with an entry under 0x800d.
fn group_info_account_devices_entry() -> Vec<Extension> {
    let mut dictionary = AppDataDictionary::default();
    dictionary.insert(ACCOUNT_DEVICES_COMPONENT_ID, vec![1]);
    vec![Extension::AppDataDictionary(
        AppDataDictionaryExtension::new(dictionary),
    )]
}

/// The Commit [`craft`] builds, with its Welcome when it adds members.
fn craft_bundle(
    sender: &Device,
    gid: &GroupId,
    parts: Parts,
) -> (
    Result<CommitClass, CommitAuthorityError>,
    CommitMessageBundle,
) {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, sender.storage.mls_storage());
    let mut group = load_group(sender, gid);
    for message in &parts.by_reference {
        let message = MlsMessageIn::tls_deserialize_exact(message.payload.as_slice())
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let ProcessedMessageContent::ProposalMessage(queued) = group
            .process_message(&provider, message)
            .expect("the committer processes the proposal")
            .into_content()
        else {
            panic!("expected a proposal")
        };
        group
            .store_pending_proposal(provider.storage(), *queued)
            .unwrap();
    }
    let mut builder = group
        .commit_builder()
        .consume_proposal_store(!parts.by_reference.is_empty())
        .propose_adds(parts.adds.iter().map(parse_key_package))
        .propose_removals(parts.removes.into_iter().map(LeafNodeIndex::new))
        .add_proposals(
            parts
                .app_data
                .into_iter()
                .map(|proposal| Proposal::AppDataUpdate(Box::new(proposal))),
        );
    if let Some(extensions) = parts.leaf_extensions {
        builder = builder.force_self_update(true).leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_extensions(extensions)
                .build(),
        );
    }
    let mut builder = builder.load_psks(provider.storage()).unwrap();
    if !parts.group_info_extensions.is_empty() {
        builder = builder
            .create_group_info_with_extensions(parts.group_info_extensions)
            .unwrap();
    }
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
    for (component_id, state) in parts.app_data_state {
        updater.set(ComponentData::from_parts(component_id, state.into()));
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
    let verdict = authorize_staged_commit(
        &group,
        gid,
        Some(group.own_leaf_index()),
        Some(&sender.engine.self_id()),
        group.pending_commit().unwrap(),
    );
    group.clear_pending_commit(provider.storage()).unwrap();
    group.clear_pending_proposals(provider.storage()).unwrap();
    (verdict, bundle)
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
    craft(
        sender,
        gid,
        Parts {
            adds,
            app_data,
            leaf_extensions,
            ..Parts::default()
        },
    )
    .1
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
    standalone_dictionary_extensions(
        sender,
        gid,
        APP_COMPONENTS_COMPONENT_ID,
        encode_components_list(&ids.ids),
    )
}

/// A standalone GroupContextExtensions proposal that keeps the current
/// GroupContext except for `bytes` under `component_id`.
fn standalone_dictionary_extensions(
    sender: &Device,
    gid: &GroupId,
    component_id: u16,
    bytes: Vec<u8>,
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
    dictionary.insert(component_id, bytes);
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
    EngineBuilder::new(SqliteAccountStorage::in_memory_for_test().unwrap())
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
    let mut supported = defaults.clone();
    supported.push(SAFE_AAD_COMPONENT_ID);
    let error = try_build(supported).err().expect("the builder refuses");
    assert!(
        error.to_string().contains("does not implement it"),
        "unexpected error: {error}"
    );
    // The engine enforces every account-devices rule, so any build may
    // advertise it (mdk#2628, item 2.2).
    let mut supported = defaults.clone();
    supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
    try_build(supported).expect("account-devices is advertisable");
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

/// The resulting-state refusal of an account over the leaf limit.
fn limit_error() -> String {
    format!("an account holds more than {MAX_LEAVES_PER_ACCOUNT} leaves")
}

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
    let limit_error = limit_error();

    // Founding one leaf over the limit is refused
    // (`creation::a_founding_add_over_the_leaf_limit_is_refused_before_any_welcome`).
    let refused = create(&mut alice, over_limit.clone(), vec![]).await;
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
        let storage = SqliteAccountStorage::in_memory_for_test().unwrap();
        let mut supported: Vec<_> = default_group_components().into_iter().collect();
        supported.push(ACCOUNT_DEVICES_COMPONENT_ID);
        let engine = EngineBuilder::new(storage.clone())
            .legacy_compatibility_profile()
            .identity(pad32(account))
            .account_identity_proof_signer(proof_signer(account))
            .feature_registry(registry())
            .supported_app_components(supported)
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

    // The account-devices activation intent refuses a legacy group outright.
    assert_eq!(
        alice
            .engine
            .account_devices_activation_refusal(&gid)
            .unwrap(),
        Some(cgka_traits::error::AccountDevicesActivationRefusal::LegacyProfile)
    );
    assert!(matches!(
        alice
            .engine
            .send(SendIntent::EnableAccountDevices {
                group_id: gid.clone(),
            })
            .await,
        Err(EngineError::AccountDevicesActivationRefused {
            reason: cgka_traits::error::AccountDevicesActivationRefusal::LegacyProfile,
            ..
        })
    ));

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
    // Only an admin adds here, even another device of the author's account.
    let mut bob_laptop = legacy_device(b"bob");
    let bob_laptop_kp = bob_laptop.engine.fresh_key_package().await.unwrap();
    let welcome = crafted_welcome(&bob, &gid, &[bob_laptop_kp], vec![], vec![], &bob_laptop);
    assert_eq!(
        join_outcome(&mut bob_laptop, &welcome).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
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

// ── Welcome acceptance ──────────────────────────────────────────────────────

async fn join_outcome(joiner: &mut Device, welcome: &TransportMessage) -> IngestOutcome {
    joiner.engine.ingest(welcome.clone()).await.unwrap()
}

fn refused(category: InputRejectionCategory) -> IngestOutcome {
    IngestOutcome::Ignored { category }
}

/// `joiner` joins `gid` through `welcome`, and names `author` as its author.
async fn assert_joins(
    joiner: &mut Device,
    welcome: &TransportMessage,
    gid: &GroupId,
    author: &Device,
) {
    assert_eq!(
        join_outcome(joiner, welcome).await,
        IngestOutcome::Processed
    );
    let welcomers: Vec<_> = joiner
        .engine
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            GroupEvent::GroupJoined {
                group_id, welcomer, ..
            } if &group_id == gid => welcomer,
            _ => None,
        })
        .collect();
    assert_eq!(welcomers, vec![author.engine.self_id()]);
}

fn is_admin(device: &Device, gid: &GroupId) -> bool {
    let id = device.engine.self_id();
    device
        .engine
        .admin_pubkeys(gid)
        .unwrap()
        .iter()
        .any(|admin| admin.as_slice() == id.as_slice())
}

/// Bob's group, requiring 0x800d when `require` is set, with Alice's phone as
/// a member who is not an admin, and Alice's laptop, which has not joined.
async fn alice_and_a_new_device(require: bool) -> (Device, Device, Device, GroupId) {
    let mut bob = device(b"bob", true);
    let mut phone = device(b"alice", true);
    let laptop = device(b"alice", true);
    let phone_kp = phone.engine.fresh_key_package().await.unwrap();
    let gid = found_group(&mut bob, vec![phone_kp], require, &mut [&mut phone]).await;
    assert!(!is_admin(&phone, &gid));
    (bob, phone, laptop, gid)
}

#[tokio::test]
async fn a_device_joins_through_its_own_accounts_welcome_once_required() {
    let (bob, phone, mut laptop, gid) = alice_and_a_new_device(true).await;
    let laptop_kp = laptop.engine.fresh_key_package().await.unwrap();
    let welcome = crafted_welcome(&phone, &gid, &[laptop_kp], vec![], vec![], &laptop);

    assert_joins(&mut laptop, &welcome, &gid, &phone).await;
    assert!(requires_account_devices(&laptop.engine, &gid));
    let leaves_of = |account: &Device| {
        let id = account.engine.self_id();
        laptop
            .engine
            .members(&gid)
            .unwrap()
            .iter()
            .filter(|member| member.id == id)
            .count()
    };
    assert_eq!((leaves_of(&phone), leaves_of(&bob)), (2, 1));
}

#[tokio::test]
async fn an_own_account_welcome_is_refused_before_account_devices_is_required() {
    let (_bob, phone, mut laptop, gid) = alice_and_a_new_device(false).await;
    let laptop_kp = laptop.engine.fresh_key_package().await.unwrap();
    let welcome = crafted_welcome(&phone, &gid, &[laptop_kp], vec![], vec![], &laptop);

    assert_eq!(
        join_outcome(&mut laptop, &welcome).await,
        refused(InputRejectionCategory::AuthorizationFailed)
    );
    assert!(laptop.engine.epoch(&gid).is_err());
}

#[tokio::test]
async fn another_accounts_non_admin_cannot_add_even_once_required() {
    let mut bob = device(b"bob", true);
    let mut phone = device(b"alice", true);
    let mut carol = device(b"carol", true);
    let phone_kp = phone.engine.fresh_key_package().await.unwrap();
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let gid = found_group(
        &mut bob,
        vec![phone_kp, carol_kp],
        true,
        &mut [&mut phone, &mut carol],
    )
    .await;

    // Carol is no admin, and neither joiner is of her account, even the one
    // whose account is already a member.
    let mut laptop = device(b"alice", true);
    let mut dave = device(b"dave", true);
    for joiner in [&mut laptop, &mut dave] {
        let kp = joiner.engine.fresh_key_package().await.unwrap();
        let welcome = crafted_welcome(&carol, &gid, &[kp], vec![], vec![], joiner);
        assert_eq!(
            join_outcome(joiner, &welcome).await,
            refused(InputRejectionCategory::AuthorizationFailed)
        );
    }
}

#[tokio::test]
async fn a_group_info_with_account_devices_data_is_refused_once_required() {
    let (bob, phone, mut laptop, gid) = alice_and_a_new_device(true).await;
    let mut dave = device(b"dave", true);
    let dave_kp = dave.engine.fresh_key_package().await.unwrap();
    let laptop_kp = laptop.engine.fresh_key_package().await.unwrap();

    // An admin's Welcome and a same-account Welcome alike. Without the entry,
    // the same Add joins.
    for (author, joiner, kp) in [(&bob, &mut dave, dave_kp), (&phone, &mut laptop, laptop_kp)] {
        let welcome = crafted_welcome(
            author,
            &gid,
            std::slice::from_ref(&kp),
            vec![],
            group_info_account_devices_entry(),
            joiner,
        );
        assert_eq!(
            join_outcome(joiner, &welcome).await,
            refused(InputRejectionCategory::InvalidEncoding)
        );
        let welcome = crafted_welcome(author, &gid, &[kp], vec![], vec![], joiner);
        assert_joins(joiner, &welcome, &gid, author).await;
    }
}

#[tokio::test]
async fn a_group_info_with_account_devices_data_is_unknown_data_before_activation() {
    let (bob, _phone, _laptop, gid) = alice_and_a_new_device(false).await;
    let mut dave = device(b"dave", true);
    let dave_kp = dave.engine.fresh_key_package().await.unwrap();
    let welcome = crafted_welcome(
        &bob,
        &gid,
        &[dave_kp],
        vec![],
        group_info_account_devices_entry(),
        &dave,
    );
    assert_joins(&mut dave, &welcome, &gid, &bob).await;
}

/// The state rules the members apply to every Commit apply to the state a
/// Welcome joins, whoever authored it.
#[tokio::test]
async fn a_joined_state_breaking_the_rules_is_refused() {
    let mut alice = device(b"alice", true);
    let mut carol = device(b"carol", true);
    let mut dave = device(b"dave", true);
    let carol_kp = carol.engine.fresh_key_package().await.unwrap();
    let dave_kp = dave.engine.fresh_key_package().await.unwrap();
    let bob_kp = device(b"bob", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let founders: Vec<_> = [carol_kp, bob_kp.clone()]
        .into_iter()
        .chain((1..MAX_LEAVES_PER_ACCOUNT).map(|_| sibling_key_package(&bob_kp, b"bob")))
        .collect();
    let gid = found_group(&mut alice, founders, true, &mut [&mut carol]).await;
    let unsupported = device(b"erin", false)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let mut frank = device(b"frank", true);
    let leaf_data = key_package_with_account_devices_data(&mut frank, true, false).await;

    for (rule, extra, app_data) in [
        (
            "leaf limit",
            vec![sibling_key_package(&bob_kp, b"bob")],
            vec![],
        ),
        ("support", vec![unsupported], vec![]),
        ("no leaf data", vec![leaf_data], vec![]),
        (
            "no GroupContext data",
            vec![],
            vec![AppDataUpdateProposal::update(
                ACCOUNT_DEVICES_COMPONENT_ID,
                vec![1],
            )],
        ),
    ] {
        let adds: Vec<_> = extra.into_iter().chain([dave_kp.clone()]).collect();
        let welcome = crafted_welcome(&alice, &gid, &adds, app_data, vec![], &dave);
        assert_eq!(
            join_outcome(&mut dave, &welcome).await,
            refused(InputRejectionCategory::InvalidEncoding),
            "{rule}"
        );
    }
    let welcome = crafted_welcome(&alice, &gid, &[dave_kp], vec![], vec![], &dave);
    assert_joins(&mut dave, &welcome, &gid, &alice).await;
}

// ── Same-account Commits ────────────────────────────────────────────────────

/// alice founds the group and is its only admin; bob joins on two devices and
/// carol on one. Every device advertises 0x800d; the group requires it when
/// `require` is set.
struct Members {
    alice: Device,
    bob: Device,
    bob_sibling: Device,
    carol: Device,
    gid: GroupId,
}

async fn members(require: bool) -> Members {
    let mut alice = device(b"alice", true);
    let mut bob = device(b"bob", true);
    let mut bob_sibling = device(b"bob", true);
    let mut carol = device(b"carol", true);
    let key_packages = vec![
        bob.engine.fresh_key_package().await.unwrap(),
        bob_sibling.engine.fresh_key_package().await.unwrap(),
        carol.engine.fresh_key_package().await.unwrap(),
    ];
    let gid = found_group(
        &mut alice,
        key_packages,
        require,
        &mut [&mut bob, &mut bob_sibling, &mut carol],
    )
    .await;
    Members {
        alice,
        bob,
        bob_sibling,
        carol,
        gid,
    }
}

fn leaf(device: &Device, gid: &GroupId) -> u32 {
    load_group(device, gid).own_leaf_index().u32()
}

/// The signature key of `device`'s leaf, which names it in a same-account
/// Remove.
fn signature_key(device: &Device, gid: &GroupId) -> Vec<u8> {
    load_group(device, gid)
        .own_leaf_node()
        .expect("a current member")
        .signature_key()
        .as_slice()
        .to_vec()
}

fn add_own_devices(gid: &GroupId, key_packages: Vec<KeyPackage>) -> SendIntent {
    SendIntent::AddOwnAccountDevices {
        group_id: gid.clone(),
        key_packages,
    }
}

fn remove_own_devices(gid: &GroupId, leaf_signature_keys: Vec<Vec<u8>>) -> SendIntent {
    SendIntent::RemoveOwnAccountDevices {
        group_id: gid.clone(),
        leaf_signature_keys,
    }
}

/// A KeyPackage of a new device of `device`'s account.
async fn new_sibling_key_package(device: &mut Device, account: &[u8]) -> KeyPackage {
    sibling_key_package(&device.engine.fresh_key_package().await.unwrap(), account)
}

/// The priority `device`'s publish stamped on its own commit.
fn stamped_priority(device: &Device, commit: &TransportMessage) -> CommitOrderingPriority {
    let record = device.storage.get_message(&commit.id).unwrap();
    StoredMessagePayload::decode(&record.payload)
        .unwrap()
        .own_commit_stamp()
        .expect("an own commit carries its stamp")
        .priority
}

/// The priority a pass gave the branch whose tip is `commit`.
fn traced_priority(
    result: &CanonicalizationResult,
    commit: &TransportMessage,
) -> CommitOrderingPriority {
    let digest: [u8; 32] = Sha256::digest(&commit.payload).into();
    result
        .selection_trace
        .as_ref()
        .expect("the pass selected among candidates")
        .candidates
        .iter()
        .find(|candidate| candidate.tip_digest == digest)
        .expect("the commit is a branch tip")
        .tip_priority
}

fn assert_refused_for_authorization(verdict: Result<CommitClass, CommitAuthorityError>) {
    assert!(
        matches!(
            verdict,
            Err(CommitAuthorityError::Proposal(
                ProposalRejectionCategory::AuthorizationFailed
            ))
        ),
        "the committer refuses it as authorization_failed, got {verdict:?}"
    );
}

#[tokio::test]
async fn a_non_admin_commits_its_own_accounts_adds_and_removes() {
    // An Add of a new bob device.
    let mut m = members(true).await;
    let kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let (verdict, add) = craft(
        &m.bob,
        &m.gid,
        Parts {
            adds: vec![kp],
            ..Parts::default()
        },
    );
    assert_eq!(verdict.unwrap(), CommitClass::SameAccount);
    for receiver in [&mut m.alice, &mut m.bob_sibling, &mut m.carol] {
        let result = assert_accepted(receiver, &add, &m.gid).await;
        assert_eq!(
            traced_priority(&result, &add),
            CommitOrderingPriority::Ordinary
        );
    }

    // A Remove of bob's other device, through the committer's own send path.
    let mut m = members(true).await;
    let sibling = signature_key(&m.bob_sibling, &m.gid);
    let remove = send_commit(
        &mut m.bob,
        remove_own_devices(&m.gid, vec![sibling]),
        &m.gid,
    )
    .await;
    assert_eq!(
        stamped_priority(&m.bob, &remove),
        CommitOrderingPriority::Ordinary
    );
    for receiver in [&mut m.alice, &mut m.carol] {
        let result = assert_accepted(receiver, &remove, &m.gid).await;
        assert_eq!(
            traced_priority(&result, &remove),
            CommitOrderingPriority::Ordinary
        );
    }
    assert_accepted(&mut m.bob_sibling, &remove, &m.gid).await;
    assert!(m.bob_sibling.engine.group_record(&m.gid).unwrap().removed);

    // Both in one Commit.
    let mut m = members(true).await;
    let kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let (verdict, both) = craft(
        &m.bob,
        &m.gid,
        Parts {
            adds: vec![kp],
            removes: vec![leaf(&m.bob_sibling, &m.gid)],
            ..Parts::default()
        },
    );
    assert_eq!(verdict.unwrap(), CommitClass::SameAccount);
    assert_accepted(&mut m.carol, &both, &m.gid).await;
    assert_accepted(&mut m.alice, &both, &m.gid).await;
}

/// Every Commit outside the same-account shape needs an admin. The committer
/// refuses each one before publishing, and replay rejects it, leaving the
/// receiver at the parent.
#[tokio::test]
async fn a_non_admin_cannot_commit_anything_beside_its_own_accounts_leaves() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let bob_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let dave_kp = device(b"dave", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let carol_leaf = leaf(&m.carol, &gid);
    let profile = AppDataUpdateProposal::update(
        GROUP_PROFILE_COMPONENT_ID,
        encode_group_profile_v1(&GroupProfileV1 {
            name: "renamed".into(),
            description: String::new(),
        })
        .unwrap(),
    );

    for parts in [
        // An Add whose KeyPackage belongs to another account.
        Parts {
            adds: vec![dave_kp.clone()],
            ..Parts::default()
        },
        // A Remove of another account's leaf.
        Parts {
            removes: vec![carol_leaf],
            ..Parts::default()
        },
        // Same-account operations mixed with another account's.
        Parts {
            adds: vec![bob_kp.clone(), dave_kp.clone()],
            ..Parts::default()
        },
        Parts {
            adds: vec![bob_kp.clone()],
            removes: vec![carol_leaf],
            ..Parts::default()
        },
        // Same-account operations mixed with a group change.
        Parts {
            adds: vec![bob_kp.clone()],
            app_data: vec![profile.clone()],
            ..Parts::default()
        },
    ] {
        let (verdict, commit) = craft(&m.bob, &gid, parts);
        assert_refused_for_authorization(verdict);
        assert_eq!(
            assert_rejected_on_replay(&mut m.carol, &commit, &gid).await,
            Some(ProposalRejectionCategory::AuthorizationFailed)
        );
    }

    // The committer's send path refuses another account's leaf, alone or
    // beside a same-account Remove, and its own leaf, which leaves through
    // Leave. OpenMLS also refuses to stage a Commit that removes its
    // committer (and rejects one on receipt), so that one is never classified.
    let carol_key = signature_key(&m.carol, &gid);
    let sibling_key = signature_key(&m.bob_sibling, &gid);
    for (keys, reason) in [
        (vec![carol_key.clone()], "belongs to another account"),
        (vec![sibling_key, carol_key], "belongs to another account"),
        (vec![signature_key(&m.bob, &gid)], "use SendIntent::Leave"),
    ] {
        assert_refused(
            m.bob.engine.send(remove_own_devices(&gid, keys)).await,
            reason,
        );
    }

    // An Add of bob's device carried by reference: alice, an admin, proposes
    // it and bob commits her proposal. A same-account Add is by value only, so
    // the Commit is admin-required. Each proposal is authorized on its own, so
    // the refusal is the committer check, which replay reports without a
    // category in every group, as before this class existed (mdk#2647).
    let proposal = standalone_add(&m.alice, &gid, &bob_kp);
    let outcome = m.carol.engine.ingest(proposal.clone()).await.unwrap();
    assert!(
        !matches!(outcome, IngestOutcome::Rejected { .. }),
        "an admin's Add proposal is admitted: {outcome:?}"
    );
    let (verdict, by_reference) = craft(
        &m.bob,
        &gid,
        Parts {
            by_reference: vec![proposal],
            ..Parts::default()
        },
    );
    assert!(
        matches!(verdict, Err(CommitAuthorityError::NotAdmin)),
        "{verdict:?}"
    );
    assert_eq!(
        assert_rejected_on_replay(&mut m.carol, &by_reference, &gid).await,
        None
    );

    // Every rejected Commit left the parent open: bob's same-account Add of
    // the same KeyPackage, by value, is accepted.
    let (verdict, add) = craft(
        &m.bob,
        &gid,
        Parts {
            adds: vec![bob_kp],
            ..Parts::default()
        },
    );
    assert_eq!(verdict.unwrap(), CommitClass::SameAccount);
    assert_accepted(&mut m.carol, &add, &gid).await;
}

/// Without the requirement, a Commit of one's own account's leaves needs an
/// admin as before, and an admin's is `privileged`. The Commit that turns the
/// requirement on authorizes nothing either.
#[tokio::test]
async fn without_account_devices_own_account_commits_need_an_admin() {
    let mut m = members(false).await;
    let gid = m.gid.clone();
    let bob_kp = new_sibling_key_package(&mut m.bob, b"bob").await;
    let activation = required_list_update(&with_account_devices(required(&m.bob.engine, &gid)));

    for parts in [
        Parts {
            adds: vec![bob_kp.clone()],
            ..Parts::default()
        },
        Parts {
            removes: vec![leaf(&m.bob_sibling, &gid)],
            ..Parts::default()
        },
        Parts {
            adds: vec![bob_kp.clone()],
            app_data: vec![activation.clone()],
            ..Parts::default()
        },
        Parts {
            app_data: vec![activation],
            ..Parts::default()
        },
    ] {
        let (verdict, commit) = craft(&m.bob, &gid, parts);
        assert_refused_for_authorization(verdict);
        assert_eq!(
            assert_rejected_on_replay(&mut m.carol, &commit, &gid).await,
            Some(ProposalRejectionCategory::AuthorizationFailed)
        );
    }
    assert_not_required(
        m.bob
            .engine
            .send(remove_own_devices(
                &gid,
                vec![signature_key(&m.bob_sibling, &gid)],
            ))
            .await,
    );

    // An admin adding its own device keeps today's `privileged` class.
    let alice_kp = new_sibling_key_package(&mut m.alice, b"alice").await;
    let invite = send_commit(
        &mut m.alice,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![alice_kp],
            initial_admins: vec![],
        },
        &gid,
    )
    .await;
    assert_eq!(
        stamped_priority(&m.alice, &invite),
        CommitOrderingPriority::Privileged
    );
    let result = assert_accepted(&mut m.carol, &invite, &gid).await;
    assert_eq!(
        traced_priority(&result, &invite),
        CommitOrderingPriority::Privileged
    );
}

/// For every class, the priority the committer stamps at publish equals the
/// one each receiver's replay derives from the same parent.
#[tokio::test]
async fn the_stamp_and_replay_give_every_class_the_same_priority() {
    let mut m = members(true).await;
    let gid = m.gid.clone();

    // Self-update.
    let commit = send_commit(
        &mut m.carol,
        SendIntent::SelfUpdate {
            group_id: gid.clone(),
        },
        &gid,
    )
    .await;
    assert_priorities(
        &m.carol,
        &commit,
        &mut [&mut m.alice, &mut m.bob, &mut m.bob_sibling],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;

    // Same-account, by an admin: alice invites a device of her own.
    let alice_kp = new_sibling_key_package(&mut m.alice, b"alice").await;
    let commit = send_commit(
        &mut m.alice,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![alice_kp],
            initial_admins: vec![],
        },
        &gid,
    )
    .await;
    assert_priorities(
        &m.alice,
        &commit,
        &mut [&mut m.bob, &mut m.bob_sibling, &mut m.carol],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;

    // Admin-required: alice invites dave.
    let dave_kp = device(b"dave", true)
        .engine
        .fresh_key_package()
        .await
        .unwrap();
    let commit = send_commit(
        &mut m.alice,
        SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![dave_kp],
            initial_admins: vec![],
        },
        &gid,
    )
    .await;
    assert_priorities(
        &m.alice,
        &commit,
        &mut [&mut m.bob, &mut m.bob_sibling, &mut m.carol],
        &gid,
        CommitOrderingPriority::Privileged,
    )
    .await;

    // SelfRemove-only: alice commits carol's Leave.
    let SendResult::Proposal { msg } = m
        .carol
        .engine
        .send(SendIntent::Leave {
            group_id: gid.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected a SelfRemove proposal")
    };
    let leave = route_to_group(&msg, &gid);
    m.alice.engine.ingest(leave.clone()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(75)).await;
    assert!(
        m.alice
            .engine
            .advance_convergence(&gid)
            .await
            .unwrap()
            .is_empty()
    );
    let mut publications = m.alice.engine.drain_auto_publish();
    assert_eq!(publications.len(), 1);
    let publication = publications.remove(0);
    m.alice
        .engine
        .confirm_published(publication.pending)
        .await
        .unwrap();
    let commit = route_to_group(&publication.msg, &gid);
    m.bob.engine.ingest(leave).await.unwrap();
    assert_priorities(
        &m.alice,
        &commit,
        &mut [&mut m.bob],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;

    // Same-account, by a non-admin: bob removes his other device.
    let sibling = signature_key(&m.bob_sibling, &gid);
    let commit = send_commit(&mut m.bob, remove_own_devices(&gid, vec![sibling]), &gid).await;
    assert_priorities(
        &m.bob,
        &commit,
        &mut [&mut m.alice],
        &gid,
        CommitOrderingPriority::Ordinary,
    )
    .await;
}

async fn assert_priorities(
    committer: &Device,
    commit: &TransportMessage,
    receivers: &mut [&mut Device],
    gid: &GroupId,
    expected: CommitOrderingPriority,
) {
    assert_eq!(stamped_priority(committer, commit), expected);
    for receiver in receivers.iter_mut() {
        let result = assert_accepted(receiver, commit, gid).await;
        assert_eq!(traced_priority(&result, commit), expected);
    }
}

/// An Add proposal of `kp` by `sender`, built with raw OpenMLS. The sender's
/// own proposal store is left empty.
fn standalone_add(sender: &Device, gid: &GroupId, kp: &KeyPackage) -> TransportMessage {
    let crypto = RustCrypto::default();
    let provider =
        EngineOpenMlsProvider::<SqliteAccountStorage>::new(&crypto, sender.storage.mls_storage());
    let mut group = load_group(sender, gid);
    let (message, _) = group
        .propose_add_member(&provider, &device_signer(sender), &parse_key_package(kp))
        .expect("raw OpenMLS builds the proposal");
    group.clear_pending_proposals(provider.storage()).unwrap();
    group_transport(message, gid, "standalone-add")
}

// ── Branch priority ─────────────────────────────────────────────────────────

/// Deliver every commit in `commits` (each with the index of its sender) to
/// every other device, converge each device once, and return each device's
/// branch-selection trace. Every device must select the same branch from the
/// same candidates, scored the same way.
async fn race(
    devices: &mut [&mut Device],
    commits: &[(usize, TransportMessage)],
    gid: &GroupId,
) -> BranchSelectionTrace {
    let mut traces = Vec::new();
    for (index, device) in devices.iter_mut().enumerate() {
        for (sender, commit) in commits {
            if *sender != index {
                device.engine.ingest(commit.clone()).await.unwrap();
            }
        }
        let result = device
            .engine
            .converge_stored_openmls_messages_at(gid, 1_000_000)
            .unwrap();
        traces.push(result.selection_trace.expect("the pass selected a branch"));
    }
    let scores = |trace: &BranchSelectionTrace| {
        let mut scores: Vec<_> = trace
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.branch_id.clone(),
                    candidate.tip_priority,
                    candidate.tip_committer.clone(),
                    candidate.tip_digest,
                )
            })
            .collect();
        scores.sort();
        scores
    };
    let first = traces.remove(0);
    assert_eq!(first.candidates.len(), commits.len());
    for trace in &traces {
        assert_eq!(trace.selected_branch_id, first.selected_branch_id);
        assert_eq!(scores(trace), scores(&first));
    }
    first
}

fn decisive_rule(trace: &BranchSelectionTrace) -> &'static str {
    trace
        .rule_trace
        .iter()
        .find(|rule| rule.decisive)
        .expect("a rule decided the race")
        .rule_name
}

fn selected_tip(trace: &BranchSelectionTrace) -> [u8; 32] {
    trace
        .candidates
        .iter()
        .find(|candidate| Some(&candidate.branch_id) == trace.selected_branch_id.as_ref())
        .expect("a selected branch")
        .tip_digest
}

async fn publish(device: &mut Device, result: SendResult, gid: &GroupId) -> TransportMessage {
    let SendResult::GroupEvolution { msg, pending, .. } = result else {
        panic!("expected GroupEvolution")
    };
    device.engine.confirm_published(pending).await.unwrap();
    route_to_group(&msg, gid)
}

/// Two admins race from one parent: one adds a device of its own account
/// (`ordinary`), the other removes a member (`privileged`). The Remove wins on
/// every client, including the adder, whose account sorts first and would
/// otherwise win the committer comparison.
#[tokio::test]
async fn an_admins_remove_beats_an_admins_same_account_add() {
    let mut first = device(b"alice", true);
    let mut second = device(b"bob", true);
    let mut carol = device(b"carol", true);
    let mut dave = device(b"dave", true);
    let key_packages = vec![
        second.engine.fresh_key_package().await.unwrap(),
        carol.engine.fresh_key_package().await.unwrap(),
        dave.engine.fresh_key_package().await.unwrap(),
    ];
    let second_id = second.engine.self_id();
    let gid = found_group_with_admins(
        &mut first,
        key_packages,
        true,
        vec![second_id],
        &mut [&mut second, &mut carol, &mut dave],
    )
    .await;
    let (mut adder, adder_account, mut remover) =
        if first.engine.self_id().as_slice() < second.engine.self_id().as_slice() {
            (first, b"alice".as_slice(), second)
        } else {
            (second, b"bob".as_slice(), first)
        };

    let kp = new_sibling_key_package(&mut adder, adder_account).await;
    let add = adder
        .engine
        .send(SendIntent::Invite {
            group_id: gid.clone(),
            key_packages: vec![kp],
            initial_admins: vec![],
        })
        .await
        .unwrap();
    let add = publish(&mut adder, add, &gid).await;
    let remove = remover
        .engine
        .send(SendIntent::RemoveMembers {
            group_id: gid.clone(),
            members: vec![dave.engine.self_id()],
        })
        .await
        .unwrap();
    let remove = publish(&mut remover, remove, &gid).await;

    let trace = race(
        &mut [&mut adder, &mut remover, &mut carol],
        &[(0, add.clone()), (1, remove.clone())],
        &gid,
    )
    .await;
    assert_eq!(
        selected_tip(&trace),
        <[u8; 32]>::from(Sha256::digest(&remove.payload))
    );
    assert_eq!(decisive_rule(&trace), "tip_priority");
    assert_eq!(
        traced_priority_of(&trace, &add),
        CommitOrderingPriority::Ordinary
    );
    assert_eq!(
        traced_priority_of(&trace, &remove),
        CommitOrderingPriority::Privileged
    );
}

fn traced_priority_of(
    trace: &BranchSelectionTrace,
    commit: &TransportMessage,
) -> CommitOrderingPriority {
    let digest: [u8; 32] = Sha256::digest(&commit.payload).into();
    trace
        .candidates
        .iter()
        .find(|candidate| candidate.tip_digest == digest)
        .expect("the commit is a branch tip")
        .tip_priority
}

/// Two devices of one account remove each other from one parent. Both
/// Commits are `ordinary` from the same account, so the digest decides, the
/// same way on every client, both committers included.
#[tokio::test]
async fn sibling_devices_removing_each_other_are_settled_by_digest() {
    let mut m = members(true).await;
    let gid = m.gid.clone();
    let bob_key = signature_key(&m.bob, &gid);
    let sibling_key = signature_key(&m.bob_sibling, &gid);
    let removes_sibling = m
        .bob
        .engine
        .send(remove_own_devices(&gid, vec![sibling_key]))
        .await
        .unwrap();
    let removes_sibling = publish(&mut m.bob, removes_sibling, &gid).await;
    let removes_bob = m
        .bob_sibling
        .engine
        .send(remove_own_devices(&gid, vec![bob_key]))
        .await
        .unwrap();
    let removes_bob = publish(&mut m.bob_sibling, removes_bob, &gid).await;

    let trace = race(
        &mut [&mut m.bob, &mut m.bob_sibling, &mut m.alice, &mut m.carol],
        &[(0, removes_sibling.clone()), (1, removes_bob.clone())],
        &gid,
    )
    .await;
    assert_eq!(decisive_rule(&trace), "tip_digest");
    for candidate in &trace.candidates {
        assert_eq!(candidate.tip_priority, CommitOrderingPriority::Ordinary);
        assert_eq!(candidate.tip_committer, m.bob.engine.self_id().as_slice());
    }
    let lower = [&removes_sibling, &removes_bob]
        .map(|commit| <[u8; 32]>::from(Sha256::digest(&commit.payload)))
        .into_iter()
        .min()
        .unwrap();
    assert_eq!(selected_tip(&trace), lower);
}
