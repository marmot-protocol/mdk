//! Marmot account identity proofs carried by profile-specific LeafNode data.
//!
//! The MLS BasicCredential identity names a Marmot account, but the MLS
//! signature key is a separate leaf key. The proof binds those two public keys
//! with a Nostr-account Schnorr signature so account-scoped policy, such as
//! admin authorization, can safely trust the credential identity.
//!
//! Deployed legacy leaves carry the event-shaped proof in custom extension
//! `0xf2f1`. Current leaves carry the spec-defined 104-byte component `0x8009`
//! in `app_data_dictionary`. A leaf or group must classify as exactly one
//! profile; hybrid or carrier-free inputs are rejected.
//!
//! TODO(mdk#755, layering): this module currently depends on the `nostr` crate
//! (EventBuilder construction, `Event::from_json`, `add_signature`), which
//! breaks the cgka-engine "no Nostr SDK types" invariant (see this crate's
//! AGENTS.md). The engine should keep a neutral contract — canonical event
//! bytes/JSON plus the 32-byte event id and the 64-byte Schnorr signature — and
//! the event construction plus signature verification should move to the
//! app/session signer adapter boundary (marmot-app / marmot-uniffi), which
//! already depend on nostr. This was left as follow-up because verification
//! runs deep in the engine ingest paths (staged-commit and KeyPackage
//! validation) and must recompute the canonical event id from the request
//! fields, so a sound move needs either a proof-message-computer callback
//! threaded through those paths or an in-engine NIP-01 canonicalization that
//! does not pull in the SDK — neither is a clean lift.

use cgka_traits::app_components::{ACCOUNT_IDENTITY_PROOF_COMPONENT_ID, decode_components_list};
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::types::MemberId;
use nostr::prelude::JsonUtil;
use nostr::{
    Event, EventBuilder, Kind, PublicKey, Tag, TagKind, Timestamp, UnsignedEvent,
    secp256k1::schnorr::Signature,
};
use openmls::extensions::{Extension, ExtensionType, Extensions, UnknownExtension};
use openmls::group::{GroupContext as OpenMlsGroupContext, MlsGroup, StagedCommit};
use openmls::prelude::{BasicCredential, LeafNode, Proposal, QueuedProposal, SignatureScheme};
use openmls_traits::types::Ciphersuite;

/// Deployed legacy custom LeafNode proof extension.
pub const ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE: u16 = 0xF2F1;
pub const ACCOUNT_IDENTITY_PROOF_EVENT_KIND: u16 = 450;

const LEGACY_ACCOUNT_IDENTITY_PROOF_VERSION: u8 = 2;
const ACCOUNT_IDENTITY_PROOF_DOMAIN: &str = "marmot.account-identity-proof.v2";
const ACCOUNT_IDENTITY_PROOF_CONTENT: &str = "Authorize this MLS leaf key for my Marmot account";
const SCHNORR_SIGNATURE_LEN: usize = 64;
const CURRENT_PROOF_LEN: usize = 32 + 8 + SCHNORR_SIGNATURE_LEN;
const MAX_NIP01_TIMESTAMP: u64 = (1_u64 << 53) - 1;

/// Values a Marmot account key signs to bind an MLS leaf to that account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIdentityProofRequest {
    pub account_identity: Vec<u8>,
    pub mls_signature_public_key: Vec<u8>,
    pub ciphersuite: u16,
    pub signature_scheme: u16,
    pub created_at: u64,
    pub protocol_profile: ProtocolProfile,
}

impl AccountIdentityProofRequest {
    /// Construct the deployed legacy extension request.
    pub fn new(
        account_identity: impl Into<Vec<u8>>,
        mls_signature_public_key: impl Into<Vec<u8>>,
        ciphersuite: Ciphersuite,
        signature_scheme: SignatureScheme,
    ) -> Self {
        Self {
            account_identity: account_identity.into(),
            mls_signature_public_key: mls_signature_public_key.into(),
            ciphersuite: u16::from(ciphersuite),
            signature_scheme: signature_scheme as u16,
            created_at: 0,
            protocol_profile: ProtocolProfile::Legacy,
        }
    }

    /// Construct the current component request.
    pub fn current(
        account_identity: impl Into<Vec<u8>>,
        mls_signature_public_key: impl Into<Vec<u8>>,
        ciphersuite: Ciphersuite,
        signature_scheme: SignatureScheme,
        created_at: u64,
    ) -> Self {
        Self {
            account_identity: account_identity.into(),
            mls_signature_public_key: mls_signature_public_key.into(),
            ciphersuite: u16::from(ciphersuite),
            signature_scheme: signature_scheme as u16,
            created_at,
            protocol_profile: ProtocolProfile::Current,
        }
    }

    pub fn proof_event(&self) -> Result<UnsignedEvent, String> {
        let public_key = PublicKey::from_slice(&self.account_identity)
            .map_err(|err| format!("invalid account identity public key: {err}"))?;
        match self.protocol_profile {
            ProtocolProfile::Legacy => {
                let tags = [
                    Tag::custom(
                        TagKind::custom("d"),
                        [ACCOUNT_IDENTITY_PROOF_DOMAIN.to_string()],
                    ),
                    Tag::custom(
                        TagKind::custom("extension"),
                        [format!("0x{ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE:04x}")],
                    ),
                    Tag::custom(
                        TagKind::custom("version"),
                        [LEGACY_ACCOUNT_IDENTITY_PROOF_VERSION.to_string()],
                    ),
                    Tag::custom(
                        TagKind::custom("ciphersuite"),
                        [self.ciphersuite.to_string()],
                    ),
                    Tag::custom(
                        TagKind::custom("signature_scheme"),
                        [self.signature_scheme.to_string()],
                    ),
                    Tag::custom(
                        TagKind::custom("mls_signature_key"),
                        [hex::encode(&self.mls_signature_public_key)],
                    ),
                ];
                Ok(
                    EventBuilder::new(Kind::Custom(ACCOUNT_IDENTITY_PROOF_EVENT_KIND), "")
                        .tags(tags)
                        .custom_created_at(Timestamp::zero())
                        .build(public_key),
                )
            }
            ProtocolProfile::Current => {
                validate_current_timestamp(self.created_at)?;
                let tags = [
                    Tag::custom(
                        TagKind::custom("d"),
                        [ACCOUNT_IDENTITY_PROOF_DOMAIN.to_string()],
                    ),
                    Tag::custom(
                        TagKind::custom("component"),
                        [format!("0x{ACCOUNT_IDENTITY_PROOF_COMPONENT_ID:04x}")],
                    ),
                    Tag::custom(
                        TagKind::custom("ciphersuite"),
                        [format!("0x{:04x}", self.ciphersuite)],
                    ),
                    Tag::custom(
                        TagKind::custom("signature_scheme"),
                        [format!("0x{:04x}", self.signature_scheme)],
                    ),
                    Tag::custom(
                        TagKind::custom("mls_signature_key"),
                        [hex::encode(&self.mls_signature_public_key)],
                    ),
                ];
                Ok(EventBuilder::new(
                    Kind::Custom(ACCOUNT_IDENTITY_PROOF_EVENT_KIND),
                    ACCOUNT_IDENTITY_PROOF_CONTENT,
                )
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(self.created_at))
                .build(public_key))
            }
        }
    }

    pub fn proof_event_json(&self) -> Result<String, String> {
        self.proof_event().map(|event| event.as_json())
    }

    pub fn proof_event_id(&self) -> Result<[u8; 32], String> {
        self.proof_event()?
            .id
            .map(|id| id.to_bytes())
            .ok_or_else(|| "proof event id was not set".to_string())
    }

    pub fn signature_from_signed_event(&self, event: Event) -> Result<[u8; 64], String> {
        let proof_event = self.proof_event()?;
        if event.pubkey.to_bytes().as_slice() != self.account_identity.as_slice() {
            return Err("proof event signer does not match account identity".into());
        }
        let proof_event_id = proof_event
            .id
            .ok_or_else(|| "proof event id was not set".to_string())?;
        if event.id != proof_event_id {
            return Err("signed proof event does not match proof request".into());
        }
        event
            .verify()
            .map_err(|err| format!("invalid signed proof event: {err}"))?;
        Ok(event.sig.serialize())
    }
}

/// Account-key signing hook supplied by the account/session layer.
///
/// Implementations sign `request.proof_event()` with the private key whose
/// x-only public key is `request.account_identity`, then return the event
/// signature bytes. The event is canonical and unpublished.
pub trait AccountIdentityProofSigner: Send + Sync {
    fn sign_account_identity_proof(
        &self,
        request: &AccountIdentityProofRequest,
    ) -> Result<[u8; SCHNORR_SIGNATURE_LEN], String>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AccountIdentityProof {
    request: AccountIdentityProofRequest,
    signature: [u8; SCHNORR_SIGNATURE_LEN],
}

#[derive(Clone, Debug)]
pub(crate) enum AccountIdentityProofMaterial {
    LegacyExtension(Extension),
    CurrentComponent(Vec<u8>),
}

impl AccountIdentityProofMaterial {
    pub(crate) fn protocol_profile(&self) -> ProtocolProfile {
        match self {
            Self::LegacyExtension(_) => ProtocolProfile::Legacy,
            Self::CurrentComponent(_) => ProtocolProfile::Current,
        }
    }
}

pub fn account_identity_proof_extension(
    account_identity: &[u8],
    mls_signature_public_key: &[u8],
    ciphersuite: Ciphersuite,
    signature_scheme: SignatureScheme,
    proof_signer: &dyn AccountIdentityProofSigner,
) -> Result<Extension, EngineError> {
    let request = AccountIdentityProofRequest::new(
        account_identity.to_vec(),
        mls_signature_public_key.to_vec(),
        ciphersuite,
        signature_scheme,
    );
    let signature = proof_signer
        .sign_account_identity_proof(&request)
        .map_err(|e| EngineError::InvalidAccountIdentityProof(format!("signing failed: {e}")))?;
    Ok(Extension::Unknown(
        ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE,
        UnknownExtension(encode_proof(&AccountIdentityProof { request, signature })),
    ))
}

pub fn account_identity_proof_component(
    account_identity: &[u8],
    mls_signature_public_key: &[u8],
    ciphersuite: Ciphersuite,
    signature_scheme: SignatureScheme,
    created_at: u64,
    proof_signer: &dyn AccountIdentityProofSigner,
) -> Result<Vec<u8>, EngineError> {
    let request = AccountIdentityProofRequest::current(
        account_identity.to_vec(),
        mls_signature_public_key.to_vec(),
        ciphersuite,
        signature_scheme,
        created_at,
    );
    validate_current_timestamp(created_at).map_err(EngineError::InvalidAccountIdentityProof)?;
    let signature = proof_signer
        .sign_account_identity_proof(&request)
        .map_err(|e| EngineError::InvalidAccountIdentityProof(format!("signing failed: {e}")))?;
    let mut out = Vec::with_capacity(CURRENT_PROOF_LEN);
    out.extend_from_slice(account_identity);
    out.extend_from_slice(&created_at.to_be_bytes());
    out.extend_from_slice(&signature);
    if out.len() != CURRENT_PROOF_LEN {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "current proof must be exactly {CURRENT_PROOF_LEN} bytes"
        )));
    }
    Ok(out)
}

pub(crate) fn account_identity_proof_material(
    account_identity: &[u8],
    mls_signature_public_key: &[u8],
    ciphersuite: Ciphersuite,
    signature_scheme: SignatureScheme,
    protocol_profile: ProtocolProfile,
    created_at: u64,
    proof_signer: &dyn AccountIdentityProofSigner,
) -> Result<AccountIdentityProofMaterial, EngineError> {
    match protocol_profile {
        ProtocolProfile::Legacy => account_identity_proof_extension(
            account_identity,
            mls_signature_public_key,
            ciphersuite,
            signature_scheme,
            proof_signer,
        )
        .map(AccountIdentityProofMaterial::LegacyExtension),
        ProtocolProfile::Current => account_identity_proof_component(
            account_identity,
            mls_signature_public_key,
            ciphersuite,
            signature_scheme,
            created_at,
            proof_signer,
        )
        .map(AccountIdentityProofMaterial::CurrentComponent),
    }
}

pub(crate) fn validate_leaf_account_identity_proof(
    leaf: &LeafNode,
    ciphersuite: Ciphersuite,
) -> Result<ProtocolProfile, EngineError> {
    let credential = BasicCredential::try_from(leaf.credential().clone()).map_err(|e| {
        EngineError::InvalidCredentialIdentity(format!("not a BasicCredential: {e:?}"))
    })?;
    let account_identity = credential.identity();
    crate::identity::validate_credential_identity(account_identity)?;

    let legacy = leaf
        .extensions()
        .unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE);
    let current = leaf
        .extensions()
        .app_data_dictionary()
        .and_then(|extension| {
            extension
                .dictionary()
                .get(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
        });
    match (legacy, current) {
        (Some(_), Some(_)) => Err(EngineError::InvalidAccountIdentityProof(
            "LeafNode mixes legacy proof extension 0xf2f1 with current proof component 0x8009"
                .into(),
        )),
        (None, None) => Err(EngineError::InvalidAccountIdentityProof(
            "LeafNode carries neither legacy proof extension 0xf2f1 nor current proof component 0x8009"
                .into(),
        )),
        (Some(raw), None) => {
            validate_legacy_proof(raw.0.as_slice(), leaf, account_identity, ciphersuite)?;
            Ok(ProtocolProfile::Legacy)
        }
        (None, Some(raw)) => {
            let advertised = crate::app_components::app_components_of_leaf(leaf)?;
            if !advertised.contains(ACCOUNT_IDENTITY_PROOF_COMPONENT_ID) {
                return Err(EngineError::InvalidAccountIdentityProof(
                    "current proof component 0x8009 is not advertised in leaf app_components"
                        .into(),
                ));
            }
            validate_current_proof(raw, leaf, account_identity, ciphersuite)?;
            Ok(ProtocolProfile::Current)
        }
    }
}

fn validate_legacy_proof(
    raw: &[u8],
    leaf: &LeafNode,
    account_identity: &[u8],
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    let proof = decode_legacy_proof(raw)?;
    validate_proof_bindings(&proof.request, leaf, account_identity, ciphersuite)?;
    verify_proof_signature(&proof.request, &proof.signature)
}

fn validate_current_proof(
    raw: &[u8],
    leaf: &LeafNode,
    account_identity: &[u8],
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    if raw.len() != CURRENT_PROOF_LEN {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "current proof component must be exactly {CURRENT_PROOF_LEN} bytes"
        )));
    }
    let signer_pubkey = &raw[..32];
    let created_at = u64::from_be_bytes(
        raw[32..40]
            .try_into()
            .expect("current proof timestamp slice has exact length"),
    );
    validate_current_timestamp(created_at).map_err(EngineError::InvalidAccountIdentityProof)?;
    let mut signature = [0_u8; SCHNORR_SIGNATURE_LEN];
    signature.copy_from_slice(&raw[40..]);
    let request = AccountIdentityProofRequest::current(
        signer_pubkey.to_vec(),
        leaf.signature_key().as_slice().to_vec(),
        ciphersuite,
        ciphersuite.signature_algorithm(),
        created_at,
    );
    validate_proof_bindings(&request, leaf, account_identity, ciphersuite)?;
    verify_proof_signature(&request, &signature)
}

fn validate_proof_bindings(
    request: &AccountIdentityProofRequest,
    leaf: &LeafNode,
    account_identity: &[u8],
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    let mls_signature_public_key = leaf.signature_key().as_slice();
    if request.account_identity.as_slice() != account_identity {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof account identity does not match credential identity".into(),
        ));
    }
    if request.mls_signature_public_key.as_slice() != mls_signature_public_key {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof MLS signature key does not match leaf signature key".into(),
        ));
    }
    if request.ciphersuite != u16::from(ciphersuite) {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof ciphersuite does not match expected ciphersuite".into(),
        ));
    }
    if request.signature_scheme != ciphersuite.signature_algorithm() as u16 {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof signature scheme does not match ciphersuite".into(),
        ));
    }
    Ok(())
}

fn verify_proof_signature(
    request: &AccountIdentityProofRequest,
    signature_bytes: &[u8; SCHNORR_SIGNATURE_LEN],
) -> Result<(), EngineError> {
    let signature = Signature::from_slice(signature_bytes).map_err(|_| {
        EngineError::InvalidAccountIdentityProof(
            "proof signature is not a Nostr Schnorr signature".into(),
        )
    })?;
    let proof_event = request.proof_event().map_err(|err| {
        EngineError::InvalidAccountIdentityProof(format!("invalid proof event: {err}"))
    })?;
    proof_event.add_signature(signature).map_err(|_| {
        EngineError::InvalidAccountIdentityProof(
            "proof signature does not verify for credential identity".into(),
        )
    })?;
    Ok(())
}

fn validate_current_timestamp(created_at: u64) -> Result<(), String> {
    // The adopted account-identity-proof-v2 profile constrains the NIP-01
    // integer range but explicitly gives proofs no receiver-side age limit.
    // Do not add past-age or future-skew rejection here.
    if !(1..=MAX_NIP01_TIMESTAMP).contains(&created_at) {
        return Err(format!(
            "current proof timestamp must be in 1..={MAX_NIP01_TIMESTAMP}"
        ));
    }
    Ok(())
}

pub(crate) fn protocol_profile_of_group(group: &MlsGroup) -> Result<ProtocolProfile, EngineError> {
    protocol_profile_of_group_extensions(group.extensions())
}

fn protocol_profile_of_group_extensions(
    extensions: &Extensions<OpenMlsGroupContext>,
) -> Result<ProtocolProfile, EngineError> {
    let legacy_required = extensions.iter().any(|extension| {
        matches!(
            extension,
            Extension::RequiredCapabilities(required)
                if required.extension_types().contains(
                    &ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
                )
        )
    });
    let app_data = extensions.app_data_dictionary();
    if app_data.is_some_and(|extension| {
        extension
            .dictionary()
            .contains(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID)
    }) {
        return Err(EngineError::InvalidAccountIdentityProof(
            "GroupContext carries leaf-only proof component 0x8009 state".into(),
        ));
    }
    let current_required = app_data
        .and_then(|extension| {
            extension
                .dictionary()
                .get(&cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID)
        })
        .map(decode_components_list)
        .transpose()
        .map_err(|error| {
            EngineError::InvalidAccountIdentityProof(format!(
                "group app_components cannot classify proof profile: {error}"
            ))
        })?
        .is_some_and(|components| components.contains(&ACCOUNT_IDENTITY_PROOF_COMPONENT_ID));
    match (legacy_required, current_required) {
        (true, false) => Ok(ProtocolProfile::Legacy),
        (false, true) => Ok(ProtocolProfile::Current),
        (true, true) => Err(EngineError::InvalidAccountIdentityProof(
            "group mixes legacy proof requirement 0xf2f1 with current proof requirement 0x8009"
                .into(),
        )),
        (false, false) => Err(EngineError::InvalidAccountIdentityProof(
            "group requires neither legacy proof extension 0xf2f1 nor current proof component 0x8009"
                .into(),
        )),
    }
}

fn ensure_profile(
    actual: ProtocolProfile,
    expected: ProtocolProfile,
    context: &str,
) -> Result<(), EngineError> {
    if actual != expected {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "{context} uses {actual:?} proof in a {expected:?} group"
        )));
    };
    Ok(())
}

pub(crate) fn validate_leaf_account_identity_proof_for_member(
    leaf: &LeafNode,
    ciphersuite: Ciphersuite,
    expected_member_id: &MemberId,
    context: &str,
) -> Result<ProtocolProfile, EngineError> {
    let actual_member_id = crate::identity::validated_member_id_of_leaf(leaf)?;
    let profile = validate_leaf_account_identity_proof(leaf, ciphersuite)?;
    if actual_member_id != *expected_member_id {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "{context} credential identity does not match existing member identity"
        )));
    }
    Ok(profile)
}

pub(crate) fn validate_staged_commit_account_identity_proofs(
    staged: &StagedCommit,
    group: &MlsGroup,
    committer: &MemberId,
    ciphersuite: Ciphersuite,
) -> Result<Vec<MemberId>, EngineError> {
    let mut added = Vec::new();
    let profile = protocol_profile_of_group(group)?;
    let resulting_profile =
        protocol_profile_of_group_extensions(staged.group_context().extensions())?;
    if resulting_profile != profile {
        return Err(EngineError::InvalidAccountIdentityProof(
            "commit attempts to change the group's protocol profile".into(),
        ));
    }

    for add in staged.add_proposals() {
        let key_package = add.add_proposal().key_package();
        let leaf = key_package.leaf_node();
        ensure_profile(
            validate_leaf_account_identity_proof(leaf, key_package.ciphersuite())?,
            profile,
            "Add proposal",
        )?;
        added.push(crate::identity::validated_member_id_of_leaf(leaf)?);
    }

    for update in staged.update_proposals() {
        let expected =
            crate::identity::member_id_of_sender(update.sender(), group).ok_or_else(|| {
                EngineError::InvalidAccountIdentityProof(
                    "Update proposal has no authenticated member sender".into(),
                )
            })?;
        let update_profile = validate_leaf_account_identity_proof_for_member(
            update.update_proposal().leaf_node(),
            ciphersuite,
            &expected,
            "Update proposal",
        )?;
        ensure_profile(update_profile, profile, "Update proposal")?;
    }

    if let Some(update_path_leaf) = staged.update_path_leaf_node() {
        let update_profile = validate_leaf_account_identity_proof_for_member(
            update_path_leaf,
            ciphersuite,
            committer,
            "commit update path",
        )?;
        ensure_profile(update_profile, profile, "commit update path")?;
    }

    Ok(added)
}

/// Validate the account identity carried by a standalone Add or Update before
/// the proposal is admitted to Marmot's durable pending set.
///
/// Commit validation performs the same checks again against the authenticated
/// candidate parent. Keeping this proposal seam separate is intentional: a
/// syntactically valid MLS proposal must not sit pending until a later Commit
/// discovers that its leaf proof or profile is invalid.
pub(crate) fn validate_standalone_proposal_account_identity_proof(
    proposal: &QueuedProposal,
    group: &MlsGroup,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    let profile = protocol_profile_of_group(group)?;
    match proposal.proposal() {
        Proposal::Add(add) => {
            let key_package = add.key_package();
            let leaf = key_package.leaf_node();
            ensure_profile(
                validate_leaf_account_identity_proof(leaf, key_package.ciphersuite())?,
                profile,
                "standalone Add proposal",
            )?;
            crate::identity::validated_member_id_of_leaf(leaf)?;
        }
        Proposal::Update(update) => {
            let expected = crate::identity::member_id_of_sender(proposal.sender(), group)
                .ok_or_else(|| {
                    EngineError::InvalidAccountIdentityProof(
                        "standalone Update proposal has no authenticated member sender".into(),
                    )
                })?;
            let update_profile = validate_leaf_account_identity_proof_for_member(
                update.leaf_node(),
                ciphersuite,
                &expected,
                "standalone Update proposal",
            )?;
            ensure_profile(update_profile, profile, "standalone Update proposal")?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn account_identity_proof_capability() -> ExtensionType {
    ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
}

fn encode_proof(proof: &AccountIdentityProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(LEGACY_ACCOUNT_IDENTITY_PROOF_VERSION);
    out.extend_from_slice(&proof.request.ciphersuite.to_be_bytes());
    out.extend_from_slice(&proof.request.signature_scheme.to_be_bytes());
    out.extend_from_slice(&proof.request.account_identity);
    out.extend_from_slice(&(proof.request.mls_signature_public_key.len() as u16).to_be_bytes());
    out.extend_from_slice(&proof.request.mls_signature_public_key);
    out.extend_from_slice(&proof.signature);
    out
}

fn decode_legacy_proof(bytes: &[u8]) -> Result<AccountIdentityProof, EngineError> {
    let mut cursor = bytes;
    let version = read_u8(&mut cursor, "version")?;
    if version != LEGACY_ACCOUNT_IDENTITY_PROOF_VERSION {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "unsupported proof version {version}"
        )));
    }
    let ciphersuite = read_u16(&mut cursor, "ciphersuite")?;
    let signature_scheme = read_u16(&mut cursor, "signature scheme")?;
    let account_identity = read_exact(&mut cursor, 32, "account identity")?.to_vec();
    let key_len = read_u16(&mut cursor, "MLS signature key length")? as usize;
    let mls_signature_public_key =
        read_exact(&mut cursor, key_len, "MLS signature public key")?.to_vec();
    let signature_bytes = read_exact(&mut cursor, SCHNORR_SIGNATURE_LEN, "signature")?;
    if !cursor.is_empty() {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof has trailing bytes".into(),
        ));
    }
    let mut signature = [0_u8; SCHNORR_SIGNATURE_LEN];
    signature.copy_from_slice(signature_bytes);
    Ok(AccountIdentityProof {
        request: AccountIdentityProofRequest {
            account_identity,
            mls_signature_public_key,
            ciphersuite,
            signature_scheme,
            created_at: 0,
            protocol_profile: ProtocolProfile::Legacy,
        },
        signature,
    })
}

fn read_u8(cursor: &mut &[u8], field: &str) -> Result<u8, EngineError> {
    if cursor.is_empty() {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "proof missing {field}"
        )));
    }
    let value = cursor[0];
    *cursor = &cursor[1..];
    Ok(value)
}

fn read_u16(cursor: &mut &[u8], field: &str) -> Result<u16, EngineError> {
    let bytes = read_exact(cursor, 2, field)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_exact<'a>(cursor: &mut &'a [u8], len: usize, field: &str) -> Result<&'a [u8], EngineError> {
    if cursor.len() < len {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "proof {field} is truncated"
        )));
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedSigner([u8; 64]);

    impl AccountIdentityProofSigner for FixedSigner {
        fn sign_account_identity_proof(
            &self,
            _request: &AccountIdentityProofRequest,
        ) -> Result<[u8; 64], String> {
            Ok(self.0)
        }
    }

    fn request(keys: &nostr::Keys, leaf_key: &[u8]) -> AccountIdentityProofRequest {
        AccountIdentityProofRequest {
            account_identity: keys.public_key().to_bytes().to_vec(),
            mls_signature_public_key: leaf_key.to_vec(),
            ciphersuite: 1,
            signature_scheme: 0x0807,
            created_at: 0,
            protocol_profile: ProtocolProfile::Legacy,
        }
    }

    #[test]
    fn legacy_proof_event_remains_the_deployed_zero_timestamp_shape() {
        let keys = nostr::Keys::generate();
        let request = request(&keys, b"leaf-key");
        let event = request.proof_event().unwrap();

        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.kind, Kind::Custom(ACCOUNT_IDENTITY_PROOF_EVENT_KIND));
        assert_eq!(event.created_at, Timestamp::zero());
        assert_eq!(event.content, "");
        assert!(event.id.is_some());
        assert!(event.tags.iter().any(|tag| {
            tag.as_slice() == ["d".to_owned(), ACCOUNT_IDENTITY_PROOF_DOMAIN.to_owned()]
        }));
        assert!(event.tags.iter().any(|tag| {
            tag.as_slice()
                == [
                    "version".to_owned(),
                    LEGACY_ACCOUNT_IDENTITY_PROOF_VERSION.to_string(),
                ]
        }));
    }

    #[test]
    fn current_proof_event_is_the_exact_kind_450_spec_shape() {
        let keys = nostr::Keys::generate();
        let request = AccountIdentityProofRequest::current(
            keys.public_key().to_bytes(),
            [0xAB; 32],
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            SignatureScheme::ED25519,
            1_721_234_567,
        );

        let event = request.proof_event().unwrap();

        assert_eq!(event.pubkey, keys.public_key());
        assert_eq!(event.kind, Kind::Custom(ACCOUNT_IDENTITY_PROOF_EVENT_KIND));
        assert_eq!(event.created_at, Timestamp::from_secs(1_721_234_567));
        assert_eq!(event.content, ACCOUNT_IDENTITY_PROOF_CONTENT);
        let tags: Vec<Vec<String>> = event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        assert_eq!(
            tags,
            vec![
                vec!["d".into(), ACCOUNT_IDENTITY_PROOF_DOMAIN.into()],
                vec!["component".into(), "0x8009".into()],
                vec!["ciphersuite".into(), "0x0001".into()],
                vec!["signature_scheme".into(), "0x0807".into()],
                vec!["mls_signature_key".into(), "ab".repeat(32)],
            ]
        );
    }

    #[test]
    fn current_proof_rejects_zero_and_out_of_range_timestamps() {
        let keys = nostr::Keys::generate();
        for created_at in [0, MAX_NIP01_TIMESTAMP + 1] {
            let request = AccountIdentityProofRequest::current(
                keys.public_key().to_bytes(),
                [0xAB; 32],
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                SignatureScheme::ED25519,
                created_at,
            );
            assert!(request.proof_event().is_err());
        }
    }

    #[test]
    fn current_proof_matches_the_adopted_signing_vector() {
        let account_identity =
            hex::decode("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .unwrap();
        let mls_signature_key: Vec<u8> = (0_u8..32).collect();
        let signature: [u8; 64] = hex::decode(
            "c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a\
             51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let request = AccountIdentityProofRequest::current(
            account_identity.clone(),
            mls_signature_key.clone(),
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            SignatureScheme::ED25519,
            1_700_000_000,
        );
        assert_eq!(
            hex::encode(request.proof_event_id().unwrap()),
            "b7e9a15dd85990fb0f49c33db3cc9875f73986207b038404ceb6b7fec4e0af6b"
        );

        let component = account_identity_proof_component(
            &account_identity,
            &mls_signature_key,
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            SignatureScheme::ED25519,
            1_700_000_000,
            &FixedSigner(signature),
        )
        .unwrap();
        assert_eq!(
            hex::encode(component),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9\
             000000006553f100\
             c5315d3c85b9d4907cb03395a2a97b3ba2eab393f8e45b13a5d5233acedac60a\
             51d2a295e1b1b5ee372d18a49bdb8041a7dba9dedce722c7c6f712f78bbdfb5d"
        );
    }

    #[test]
    fn proof_signature_must_match_the_exact_request_event() {
        let keys = nostr::Keys::generate();
        let original = request(&keys, b"leaf-key-a");
        let tampered = request(&keys, b"leaf-key-b");
        let signed_tampered = tampered
            .proof_event()
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        assert!(
            original
                .signature_from_signed_event(signed_tampered)
                .is_err(),
            "a proof signature for another leaf key must not verify for this request"
        );
    }
}
