//! Marmot account identity proof carried as a custom MLS LeafNode extension.
//!
//! The MLS BasicCredential identity names a Marmot account, but the MLS
//! signature key is a separate leaf key. This extension binds those two public
//! keys with a Nostr-account Schnorr signature so account-scoped policy, such
//! as admin authorization, can safely trust the credential identity.
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

use cgka_traits::error::EngineError;
use cgka_traits::types::MemberId;
use nostr::prelude::JsonUtil;
use nostr::{
    Event, EventBuilder, Kind, PublicKey, Tag, TagKind, Timestamp, UnsignedEvent,
    secp256k1::schnorr::Signature,
};
use openmls::extensions::{Extension, ExtensionType, UnknownExtension};
use openmls::group::{MlsGroup, StagedCommit};
use openmls::prelude::{BasicCredential, LeafNode, SignatureScheme};
use openmls_traits::types::Ciphersuite;

/// Marmot custom LeafNode extension:
/// `marmot.account-identity-proof.v2`.
pub const ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE: u16 = 0xF2F1;
pub const ACCOUNT_IDENTITY_PROOF_EVENT_KIND: u16 = 450;

const ACCOUNT_IDENTITY_PROOF_VERSION: u8 = 2;
const ACCOUNT_IDENTITY_PROOF_DOMAIN: &str = "marmot.account-identity-proof.v2";
const SCHNORR_SIGNATURE_LEN: usize = 64;

/// Values a Marmot account key signs to bind an MLS leaf to that account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountIdentityProofRequest {
    pub account_identity: Vec<u8>,
    pub mls_signature_public_key: Vec<u8>,
    pub ciphersuite: u16,
    pub signature_scheme: u16,
}

impl AccountIdentityProofRequest {
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
        }
    }

    pub fn proof_event(&self) -> Result<UnsignedEvent, String> {
        let public_key = PublicKey::from_slice(&self.account_identity)
            .map_err(|err| format!("invalid account identity public key: {err}"))?;
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
                [ACCOUNT_IDENTITY_PROOF_VERSION.to_string()],
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

pub(crate) fn validate_leaf_account_identity_proof(
    leaf: &LeafNode,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    let credential = BasicCredential::try_from(leaf.credential().clone()).map_err(|e| {
        EngineError::InvalidCredentialIdentity(format!("not a BasicCredential: {e:?}"))
    })?;
    let account_identity = credential.identity();
    crate::identity::validate_credential_identity(account_identity)?;

    let Some(raw) = leaf
        .extensions()
        .unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
    else {
        return Err(EngineError::InvalidAccountIdentityProof(
            "missing marmot.account-identity-proof.v2 LeafNode extension".into(),
        ));
    };
    let proof = decode_proof(&raw.0)?;
    let mls_signature_public_key = leaf.signature_key().as_slice();
    if proof.request.account_identity.as_slice() != account_identity {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof account identity does not match credential identity".into(),
        ));
    }
    if proof.request.mls_signature_public_key.as_slice() != mls_signature_public_key {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof MLS signature key does not match leaf signature key".into(),
        ));
    }
    if proof.request.ciphersuite != u16::from(ciphersuite) {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof ciphersuite does not match expected ciphersuite".into(),
        ));
    }
    if proof.request.signature_scheme != ciphersuite.signature_algorithm() as u16 {
        return Err(EngineError::InvalidAccountIdentityProof(
            "proof signature scheme does not match ciphersuite".into(),
        ));
    }

    let signature = Signature::from_slice(&proof.signature).map_err(|_| {
        EngineError::InvalidAccountIdentityProof(
            "proof signature is not a Nostr Schnorr signature".into(),
        )
    })?;
    let proof_event = proof.request.proof_event().map_err(|err| {
        EngineError::InvalidAccountIdentityProof(format!("invalid proof event: {err}"))
    })?;
    proof_event.add_signature(signature).map_err(|_| {
        EngineError::InvalidAccountIdentityProof(
            "proof signature does not verify for credential identity".into(),
        )
    })?;
    Ok(())
}

pub(crate) fn validate_leaf_account_identity_proof_for_member(
    leaf: &LeafNode,
    ciphersuite: Ciphersuite,
    expected_member_id: &MemberId,
    context: &str,
) -> Result<(), EngineError> {
    let actual_member_id = crate::identity::validated_member_id_of_leaf(leaf)?;
    validate_leaf_account_identity_proof(leaf, ciphersuite)?;
    if actual_member_id != *expected_member_id {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "{context} credential identity does not match existing member identity"
        )));
    }
    Ok(())
}

pub(crate) fn validate_staged_commit_account_identity_proofs(
    staged: &StagedCommit,
    group: &MlsGroup,
    committer: &MemberId,
    ciphersuite: Ciphersuite,
) -> Result<Vec<MemberId>, EngineError> {
    let mut added = Vec::new();

    for add in staged.add_proposals() {
        let leaf = add.add_proposal().key_package().leaf_node();
        validate_leaf_account_identity_proof(leaf, ciphersuite)?;
        added.push(crate::identity::validated_member_id_of_leaf(leaf)?);
    }

    for update in staged.update_proposals() {
        let expected =
            crate::identity::member_id_of_sender(update.sender(), group).ok_or_else(|| {
                EngineError::InvalidAccountIdentityProof(
                    "Update proposal has no authenticated member sender".into(),
                )
            })?;
        validate_leaf_account_identity_proof_for_member(
            update.update_proposal().leaf_node(),
            ciphersuite,
            &expected,
            "Update proposal",
        )?;
    }

    if let Some(update_path_leaf) = staged.update_path_leaf_node() {
        validate_leaf_account_identity_proof_for_member(
            update_path_leaf,
            ciphersuite,
            committer,
            "commit update path",
        )?;
    }

    Ok(added)
}

pub(crate) fn account_identity_proof_capability() -> ExtensionType {
    ExtensionType::Unknown(ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE)
}

fn encode_proof(proof: &AccountIdentityProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ACCOUNT_IDENTITY_PROOF_VERSION);
    out.extend_from_slice(&proof.request.ciphersuite.to_be_bytes());
    out.extend_from_slice(&proof.request.signature_scheme.to_be_bytes());
    out.extend_from_slice(&proof.request.account_identity);
    out.extend_from_slice(&(proof.request.mls_signature_public_key.len() as u16).to_be_bytes());
    out.extend_from_slice(&proof.request.mls_signature_public_key);
    out.extend_from_slice(&proof.signature);
    out
}

fn decode_proof(bytes: &[u8]) -> Result<AccountIdentityProof, EngineError> {
    let mut cursor = bytes;
    let version = read_u8(&mut cursor, "version")?;
    if version != ACCOUNT_IDENTITY_PROOF_VERSION {
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

    fn request(keys: &nostr::Keys, leaf_key: &[u8]) -> AccountIdentityProofRequest {
        AccountIdentityProofRequest {
            account_identity: keys.public_key().to_bytes().to_vec(),
            mls_signature_public_key: leaf_key.to_vec(),
            ciphersuite: 1,
            signature_scheme: 0x0807,
        }
    }

    #[test]
    fn proof_event_is_canonical_unpublished_kind_450() {
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
                    ACCOUNT_IDENTITY_PROOF_VERSION.to_string(),
                ]
        }));
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
