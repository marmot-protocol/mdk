//! Marmot account identity proof carried as a custom MLS LeafNode extension.
//!
//! The MLS BasicCredential identity names a Marmot account, but the MLS
//! signature key is a separate leaf key. This extension binds those two public
//! keys with a Nostr-account Schnorr signature so account-scoped policy, such
//! as admin authorization, can safely trust the credential identity.

use cgka_traits::error::EngineError;
use openmls::extensions::{Extension, ExtensionType, UnknownExtension};
use openmls::prelude::{BasicCredential, LeafNode, SignatureScheme};
use openmls_traits::types::Ciphersuite;
use sha2::{Digest, Sha256};

/// Marmot custom LeafNode extension:
/// `marmot.account-identity-proof.v1`.
pub const ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE: u16 = 0xF2F1;

const ACCOUNT_IDENTITY_PROOF_VERSION: u8 = 1;
const ACCOUNT_IDENTITY_PROOF_DOMAIN: &[u8] = b"marmot.account-identity-proof.v1";
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

    /// Nostr-style BIP-340 message digest signed by the Marmot account key.
    pub fn signing_digest(&self) -> [u8; 32] {
        let message = self.canonical_message();
        let digest = Sha256::digest(&message);
        digest.into()
    }

    fn canonical_message(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ACCOUNT_IDENTITY_PROOF_DOMAIN);
        out.push(0);
        out.extend_from_slice(&ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE.to_be_bytes());
        out.push(ACCOUNT_IDENTITY_PROOF_VERSION);
        out.extend_from_slice(&self.ciphersuite.to_be_bytes());
        out.extend_from_slice(&self.signature_scheme.to_be_bytes());
        out.extend_from_slice(&(self.account_identity.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.account_identity);
        out.extend_from_slice(&(self.mls_signature_public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mls_signature_public_key);
        out
    }
}

/// Account-key signing hook supplied by the account/session layer.
///
/// Implementations sign `request.signing_digest()` with the private key whose
/// x-only public key is `request.account_identity`.
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
            "missing marmot.account-identity-proof.v1 LeafNode extension".into(),
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

    let verifying_key =
        k256::schnorr::VerifyingKey::from_bytes(account_identity).map_err(|_| {
            EngineError::InvalidCredentialIdentity(
                "credential identity is not a valid x-only secp256k1 public key".to_string(),
            )
        })?;
    let signature =
        k256::schnorr::Signature::try_from(proof.signature.as_slice()).map_err(|_| {
            EngineError::InvalidAccountIdentityProof(
                "proof signature is not a BIP-340 signature".into(),
            )
        })?;
    k256::schnorr::signature::hazmat::PrehashVerifier::verify_prehash(
        &verifying_key,
        &proof.request.signing_digest(),
        &signature,
    )
    .map_err(|_| {
        EngineError::InvalidAccountIdentityProof(
            "proof signature does not verify for credential identity".into(),
        )
    })
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
