//! Nostr identity proof for MIP-06 External Commits.
//!
//! Binds an External Commit to the Nostr private key of the joining user via a
//! canonical unsigned Nostr proof event (`kind: 450`) placed in
//! `FramedContent.authenticated_data`.
//!
//! The challenge hash binds to the credential identity (Nostr pubkey) and MLS
//! signature key — both known before `ExternalCommitBuilder::build_group()` — so
//! the proof can be constructed as AAD without needing the full LeafNode.

use nostr::{EventBuilder, Keys, Kind, PublicKey, Tag, TagKind, Timestamp};
use sha2::{Digest, Sha256};
use tls_codec::{DeserializeBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::error::Error;

/// Domain-separation prefix for the challenge hash.
const CHALLENGE_PREFIX: &[u8] = b"marmot-external-commit-v1";

/// Marker tag value for the canonical proof event.
const PROOF_EVENT_MARKER: &str = "marmot-external-commit-auth-v1";

/// Nostr event kind for the identity proof template (never published to relays).
const PROOF_EVENT_KIND: u16 = 450;

/// TLS-serialized identity proof carried in `FramedContent.authenticated_data`.
///
/// ```tls
/// struct {
///     uint16 version;                  // current: 1
///     opaque nostr_event_sig[64];      // Nostr signature over canonical proof event id
/// } NostrIdentityProof;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct NostrIdentityProof {
    version: u16,
    nostr_event_sig: [u8; 64],
}

impl NostrIdentityProof {
    /// Current proof version.
    pub const CURRENT_VERSION: u16 = 1;

    /// Construct a new proof from a pre-computed Nostr event signature.
    pub fn new(nostr_event_sig: [u8; 64]) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            nostr_event_sig,
        }
    }

    /// Get the version.
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Get the Nostr event signature bytes.
    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.nostr_event_sig
    }

    /// Serialize to bytes for use as `authenticated_data`.
    pub fn to_authenticated_data(&self) -> Result<Vec<u8>, Error> {
        use tls_codec::Serialize;
        let mut buf = Vec::new();
        self.tls_serialize(&mut buf)
            .map_err(|e| Error::IdentityProofError(e.to_string()))?;
        Ok(buf)
    }

    /// Deserialize from `authenticated_data` bytes.
    pub fn from_authenticated_data(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::IdentityProofError(
                "authenticated_data is empty".to_string(),
            ));
        }
        let (proof, _remainder) = Self::tls_deserialize_bytes(bytes)
            .map_err(|e| Error::IdentityProofError(e.to_string()))?;
        if proof.version != Self::CURRENT_VERSION {
            return Err(Error::IdentityProofError(format!(
                "unsupported proof version: {}",
                proof.version
            )));
        }
        Ok(proof)
    }
}

/// Compute the challenge hash per MIP-06:
///
/// ```text
/// SHA-256("marmot-external-commit-v1" || credential_identity || signature_key || serialized_GroupContext)
/// ```
///
/// The challenge binds to the identity-relevant fields (Nostr pubkey from the
/// credential and the MLS signature public key) rather than the full serialized
/// LeafNode. This allows the proof to be constructed before the External Commit's
/// LeafNode exists, since both values are supplied by the application via
/// `CredentialWithKey` before `build_group()`.
pub fn compute_challenge(
    credential_identity: &[u8],
    signature_key: &[u8],
    serialized_group_context: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_PREFIX);
    hasher.update(credential_identity);
    hasher.update(signature_key);
    hasher.update(serialized_group_context);
    hasher.finalize().into()
}

/// Build the canonical proof event and sign it, returning the signed `Event`.
///
/// The event is:
/// ```json
/// {
///   "kind": 450,
///   "created_at": 0,
///   "pubkey": "<joining user's nostr pubkey>",
///   "tags": [["m", "marmot-external-commit-auth-v1"]],
///   "content": "<hex-encoded challenge>"
/// }
/// ```
fn sign_canonical_proof_event(keys: &Keys, challenge: &[u8; 32]) -> Result<nostr::Event, Error> {
    let content = hex::encode(challenge);

    let event = EventBuilder::new(Kind::Custom(PROOF_EVENT_KIND), &content)
        .custom_created_at(Timestamp::from(0))
        .tag(Tag::custom(
            TagKind::SingleLetter(nostr::SingleLetterTag::lowercase(nostr::Alphabet::M)),
            vec![PROOF_EVENT_MARKER],
        ))
        .sign_with_keys(keys)
        .map_err(|e| Error::IdentityProofError(format!("failed to sign proof event: {e}")))?;

    Ok(event)
}

/// Reconstruct the canonical unsigned event for verification, then verify the signature.
fn verify_canonical_proof_event(
    pubkey: &PublicKey,
    challenge: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), Error> {
    let content = hex::encode(challenge);

    // Build the unsigned event to get the event ID (hash of canonical JSON)
    let unsigned = EventBuilder::new(Kind::Custom(PROOF_EVENT_KIND), &content)
        .custom_created_at(Timestamp::from(0))
        .tag(Tag::custom(
            TagKind::SingleLetter(nostr::SingleLetterTag::lowercase(nostr::Alphabet::M)),
            vec![PROOF_EVENT_MARKER],
        ))
        .build(*pubkey);

    // Verify the Schnorr signature over the event id
    let event_id = unsigned
        .id
        .ok_or_else(|| Error::IdentityProofError("failed to compute proof event id".to_string()))?;
    let event_id_bytes: [u8; 32] = event_id.to_bytes();
    let sig = nostr::secp256k1::schnorr::Signature::from_slice(sig_bytes)
        .map_err(|e| Error::IdentityProofError(format!("invalid signature format: {e}")))?;

    let secp = nostr::secp256k1::Secp256k1::verification_only();
    let xonly = pubkey
        .xonly()
        .map_err(|e| Error::IdentityProofError(format!("invalid pubkey: {e}")))?;
    let message = nostr::secp256k1::Message::from_digest(event_id_bytes);

    secp.verify_schnorr(&sig, &message, &xonly)
        .map_err(|e| Error::IdentityProofError(format!("signature verification failed: {e}")))
}

/// Verify a Nostr identity proof.
///
/// The verifier extracts `credential_identity` and `signature_key` from the
/// joining LeafNode in the staged commit, and `serialized_group_context` from
/// the pre-commit group state.
pub fn verify_identity_proof(
    proof: &NostrIdentityProof,
    pubkey: &PublicKey,
    credential_identity: &[u8],
    signature_key: &[u8],
    serialized_group_context: &[u8],
) -> Result<(), Error> {
    let challenge = compute_challenge(credential_identity, signature_key, serialized_group_context);
    verify_canonical_proof_event(pubkey, &challenge, proof.signature_bytes())
}

/// Construct an identity proof by signing the canonical proof event.
///
/// The joiner supplies `credential_identity` (raw Nostr pubkey bytes from the
/// `BasicCredential`) and `signature_key` (MLS signature public key bytes from
/// the `CredentialWithKey`), both of which are known before
/// `ExternalCommitBuilder::build_group()`.
pub fn construct_identity_proof(
    keys: &Keys,
    credential_identity: &[u8],
    signature_key: &[u8],
    serialized_group_context: &[u8],
) -> Result<NostrIdentityProof, Error> {
    let challenge = compute_challenge(credential_identity, signature_key, serialized_group_context);
    let event = sign_canonical_proof_event(keys, &challenge)?;

    let sig_bytes: [u8; 64] = event.sig.serialize();

    Ok(NostrIdentityProof::new(sig_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_roundtrip() {
        let sig = [0xABu8; 64];
        let proof = NostrIdentityProof::new(sig);

        let bytes = proof.to_authenticated_data().unwrap();
        let decoded = NostrIdentityProof::from_authenticated_data(&bytes).unwrap();
        assert_eq!(proof, decoded);
    }

    #[test]
    fn test_construct_and_verify() {
        let keys = Keys::generate();
        let credential_identity = b"fake-nostr-pubkey-32-bytes------";
        let signature_key = b"fake-mls-signature-key-bytes----";
        let group_context = b"fake-group-context-tls-bytes";

        let proof =
            construct_identity_proof(&keys, credential_identity, signature_key, group_context)
                .unwrap();

        verify_identity_proof(
            &proof,
            &keys.public_key(),
            credential_identity,
            signature_key,
            group_context,
        )
        .unwrap();
    }

    #[test]
    fn test_wrong_pubkey_fails_verification() {
        let keys = Keys::generate();
        let other_keys = Keys::generate();
        let cred = b"cred";
        let sig_key = b"sigkey";
        let gc = b"context";

        let proof = construct_identity_proof(&keys, cred, sig_key, gc).unwrap();

        let result = verify_identity_proof(&proof, &other_keys.public_key(), cred, sig_key, gc);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_challenge_fails_verification() {
        let keys = Keys::generate();
        let cred = b"cred";
        let sig_key = b"sigkey";
        let gc = b"context";

        let proof = construct_identity_proof(&keys, cred, sig_key, gc).unwrap();

        let result = verify_identity_proof(&proof, &keys.public_key(), b"wrong-cred", sig_key, gc);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_signature_key_fails_verification() {
        let keys = Keys::generate();
        let cred = b"cred";
        let sig_key = b"sigkey";
        let gc = b"context";

        let proof = construct_identity_proof(&keys, cred, sig_key, gc).unwrap();

        let result = verify_identity_proof(&proof, &keys.public_key(), cred, b"wrong-sigkey", gc);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_authenticated_data_rejected() {
        let result = NostrIdentityProof::from_authenticated_data(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_is_deterministic() {
        let c1 = compute_challenge(b"cred", b"sigkey", b"ctx");
        let c2 = compute_challenge(b"cred", b"sigkey", b"ctx");
        assert_eq!(c1, c2);

        let c3 = compute_challenge(b"different", b"sigkey", b"ctx");
        assert_ne!(c1, c3);
    }
}
