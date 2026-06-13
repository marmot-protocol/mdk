//! Local client identity — signer + credential bundle carried by the engine.
//!
//! Generated once per Marmot identity and persisted through the configured
//! storage backend so reopened account-device sessions keep the same MLS
//! signing key.

use cgka_traits::error::EngineError;
use cgka_traits::storage::{
    AccountDeviceSignerBinding, StorageProvider as CgkaStorageProvider, StorageResult,
};
use cgka_traits::types::MemberId;
use openmls::extensions::Extension;
use openmls::group::MlsGroup;
use openmls::prelude::{
    BasicCredential, Credential, CredentialWithKey, LeafNode, LeafNodeIndex, Sender,
    SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;

/// Bundle of everything needed to sign + identify the local client.
pub struct Identity {
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) self_id: MemberId,
    pub(crate) account_identity_proof_extension: Extension,
}

impl Identity {
    /// Load or create an identity with a basic credential whose `identity`
    /// field carries `identity_bytes` (opaque — typically a stable pubkey).
    pub fn load_or_generate<S>(
        ciphersuite: Ciphersuite,
        identity_bytes: Vec<u8>,
        storage: &S,
        proof_signer: &dyn crate::account_identity_proof::AccountIdentityProofSigner,
    ) -> Result<Self, String>
    where
        S: CgkaStorageProvider,
    {
        // foundation/identity.md: the local Marmot identity is a 32-byte x-only
        // secp256k1 public key. Reject anything else before it can become a
        // credential other clients would also reject.
        validate_credential_identity(&identity_bytes).map_err(|e| e.to_string())?;
        let scheme: SignatureScheme = ciphersuite.signature_algorithm();
        let self_id = MemberId::new(identity_bytes.clone());
        if let Some(binding) = storage_err(storage.account_device_signer(&self_id))? {
            let signer = SignatureKeyPair::read(
                storage.mls_storage(),
                &binding.mls_signature_public_key,
                scheme,
            )
            .ok_or_else(|| {
                "identity storage: local signer record exists, but OpenMLS keypair is missing"
                    .to_string()
            })?;
            return Self::from_signer(signer, identity_bytes, ciphersuite, proof_signer);
        }

        let signer = SignatureKeyPair::new(scheme).map_err(|e| format!("signer: {e}"))?;
        signer
            .store(storage.mls_storage())
            .map_err(|e| format!("store signer: {e:?}"))?;
        storage_err(
            storage.put_account_device_signer(&AccountDeviceSignerBinding {
                marmot_identity: self_id,
                mls_signature_public_key: signer.to_public_vec(),
            }),
        )?;
        Self::from_signer(signer, identity_bytes, ciphersuite, proof_signer)
    }

    fn from_signer(
        signer: SignatureKeyPair,
        identity_bytes: Vec<u8>,
        ciphersuite: Ciphersuite,
        proof_signer: &dyn crate::account_identity_proof::AccountIdentityProofSigner,
    ) -> Result<Self, String> {
        let credential = BasicCredential::new(identity_bytes.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        let account_identity_proof_extension =
            crate::account_identity_proof::account_identity_proof_extension(
                &identity_bytes,
                &signer.to_public_vec(),
                ciphersuite,
                ciphersuite.signature_algorithm(),
                proof_signer,
            )
            .map_err(|e| e.to_string())?;
        Ok(Self {
            signer,
            credential_with_key,
            self_id: MemberId::new(identity_bytes),
            account_identity_proof_extension,
        })
    }

    pub fn self_id(&self) -> &MemberId {
        &self.self_id
    }
}

fn storage_err<T>(result: StorageResult<T>) -> Result<T, String> {
    result.map_err(|e| format!("identity storage: {e}"))
}

/// Validate that `identity` is a valid Marmot member-leaf credential identity.
///
/// Per `spec/foundation/identity.md` and `spec/foundation/key-packages.md`,
/// the identity MUST be exactly 32 bytes AND those bytes MUST encode a valid
/// x-only secp256k1 (BIP-340) public key, i.e. a field element `x < p` that
/// lifts to a point on secp256k1.
///
/// We validate with `k256::schnorr::VerifyingKey::from_bytes`, which performs
/// the BIP-340 `lift_x` decompaction and on-curve check. The length check is
/// performed first because the underlying field-element parser expects exactly
/// 32 bytes.
pub(crate) fn validate_credential_identity(identity: &[u8]) -> Result<(), EngineError> {
    if identity.len() != 32 {
        return Err(EngineError::InvalidCredentialIdentity(format!(
            "credential identity must be exactly 32 bytes; got {}",
            identity.len()
        )));
    }
    k256::schnorr::VerifyingKey::from_bytes(identity).map_err(|_| {
        EngineError::InvalidCredentialIdentity(
            "credential identity is not a valid x-only secp256k1 public key".to_string(),
        )
    })?;
    Ok(())
}

/// Extract the validated `MemberId` from an MLS `Credential`.
///
/// The credential MUST be a `BasicCredential` whose identity is a valid Marmot
/// account identity. Used at every credential ingress so a malformed identity
/// is rejected before it can be trusted as a member id.
pub(crate) fn validated_member_id(credential: &Credential) -> Result<MemberId, EngineError> {
    let basic = BasicCredential::try_from(credential.clone()).map_err(|e| {
        EngineError::InvalidCredentialIdentity(format!("not a BasicCredential: {e:?}"))
    })?;
    let identity = basic.identity();
    validate_credential_identity(identity)?;
    Ok(MemberId::new(identity.to_vec()))
}

/// Validate the credential identity carried by a `LeafNode` (KeyPackage leaf or
/// in-tree leaf). Returns the validated `MemberId`.
pub(crate) fn validated_member_id_of_leaf(leaf: &LeafNode) -> Result<MemberId, EngineError> {
    validated_member_id(leaf.credential())
}

pub(crate) fn member_id_of_sender(sender: &Sender, group: &MlsGroup) -> Option<MemberId> {
    match sender {
        Sender::Member(leaf_idx) => member_id_at_leaf(group, *leaf_idx),
        _ => None,
    }
}

pub(crate) fn member_id_at_leaf(group: &MlsGroup, leaf_idx: LeafNodeIndex) -> Option<MemberId> {
    let member = group.member_at(leaf_idx)?;
    validated_member_id(&member.credential).ok()
}

#[cfg(test)]
mod tests {
    use super::validate_credential_identity;
    use k256::schnorr::SigningKey;

    /// A deterministic valid x-only secp256k1 public key derived from a seed.
    fn valid_xonly(seed: &[u8]) -> [u8; 32] {
        let mut counter = 0u64;
        loop {
            let mut material = [0u8; 32];
            let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
            sha2::Digest::update(&mut hasher, b"cgka-engine-identity-test-v1");
            sha2::Digest::update(&mut hasher, seed);
            sha2::Digest::update(&mut hasher, counter.to_be_bytes());
            material.copy_from_slice(&sha2::Digest::finalize(hasher));
            if let Ok(sk) = SigningKey::from_bytes(&material) {
                return sk.verifying_key().to_bytes().into();
            }
            counter += 1;
        }
    }

    #[test]
    fn accepts_valid_x_only_pubkey() {
        let pk = valid_xonly(b"alice");
        assert!(validate_credential_identity(&pk).is_ok());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(validate_credential_identity(&[0u8; 31]).is_err());
        assert!(validate_credential_identity(&[0u8; 33]).is_err());
        assert!(validate_credential_identity(b"alice").is_err());
    }

    #[test]
    fn rejects_invalid_curve_point() {
        // `pad32(b"david")` is 32 bytes but not a valid x-only point: a
        // zero-padded label is not a curve point in general.
        let mut padded = vec![0u8; 32];
        padded[..5].copy_from_slice(b"david");
        assert!(validate_credential_identity(&padded).is_err());
    }

    #[test]
    fn rejects_all_zero_and_field_overflow() {
        // All-zero x is not a valid x-only point.
        assert!(validate_credential_identity(&[0u8; 32]).is_err());
        // x >= field prime p must be rejected (all-0xFF overflows p).
        assert!(validate_credential_identity(&[0xFFu8; 32]).is_err());
    }
}
