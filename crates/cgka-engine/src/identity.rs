//! Local client identity — signer + credential bundle carried by the engine.
//!
//! Generated once per Marmot identity and persisted through the configured
//! storage backend so reopened account-device sessions keep the same MLS
//! signing key.

use cgka_traits::storage::{
    AccountDeviceSignerBinding, StorageProvider as CgkaStorageProvider, StorageResult,
};
use cgka_traits::types::MemberId;
use openmls::prelude::{BasicCredential, CredentialWithKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::Ciphersuite;

/// Bundle of everything needed to sign + identify the local client.
pub struct Identity {
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) self_id: MemberId,
}

impl Identity {
    /// Load or create an identity with a basic credential whose `identity`
    /// field carries `identity_bytes` (opaque — typically a stable pubkey).
    pub fn load_or_generate<S>(
        ciphersuite: Ciphersuite,
        identity_bytes: Vec<u8>,
        storage: &S,
    ) -> Result<Self, String>
    where
        S: CgkaStorageProvider,
    {
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
            return Ok(Self::from_signer(signer, identity_bytes));
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
        Ok(Self::from_signer(signer, identity_bytes))
    }

    fn from_signer(signer: SignatureKeyPair, identity_bytes: Vec<u8>) -> Self {
        let credential = BasicCredential::new(identity_bytes.clone());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        };
        Self {
            signer,
            credential_with_key,
            self_id: MemberId::new(identity_bytes),
        }
    }

    pub fn self_id(&self) -> &MemberId {
        &self.self_id
    }
}

fn storage_err<T>(result: StorageResult<T>) -> Result<T, String> {
    result.map_err(|e| format!("identity storage: {e}"))
}
