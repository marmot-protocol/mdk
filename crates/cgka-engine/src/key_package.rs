//! KeyPackage generation + validation.
//!
//! Scope for 0.1.0: produce a fresh KeyPackage whose leaf capabilities are
//! derived from the [`crate::FeatureRegistry`]. Expiry and refresh scheduling
//! are handled above the engine.

use crate::capabilities::leaf_capabilities;
use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use openmls::prelude::{
    Extensions, KeyPackage as MlsKeyPackage, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use tls_codec::{Deserialize as _, Serialize as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageMetadata {
    pub key_package_ref_hex: String,
    pub credential_identity_hex: String,
}

/// Parse and validate a transported KeyPackage enough for transport-directory
/// publication/fetch checks.
pub fn key_package_metadata(kp: &KeyPackage) -> Result<KeyPackageMetadata, EngineError> {
    let msg = MlsMessageIn::tls_deserialize_exact(kp.bytes())
        .map_err(|e| EngineError::Serialize(format!("key_package deserialize: {e:?}")))?;
    let kp_in = match msg.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => {
            return Err(EngineError::Serialize(
                "MLS message did not carry a KeyPackage".into(),
            ));
        }
    };
    let crypto = RustCrypto::default();
    let key_package = kp_in
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(|e| EngineError::Backend(format!("key_package validate: {e:?}")))?;
    let member_id = crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
    crate::account_identity_proof::validate_leaf_account_identity_proof(
        key_package.leaf_node(),
        crate::DEFAULT_CIPHERSUITE,
    )?;
    let key_package_ref = key_package
        .hash_ref(&crypto)
        .map_err(|e| EngineError::Backend(format!("key_package ref: {e:?}")))?;
    Ok(KeyPackageMetadata {
        key_package_ref_hex: hex::encode(key_package_ref.as_slice()),
        credential_identity_hex: hex::encode(member_id.as_slice()),
    })
}

/// Parse and validate a transported KeyPackage and report whether it carries
/// the MLS last-resort extension.
pub fn is_last_resort_key_package(kp: &KeyPackage) -> Result<bool, EngineError> {
    let msg = MlsMessageIn::tls_deserialize_exact(kp.bytes())
        .map_err(|e| EngineError::Serialize(format!("key_package deserialize: {e:?}")))?;
    let kp_in = match msg.extract() {
        MlsMessageBodyIn::KeyPackage(key_package) => key_package,
        _ => {
            return Err(EngineError::Serialize(
                "MLS message did not carry a KeyPackage".into(),
            ));
        }
    };
    let crypto = RustCrypto::default();
    let key_package = kp_in
        .validate(&crypto, ProtocolVersion::Mls10)
        .map_err(|e| EngineError::Backend(format!("key_package validate: {e:?}")))?;
    crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
    crate::account_identity_proof::validate_leaf_account_identity_proof(
        key_package.leaf_node(),
        crate::DEFAULT_CIPHERSUITE,
    )?;
    Ok(key_package.last_resort())
}

impl<S: StorageProvider> Engine<S> {
    /// Build + persist a fresh KeyPackage, returning its wire bytes.
    pub(crate) fn do_fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        let caps = leaf_capabilities(&self.registry, self.ciphersuite);
        let leaf_extensions = Extensions::from_vec(vec![
            crate::app_components::leaf_app_components_extension(&self.supported_app_components)?,
            self.identity.account_identity_proof_extension.clone(),
        ])
        .map_err(|e| EngineError::Backend(format!("leaf extensions: {e:?}")))?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());

        let bundle = MlsKeyPackage::builder()
            .leaf_node_capabilities(caps)
            .leaf_node_extensions(leaf_extensions)
            .mark_as_last_resort()
            .build(
                self.ciphersuite,
                &provider,
                &self.identity.signer,
                self.identity.credential_with_key.clone(),
            )
            .map_err(|e| EngineError::Backend(format!("key_package build: {e:?}")))?;

        let mls_msg: MlsMessageOut = bundle.key_package().clone().into();
        let bytes = mls_msg
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;
        Ok(KeyPackage::new(bytes))
    }

    /// Delete a previously generated (and persisted) KeyPackage bundle from
    /// storage, identified by its wire bytes.
    ///
    /// `do_fresh_key_package` persists the bundle's private HPKE init key
    /// material through the OpenMLS storage provider as a side effect of
    /// `KeyPackageBuilder::build`. When the higher layer fails to publish that
    /// KeyPackage it must call this to prune the orphaned private bundle;
    /// otherwise retries against a failing publisher accumulate unused private
    /// key material indefinitely (darkmatter#160). The KeyPackages produced
    /// here carry the last-resort extension, so OpenMLS never deletes them on
    /// the welcome path — cleanup is entirely the caller's responsibility.
    ///
    /// Deleting a KeyPackage that is not present in storage is a no-op (the
    /// underlying `DELETE` matches zero rows), so this is safe to call
    /// idempotently on a retry path.
    pub(crate) fn do_delete_key_package(&mut self, kp: &KeyPackage) -> Result<(), EngineError> {
        let msg = MlsMessageIn::tls_deserialize_exact(kp.bytes())
            .map_err(|e| EngineError::Serialize(format!("key_package deserialize: {e:?}")))?;
        let kp_in = match msg.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => {
                return Err(EngineError::Serialize(
                    "MLS message did not carry a KeyPackage".into(),
                ));
            }
        };
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let key_package = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| EngineError::Backend(format!("key_package validate: {e:?}")))?;
        let hash_ref = key_package
            .hash_ref(provider.crypto())
            .map_err(|e| EngineError::Backend(format!("key_package ref: {e:?}")))?;
        // Bring the OpenMLS storage trait into scope so `delete_key_package` is
        // callable on the MLS storage side. Aliased to avoid clashing with the
        // crate's own `cgka_traits::storage::StorageProvider` bound on `S`.
        use openmls_traits::storage::StorageProvider as OpenMlsStorageProvider;
        OpenMlsStorageProvider::delete_key_package(provider.storage(), &hash_ref)
            .map_err(|e| EngineError::Backend(format!("key_package delete: {e:?}")))?;
        Ok(())
    }

    /// Parse a transported KeyPackage back into an OpenMLS
    /// [`MlsKeyPackage`], running the MLS 1.0 validation pass. Used by
    /// `create_group` and `invite`.
    pub(crate) fn parse_key_package(&self, kp: &KeyPackage) -> Result<MlsKeyPackage, EngineError> {
        let msg = MlsMessageIn::tls_deserialize_exact(kp.bytes())
            .map_err(|e| EngineError::Serialize(format!("key_package deserialize: {e:?}")))?;

        let kp_in = match msg.extract() {
            MlsMessageBodyIn::KeyPackage(k) => k,
            _ => {
                return Err(EngineError::Serialize(
                    "MLS message did not carry a KeyPackage".into(),
                ));
            }
        };

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let key_package = kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| EngineError::Backend(format!("key_package validate: {e:?}")))?;
        // foundation/key-packages.md: reject a KeyPackage whose credential
        // identity is not a valid Marmot account identity. This single gate
        // covers both the create-group and invite invitee paths.
        crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
        crate::account_identity_proof::validate_leaf_account_identity_proof(
            key_package.leaf_node(),
            self.ciphersuite,
        )?;
        Ok(key_package)
    }
}
