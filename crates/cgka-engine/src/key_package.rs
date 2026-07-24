//! KeyPackage generation + validation.
//!
//! Scope for 0.1.0: produce a fresh KeyPackage whose leaf capabilities are
//! derived from the [`crate::FeatureRegistry`]. Transported KeyPackages are
//! validated for OpenMLS lifetime validity and accepted lifetime range;
//! refresh scheduling is handled above the engine.

use crate::capabilities::leaf_capabilities;
use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::KeyPackage;
use cgka_traits::error::EngineError;
use cgka_traits::group::ProtocolProfile;
use cgka_traits::storage::StorageProvider;
use openmls::prelude::{
    KeyPackage as MlsKeyPackage, KeyPackageVerifyError, MlsMessageBodyIn, MlsMessageIn,
    MlsMessageOut, ProtocolVersion,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider as _;
use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPackageMetadata {
    pub key_package_ref_hex: String,
    pub credential_identity_hex: String,
    pub protocol_profile: ProtocolProfile,
    pub ciphersuite: u16,
    pub mls_extensions: Vec<u16>,
    pub mls_proposals: Vec<u16>,
    pub app_components: Vec<u16>,
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
    let key_package = validate_key_package(kp_in, &crypto)?;
    let member_id = crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
    // Validate the account-identity proof against the KeyPackage's OWN
    // ciphersuite, matching `parse_key_package` (mdk#747). `DEFAULT_CIPHERSUITE`
    // is correct only while the engine is single-ciphersuite; deriving it from
    // the KeyPackage keeps these directory helpers consistent with the invite
    // path the instant a second ciphersuite is supported.
    let protocol_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
        key_package.leaf_node(),
        key_package.ciphersuite(),
    )?;
    ensure_key_package_profile(kp, protocol_profile)?;
    let capabilities = crate::capabilities::capabilities_of_key_package(&key_package);
    let key_package_ref = key_package
        .hash_ref(&crypto)
        .map_err(|e| EngineError::Backend(format!("key_package ref: {e:?}")))?;
    Ok(KeyPackageMetadata {
        key_package_ref_hex: hex::encode(key_package_ref.as_slice()),
        credential_identity_hex: hex::encode(member_id.as_slice()),
        protocol_profile,
        ciphersuite: u16::from(key_package.ciphersuite()),
        mls_extensions: capabilities.extensions.into_iter().collect(),
        mls_proposals: capabilities.proposals.into_iter().collect(),
        app_components: capabilities.app_components.ids.into_iter().collect(),
    })
}

/// Parse and validate a transported KeyPackage and report whether it carries
/// either the current last-resort application-data component or the legacy
/// last-resort extension.
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
    let key_package = validate_key_package(kp_in, &crypto)?;
    crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
    // See `key_package_metadata`: validate against the KeyPackage's own
    // ciphersuite, not `DEFAULT_CIPHERSUITE` (mdk#747).
    let protocol_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
        key_package.leaf_node(),
        key_package.ciphersuite(),
    )?;
    ensure_key_package_profile(kp, protocol_profile)?;
    Ok(key_package.last_resort())
}

impl<S: StorageProvider> Engine<S> {
    /// Build + persist a fresh KeyPackage, returning its wire bytes.
    pub(crate) fn do_fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        let caps = leaf_capabilities(&self.registry, self.ciphersuite, self.new_protocol_profile);
        let leaf_extensions = self
            .identity
            .leaf_extensions(&self.supported_app_components)?;
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
        Ok(KeyPackage::new(bytes).with_protocol_profile(self.new_protocol_profile))
    }

    /// Delete a previously generated (and persisted) KeyPackage bundle from
    /// storage, identified by its wire bytes.
    ///
    /// `do_fresh_key_package` persists the bundle's private HPKE init key
    /// material through the OpenMLS storage provider as a side effect of
    /// `KeyPackageBuilder::build`. When the higher layer fails to publish that
    /// KeyPackage it must call this to prune the orphaned private bundle;
    /// otherwise retries against a failing publisher accumulate unused private
    /// key material indefinitely (mdk#160). The KeyPackages produced
    /// here carry the last-resort application-data component, so OpenMLS never
    /// deletes them on the welcome path — cleanup is entirely the caller's
    /// responsibility.
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
        let key_package = validate_key_package(kp_in, provider.crypto())?;
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
        let key_package = validate_key_package(kp_in, provider.crypto())?;
        // foundation/key-packages.md: reject a KeyPackage whose credential
        // identity is not a valid Marmot account identity. This single gate
        // covers both the create-group and invite invitee paths.
        crate::identity::validated_member_id_of_leaf(key_package.leaf_node())?;
        let protocol_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
            key_package.leaf_node(),
            key_package.ciphersuite(),
        )?;
        ensure_key_package_profile(kp, protocol_profile)?;
        Ok(key_package)
    }
}

fn ensure_key_package_profile(
    key_package: &KeyPackage,
    wire_profile: ProtocolProfile,
) -> Result<(), EngineError> {
    if key_package.protocol_profile != wire_profile {
        return Err(EngineError::InvalidAccountIdentityProof(format!(
            "KeyPackage metadata says {:?}, but its decoded account proof is {wire_profile:?}",
            key_package.protocol_profile
        )));
    }
    Ok(())
}

fn validate_key_package(
    kp_in: openmls::prelude::KeyPackageIn,
    crypto: &impl OpenMlsCrypto,
) -> Result<MlsKeyPackage, EngineError> {
    let key_package = kp_in
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(key_package_verify_error)?;
    validate_key_package_lifetime_policy(&key_package)?;
    Ok(key_package)
}

fn key_package_verify_error(err: KeyPackageVerifyError) -> EngineError {
    match err {
        KeyPackageVerifyError::LifetimeError(_) | KeyPackageVerifyError::MissingLifetime => {
            EngineError::InvalidKeyPackageLifetime {
                not_before: None,
                not_after: None,
            }
        }
        other => EngineError::Backend(format!("key_package validate: {other:?}")),
    }
}

fn validate_key_package_lifetime_policy(key_package: &MlsKeyPackage) -> Result<(), EngineError> {
    let lifetime = key_package.life_time();
    if !lifetime.has_acceptable_range() {
        return Err(EngineError::InvalidKeyPackageLifetime {
            not_before: Some(lifetime.not_before()),
            not_after: Some(lifetime.not_after()),
        });
    }
    Ok(())
}
