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
    Extensions, KeyPackage as MlsKeyPackage, MlsMessageBodyIn, MlsMessageOut, ProtocolVersion,
};
use openmls_traits::OpenMlsProvider as _;
use tls_codec::{Deserialize as _, Serialize as _};

impl<S: StorageProvider> Engine<S> {
    /// Build + persist a fresh KeyPackage, returning its wire bytes.
    pub(crate) fn do_fresh_key_package(&mut self) -> Result<KeyPackage, EngineError> {
        let caps = leaf_capabilities(&self.registry, self.ciphersuite);
        let leaf_extensions = Extensions::single(
            crate::app_components::leaf_app_components_extension(&self.supported_app_components)?,
        )
        .map_err(|e| EngineError::Backend(format!("leaf extensions: {e:?}")))?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());

        let bundle = MlsKeyPackage::builder()
            .leaf_node_capabilities(caps)
            .leaf_node_extensions(leaf_extensions)
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
        Ok(KeyPackage(bytes))
    }

    /// Parse a transported KeyPackage back into an OpenMLS
    /// [`MlsKeyPackage`], running the MLS 1.0 validation pass. Used by
    /// `create_group` and `invite`.
    pub(crate) fn parse_key_package(&self, kp: &KeyPackage) -> Result<MlsKeyPackage, EngineError> {
        let msg = openmls::prelude::MlsMessageIn::tls_deserialize_exact(kp.0.as_slice())
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
        kp_in
            .validate(provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| EngineError::Backend(format!("key_package validate: {e:?}")))
    }
}
