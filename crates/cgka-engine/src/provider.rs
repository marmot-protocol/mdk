//! Ephemeral `OpenMlsProvider` adapter composed from the engine's OpenMLS
//! crypto/rand provider and the storage's OpenMLS side.
//!
//! Per the accessor-composition pattern (see the `feedback` memory on
//! OpenMLS delegation), the engine does not implement `OpenMlsProvider`
//! itself. It materializes one per MLS call via [`EngineOpenMlsProvider`].
//! Cheap (two refs); lets us avoid hand-forwarding 50+ storage methods.

use cgka_traits::storage::StorageProvider;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

pub struct EngineOpenMlsProvider<'a, S: StorageProvider> {
    crypto: &'a RustCrypto,
    storage: &'a S::Mls,
}

impl<'a, S: StorageProvider> EngineOpenMlsProvider<'a, S> {
    pub fn new(crypto: &'a RustCrypto, storage: &'a S::Mls) -> Self {
        Self { crypto, storage }
    }
}

impl<'a, S: StorageProvider> OpenMlsProvider for EngineOpenMlsProvider<'a, S> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = S::Mls;

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }

    fn storage(&self) -> &Self::StorageProvider {
        self.storage
    }
}
