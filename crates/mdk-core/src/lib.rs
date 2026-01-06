//! A Rust implementation of the Nostr Message Layer Security (MLS) protocol
//!
//! This crate provides functionality for implementing secure group messaging in Nostr using the MLS protocol.
//! It handles group creation, member management, message encryption/decryption, key management, and storage of groups and messages.
//! The implementation follows the MLS specification while integrating with Nostr's event system.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use mdk_storage_traits::MdkStorageProvider;
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;

mod constant;
#[cfg(feature = "mip04")]
#[cfg_attr(docsrs, doc(cfg(feature = "mip04")))]
pub mod encrypted_media;
pub mod error;
pub mod extension;
pub mod groups;
pub mod key_packages;
pub mod media_processing;
pub mod messages;
pub mod prelude;
#[cfg(test)]
pub mod test_util;
mod util;
pub mod welcomes;

use self::constant::{
    DEFAULT_CIPHERSUITE, GROUP_CONTEXT_REQUIRED_EXTENSIONS, SUPPORTED_EXTENSIONS,
};
pub use self::error::Error;
use self::util::NostrTagFormat;

// Re-export GroupId for convenience
pub use mdk_storage_traits::GroupId;

/// Configuration for MDK behavior
#[derive(Debug, Clone, Default)]
pub struct MdkConfig {}

impl MdkConfig {
    /// Create a new configuration with default settings
    pub fn new() -> Self {
        Self::default()
    }
}

/// Builder for constructing MDK instances
///
/// This builder provides a fluent API for configuring and creating MDK instances.
/// It follows the builder pattern commonly used in Rust libraries.
///
/// # Examples
///
/// ```no_run
/// use mdk_core::{MDK, MdkConfig};
/// use mdk_memory_storage::MdkMemoryStorage;
///
/// // Simple usage with defaults
/// let mdk = MDK::new(MdkMemoryStorage::default());
///
/// // With custom configuration
/// let mdk = MDK::builder(MdkMemoryStorage::default())
///     .with_config(MdkConfig::new())
///     .build();
/// ```
#[derive(Debug)]
pub struct MdkBuilder<Storage> {
    storage: Storage,
    config: MdkConfig,
}

impl<Storage> MdkBuilder<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Create a new MDK builder with the given storage
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            config: MdkConfig::default(),
        }
    }

    /// Set a custom configuration
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mdk_core::{MDK, MdkConfig};
    /// # use mdk_memory_storage::MdkMemoryStorage;
    /// let config = MdkConfig::new();
    /// let mdk = MDK::builder(MdkMemoryStorage::default())
    ///     .with_config(config)
    ///     .build();
    /// ```
    pub fn with_config(mut self, config: MdkConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the MDK instance with the configured settings
    pub fn build(self) -> MDK<Storage> {
        MDK {
            ciphersuite: DEFAULT_CIPHERSUITE,
            extensions: SUPPORTED_EXTENSIONS.to_vec(),
            provider: MdkProvider {
                crypto: RustCrypto::default(),
                storage: self.storage,
            },
            config: self.config,
        }
    }
}

/// The main struct for the Nostr MLS implementation.
///
/// This struct provides the core functionality for MLS operations in Nostr:
/// - Group management (creation, updates, member management)
/// - Message handling (encryption, decryption, processing)
/// - Key management (key packages, welcome messages)
///
/// It uses a generic storage provider that implements the `MdkStorageProvider` trait,
/// allowing for flexible storage backends.
#[derive(Debug)]
pub struct MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// The MLS ciphersuite used for cryptographic operations
    pub ciphersuite: Ciphersuite,
    /// Required MLS extensions for Nostr functionality
    pub extensions: Vec<ExtensionType>,
    /// The OpenMLS provider implementation for cryptographic and storage operations
    pub provider: MdkProvider<Storage>,
    /// Configuration for encoding behavior
    pub config: MdkConfig,
}

/// Provider implementation for OpenMLS that integrates with Nostr.
///
/// This struct implements the OpenMLS Provider trait, providing:
/// - Cryptographic operations through RustCrypto
/// - Storage operations through the generic Storage type
/// - Random number generation through RustCrypto
#[derive(Debug)]
pub struct MdkProvider<Storage>
where
    Storage: MdkStorageProvider,
{
    crypto: RustCrypto,
    storage: Storage,
}

impl<Storage> OpenMlsProvider for MdkProvider<Storage>
where
    Storage: MdkStorageProvider,
{
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = Storage::OpenMlsStorageProvider;

    fn storage(&self) -> &Self::StorageProvider {
        self.storage.openmls_storage()
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Create a builder for constructing an MDK instance
    ///
    /// This is the recommended way to create MDK instances when you need
    /// custom configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mdk_core::MDK;
    /// # use mdk_memory_storage::MdkMemoryStorage;
    /// let mdk = MDK::builder(MdkMemoryStorage::default())
    ///     .build();
    /// ```
    pub fn builder(storage: Storage) -> MdkBuilder<Storage> {
        MdkBuilder::new(storage)
    }

    /// Construct a new MDK instance with default configuration
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mdk_core::MDK;
    /// # use mdk_memory_storage::MdkMemoryStorage;
    /// # use mdk_core::MdkConfig;
    /// let mdk = MDK::new(MdkMemoryStorage::default());
    ///
    /// let mdk = MDK::builder(MdkMemoryStorage::default())
    ///     .with_config(MdkConfig::new())
    ///     .build();
    /// ```
    pub fn new(storage: Storage) -> Self {
        Self::builder(storage).build()
    }

    /// Get nostr MLS capabilities
    #[inline]
    pub(crate) fn capabilities(&self) -> Capabilities {
        Capabilities::new(
            None,
            Some(&[self.ciphersuite]),
            Some(&self.extensions),
            None,
            None,
        )
    }

    /// Get nostr mls group's required capabilities extension
    #[inline]
    pub(crate) fn required_capabilities_extension(&self) -> Extension {
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &GROUP_CONTEXT_REQUIRED_EXTENSIONS,
            &[],
            &[],
        ))
    }

    /// Get the ciphersuite value formatted for Nostr tags (hex with 0x prefix)
    pub(crate) fn ciphersuite_value(&self) -> String {
        self.ciphersuite.to_nostr_tag()
    }

    /// Get the extensions value formatted for Nostr tags (array of hex values)
    pub(crate) fn extensions_value(&self) -> Vec<String> {
        self.extensions.iter().map(|e| e.to_nostr_tag()).collect()
    }

    /// Get the storage provider
    pub(crate) fn storage(&self) -> &Storage {
        &self.provider.storage
    }
}

/// Tests module for nostr-mls
#[cfg(test)]
pub mod tests {
    use mdk_memory_storage::MdkMemoryStorage;

    use super::*;

    /// Create a test MDK instance with an in-memory storage provider
    pub fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
    }

    /// Create a test MDK instance with custom configuration
    pub fn create_test_mdk_with_config(config: MdkConfig) -> MDK<MdkMemoryStorage> {
        MDK::builder(MdkMemoryStorage::default())
            .with_config(config)
            .build()
    }
}
