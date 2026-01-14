//! Nostr MLS storage - A set of storage provider traits and types for implementing MLS storage
//! It is designed to be used in conjunction with the `openmls` crate.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use openmls_traits::storage::StorageProvider;

pub mod error;
pub mod group_id;
pub mod groups;
pub mod messages;
pub mod mls_codec;
/// Secret wrapper for zeroization
pub mod secret;
#[cfg(feature = "test-utils")]
pub mod test_utils;

pub mod welcomes;

// Re-export GroupId for convenience
pub use error::MdkStorageError;
pub use group_id::GroupId;
pub use secret::{Secret, Zeroize};

use self::groups::GroupStorage;
use self::messages::MessageStorage;
use self::welcomes::WelcomeStorage;

const CURRENT_VERSION: u16 = 1;

/// Backend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// Memory
    Memory,
    /// SQLite
    SQLite,
}

impl Backend {
    /// Check if it's a persistent backend
    ///
    /// All values different from [`Backend::Memory`] are considered persistent
    pub fn is_persistent(&self) -> bool {
        !matches!(self, Self::Memory)
    }
}

/// Storage provider for the Nostr MLS storage.
///
/// This trait combines all MDK storage requirements with the OpenMLS
/// `StorageProvider` trait, enabling unified storage implementations
/// that can atomically manage both MLS state and MDK-specific data.
///
/// Implementors must provide:
/// - Group storage for MLS group metadata and relays
/// - Message storage for encrypted messages
/// - Welcome storage for pending welcome messages
/// - Full OpenMLS `StorageProvider<1>` implementation for MLS cryptographic state
pub trait MdkStorageProvider:
    GroupStorage + MessageStorage + WelcomeStorage + StorageProvider<CURRENT_VERSION>
{
    /// Returns the backend type.
    ///
    /// # Returns
    ///
    /// The storage backend type (e.g., [`Backend::Memory`] or [`Backend::SQLite`]).
    fn backend(&self) -> Backend;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_is_persistent() {
        assert!(!Backend::Memory.is_persistent());
        assert!(Backend::SQLite.is_persistent());
    }
}
