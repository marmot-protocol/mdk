//! MDK storage - A set of storage provider traits and types for implementing MLS storage
//! It is designed to be used in conjunction with the `openmls` crate.

#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::bare_urls)]

use openmls_traits::storage::StorageProvider;

macro_rules! string_enum {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident => $error_ty:ty, $invalid_message:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $value:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Get as `&str`
            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = $error_ty;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(<$error_ty>::InvalidParameters(format!($invalid_message, s))),
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s: String = String::deserialize(deserializer)?;
                Self::from_str(&s).map_err(serde::de::Error::custom)
            }
        }

        pastey::paste! {
            #[cfg(test)]
            mod [<$name:snake _string_enum_tests>] {
                use super::*;
                use std::str::FromStr;

                #[test]
                fn from_str_valid() {
                    $(
                        assert_eq!(
                            $name::from_str($value).unwrap(),
                            $name::$variant,
                        );
                    )+
                }

                #[test]
                fn from_str_invalid() {
                    assert!($name::from_str("__invalid_test_value__").is_err());
                }

                #[test]
                fn to_string_matches_value() {
                    $(
                        assert_eq!($name::$variant.to_string(), $value);
                    )+
                }

                #[test]
                fn serde_roundtrip() {
                    $(
                        let serialized = serde_json::to_string(&$name::$variant).unwrap();
                        assert_eq!(serialized, format!("\"{}\"", $value));
                        let deserialized: $name = serde_json::from_str(&serialized).unwrap();
                        assert_eq!(deserialized, $name::$variant);
                    )+
                }

                #[test]
                fn serde_invalid() {
                    let result = serde_json::from_str::<$name>(r#""__invalid_test_value__""#);
                    assert!(result.is_err());
                }
            }
        }
    };
}

/// Generate a `Pagination` struct with bounded limit/offset and a validation function.
///
/// Produces:
/// - `pub struct Pagination` with `limit`, `offset`, and any extra fields
/// - `new(limit, offset)` constructor
/// - `limit()` / `offset()` accessors with defaults
/// - `Default` impl
/// - A public `$validate` function that checks `1..=$max`
///
/// Extra fields are wrapped in `Option` and default to `None`.
macro_rules! bounded_pagination {
    (
        $(#[$struct_meta:meta])*
        default_limit: $default:expr,
        max_limit: $max:expr,
        error_type: $err:ty,
        validate_fn: $validate:ident
        $(, extra {
            $( $(#[$field_meta:meta])* $field:ident : $field_ty:ty ),+ $(,)?
        })?
    ) => {
        $(#[$struct_meta])*
        #[derive(Debug, Clone, Copy)]
        pub struct Pagination {
            /// Maximum number of items to return
            pub limit: Option<usize>,
            /// Number of items to skip
            pub offset: Option<usize>,
            $( $(
                $(#[$field_meta])*
                pub $field: Option<$field_ty>,
            )+ )?
        }

        impl Pagination {
            /// Create a new Pagination with specified limit and offset
            pub fn new(limit: Option<usize>, offset: Option<usize>) -> Self {
                Self {
                    limit,
                    offset,
                    $( $( $field: None, )+ )?
                }
            }

            /// Get the limit value, using default if not specified
            pub fn limit(&self) -> usize {
                self.limit.unwrap_or($default)
            }

            /// Get the offset value, using 0 if not specified
            pub fn offset(&self) -> usize {
                self.offset.unwrap_or(0)
            }
        }

        impl Default for Pagination {
            fn default() -> Self {
                Self {
                    limit: Some($default),
                    offset: Some(0),
                    $( $( $field: None, )+ )?
                }
            }
        }

        /// Validate that a limit is within the allowed range.
        ///
        /// Returns `Ok(())` if `limit` is between 1 and the maximum (inclusive),
        /// or an error otherwise.
        #[inline]
        pub fn $validate(limit: usize) -> Result<(), $err> {
            if (1..=$max).contains(&limit) {
                Ok(())
            } else {
                Err(<$err>::InvalidParameters(format!(
                    "Limit must be between 1 and {}, got {}",
                    $max, limit
                )))
            }
        }
    };
}

/// Generate a storage error enum with common `InvalidParameters(String)` and
/// `DatabaseError(String)` variants, plus any module-specific extras.
macro_rules! storage_error {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$extra_meta:meta])*
                $extra_variant:ident $( ($extra_inner:ty) )?
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, thiserror::Error)]
        $vis enum $name {
            /// Invalid parameters
            #[error("Invalid parameters: {0}")]
            InvalidParameters(String),
            /// Database error
            #[error("Database error: {0}")]
            DatabaseError(String),
            $(
                $(#[$extra_meta])*
                $extra_variant $( ($extra_inner) )?,
            )*
        }
    };
}

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

/// Storage provider for MDK.
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

    /// Create a snapshot of a group's state before applying a commit.
    ///
    /// This captures all MLS and MDK state for the specified group,
    /// enabling rollback if a better commit arrives later (MIP-03).
    ///
    /// The snapshot is stored persistently (in SQLite) or in memory,
    /// keyed by both the group ID and snapshot name.
    fn create_group_snapshot(&self, group_id: &GroupId, name: &str) -> Result<(), MdkStorageError>;

    /// Rollback a group's state to a previously created snapshot.
    ///
    /// This restores all MLS and MDK state for the group to what it was
    /// when the snapshot was created. The snapshot is consumed (deleted) after use.
    fn rollback_group_to_snapshot(
        &self,
        group_id: &GroupId,
        name: &str,
    ) -> Result<(), MdkStorageError>;

    /// Release a snapshot that is no longer needed.
    ///
    /// Call this to free resources when a snapshot won't be used for rollback.
    fn release_group_snapshot(&self, group_id: &GroupId, name: &str)
    -> Result<(), MdkStorageError>;

    /// List all snapshots for a specific group with their creation timestamps.
    ///
    /// Returns a list of (snapshot_name, created_at_unix_timestamp) tuples
    /// ordered by creation time (oldest first). This is used for:
    /// - Hydrating the EpochSnapshotManager after restart
    /// - Auditing existing snapshots
    ///
    /// # Arguments
    ///
    /// * `group_id` - The group to list snapshots for
    ///
    /// # Returns
    ///
    /// A vector of (snapshot_name, created_at) tuples, or an error.
    fn list_group_snapshots(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(String, u64)>, MdkStorageError>;

    /// Prune all snapshots created before the given Unix timestamp.
    ///
    /// This is used for TTL-based cleanup of old snapshots to prevent
    /// indefinite storage growth and ensure cryptographic key material
    /// doesn't persist longer than necessary.
    ///
    /// # Arguments
    ///
    /// * `min_timestamp` - Unix timestamp cutoff; snapshots with `created_at < min_timestamp` are deleted
    ///
    /// # Returns
    ///
    /// The number of snapshots deleted, or an error.
    fn prune_expired_snapshots(&self, min_timestamp: u64) -> Result<usize, MdkStorageError>;

    /// Delete all local state for a group.
    ///
    /// Removes the group, its messages, processed message records, MLS tree state,
    /// epoch secrets, key material, proposals, and snapshots from local storage.
    ///
    /// This is irreversible. After deletion, the group cannot receive or decrypt
    /// new messages. Call `leave_group()` before this method to notify other members.
    ///
    /// Idempotent: deleting a nonexistent group returns `Ok(())`.
    ///
    /// This is a local-only operation with no protocol-level side effects.
    fn delete_group(&self, group_id: &GroupId) -> Result<(), MdkStorageError>;
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
