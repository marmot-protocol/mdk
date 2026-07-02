//! Core newtype identifiers used across every crate boundary.
//!
//! All ids are opaque byte strings or wrapped primitives. None of them carry
//! transport-layer semantics — a [`GroupId`] is the MLS group id only; any
//! mapping to a `nostr_group_id` or FIPS mesh id lives in a transport adapter,
//! never here.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! byte_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
                Self(bytes.into())
            }

            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }

            pub fn into_bytes(self) -> Vec<u8> {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(&self.0))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", hex::encode(&self.0))
            }
        }
    };
}

byte_id!(
    /// MLS group identifier. Opaque byte string produced by OpenMLS at group
    /// creation. Never a Nostr group id.
    GroupId
);

byte_id!(
    /// Transport-assigned message identifier. Unique per message; used for
    /// dedup inside `IngestOutcome::Stale { AlreadySeen }`.
    MessageId
);

byte_id!(
    /// Cross-transport member identifier. Typically a signature public key.
    /// Not an MLS leaf index — indices change as the tree evolves; this id
    /// stays stable across epochs.
    MemberId
);

/// Monotonically-increasing epoch number, scoped per group.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct EpochId(pub u64);

impl EpochId {
    pub fn next(self) -> Self {
        EpochId(self.0 + 1)
    }
}

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

/// Which storage backend implementation a [`StorageProvider`](crate::storage::StorageProvider)
/// instance is. Consumers rarely need this, but tests and diagnostics sometimes do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// SQLCipher-backed SQLite persistence. See `storage-sqlite`.
    Sqlite,
}
