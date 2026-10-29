//! Identifiers a pairing session binds.

use std::fmt;

/// Largest `KeyPackageRef`, in bytes. Marmot's ciphersuite makes it 32; the
/// device roster allows up to 64.
pub const KEY_PACKAGE_REF_MAX_LEN: usize = 64;

/// Largest MLS group id a confirmation can name, in bytes.
pub const GROUP_ID_MAX_LEN: usize = 255;

/// Largest MLS signature public key a confirmation can name, in bytes: the
/// longest MLS signature scheme's, P-521's uncompressed point. With the
/// longest group id it keeps a confirmation under the content limit.
pub const SIGNATURE_KEY_MAX_LEN: usize = 133;

macro_rules! fixed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(self.0))
            }
        }
    };
}

fixed_id!(
    /// A pairing session's id: 32 random bytes the new device picks.
    SessionId
);

fixed_id!(
    /// The account both devices sign in to: its 32-byte x-only public key.
    AccountKey
);

fixed_id!(
    /// A device's KeyPackage publication slot. On Nostr it is the 32 bytes of
    /// the KeyPackage event's `d` value, the device roster's slot key.
    SlotId
);

fixed_id!(
    /// The transport's id for the new device's published KeyPackage. On Nostr
    /// it is the kind 30443 event id.
    KeyPackageEventId
);

fixed_id!(
    /// A pairing ephemeral X25519 public key.
    ExchangeKey
);

/// An MLS `KeyPackageRef`: opaque bytes, 1 to [`KEY_PACKAGE_REF_MAX_LEN`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyPackageRef(Vec<u8>);

impl KeyPackageRef {
    /// `None` if `bytes` is empty or longer than [`KEY_PACKAGE_REF_MAX_LEN`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        (1..=KEY_PACKAGE_REF_MAX_LEN)
            .contains(&bytes.len())
            .then_some(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for KeyPackageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPackageRef({})", hex::encode(&self.0))
    }
}

/// An MLS signature public key, as a leaf node's `signature_key`: opaque
/// bytes, 1 to [`SIGNATURE_KEY_MAX_LEN`]. Marmot's ciphersuite makes it a
/// 32-byte Ed25519 key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignatureKey(Vec<u8>);

impl SignatureKey {
    /// `None` if `bytes` is empty or longer than [`SIGNATURE_KEY_MAX_LEN`].
    pub fn new(bytes: impl Into<Vec<u8>>) -> Option<Self> {
        let bytes = bytes.into();
        (1..=SIGNATURE_KEY_MAX_LEN)
            .contains(&bytes.len())
            .then_some(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SignatureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SignatureKey({})", hex::encode(&self.0))
    }
}

/// Whether `bytes` fits a pairing confirmation's device-group id.
pub(crate) fn valid_group_id_len(bytes: &[u8]) -> bool {
    (1..=GROUP_ID_MAX_LEN).contains(&bytes.len())
}
