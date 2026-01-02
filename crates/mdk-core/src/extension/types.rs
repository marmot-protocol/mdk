//! Nostr Group Extension functionality for MLS Group Context.
//! This is a required extension for Nostr Groups as per NIP-104.

use std::collections::BTreeSet;
use std::str;

use nostr::secp256k1::rand::Rng;
use nostr::secp256k1::rand::rngs::OsRng;
use nostr::{PublicKey, RelayUrl};
use openmls::extensions::{Extension, ExtensionType};
use openmls::group::{GroupContext, MlsGroup};
use tls_codec::{
    DeserializeBytes, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSerializeBytes, TlsSize,
};

use crate::constant::NOSTR_GROUP_DATA_EXTENSION_TYPE;
use crate::error::Error;

/// Legacy TLS-serializable representation of Nostr Group Data Extension (pre-version field).
///
/// This struct represents the format used before the version field was added to the spec.
/// It's used for backward compatibility to migrate existing groups to the versioned format.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerializeBytes,
    TlsSize,
)]
pub(crate) struct LegacyTlsNostrGroupDataExtension {
    pub nostr_group_id: [u8; 32],
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub admin_pubkeys: Vec<Vec<u8>>,
    pub relays: Vec<Vec<u8>>,
    pub image_hash: Vec<u8>,
    pub image_key: Vec<u8>,
    pub image_nonce: Vec<u8>,
}

/// TLS-serializable representation of Nostr Group Data Extension.
///
/// This struct is used exclusively for TLS codec serialization/deserialization
/// when the extension is transmitted over the MLS protocol. It uses `Vec<u8>`
/// for optional binary fields to allow empty vectors to represent `None` values,
/// which avoids the serialization issues that would occur with fixed-size arrays.
///
/// Users should not interact with this struct directly - use `NostrGroupDataExtension`
/// instead, which provides proper type safety and a clean API.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerializeBytes,
    TlsSize,
)]
pub(crate) struct TlsNostrGroupDataExtension {
    pub version: u16,
    pub nostr_group_id: [u8; 32],
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub admin_pubkeys: Vec<Vec<u8>>,
    pub relays: Vec<Vec<u8>>,
    pub image_hash: Vec<u8>,       // Use Vec<u8> to allow empty for None
    pub image_key: Vec<u8>,        // Use Vec<u8> to allow empty for None
    pub image_nonce: Vec<u8>,      // Use Vec<u8> to allow empty for None
    pub image_upload_key: Vec<u8>, // Use Vec<u8> to allow empty for None (v2 only)
}

/// This is an MLS Group Context extension used to store the group's name,
/// description, ID, admin identities, image URL, and image encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrGroupDataExtension {
    /// Extension format version (current: 2)
    /// Version 2: image_key field contains image_seed, image_upload_key contains upload_seed
    /// Version 1: image_key field contains encryption key directly (deprecated)
    pub version: u16,
    /// Nostr Group ID
    pub nostr_group_id: [u8; 32],
    /// Group name
    pub name: String,
    /// Group description
    pub description: String,
    /// Group admins
    pub admins: BTreeSet<PublicKey>,
    /// Relays
    pub relays: BTreeSet<RelayUrl>,
    /// Group image hash (blossom hash)
    pub image_hash: Option<[u8; 32]>,
    /// Image seed (v2) or encryption key (v1) for group image decryption
    ///
    /// **IMPORTANT**: The interpretation of this field depends on the `version` field:
    /// - **Version 2**: This is the seed used to derive the encryption key via HKDF
    /// - **Version 1**: This is the encryption key directly (deprecated, kept for backward compatibility)
    ///
    /// Consumers MUST check the `version` field before interpreting `image_key` to ensure correct usage.
    pub image_key: Option<[u8; 32]>,
    /// Nonce to decrypt group image
    pub image_nonce: Option<[u8; 12]>,
    /// Upload seed (v2 only) for deriving the Nostr keypair used for Blossom authentication
    ///
    /// In v2, the upload keypair is derived from this seed (cryptographically independent from image_key).
    /// In v1, the upload keypair was derived from image_key (now deprecated).
    pub image_upload_key: Option<[u8; 32]>,
}

impl NostrGroupDataExtension {
    /// Nostr Group Data extension type
    pub const EXTENSION_TYPE: u16 = NOSTR_GROUP_DATA_EXTENSION_TYPE;

    /// Current extension format version (MIP-01)
    /// Version 2: Uses image_seed (stored in image_key field) with HKDF derivation
    /// Version 1: Uses image_key directly as encryption key (deprecated)
    pub const CURRENT_VERSION: u16 = 2;

    /// Creates a new NostrGroupDataExtension with the given parameters.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the group
    /// * `description` - A description of the group's purpose
    /// * `admin_identities` - A list of Nostr public keys that have admin privileges
    /// * `relays` - A list of relay URLs where group messages will be published
    ///
    /// # Returns
    ///
    /// A new NostrGroupDataExtension instance with a randomly generated group ID and
    /// the provided parameters converted to bytes. This group ID value is what's used when publishing
    /// events to Nostr relays for the group.
    #[allow(clippy::too_many_arguments)]
    pub fn new<T1, T2, IA, IR>(
        name: T1,
        description: T2,
        admins: IA,
        relays: IR,
        image_hash: Option<[u8; 32]>,
        image_key: Option<[u8; 32]>,
        image_nonce: Option<[u8; 12]>,
        image_upload_key: Option<[u8; 32]>,
    ) -> Self
    where
        T1: Into<String>,
        T2: Into<String>,
        IA: IntoIterator<Item = PublicKey>,
        IR: IntoIterator<Item = RelayUrl>,
    {
        // Generate a random 32-byte group ID
        let mut rng = OsRng;
        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);

        Self {
            version: Self::CURRENT_VERSION,
            nostr_group_id: random_bytes,
            name: name.into(),
            description: description.into(),
            admins: admins.into_iter().collect(),
            relays: relays.into_iter().collect(),
            image_hash,
            image_key,
            image_nonce,
            image_upload_key,
        }
    }

    /// Migrate a legacy extension (without version field) to version 1 format
    ///
    /// Legacy extensions are migrated to version 1 (not CURRENT_VERSION) because they
    /// were created before versioning existed and use the v1 format (direct image_key).
    pub(crate) fn from_legacy_raw(legacy: LegacyTlsNostrGroupDataExtension) -> Result<Self, Error> {
        tracing::info!(
            target: "mdk_core::extension::types",
            "Migrating legacy extension without version field to version 1"
        );

        let mut admins = BTreeSet::new();
        for admin in legacy.admin_pubkeys {
            let bytes = hex::decode(&admin)?;
            let pk = PublicKey::from_slice(&bytes)?;
            admins.insert(pk);
        }

        let mut relays = BTreeSet::new();
        for relay in legacy.relays {
            let url: &str = str::from_utf8(&relay)?;
            let url = RelayUrl::parse(url)?;
            relays.insert(url);
        }

        let image_hash = if legacy.image_hash.is_empty() {
            None
        } else {
            Some(
                legacy
                    .image_hash
                    .try_into()
                    .map_err(|_| Error::InvalidImageHashLength)?,
            )
        };

        let image_key = if legacy.image_key.is_empty() {
            None
        } else {
            Some(
                legacy
                    .image_key
                    .try_into()
                    .map_err(|_| Error::InvalidImageKeyLength)?,
            )
        };

        let image_nonce = if legacy.image_nonce.is_empty() {
            None
        } else {
            Some(
                legacy
                    .image_nonce
                    .try_into()
                    .map_err(|_| Error::InvalidImageNonceLength)?,
            )
        };

        Ok(Self {
            version: 1, // Migrate to version 1 (legacy extensions use v1 format)
            nostr_group_id: legacy.nostr_group_id,
            name: String::from_utf8(legacy.name)?,
            description: String::from_utf8(legacy.description)?,
            admins,
            relays,
            image_hash,
            image_key,
            image_nonce,
            image_upload_key: None, // Legacy extensions don't have this field
        })
    }

    /// Deserialize extension bytes with automatic migration from legacy format.
    ///
    /// This private helper method attempts to deserialize raw bytes as a NostrGroupDataExtension,
    /// first trying the current format (with version field), and falling back to the legacy format
    /// (without version field) if needed.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw TLS-serialized bytes of the extension
    ///
    /// # Returns
    ///
    /// * `Ok(NostrGroupDataExtension)` - Successfully deserialized (and possibly migrated) extension
    /// * `Err(Error)` - Failed to deserialize with both current and legacy formats
    fn deserialize_with_migration(bytes: &[u8]) -> Result<Self, Error> {
        // Try to deserialize with current format (with version field)
        match TlsNostrGroupDataExtension::tls_deserialize_bytes(bytes) {
            Ok((deserialized, _)) => Self::from_raw(deserialized),
            Err(_) => {
                // If that fails, try legacy format (without version field)
                tracing::debug!(
                    target: "mdk_core::extension::types",
                    "Failed to deserialize with current format, attempting legacy format"
                );
                match LegacyTlsNostrGroupDataExtension::tls_deserialize_bytes(bytes) {
                    Ok((legacy_deserialized, _)) => Self::from_legacy_raw(legacy_deserialized),
                    Err(e) => {
                        tracing::error!(
                            target: "mdk_core::extension::types",
                            "Failed to deserialize extension with both current and legacy formats: {:?}",
                            e
                        );
                        Err(e.into())
                    }
                }
            }
        }
    }

    pub(crate) fn from_raw(raw: TlsNostrGroupDataExtension) -> Result<Self, Error> {
        // Validate version - we support versions 1 and 2
        // Future versions should be handled with forward compatibility
        if raw.version == 0 {
            return Err(Error::InvalidExtensionVersion(raw.version));
        }

        if raw.version > Self::CURRENT_VERSION {
            tracing::warn!(
                target: "mdk_core::extension::types",
                "Received extension with unknown future version {}, attempting forward compatibility. Note: field interpretation (especially image_key) depends on version - ensure correct version-specific handling",
                raw.version
            );
            // Continue processing with forward compatibility - unknown fields will be ignored
            // WARNING: Future versions might change field semantics (e.g., image_key meaning),
            // so consumers must check version before interpreting fields
        }

        let mut admins = BTreeSet::new();
        for admin in raw.admin_pubkeys {
            let bytes = hex::decode(&admin)?;
            let pk = PublicKey::from_slice(&bytes)?;
            admins.insert(pk);
        }

        let mut relays = BTreeSet::new();
        for relay in raw.relays {
            let url: &str = str::from_utf8(&relay)?;
            let url = RelayUrl::parse(url)?;
            relays.insert(url);
        }

        let image_hash = if raw.image_hash.is_empty() {
            None
        } else {
            Some(
                raw.image_hash
                    .try_into()
                    .map_err(|_| Error::InvalidImageHashLength)?,
            )
        };

        let image_key = if raw.image_key.is_empty() {
            None
        } else {
            Some(
                raw.image_key
                    .try_into()
                    .map_err(|_| Error::InvalidImageKeyLength)?,
            )
        };

        let image_nonce = if raw.image_nonce.is_empty() {
            None
        } else {
            Some(
                raw.image_nonce
                    .try_into()
                    .map_err(|_| Error::InvalidImageNonceLength)?,
            )
        };

        let image_upload_key = if raw.image_upload_key.is_empty() {
            None
        } else {
            Some(
                raw.image_upload_key
                    .try_into()
                    .map_err(|_| Error::InvalidImageUploadKeyLength)?,
            )
        };

        Ok(Self {
            version: raw.version,
            nostr_group_id: raw.nostr_group_id,
            name: String::from_utf8(raw.name)?,
            description: String::from_utf8(raw.description)?,
            admins,
            relays,
            image_hash,
            image_key,
            image_nonce,
            image_upload_key,
        })
    }

    /// Attempts to extract and deserialize a NostrGroupDataExtension from a GroupContext.
    ///
    /// # Arguments
    ///
    /// * `group_context` - Reference to the GroupContext containing the extension
    ///
    /// # Returns
    ///
    /// * `Ok(NostrGroupDataExtension)` - Successfully extracted and deserialized extension
    /// * `Err(Error)` - Failed to find or deserialize the extension
    ///
    /// # Migration Support
    ///
    /// This method supports backward compatibility with legacy extensions (pre-version field).
    /// If deserialization fails with the current format, it attempts to deserialize using
    /// the legacy format and migrates the extension to version 1.
    pub fn from_group_context(group_context: &GroupContext) -> Result<Self, Error> {
        let group_data_extension = match group_context.extensions().iter().find(|ext| {
            ext.extension_type() == ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE)
        }) {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(Error::UnexpectedExtensionType),
            None => return Err(Error::NostrGroupDataExtensionNotFound),
        };

        Self::deserialize_with_migration(&group_data_extension.0)
    }

    /// Attempts to extract and deserialize a NostrGroupDataExtension from an MlsGroup.
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the MlsGroup containing the extension
    ///
    /// # Migration Support
    ///
    /// This method supports backward compatibility with legacy extensions (pre-version field).
    /// If deserialization fails with the current format, it attempts to deserialize using
    /// the legacy format and migrates the extension to version 1.
    pub fn from_group(group: &MlsGroup) -> Result<Self, Error> {
        let group_data_extension = match group.extensions().iter().find(|ext| {
            ext.extension_type() == ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE)
        }) {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(Error::UnexpectedExtensionType),
            None => return Err(Error::NostrGroupDataExtensionNotFound),
        };

        Self::deserialize_with_migration(&group_data_extension.0)
    }

    /// Returns the group ID as a hex-encoded string.
    pub fn nostr_group_id(&self) -> String {
        hex::encode(self.nostr_group_id)
    }

    /// Get nostr group data extension type
    #[inline]
    pub fn extension_type(&self) -> u16 {
        Self::EXTENSION_TYPE
    }

    /// Sets the group ID using a 32-byte array.
    ///
    /// # Arguments
    ///
    /// * `nostr_group_id` - The new 32-byte group ID
    pub fn set_nostr_group_id(&mut self, nostr_group_id: [u8; 32]) {
        self.nostr_group_id = nostr_group_id;
    }

    /// Returns the group name as a UTF-8 string.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Sets the group name.
    ///
    /// # Arguments
    ///
    /// * `name` - The new group name
    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    /// Returns the group description as a UTF-8 string.
    pub fn description(&self) -> &str {
        self.description.as_str()
    }

    /// Sets the group description.
    ///
    /// # Arguments
    ///
    /// * `description` - The new group description
    pub fn set_description(&mut self, description: String) {
        self.description = description;
    }

    /// Adds a new admin identity to the list.
    pub fn add_admin(&mut self, public_key: PublicKey) {
        self.admins.insert(public_key);
    }

    /// Removes an admin identity from the list if it exists.
    pub fn remove_admin(&mut self, public_key: &PublicKey) {
        self.admins.remove(public_key);
    }

    /// Adds a new relay URL to the list.
    pub fn add_relay(&mut self, relay: RelayUrl) {
        self.relays.insert(relay);
    }

    /// Removes a relay URL from the list if it exists.
    pub fn remove_relay(&mut self, relay: &RelayUrl) {
        self.relays.remove(relay);
    }

    /// Returns the group image URL.
    pub fn image_hash(&self) -> Option<&[u8; 32]> {
        self.image_hash.as_ref()
    }

    /// Sets the group image URL.
    ///
    /// # Arguments
    ///
    /// * `image` - The new image URL (optional)
    pub fn set_image_hash(&mut self, image_hash: Option<[u8; 32]>) {
        self.image_hash = image_hash;
    }

    /// Returns the group image key.
    pub fn image_key(&self) -> Option<&[u8; 32]> {
        self.image_key.as_ref()
    }

    /// Returns the group image nonce
    pub fn image_nonce(&self) -> Option<&[u8; 12]> {
        self.image_nonce.as_ref()
    }

    /// Sets the group image key.
    ///
    /// # Arguments
    ///
    /// * `image_key` - The new image encryption key (optional)
    pub fn set_image_key(&mut self, image_key: Option<[u8; 32]>) {
        self.image_key = image_key;
    }

    /// Sets the group image nonce.
    ///
    /// # Arguments
    ///
    /// * `image_nonce` - The new image encryption key (optional)
    pub fn set_image_nonce(&mut self, image_nonce: Option<[u8; 12]>) {
        self.image_nonce = image_nonce;
    }

    /// Migrate extension to version 2 format
    ///
    /// Updates the extension version to 2. This should be called after migrating
    /// the group image from v1 to v2 format using `migrate_group_image_v1_to_v2`.
    ///
    /// # Arguments
    ///
    /// * `new_image_hash` - The new image hash (SHA256 of v2 encrypted image)
    /// * `new_image_seed` - The new image seed (32 bytes, stored in image_key field for v2)
    ///   **REQUIRED** when migrating from v1 to v2, as v1 image_key is a direct encryption key,
    ///   not a seed. Optional when updating an already-v2 extension.
    /// * `new_image_nonce` - The new image nonce (12 bytes)
    ///
    /// # Warning
    ///
    /// Migrating from v1 to v2 without providing `new_image_seed` creates a semantic mismatch:
    /// the version will be set to 2 (expecting seed-based derivation), but the existing
    /// `image_key` is in v1 format (direct encryption key). This pattern should only be used
    /// when updating image data for an already-v2 extension.
    ///
    /// # Example
    /// ```ignore
    /// // Migrate image from v1 to v2
    /// let v2_prepared = migrate_group_image_v1_to_v2(
    ///     &encrypted_v1_data,
    ///     &v1_extension.image_key.unwrap(),
    ///     &v1_extension.image_nonce.unwrap(),
    ///     "image/jpeg"
    /// )?;
    ///
    /// // Upload to Blossom
    /// let new_hash = blossom_client.upload(
    ///     &v2_prepared.encrypted_data,
    ///     &v2_prepared.upload_keypair
    /// ).await?;
    ///
    /// // Migrate extension to v2 (MUST provide new seed when migrating from v1)
    /// extension.migrate_to_v2(
    ///     Some(new_hash),
    ///     Some(v2_prepared.image_key), // This is the seed in v2
    ///     Some(v2_prepared.image_nonce)
    /// );
    /// ```
    pub fn migrate_to_v2(
        &mut self,
        new_image_hash: Option<[u8; 32]>,
        new_image_seed: Option<[u8; 32]>,
        new_image_nonce: Option<[u8; 12]>,
        new_image_upload_seed: Option<[u8; 32]>,
    ) {
        // Warn if migrating from v1 without providing new seeds
        if self.version == 1
            && (new_image_seed.is_none() || new_image_upload_seed.is_none())
            && self.image_key.is_some()
        {
            tracing::warn!(
                target: "mdk_core::extension::types",
                "Migrating from v1 to v2 without new image_seed and image_upload_seed - existing image_key will be treated as seed, which may cause issues since v1 image_key is a direct encryption key, not a seed"
            );
        }
        self.version = Self::CURRENT_VERSION; // Set to version 2
        if let Some(hash) = new_image_hash {
            self.image_hash = Some(hash);
        }
        if let Some(seed) = new_image_seed {
            self.image_key = Some(seed);
        }
        if let Some(nonce) = new_image_nonce {
            self.image_nonce = Some(nonce);
        }
        if let Some(upload_seed) = new_image_upload_seed {
            self.image_upload_key = Some(upload_seed);
        }
    }

    /// Get group image encryption data if all required fields are set
    ///
    /// Returns `Some` only when image_hash, image_key, and image_nonce are all present.
    /// For v2 extensions, image_upload_key is also included for cryptographic independence.
    /// This ensures you have all necessary data to download and decrypt the group image.
    ///
    /// # Example
    /// ```ignore
    /// if let Some(info) = extension.group_image_encryption_data() {
    ///     let encrypted_blob = download_from_blossom(&info.image_hash).await?;
    ///     let image = group_image::decrypt_group_image(
    ///         &encrypted_blob,
    ///         Some(&info.image_hash),
    ///         &info.image_key,
    ///         &info.image_nonce
    ///     )?;
    ///     // For v2, use image_upload_key for Blossom authentication
    ///     if let Some(upload_key) = info.image_upload_key {
    ///         let keypair = group_image::derive_upload_keypair(&upload_key, 2)?;
    ///         // Use keypair for Blossom operations
    ///     }
    /// }
    /// ```
    pub fn group_image_encryption_data(
        &self,
    ) -> Option<crate::extension::group_image::GroupImageEncryptionInfo> {
        match (self.image_hash, self.image_key, self.image_nonce) {
            (Some(hash), Some(key), Some(nonce)) => {
                Some(crate::extension::group_image::GroupImageEncryptionInfo {
                    version: self.version,
                    image_hash: hash,
                    image_key: mdk_storage_traits::Secret::new(key),
                    image_nonce: mdk_storage_traits::Secret::new(nonce),
                    image_upload_key: self.image_upload_key.map(mdk_storage_traits::Secret::new),
                })
            }
            _ => None,
        }
    }

    pub(crate) fn as_raw(&self) -> TlsNostrGroupDataExtension {
        TlsNostrGroupDataExtension {
            version: self.version,
            nostr_group_id: self.nostr_group_id,
            name: self.name.as_bytes().to_vec(),
            description: self.description.as_bytes().to_vec(),
            admin_pubkeys: self
                .admins
                .iter()
                .map(|pk| pk.to_hex().into_bytes())
                .collect(),
            relays: self
                .relays
                .iter()
                .map(|url| url.to_string().into_bytes())
                .collect(),
            image_hash: self.image_hash.map_or_else(Vec::new, |hash| hash.to_vec()),
            image_key: self.image_key.map_or_else(Vec::new, |key| key.to_vec()),
            image_nonce: self
                .image_nonce
                .map_or_else(Vec::new, |nonce| nonce.to_vec()),
            image_upload_key: self
                .image_upload_key
                .map_or_else(Vec::new, |key| key.to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes;

    use super::*;

    const ADMIN_1: &str = "npub1a6awmmklxfmspwdv52qq58sk5c07kghwc4v2eaudjx2ju079cdqs2452ys";
    const ADMIN_2: &str = "npub1t5sdrgt7md8a8lf77ka02deta4vj35p3ktfskd5yz68pzmt9334qy6qks0";
    const RELAY_1: &str = "wss://relay1.com";
    const RELAY_2: &str = "wss://relay2.com";

    fn create_test_extension() -> NostrGroupDataExtension {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let pk2 = PublicKey::parse(ADMIN_2).unwrap();

        let relay1 = RelayUrl::parse(RELAY_1).unwrap();
        let relay2 = RelayUrl::parse(RELAY_2).unwrap();

        let image_hash = generate_random_bytes(32).try_into().unwrap();
        let image_key = generate_random_bytes(32).try_into().unwrap();
        let image_nonce = generate_random_bytes(12).try_into().unwrap();

        NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [pk1, pk2],
            [relay1, relay2],
            Some(image_hash),
            Some(image_key),
            Some(image_nonce),
            Some(generate_random_bytes(32).try_into().unwrap()), // image_upload_key for v2
        )
    }

    #[test]
    fn test_new_and_getters() {
        let extension = create_test_extension();

        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let pk2 = PublicKey::parse(ADMIN_2).unwrap();

        let relay1 = RelayUrl::parse(RELAY_1).unwrap();
        let relay2 = RelayUrl::parse(RELAY_2).unwrap();

        // Test that group_id is 32 bytes
        assert_eq!(extension.nostr_group_id.len(), 32);

        // Test basic getters
        assert_eq!(extension.name(), "Test Group");
        assert_eq!(extension.description(), "Test Description");

        assert!(extension.admins.contains(&pk1));
        assert!(extension.admins.contains(&pk2));

        assert!(extension.relays.contains(&relay1));
        assert!(extension.relays.contains(&relay2));
    }

    #[test]
    fn test_group_id_operations() {
        let mut extension = create_test_extension();
        let new_id = [42u8; 32];

        extension.set_nostr_group_id(new_id);
        assert_eq!(extension.nostr_group_id(), hex::encode(new_id));
    }

    #[test]
    fn test_name_operations() {
        let mut extension = create_test_extension();

        extension.set_name("New Name".to_string());
        assert_eq!(extension.name(), "New Name");
    }

    #[test]
    fn test_description_operations() {
        let mut extension = create_test_extension();

        extension.set_description("New Description".to_string());
        assert_eq!(extension.description(), "New Description");
    }

    #[test]
    fn test_admin_pubkey_operations() {
        let mut extension = create_test_extension();

        let admin1 = PublicKey::parse(ADMIN_1).unwrap();
        let admin2 = PublicKey::parse(ADMIN_2).unwrap();
        let admin3 =
            PublicKey::parse("npub13933f9shzt90uccjaf4p4f4arxlfcy3q6037xnx8a2kxaafrn5yqtzehs6")
                .unwrap();

        // Test add
        extension.add_admin(admin3);
        assert_eq!(extension.admins.len(), 3);
        assert!(extension.admins.contains(&admin1));
        assert!(extension.admins.contains(&admin2));
        assert!(extension.admins.contains(&admin3));

        // Test remove
        extension.remove_admin(&admin2);
        assert_eq!(extension.admins.len(), 2);
        assert!(extension.admins.contains(&admin1));
        assert!(!extension.admins.contains(&admin2)); // NOT contains
        assert!(extension.admins.contains(&admin3));
    }

    #[test]
    fn test_relay_operations() {
        let mut extension = create_test_extension();

        let relay1 = RelayUrl::parse(RELAY_1).unwrap();
        let relay2 = RelayUrl::parse(RELAY_2).unwrap();
        let relay3 = RelayUrl::parse("wss://relay3.com").unwrap();

        // Test add
        extension.add_relay(relay3.clone());
        assert_eq!(extension.relays.len(), 3);
        assert!(extension.relays.contains(&relay1));
        assert!(extension.relays.contains(&relay2));
        assert!(extension.relays.contains(&relay3));

        // Test remove
        extension.remove_relay(&relay2);
        assert_eq!(extension.relays.len(), 2);
        assert!(extension.relays.contains(&relay1));
        assert!(!extension.relays.contains(&relay2)); // NOT contains
        assert!(extension.relays.contains(&relay3));
    }

    #[test]
    fn test_image_operations() {
        let mut extension = create_test_extension();

        // Test setting image URL
        let image_hash = Some(generate_random_bytes(32).try_into().unwrap());
        extension.set_image_hash(image_hash);
        assert_eq!(extension.image_hash(), image_hash.as_ref());

        // Test setting image key
        let image_key = generate_random_bytes(32).try_into().unwrap();
        extension.set_image_key(Some(image_key));
        assert!(extension.image_key().is_some());

        // Test setting image nonce
        let image_nonce = generate_random_bytes(12).try_into().unwrap();
        extension.set_image_nonce(Some(image_nonce));
        assert!(extension.image_nonce().is_some());

        // Test clearing image
        extension.set_image_hash(None);
        extension.set_image_key(None);
        extension.set_image_nonce(None);
        assert!(extension.image_hash().is_none());
        assert!(extension.image_key().is_none());
        assert!(extension.image_nonce().is_none());
    }

    #[test]
    fn test_new_fields_in_serialization() {
        let mut extension = create_test_extension();

        // Set some image data
        let image_hash = generate_random_bytes(32).try_into().unwrap();
        let image_key = generate_random_bytes(32).try_into().unwrap();
        let image_nonce = generate_random_bytes(12).try_into().unwrap();

        extension.set_image_hash(Some(image_hash));
        extension.set_image_key(Some(image_key));
        extension.set_image_nonce(Some(image_nonce));

        // Convert to raw and back
        let raw = extension.as_raw();
        let reconstructed = NostrGroupDataExtension::from_raw(raw).unwrap();

        assert_eq!(reconstructed.image_hash(), Some(&image_hash));
        assert_eq!(reconstructed.image_nonce(), Some(&image_nonce));
        assert!(reconstructed.image_key().is_some());
        // We can't directly compare SecretKeys due to how they're implemented,
        // but we can verify the bytes are the same
        assert_eq!(reconstructed.image_key().unwrap(), &image_key);
    }

    #[test]
    fn test_serialization_overhead() {
        use tls_codec::Size;

        // Test with fixed-size vs variable-size fields
        let test_hash = [1u8; 32];
        let test_key = [2u8; 32];
        let test_nonce = [3u8; 12];

        // Create extension with Some values
        let extension_with_data = NostrGroupDataExtension::new(
            "Test",
            "Description",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            Some(test_hash),
            Some(test_key),
            Some(test_nonce),
            Some([4u8; 32]), // image_upload_key
        );

        // Create extension with None values
        let extension_without_data = NostrGroupDataExtension::new(
            "Test",
            "Description",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            None,
            None,
            None,
            None, // image_upload_key
        );

        // Serialize both to measure size
        let with_data_raw = extension_with_data.as_raw();
        let without_data_raw = extension_without_data.as_raw();

        let with_data_size = with_data_raw.tls_serialized_len();
        let without_data_size = without_data_raw.tls_serialized_len();

        println!("With data: {} bytes", with_data_size);
        println!("Without data: {} bytes", without_data_size);
        println!(
            "Overhead difference: {} bytes",
            with_data_size as i32 - without_data_size as i32
        );

        // Test round-trip to ensure correctness
        let roundtrip_with = NostrGroupDataExtension::from_raw(with_data_raw).unwrap();
        let roundtrip_without = NostrGroupDataExtension::from_raw(without_data_raw).unwrap();

        // Verify data preservation
        assert_eq!(roundtrip_with.image_hash, Some(test_hash));
        assert_eq!(roundtrip_with.image_key, Some(test_key));
        assert_eq!(roundtrip_with.image_nonce, Some(test_nonce));

        assert_eq!(roundtrip_without.image_hash, None);
        assert_eq!(roundtrip_without.image_key, None);
        assert_eq!(roundtrip_without.image_nonce, None);
    }

    /// Test that version field is properly serialized at the beginning of the structure (MIP-01)
    #[test]
    fn test_version_field_serialization() {
        use tls_codec::Serialize as TlsSerialize;

        let extension = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            None,
            None,
            None,
            None,
        );

        // Verify version is set to current version
        assert_eq!(
            extension.version,
            NostrGroupDataExtension::CURRENT_VERSION,
            "Version should be set to CURRENT_VERSION (1)"
        );

        // Serialize and verify version field is at the beginning
        let raw = extension.as_raw();
        let serialized = raw.tls_serialize_detached().unwrap();

        // The first 2 bytes should be the version field (u16 in big-endian)
        assert!(
            serialized.len() >= 2,
            "Serialized data should be at least 2 bytes"
        );
        let version_bytes = &serialized[0..2];
        let version_from_bytes = u16::from_be_bytes([version_bytes[0], version_bytes[1]]);

        assert_eq!(
            version_from_bytes,
            NostrGroupDataExtension::CURRENT_VERSION,
            "First 2 bytes of serialized data should contain version field"
        );
    }

    /// Test version validation and forward compatibility (MIP-01)
    #[test]
    fn test_version_validation() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Test version 0 is rejected
        let raw_v0 = TlsNostrGroupDataExtension {
            version: 0,
            nostr_group_id: [0u8; 32],
            name: b"Test".to_vec(),
            description: b"Desc".to_vec(),
            admin_pubkeys: vec![pk1.to_hex().into_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
        };

        let result = NostrGroupDataExtension::from_raw(raw_v0);
        assert!(
            matches!(result, Err(Error::InvalidExtensionVersion(0))),
            "Version 0 should be rejected"
        );

        // Test version 1 is accepted
        let raw_v1 = TlsNostrGroupDataExtension {
            version: 1,
            nostr_group_id: [0u8; 32],
            name: b"Test".to_vec(),
            description: b"Desc".to_vec(),
            admin_pubkeys: vec![pk1.to_hex().into_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
        };

        let result = NostrGroupDataExtension::from_raw(raw_v1);
        assert!(result.is_ok(), "Version 1 should be accepted");
        assert_eq!(result.unwrap().version, 1);

        // Test future version is accepted with warning (forward compatibility)
        let raw_v99 = TlsNostrGroupDataExtension {
            version: 99,
            nostr_group_id: [0u8; 32],
            name: b"Test".to_vec(),
            description: b"Desc".to_vec(),
            admin_pubkeys: vec![pk1.to_hex().into_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
        };

        let result = NostrGroupDataExtension::from_raw(raw_v99);
        assert!(
            result.is_ok(),
            "Future version should be accepted for forward compatibility"
        );
        assert_eq!(
            result.unwrap().version,
            99,
            "Future version number should be preserved"
        );
    }

    /// Test that version field is preserved through serialization round-trip
    #[test]
    fn test_version_field_roundtrip() {
        let extension = create_test_extension();

        // Verify initial version
        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);

        // Serialize and deserialize
        let raw = extension.as_raw();
        let reconstructed = NostrGroupDataExtension::from_raw(raw).unwrap();

        // Verify version is preserved
        assert_eq!(
            reconstructed.version, extension.version,
            "Version should be preserved through serialization round-trip"
        );
    }

    /// Test migration from legacy extension format (without version field) to version 1
    #[test]
    fn test_legacy_extension_migration() {
        use tls_codec::Serialize as TlsSerialize;

        // Create a legacy extension (without version field)
        let admin1 = PublicKey::parse(ADMIN_1).unwrap();
        let legacy_extension = LegacyTlsNostrGroupDataExtension {
            nostr_group_id: [42u8; 32],
            name: "Legacy Group".as_bytes().to_vec(),
            description: "Created before version field was added".as_bytes().to_vec(),
            admin_pubkeys: vec![hex::encode(admin1.to_bytes()).as_bytes().to_vec()],
            relays: vec![RELAY_1.as_bytes().to_vec()],
            image_hash: vec![],
            image_key: vec![],
            image_nonce: vec![],
        };

        // Serialize it as a legacy extension
        let legacy_serialized = legacy_extension.tls_serialize_detached().unwrap();

        // Verify it doesn't start with a version field (first bytes should be part of nostr_group_id)
        assert_eq!(
            legacy_serialized[0], 42,
            "Legacy format should start with nostr_group_id"
        );

        // Now migrate by deserializing
        let (deserialized_legacy, _) =
            LegacyTlsNostrGroupDataExtension::tls_deserialize_bytes(&legacy_serialized).unwrap();
        let migrated_extension =
            NostrGroupDataExtension::from_legacy_raw(deserialized_legacy).unwrap();

        // Verify migration preserved all data and added version
        assert_eq!(
            migrated_extension.version, 1,
            "Migrated extension should have version 1"
        );
        assert_eq!(
            migrated_extension.nostr_group_id, [42u8; 32],
            "Group ID should be preserved"
        );
        assert_eq!(
            migrated_extension.name, "Legacy Group",
            "Name should be preserved"
        );
        assert_eq!(
            migrated_extension.description, "Created before version field was added",
            "Description should be preserved"
        );
        assert_eq!(
            migrated_extension.admins.len(),
            1,
            "Admin count should be preserved"
        );
        assert_eq!(
            migrated_extension.relays.len(),
            1,
            "Relay count should be preserved"
        );

        // Verify that the migrated extension can be serialized with the version field
        let migrated_raw = migrated_extension.as_raw();
        let migrated_serialized = migrated_raw.tls_serialize_detached().unwrap();

        // Should now start with version field
        assert_eq!(
            migrated_serialized[0], 0x00,
            "Migrated format should start with version MSB"
        );
        assert_eq!(
            migrated_serialized[1], 0x01,
            "Migrated format should start with version LSB"
        );
    }

    /// Test that deserialization gracefully handles both legacy and current formats
    #[test]
    fn test_mixed_format_deserialization() {
        use tls_codec::Serialize as TlsSerialize;

        // Create a legacy extension
        let admin1 = PublicKey::parse(ADMIN_1).unwrap();
        let legacy_extension = LegacyTlsNostrGroupDataExtension {
            nostr_group_id: [99u8; 32],
            name: "Mixed Format Test".as_bytes().to_vec(),
            description: "Testing backward compatibility".as_bytes().to_vec(),
            admin_pubkeys: vec![hex::encode(admin1.to_bytes()).as_bytes().to_vec()],
            relays: vec![RELAY_1.as_bytes().to_vec()],
            image_hash: vec![],
            image_key: vec![],
            image_nonce: vec![],
        };
        let legacy_bytes = legacy_extension.tls_serialize_detached().unwrap();

        // Create a current (versioned) extension
        let current_extension = NostrGroupDataExtension::new(
            "Mixed Format Test",
            "Testing backward compatibility",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            None,
            None,
            None,
            None,
        );
        let current_bytes = current_extension.as_raw().tls_serialize_detached().unwrap();

        // Both should be deserializable via the migration-aware methods
        // (We can't test from_group_context directly here without setting up a full MLS group,
        // but we can test the underlying logic)

        // Test legacy deserialization
        let (legacy_deser, _) =
            LegacyTlsNostrGroupDataExtension::tls_deserialize_bytes(&legacy_bytes).unwrap();
        let migrated = NostrGroupDataExtension::from_legacy_raw(legacy_deser).unwrap();
        assert_eq!(migrated.version, 1);
        assert_eq!(migrated.name, "Mixed Format Test");

        // Test current deserialization
        let (current_deser, _) =
            TlsNostrGroupDataExtension::tls_deserialize_bytes(&current_bytes).unwrap();
        let current_parsed = NostrGroupDataExtension::from_raw(current_deser).unwrap();
        assert_eq!(
            current_parsed.version,
            NostrGroupDataExtension::CURRENT_VERSION
        );
        assert_eq!(current_parsed.name, "Mixed Format Test");

        // Verify that trying to deserialize legacy bytes with the current format fails
        // (this is expected and why we need the fallback logic)
        let result = TlsNostrGroupDataExtension::tls_deserialize_bytes(&legacy_bytes);
        assert!(
            result.is_err() || {
                // If it doesn't error, it should have misread the data
                let (deser, _) = result.unwrap();
                deser.version != 1 || deser.nostr_group_id != [99u8; 32]
            },
            "Legacy format should not deserialize correctly with current format"
        );
    }

    /// Test migration to version 2
    #[test]
    fn test_migrate_to_v2() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Create a version 1 extension with image data
        let mut extension = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [pk1],
            [relay1.clone()],
            Some([1u8; 32]),
            Some([2u8; 32]),
            Some([3u8; 12]),
            None, // v1 doesn't use image_upload_key
        );

        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);

        // Manually set to version 1 for testing
        extension.version = 1;
        assert_eq!(extension.version, 1);

        // Migrate to v2 with new image data
        let new_hash = [10u8; 32];
        let new_seed = [20u8; 32];
        let new_nonce = [30u8; 12];
        let new_upload_seed = [40u8; 32];

        extension.migrate_to_v2(
            Some(new_hash),
            Some(new_seed),
            Some(new_nonce),
            Some(new_upload_seed),
        );

        // Verify version is now 2
        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);
        assert_eq!(extension.image_hash, Some(new_hash));
        assert_eq!(extension.image_key, Some(new_seed));
        assert_eq!(extension.image_nonce, Some(new_nonce));

        // Test partial migration (only updating some fields)
        let mut extension2 = NostrGroupDataExtension::new(
            "Test Group 2",
            "Test Description 2",
            [pk1],
            [relay1],
            Some([1u8; 32]),
            Some([2u8; 32]),
            Some([3u8; 12]),
            None,
        );
        extension2.version = 1;

        extension2.migrate_to_v2(Some(new_hash), None, None, None);

        // Version should be updated, but only hash should change
        assert_eq!(extension2.version, NostrGroupDataExtension::CURRENT_VERSION);
        assert_eq!(extension2.image_hash, Some(new_hash));
        assert_eq!(extension2.image_key, Some([2u8; 32])); // Unchanged
        assert_eq!(extension2.image_nonce, Some([3u8; 12])); // Unchanged
    }

    /// Test that migrating an already-v2 extension updates fields correctly
    #[test]
    fn test_migrate_to_v2_already_v2() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Create v2 extension
        let mut extension = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [pk1],
            [relay1.clone()],
            Some([1u8; 32]),
            Some([2u8; 32]),
            Some([3u8; 12]),
            Some([4u8; 32]), // image_upload_key for v2
        );

        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);

        // Migrate to v2 again (should still work, just update fields)
        let new_hash = [10u8; 32];
        let new_seed = [20u8; 32];
        let new_nonce = [30u8; 12];
        let new_upload_seed = [40u8; 32];

        extension.migrate_to_v2(
            Some(new_hash),
            Some(new_seed),
            Some(new_nonce),
            Some(new_upload_seed),
        );

        // Version should remain 2, fields should be updated
        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);
        assert_eq!(extension.image_hash, Some(new_hash));
        assert_eq!(extension.image_key, Some(new_seed));
        assert_eq!(extension.image_nonce, Some(new_nonce));
    }

    /// Test migration with all None values (just version bump)
    #[test]
    fn test_migrate_to_v2_all_none() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        let mut extension = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [pk1],
            [relay1],
            Some([1u8; 32]),
            Some([2u8; 32]),
            Some([3u8; 12]),
            None,
        );
        extension.version = 1;

        // Migrate with all None (just version bump)
        extension.migrate_to_v2(None, None, None, None);

        // Version should be updated, but fields unchanged
        assert_eq!(extension.version, NostrGroupDataExtension::CURRENT_VERSION);
        assert_eq!(extension.image_hash, Some([1u8; 32]));
        assert_eq!(extension.image_key, Some([2u8; 32]));
        assert_eq!(extension.image_nonce, Some([3u8; 12]));
    }
}
