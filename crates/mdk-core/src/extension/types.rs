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
    DeserializeBytes, Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes,
    TlsSerialize, TlsSerializeBytes, TlsSize,
};

use crate::constant::NOSTR_GROUP_DATA_EXTENSION_TYPE;
use crate::error::Error;

/// TLS-serializable representation of Nostr Group Data Extension (v3+).
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
    pub admin_pubkeys: Vec<[u8; 32]>,
    pub relays: Vec<Vec<u8>>,
    pub image_hash: Vec<u8>,       // Use Vec<u8> to allow empty for None
    pub image_key: Vec<u8>,        // Use Vec<u8> to allow empty for None
    pub image_nonce: Vec<u8>,      // Use Vec<u8> to allow empty for None
    pub image_upload_key: Vec<u8>, // Use Vec<u8> to allow empty for None (v2 only)
    pub disappearing_message_secs: Vec<u8>, // Use Vec<u8>: empty for None, 8 bytes for Some(u64) (v3 only)
}

/// TLS-serializable representation for v1/v2 payloads (before disappearing messages).
///
/// Legacy groups serialized without the `disappearing_message_secs` field
/// use this struct for deserialization. The missing field is synthesized as an empty
/// Vec (mapping to `None`) when converting to `TlsNostrGroupDataExtension`.
#[derive(
    Clone,
    PartialEq,
    Eq,
    TlsSerialize,
    TlsDeserialize,
    TlsSerializeBytes,
    TlsDeserializeBytes,
    TlsSize,
)]
struct TlsNostrGroupDataExtensionV1V2 {
    pub version: u16,
    pub nostr_group_id: [u8; 32],
    pub name: Vec<u8>,
    pub description: Vec<u8>,
    pub admin_pubkeys: Vec<[u8; 32]>,
    pub relays: Vec<Vec<u8>>,
    pub image_hash: Vec<u8>,
    pub image_key: Vec<u8>,
    pub image_nonce: Vec<u8>,
    pub image_upload_key: Vec<u8>,
}

impl TlsNostrGroupDataExtensionV1V2 {
    /// Promote to the v3 struct with the missing field defaulted to empty.
    fn into_v3(self) -> TlsNostrGroupDataExtension {
        TlsNostrGroupDataExtension {
            version: self.version,
            nostr_group_id: self.nostr_group_id,
            name: self.name,
            description: self.description,
            admin_pubkeys: self.admin_pubkeys,
            relays: self.relays,
            image_hash: self.image_hash,
            image_key: self.image_key,
            image_nonce: self.image_nonce,
            image_upload_key: self.image_upload_key,
            disappearing_message_secs: Vec::new(),
        }
    }
}

/// This is an MLS Group Context extension used to store the group's name,
/// description, ID, admin identities, image URL, and image encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrGroupDataExtension {
    /// Extension format version (current: 3)
    /// Version 3: Adds disappearing_message_secs field
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
    /// Disappearing message duration in seconds (v3 only)
    ///
    /// - `None`: Messages persist forever (disabled)
    /// - `Some(n)`: Messages expire `n` seconds after creation (`n > 0`)
    pub disappearing_message_secs: Option<u64>,
}

impl NostrGroupDataExtension {
    /// Nostr Group Data extension type
    pub const EXTENSION_TYPE: u16 = NOSTR_GROUP_DATA_EXTENSION_TYPE;

    /// Current extension format version (MIP-01)
    /// Version 3: Adds disappearing_message_secs field
    /// Version 2: Uses image_seed (stored in image_key field) with HKDF derivation
    /// Version 1: Uses image_key directly as encryption key (deprecated)
    pub const CURRENT_VERSION: u16 = 3;

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
        disappearing_message_secs: Option<u64>,
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

        // Normalize Some(0) to None — zero means "no expiration" and from_raw()
        // rejects it on the read path, so the write path must not produce it.
        let disappearing_message_secs = disappearing_message_secs.filter(|&d| d != 0);

        // Version tracks protocol capabilities: v3 when disappearing messages
        // are active, v2 otherwise. The wire format in to_tls_bytes() uses this
        // to decide whether to emit the v3 struct (with the extra field) or the
        // v1/v2 struct (backward-compatible with older clients).
        let version = if disappearing_message_secs.is_some() {
            Self::CURRENT_VERSION
        } else {
            2
        };

        Self {
            version,
            nostr_group_id: random_bytes,
            name: name.into(),
            description: description.into(),
            admins: admins.into_iter().collect(),
            relays: relays.into_iter().collect(),
            image_hash,
            image_key,
            image_nonce,
            image_upload_key,
            disappearing_message_secs,
        }
    }

    /// Deserialize extension bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw TLS-serialized bytes of the extension
    ///
    /// # Returns
    ///
    /// * `Ok(NostrGroupDataExtension)` - Successfully deserialized extension
    /// * `Err(Error)` - Failed to deserialize
    fn deserialize_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Dispatch on the version field (first 2 bytes, big-endian u16) so that
        // a corrupt v3 payload can never silently fall through to the v1/v2 parser.
        if bytes.len() < 2 {
            return Err(Error::ExtensionFormatError(
                "Extension payload too short to contain a version".to_string(),
            ));
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);

        let raw = if version >= 3 {
            let (deserialized, remainder) =
                TlsNostrGroupDataExtension::tls_deserialize_bytes(bytes)?;
            if !remainder.is_empty() {
                return Err(Error::ExtensionFormatError(
                    "Trailing bytes in NostrGroupDataExtension".to_string(),
                ));
            }
            deserialized
        } else {
            let (v1v2, remainder) = TlsNostrGroupDataExtensionV1V2::tls_deserialize_bytes(bytes)?;
            if !remainder.is_empty() {
                return Err(Error::ExtensionFormatError(
                    "Trailing bytes in NostrGroupDataExtension".to_string(),
                ));
            }
            v1v2.into_v3()
        };
        Self::from_raw(raw)
    }

    pub(crate) fn from_raw(raw: TlsNostrGroupDataExtension) -> Result<Self, Error> {
        // Validate version - we support versions 1, 2, and 3
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
            let pk = PublicKey::from_byte_array(admin);
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

        // Backward compatibility: v1/v2 groups don't have this field, so empty Vec maps to None
        let disappearing_message_secs = if raw.disappearing_message_secs.is_empty() {
            None
        } else {
            let bytes: [u8; 8] = raw.disappearing_message_secs.try_into().map_err(|_| {
                Error::ExtensionFormatError(
                    "Invalid disappearing_message_secs length (expected 8 bytes)".to_string(),
                )
            })?;
            let duration = u64::from_be_bytes(bytes);
            if duration == 0 {
                return Err(Error::ExtensionFormatError(
                    "disappearing_message_secs cannot be zero".to_string(),
                ));
            }
            Some(duration)
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
            disappearing_message_secs,
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
    pub fn from_group_context(group_context: &GroupContext) -> Result<Self, Error> {
        let group_data_extension = match group_context.extensions().iter().find(|ext| {
            ext.extension_type() == ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE)
        }) {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(Error::UnexpectedExtensionType),
            None => return Err(Error::NostrGroupDataExtensionNotFound),
        };

        Self::deserialize_bytes(&group_data_extension.0)
    }

    /// Attempts to extract and deserialize a NostrGroupDataExtension from an MlsGroup.
    ///
    /// # Arguments
    ///
    /// * `group` - Reference to the MlsGroup containing the extension
    ///
    /// # Returns
    ///
    /// * `Ok(NostrGroupDataExtension)` - Successfully extracted and deserialized extension
    /// * `Err(Error)` - Failed to find or deserialize the extension
    pub fn from_group(group: &MlsGroup) -> Result<Self, Error> {
        let group_data_extension = match group.extensions().iter().find(|ext| {
            ext.extension_type() == ExtensionType::Unknown(NOSTR_GROUP_DATA_EXTENSION_TYPE)
        }) {
            Some(Extension::Unknown(_, ext)) => ext,
            Some(_) => return Err(Error::UnexpectedExtensionType),
            None => return Err(Error::NostrGroupDataExtensionNotFound),
        };

        Self::deserialize_bytes(&group_data_extension.0)
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

    mdk_macros::mut_setters! {
        /// Sets the group ID using a 32-byte array.
        set_nostr_group_id<direct> -> nostr_group_id: [u8; 32];
        /// Sets the group name.
        set_name<direct> -> name: String;
        /// Sets the group description.
        set_description<direct> -> description: String;
        /// Sets the group image hash.
        set_image_hash<direct> -> image_hash: Option<[u8; 32]>;
        /// Sets the group image key.
        set_image_key<direct> -> image_key: Option<[u8; 32]>;
        /// Sets the group image nonce.
        set_image_nonce<direct> -> image_nonce: Option<[u8; 12]>;
    }

    /// Returns the group name as a UTF-8 string.
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the group description as a UTF-8 string.
    pub fn description(&self) -> &str {
        self.description.as_str()
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

    mdk_macros::ref_getters! {
        /// Returns the group image hash.
        image_hash: [u8; 32];
        /// Returns the group image key.
        image_key: [u8; 32];
        /// Returns the group image nonce.
        image_nonce: [u8; 12];
    }

    /// Migrate extension image semantics from v1 to v2.
    ///
    /// In v1 the `image_key` field holds the encryption key directly.
    /// In v2+ it holds a seed used for HKDF derivation, and `image_upload_key`
    /// holds an independent upload seed.
    ///
    /// This method updates the image fields and bumps the version to 2.
    /// A separate v2→v3 migration is not needed: the wire format automatically
    /// upgrades to v3 when `disappearing_message_secs` is set (see
    /// [`to_tls_bytes`]).
    ///
    /// # Arguments
    ///
    /// * `new_image_hash` - The new image hash (SHA256 of v2 encrypted image)
    /// * `new_image_seed` - The new image seed (32 bytes, stored in image_key field for v2+)
    /// * `new_image_nonce` - The new image nonce (12 bytes)
    /// * `new_image_upload_seed` - The new upload seed (32 bytes)
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
    /// // Migrate extension from v1 to v2
    /// extension.migrate_v1_to_v2(
    ///     new_hash,
    ///     v2_prepared.image_key,
    ///     v2_prepared.image_nonce,
    ///     v2_prepared.upload_seed,
    /// );
    /// ```
    pub fn migrate_v1_to_v2(
        &mut self,
        new_image_hash: [u8; 32],
        new_image_seed: [u8; 32],
        new_image_nonce: [u8; 12],
        new_image_upload_seed: [u8; 32],
    ) {
        self.version = 2;
        self.image_hash = Some(new_image_hash);
        self.image_key = Some(new_image_seed);
        self.image_nonce = Some(new_image_nonce);
        self.image_upload_key = Some(new_image_upload_seed);
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
            admin_pubkeys: self.admins.iter().map(|pk| *pk.as_bytes()).collect(),
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
            // Zero normalization is enforced by new() and from_raw(); no re-check here.
            disappearing_message_secs: self
                .disappearing_message_secs
                .map_or_else(Vec::new, |d| d.to_be_bytes().to_vec()),
        }
    }

    /// Serialize the extension to TLS wire bytes with version gating.
    ///
    /// When `disappearing_message_secs` is active the v3 wire format is used
    /// (includes the extra field). Otherwise the v1/v2 struct is emitted so
    /// that older clients can still parse the extension.
    pub(crate) fn to_tls_bytes(&self) -> Result<Vec<u8>, tls_codec::Error> {
        if self.disappearing_message_secs.is_some() {
            // v3 wire format — includes disappearing_message_secs
            let mut raw = self.as_raw();
            raw.version = 3;
            raw.tls_serialize_detached()
        } else {
            // v1/v2 wire format — omits disappearing_message_secs for backward compat
            let raw = TlsNostrGroupDataExtensionV1V2 {
                version: self.version.min(2),
                nostr_group_id: self.nostr_group_id,
                name: self.name.as_bytes().to_vec(),
                description: self.description.as_bytes().to_vec(),
                admin_pubkeys: self.admins.iter().map(|pk| *pk.as_bytes()).collect(),
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
            };
            raw.tls_serialize_detached()
        }
    }
}

#[cfg(test)]
mod tests {
    use mdk_storage_traits::test_utils::crypto_utils::generate_random_bytes;
    use tls_codec::Serialize as TlsSerialize;

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
            None,                                                // disappearing_message_secs
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
            None,            // disappearing_message_secs
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
            None, // disappearing_message_secs
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
        // Without disappearing messages → version 2
        let ext_v2 = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(ext_v2.version, 2);

        let bytes_v2 = ext_v2.to_tls_bytes().unwrap();
        assert!(bytes_v2.len() >= 2);
        let wire_version_v2 = u16::from_be_bytes([bytes_v2[0], bytes_v2[1]]);
        assert_eq!(
            wire_version_v2, 2,
            "Wire version should be 2 when no disappearing messages"
        );

        // With disappearing messages → version 3
        let ext_v3 = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [PublicKey::parse(ADMIN_1).unwrap()],
            [RelayUrl::parse(RELAY_1).unwrap()],
            None,
            None,
            None,
            None,
            Some(3600),
        );
        assert_eq!(ext_v3.version, NostrGroupDataExtension::CURRENT_VERSION);

        let bytes_v3 = ext_v3.to_tls_bytes().unwrap();
        let wire_version_v3 = u16::from_be_bytes([bytes_v3[0], bytes_v3[1]]);
        assert_eq!(
            wire_version_v3, 3,
            "Wire version should be 3 when disappearing messages set"
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
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
            disappearing_message_secs: Vec::new(),
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
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
            disappearing_message_secs: Vec::new(),
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
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
            disappearing_message_secs: Vec::new(),
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

    /// Test that version field is preserved through as_raw/from_raw round-trip
    #[test]
    fn test_version_field_roundtrip() {
        let extension = create_test_extension();

        // create_test_extension() has no disappearing messages → version 2
        assert_eq!(extension.version, 2);

        // as_raw/from_raw preserves version
        let raw = extension.as_raw();
        let reconstructed = NostrGroupDataExtension::from_raw(raw).unwrap();
        assert_eq!(
            reconstructed.version, extension.version,
            "Version should be preserved through as_raw/from_raw round-trip"
        );
    }

    /// Test that deserialize_bytes correctly deserializes TLS-encoded extension data
    #[test]
    fn test_deserialize_bytes() {
        let extension = create_test_extension();

        // Serialize using to_tls_bytes (version-gated wire format)
        let serialized_bytes = extension.to_tls_bytes().unwrap();

        // Deserialize using deserialize_bytes
        let deserialized = NostrGroupDataExtension::deserialize_bytes(&serialized_bytes).unwrap();

        // Verify all fields are preserved
        assert_eq!(deserialized.version, extension.version);
        assert_eq!(deserialized.nostr_group_id, extension.nostr_group_id);
        assert_eq!(deserialized.name, extension.name);
        assert_eq!(deserialized.description, extension.description);
        assert_eq!(deserialized.admins, extension.admins);
        assert_eq!(deserialized.relays, extension.relays);
        assert_eq!(deserialized.image_hash, extension.image_hash);
        assert_eq!(deserialized.image_key, extension.image_key);
        assert_eq!(deserialized.image_nonce, extension.image_nonce);
        assert_eq!(deserialized.image_upload_key, extension.image_upload_key);
        assert_eq!(
            deserialized.disappearing_message_secs,
            extension.disappearing_message_secs
        );
    }

    /// Test that deserialize_bytes returns an error for invalid data
    #[test]
    fn test_deserialize_bytes_invalid_data() {
        // Empty bytes should fail
        let result = NostrGroupDataExtension::deserialize_bytes(&[]);
        assert!(result.is_err(), "Empty bytes should fail to deserialize");

        // Random garbage should fail
        let result = NostrGroupDataExtension::deserialize_bytes(&[0x00, 0x01, 0x02, 0x03]);
        assert!(result.is_err(), "Invalid bytes should fail to deserialize");

        // Truncated data should fail
        let result = NostrGroupDataExtension::deserialize_bytes(&[0x00, 0x02]); // Just version field
        assert!(result.is_err(), "Truncated data should fail to deserialize");
    }

    /// Test that deserialize_bytes rejects data with trailing bytes
    #[test]
    fn test_deserialize_bytes_rejects_trailing_bytes() {
        let extension = create_test_extension();

        // Serialize using to_tls_bytes (version-gated wire format)
        let mut serialized_bytes = extension.to_tls_bytes().unwrap();

        // Append trailing garbage bytes
        serialized_bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        // Deserialize should fail due to trailing bytes
        let result = NostrGroupDataExtension::deserialize_bytes(&serialized_bytes);
        assert!(result.is_err(), "Should reject data with trailing bytes");

        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("Trailing bytes"),
            "Error should mention trailing bytes, got: {}",
            error
        );
    }

    /// Test v1→v2 image semantic migration
    #[test]
    fn test_migrate_v1_to_v2() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Create a v1 extension with image data
        let mut extension = NostrGroupDataExtension::new(
            "Test Group",
            "Test Description",
            [pk1],
            [relay1],
            Some([1u8; 32]),
            Some([2u8; 32]),
            Some([3u8; 12]),
            None, // v1 doesn't use image_upload_key
            None,
        );
        extension.version = 1;
        assert_eq!(extension.version, 1);

        // Migrate to v2 with new image data
        let new_hash = [10u8; 32];
        let new_seed = [20u8; 32];
        let new_nonce = [30u8; 12];
        let new_upload_seed = [40u8; 32];

        extension.migrate_v1_to_v2(new_hash, new_seed, new_nonce, new_upload_seed);

        // Version should be 2, all image fields updated
        assert_eq!(extension.version, 2);
        assert_eq!(extension.image_hash, Some(new_hash));
        assert_eq!(extension.image_key, Some(new_seed));
        assert_eq!(extension.image_nonce, Some(new_nonce));
        assert_eq!(extension.image_upload_key, Some(new_upload_seed));
    }

    /// Test that to_tls_bytes gates the version: v2 wire format when no
    /// disappearing messages, v3 when disappearing messages are set.
    #[test]
    fn test_to_tls_bytes_version_gating() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Without disappearing messages → v2 wire format
        let ext_no_dm = NostrGroupDataExtension::new(
            "Test",
            "Desc",
            [pk1],
            [relay1.clone()],
            None,
            None,
            None,
            None,
            None,
        );
        let bytes = ext_no_dm.to_tls_bytes().unwrap();
        let wire_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(wire_version, 2, "No disappearing messages → v2 wire format");

        // Round-trip should work through v1v2 parser
        let rt = NostrGroupDataExtension::deserialize_bytes(&bytes).unwrap();
        assert_eq!(rt.version, 2);
        assert_eq!(rt.disappearing_message_secs, None);

        // With disappearing messages → v3 wire format
        let ext_dm = NostrGroupDataExtension::new(
            "Test",
            "Desc",
            [pk1],
            [relay1],
            None,
            None,
            None,
            None,
            Some(3600),
        );
        let bytes = ext_dm.to_tls_bytes().unwrap();
        let wire_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(
            wire_version, 3,
            "Disappearing messages set → v3 wire format"
        );

        // Round-trip should work through v3 parser
        let rt = NostrGroupDataExtension::deserialize_bytes(&bytes).unwrap();
        assert_eq!(rt.version, 3);
        assert_eq!(rt.disappearing_message_secs, Some(3600));
    }

    /// Test that a v1 group without disappearing messages preserves v1 on the wire
    #[test]
    fn test_to_tls_bytes_preserves_v1_for_legacy_groups() {
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
            None,
        );
        extension.version = 1;

        let bytes = extension.to_tls_bytes().unwrap();
        let wire_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(
            wire_version, 1,
            "v1 group without disappearing messages should stay v1 on wire"
        );

        let rt = NostrGroupDataExtension::deserialize_bytes(&bytes).unwrap();
        assert_eq!(rt.version, 1);
        assert_eq!(rt.image_hash, Some([1u8; 32]));
    }

    /// Test that legacy v1/v2 TLS payloads (without disappearing_message_secs)
    /// deserialize successfully with the field defaulting to None.
    #[test]
    fn test_deserialize_legacy_v1v2_payload_without_disappearing_field() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Serialize a v1/v2 payload directly — no disappearing_message_secs field.
        let v2_raw = TlsNostrGroupDataExtensionV1V2 {
            version: 2,
            nostr_group_id: [42u8; 32],
            name: b"Legacy Group".to_vec(),
            description: b"A v2 group".to_vec(),
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
        };

        let v2_bytes = v2_raw.tls_serialize_detached().unwrap();

        // Now deserialize — this should succeed via the v1/v2 fallback path.
        let extension = NostrGroupDataExtension::deserialize_bytes(&v2_bytes).unwrap();

        assert_eq!(extension.version, 2);
        assert_eq!(extension.name, "Legacy Group");
        assert_eq!(extension.description, "A v2 group");
        assert!(extension.admins.contains(&pk1));
        assert!(extension.relays.contains(&relay1));
        assert_eq!(
            extension.disappearing_message_secs, None,
            "Legacy v2 payload should default to None"
        );
    }

    /// Test that v3 payloads with disappearing_message_secs round-trip correctly.
    #[test]
    fn test_deserialize_v3_payload_with_disappearing_duration() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        let extension = NostrGroupDataExtension::new(
            "v3 Group",
            "Has disappearing messages",
            [pk1],
            [relay1],
            None,
            None,
            None,
            None,
            Some(3600),
        );

        let bytes = extension.to_tls_bytes().unwrap();

        let deserialized = NostrGroupDataExtension::deserialize_bytes(&bytes).unwrap();
        assert_eq!(
            deserialized.version,
            NostrGroupDataExtension::CURRENT_VERSION
        );
        assert_eq!(deserialized.disappearing_message_secs, Some(3600));
    }

    /// Test that a zero-valued disappearing_message_secs is rejected during parsing.
    #[test]
    fn test_from_raw_rejects_zero_disappearing_duration() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        let raw = TlsNostrGroupDataExtension {
            version: 3,
            nostr_group_id: [0u8; 32],
            name: b"Test".to_vec(),
            description: b"Desc".to_vec(),
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
            disappearing_message_secs: 0u64.to_be_bytes().to_vec(),
        };

        let result = NostrGroupDataExtension::from_raw(raw);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("cannot be zero"),
            "Expected zero-duration rejection, got: {err}"
        );
    }

    /// Test that a v3 header with a v1/v2 body (missing the disappearing_message_secs
    /// field) is rejected rather than silently falling back to the v1/v2 parser.
    #[test]
    fn test_deserialize_rejects_v3_header_with_v1v2_body() {
        let pk1 = PublicKey::parse(ADMIN_1).unwrap();
        let relay1 = RelayUrl::parse(RELAY_1).unwrap();

        // Serialize a v1/v2 payload (no disappearing_message_secs field)
        // but with version = 3 — this is corrupt.
        let corrupt = TlsNostrGroupDataExtensionV1V2 {
            version: 3,
            nostr_group_id: [42u8; 32],
            name: b"Corrupt Group".to_vec(),
            description: b"v3 header but v1v2 body".to_vec(),
            admin_pubkeys: vec![*pk1.as_bytes()],
            relays: vec![relay1.to_string().into_bytes()],
            image_hash: Vec::new(),
            image_key: Vec::new(),
            image_nonce: Vec::new(),
            image_upload_key: Vec::new(),
        };

        let bytes = corrupt.tls_serialize_detached().unwrap();

        // With version-based dispatch, this should be routed to the v3 parser
        // which will fail because the payload is too short (missing field).
        let result = NostrGroupDataExtension::deserialize_bytes(&bytes);
        assert!(
            result.is_err(),
            "Corrupt v3-header + v1v2-body should fail, not silently parse"
        );
    }
}
