//! Main encrypted media manager
//!
//! This module contains the EncryptedMediaManager struct which provides the
//! high-level API for encrypting, decrypting, and managing encrypted media
//! within MLS groups on Nostr.

use nostr::{Tag as NostrTag, TagKind, Timestamp};
use sha2::{Digest, Sha256};

use crate::encrypted_media::crypto::{
    DEFAULT_SCHEME_VERSION, decrypt_data_with_aad, derive_encryption_key,
    derive_encryption_key_with_secret, derive_legacy_encryption_key_with_secret,
    encrypt_data_with_aad, generate_encryption_nonce, is_scheme_version_supported,
};
use crate::encrypted_media::metadata::extract_and_process_metadata;
use crate::encrypted_media::types::{
    EncryptedMediaError, EncryptedMediaUpload, MediaProcessingOptions, MediaReference,
};
use crate::media_processing::validation;
use crate::{GroupId, MDK};
use mdk_storage_traits::groups::error::GroupError;
use mdk_storage_traits::groups::types::GroupExporterSecret;
use mdk_storage_traits::{MdkStorageProvider, Secret};

/// Legacy MIP-04 key-derivation compatibility is accepted only until May 15, 2026
/// 00:00:00 UTC. This keeps the `0.6.x -> 0.7.x` media migration path available
/// temporarily without leaving the legacy fallback open-ended.
const LEGACY_MEDIA_MIGRATION_DEADLINE: u64 = 1_778_803_200;

/// Manager for encrypted media operations
pub struct EncryptedMediaManager<'a, Storage>
where
    Storage: MdkStorageProvider,
{
    mdk: &'a MDK<Storage>,
    group_id: GroupId,
}

impl<'a, Storage> EncryptedMediaManager<'a, Storage>
where
    Storage: MdkStorageProvider,
{
    fn allow_legacy_media_fallback_at(current_time: u64) -> bool {
        current_time <= LEGACY_MEDIA_MIGRATION_DEADLINE
    }

    /// Try to decrypt with a single exporter secret, falling back to the legacy
    /// key-derivation path when `allow_legacy` is true and the primary attempt fails.
    fn try_decrypt_with_secret_compat(
        encrypted_data: &[u8],
        reference: &MediaReference,
        secret: &GroupExporterSecret,
        allow_legacy: bool,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let key = derive_encryption_key_with_secret(
            &secret.secret,
            &reference.scheme_version,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;

        match Self::decrypt_and_verify(encrypted_data, &key, reference) {
            Ok(data) => return Ok(data),
            Err(EncryptedMediaError::DecryptionFailed { .. }) if allow_legacy => {
                tracing::trace!(
                    target: "mdk_core::encrypted_media::manager",
                    "Current key derivation failed, attempting legacy key derivation fallback",
                );
            }
            Err(e) => return Err(e),
        }

        let legacy_key = derive_legacy_encryption_key_with_secret(
            &secret.secret,
            &reference.scheme_version,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;
        Self::decrypt_and_verify(encrypted_data, &legacy_key, reference)
    }

    fn try_decrypt_with_current_epoch_compat(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
        allow_legacy: bool,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let mip04_secret = self
            .mdk
            .mip04_exporter_secret(&self.group_id)
            .map_err(|_| EncryptedMediaError::GroupNotFound)?;

        match Self::try_decrypt_with_secret_compat(
            encrypted_data,
            reference,
            &mip04_secret,
            allow_legacy,
        ) {
            Ok(data) => return Ok(data),
            Err(EncryptedMediaError::DecryptionFailed { .. }) if allow_legacy => {}
            Err(e) => return Err(e),
        }

        let legacy_secret = self
            .mdk
            .legacy_exporter_secret(&self.group_id)
            .map_err(|_| EncryptedMediaError::GroupNotFound)?;
        Self::try_decrypt_with_secret_compat(
            encrypted_data,
            reference,
            &legacy_secret,
            allow_legacy,
        )
    }

    /// Create a new encrypted media manager for a specific group
    pub fn new(mdk: &'a MDK<Storage>, group_id: GroupId) -> Self {
        Self { mdk, group_id }
    }

    /// Encrypt media for upload with default options
    ///
    /// # Parameters
    /// - `data`: The raw media file data
    /// - `mime_type`: MIME type of the media (e.g., "image/jpeg")
    /// - `filename`: Original filename (required for AAD in encryption)
    pub fn encrypt_for_upload(
        &self,
        data: &[u8],
        mime_type: &str,
        filename: &str,
    ) -> Result<EncryptedMediaUpload, EncryptedMediaError> {
        self.encrypt_for_upload_with_options(
            data,
            mime_type,
            filename,
            &MediaProcessingOptions::default(),
        )
    }

    /// Encrypt media for upload with custom options
    ///
    /// # Parameters
    /// - `data`: The raw media file data
    /// - `mime_type`: MIME type of the media (e.g., "image/jpeg")
    /// - `filename`: Original filename (required for AAD in encryption)
    /// - `options`: Custom processing options for metadata handling
    pub fn encrypt_for_upload_with_options(
        &self,
        data: &[u8],
        mime_type: &str,
        filename: &str,
        options: &MediaProcessingOptions,
    ) -> Result<EncryptedMediaUpload, EncryptedMediaError> {
        validation::validate_file_size(data, options)?;
        // Validate MIME type: canonicalize, check allowlist, and validate against file bytes (for images)
        // This prevents spoofing and ensures only supported types are encrypted
        let canonical_mime_type = validation::validate_mime_type(mime_type)?;
        // For image types, validate against file bytes to prevent spoofing
        if canonical_mime_type.starts_with("image/") {
            validation::validate_mime_type_matches_data(data, &canonical_mime_type)?;
        }
        validation::validate_filename(filename)?;

        // Extract metadata and optionally sanitize the file
        // If sanitize_exif is true, processed_data will have EXIF stripped
        // If sanitize_exif is false, processed_data will be the original with EXIF intact
        let (processed_data, metadata) =
            extract_and_process_metadata(data, &canonical_mime_type, options)?;

        // Calculate hash of the PROCESSED (potentially sanitized) data
        // This ensures the hash is of the clean file, not the original with EXIF
        let original_hash: [u8; 32] = Sha256::digest(&processed_data).into();
        let scheme_version = DEFAULT_SCHEME_VERSION;
        let encryption_key = derive_encryption_key(
            self.mdk,
            &self.group_id,
            scheme_version,
            &original_hash,
            &metadata.mime_type,
            filename,
        )?;
        let nonce = generate_encryption_nonce();

        // Encrypt the PROCESSED data (which may have EXIF stripped)
        let encrypted_data = encrypt_data_with_aad(
            &processed_data,
            &encryption_key,
            &nonce,
            scheme_version,
            &original_hash,
            &metadata.mime_type,
            filename,
        )?;
        let encrypted_hash = Sha256::digest(&encrypted_data).into();
        let encrypted_size = encrypted_data.len() as u64;

        Ok(EncryptedMediaUpload {
            encrypted_data,
            original_hash,
            encrypted_hash,
            mime_type: metadata.mime_type,
            filename: filename.to_string(),
            original_size: processed_data.len() as u64,
            encrypted_size,
            dimensions: metadata.dimensions,
            blurhash: metadata.blurhash,
            thumbhash: metadata.thumbhash,
            nonce: *nonce,
        })
    }

    /// Decrypt downloaded media
    ///
    /// The filename for AAD is taken from the MediaReference, which was parsed from the imeta tag.
    /// The scheme_version from MediaReference is used to select the correct encryption scheme.
    ///
    /// Looks up the encryption epoch from the stored message's IMETA tag (via the
    /// `x <hash>` field), then decrypts with that epoch's exporter secret. This is
    /// O(1) regardless of how many epoch advancements have occurred.
    ///
    /// The legacy key-derivation fallback (pre-0.7.1 HKDF extract+expand path) is
    /// permitted only until May 15, 2026 00:00:00 UTC.
    pub fn decrypt_from_download(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        self.decrypt_from_download_at(encrypted_data, reference, Timestamp::now().as_secs())
    }

    /// Like [`Self::decrypt_from_download`] but accepts an explicit `current_time` (Unix
    /// seconds) for deterministic testing of the migration deadline.
    pub(crate) fn decrypt_from_download_at(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
        current_time: u64,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let allow_legacy = Self::allow_legacy_media_fallback_at(current_time);

        match self.try_decrypt_with_epoch_hint(encrypted_data, reference, allow_legacy) {
            Ok(data) => Ok(data),
            Err(EncryptedMediaError::NoExporterSecretForEpoch(_))
            | Err(EncryptedMediaError::DecryptionFailed { .. }) => {
                tracing::debug!(
                    target: "mdk_core::encrypted_media::manager",
                    "Epoch hint unavailable or failed, falling back to current epoch key",
                );
                self.try_decrypt_with_current_epoch_compat(encrypted_data, reference, allow_legacy)
            }
            Err(e) => Err(e),
        }
    }

    /// Decrypt and verify media data using a pre-derived encryption key
    ///
    /// Performs ChaCha20-Poly1305 decryption with AAD, then verifies the SHA256 hash
    /// of the decrypted data matches the original hash from the MediaReference.
    fn decrypt_and_verify(
        encrypted_data: &[u8],
        key: &Secret<[u8; 32]>,
        reference: &MediaReference,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let decrypted_data = decrypt_data_with_aad(
            encrypted_data,
            key,
            &Secret::new(reference.nonce),
            &reference.scheme_version,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;

        let calculated_hash: [u8; 32] = Sha256::digest(&decrypted_data).into();
        if calculated_hash != reference.original_hash {
            return Err(EncryptedMediaError::HashVerificationFailed);
        }

        Ok(decrypted_data)
    }

    /// Try to decrypt media using the epoch stored alongside the message's IMETA tag.
    ///
    /// Looks up the epoch from the `messages` table by searching for the IMETA tag's
    /// `x <hex_hash>` field, then attempts decryption with that epoch's exporter secret.
    /// This avoids brute-forcing all historical epochs in the common case.
    fn try_decrypt_with_epoch_hint(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
        allow_legacy: bool,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let search_term = format!("x {}", hex::encode(reference.original_hash));

        let epoch = self
            .mdk
            .storage()
            .find_message_epoch_by_tag_content(&self.group_id, &search_term)
            .map_err(|_| EncryptedMediaError::DecryptionFailed {
                reason: "Failed to query message epoch hint".to_string(),
            })?
            .ok_or(EncryptedMediaError::DecryptionFailed {
                reason: "No epoch hint found for media reference".to_string(),
            })?;

        tracing::debug!(
            target: "mdk_core::encrypted_media::manager",
            "Trying epoch hint: epoch {}",
            epoch
        );

        let mut found_secret = false;

        if let Some(data) = self.try_decrypt_with_epoch_secret_source(
            epoch,
            encrypted_data,
            reference,
            &mut found_secret,
            allow_legacy,
            |storage, group_id, epoch| storage.get_group_mip04_exporter_secret(group_id, epoch),
        )? {
            return Ok(data);
        }

        if let Some(data) = self.try_decrypt_with_epoch_secret_source(
            epoch,
            encrypted_data,
            reference,
            &mut found_secret,
            allow_legacy,
            |storage, group_id, epoch| storage.get_group_exporter_secret(group_id, epoch),
        )? {
            return Ok(data);
        }

        if let Some(data) = self.try_decrypt_with_epoch_secret_source(
            epoch,
            encrypted_data,
            reference,
            &mut found_secret,
            allow_legacy,
            |storage, group_id, epoch| storage.get_group_legacy_exporter_secret(group_id, epoch),
        )? {
            return Ok(data);
        }

        if found_secret {
            Err(EncryptedMediaError::DecryptionFailed {
                reason: "Failed to decrypt media with any compatibility secret".to_string(),
            })
        } else {
            Err(EncryptedMediaError::NoExporterSecretForEpoch(epoch))
        }
    }

    fn try_decrypt_with_epoch_secret_source<F>(
        &self,
        epoch: u64,
        encrypted_data: &[u8],
        reference: &MediaReference,
        found_secret: &mut bool,
        allow_legacy: bool,
        load_secret: F,
    ) -> Result<Option<Vec<u8>>, EncryptedMediaError>
    where
        F: FnOnce(&Storage, &GroupId, u64) -> Result<Option<GroupExporterSecret>, GroupError>,
    {
        let maybe_secret = load_secret(self.mdk.storage(), &self.group_id, epoch)
            .map_err(|_| EncryptedMediaError::NoExporterSecretForEpoch(epoch))?;

        let Some(secret) = maybe_secret else {
            return Ok(None);
        };

        *found_secret = true;

        match Self::try_decrypt_with_secret_compat(encrypted_data, reference, &secret, allow_legacy)
        {
            Ok(data) => Ok(Some(data)),
            Err(EncryptedMediaError::DecryptionFailed { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Create an imeta tag for encrypted media (after upload)
    ///
    /// Creates IMETA tag according to Marmot protocol 04.md specification:
    /// imeta url \<storage_url\> m \<mime_type\> filename \<original_filename\>
    /// [dim \<dimensions\>] [blurhash \<blurhash\>] [thumbhash \<thumbhash\>]
    /// x \<file_hash_hex\> n \<nonce_hex\> v \<version\>
    ///
    /// During migration, IMETA tags emit both preview hashes when available.
    /// Consumers that understand both should prefer thumbhash. If only one hash
    /// was generated, only that hash is emitted.
    pub fn create_imeta_tag(&self, upload: &EncryptedMediaUpload, uploaded_url: &str) -> NostrTag {
        let mut tag_values = vec![
            format!("url {}", uploaded_url),
            format!("m {}", upload.mime_type), // MIME type should already be canonical
            format!("filename {}", upload.filename),
        ];

        if let Some((width, height)) = upload.dimensions {
            tag_values.push(format!("dim {}x{}", width, height));
        }

        if let Some(ref blurhash) = upload.blurhash {
            tag_values.push(format!("blurhash {}", blurhash));
        }
        if let Some(ref thumbhash) = upload.thumbhash {
            tag_values.push(format!("thumbhash {}", thumbhash));
        }

        // x field contains SHA256 hash of original file content (hex-encoded)
        tag_values.push(format!("x {}", hex::encode(upload.original_hash)));

        // n field contains the encryption nonce (hex-encoded, 24 hex chars for 12 bytes)
        tag_values.push(format!("n {}", hex::encode(upload.nonce)));

        // v field contains encryption version number (currently "mip04-v2")
        tag_values.push(format!("v {}", DEFAULT_SCHEME_VERSION));

        NostrTag::custom(TagKind::Custom("imeta".into()), tag_values)
    }

    /// Create a media reference from upload result
    pub fn create_media_reference(
        &self,
        upload: &EncryptedMediaUpload,
        uploaded_url: String,
    ) -> MediaReference {
        MediaReference {
            url: uploaded_url,
            original_hash: upload.original_hash,
            mime_type: upload.mime_type.clone(),
            filename: upload.filename.clone(),
            dimensions: upload.dimensions,
            scheme_version: DEFAULT_SCHEME_VERSION.to_string(),
            nonce: upload.nonce,
        }
    }

    /// Parse an IMETA tag to create a MediaReference for decryption
    ///
    /// Expected IMETA format per MIP-04: url \<storage_url\> m \<mime_type\>
    /// filename \<filename\> [dim \<dimensions\>] [blurhash \<blurhash\>]
    /// [thumbhash \<thumbhash\>] x \<file_hash_hex\> n \<nonce_hex\> v \<version\>
    pub fn parse_imeta_tag(
        &self,
        imeta_tag: &NostrTag,
    ) -> Result<MediaReference, EncryptedMediaError> {
        // Verify this is an imeta tag
        if imeta_tag.kind() != TagKind::Custom("imeta".into()) {
            return Err(EncryptedMediaError::InvalidImetaTag {
                reason: "Not an imeta tag".to_string(),
            });
        }

        let tag_values = imeta_tag.clone().to_vec();
        // Minimum required fields: url, m (MIME type), filename, x (hash), n (nonce), v (version) = 6 fields + "imeta" tag = 7
        if tag_values.len() < 7 {
            return Err(EncryptedMediaError::InvalidImetaTag {
                reason: "IMETA tag has insufficient fields (minimum: url, m, filename, x, n, v)"
                    .to_string(),
            });
        }

        let mut url: Option<String> = None;
        let mut mime_type: Option<String> = None;
        let mut filename: Option<String> = None;
        let mut original_hash: Option<[u8; 32]> = None;
        let mut nonce: Option<[u8; 12]> = None;
        let mut dimensions: Option<(u32, u32)> = None;
        let mut version: Option<String> = None;

        // Parse key-value pairs from IMETA tag
        // Skip the first element which is "imeta"
        for item in tag_values.iter().skip(1) {
            let parts: Vec<&str> = item.splitn(2, ' ').collect();
            if parts.len() != 2 {
                continue;
            }

            match parts[0] {
                "url" => url = Some(parts[1].to_string()),
                "m" => {
                    // Use centralized MIME type canonicalization to handle aliases properly
                    match validation::validate_mime_type(parts[1]) {
                        Ok(canonical) => mime_type = Some(canonical),
                        Err(_) => {
                            return Err(EncryptedMediaError::InvalidImetaTag {
                                reason: format!("Invalid MIME type: {}", parts[1]),
                            });
                        }
                    }
                }
                "x" => {
                    // Decode hex-encoded original file hash
                    match hex::decode(parts[1]) {
                        Ok(bytes) if bytes.len() == 32 => {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&bytes);
                            original_hash = Some(hash);
                        }
                        _ => {
                            return Err(EncryptedMediaError::InvalidImetaTag {
                                reason: "Invalid 'x' (file_hash) field".to_string(),
                            });
                        }
                    }
                }
                "n" => {
                    // Decode hex-encoded encryption nonce (12 bytes = 24 hex chars)
                    match hex::decode(parts[1]) {
                        Ok(bytes) if bytes.len() == 12 => {
                            let mut nonce_bytes = [0u8; 12];
                            nonce_bytes.copy_from_slice(&bytes);
                            nonce = Some(nonce_bytes);
                        }
                        _ => {
                            return Err(EncryptedMediaError::InvalidImetaTag {
                                reason: "Invalid 'n' (nonce) field - must be 24 hex characters (12 bytes)".to_string(),
                            });
                        }
                    }
                }
                "dim" => {
                    // Parse dimensions in format "widthxheight"
                    let dim_parts: Vec<&str> = parts[1].split('x').collect();
                    if dim_parts.len() == 2
                        && let (Ok(width), Ok(height)) =
                            (dim_parts[0].parse::<u32>(), dim_parts[1].parse::<u32>())
                    {
                        dimensions = Some((width, height));
                    }
                }
                "filename" => match validation::validate_filename(parts[1]) {
                    Ok(_) => filename = Some(parts[1].to_string()),
                    Err(_) => {
                        return Err(EncryptedMediaError::InvalidImetaTag {
                            reason: format!("Invalid filename: {}", parts[1]),
                        });
                    }
                },
                "v" => version = Some(parts[1].to_string()),
                "blurhash" | "thumbhash" => {
                    // Preview hashes are optional and not needed for decryption.
                    // Parsers that expose both should prefer thumbhash when present.
                }
                _ => {
                    // Ignore unknown fields for forward compatibility
                }
            }
        }

        // Validate required fields
        let url = url.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'url' field".to_string(),
        })?;
        let mime_type = mime_type.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'm' (mime_type) field".to_string(),
        })?;
        let original_hash = original_hash.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing or invalid 'x' (file_hash) field".to_string(),
        })?;
        let filename = filename.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'filename' field".to_string(),
        })?;

        // Validate version (required field)
        let scheme_version = version.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'v' (version) field".to_string(),
        })?;

        // Validate that the version is supported
        if !is_scheme_version_supported(&scheme_version) {
            return Err(EncryptedMediaError::DecryptionFailed {
                reason: format!("Unsupported MIP-04 encryption version: {}", scheme_version),
            });
        }

        let nonce = nonce.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'n' (nonce) field".to_string(),
        })?;

        Ok(MediaReference {
            url,
            original_hash,
            mime_type,
            filename,
            dimensions,
            scheme_version,
            nonce,
        })
    }
}

impl<Storage> MDK<Storage>
where
    Storage: MdkStorageProvider,
{
    /// Create an encrypted media manager for a specific group
    pub fn media_manager(&self, group_id: GroupId) -> EncryptedMediaManager<'_, Storage> {
        EncryptedMediaManager::new(self, group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use image::{ImageBuffer, Rgb};
    use mdk_memory_storage::MdkMemoryStorage;
    use mdk_storage_traits::groups::{GroupStorage, types::GroupExporterSecret};
    use mdk_storage_traits::messages::MessageStorage;
    use mdk_storage_traits::messages::types::{Message, MessageState};
    use nostr::{EventId, Keys, Kind, Tags, Timestamp, UnsignedEvent};

    use crate::encrypted_media::crypto::{
        derive_legacy_encryption_key_with_secret, encrypt_data_with_aad, generate_encryption_nonce,
    };
    use crate::media_processing::types::MediaProcessingError;
    use crate::test_util::{create_key_package_event, create_nostr_group_config_data};

    fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
    }

    fn create_test_mdk_with_config(config: crate::MdkConfig) -> MDK<MdkMemoryStorage> {
        MDK::builder(MdkMemoryStorage::default())
            .with_config(config)
            .build()
    }

    /// Create a group, merge its pending commit, and return the MDK instance,
    /// group ID, and the creator's keys.
    fn setup_group() -> (MDK<MdkMemoryStorage>, GroupId, Keys) {
        let mdk = create_test_mdk();
        let alice_keys = Keys::generate();
        let admins = vec![alice_keys.public_key()];
        let create_result = mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(admins),
            )
            .unwrap();

        let group_id = create_result.group.mls_group_id.clone();
        mdk.merge_pending_commit(&group_id).unwrap();

        (mdk, group_id, alice_keys)
    }

    /// Store a message with IMETA tags for the given upload, returning the epoch
    /// at which the message was recorded.
    fn store_imeta_message(
        mdk: &MDK<MdkMemoryStorage>,
        group_id: &GroupId,
        upload: &EncryptedMediaUpload,
        pubkey: nostr::PublicKey,
        url: &str,
    ) -> u64 {
        let group = mdk.load_mls_group(group_id).unwrap().unwrap();
        let encryption_epoch = group.epoch().as_u64();

        let manager = mdk.media_manager(group_id.clone());
        let imeta_tag = manager.create_imeta_tag(upload, url);
        let mut tags = Tags::new();
        tags.push(imeta_tag);

        let event_id = EventId::all_zeros();
        let wrapper_event_id = EventId::from_slice(&[1u8; 32]).unwrap();

        let message = Message {
            id: event_id,
            pubkey,
            kind: Kind::from(445u16),
            mls_group_id: group_id.clone(),
            created_at: Timestamp::now(),
            processed_at: Timestamp::now(),
            content: "".to_string(),
            tags: tags.clone(),
            event: UnsignedEvent::new(
                pubkey,
                Timestamp::now(),
                Kind::from(445u16),
                tags,
                "".to_string(),
            ),
            wrapper_event_id,
            epoch: Some(encryption_epoch),
            state: MessageState::Processed,
        };

        mdk.storage().save_message(message).unwrap();
        encryption_epoch
    }

    /// Advance the group epoch by performing self-updates.
    fn advance_epochs(mdk: &MDK<MdkMemoryStorage>, group_id: &GroupId, count: usize) {
        for _ in 0..count {
            mdk.self_update(group_id).unwrap();
            mdk.merge_pending_commit(group_id).unwrap();
        }
    }

    fn fixed_pre_deadline_ts() -> u64 {
        LEGACY_MEDIA_MIGRATION_DEADLINE.saturating_sub(1)
    }

    fn fixed_post_deadline_ts() -> u64 {
        LEGACY_MEDIA_MIGRATION_DEADLINE.saturating_add(1)
    }

    #[test]
    fn test_create_imeta_tag() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            original_size: 1000,
            encrypted_size: 1004,
            dimensions: Some((1920, 1080)),
            blurhash: Some("LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string()),
            thumbhash: Some("}U#WoBrZy#_/qQ8PC,N]q7m}6X".to_string()),
            nonce: [0xAA; 12],
        };

        let tag = manager.create_imeta_tag(&upload, "https://example.com/file.jpg");

        // Verify tag structure
        assert_eq!(tag.kind(), TagKind::Custom("imeta".into()));
        let values = tag.to_vec();

        // Check required fields
        assert!(
            values
                .iter()
                .any(|v| v.starts_with("url https://example.com/file.jpg"))
        );
        assert!(values.iter().any(|v| v.starts_with("m image/jpeg")));
        assert!(values.iter().any(|v| v.starts_with("filename test.jpg")));
        assert!(values.iter().any(|v| v.starts_with("dim 1920x1080")));
        assert!(
            values
                .iter()
                .any(|v| v.starts_with("blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH"))
        );
        assert!(
            values
                .iter()
                .any(|v| v.starts_with("thumbhash }U#WoBrZy#_/qQ8PC,N]q7m}6X"))
        );
        assert!(
            values
                .iter()
                .any(|v| v.starts_with(&format!("x {}", hex::encode([0x42; 32]))))
        );
        assert!(
            values
                .iter()
                .any(|v| v.starts_with(&format!("n {}", hex::encode([0xAA; 12]))))
        );
        assert!(values.iter().any(|v| v.starts_with("v mip04-v2")));
    }

    #[test]
    fn test_create_imeta_tag_falls_back_to_blurhash() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            original_size: 1000,
            encrypted_size: 1004,
            dimensions: Some((1920, 1080)),
            blurhash: Some("LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string()),
            thumbhash: None,
            nonce: [0xAA; 12],
        };

        let tag = manager.create_imeta_tag(&upload, "https://example.com/file.jpg");
        let values = tag.to_vec();

        assert!(
            values
                .iter()
                .any(|v| v.starts_with("blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH"))
        );
        assert!(!values.iter().any(|v| v.starts_with("thumbhash ")));
    }

    #[test]
    fn test_create_imeta_tag_emits_thumbhash_when_only_thumbhash_exists() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            original_size: 1000,
            encrypted_size: 1004,
            dimensions: Some((1920, 1080)),
            blurhash: None,
            thumbhash: Some("}U#WoBrZy#_/qQ8PC,N]q7m}6X".to_string()),
            nonce: [0xAA; 12],
        };

        let tag = manager.create_imeta_tag(&upload, "https://example.com/file.jpg");
        let values = tag.to_vec();

        assert!(!values.iter().any(|v| v.starts_with("blurhash ")));
        assert!(
            values
                .iter()
                .any(|v| v.starts_with("thumbhash }U#WoBrZy#_/qQ8PC,N]q7m}6X"))
        );
    }

    #[test]
    fn test_parse_imeta_tag() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Create a valid IMETA tag
        let test_nonce = [0xBB; 12];
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            "dim 1920x1080".to_string(),
            "thumbhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];

        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.url, "https://example.com/encrypted.jpg");
        assert_eq!(media_ref.mime_type, "image/jpeg");
        assert_eq!(media_ref.original_hash, [0x42; 32]);
        assert_eq!(media_ref.filename, "photo.jpg");
        assert_eq!(media_ref.dimensions, Some((1920, 1080)));
        assert_eq!(media_ref.scheme_version, "mip04-v2");
        assert_eq!(media_ref.nonce, test_nonce);
    }

    #[test]
    fn test_parse_imeta_tag_accepts_legacy_blurhash() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let test_nonce = [0xBC; 12];
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            "dim 1920x1080".to_string(),
            "blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];

        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&imeta_tag);

        assert!(result.is_ok(), "legacy blurhash tag should be accepted");
        let media_ref = result.unwrap();
        assert_eq!(media_ref.url, "https://example.com/encrypted.jpg");
        assert_eq!(media_ref.nonce, test_nonce);
    }

    #[test]
    fn test_parse_imeta_tag_accepts_both_preview_hashes() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let test_nonce = [0xBD; 12];
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            "dim 1920x1080".to_string(),
            "blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string(),
            "thumbhash }U#WoBrZy#_/qQ8PC,N]q7m}6X".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];

        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&imeta_tag);

        assert!(
            result.is_ok(),
            "IMETA tags with both preview hashes should be accepted"
        );
    }

    #[test]
    fn test_parse_imeta_tag_invalid() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with wrong tag kind
        let wrong_tag = NostrTag::custom(TagKind::Custom("wrong".into()), vec!["test".to_string()]);
        let result = manager.parse_imeta_tag(&wrong_tag);
        assert!(result.is_err());

        // Test with missing required fields
        let incomplete_tag = NostrTag::custom(
            TagKind::Custom("imeta".into()),
            vec![
                "url https://example.com/test.jpg".to_string(),
                // Missing mime type and hash
            ],
        );
        let result = manager.parse_imeta_tag(&incomplete_tag);
        assert!(result.is_err());

        // Test with invalid hash
        let invalid_hash_tag = NostrTag::custom(
            TagKind::Custom("imeta".into()),
            vec![
                "url https://example.com/test.jpg".to_string(),
                "m image/jpeg".to_string(),
                "filename test.jpg".to_string(),
                "x invalidhash".to_string(),
            ],
        );
        let result = manager.parse_imeta_tag(&invalid_hash_tag);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_media_reference() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let test_nonce = [0xCC; 12];
        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3, 4],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/png".to_string(),
            filename: "test.png".to_string(),
            original_size: 2000,
            encrypted_size: 2004,
            dimensions: Some((800, 600)),
            blurhash: None,
            thumbhash: None,
            nonce: test_nonce,
        };

        let media_ref = manager
            .create_media_reference(&upload, "https://cdn.example.com/image.png".to_string());

        assert_eq!(media_ref.url, "https://cdn.example.com/image.png");
        assert_eq!(media_ref.original_hash, [0x42; 32]);
        assert_eq!(media_ref.mime_type, "image/png");
        assert_eq!(media_ref.filename, "test.png");
        assert_eq!(media_ref.dimensions, Some((800, 600)));
        assert_eq!(media_ref.scheme_version, DEFAULT_SCHEME_VERSION);
        assert_eq!(media_ref.nonce, test_nonce);
    }

    #[test]
    fn test_encrypt_for_upload_supported_mime_types() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test data (not real files, but that's fine for this test)
        let test_data = vec![0u8; 1000];
        // Use options that skip metadata extraction for images to avoid format errors
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            generate_thumbhash: false,
            max_dimension: None,
            max_file_size: None,
            max_filename_length: None,
        };

        // Test with various supported non-image MIME types - all should pass validation
        let test_cases = vec![
            ("application/pdf", "document.pdf"),
            ("video/quicktime", "video.mov"),
            ("audio/mpeg", "song.mp3"),
            ("text/plain", "note.txt"),
        ];

        for (mime_type, filename) in test_cases {
            let result =
                manager.encrypt_for_upload_with_options(&test_data, mime_type, filename, &options);

            // This will fail because we don't have a real MLS group, but we can check
            // that the validation passes and the error is about the missing group
            assert!(result.is_err());
            if let Err(EncryptedMediaError::GroupNotFound) = result {
                // This is expected - the MIME type validation passed, but we don't have a real group
            } else {
                panic!(
                    "Expected GroupNotFound error for MIME type {}, got: {:?}",
                    mime_type, result
                );
            }
        }
    }

    #[test]
    fn test_encrypt_for_upload_rejects_unsupported_mime_types() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let test_data = vec![0u8; 1000];
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            generate_thumbhash: false,
            max_dimension: None,
            max_file_size: None,
            max_filename_length: None,
        };

        // Test with unsupported MIME types - all should be rejected
        let unsupported_cases = vec![
            ("application/x-executable", "malware.exe"),
            ("text/html", "page.html"),
            ("application/javascript", "script.js"),
            ("image/svg+xml", "image.svg"),
            ("application/x-sh", "script.sh"),
        ];

        for (mime_type, filename) in unsupported_cases {
            let result =
                manager.encrypt_for_upload_with_options(&test_data, mime_type, filename, &options);

            // Should fail with InvalidMimeType error
            assert!(result.is_err());
            assert!(
                matches!(
                    result,
                    Err(EncryptedMediaError::MediaProcessing(
                        MediaProcessingError::InvalidMimeType { .. }
                    ))
                ),
                "Expected InvalidMimeType error for unsupported MIME type {}, got: {:?}",
                mime_type,
                result
            );
        }
    }

    #[test]
    fn test_encrypt_for_upload_allows_escape_hatch() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test data (can be anything - escape hatch bypasses validation)
        let test_data = vec![0x42u8; 1000];
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            generate_thumbhash: false,
            max_dimension: None,
            max_file_size: None,
            max_filename_length: None,
        };

        // Test escape hatch MIME type - should pass validation
        // (will fail later due to missing group, but validation should pass)
        let result = manager.encrypt_for_upload_with_options(
            &test_data,
            "application/octet-stream",
            "custom_file.bin",
            &options,
        );

        // Validation should pass (escape hatch bypasses allowlist check)
        // The error should be about missing group, not invalid MIME type
        assert!(result.is_err());
        assert!(
            matches!(result, Err(EncryptedMediaError::GroupNotFound)),
            "Escape hatch should pass validation, got: {:?}",
            result
        );

        // Test escape hatch with parameters (should be canonicalized)
        let result = manager.encrypt_for_upload_with_options(
            &test_data,
            "application/octet-stream; charset=binary",
            "custom_file.bin",
            &options,
        );

        assert!(result.is_err());
        assert!(
            matches!(result, Err(EncryptedMediaError::GroupNotFound)),
            "Escape hatch with parameters should pass validation"
        );
    }

    #[test]
    fn test_encrypt_prevents_spoofing() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Create a PNG image
        let img = ImageBuffer::from_fn(8, 8, |x, y| {
            Rgb([(x * 32) as u8, (y * 32) as u8, ((x + y) * 16) as u8])
        });
        let mut png_data = Vec::new();
        img.write_to(&mut Cursor::new(&mut png_data), image::ImageFormat::Png)
            .unwrap();

        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            generate_thumbhash: false,
            max_dimension: None,
            max_file_size: None,
            max_filename_length: None,
        };

        // Test 1: Spoofed image type (claiming JPEG but file is PNG) should fail
        // This verifies that validate_mime_type_matches_data is called for images
        let result =
            manager.encrypt_for_upload_with_options(&png_data, "image/jpeg", "photo.jpg", &options);
        assert!(result.is_err(), "Spoofed MIME type should be rejected");
        assert!(
            matches!(
                result,
                Err(EncryptedMediaError::MediaProcessing(
                    MediaProcessingError::MimeTypeMismatch { .. }
                ))
            ),
            "Expected MimeTypeMismatch error for spoofed image type, got: {:?}",
            result
        );

        // Test 2: Unsupported image type should be rejected (allowlist check)
        let result = manager.encrypt_for_upload_with_options(
            &png_data,
            "image/svg+xml",
            "image.svg",
            &options,
        );
        assert!(
            result.is_err(),
            "Unsupported image MIME type should be rejected"
        );
        assert!(
            matches!(
                result,
                Err(EncryptedMediaError::MediaProcessing(
                    MediaProcessingError::InvalidMimeType { .. }
                ))
            ),
            "Expected InvalidMimeType error for unsupported image type, got: {:?}",
            result
        );

        // Test 3: Valid matching image type should pass (if we had a real group)
        // Note: This will fail with GroupNotFound, but that's expected - the validation passed
        let result =
            manager.encrypt_for_upload_with_options(&png_data, "image/png", "photo.png", &options);
        assert!(result.is_err()); // Will fail due to missing group, not validation
        // But we can verify it's not a validation error
        assert!(
            !matches!(
                result,
                Err(EncryptedMediaError::MediaProcessing(
                    MediaProcessingError::InvalidMimeType { .. }
                )) | Err(EncryptedMediaError::MediaProcessing(
                    MediaProcessingError::MimeTypeMismatch { .. }
                ))
            ),
            "Should not fail with validation error for valid matching MIME type, got: {:?}",
            result
        );
    }

    #[test]
    fn test_parse_imeta_tag_missing_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test missing URL
        let tag_values = vec![
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing MIME type
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing filename
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing hash
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Test missing version
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }

    #[test]
    fn test_generate_encryption_nonce_uniqueness() {
        // Generate multiple nonces and verify they are unique
        let nonces: Vec<[u8; 12]> = (0..100).map(|_| *generate_encryption_nonce()).collect();

        for i in 0..nonces.len() {
            for j in (i + 1)..nonces.len() {
                assert_ne!(nonces[i], nonces[j], "Nonces should be unique");
            }
        }

        // Verify nonces are not all zeros
        for nonce in &nonces {
            assert_ne!(nonce, &[0u8; 12], "Nonce should not be all zeros");
        }
    }

    #[test]
    fn missing_nonce_results_in_invalid_imeta() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "v mip04-v2".to_string(),
            // Missing 'n' (nonce) field
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }

    #[test]
    fn test_parse_imeta_tag_version_validation() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test unsupported version
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode([0xDD; 12])),
            "v mip04-v3".to_string(), // Unsupported version
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DecryptionFailed { .. })
        ));

        // Test that mip04-v1 is explicitly rejected (breaking change)
        let test_nonce = [0xAB; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v1".to_string(), // Legacy version
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(
            matches!(result, Err(EncryptedMediaError::DecryptionFailed { .. })),
            "mip04-v1 should be rejected to prevent nonce reuse vulnerability"
        );

        // Test supported version
        let test_nonce = [0xDD; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        // Test that mip04-v1 is explicitly rejected (breaking change)
        let test_nonce = [0xAB; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v1".to_string(), // Legacy version
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(
            matches!(result, Err(EncryptedMediaError::DecryptionFailed { .. })),
            "mip04-v1 should be rejected to prevent nonce reuse vulnerability"
        );
    }

    #[test]
    fn test_parse_imeta_tag_optional_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with minimal required fields only
        let test_nonce1 = [0xEE; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce1)),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.dimensions, None); // Optional field should be None
        assert_eq!(media_ref.scheme_version, "mip04-v2"); // Version should be stored

        // Test with dimensions
        let test_nonce2 = [0xFF; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce2)),
            "v mip04-v2".to_string(),
            "dim 1920x1080".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.dimensions, Some((1920, 1080)));
        assert_eq!(media_ref.scheme_version, "mip04-v2"); // Version should be stored
    }

    #[test]
    fn test_parse_imeta_tag_mime_type_canonicalization() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test with mixed-case MIME type
        let test_nonce1 = [0x11; 12];
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m IMAGE/JPEG".to_string(), // Mixed case
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce1)),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "image/jpeg"); // Should be lowercase

        // Test with whitespace around MIME type
        let test_nonce2 = [0x22; 12];
        let tag_values = vec![
            "url https://example.com/test.png".to_string(),
            "m  Image/PNG  ".to_string(), // Whitespace and mixed case
            "filename photo.png".to_string(),
            format!("x {}", hex::encode([0x43; 32])),
            format!("n {}", hex::encode(test_nonce2)),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "image/png"); // Should be trimmed and lowercase

        // Test with various supported MIME types and case combinations
        let test_cases = [
            ("video/MP4", "video/mp4"),
            ("Audio/MPEG", "audio/mpeg"),
            ("IMAGE/webp", "image/webp"),
            ("AUDIO/wav", "audio/wav"),
        ];

        for (idx, (input_mime, expected_mime)) in test_cases.iter().enumerate() {
            let test_nonce = [0x33 + idx as u8; 12];
            let tag_values = vec![
                "url https://example.com/test.file".to_string(),
                format!("m {}", input_mime),
                "filename test.file".to_string(),
                format!("x {}", hex::encode([0x44; 32])),
                format!("n {}", hex::encode(test_nonce)),
                "v mip04-v2".to_string(),
            ];
            let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
            let result = manager.parse_imeta_tag(&tag);
            assert!(result.is_ok(), "Failed to parse MIME type: {}", input_mime);

            let media_ref = result.unwrap();
            assert_eq!(
                media_ref.mime_type, *expected_mime,
                "MIME type canonicalization failed for input: {}",
                input_mime
            );
        }
    }

    #[test]
    fn test_imeta_roundtrip_with_mixed_case_mime() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Simulate an IMETA tag created by a producer that uses mixed-case MIME type
        let test_nonce = [0x55; 12];
        let tag_values = vec![
            "url https://example.com/encrypted.jpg".to_string(),
            "m IMAGE/JPEG".to_string(), // Mixed case from producer
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        // Parse the IMETA tag (this should canonicalize the MIME type)
        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());

        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "image/jpeg");
    }

    #[test]
    fn test_parse_imeta_tag_duplicate_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let test_nonce = [0xAA; 12];
        let tag_values = vec![
            "url https://example.com/first.jpg".to_string(),
            "url https://example.com/second.jpg".to_string(), // Duplicate
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode(test_nonce)),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&tag);
        assert!(result.is_ok());
        let media_ref = result.unwrap();
        // Last one wins
        assert_eq!(media_ref.url, "https://example.com/second.jpg");
    }

    #[test]
    fn test_parse_imeta_tag_malformed_hex() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Invalid hex in 'x' (hash)
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            "x ZZZZ".to_string(), // Invalid hex
            format!("n {}", hex::encode([0xAA; 12])),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Invalid hex in 'n' (nonce)
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            "n ZZZZ".to_string(), // Invalid hex
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));

        // Wrong length hex in 'x'
        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 31])), // 31 bytes instead of 32
            format!("n {}", hex::encode([0xAA; 12])),
            "v mip04-v2".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }

    #[test]
    fn test_parse_imeta_tag_invalid_dimensions() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let invalid_dims = vec!["100x", "x100", "abc", "100xabc", "100x200x300"];

        for dim in invalid_dims {
            let tag_values = vec![
                "url https://example.com/test.jpg".to_string(),
                "m image/jpeg".to_string(),
                "filename photo.jpg".to_string(),
                format!("x {}", hex::encode([0x42; 32])),
                format!("n {}", hex::encode([0xAA; 12])),
                "v mip04-v2".to_string(),
                format!("dim {}", dim),
            ];
            let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
            let result = manager.parse_imeta_tag(&tag);

            // Invalid dimensions should be ignored, not cause failure
            assert!(
                result.is_ok(),
                "Should parse successfully ignoring invalid dimensions: {}",
                dim
            );
            let media_ref = result.unwrap();
            assert_eq!(media_ref.dimensions, None);
        }
    }

    #[test]
    fn test_parse_imeta_tag_unknown_fields() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        let tag_values = vec![
            "url https://example.com/test.jpg".to_string(),
            "m image/jpeg".to_string(),
            "filename photo.jpg".to_string(),
            format!("x {}", hex::encode([0x42; 32])),
            format!("n {}", hex::encode([0xAA; 12])),
            "v mip04-v2".to_string(),
            "unknown_field some_value".to_string(),
            "another_unknown".to_string(),
        ];
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);
        let result = manager.parse_imeta_tag(&tag);

        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_from_download_hash_verification_failure() {
        let mdk = create_test_mdk();
        let alice_keys = Keys::generate();
        let admins = vec![alice_keys.public_key()];
        let create_result = mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(admins),
            )
            .unwrap();

        let group_id = create_result.group.mls_group_id;
        let manager = mdk.media_manager(group_id);

        let data = b"secret data";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "secret.txt")
            .unwrap();

        // Tamper with the hash -- this changes the AAD, causing Poly1305 to fail
        let mut media_ref =
            manager.create_media_reference(&upload, "https://example.com".to_string());
        media_ref.original_hash[0] ^= 0xFF;

        let result = manager.decrypt_from_download(&upload.encrypted_data, &media_ref);
        assert!(matches!(
            result,
            Err(EncryptedMediaError::DecryptionFailed { .. })
        ));
    }

    /// Verifies that decrypt_from_download resolves via the epoch hint when the
    /// current epoch has advanced past the encryption epoch.
    #[test]
    fn test_decrypt_from_download_epoch_fallback() {
        let (mdk, group_id, alice_keys) = setup_group();

        let manager = mdk.media_manager(group_id.clone());
        let data = b"epoch fallback test data";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "fallback.txt")
            .unwrap();
        let media_ref =
            manager.create_media_reference(&upload, "https://example.com/fallback".to_string());

        store_imeta_message(
            &mdk,
            &group_id,
            &upload,
            alice_keys.public_key(),
            "https://example.com/fallback",
        );

        advance_epochs(&mdk, &group_id, 3);

        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&upload.encrypted_data, &media_ref)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    /// Verifies that decrypt_from_download succeeds via the epoch hint path
    /// after multiple epoch advancements.
    #[test]
    fn test_decrypt_from_download_epoch_hint() {
        let (mdk, group_id, alice_keys) = setup_group();

        let manager = mdk.media_manager(group_id.clone());
        let data = b"epoch hint test data";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "hint.txt")
            .unwrap();
        let media_ref =
            manager.create_media_reference(&upload, "https://example.com/hint".to_string());

        store_imeta_message(
            &mdk,
            &group_id,
            &upload,
            alice_keys.public_key(),
            "https://example.com/hint",
        );

        advance_epochs(&mdk, &group_id, 3);

        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&upload.encrypted_data, &media_ref)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    /// Verifies that decrypt_from_download falls back to the current epoch key
    /// when no epoch hint message is stored (e.g., freshly downloaded media).
    #[test]
    fn test_decrypt_from_download_current_epoch_fallback() {
        let (mdk, group_id, _alice_keys) = setup_group();

        let manager = mdk.media_manager(group_id.clone());
        let data = b"current epoch fallback test";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "fallback_current.txt")
            .unwrap();
        let media_ref = manager
            .create_media_reference(&upload, "https://example.com/fallback_current".to_string());

        // No message stored -- epoch hint will fail, triggering current-epoch fallback
        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&upload.encrypted_data, &media_ref)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_from_download_current_epoch_legacy_media_compat() {
        let (mdk, group_id, _alice_keys) = setup_group();

        let data = b"legacy current epoch media";
        let original_hash: [u8; 32] = Sha256::digest(data).into();
        let legacy_secret = mdk
            .legacy_exporter_secret(&group_id)
            .expect("Should derive legacy exporter secret");
        let key = derive_legacy_encryption_key_with_secret(
            &legacy_secret.secret,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-current.txt",
        )
        .expect("Should derive legacy media key");
        let nonce = generate_encryption_nonce();
        let encrypted_data = encrypt_data_with_aad(
            data,
            &key,
            &nonce,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-current.txt",
        )
        .expect("Should encrypt legacy media");

        let reference = MediaReference {
            url: "https://example.com/legacy-current".to_string(),
            original_hash,
            mime_type: "text/plain".to_string(),
            filename: "legacy-current.txt".to_string(),
            dimensions: None,
            scheme_version: DEFAULT_SCHEME_VERSION.to_string(),
            nonce: *nonce,
        };

        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&encrypted_data, &reference)
            .expect("Legacy current-epoch media should decrypt");
        assert_eq!(decrypted, data);
    }

    /// Verifies that non-recoverable errors from the epoch hint path propagate
    /// immediately without falling back to the current epoch key.
    #[test]
    fn test_decrypt_from_download_non_recoverable_error_propagates() {
        let (mdk, group_id, alice_keys) = setup_group();

        let manager = mdk.media_manager(group_id.clone());
        let data = b"non-recoverable error test";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "propagate.txt")
            .unwrap();
        let mut media_ref =
            manager.create_media_reference(&upload, "https://example.com/propagate".to_string());

        store_imeta_message(
            &mdk,
            &group_id,
            &upload,
            alice_keys.public_key(),
            "https://example.com/propagate",
        );

        // Corrupt the scheme version -- epoch hint succeeds but key derivation
        // fails with UnknownSchemeVersion, which must not be swallowed
        media_ref.scheme_version = "invalid-scheme-v99".to_string();

        let manager = mdk.media_manager(group_id);
        let result = manager.decrypt_from_download(&upload.encrypted_data, &media_ref);
        assert!(
            matches!(result, Err(EncryptedMediaError::UnknownSchemeVersion(ref v)) if v == "invalid-scheme-v99"),
            "Expected UnknownSchemeVersion to propagate, got: {:?}",
            result
        );
    }

    /// Verifies that the NoExporterSecretForEpoch fallback arm triggers when
    /// the epoch hint finds an epoch but no exporter secret exists for it,
    /// and decryption still succeeds via the current epoch key.
    #[test]
    fn test_decrypt_from_download_no_exporter_secret_fallback() {
        let (mdk, group_id, alice_keys) = setup_group();

        let manager = mdk.media_manager(group_id.clone());
        let data = b"missing secret fallback test";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "missing_secret.txt")
            .unwrap();
        let media_ref = manager
            .create_media_reference(&upload, "https://example.com/missing_secret".to_string());

        // Store a message referencing a fake epoch that has no exporter secret.
        // We manually construct the message with a non-existent epoch (9999).
        let search_term = format!("x {}", hex::encode(upload.original_hash));
        let tags = Tags::parse(vec![vec!["imeta", &search_term]]).unwrap();

        let event_id = EventId::all_zeros();
        let wrapper_event_id = EventId::from_slice(&[1u8; 32]).unwrap();

        let message = Message {
            id: event_id,
            pubkey: alice_keys.public_key(),
            kind: Kind::from(445u16),
            mls_group_id: group_id.clone(),
            created_at: Timestamp::now(),
            processed_at: Timestamp::now(),
            content: "".to_string(),
            tags: tags.clone(),
            event: UnsignedEvent::new(
                alice_keys.public_key(),
                Timestamp::now(),
                Kind::from(445u16),
                tags,
                "".to_string(),
            ),
            wrapper_event_id,
            epoch: Some(9999),
            state: MessageState::Processed,
        };
        mdk.storage().save_message(message).unwrap();

        // Epoch hint finds epoch 9999, but no secret exists for it.
        // Should fall back to the current epoch key and succeed.
        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&upload.encrypted_data, &media_ref)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_from_download_epoch_hint_legacy_media_compat() {
        let (mdk, group_id, alice_keys) = setup_group();

        let data = b"legacy hinted media";
        let original_hash: [u8; 32] = Sha256::digest(data).into();
        let legacy_secret = mdk
            .legacy_exporter_secret(&group_id)
            .expect("Should derive legacy exporter secret");
        let key = derive_legacy_encryption_key_with_secret(
            &legacy_secret.secret,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-hint.txt",
        )
        .expect("Should derive legacy media key");
        let nonce = generate_encryption_nonce();
        let encrypted_data = encrypt_data_with_aad(
            data,
            &key,
            &nonce,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-hint.txt",
        )
        .expect("Should encrypt legacy media");
        let encrypted_hash: [u8; 32] = Sha256::digest(&encrypted_data).into();
        let upload = EncryptedMediaUpload {
            encrypted_data: encrypted_data.clone(),
            original_hash,
            encrypted_hash,
            mime_type: "text/plain".to_string(),
            filename: "legacy-hint.txt".to_string(),
            original_size: data.len() as u64,
            encrypted_size: encrypted_data.len() as u64,
            dimensions: None,
            blurhash: None,
            thumbhash: None,
            nonce: *nonce,
        };
        let media_ref = mdk
            .media_manager(group_id.clone())
            .create_media_reference(&upload, "https://example.com/legacy-hint".to_string());
        let encryption_epoch = store_imeta_message(
            &mdk,
            &group_id,
            &upload,
            alice_keys.public_key(),
            "https://example.com/legacy-hint",
        );
        mdk.storage()
            .save_group_exporter_secret(GroupExporterSecret {
                mls_group_id: group_id.clone(),
                epoch: encryption_epoch,
                secret: legacy_secret.secret.clone(),
            })
            .expect("Should persist legacy epoch secret");

        advance_epochs(&mdk, &group_id, 2);

        let manager = mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&encrypted_data, &media_ref)
            .expect("Legacy media referenced by epoch hint should decrypt");
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_from_download_cross_epoch_respects_lookback_cleanup() {
        use mdk_storage_traits::groups::GroupStorage;

        let config = crate::MdkConfig {
            max_past_epochs: 2,
            ..Default::default()
        };
        let mdk = create_test_mdk_with_config(config);
        let alice_keys = Keys::generate();
        let admins = vec![alice_keys.public_key()];
        let create_result = mdk
            .create_group(
                &alice_keys.public_key(),
                vec![],
                create_nostr_group_config_data(admins),
            )
            .unwrap();
        let group_id = create_result.group.mls_group_id;
        mdk.merge_pending_commit(&group_id).unwrap();

        // Encrypt at epoch 0 and store hint message.
        let manager = mdk.media_manager(group_id.clone());
        let old_data = b"old media at epoch 0";
        let old_upload = manager
            .encrypt_for_upload(old_data, "text/plain", "old.txt")
            .unwrap();
        let old_ref =
            manager.create_media_reference(&old_upload, "https://example.com/old".to_string());
        let old_epoch = store_imeta_message(
            &mdk,
            &group_id,
            &old_upload,
            alice_keys.public_key(),
            "https://example.com/old",
        );
        assert_eq!(old_epoch, 0);

        // Advance to epoch 2, then encrypt newer media at epoch 2.
        for _ in 0..2 {
            mdk.self_update(&group_id).unwrap();
            mdk.merge_pending_commit(&group_id).unwrap();
        }

        let manager = mdk.media_manager(group_id.clone());
        let recent_data = b"recent media at epoch 2";
        let recent_upload = manager
            .encrypt_for_upload(recent_data, "text/plain", "recent.txt")
            .unwrap();
        let recent_ref = manager
            .create_media_reference(&recent_upload, "https://example.com/recent".to_string());
        let recent_epoch = store_imeta_message(
            &mdk,
            &group_id,
            &recent_upload,
            alice_keys.public_key(),
            "https://example.com/recent",
        );
        assert_eq!(recent_epoch, 2);

        // Advance to epoch 4. With max_past_epochs = 2, keep epochs >= 2.
        for _ in 0..2 {
            mdk.self_update(&group_id).unwrap();
            mdk.merge_pending_commit(&group_id).unwrap();
        }

        let current_epoch = mdk.get_group(&group_id).unwrap().unwrap().epoch;
        assert_eq!(current_epoch, 4);

        let secret_epoch_0 = mdk
            .storage()
            .get_group_mip04_exporter_secret(&group_id, 0)
            .unwrap();
        let secret_epoch_1 = mdk
            .storage()
            .get_group_mip04_exporter_secret(&group_id, 1)
            .unwrap();
        let secret_epoch_2 = mdk
            .storage()
            .get_group_mip04_exporter_secret(&group_id, 2)
            .unwrap();

        assert!(secret_epoch_0.is_none(), "Epoch 0 key should be pruned");
        assert!(secret_epoch_1.is_none(), "Epoch 1 key should be pruned");
        assert!(secret_epoch_2.is_some(), "Epoch 2 key should be retained");

        let manager = mdk.media_manager(group_id.clone());

        // Media from pruned epoch should no longer decrypt.
        let old_result = manager.decrypt_from_download(&old_upload.encrypted_data, &old_ref);
        assert!(
            matches!(
                old_result,
                Err(EncryptedMediaError::DecryptionFailed { .. })
            ),
            "Expected old media decryption to fail after lookback cleanup, got: {:?}",
            old_result
        );

        // Media from retained epoch should still decrypt via stored epoch hint secret.
        let recent_decrypted = manager
            .decrypt_from_download(&recent_upload.encrypted_data, &recent_ref)
            .unwrap();
        assert_eq!(recent_decrypted, recent_data);
    }

    /// Verifies that media encrypted after processing an incoming commit (remote epoch
    /// advancement) can still be decrypted after further epoch changes. This ensures
    /// the incoming commit path persisted the MIP-04 exporter secret for that epoch.
    #[test]
    fn test_decrypt_media_from_incoming_commit_epoch_after_epoch_advancement() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let charlie_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();
        let charlie_mdk = create_test_mdk();

        let bob_key_package = create_key_package_event(&bob_mdk, &bob_keys);
        let charlie_key_package = create_key_package_event(&charlie_mdk, &charlie_keys);

        let create_result = alice_mdk
            .create_group(
                &alice_keys.public_key(),
                vec![bob_key_package],
                create_nostr_group_config_data(vec![alice_keys.public_key()]),
            )
            .unwrap();

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk.merge_pending_commit(&group_id).unwrap();

        let bob_welcome = bob_mdk
            .process_welcome(&EventId::all_zeros(), &create_result.welcome_rumors[0])
            .unwrap();
        bob_mdk.accept_welcome(&bob_welcome).unwrap();

        let add_charlie_result = alice_mdk
            .add_members(&group_id, &[charlie_key_package])
            .unwrap();
        alice_mdk.merge_pending_commit(&group_id).unwrap();

        // Bob processes Alice's incoming commit: this exercises `process_commit`.
        bob_mdk
            .process_message(&add_charlie_result.evolution_event)
            .unwrap();

        // Encrypt media at Bob's current epoch (the epoch reached via incoming commit).
        let manager = bob_mdk.media_manager(group_id.clone());
        let data = b"media encrypted after incoming commit";
        let upload = manager
            .encrypt_for_upload(data, "text/plain", "incoming_epoch.txt")
            .unwrap();
        let media_ref = manager
            .create_media_reference(&upload, "https://example.com/incoming-epoch".to_string());
        let encryption_epoch = store_imeta_message(
            &bob_mdk,
            &group_id,
            &upload,
            bob_keys.public_key(),
            "https://example.com/incoming-epoch",
        );

        // Advance to a later epoch so decryption must use stored epoch-hint secret.
        bob_mdk.self_update(&group_id).unwrap();
        bob_mdk.merge_pending_commit(&group_id).unwrap();

        let bob_current_epoch = bob_mdk.get_group(&group_id).unwrap().unwrap().epoch;
        assert!(bob_current_epoch > encryption_epoch);

        let manager = bob_mdk.media_manager(group_id);
        let decrypted = manager
            .decrypt_from_download(&upload.encrypted_data, &media_ref)
            .unwrap();
        assert_eq!(decrypted, data);
    }

    /// Verifies that the legacy key-derivation fallback (pre-0.7.1 HKDF extract+expand)
    /// is accepted before the migration deadline.
    #[test]
    fn test_legacy_media_key_derivation_accepted_before_deadline() {
        let (mdk, group_id, alice_keys) = setup_group();

        let data = b"legacy key derivation test";
        let original_hash: [u8; 32] = sha2::Sha256::digest(data).into();
        let legacy_secret = mdk
            .legacy_exporter_secret(&group_id)
            .expect("Should derive legacy exporter secret");
        let key = derive_legacy_encryption_key_with_secret(
            &legacy_secret.secret,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy.txt",
        )
        .expect("Should derive legacy media key");
        let nonce = generate_encryption_nonce();
        let encrypted_data = encrypt_data_with_aad(
            data,
            &key,
            &nonce,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy.txt",
        )
        .expect("Should encrypt with legacy key");

        let reference = MediaReference {
            url: "https://example.com/legacy".to_string(),
            original_hash,
            mime_type: "text/plain".to_string(),
            filename: "legacy.txt".to_string(),
            dimensions: None,
            scheme_version: DEFAULT_SCHEME_VERSION.to_string(),
            nonce: *nonce,
        };

        let manager = mdk.media_manager(group_id.clone());
        store_imeta_message(
            &mdk,
            &group_id,
            &EncryptedMediaUpload {
                encrypted_data: encrypted_data.clone(),
                original_hash,
                encrypted_hash: sha2::Sha256::digest(&encrypted_data).into(),
                mime_type: "text/plain".to_string(),
                filename: "legacy.txt".to_string(),
                original_size: data.len() as u64,
                encrypted_size: encrypted_data.len() as u64,
                dimensions: None,
                blurhash: None,
                thumbhash: None,
                nonce: *nonce,
            },
            alice_keys.public_key(),
            "https://example.com/legacy",
        );

        // Before the deadline the legacy key-derivation path must succeed.
        let result =
            manager.decrypt_from_download_at(&encrypted_data, &reference, fixed_pre_deadline_ts());
        assert!(
            result.is_ok(),
            "Legacy media key derivation must be accepted before the deadline, got: {:?}",
            result
        );
        assert_eq!(result.unwrap(), data);
    }

    /// Verifies that the legacy key-derivation fallback is rejected after the migration
    /// deadline. Media that can only be decrypted with the pre-0.7.1 HKDF path must
    /// fail once the deadline has passed.
    #[test]
    fn test_legacy_media_key_derivation_rejected_after_deadline() {
        let (mdk, group_id, alice_keys) = setup_group();

        let data = b"post-deadline legacy key derivation test";
        let original_hash: [u8; 32] = sha2::Sha256::digest(data).into();
        let legacy_secret = mdk
            .legacy_exporter_secret(&group_id)
            .expect("Should derive legacy exporter secret");
        let key = derive_legacy_encryption_key_with_secret(
            &legacy_secret.secret,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-post.txt",
        )
        .expect("Should derive legacy media key");
        let nonce = generate_encryption_nonce();
        let encrypted_data = encrypt_data_with_aad(
            data,
            &key,
            &nonce,
            DEFAULT_SCHEME_VERSION,
            &original_hash,
            "text/plain",
            "legacy-post.txt",
        )
        .expect("Should encrypt with legacy key");

        let reference = MediaReference {
            url: "https://example.com/legacy-post".to_string(),
            original_hash,
            mime_type: "text/plain".to_string(),
            filename: "legacy-post.txt".to_string(),
            dimensions: None,
            scheme_version: DEFAULT_SCHEME_VERSION.to_string(),
            nonce: *nonce,
        };

        let manager = mdk.media_manager(group_id.clone());
        store_imeta_message(
            &mdk,
            &group_id,
            &EncryptedMediaUpload {
                encrypted_data: encrypted_data.clone(),
                original_hash,
                encrypted_hash: sha2::Sha256::digest(&encrypted_data).into(),
                mime_type: "text/plain".to_string(),
                filename: "legacy-post.txt".to_string(),
                original_size: data.len() as u64,
                encrypted_size: encrypted_data.len() as u64,
                dimensions: None,
                blurhash: None,
                thumbhash: None,
                nonce: *nonce,
            },
            alice_keys.public_key(),
            "https://example.com/legacy-post",
        );

        // After the deadline the legacy key-derivation fallback must be suppressed.
        let result =
            manager.decrypt_from_download_at(&encrypted_data, &reference, fixed_post_deadline_ts());
        assert!(
            result.is_err(),
            "Legacy media key derivation must be rejected after the deadline"
        );
    }

    /// Verifies that the allow_legacy_media_fallback_at gate functions correctly at
    /// the boundary values.
    #[test]
    fn test_allow_legacy_media_fallback_at_boundary() {
        type Manager<'a> = EncryptedMediaManager<'a, MdkMemoryStorage>;

        assert!(
            Manager::allow_legacy_media_fallback_at(LEGACY_MEDIA_MIGRATION_DEADLINE),
            "Should allow legacy at exactly the deadline"
        );
        assert!(
            Manager::allow_legacy_media_fallback_at(fixed_pre_deadline_ts()),
            "Should allow legacy before the deadline"
        );
        assert!(
            !Manager::allow_legacy_media_fallback_at(fixed_post_deadline_ts()),
            "Should reject legacy after the deadline"
        );
    }
}
