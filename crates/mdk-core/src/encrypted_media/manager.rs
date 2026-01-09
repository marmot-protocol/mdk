//! Main encrypted media manager
//!
//! This module contains the EncryptedMediaManager struct which provides the
//! high-level API for encrypting, decrypting, and managing encrypted media
//! within MLS groups on Nostr.

use nostr::{Tag as NostrTag, TagKind};
use sha2::{Digest, Sha256};

use crate::encrypted_media::crypto::{
    decrypt_data_with_aad, derive_encryption_key, encrypt_data_with_aad, generate_encryption_nonce,
};
use crate::encrypted_media::metadata::extract_and_process_metadata;
use crate::encrypted_media::types::{
    EncryptedMediaError, EncryptedMediaUpload, MediaProcessingOptions, MediaReference,
};
use crate::media_processing::validation;
use crate::{GroupId, MDK};
use mdk_storage_traits::MdkStorageProvider;

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
        let canonical_mime_type = validation::validate_mime_type(mime_type)?;
        validation::validate_filename(filename)?;

        // Extract metadata and optionally sanitize the file
        // If sanitize_exif is true, processed_data will have EXIF stripped
        // If sanitize_exif is false, processed_data will be the original with EXIF intact
        let (processed_data, metadata) =
            extract_and_process_metadata(data, &canonical_mime_type, options)?;

        // Calculate hash of the PROCESSED (potentially sanitized) data
        // This ensures the hash is of the clean file, not the original with EXIF
        let original_hash: [u8; 32] = Sha256::digest(&processed_data).into();
        let encryption_key = derive_encryption_key(
            self.mdk,
            &self.group_id,
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
            nonce: *nonce,
        })
    }

    /// Decrypt downloaded media
    ///
    /// The filename for AAD is taken from the MediaReference, which was parsed from the imeta tag.
    pub fn decrypt_from_download(
        &self,
        encrypted_data: &[u8],
        reference: &MediaReference,
    ) -> Result<Vec<u8>, EncryptedMediaError> {
        let encryption_key = derive_encryption_key(
            self.mdk,
            &self.group_id,
            &reference.original_hash,
            &reference.mime_type,
            &reference.filename,
        )?;
        let decrypted_data = decrypt_data_with_aad(
            encrypted_data,
            &encryption_key,
            &mdk_storage_traits::Secret::new(reference.nonce),
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

    /// Create an imeta tag for encrypted media (after upload)
    ///
    /// Creates IMETA tag according to Marmot protocol 04.md specification:
    /// imeta url \<storage_url\> m \<mime_type\> filename \<original_filename\> [dim \<dimensions\>] [blurhash \<blurhash\>] x \<file_hash_hex\> n \<nonce_hex\> v \<version\>
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

        // x field contains SHA256 hash of original file content (hex-encoded)
        tag_values.push(format!("x {}", hex::encode(upload.original_hash)));

        // n field contains the encryption nonce (hex-encoded, 24 hex chars for 12 bytes)
        tag_values.push(format!("n {}", hex::encode(upload.nonce)));

        // v field contains encryption version number (currently "mip04-v2")
        tag_values.push("v mip04-v2".to_string());

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
            nonce: upload.nonce,
        }
    }

    /// Parse an IMETA tag to create a MediaReference for decryption
    ///
    /// Expected IMETA format: url \<storage_url\> m \<mime_type\> filename \<filename\> x \<file_hash_hex\> n \<nonce_hex\> v \<version\> [dim \<dimensions\>] [blurhash \<blurhash\>]
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
                "blurhash" => {
                    // Blurhash is optional and not needed for decryption
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

        // Validate version (required field, currently only support mip04-v2)
        let version = version.ok_or(EncryptedMediaError::InvalidImetaTag {
            reason: "Missing required 'v' (version) field".to_string(),
        })?;
        if version != "mip04-v2" {
            return Err(EncryptedMediaError::DecryptionFailed {
                reason: format!("Unsupported MIP-04 encryption version: {}", version),
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
    use mdk_memory_storage::MdkMemoryStorage;

    fn create_test_mdk() -> MDK<MdkMemoryStorage> {
        MDK::new(MdkMemoryStorage::default())
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
            "blurhash LKO2?U%2Tw=w]~RBVZRi};RPxuwH".to_string(),
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
        assert_eq!(media_ref.nonce, test_nonce);
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
            nonce: test_nonce,
        };

        let media_ref = manager
            .create_media_reference(&upload, "https://cdn.example.com/image.png".to_string());

        assert_eq!(media_ref.url, "https://cdn.example.com/image.png");
        assert_eq!(media_ref.original_hash, [0x42; 32]);
        assert_eq!(media_ref.mime_type, "image/png");
        assert_eq!(media_ref.filename, "test.png");
        assert_eq!(media_ref.dimensions, Some((800, 600)));
        assert_eq!(media_ref.nonce, test_nonce);
    }

    #[test]
    fn test_encrypt_for_upload_accepts_any_mime_type() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test data (not real files, but that's fine for this test)
        let test_data = vec![0u8; 1000];
        // Use options that skip metadata extraction for images to avoid format errors
        let options = MediaProcessingOptions {
            sanitize_exif: true,
            generate_blurhash: false,
            max_dimension: None,
            max_file_size: None,
            max_filename_length: None,
        };

        // Test with various non-image MIME types - all should pass validation
        let test_cases = vec![
            ("application/pdf", "document.pdf"),
            ("video/quicktime", "video.mov"),
            ("audio/mpeg", "song.mp3"),
            ("text/plain", "note.txt"),
            ("application/octet-stream", "file.bin"),
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

        // Verify the MIME type was canonicalized to lowercase
        assert_eq!(media_ref.mime_type, "image/jpeg");
        assert_eq!(media_ref.url, "https://example.com/encrypted.jpg");
        assert_eq!(media_ref.filename, "photo.jpg");
        assert_eq!(media_ref.original_hash, [0x42; 32]);

        // The canonicalized MIME type should now work correctly for key derivation
        // and decryption operations (even though we can't test the full flow without
        // a real MLS group, we can verify the MediaReference structure is correct)
    }

    #[test]
    fn test_parse_imeta_tag_with_invalid_mime_type() {
        let mdk = create_test_mdk();
        let group_id = GroupId::from_slice(&[1, 2, 3, 4]);
        let manager = mdk.media_manager(group_id);

        // Test parsing IMETA tag with any MIME type (all should be accepted)
        let test_nonce1 = [0x66; 12];
        let tag_values = vec![
            "url https://example.com/test.pdf".to_string(),
            "m application/pdf".to_string(),
            "filename document.pdf".to_string(),
            format!("x {}", hex::encode([0x46; 32])),
            format!("n {}", hex::encode(test_nonce1)),
            "v mip04-v2".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_ok());
        let media_ref = result.unwrap();
        assert_eq!(media_ref.mime_type, "application/pdf");

        // Test parsing IMETA tag with invalid MIME type format (no slash)
        let test_nonce2 = [0x77; 12];
        let tag_values = vec![
            "url https://example.com/test.file".to_string(),
            "m invalid".to_string(), // Invalid format
            "filename test.file".to_string(),
            format!("x {}", hex::encode([0x47; 32])),
            format!("n {}", hex::encode(test_nonce2)),
            "v mip04-v2".to_string(),
        ];
        let imeta_tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values);

        let result = manager.parse_imeta_tag(&imeta_tag);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EncryptedMediaError::InvalidImetaTag { .. })
        ));
    }

    // ============================================================================
    // Encrypted Media (MIP-04) Integration Tests
    // ============================================================================

    /// Multi-Device Media Encryption
    ///
    /// Validates that encrypted media can be decrypted across different devices
    /// in the same group using the group's exporter secret within the same epoch.
    #[test]
    fn test_media_encryption_across_devices() {
        use nostr::Keys;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Create key package for Bob only (not Alice, as she's the creator)
        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);

        // Alice creates group with Bob
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Bob joins the group
        let bob_welcome_rumor = &create_result.welcome_rumors[0];
        let bob_welcome = bob_mdk
            .process_welcome(&nostr::EventId::all_zeros(), bob_welcome_rumor)
            .expect("Bob should process welcome");

        bob_mdk
            .accept_welcome(&bob_welcome)
            .expect("Bob should accept welcome");

        // Test media file - use text/plain for simple test data
        let test_media = b"Test media data for cross-device encryption";

        let alice_manager = alice_mdk.media_manager(group_id.clone());
        let upload_result = alice_manager
            .encrypt_for_upload(test_media, "text/plain", "document.txt")
            .expect("Alice should encrypt media");

        let encrypted_data = upload_result.encrypted_data.clone();

        // Create media reference for Bob
        let media_ref = alice_manager.create_media_reference(
            &upload_result,
            "https://storage.example.com/file1.enc".to_string(),
        );

        // Bob decrypts media using his instance of the same group
        let bob_manager = bob_mdk.media_manager(group_id.clone());
        let decrypted_data = bob_manager
            .decrypt_from_download(&encrypted_data, &media_ref)
            .expect("Bob should decrypt media");

        assert_eq!(
            decrypted_data, test_media,
            "Decrypted data should match original"
        );

        // Verify Bob can also decrypt the original media (cross-device access)
        let bob_decrypted_again = bob_manager
            .decrypt_from_download(&encrypted_data, &media_ref)
            .expect("Bob should be able to decrypt media multiple times");

        assert_eq!(
            bob_decrypted_again, test_media,
            "Bob's second decryption should match original"
        );
    }

    /// Large Media File Encryption
    ///
    /// Validates that large media files can be encrypted and decrypted successfully
    /// without memory issues.
    #[test]
    fn test_large_media_file_encryption() {
        use nostr::Keys;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        // Alice creates a group with Bob for testing
        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);

        // Create key package for Bob (not Alice, as she's the creator)
        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        // Create a 1MB test file (not 10MB to keep tests fast)
        let large_media = vec![0xAB; 1024 * 1024]; // 1MB

        let manager = alice_mdk.media_manager(group_id.clone());

        // Encrypt the large file
        let upload_result = manager
            .encrypt_for_upload(&large_media, "video/mp4", "large_video.mp4")
            .expect("Should encrypt large file");

        assert_eq!(
            upload_result.original_size,
            1024 * 1024,
            "Original size should be 1MB"
        );

        // The encrypted size should be slightly larger due to authentication tag
        assert!(
            upload_result.encrypted_size > upload_result.original_size,
            "Encrypted size should be larger than original"
        );

        // Decrypt the large file
        let encrypted_data = upload_result.encrypted_data.clone();
        let media_ref = manager
            .create_media_reference(&upload_result, "https://example.com/video.enc".to_string());

        let decrypted_data = manager
            .decrypt_from_download(&encrypted_data, &media_ref)
            .expect("Should decrypt large file");

        assert_eq!(
            decrypted_data.len(),
            large_media.len(),
            "Decrypted size should match original"
        );
        assert_eq!(
            decrypted_data, large_media,
            "Decrypted data should match original"
        );
    }

    /// Media Metadata Validation
    ///
    /// Validates that media metadata fields are properly validated including
    /// required fields, size limits, and format constraints.
    #[test]
    fn test_media_metadata_validation() {
        use nostr::Keys;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);

        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        let manager = alice_mdk.media_manager(group_id.clone());

        // Test 1: Valid metadata should succeed (use text/plain to match test data)
        let valid_media = b"Valid media content";
        let result = manager.encrypt_for_upload(valid_media, "text/plain", "document.txt");
        assert!(result.is_ok(), "Valid metadata should succeed");

        // Test 2: Invalid MIME type should fail
        let result = manager.encrypt_for_upload(valid_media, "invalid", "document.pdf");
        assert!(result.is_err(), "Invalid MIME type should fail");

        // Test 3: Empty filename should fail
        let result = manager.encrypt_for_upload(valid_media, "text/plain", "");
        assert!(result.is_err(), "Empty filename should fail");

        // Test 4: Extremely long filename should fail
        use crate::encrypted_media::MAX_FILENAME_LENGTH;
        let long_filename = "a".repeat(MAX_FILENAME_LENGTH + 1);
        let result = manager.encrypt_for_upload(valid_media, "text/plain", &long_filename);
        assert!(result.is_err(), "Overly long filename should fail");

        // Test 5: File too large should fail
        let options = crate::encrypted_media::types::MediaProcessingOptions {
            max_file_size: Some(100), // Set max to 100 bytes
            ..Default::default()
        };
        let large_media = vec![0u8; 1000]; // 1000 bytes
        let result = manager.encrypt_for_upload_with_options(
            &large_media,
            "image/jpeg",
            "test.jpg",
            &options,
        );
        assert!(result.is_err(), "File exceeding size limit should fail");
    }

    /// Media Encryption/Decryption with Hash Verification
    ///
    /// Validates that encrypted media includes hash verification and
    /// that tampering is detected.
    #[test]
    fn test_media_hash_verification() {
        use nostr::Keys;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);

        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        let test_media = b"Media content for hash verification";
        let manager = alice_mdk.media_manager(group_id.clone());

        let upload_result = manager
            .encrypt_for_upload(test_media, "text/plain", "document.txt")
            .expect("Should encrypt media");

        // Valid decryption should succeed
        let mut encrypted_data = upload_result.encrypted_data.clone();
        let media_ref = manager
            .create_media_reference(&upload_result, "https://example.com/photo.enc".to_string());

        let decrypt_result = manager.decrypt_from_download(&encrypted_data, &media_ref);
        assert!(decrypt_result.is_ok(), "Valid decryption should succeed");

        // Tamper with encrypted data
        if !encrypted_data.is_empty() {
            encrypted_data[0] ^= 0xFF; // Flip bits
        }

        // Decryption with tampered data should fail
        let decrypt_result = manager.decrypt_from_download(&encrypted_data, &media_ref);
        assert!(
            decrypt_result.is_err(),
            "Decryption of tampered data should fail"
        );

        // Test hash verification by tampering with the hash in media_ref
        let encrypted_data_valid = upload_result.encrypted_data.clone();
        let mut tampered_media_ref = media_ref.clone();
        // Replace hash with an incorrect one (all zeros)
        tampered_media_ref.original_hash = [0u8; 32];

        let hash_verify_result =
            manager.decrypt_from_download(&encrypted_data_valid, &tampered_media_ref);
        assert!(
            hash_verify_result.is_err(),
            "Decryption with incorrect hash should fail"
        );

        // The hash mismatch causes decryption to fail
        // (either during hash check or AEAD verification depending on implementation)
    }

    /// Media Encryption with Different File Types
    ///
    /// Validates that various media file types can be encrypted and decrypted,
    /// including images, videos, audio, and documents.
    #[test]
    fn test_media_encryption_various_file_types() {
        use nostr::Keys;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);

        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);

        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");

        let group_id = create_result.group.mls_group_id.clone();

        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Alice should merge commit");

        let manager = alice_mdk.media_manager(group_id.clone());

        // Use non-image MIME types to avoid metadata extraction issues with test data
        let test_cases = vec![
            ("video/mp4", "video.mp4", b"MP4 video data".as_slice()),
            ("video/quicktime", "video.mov", b"MOV video data".as_slice()),
            ("audio/mpeg", "song.mp3", b"MP3 audio data".as_slice()),
            ("audio/wav", "sound.wav", b"WAV audio data".as_slice()),
            (
                "application/pdf",
                "document.pdf",
                b"PDF document data".as_slice(),
            ),
            ("text/plain", "notes.txt", b"Plain text data".as_slice()),
        ];

        for (mime_type, filename, data) in test_cases {
            // Encrypt
            let upload_result = manager.encrypt_for_upload(data, mime_type, filename);
            assert!(upload_result.is_ok(), "Should encrypt {} file", mime_type);

            let upload = upload_result.unwrap();
            assert_eq!(upload.mime_type, mime_type);
            assert_eq!(upload.filename, filename);

            // Decrypt
            let media_ref = manager
                .create_media_reference(&upload, format!("https://example.com/{}", filename));
            let decrypt_result = manager.decrypt_from_download(&upload.encrypted_data, &media_ref);
            assert!(decrypt_result.is_ok(), "Should decrypt {} file", mime_type);

            let decrypted = decrypt_result.unwrap();
            assert_eq!(decrypted, data, "Decrypted {} data should match", mime_type);
        }
    }

    #[test]
    fn test_encryption_nonce_uniqueness() {
        use nostr::Keys;
        use std::collections::HashSet;

        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_mdk = create_test_mdk();
        let bob_mdk = create_test_mdk();

        let admin_pubkeys = vec![alice_keys.public_key()];
        let config = crate::test_util::create_nostr_group_config_data(admin_pubkeys);
        let bob_key_package = crate::test_util::create_key_package_event(&bob_mdk, &bob_keys);
        let create_result = alice_mdk
            .create_group(&alice_keys.public_key(), vec![bob_key_package], config)
            .expect("Alice should create group");
        let group_id = create_result.group.mls_group_id.clone();
        alice_mdk
            .merge_pending_commit(&group_id)
            .expect("Merge commit");

        let manager = alice_mdk.media_manager(group_id.clone());
        let test_data = b"Test data";

        // Encrypt same data multiple times
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let upload = manager
                .encrypt_for_upload(test_data, "text/plain", "test.txt")
                .expect("Should encrypt");
            assert!(nonces.insert(upload.nonce), "Nonce should be unique");
        }
        assert_eq!(nonces.len(), 100, "All 100 nonces should be unique");
    }
}
