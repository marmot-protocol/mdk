//! MIP-04 encrypted media functions.
//!
//! These functions require an `MdkHandle` and a group ID because encryption
//! keys are derived from the group's MLS exporter secret.

use std::os::raw::c_char;

use mdk_core::encrypted_media::types::{
    EncryptedMediaUpload, MediaProcessingOptions, MediaReference,
};
use nostr::{Tag as NostrTag, TagKind};

use crate::error::{self, MdkError};
use crate::types::{
    MdkHandle, cstr_to_str, deref_handle, ffi_try_unwind_safe, lock_handle, parse_group_id,
    parse_json, require_non_null, to_json, write_cstring_to,
};

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// JSON metadata returned alongside the encrypted bytes from
/// [`mdk_encrypt_media`] and [`mdk_encrypt_media_with_options`].
///
/// The `encrypted_data` blob is returned separately (via byte out-params)
/// to avoid base64-encoding potentially 100 MB of data.
#[derive(serde::Serialize, serde::Deserialize)]
struct EncryptedMediaMetadataJson {
    original_hash: String,
    encrypted_hash: String,
    mime_type: String,
    filename: String,
    original_size: u64,
    encrypted_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<[u32; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blurhash: Option<String>,
    nonce: String,
}

impl From<&EncryptedMediaUpload> for EncryptedMediaMetadataJson {
    fn from(u: &EncryptedMediaUpload) -> Self {
        Self {
            original_hash: hex::encode(u.original_hash),
            encrypted_hash: hex::encode(u.encrypted_hash),
            mime_type: u.mime_type.clone(),
            filename: u.filename.clone(),
            original_size: u.original_size,
            encrypted_size: u.encrypted_size,
            dimensions: u.dimensions.map(|(w, h)| [w, h]),
            blurhash: u.blurhash.clone(),
            nonce: hex::encode(u.nonce),
        }
    }
}

/// JSON representation of a [`MediaReference`].
#[derive(serde::Serialize, serde::Deserialize)]
struct MediaReferenceJson {
    url: String,
    original_hash: String,
    mime_type: String,
    filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<[u32; 2]>,
    scheme_version: String,
    nonce: String,
}

impl From<&MediaReference> for MediaReferenceJson {
    fn from(r: &MediaReference) -> Self {
        Self {
            url: r.url.clone(),
            original_hash: hex::encode(r.original_hash),
            mime_type: r.mime_type.clone(),
            filename: r.filename.clone(),
            dimensions: r.dimensions.map(|(w, h)| [w, h]),
            scheme_version: r.scheme_version.clone(),
            nonce: hex::encode(r.nonce),
        }
    }
}

impl TryFrom<&MediaReferenceJson> for MediaReference {
    type Error = MdkError;

    fn try_from(j: &MediaReferenceJson) -> Result<Self, Self::Error> {
        Ok(Self {
            url: j.url.clone(),
            original_hash: decode_hash(&j.original_hash)?,
            mime_type: j.mime_type.clone(),
            filename: j.filename.clone(),
            dimensions: j.dimensions.map(|d| (d[0], d[1])),
            scheme_version: j.scheme_version.clone(),
            nonce: decode_nonce(&j.nonce)?,
        })
    }
}

/// JSON representation of [`MediaProcessingOptions`].
#[derive(serde::Deserialize)]
struct MediaProcessingOptionsJson {
    #[serde(default = "default_true")]
    sanitize_exif: bool,
    #[serde(default = "default_true")]
    generate_blurhash: bool,
    #[serde(default)]
    max_dimension: Option<u32>,
    #[serde(default)]
    max_file_size: Option<usize>,
    #[serde(default)]
    max_filename_length: Option<usize>,
}

fn default_true() -> bool {
    true
}

impl From<&MediaProcessingOptionsJson> for MediaProcessingOptions {
    fn from(j: &MediaProcessingOptionsJson) -> Self {
        Self {
            sanitize_exif: j.sanitize_exif,
            generate_blurhash: j.generate_blurhash,
            max_dimension: j.max_dimension,
            max_file_size: j.max_file_size,
            max_filename_length: j.max_filename_length,
        }
    }
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn decode_hash(hex_str: &str) -> Result<[u8; 32], MdkError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| error::invalid_input(&format!("Invalid hash hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(error::invalid_input(&format!(
            "Hash must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn decode_nonce(hex_str: &str) -> Result<[u8; 12], MdkError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| error::invalid_input(&format!("Invalid nonce hex: {e}")))?;
    if bytes.len() != 12 {
        return Err(error::invalid_input(&format!(
            "Nonce must be 12 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 12];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Map an encrypted media error to an [`MdkError`].
fn from_media_error(e: mdk_core::encrypted_media::types::EncryptedMediaError) -> MdkError {
    tracing::debug!("Encrypted media error (suppressed in FFI message): {e}");
    error::set_last_error(&format!("Encrypted media error: {e}"));
    MdkError::Mdk
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Encrypt media for upload using default processing options.
///
/// The encrypted data is returned via the `out_data` / `out_data_len` byte
/// out-params (caller frees with `mdk_bytes_free`).  Metadata (hashes, MIME
/// type, dimensions, nonce, etc.) is returned as a JSON string in
/// `out_meta_json` (caller frees with `mdk_string_free`).
///
/// # Parameters
///
/// * `h`              — MDK handle.
/// * `mls_group_id`   — Hex-encoded MLS group ID.
/// * `data` / `data_len` — Raw media bytes.
/// * `mime`           — MIME type (e.g. `"image/jpeg"`).
/// * `filename`       — Original filename.
/// * `out_data`       — Receives the encrypted bytes.
/// * `out_data_len`   — Receives the length of the encrypted bytes.
/// * `out_meta_json`  — Receives a JSON string with encryption metadata.
///
/// # Safety
///
/// `data` must point to at least `data_len` readable bytes.
/// All other pointer arguments must be valid and non-null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_encrypt_media(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    data: *const u8,
    data_len: usize,
    mime: *const c_char,
    filename: *const c_char,
    out_data: *mut *mut u8,
    out_data_len: *mut usize,
    out_meta_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(data, "data");
        require_non_null!(out_data, "out_data");
        require_non_null!(out_data_len, "out_data_len");
        require_non_null!(out_meta_json, "out_meta_json");

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let media_bytes = unsafe { std::slice::from_raw_parts(data, data_len) };
        let mime_str = unsafe { cstr_to_str(mime) }?;
        let filename_str = unsafe { cstr_to_str(filename) }?;

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let upload = manager
            .encrypt_for_upload(media_bytes, mime_str, filename_str)
            .map_err(from_media_error)?;

        write_encrypt_output(&upload, out_data, out_data_len, out_meta_json)
    })
}

/// Encrypt media for upload with custom processing options.
///
/// Same as [`mdk_encrypt_media`] but accepts a JSON options object
/// controlling EXIF sanitisation, blurhash generation, size limits, etc.
///
/// # Parameters
///
/// * `options_json` — JSON object with optional fields:
///   `sanitize_exif` (bool), `generate_blurhash` (bool),
///   `max_dimension` (u32), `max_file_size` (usize),
///   `max_filename_length` (usize).
///   Pass null for defaults.
///
/// # Safety
///
/// Same as [`mdk_encrypt_media`].
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_encrypt_media_with_options(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    data: *const u8,
    data_len: usize,
    mime: *const c_char,
    filename: *const c_char,
    options_json: *const c_char,
    out_data: *mut *mut u8,
    out_data_len: *mut usize,
    out_meta_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(data, "data");
        require_non_null!(out_data, "out_data");
        require_non_null!(out_data_len, "out_data_len");
        require_non_null!(out_meta_json, "out_meta_json");

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let media_bytes = unsafe { std::slice::from_raw_parts(data, data_len) };
        let mime_str = unsafe { cstr_to_str(mime) }?;
        let filename_str = unsafe { cstr_to_str(filename) }?;

        let options = if options_json.is_null() {
            MediaProcessingOptions::default()
        } else {
            let opts: MediaProcessingOptionsJson = parse_json(
                unsafe { cstr_to_str(options_json) }?,
                "media processing options",
            )?;
            MediaProcessingOptions::from(&opts)
        };

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let upload = manager
            .encrypt_for_upload_with_options(media_bytes, mime_str, filename_str, &options)
            .map_err(from_media_error)?;

        write_encrypt_output(&upload, out_data, out_data_len, out_meta_json)
    })
}

/// Shared helper to write encrypt results to FFI out-params.
#[allow(unsafe_code)]
fn write_encrypt_output(
    upload: &EncryptedMediaUpload,
    out_data: *mut *mut u8,
    out_data_len: *mut usize,
    out_meta_json: *mut *mut c_char,
) -> Result<(), MdkError> {
    let meta = EncryptedMediaMetadataJson::from(upload);
    let json = to_json(&meta)?;

    let len = upload.encrypted_data.len();
    let boxed = upload.encrypted_data.clone().into_boxed_slice();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        *out_data = ptr;
        *out_data_len = len;
        write_cstring_to(out_meta_json, json)
    }
}

/// Decrypt downloaded encrypted media.
///
/// # Parameters
///
/// * `h`                  — MDK handle.
/// * `mls_group_id`       — Hex-encoded MLS group ID.
/// * `data` / `data_len`  — Encrypted media bytes.
/// * `reference_json`     — JSON object describing the media reference
///   (url, original_hash, mime_type, filename, dimensions, scheme_version, nonce).
/// * `out` / `out_len`    — Receives decrypted media bytes
///   (caller frees with `mdk_bytes_free`).
///
/// # Safety
///
/// `data` must point to at least `data_len` readable bytes.
/// All other pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_decrypt_media(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    data: *const u8,
    data_len: usize,
    reference_json: *const c_char,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(data, "data");
        require_non_null!(out, "out");
        require_non_null!(out_len, "out_len");

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let encrypted = unsafe { std::slice::from_raw_parts(data, data_len) };
        let ref_json: MediaReferenceJson = parse_json(
            unsafe { cstr_to_str(reference_json) }?,
            "media reference JSON",
        )?;
        let reference = MediaReference::try_from(&ref_json)?;

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let decrypted = manager
            .decrypt_from_download(encrypted, &reference)
            .map_err(from_media_error)?;

        let len = decrypted.len();
        let boxed = decrypted.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;
        unsafe {
            *out = ptr;
            *out_len = len;
        }
        Ok(())
    })
}

/// Create an IMETA tag for encrypted media after upload.
///
/// The returned JSON is a Nostr tag array (e.g.
/// `["imeta", "url ...", "m ...", ...]`).
///
/// # Parameters
///
/// * `h`              — MDK handle.
/// * `mls_group_id`   — Hex-encoded MLS group ID.
/// * `meta_json`      — Metadata JSON as returned by `mdk_encrypt_media`.
/// * `uploaded_url`   — The URL where the encrypted data was uploaded.
/// * `out_json`       — Receives the IMETA tag as a JSON array string.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_imeta_tag(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    meta_json: *const c_char,
    uploaded_url: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        unsafe { *out_json = std::ptr::null_mut() };

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let meta: EncryptedMediaMetadataJson = parse_json(
            unsafe { cstr_to_str(meta_json) }?,
            "encryption metadata JSON",
        )?;
        let url_str = unsafe { cstr_to_str(uploaded_url) }?;

        // Reconstruct the EncryptedMediaUpload from metadata.
        // We don't need encrypted_data for IMETA tag creation.
        let upload = upload_from_meta(&meta)?;

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let tag = manager.create_imeta_tag(&upload, url_str);

        let json = to_json(&tag)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Create a media reference from upload metadata.
///
/// Returns a JSON object with all fields needed for later decryption.
///
/// # Parameters
///
/// * `h`              — MDK handle.
/// * `mls_group_id`   — Hex-encoded MLS group ID.
/// * `meta_json`      — Metadata JSON as returned by `mdk_encrypt_media`.
/// * `uploaded_url`   — The URL where the encrypted data was uploaded.
/// * `out_json`       — Receives the media reference JSON.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_media_reference(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    meta_json: *const c_char,
    uploaded_url: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        unsafe { *out_json = std::ptr::null_mut() };

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let meta: EncryptedMediaMetadataJson = parse_json(
            unsafe { cstr_to_str(meta_json) }?,
            "encryption metadata JSON",
        )?;
        let url_str = unsafe { cstr_to_str(uploaded_url) }?.to_string();

        let upload = upload_from_meta(&meta)?;

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let reference = manager.create_media_reference(&upload, url_str);

        let ref_json = MediaReferenceJson::from(&reference);
        let json = to_json(&ref_json)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Parse an IMETA tag to extract a media reference for decryption.
///
/// # Parameters
///
/// * `h`              — MDK handle.
/// * `mls_group_id`   — Hex-encoded MLS group ID.
/// * `imeta_tag_json` — JSON array representing the IMETA Nostr tag
///   (e.g. `["imeta", "url ...", "m ...", ...]`).
/// * `out_json`       — Receives the parsed media reference JSON.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_parse_imeta_tag(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    imeta_tag_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        unsafe { *out_json = std::ptr::null_mut() };

        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;

        // Parse the JSON array into tag values.
        let tag_values: Vec<String> = parse_json(
            unsafe { cstr_to_str(imeta_tag_json) }?,
            "IMETA tag JSON array",
        )?;

        // Reconstruct the NostrTag.  The first element should be "imeta".
        if tag_values.is_empty() || tag_values[0] != "imeta" {
            return Err(error::invalid_input(
                "IMETA tag JSON must start with \"imeta\"",
            ));
        }
        let tag = NostrTag::custom(TagKind::Custom("imeta".into()), tag_values[1..].to_vec());

        let mdk = lock_handle(handle)?;
        let manager = mdk.media_manager(gid);
        let reference = manager.parse_imeta_tag(&tag).map_err(from_media_error)?;

        let ref_json = MediaReferenceJson::from(&reference);
        let json = to_json(&ref_json)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Reconstruct an [`EncryptedMediaUpload`] from metadata JSON.
///
/// `encrypted_data` is set to an empty vec — it is not needed for
/// IMETA tag or media reference creation.
fn upload_from_meta(meta: &EncryptedMediaMetadataJson) -> Result<EncryptedMediaUpload, MdkError> {
    Ok(EncryptedMediaUpload {
        encrypted_data: Vec::new(),
        original_hash: decode_hash(&meta.original_hash)?,
        encrypted_hash: decode_hash(&meta.encrypted_hash)?,
        mime_type: meta.mime_type.clone(),
        filename: meta.filename.clone(),
        original_size: meta.original_size,
        encrypted_size: meta.encrypted_size,
        dimensions: meta.dimensions.map(|d| (d[0], d[1])),
        blurhash: meta.blurhash.clone(),
        nonce: decode_nonce(&meta.nonce)?,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    // ── Serialisation roundtrips ─────────────────────────────────────────

    #[test]
    fn metadata_json_roundtrip() {
        let upload = EncryptedMediaUpload {
            encrypted_data: vec![1, 2, 3],
            original_hash: [0x42; 32],
            encrypted_hash: [0x43; 32],
            mime_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            original_size: 1000,
            encrypted_size: 1016,
            dimensions: Some((1920, 1080)),
            blurhash: Some("LKO2?U%2Tw".to_string()),
            nonce: [0xAA; 12],
        };

        let meta = EncryptedMediaMetadataJson::from(&upload);
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: EncryptedMediaMetadataJson = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.original_hash, hex::encode([0x42; 32]));
        assert_eq!(parsed.encrypted_hash, hex::encode([0x43; 32]));
        assert_eq!(parsed.mime_type, "image/jpeg");
        assert_eq!(parsed.filename, "test.jpg");
        assert_eq!(parsed.original_size, 1000);
        assert_eq!(parsed.encrypted_size, 1016);
        assert_eq!(parsed.dimensions, Some([1920, 1080]));
        assert_eq!(parsed.blurhash.as_deref(), Some("LKO2?U%2Tw"));
        assert_eq!(parsed.nonce, hex::encode([0xAA; 12]));
    }

    #[test]
    fn metadata_json_no_optional_fields() {
        let upload = EncryptedMediaUpload {
            encrypted_data: vec![],
            original_hash: [0x01; 32],
            encrypted_hash: [0x02; 32],
            mime_type: "application/pdf".to_string(),
            filename: "doc.pdf".to_string(),
            original_size: 500,
            encrypted_size: 516,
            dimensions: None,
            blurhash: None,
            nonce: [0xBB; 12],
        };

        let meta = EncryptedMediaMetadataJson::from(&upload);
        let json = serde_json::to_string(&meta).unwrap();

        // Verify optional fields are absent
        assert!(!json.contains("dimensions"));
        assert!(!json.contains("blurhash"));
    }

    #[test]
    fn media_reference_json_roundtrip() {
        let reference = MediaReference {
            url: "https://example.com/file.enc".to_string(),
            original_hash: [0x42; 32],
            mime_type: "image/png".to_string(),
            filename: "photo.png".to_string(),
            dimensions: Some((800, 600)),
            scheme_version: "mip04-v2".to_string(),
            nonce: [0xCC; 12],
        };

        let json_repr = MediaReferenceJson::from(&reference);
        let json = serde_json::to_string(&json_repr).unwrap();
        let parsed: MediaReferenceJson = serde_json::from_str(&json).unwrap();
        let back = MediaReference::try_from(&parsed).unwrap();

        assert_eq!(back.url, reference.url);
        assert_eq!(back.original_hash, reference.original_hash);
        assert_eq!(back.mime_type, reference.mime_type);
        assert_eq!(back.filename, reference.filename);
        assert_eq!(back.dimensions, reference.dimensions);
        assert_eq!(back.scheme_version, reference.scheme_version);
        assert_eq!(back.nonce, reference.nonce);
    }

    #[test]
    fn upload_from_meta_roundtrip() {
        let meta = EncryptedMediaMetadataJson {
            original_hash: hex::encode([0x42; 32]),
            encrypted_hash: hex::encode([0x43; 32]),
            mime_type: "image/webp".to_string(),
            filename: "img.webp".to_string(),
            original_size: 2000,
            encrypted_size: 2016,
            dimensions: Some([640, 480]),
            blurhash: None,
            nonce: hex::encode([0xDD; 12]),
        };

        let upload = upload_from_meta(&meta).unwrap();
        assert_eq!(upload.original_hash, [0x42; 32]);
        assert_eq!(upload.encrypted_hash, [0x43; 32]);
        assert_eq!(upload.mime_type, "image/webp");
        assert_eq!(upload.filename, "img.webp");
        assert_eq!(upload.dimensions, Some((640, 480)));
        assert_eq!(upload.nonce, [0xDD; 12]);
        assert!(upload.encrypted_data.is_empty());
    }

    // ── Hex decode errors ───────────────────────────────────────────────

    #[test]
    fn decode_hash_invalid_hex() {
        assert!(decode_hash("ZZZZ").is_err());
    }

    #[test]
    fn decode_hash_wrong_length() {
        assert!(decode_hash(&hex::encode([0u8; 16])).is_err());
    }

    #[test]
    fn decode_nonce_invalid_hex() {
        assert!(decode_nonce("ZZZZ").is_err());
    }

    #[test]
    fn decode_nonce_wrong_length() {
        assert!(decode_nonce(&hex::encode([0u8; 8])).is_err());
    }

    // ── Processing options defaults ─────────────────────────────────────

    #[test]
    fn options_json_defaults() {
        let json = "{}";
        let opts: MediaProcessingOptionsJson = serde_json::from_str(json).unwrap();
        assert!(opts.sanitize_exif);
        assert!(opts.generate_blurhash);
        assert!(opts.max_dimension.is_none());
        assert!(opts.max_file_size.is_none());
        assert!(opts.max_filename_length.is_none());
    }

    #[test]
    fn options_json_custom() {
        let json = r#"{"sanitize_exif": false, "max_dimension": 1024}"#;
        let opts: MediaProcessingOptionsJson = serde_json::from_str(json).unwrap();
        assert!(!opts.sanitize_exif);
        assert!(opts.generate_blurhash);
        assert_eq!(opts.max_dimension, Some(1024));
    }

    // ── Null-pointer guards ─────────────────────────────────────────────

    #[test]
    fn encrypt_media_null_data() {
        let mut out_data: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let mut out_meta: *mut c_char = std::ptr::null_mut();
        let mime = std::ffi::CString::new("image/png").unwrap();
        let fname = std::ffi::CString::new("test.png").unwrap();
        let gid = std::ffi::CString::new("aa").unwrap();

        let code = unsafe {
            mdk_encrypt_media(
                std::ptr::null_mut(), // null handle
                gid.as_ptr(),
                std::ptr::null(), // null data
                100,
                mime.as_ptr(),
                fname.as_ptr(),
                &mut out_data,
                &mut out_len,
                &mut out_meta,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn encrypt_media_null_out_data() {
        let mime = std::ffi::CString::new("image/png").unwrap();
        let fname = std::ffi::CString::new("test.png").unwrap();
        let gid = std::ffi::CString::new("aa").unwrap();
        let data = [0u8; 10];
        let mut out_len: usize = 0;
        let mut out_meta: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_encrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                data.as_ptr(),
                data.len(),
                mime.as_ptr(),
                fname.as_ptr(),
                std::ptr::null_mut(), // null out_data
                &mut out_len,
                &mut out_meta,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn encrypt_media_null_out_len() {
        let mime = std::ffi::CString::new("image/png").unwrap();
        let fname = std::ffi::CString::new("test.png").unwrap();
        let gid = std::ffi::CString::new("aa").unwrap();
        let data = [0u8; 10];
        let mut out_data: *mut u8 = std::ptr::null_mut();
        let mut out_meta: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_encrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                data.as_ptr(),
                data.len(),
                mime.as_ptr(),
                fname.as_ptr(),
                &mut out_data,
                std::ptr::null_mut(), // null out_data_len
                &mut out_meta,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn encrypt_media_null_out_meta() {
        let mime = std::ffi::CString::new("image/png").unwrap();
        let fname = std::ffi::CString::new("test.png").unwrap();
        let gid = std::ffi::CString::new("aa").unwrap();
        let data = [0u8; 10];
        let mut out_data: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_encrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                data.as_ptr(),
                data.len(),
                mime.as_ptr(),
                fname.as_ptr(),
                &mut out_data,
                &mut out_len,
                std::ptr::null_mut(), // null out_meta_json
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn encrypt_media_with_options_null_data() {
        let mut out_data: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let mut out_meta: *mut c_char = std::ptr::null_mut();
        let mime = std::ffi::CString::new("image/png").unwrap();
        let fname = std::ffi::CString::new("test.png").unwrap();
        let gid = std::ffi::CString::new("aa").unwrap();

        let code = unsafe {
            mdk_encrypt_media_with_options(
                std::ptr::null_mut(),
                gid.as_ptr(),
                std::ptr::null(),
                100,
                mime.as_ptr(),
                fname.as_ptr(),
                std::ptr::null(), // null options (OK)
                &mut out_data,
                &mut out_len,
                &mut out_meta,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_media_null_data() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let ref_json = std::ffi::CString::new("{}").unwrap();
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                std::ptr::null(),
                10,
                ref_json.as_ptr(),
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_media_null_out() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let ref_json = std::ffi::CString::new("{}").unwrap();
        let data = [0u8; 64];
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                data.as_ptr(),
                data.len(),
                ref_json.as_ptr(),
                std::ptr::null_mut(),
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_media_null_out_len() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let ref_json = std::ffi::CString::new("{}").unwrap();
        let data = [0u8; 64];
        let mut out: *mut u8 = std::ptr::null_mut();

        let code = unsafe {
            mdk_decrypt_media(
                std::ptr::null_mut(),
                gid.as_ptr(),
                data.as_ptr(),
                data.len(),
                ref_json.as_ptr(),
                &mut out,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn create_imeta_tag_null_handle() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let meta = std::ffi::CString::new("{}").unwrap();
        let url = std::ffi::CString::new("https://example.com").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_create_imeta_tag(
                std::ptr::null_mut(),
                gid.as_ptr(),
                meta.as_ptr(),
                url.as_ptr(),
                &mut out,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn create_imeta_tag_null_out() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let meta = std::ffi::CString::new("{}").unwrap();
        let url = std::ffi::CString::new("https://example.com").unwrap();

        let code = unsafe {
            mdk_create_imeta_tag(
                std::ptr::null_mut(),
                gid.as_ptr(),
                meta.as_ptr(),
                url.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn create_media_reference_null_handle() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let meta = std::ffi::CString::new("{}").unwrap();
        let url = std::ffi::CString::new("https://example.com").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_create_media_reference(
                std::ptr::null_mut(),
                gid.as_ptr(),
                meta.as_ptr(),
                url.as_ptr(),
                &mut out,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn create_media_reference_null_out() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let meta = std::ffi::CString::new("{}").unwrap();
        let url = std::ffi::CString::new("https://example.com").unwrap();

        let code = unsafe {
            mdk_create_media_reference(
                std::ptr::null_mut(),
                gid.as_ptr(),
                meta.as_ptr(),
                url.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn parse_imeta_tag_null_handle() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let tag = std::ffi::CString::new(r#"["imeta","url https://example.com"]"#).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_parse_imeta_tag(std::ptr::null_mut(), gid.as_ptr(), tag.as_ptr(), &mut out)
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn parse_imeta_tag_null_out() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let tag = std::ffi::CString::new(r#"["imeta"]"#).unwrap();

        let code = unsafe {
            mdk_parse_imeta_tag(
                std::ptr::null_mut(),
                gid.as_ptr(),
                tag.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn parse_imeta_tag_invalid_json() {
        let gid = std::ffi::CString::new("aa").unwrap();
        let tag = std::ffi::CString::new("not json").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();

        let code = unsafe {
            mdk_parse_imeta_tag(std::ptr::null_mut(), gid.as_ptr(), tag.as_ptr(), &mut out)
        };
        // NullPointer because handle is null (checked first)
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn parse_imeta_tag_not_imeta() {
        // Need a real handle for this test
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let c_path = std::ffi::CString::new(db_path.to_str().unwrap()).unwrap();
        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code =
            unsafe { crate::mdk_new_unencrypted(c_path.as_ptr(), std::ptr::null(), &mut handle) };
        assert_eq!(code, MdkError::Ok);

        let gid = std::ffi::CString::new(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let tag = std::ffi::CString::new(r#"["wrong","url https://example.com"]"#).unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();

        let code = unsafe { mdk_parse_imeta_tag(handle, gid.as_ptr(), tag.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::InvalidInput);

        unsafe { crate::mdk_free(handle) };
    }
}
