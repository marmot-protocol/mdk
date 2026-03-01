//! Free functions for group image encryption/decryption.
//!
//! These are **not** methods on `MdkHandle` — they operate purely on data
//! without group state.

use std::os::raw::c_char;

use mdk_core::extension::group_image::{
    decrypt_group_image as core_decrypt, derive_upload_keypair as core_derive_upload_keypair,
    prepare_group_image_for_upload as core_prepare,
};

use crate::error::{self, MdkError};
use crate::types::{cstr_to_str, ffi_try_unwind_safe, require_non_null, to_json, write_cstring_to};

// ---------------------------------------------------------------------------
// Serialisation helper
// ---------------------------------------------------------------------------

/// JSON representation returned by [`mdk_prepare_group_image`].
///
/// # Security Note
///
/// `upload_secret_key` is serialised as a plain hex string. Because this
/// struct is immediately JSON-serialised and the JSON string is handed back
/// to the caller, the secret key will briefly reside in a regular heap
/// `String` that is not zeroised on drop. This is an inherent limitation of
/// returning secret material through a JSON-over-FFI interface. Callers
/// that need stronger guarantees should use the dedicated
/// [`mdk_derive_upload_keypair`] function and handle the key material on
/// their side of the FFI boundary.
#[derive(serde::Serialize)]
struct PreparedImageJson {
    encrypted_data: Vec<u8>,
    encrypted_hash: Vec<u8>,
    image_key: Vec<u8>,
    image_nonce: Vec<u8>,
    upload_secret_key: String,
    original_size: u64,
    encrypted_size: u64,
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<[u32; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blurhash: Option<String>,
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Prepare a group image for upload to Blossom.
///
/// Encrypts the image, derives the upload keypair, and returns everything
/// needed to publish the image as a JSON string.
///
/// # Parameters
///
/// * `data`     — Raw image bytes.
/// * `len`      — Length of `data`.
/// * `mime`     — MIME type (e.g. `"image/png"`).
/// * `out_json` — Receives a JSON object with encrypted data and metadata.
///
/// # Safety
///
/// `data` must point to at least `len` readable bytes. Other pointer
/// arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_prepare_group_image(
    data: *const u8,
    len: usize,
    mime: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        require_non_null!(data, "data");
        require_non_null!(out_json, "out_json");
        let image_bytes = unsafe { std::slice::from_raw_parts(data, len) };
        let mime_str = unsafe { cstr_to_str(mime) }?;

        let prepared = core_prepare(image_bytes, mime_str).map_err(|e| {
            error::set_last_error(&format!("Prepare group image failed: {e}"));
            MdkError::Mdk
        })?;

        let result = PreparedImageJson {
            encrypted_hash: prepared.encrypted_hash.to_vec(),
            image_key: prepared.image_key.as_ref().to_vec(),
            image_nonce: prepared.image_nonce.as_ref().to_vec(),
            upload_secret_key: prepared.upload_keypair.secret_key().to_secret_hex(),
            original_size: prepared.original_size as u64,
            encrypted_size: prepared.encrypted_size as u64,
            mime_type: prepared.mime_type,
            dimensions: prepared.dimensions.map(|(w, h)| [w, h]),
            blurhash: prepared.blurhash,
            encrypted_data: prepared.encrypted_data.to_vec(),
        };

        let json = to_json(&result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Decrypt a group image.
///
/// # Parameters
///
/// * `data` / `data_len` — Encrypted image data.
/// * `hash` / `hash_len` — Expected SHA-256 hash (32 bytes), or null to skip verification.
/// * `key` / `key_len`   — 32-byte encryption key.
/// * `nonce` / `nonce_len` — 12-byte nonce.
/// * `out` / `out_len`   — On success, receives the decrypted image bytes
///   (caller must free with [`mdk_bytes_free`](crate::free::mdk_bytes_free)).
///
/// # Safety
///
/// All data pointers must point to at least their corresponding `*_len` bytes.
/// `hash` may be null (no hash verification). `out` and `out_len` must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_decrypt_group_image(
    data: *const u8,
    data_len: usize,
    hash: *const u8,
    hash_len: usize,
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        require_non_null!(data, "data");
        require_non_null!(key, "key");
        require_non_null!(nonce, "nonce");
        require_non_null!(out, "out");
        require_non_null!(out_len, "out_len");

        let encrypted = unsafe { std::slice::from_raw_parts(data, data_len) };

        let hash_opt: Option<[u8; 32]> = if hash.is_null() {
            None
        } else {
            if hash_len != 32 {
                return Err(error::invalid_input("Expected hash must be 32 bytes"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(unsafe { std::slice::from_raw_parts(hash, 32) });
            Some(arr)
        };

        if key_len != 32 {
            return Err(error::invalid_input("Image key must be 32 bytes"));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(unsafe { std::slice::from_raw_parts(key, 32) });

        if nonce_len != 12 {
            return Err(error::invalid_input("Image nonce must be 12 bytes"));
        }
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(unsafe { std::slice::from_raw_parts(nonce, 12) });

        let decrypted = core_decrypt(
            encrypted,
            hash_opt.as_ref(),
            &mdk_storage_traits::Secret::new(key_arr),
            &mdk_storage_traits::Secret::new(nonce_arr),
        )
        .map_err(|e| {
            error::set_last_error(&format!("Decrypt group image failed: {e}"));
            MdkError::Mdk
        })?;

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

/// Derive an upload keypair from an image key.
///
/// Returns the secret key as a hex string.
///
/// # Parameters
///
/// * `key` / `key_len` — 32-byte image encryption key.
/// * `version`         — Version number for key derivation.
/// * `out`             — Receives a hex-encoded secret key string.
///
/// # Safety
///
/// `key` must point to at least `key_len` bytes. `out` must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_derive_upload_keypair(
    key: *const u8,
    key_len: usize,
    version: u16,
    out: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        require_non_null!(key, "key");
        require_non_null!(out, "out");
        if key_len != 32 {
            return Err(error::invalid_input("Image key must be 32 bytes"));
        }

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(unsafe { std::slice::from_raw_parts(key, 32) });

        let keys = core_derive_upload_keypair(&mdk_storage_traits::Secret::new(key_arr), version)
            .map_err(|e| {
            error::set_last_error(&format!("Derive upload keypair failed: {e}"));
            MdkError::Mdk
        })?;

        let hex = keys.secret_key().to_secret_hex();
        unsafe { write_cstring_to(out, hex) }
    })
}
