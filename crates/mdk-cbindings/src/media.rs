//! Free functions for group image encryption/decryption.
//!
//! These are **not** methods on `MdkHandle` — they operate purely on data
//! without group state.

use std::ffi::CString;
use std::os::raw::c_char;

use mdk_core::extension::group_image::{
    decrypt_group_image as core_decrypt, derive_upload_keypair as core_derive_upload_keypair,
    prepare_group_image_for_upload as core_prepare,
};
use zeroize::Zeroize;

use crate::error::{self, MdkError};
use crate::types::{cstr_to_str, ffi_try_unwind_safe, require_non_null, to_json, write_cstring_to};

// ---------------------------------------------------------------------------
// Serialisation helper
// ---------------------------------------------------------------------------

/// JSON representation returned by [`mdk_prepare_group_image`].
///
/// The upload secret key is intentionally **not** included here.
/// Callers must use [`mdk_derive_upload_keypair`] to obtain the upload
/// keypair from the `image_key` returned in this struct.
///
/// # Security
///
/// `image_key` and `image_nonce` contain secret material.  The struct
/// implements [`Zeroize`] so callers **must** call `.zeroize()` once the
/// JSON has been serialized.
#[derive(serde::Serialize)]
struct PreparedImageJson {
    encrypted_data: Vec<u8>,
    encrypted_hash: Vec<u8>,
    image_key: Vec<u8>,
    image_nonce: Vec<u8>,
    original_size: u64,
    encrypted_size: u64,
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<[u32; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blurhash: Option<String>,
}

impl Zeroize for PreparedImageJson {
    fn zeroize(&mut self) {
        self.image_key.zeroize();
        self.image_nonce.zeroize();
        // encrypted_data is ciphertext, not secret; no need to zeroize.
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Prepare a group image for upload to Blossom.
///
/// Encrypts the image and returns the encrypted data together with the
/// encryption key and metadata as a JSON string.  The returned JSON does
/// **not** include the upload secret key — callers must derive the upload
/// keypair separately via [`mdk_derive_upload_keypair`] using the
/// `image_key` from the returned JSON.
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

        let prepared = core_prepare(image_bytes, mime_str).map_err(|_| {
            tracing::warn!("Prepare group image failed");
            error::set_last_error("Prepare group image failed");
            MdkError::Mdk
        })?;

        let mut result = PreparedImageJson {
            encrypted_hash: prepared.encrypted_hash.to_vec(),
            image_key: prepared.image_key.as_ref().to_vec(),
            image_nonce: prepared.image_nonce.as_ref().to_vec(),
            original_size: prepared.original_size as u64,
            encrypted_size: prepared.encrypted_size as u64,
            mime_type: prepared.mime_type,
            dimensions: prepared.dimensions.map(|(w, h)| [w, h]),
            blurhash: prepared.blurhash,
            encrypted_data: prepared.encrypted_data.to_vec(),
        };

        let json = to_json(&result);
        result.zeroize();
        let json = json?;
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
///   (caller must free with `mdk_bytes_free`).
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
        let key_secret = mdk_storage_traits::Secret::new(key_arr);
        key_arr.zeroize();

        if nonce_len != 12 {
            return Err(error::invalid_input("Image nonce must be 12 bytes"));
        }
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(unsafe { std::slice::from_raw_parts(nonce, 12) });
        let nonce_secret = mdk_storage_traits::Secret::new(nonce_arr);
        nonce_arr.zeroize();

        let decrypted = core_decrypt(encrypted, hash_opt.as_ref(), &key_secret, &nonce_secret)
            .map_err(|_| {
                tracing::warn!("Decrypt group image failed");
                error::set_last_error("Decrypt group image failed");
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
        let key_secret = mdk_storage_traits::Secret::new(key_arr);
        key_arr.zeroize();

        let keys = core_derive_upload_keypair(&key_secret, version).map_err(|_| {
            tracing::warn!("Derive upload keypair failed");
            error::set_last_error("Derive upload keypair failed");
            MdkError::Mdk
        })?;

        // Convert to CString first, then zeroize the intermediate String.
        // The CString now owns the only copy; it will be freed by the
        // caller via `mdk_string_free`.
        let mut hex = keys.secret_key().to_secret_hex();
        let c = CString::new(hex.as_str()).map_err(|e| {
            hex.zeroize();
            error::invalid_input(&format!("String contained null byte: {e}"))
        })?;
        hex.zeroize();
        unsafe {
            *out = c.into_raw();
        }
        Ok(())
    })
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    // ── PreparedImageJson zeroization ────────────────────────────────────

    #[test]
    fn prepared_image_json_zeroize_clears_secrets() {
        let mut p = PreparedImageJson {
            encrypted_data: vec![1, 2, 3],
            encrypted_hash: vec![4, 5, 6],
            image_key: vec![0xAA; 32],
            image_nonce: vec![0xBB; 12],
            original_size: 100,
            encrypted_size: 200,
            mime_type: "image/png".to_string(),
            dimensions: Some([640, 480]),
            blurhash: None,
        };
        p.zeroize();

        assert!(
            p.image_key.iter().all(|&b| b == 0),
            "image_key must be zeroed"
        );
        assert!(
            p.image_nonce.iter().all(|&b| b == 0),
            "image_nonce must be zeroed"
        );
        // encrypted_data is ciphertext, not secret — should be untouched.
        assert_eq!(p.encrypted_data, vec![1, 2, 3]);
    }

    // ── Input validation ────────────────────────────────────────────────

    #[test]
    fn decrypt_null_data_returns_null_pointer() {
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let key = [0u8; 32];
        let nonce = [0u8; 12];

        let code = unsafe {
            mdk_decrypt_group_image(
                std::ptr::null(),
                10,
                std::ptr::null(),
                0,
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_null_key_returns_null_pointer() {
        let data = [0u8; 64];
        let nonce = [0u8; 12];
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_group_image(
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                32,
                nonce.as_ptr(),
                12,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_null_nonce_returns_null_pointer() {
        let data = [0u8; 64];
        let key = [0u8; 32];
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_group_image(
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                key.as_ptr(),
                32,
                std::ptr::null(),
                12,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn decrypt_wrong_key_len_returns_invalid_input() {
        let data = [0u8; 64];
        let key = [0u8; 16]; // Wrong length
        let nonce = [0u8; 12];
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_group_image(
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                key.as_ptr(),
                key.len(),
                nonce.as_ptr(),
                12,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::InvalidInput);
    }

    #[test]
    fn decrypt_wrong_nonce_len_returns_invalid_input() {
        let data = [0u8; 64];
        let key = [0u8; 32];
        let nonce = [0u8; 8]; // Wrong length
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_group_image(
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                nonce.len(),
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::InvalidInput);
    }

    #[test]
    fn decrypt_wrong_hash_len_returns_invalid_input() {
        let data = [0u8; 64];
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let hash = [0u8; 16]; // Wrong length
        let mut out: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;

        let code = unsafe {
            mdk_decrypt_group_image(
                data.as_ptr(),
                data.len(),
                hash.as_ptr(),
                hash.len(),
                key.as_ptr(),
                32,
                nonce.as_ptr(),
                12,
                &mut out,
                &mut out_len,
            )
        };
        assert_eq!(code, MdkError::InvalidInput);
    }

    #[test]
    fn derive_keypair_null_key_returns_null_pointer() {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { mdk_derive_upload_keypair(std::ptr::null(), 32, 2, &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn derive_keypair_wrong_key_len_returns_invalid_input() {
        let key = [0u8; 16]; // Wrong length
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { mdk_derive_upload_keypair(key.as_ptr(), key.len(), 2, &mut out) };
        assert_eq!(code, MdkError::InvalidInput);
    }

    #[test]
    fn derive_keypair_null_out_returns_null_pointer() {
        let key = [0u8; 32];
        let code = unsafe { mdk_derive_upload_keypair(key.as_ptr(), 32, 2, std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn prepare_null_data_returns_null_pointer() {
        let mime = std::ffi::CString::new("image/png").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code =
            unsafe { mdk_prepare_group_image(std::ptr::null(), 100, mime.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn prepare_null_out_returns_null_pointer() {
        let data = [0u8; 10];
        let mime = std::ffi::CString::new("image/png").unwrap();
        let code = unsafe {
            mdk_prepare_group_image(
                data.as_ptr(),
                data.len(),
                mime.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }
}
