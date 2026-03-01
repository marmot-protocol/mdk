//! Key package management functions.

use std::os::raw::c_char;

use nostr::Event;

use crate::error::{self, MdkError};
use crate::types::{
    MdkHandle, cstr_to_str, deref_handle, ffi_try_unwind_safe, lock_handle, parse_json,
    parse_public_key, parse_relay_urls, require_non_null, to_json, write_cstring_to,
};

// ---------------------------------------------------------------------------
// Serialisation helper
// ---------------------------------------------------------------------------

/// JSON representation of a key-package result (mirrors UniFFI's
/// `KeyPackageResult`).
#[derive(serde::Serialize)]
struct KeyPackageResultJson {
    key_package: String,
    tags: Vec<Vec<String>>,
    hash_ref: Vec<u8>,
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Create a key package for a Nostr event.
///
/// Does **not** add the NIP-70 protected tag for maximum relay compatibility.
/// Use [`mdk_create_key_package_with_options`] if you need the protected tag.
///
/// On success, `*out_json` receives a JSON object with fields
/// `key_package`, `tags`, and `hash_ref`.
///
/// # Safety
///
/// All pointer arguments must be valid.  `out_json` must not be null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_key_package(
    h: *mut MdkHandle,
    pubkey: *const c_char,
    relays_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let pk = parse_public_key(unsafe { cstr_to_str(pubkey) }?)?;
        let relays = parse_relay_urls(unsafe { cstr_to_str(relays_json) }?)?;

        let mdk = lock_handle(handle)?;
        let (kp_hex, tags, hash_ref) = mdk
            .create_key_package_for_event(&pk, relays)
            .map_err(error::from_mdk_error)?;

        let tags_vec: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let result = KeyPackageResultJson {
            key_package: kp_hex,
            tags: tags_vec,
            hash_ref,
        };
        let json = to_json(&result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Create a key package for a Nostr event with additional options.
///
/// # Parameters
///
/// * `protected_` — When `true`, adds the NIP-70 protected tag.
///
/// # Safety
///
/// Same as [`mdk_create_key_package`].
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_key_package_with_options(
    h: *mut MdkHandle,
    pubkey: *const c_char,
    relays_json: *const c_char,
    protected_: bool,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let pk = parse_public_key(unsafe { cstr_to_str(pubkey) }?)?;
        let relays = parse_relay_urls(unsafe { cstr_to_str(relays_json) }?)?;

        let mdk = lock_handle(handle)?;
        let (kp_hex, tags, hash_ref) = mdk
            .create_key_package_for_event_with_options(&pk, relays, protected_)
            .map_err(error::from_mdk_error)?;

        let tags_vec: Vec<Vec<String>> = tags.iter().map(|t| t.as_slice().to_vec()).collect();
        let result = KeyPackageResultJson {
            key_package: kp_hex,
            tags: tags_vec,
            hash_ref,
        };
        let json = to_json(&result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Parse a key package from a Nostr event.
///
/// On success, `*out` receives the key-package content string (the event's
/// `content` field, after validation).
///
/// # Safety
///
/// All pointer arguments must be valid. `out` must not be null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_parse_key_package(
    h: *mut MdkHandle,
    event_json: *const c_char,
    out: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out, "out");
        let event: Event = parse_json(unsafe { cstr_to_str(event_json) }?, "event JSON")?;

        let mdk = lock_handle(handle)?;
        mdk.parse_key_package(&event)
            .map_err(error::from_mdk_error)?;

        unsafe { write_cstring_to(out, event.content.clone()) }
    })
}
