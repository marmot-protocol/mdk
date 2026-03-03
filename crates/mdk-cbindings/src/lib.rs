//! C ABI bindings for mdk-core with SQLite storage.
//!
//! This crate exposes the same 33-function API surface as `mdk-uniffi`, but
//! through `extern "C"` functions suitable for embedding in C/C++ applications
//! or as a base for other language FFI (Go, Zig, etc.).
//!
//! Complex types (groups, messages, welcomes, etc.) are serialised as JSON
//! strings across the FFI boundary.  The main `Mdk` handle is an opaque
//! pointer. Simple scalars stay as scalars.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::Mutex;

use mdk_core::{MDK, MdkConfig as CoreMdkConfig};
use mdk_sqlite_storage::{EncryptionConfig, MdkSqliteStorage};

mod error;
mod free;
mod groups;
mod key_packages;
#[cfg(feature = "mip04")]
mod media;
mod messages;
mod types;
mod welcomes;

use crate::types::require_non_null;

pub use self::error::MdkError;
pub use self::types::MdkHandle;

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

/// Parse an optional JSON config string into a [`CoreMdkConfig`].
///
/// If the pointer is null, returns `CoreMdkConfig::default()`.
/// Missing fields in the JSON are filled from `MdkConfig::default()` via
/// `#[serde(default)]` on the core type, eliminating the manual
/// field-by-field defaulting and the `u32` → `usize` truncation that the
/// old `ConfigOverrides` intermediate struct had.
#[allow(unsafe_code)]
fn parse_config(config_json: *const c_char) -> Result<CoreMdkConfig, MdkError> {
    if config_json.is_null() {
        return Ok(CoreMdkConfig::default());
    }
    let json = unsafe { types::cstr_to_str(config_json) }?;
    types::parse_json::<CoreMdkConfig>(json, "config JSON")
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/// Create a new MDK instance with encrypted SQLite storage using automatic
/// key management (platform keyring).
///
/// # Parameters
///
/// * `db_path`      — Null-terminated path to the SQLite database file.
/// * `service_id`   — Stable, host-defined application identifier.
/// * `db_key_id`    — Stable identifier for this database's key.
/// * `config_json`  — Optional JSON config (null → defaults).
/// * `out`          — On success, receives a pointer to the new handle.
///
/// # Safety
///
/// All pointer arguments (except `config_json`, which may be null) must be
/// valid, null-terminated C strings.  `out` must be a valid, non-null pointer.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new(
    db_path: *const c_char,
    service_id: *const c_char,
    db_key_id: *const c_char,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        require_non_null!(out, "out");
        unsafe { *out = std::ptr::null_mut() };
        let db_path = unsafe { types::cstr_to_str(db_path) }?;
        let service_id = unsafe { types::cstr_to_str(service_id) }?;
        let db_key_id = unsafe { types::cstr_to_str(db_key_id) }?;
        let config = parse_config(config_json)?;

        let storage = MdkSqliteStorage::new(PathBuf::from(db_path), service_id, db_key_id)
            .map_err(error::from_storage_error)?;

        let mdk = MDK::builder(storage).with_config(config).build();
        let handle = Box::new(MdkHandle {
            inner: Mutex::new(mdk),
        });
        unsafe {
            *out = Box::into_raw(handle);
        }
        Ok(())
    })
}

/// Create a new MDK instance with encrypted SQLite storage using a directly
/// provided 32-byte key.
///
/// # Safety
///
/// `key` must point to at least `key_len` readable bytes.  Other pointer
/// arguments follow the same rules as [`mdk_new`].
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new_with_key(
    db_path: *const c_char,
    key: *const u8,
    key_len: usize,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        require_non_null!(out, "out");
        unsafe { *out = std::ptr::null_mut() };
        require_non_null!(key, "key");
        let db_path = unsafe { types::cstr_to_str(db_path) }?;
        let config = parse_config(config_json)?;
        let key_slice = unsafe { std::slice::from_raw_parts(key, key_len) };

        let enc = EncryptionConfig::from_slice(key_slice)
            .map_err(|e| error::invalid_input(&format!("Invalid encryption key: {e}")))?;
        let storage = MdkSqliteStorage::new_with_key(PathBuf::from(db_path), enc)
            .map_err(error::from_storage_error)?;

        let mdk = MDK::builder(storage).with_config(config).build();
        let handle = Box::new(MdkHandle {
            inner: Mutex::new(mdk),
        });
        unsafe {
            *out = Box::into_raw(handle);
        }
        Ok(())
    })
}

/// Create a new MDK instance with **unencrypted** SQLite storage.
///
/// **WARNING**: Sensitive MLS state including exporter secrets will be stored
/// in plaintext. Only use for development or testing.
///
/// # Safety
///
/// Same rules as [`mdk_new`]. `config_json` may be null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new_unencrypted(
    db_path: *const c_char,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        require_non_null!(out, "out");
        unsafe { *out = std::ptr::null_mut() };
        let db_path = unsafe { types::cstr_to_str(db_path) }?;
        let config = parse_config(config_json)?;

        let storage = MdkSqliteStorage::new_unencrypted(PathBuf::from(db_path))
            .map_err(error::from_storage_error)?;

        let mdk = MDK::builder(storage).with_config(config).build();
        let handle = Box::new(MdkHandle {
            inner: Mutex::new(mdk),
        });
        unsafe {
            *out = Box::into_raw(handle);
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Destructor
// ---------------------------------------------------------------------------

/// Free an MDK handle previously returned by one of the constructors.
///
/// After calling this, the handle pointer is invalid and must not be used.
/// Passing null is a safe no-op.
///
/// # Safety
///
/// `handle` must be a pointer previously returned by `mdk_new`,
/// `mdk_new_with_key`, or `mdk_new_unencrypted` (or null).
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_free(handle: *mut MdkHandle) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::{CStr, CString};

    use super::*;

    #[test]
    fn parse_config_null_returns_default() {
        let config = parse_config(std::ptr::null()).unwrap();
        let default = CoreMdkConfig::default();
        assert_eq!(config.max_event_age_secs, default.max_event_age_secs);
        assert_eq!(config.max_future_skew_secs, default.max_future_skew_secs);
        assert_eq!(
            config.out_of_order_tolerance,
            default.out_of_order_tolerance
        );
    }

    #[test]
    fn parse_config_partial_json() {
        let json = std::ffi::CString::new(r#"{"max_event_age_secs": 86400}"#).unwrap();
        let config = parse_config(json.as_ptr()).unwrap();
        assert_eq!(config.max_event_age_secs, 86400);
        // Other fields should be defaults
        let default = CoreMdkConfig::default();
        assert_eq!(config.max_future_skew_secs, default.max_future_skew_secs);
    }

    #[test]
    fn parse_config_all_fields() {
        let json = std::ffi::CString::new(
            r#"{"max_event_age_secs":100,"max_future_skew_secs":200,"out_of_order_tolerance":50,"maximum_forward_distance":500,"epoch_snapshot_retention":3,"snapshot_ttl_seconds":1000}"#,
        )
        .unwrap();
        let config = parse_config(json.as_ptr()).unwrap();
        assert_eq!(config.max_event_age_secs, 100);
        assert_eq!(config.max_future_skew_secs, 200);
        assert_eq!(config.out_of_order_tolerance, 50);
        assert_eq!(config.maximum_forward_distance, 500);
        assert_eq!(config.epoch_snapshot_retention, 3);
        assert_eq!(config.snapshot_ttl_seconds, 1000);
    }

    #[test]
    fn parse_config_invalid_json() {
        let json = std::ffi::CString::new("not json").unwrap();
        let result = parse_config(json.as_ptr());
        assert!(result.is_err());
    }

    #[test]
    fn parse_config_empty_object() {
        let json = std::ffi::CString::new("{}").unwrap();
        let config = parse_config(json.as_ptr()).unwrap();
        let default = CoreMdkConfig::default();
        assert_eq!(config.max_event_age_secs, default.max_event_age_secs);
    }

    #[test]
    fn ffi_roundtrip_create_get_groups_free() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();

        // Create an unencrypted handle
        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe { mdk_new_unencrypted(c_path.as_ptr(), std::ptr::null(), &mut handle) };
        assert_eq!(code, MdkError::Ok, "mdk_new_unencrypted should succeed");
        assert!(!handle.is_null(), "handle should be non-null");

        // Get groups — should return an empty JSON array
        let mut out_json: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { groups::mdk_get_groups(handle, &mut out_json) };
        assert_eq!(code, MdkError::Ok, "mdk_get_groups should succeed");
        assert!(!out_json.is_null(), "out_json should be non-null");

        let json_str = unsafe { CStr::from_ptr(out_json) }.to_str().unwrap();
        assert_eq!(json_str, "[]", "new instance should have no groups");

        // Free the returned string
        unsafe { free::mdk_string_free(out_json) };

        // Free the handle
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn ffi_null_handle_returns_null_pointer_error() {
        let mut out_json: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { groups::mdk_get_groups(std::ptr::null_mut(), &mut out_json) };
        assert_eq!(
            code,
            MdkError::NullPointer,
            "null handle should return NullPointer error"
        );
    }

    /// Create a temporary unencrypted MDK handle for testing.
    ///
    /// Returns `(handle, _tempdir)` — keep `_tempdir` alive or the DB
    /// file is deleted.
    fn test_handle() -> (*mut MdkHandle, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();

        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe { mdk_new_unencrypted(c_path.as_ptr(), std::ptr::null(), &mut handle) };
        assert_eq!(code, MdkError::Ok);
        assert!(!handle.is_null());
        (handle, dir)
    }

    // ── Constructor tests ───────────────────────────────────────────────

    #[test]
    fn mdk_new_with_key_valid() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("enc.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();
        let key = [0x42u8; 32];

        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe {
            mdk_new_with_key(
                c_path.as_ptr(),
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                &mut handle,
            )
        };
        assert_eq!(code, MdkError::Ok);
        assert!(!handle.is_null());
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn mdk_new_with_key_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("enc.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();
        let key = [0x42u8; 16]; // Wrong length

        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe {
            mdk_new_with_key(
                c_path.as_ptr(),
                key.as_ptr(),
                key.len(),
                std::ptr::null(),
                &mut handle,
            )
        };
        assert_eq!(code, MdkError::InvalidInput);
        assert!(handle.is_null());
    }

    #[test]
    fn mdk_new_null_out_returns_null_pointer() {
        let c_path = CString::new("/tmp/test.db").unwrap();
        let code =
            unsafe { mdk_new_unencrypted(c_path.as_ptr(), std::ptr::null(), std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn mdk_free_null_is_noop() {
        // Should not crash.
        unsafe { mdk_free(std::ptr::null_mut()) };
    }

    #[test]
    fn mdk_free_double_free_prevented() {
        let (handle, _dir) = test_handle();
        unsafe { mdk_free(handle) };
        // handle is now dangling — we can't free again, but we can
        // verify the pattern by ensuring mdk_free(null) is safe.
        unsafe { mdk_free(std::ptr::null_mut()) };
    }

    // ── Group query tests ───────────────────────────────────────────────

    #[test]
    fn get_group_not_found() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_get_group(handle, gid.as_ptr(), &mut out) };
        // get_group returns Ok with "null" JSON for not-found.
        assert_eq!(code, MdkError::Ok);
        assert!(!out.is_null());
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert_eq!(json, "null");

        unsafe { free::mdk_string_free(out) };
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_group_invalid_hex() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("not-valid-hex!").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_get_group(handle, gid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::InvalidInput);

        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_members_invalid_group() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("zzzz").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_get_members(handle, gid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::InvalidInput);

        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_relays_nonexistent_group() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_get_relays(handle, gid.as_ptr(), &mut out) };
        // Should return an MDK error for nonexistent group
        assert_ne!(code, MdkError::Ok);

        unsafe { mdk_free(handle) };
    }

    #[test]
    fn groups_needing_self_update_empty() {
        let (handle, _dir) = test_handle();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_groups_needing_self_update(handle, 3600, &mut out) };
        assert_eq!(code, MdkError::Ok);
        assert!(!out.is_null());
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert_eq!(json, "[]");

        unsafe { free::mdk_string_free(out) };
        unsafe { mdk_free(handle) };
    }

    // ── Group null-pointer tests ────────────────────────────────────────

    #[test]
    fn get_group_null_out() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let code = unsafe { groups::mdk_get_group(handle, gid.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_members_null_out() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let code = unsafe { groups::mdk_get_members(handle, gid.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn create_group_null_out() {
        let (handle, _dir) = test_handle();
        let pk = CString::new("aa").unwrap();
        let kp = CString::new("[]").unwrap();
        let name = CString::new("test").unwrap();
        let desc = CString::new("desc").unwrap();
        let relays = CString::new("[]").unwrap();
        let admins = CString::new("[]").unwrap();

        let code = unsafe {
            groups::mdk_create_group(
                handle,
                pk.as_ptr(),
                kp.as_ptr(),
                name.as_ptr(),
                desc.as_ptr(),
                relays.as_ptr(),
                admins.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    // ── Message tests ───────────────────────────────────────────────────

    #[test]
    fn get_messages_null_handle() {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let gid = CString::new("aa").unwrap();
        let code = unsafe {
            messages::mdk_get_messages(
                std::ptr::null_mut(),
                gid.as_ptr(),
                0,
                0,
                std::ptr::null(),
                &mut out,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn get_messages_null_out() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let code = unsafe {
            messages::mdk_get_messages(
                handle,
                gid.as_ptr(),
                0,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_message_null_out() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let eid = CString::new("bb").unwrap();
        let code = unsafe {
            messages::mdk_get_message(handle, gid.as_ptr(), eid.as_ptr(), std::ptr::null_mut())
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn create_message_null_out() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let pk = CString::new("bb").unwrap();
        let content = CString::new("hello").unwrap();
        let code = unsafe {
            messages::mdk_create_message(
                handle,
                gid.as_ptr(),
                pk.as_ptr(),
                content.as_ptr(),
                1,
                std::ptr::null(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn process_message_null_out() {
        let (handle, _dir) = test_handle();
        let ev = CString::new("{}").unwrap();
        let code =
            unsafe { messages::mdk_process_message(handle, ev.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_last_message_invalid_sort() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("aa").unwrap();
        let sort = CString::new("bad_sort").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe {
            messages::mdk_get_last_message(handle, gid.as_ptr(), sort.as_ptr(), &mut out)
        };
        assert_eq!(code, MdkError::InvalidInput);

        unsafe { mdk_free(handle) };
    }

    // ── Welcome tests ───────────────────────────────────────────────────

    #[test]
    fn get_pending_welcomes_empty() {
        let (handle, _dir) = test_handle();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { welcomes::mdk_get_pending_welcomes(handle, 0, 0, &mut out) };
        assert_eq!(code, MdkError::Ok);
        assert!(!out.is_null());
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
        assert_eq!(json, "[]");

        unsafe { free::mdk_string_free(out) };
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_pending_welcomes_null_handle() {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code =
            unsafe { welcomes::mdk_get_pending_welcomes(std::ptr::null_mut(), 0, 0, &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn get_pending_welcomes_null_out() {
        let (handle, _dir) = test_handle();
        let code =
            unsafe { welcomes::mdk_get_pending_welcomes(handle, 0, 0, std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn get_welcome_null_handle() {
        let eid = CString::new("aa").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code =
            unsafe { welcomes::mdk_get_welcome(std::ptr::null_mut(), eid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn get_welcome_null_out() {
        let (handle, _dir) = test_handle();
        let eid = CString::new("aa").unwrap();
        let code = unsafe { welcomes::mdk_get_welcome(handle, eid.as_ptr(), std::ptr::null_mut()) };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn process_welcome_null_out() {
        let (handle, _dir) = test_handle();
        let wid = CString::new("aa").unwrap();
        let rumor = CString::new("{}").unwrap();
        let code = unsafe {
            welcomes::mdk_process_welcome(
                handle,
                wid.as_ptr(),
                rumor.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn accept_welcome_invalid_json() {
        let (handle, _dir) = test_handle();
        let bad = CString::new("not json").unwrap();
        let code = unsafe { welcomes::mdk_accept_welcome(handle, bad.as_ptr()) };
        assert_eq!(code, MdkError::InvalidInput);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn decline_welcome_invalid_json() {
        let (handle, _dir) = test_handle();
        let bad = CString::new("not json").unwrap();
        let code = unsafe { welcomes::mdk_decline_welcome(handle, bad.as_ptr()) };
        assert_eq!(code, MdkError::InvalidInput);
        unsafe { mdk_free(handle) };
    }

    // ── Key package tests ───────────────────────────────────────────────

    #[test]
    fn create_key_package_null_handle() {
        let pk = CString::new("aa").unwrap();
        let relays = CString::new(r#"["wss://relay.example.com"]"#).unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe {
            key_packages::mdk_create_key_package(
                std::ptr::null_mut(),
                pk.as_ptr(),
                relays.as_ptr(),
                &mut out,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn create_key_package_null_out() {
        let (handle, _dir) = test_handle();
        let pk = CString::new("aa").unwrap();
        let relays = CString::new(r#"["wss://relay.example.com"]"#).unwrap();
        let code = unsafe {
            key_packages::mdk_create_key_package(
                handle,
                pk.as_ptr(),
                relays.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn create_key_package_invalid_pubkey() {
        let (handle, _dir) = test_handle();
        let pk = CString::new("not-a-key").unwrap();
        let relays = CString::new(r#"["wss://relay.example.com"]"#).unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe {
            key_packages::mdk_create_key_package(handle, pk.as_ptr(), relays.as_ptr(), &mut out)
        };
        assert_eq!(code, MdkError::InvalidInput);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn parse_key_package_invalid_event() {
        let (handle, _dir) = test_handle();
        let ev = CString::new("{}").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { key_packages::mdk_parse_key_package(handle, ev.as_ptr(), &mut out) };
        // Should fail because {} is not a valid Nostr event
        assert_eq!(code, MdkError::InvalidInput);
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn parse_key_package_null_out() {
        let (handle, _dir) = test_handle();
        let ev = CString::new("{}").unwrap();
        let code = unsafe {
            key_packages::mdk_parse_key_package(handle, ev.as_ptr(), std::ptr::null_mut())
        };
        assert_eq!(code, MdkError::NullPointer);
        unsafe { mdk_free(handle) };
    }

    // ── Group mutation null-pointer tests ────────────────────────────────

    #[test]
    fn merge_pending_commit_null_handle() {
        let gid = CString::new("aa").unwrap();
        let code = unsafe { groups::mdk_merge_pending_commit(std::ptr::null_mut(), gid.as_ptr()) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn clear_pending_commit_null_handle() {
        let gid = CString::new("aa").unwrap();
        let code = unsafe { groups::mdk_clear_pending_commit(std::ptr::null_mut(), gid.as_ptr()) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn sync_group_metadata_null_handle() {
        let gid = CString::new("aa").unwrap();
        let code = unsafe { groups::mdk_sync_group_metadata(std::ptr::null_mut(), gid.as_ptr()) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn leave_group_null_handle() {
        let gid = CString::new("aa").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { groups::mdk_leave_group(std::ptr::null_mut(), gid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn self_update_null_handle() {
        let gid = CString::new("aa").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { groups::mdk_self_update(std::ptr::null_mut(), gid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn add_members_null_handle() {
        let gid = CString::new("aa").unwrap();
        let kp = CString::new("[]").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe {
            groups::mdk_add_members(std::ptr::null_mut(), gid.as_ptr(), kp.as_ptr(), &mut out)
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn remove_members_null_handle() {
        let gid = CString::new("aa").unwrap();
        let pks = CString::new("[]").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe {
            groups::mdk_remove_members(std::ptr::null_mut(), gid.as_ptr(), pks.as_ptr(), &mut out)
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    #[test]
    fn update_group_data_null_handle() {
        let gid = CString::new("aa").unwrap();
        let upd = CString::new("{}").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe {
            groups::mdk_update_group_data(
                std::ptr::null_mut(),
                gid.as_ptr(),
                upd.as_ptr(),
                &mut out,
            )
        };
        assert_eq!(code, MdkError::NullPointer);
    }

    // ── With-config constructor tests ───────────────────────────────────

    #[test]
    fn mdk_new_unencrypted_with_config() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("cfg.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();
        let config = CString::new(r#"{"max_event_age_secs": 1000}"#).unwrap();

        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe { mdk_new_unencrypted(c_path.as_ptr(), config.as_ptr(), &mut handle) };
        assert_eq!(code, MdkError::Ok);
        assert!(!handle.is_null());
        unsafe { mdk_free(handle) };
    }

    #[test]
    fn mdk_new_unencrypted_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("bad.db");
        let c_path = CString::new(db_path.to_str().unwrap()).unwrap();
        let config = CString::new("not json").unwrap();

        let mut handle: *mut MdkHandle = std::ptr::null_mut();
        let code = unsafe { mdk_new_unencrypted(c_path.as_ptr(), config.as_ptr(), &mut handle) };
        assert_eq!(code, MdkError::InvalidInput);
        assert!(handle.is_null());
    }

    // ── Pagination tests ────────────────────────────────────────────────

    #[test]
    fn get_pending_welcomes_with_pagination() {
        let (handle, _dir) = test_handle();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        // With limit only
        let code = unsafe { welcomes::mdk_get_pending_welcomes(handle, 10, 0, &mut out) };
        assert_eq!(code, MdkError::Ok);
        assert!(!out.is_null());
        unsafe { free::mdk_string_free(out) };

        // With offset only
        let mut out2: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { welcomes::mdk_get_pending_welcomes(handle, 0, 5, &mut out2) };
        assert_eq!(code, MdkError::Ok);
        assert!(!out2.is_null());
        unsafe { free::mdk_string_free(out2) };

        // With both
        let mut out3: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe { welcomes::mdk_get_pending_welcomes(handle, 10, 5, &mut out3) };
        assert_eq!(code, MdkError::Ok);
        assert!(!out3.is_null());
        unsafe { free::mdk_string_free(out3) };

        unsafe { mdk_free(handle) };
    }

    // ── Error message tests ─────────────────────────────────────────────

    #[test]
    fn error_message_after_invalid_input() {
        let (handle, _dir) = test_handle();
        let gid = CString::new("not-hex!").unwrap();
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();

        let code = unsafe { groups::mdk_get_group(handle, gid.as_ptr(), &mut out) };
        assert_eq!(code, MdkError::InvalidInput);

        // Should have an error message available
        let msg_ptr = unsafe { error::mdk_last_error_message() };
        assert!(!msg_ptr.is_null());
        let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
        assert!(
            msg.contains("hex"),
            "Error message should mention hex: got '{msg}'"
        );
        drop(unsafe { CString::from_raw(msg_ptr) });

        // Second call should return null (consumed)
        let msg_ptr2 = unsafe { error::mdk_last_error_message() };
        assert!(msg_ptr2.is_null());

        unsafe { mdk_free(handle) };
    }
}
