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
}
