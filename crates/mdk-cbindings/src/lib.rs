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
// We allow `unsafe` only in explicitly marked blocks — the deny is overridden
// per-function with `#[allow(unsafe_code)]` where FFI requires it.
#![allow(unsafe_code)]
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
mod media;
mod messages;
mod types;
mod welcomes;

pub use self::error::MdkError;
pub use self::types::MdkHandle;

// ---------------------------------------------------------------------------
// Configuration parsing
// ---------------------------------------------------------------------------

/// Parse an optional JSON config string into a [`CoreMdkConfig`].
///
/// If the pointer is null, returns `CoreMdkConfig::default()`.
fn parse_config(config_json: *const c_char) -> Result<CoreMdkConfig, MdkError> {
    if config_json.is_null() {
        return Ok(CoreMdkConfig::default());
    }
    let json = unsafe { types::cstr_to_str(config_json) }?;
    types::parse_json::<ConfigOverrides>(json, "config JSON").map(|o| o.into_core())
}

/// Mirrors the UniFFI `MdkConfig` — all fields optional, defaulting to
/// [`CoreMdkConfig::default()`].
#[derive(serde::Deserialize)]
struct ConfigOverrides {
    max_event_age_secs: Option<u64>,
    max_future_skew_secs: Option<u64>,
    out_of_order_tolerance: Option<u32>,
    maximum_forward_distance: Option<u32>,
    epoch_snapshot_retention: Option<u32>,
    snapshot_ttl_seconds: Option<u64>,
}

impl ConfigOverrides {
    fn into_core(self) -> CoreMdkConfig {
        let d = CoreMdkConfig::default();
        CoreMdkConfig {
            max_event_age_secs: self.max_event_age_secs.unwrap_or(d.max_event_age_secs),
            max_future_skew_secs: self.max_future_skew_secs.unwrap_or(d.max_future_skew_secs),
            out_of_order_tolerance: self
                .out_of_order_tolerance
                .unwrap_or(d.out_of_order_tolerance),
            maximum_forward_distance: self
                .maximum_forward_distance
                .unwrap_or(d.maximum_forward_distance),
            epoch_snapshot_retention: self
                .epoch_snapshot_retention
                .map(|v| v as usize)
                .unwrap_or(d.epoch_snapshot_retention),
            snapshot_ttl_seconds: self.snapshot_ttl_seconds.unwrap_or(d.snapshot_ttl_seconds),
        }
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new(
    db_path: *const c_char,
    service_id: *const c_char,
    db_key_id: *const c_char,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        if out.is_null() {
            return Err(error::null_pointer("out"));
        }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new_with_key(
    db_path: *const c_char,
    key: *const u8,
    key_len: usize,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        if out.is_null() {
            return Err(error::null_pointer("out"));
        }
        if key.is_null() {
            return Err(error::null_pointer("key"));
        }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_new_unencrypted(
    db_path: *const c_char,
    config_json: *const c_char,
    out: *mut *mut MdkHandle,
) -> MdkError {
    types::ffi_try_unwind_safe(|| {
        if out.is_null() {
            return Err(error::null_pointer("out"));
        }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_free(handle: *mut MdkHandle) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}
