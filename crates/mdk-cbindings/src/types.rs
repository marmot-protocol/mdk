//! Opaque handle type and helper utilities for the C API.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::Mutex;

use mdk_core::MDK;
use mdk_sqlite_storage::MdkSqliteStorage;

use crate::error::{self, MdkError};

/// Opaque handle to an MDK instance, passed across the FFI boundary as a pointer.
///
/// The inner [`MDK`] is wrapped in a [`Mutex`] for thread safety, mirroring
/// the UniFFI crate's approach.
pub struct MdkHandle {
    pub(crate) inner: Mutex<MDK<MdkSqliteStorage>>,
}

/// Lock the inner MDK, returning an error if the mutex is poisoned.
pub(crate) fn lock_handle(
    h: &MdkHandle,
) -> Result<std::sync::MutexGuard<'_, MDK<MdkSqliteStorage>>, MdkError> {
    h.inner.lock().map_err(|_| {
        error::set_last_error("MDK mutex poisoned — this indicates a critical internal error");
        MdkError::Mdk
    })
}

// ---------------------------------------------------------------------------
// CString helpers
// ---------------------------------------------------------------------------

/// Read a C string pointer into a `&str`.
///
/// # Safety
///
/// `ptr` must be a valid, null-terminated C string or null.
pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, MdkError> {
    if ptr.is_null() {
        return Err(error::null_pointer("string argument"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| error::invalid_input(&format!("Invalid UTF-8: {e}")))
}

/// Allocate a Rust `String` as a C string and write its pointer to `*out`.
///
/// # Safety
///
/// `out` must be a valid, non-null pointer to a `*mut c_char`.
pub(crate) unsafe fn write_cstring_to(out: *mut *mut c_char, s: String) -> Result<(), MdkError> {
    let c = CString::new(s)
        .map_err(|e| error::invalid_input(&format!("String contained null byte: {e}")))?;
    unsafe {
        *out = c.into_raw();
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Catch-unwind wrapper
// ---------------------------------------------------------------------------

/// Execute `f` inside [`std::panic::catch_unwind`], converting any panic into
/// `MdkError::Mdk` with the panic payload stored as the last error message.
pub(crate) fn ffi_catch<F>(f: F) -> MdkError
where
    F: FnOnce() -> MdkError + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(code) => code,
        Err(payload) => {
            let msg = match payload.downcast_ref::<&str>() {
                Some(s) => s.to_string(),
                None => match payload.downcast_ref::<String>() {
                    Some(s) => s.clone(),
                    None => "unknown panic".to_string(),
                },
            };
            error::set_last_error(&format!("Internal panic: {msg}"));
            MdkError::Mdk
        }
    }
}

/// Convenience wrapper: catch panics around a closure that returns `Result<(), MdkError>`.
pub(crate) fn ffi_try<F>(f: F) -> MdkError
where
    F: FnOnce() -> Result<(), MdkError> + std::panic::UnwindSafe,
{
    ffi_catch(|| match f() {
        Ok(()) => MdkError::Ok,
        Err(code) => code,
    })
}

/// Like [`ffi_try`] but accepts a non-`UnwindSafe` closure by wrapping it in
/// [`AssertUnwindSafe`]. All our FFI functions take `&MdkHandle` which is
/// behind a `Mutex` — any poisoning is caught at the lock site.
pub(crate) fn ffi_try_unwind_safe<F>(f: F) -> MdkError
where
    F: FnOnce() -> Result<(), MdkError>,
{
    ffi_try(AssertUnwindSafe(f))
}

// ---------------------------------------------------------------------------
// JSON / hex helpers
// ---------------------------------------------------------------------------

/// Deserialise a JSON string into `T`.
pub(crate) fn parse_json<T>(json: &str, context: &str) -> Result<T, MdkError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(json).map_err(|e| error::invalid_input(&format!("Invalid {context}: {e}")))
}

/// Serialise `value` to a JSON string.
pub(crate) fn to_json<T>(value: &T) -> Result<String, MdkError>
where
    T: serde::Serialize,
{
    serde_json::to_string(value)
        .map_err(|e| error::invalid_input(&format!("Serialization failed: {e}")))
}

/// Decode a hex string into a [`mdk_storage_traits::GroupId`].
pub(crate) fn parse_group_id(hex_str: &str) -> Result<mdk_storage_traits::GroupId, MdkError> {
    hex::decode(hex_str)
        .map_err(|e| error::invalid_input(&format!("Invalid group ID hex: {e}")))
        .map(|bytes| mdk_storage_traits::GroupId::from_slice(&bytes))
}

/// Decode a hex string into a [`nostr::EventId`].
pub(crate) fn parse_event_id(hex_str: &str) -> Result<nostr::EventId, MdkError> {
    nostr::EventId::from_hex(hex_str)
        .map_err(|e| error::invalid_input(&format!("Invalid event ID: {e}")))
}

/// Decode a hex string into a [`nostr::PublicKey`].
pub(crate) fn parse_public_key(hex_str: &str) -> Result<nostr::PublicKey, MdkError> {
    nostr::PublicKey::from_hex(hex_str)
        .map_err(|e| error::invalid_input(&format!("Invalid public key: {e}")))
}

/// Parse a JSON array of relay URL strings.
pub(crate) fn parse_relay_urls(json: &str) -> Result<Vec<nostr::RelayUrl>, MdkError> {
    let urls: Vec<String> = parse_json(json, "relay URLs JSON array")?;
    urls.iter()
        .map(|r| {
            nostr::RelayUrl::parse(r)
                .map_err(|e| error::invalid_input(&format!("Invalid relay URL: {e}")))
        })
        .collect()
}

/// Parse a JSON array of public-key hex strings.
pub(crate) fn parse_public_keys(json: &str) -> Result<Vec<nostr::PublicKey>, MdkError> {
    let keys: Vec<String> = parse_json(json, "public keys JSON array")?;
    keys.iter().map(|k| parse_public_key(k)).collect()
}

/// Parse the sort-order string (`"created_at_first"` / `"processed_at_first"` / null).
pub(crate) fn parse_sort_order(
    s: *const c_char,
) -> Result<Option<mdk_storage_traits::groups::MessageSortOrder>, MdkError> {
    if s.is_null() {
        return Ok(None);
    }
    let sort = unsafe { cstr_to_str(s) }?;
    match sort {
        "created_at_first" => Ok(Some(
            mdk_storage_traits::groups::MessageSortOrder::CreatedAtFirst,
        )),
        "processed_at_first" => Ok(Some(
            mdk_storage_traits::groups::MessageSortOrder::ProcessedAtFirst,
        )),
        other => Err(error::invalid_input(&format!(
            "Invalid sort order: {other}. Expected \"created_at_first\" or \"processed_at_first\""
        ))),
    }
}
