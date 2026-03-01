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
// Null-check helpers
// ---------------------------------------------------------------------------

/// Validate that a pointer is non-null, returning a [`MdkError::NullPointer`] if
/// it is. On success, dereferences the pointer to a shared reference.
///
/// # Safety
///
/// The pointer must be valid for the lifetime of the returned reference if
/// non-null.
macro_rules! require_non_null {
    ($ptr:expr, $name:literal) => {
        if $ptr.is_null() {
            return Err($crate::error::null_pointer($name));
        }
    };
}

/// Validate that a handle pointer is non-null and dereference it.
///
/// # Safety
///
/// The pointer must point to a valid, live `MdkHandle`.
macro_rules! deref_handle {
    ($h:expr) => {{
        require_non_null!($h, "handle");
        #[allow(unsafe_code)]
        unsafe {
            &*$h
        }
    }};
}

pub(crate) use deref_handle;
pub(crate) use require_non_null;

// ---------------------------------------------------------------------------
// CString helpers
// ---------------------------------------------------------------------------

/// Read a C string pointer into a `&str`.
///
/// # Safety
///
/// `ptr` must be a valid, null-terminated C string or null.
#[allow(unsafe_code)]
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
#[allow(unsafe_code)]
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

/// Execute `f` inside [`std::panic::catch_unwind`], converting the result and
/// any panic into an [`MdkError`] code.
///
/// The closure is wrapped in [`AssertUnwindSafe`] because at the FFI boundary
/// a panic must not unwind into C. The pragmatic justification: we only need
/// to guarantee that the *Rust* state is not left in an inconsistent state
/// observable by later calls. The `MdkHandle` interior is behind a [`Mutex`],
/// so a panic will poison the lock and all subsequent operations will return an
/// error — there is no risk of silently using corrupt state.
pub(crate) fn ffi_try_unwind_safe<F>(f: F) -> MdkError
where
    F: FnOnce() -> Result<(), MdkError>,
{
    match std::panic::catch_unwind(AssertUnwindSafe(|| match f() {
        Ok(()) => MdkError::Ok,
        Err(code) => code,
    })) {
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

// ---------------------------------------------------------------------------
// Shared serialisation types
// ---------------------------------------------------------------------------

/// JSON envelope for [`mdk_core::groups::UpdateGroupResult`].
///
/// Used by both the groups and messages modules.
#[derive(serde::Serialize)]
pub(crate) struct UpdateGroupResultJson {
    /// Serialised evolution event JSON.
    pub(crate) evolution_event_json: String,
    /// Optional welcome rumor JSON strings.
    pub(crate) welcome_rumors_json: Option<Vec<String>>,
    /// Hex-encoded MLS group ID.
    pub(crate) mls_group_id: String,
}

/// Serialize an [`mdk_core::groups::UpdateGroupResult`] into a
/// [`serde_json::Value`].
///
/// Callers that need a `String` can call `.to_string()` on the result.
pub(crate) fn serialize_update_result(
    result: mdk_core::groups::UpdateGroupResult,
) -> Result<serde_json::Value, MdkError> {
    let evolution_json = serde_json::to_string(&result.evolution_event)
        .map_err(|e| error::invalid_input(&format!("Failed to serialize evolution event: {e}")))?;

    let welcome_rumors: Option<Vec<String>> = result
        .welcome_rumors
        .map(|rumors| {
            rumors
                .iter()
                .map(|r| {
                    serde_json::to_string(r).map_err(|e| {
                        error::invalid_input(&format!("Failed to serialize welcome rumor: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    serde_json::to_value(UpdateGroupResultJson {
        evolution_event_json: evolution_json,
        welcome_rumors_json: welcome_rumors,
        mls_group_id: hex::encode(result.mls_group_id.as_slice()),
    })
    .map_err(|e| error::invalid_input(&format!("Serialization failed: {e}")))
}

// ---------------------------------------------------------------------------
// Hex / JSON helpers
// ---------------------------------------------------------------------------

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
#[allow(unsafe_code)]
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

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn cstr_to_str_valid() {
        let cs = CString::new("hello").unwrap();
        let result = unsafe { cstr_to_str(cs.as_ptr()) };
        assert_eq!(result.unwrap(), "hello");
    }

    #[test]
    fn cstr_to_str_null_returns_error() {
        let result = unsafe { cstr_to_str(std::ptr::null()) };
        assert!(result.is_err());
        match result.unwrap_err() {
            MdkError::NullPointer => {}
            other => panic!("Expected NullPointer, got {other:?}"),
        }
    }

    #[test]
    fn cstr_to_str_invalid_utf8() {
        let bytes: Vec<u8> = vec![0xFF, 0xFE, 0x00];
        let result = unsafe { cstr_to_str(bytes.as_ptr() as *const std::os::raw::c_char) };
        assert!(result.is_err());
        match result.unwrap_err() {
            MdkError::InvalidInput => {}
            other => panic!("Expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn write_cstring_roundtrip() {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let result = unsafe { write_cstring_to(&mut out, "test value".to_string()) };
        assert!(result.is_ok());
        assert!(!out.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(out) }.to_str().unwrap();
        assert_eq!(s, "test value");
        // Free the allocated string
        drop(unsafe { CString::from_raw(out) });
    }

    #[test]
    fn write_cstring_with_null_byte_returns_error() {
        let mut out: *mut std::os::raw::c_char = std::ptr::null_mut();
        let result = unsafe { write_cstring_to(&mut out, "test\0value".to_string()) };
        assert!(result.is_err());
    }

    #[test]
    fn parse_json_valid() {
        let result: Result<Vec<String>, _> = parse_json(r#"["a","b"]"#, "test");
        assert_eq!(result.unwrap(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn parse_json_invalid() {
        let result: Result<Vec<String>, _> = parse_json("not json", "test");
        assert!(result.is_err());
    }

    #[test]
    fn to_json_roundtrip() {
        let data = vec![1u32, 2, 3];
        let json = to_json(&data).unwrap();
        let parsed: Vec<u32> = parse_json(&json, "test").unwrap();
        assert_eq!(parsed, vec![1, 2, 3]);
    }

    #[test]
    fn parse_group_id_valid() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let result = parse_group_id(hex);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_group_id_invalid_hex() {
        let result = parse_group_id("not-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_public_key_valid() {
        // A valid 32-byte hex public key (64 hex chars)
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_public_key(hex);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_public_key_invalid() {
        let result = parse_public_key("short");
        assert!(result.is_err());
    }

    #[test]
    fn parse_relay_urls_valid() {
        let json = r#"["wss://relay.example.com"]"#;
        let result = parse_relay_urls(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn parse_relay_urls_invalid_url() {
        let json = r#"["not a url"]"#;
        let result = parse_relay_urls(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_sort_order_null_returns_none() {
        let result = parse_sort_order(std::ptr::null());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn parse_sort_order_valid() {
        let cs = CString::new("created_at_first").unwrap();
        let result = parse_sort_order(cs.as_ptr());
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn parse_sort_order_invalid() {
        let cs = CString::new("invalid_order").unwrap();
        let result = parse_sort_order(cs.as_ptr());
        assert!(result.is_err());
    }

    #[test]
    fn ffi_try_unwind_safe_ok() {
        let result = ffi_try_unwind_safe(|| Ok(()));
        assert_eq!(result, MdkError::Ok);
    }

    #[test]
    fn ffi_try_unwind_safe_error() {
        let result = ffi_try_unwind_safe(|| Err(MdkError::InvalidInput));
        assert_eq!(result, MdkError::InvalidInput);
    }

    #[test]
    fn ffi_try_unwind_safe_catches_panic() {
        let result = ffi_try_unwind_safe(|| panic!("test panic"));
        assert_eq!(result, MdkError::Mdk);
    }

    #[test]
    fn serialize_update_result_fields() {
        // This test just verifies that the serializer produces valid JSON
        // with the expected field names. We can't easily construct an
        // UpdateGroupResult without the full MLS stack, but we can verify
        // that the struct serialization works.
        let json_val = serde_json::to_value(UpdateGroupResultJson {
            evolution_event_json: "{}".to_string(),
            welcome_rumors_json: Some(vec!["rumor1".to_string()]),
            mls_group_id: "aabb".to_string(),
        })
        .unwrap();

        assert_eq!(json_val["evolution_event_json"], "{}");
        assert_eq!(json_val["welcome_rumors_json"][0], "rumor1");
        assert_eq!(json_val["mls_group_id"], "aabb");
    }
}
