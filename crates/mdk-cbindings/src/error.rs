//! Error handling for C bindings.
//!
//! Provides a C-compatible error enum and thread-local error message storage.
//! After any function returns a non-zero error code, the caller can retrieve
//! the detailed message via [`mdk_last_error_message`].

use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;

use mdk_core::Error as CoreMdkError;
use mdk_sqlite_storage::error::Error as StorageError;

/// Error codes returned by all fallible C API functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdkError {
    /// Success — no error.
    Ok = 0,
    /// Storage-layer error (SQLite, I/O, etc.).
    Storage = 1,
    /// MDK core error (MLS, protocol, crypto).
    Mdk = 2,
    /// Invalid input from the caller (bad hex, bad JSON, wrong byte length, etc.).
    InvalidInput = 3,
    /// A required pointer argument was null.
    NullPointer = 4,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Store an error message in the thread-local slot.
pub(crate) fn set_last_error(msg: &str) {
    let c = CString::new(msg).unwrap_or_else(|_| {
        CString::new("(error message contained an interior null byte)").unwrap()
    });
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(c);
    });
}

/// Retrieve the last error message.
///
/// Returns a heap-allocated C string that the caller **must** free with
/// [`mdk_string_free`](crate::free::mdk_string_free). Returns null if no
/// error has been recorded on this thread.
///
/// # Safety
///
/// The returned pointer is valid until freed. Calling this function clears
/// the stored message — a second call without an intervening error returns null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_last_error_message() -> *mut c_char {
    LAST_ERROR.with(|cell| {
        cell.borrow_mut()
            .take()
            .map_or(std::ptr::null_mut(), CString::into_raw)
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers used by the domain modules
// ---------------------------------------------------------------------------

/// Map a [`StorageError`] into an [`MdkError`], recording the message.
pub(crate) fn from_storage_error(e: StorageError) -> MdkError {
    set_last_error(&format!("Storage error: {e}"));
    MdkError::Storage
}

/// Map a [`CoreMdkError`] into an [`MdkError`], recording the message.
pub(crate) fn from_mdk_error(e: CoreMdkError) -> MdkError {
    set_last_error(&format!("MDK error: {e}"));
    MdkError::Mdk
}

/// Record an invalid-input error and return the corresponding code.
pub(crate) fn invalid_input(msg: &str) -> MdkError {
    set_last_error(msg);
    MdkError::InvalidInput
}

/// Record a null-pointer error and return the corresponding code.
pub(crate) fn null_pointer(param: &str) -> MdkError {
    set_last_error(&format!("Null pointer: {param}"));
    MdkError::NullPointer
}
