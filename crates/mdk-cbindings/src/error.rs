//! Error handling for C bindings.
//!
//! Provides a C-compatible error enum and **thread-local** error message
//! storage.  After any function returns a non-zero error code, the caller can
//! retrieve the detailed message via [`mdk_last_error_message`].
//!
//! # Thread Safety
//!
//! The error message is stored in a thread-local variable.  This means:
//!
//! - The error is only available on the **same thread** that made the failing
//!   call.
//! - If you make an MDK call on thread A and check the error on thread B, you
//!   will get `null` (no error).  This is the standard C errno pattern.
//! - Calling [`mdk_last_error_message`] **consumes** the message — a second
//!   call without an intervening error returns `null`.

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

/// Retrieve the last error message from the **calling thread**.
///
/// Returns a heap-allocated C string that the caller **must** free with
/// `mdk_string_free`. Returns null if no
/// error has been recorded on this thread.
///
/// **Important**: Error messages are thread-local. You must call this from the
/// same thread that received the error code. In callback-based architectures
/// where the call and the error check happen on different threads, the message
/// will not be available.
///
/// # Safety
///
/// The returned pointer is valid until freed. Calling this function clears
/// the stored message — a second call without an intervening error returns null.
#[allow(unsafe_code)]
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

/// Map a [`StorageError`] into an [`MdkError`], recording a generic message.
///
/// The original error is intentionally **not** interpolated into the
/// user-visible message to avoid leaking sensitive internals (group IDs,
/// key material, file paths, etc.) through the FFI error channel.
pub(crate) fn from_storage_error(_e: StorageError) -> MdkError {
    set_last_error("Storage error: internal");
    MdkError::Storage
}

/// Map a [`CoreMdkError`] into an [`MdkError`], recording a generic message.
///
/// See [`from_storage_error`] for the rationale on why the original error
/// is not included in the user-visible message.
pub(crate) fn from_mdk_error(_e: CoreMdkError) -> MdkError {
    set_last_error("MDK error: internal");
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

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    #[test]
    fn set_and_get_last_error() {
        set_last_error("test error message");
        let ptr = unsafe { mdk_last_error_message() };
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(msg, "test error message");
        // Free the string
        drop(unsafe { CString::from_raw(ptr) });
    }

    #[test]
    fn last_error_is_consumed() {
        set_last_error("consumed");
        let ptr1 = unsafe { mdk_last_error_message() };
        assert!(!ptr1.is_null());
        drop(unsafe { CString::from_raw(ptr1) });

        // Second call should return null
        let ptr2 = unsafe { mdk_last_error_message() };
        assert!(ptr2.is_null());
    }

    #[test]
    fn no_error_returns_null() {
        // Consume any existing error first
        let ptr = unsafe { mdk_last_error_message() };
        if !ptr.is_null() {
            drop(unsafe { CString::from_raw(ptr) });
        }
        let ptr = unsafe { mdk_last_error_message() };
        assert!(ptr.is_null());
    }

    #[test]
    fn invalid_input_sets_message() {
        let code = invalid_input("bad input");
        assert_eq!(code, MdkError::InvalidInput);

        let ptr = unsafe { mdk_last_error_message() };
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(msg, "bad input");
        drop(unsafe { CString::from_raw(ptr) });
    }

    #[test]
    fn null_pointer_error() {
        let code = null_pointer("my_param");
        assert_eq!(code, MdkError::NullPointer);

        let ptr = unsafe { mdk_last_error_message() };
        assert!(!ptr.is_null());
        let msg = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(msg, "Null pointer: my_param");
        drop(unsafe { CString::from_raw(ptr) });
    }
}
