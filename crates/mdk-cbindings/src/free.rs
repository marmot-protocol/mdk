//! Memory-management functions for strings and byte arrays returned by the C API.

use std::ffi::CString;
use std::os::raw::c_char;

/// Free a string previously returned by any `mdk_*` function.
///
/// # Safety
///
/// `s` must be a pointer previously returned by an `mdk_*` function, or null
/// (in which case this is a no-op). Passing any other pointer is undefined
/// behaviour. Do **not** call this more than once on the same pointer.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Free a byte array previously returned by an `mdk_*` function.
///
/// Handles zero-length allocations correctly — `Box::from_raw` with a
/// zero-length slice is valid in Rust, so `len == 0` with a non-null
/// `data` will still free the allocation.
///
/// # Safety
///
/// `data` must be a pointer previously returned by an `mdk_*` function (paired
/// with the correct `len`), or null (no-op). Passing any other pointer or an
/// incorrect length is undefined behaviour.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_bytes_free(data: *mut u8, len: usize) {
    if !data.is_null() {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(data, len)) });
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    #[test]
    fn string_free_null_is_noop() {
        // Should not crash
        unsafe { mdk_string_free(std::ptr::null_mut()) };
    }

    #[test]
    fn string_free_valid_cstring() {
        let cs = CString::new("test").unwrap();
        let ptr = cs.into_raw();
        // Should free without crash
        unsafe { mdk_string_free(ptr) };
    }

    #[test]
    fn bytes_free_null_is_noop() {
        unsafe { mdk_bytes_free(std::ptr::null_mut(), 42) };
    }

    #[test]
    fn bytes_free_valid_bytes() {
        let data = vec![1u8, 2, 3, 4, 5];
        let boxed = data.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        unsafe { mdk_bytes_free(ptr, len) };
    }

    #[test]
    fn bytes_free_zero_length() {
        // Zero-length allocation should be freed correctly
        let data: Vec<u8> = Vec::new();
        let boxed = data.into_boxed_slice();
        let ptr = Box::into_raw(boxed) as *mut u8;
        unsafe { mdk_bytes_free(ptr, 0) };
    }
}
