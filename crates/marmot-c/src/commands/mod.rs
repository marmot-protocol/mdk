//! `extern "C"` command wrappers over `marmot_uniffi::Marmot`.
//!
//! One module per `marmot-uniffi` commands module, same names. Every
//! wrapper follows the same shape:
//!
//! - `ffi_guard` around the body (no unwinding into C).
//! - Borrowed inputs read with `required_str` / `optional_str` /
//!   `str_array` / input-struct `to_ffi`; caller memory is never freed.
//! - Async runtime methods run via `client.block_on`.
//! - Results are converted to `#[repr(C)]` mirrors, moved to the heap
//!   with `memory::boxed`, and written through the out-pointer; the
//!   caller releases them with the type's `marmot_*_free`.
//! - Errors map through `status::status_from_error`.

pub mod account;
pub mod agent_stream;
pub mod audit;
pub mod chat_list;
pub mod directory;
pub mod group;
pub mod media;
pub mod message;
pub mod notification;
pub mod push;
pub mod relay;
pub mod subscription;
pub mod timeline;

use std::ffi::c_char;

use marmot_uniffi::MarmotKitError;

use crate::MarmotStatus;
use crate::memory::{CFree, boxed, owned_c_string};
use crate::status::status_from_error;
use crate::write_out;

/// Deliver a fallible record result: convert to the mirror, move it to the
/// heap, write it through the out-pointer.
pub(crate) unsafe fn deliver<TFfi, TMirror>(
    result: Result<TFfi, MarmotKitError>,
    out: *mut *mut TMirror,
) -> MarmotStatus
where
    TMirror: From<TFfi> + CFree,
{
    match result {
        Ok(value) => {
            let root = boxed(TMirror::from(value));
            match unsafe { write_out(out, root) } {
                Ok(()) => MarmotStatus::Ok,
                Err(status) => {
                    unsafe { crate::memory::free_boxed(root) };
                    status
                }
            }
        }
        Err(err) => status_from_error(&err),
    }
}

/// Deliver a fallible `Option<record>` result: `None` writes NULL and still
/// returns `MARMOT_STATUS_OK` — callers distinguish "absent" from failure
/// by the status code.
pub(crate) unsafe fn deliver_opt<TFfi, TMirror>(
    result: Result<Option<TFfi>, MarmotKitError>,
    out: *mut *mut TMirror,
) -> MarmotStatus
where
    TMirror: From<TFfi> + CFree,
{
    match result {
        Ok(value) => {
            let root = value.map_or(std::ptr::null_mut(), |v| boxed(TMirror::from(v)));
            match unsafe { write_out(out, root) } {
                Ok(()) => MarmotStatus::Ok,
                Err(status) => {
                    unsafe { crate::memory::free_boxed(root) };
                    status
                }
            }
        }
        Err(err) => status_from_error(&err),
    }
}

/// Deliver a fallible scalar result (u64/bool/...) by value.
pub(crate) unsafe fn deliver_scalar<T>(
    result: Result<T, MarmotKitError>,
    out: *mut T,
) -> MarmotStatus {
    match result {
        Ok(value) => match unsafe { write_out(out, value) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => status,
        },
        Err(err) => status_from_error(&err),
    }
}

/// Deliver a fallible `String` result as an owned C string.
pub(crate) unsafe fn deliver_string(
    result: Result<String, MarmotKitError>,
    out: *mut *mut c_char,
) -> MarmotStatus {
    match result {
        Ok(value) => {
            let ptr = owned_c_string(value);
            match unsafe { write_out(out, ptr) } {
                Ok(()) => MarmotStatus::Ok,
                Err(status) => {
                    unsafe { crate::memory::free_c_string(ptr) };
                    status
                }
            }
        }
        Err(err) => status_from_error(&err),
    }
}

/// Deliver an infallible unit result for fallible unit commands.
pub(crate) fn deliver_unit(result: Result<(), MarmotKitError>) -> MarmotStatus {
    match result {
        Ok(()) => MarmotStatus::Ok,
        Err(err) => status_from_error(&err),
    }
}

/// Deliver a fallible `Vec<u8>` result as an owned `(ptr, len)` byte buffer.
/// The caller frees it with `marmot_bytes_free`. Empty is `(NULL, 0)`.
pub(crate) unsafe fn deliver_bytes(
    result: Result<Vec<u8>, MarmotKitError>,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> MarmotStatus {
    match result {
        Ok(bytes) => {
            if out_data.is_null() || out_len.is_null() {
                crate::status::set_last_error("out-pointer argument was NULL");
                return MarmotStatus::NullPointer;
            }
            let (ptr, len) = crate::memory::owned_vec(bytes);
            unsafe {
                out_data.write(ptr);
                out_len.write(len);
            }
            MarmotStatus::Ok
        }
        Err(err) => status_from_error(&err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_bytes_writes_pair() {
        let _guard = crate::memory::audit::test_lock();
        let mut data: *mut u8 = std::ptr::null_mut();
        let mut len: usize = 999;
        let status = unsafe { deliver_bytes(Ok(vec![1, 2, 3]), &mut data, &mut len) };
        assert_eq!(status, MarmotStatus::Ok);
        assert!(!data.is_null());
        assert_eq!(len, 3);
        assert_eq!(unsafe { std::slice::from_raw_parts(data, len) }, &[1, 2, 3]);
        unsafe { crate::memory::free_vec(data, len) };
    }

    #[test]
    fn deliver_bytes_empty_is_null() {
        let _guard = crate::memory::audit::test_lock();
        let mut data: *mut u8 = (&mut 0u8) as *mut u8;
        let mut len: usize = 999;
        let status = unsafe { deliver_bytes(Ok(Vec::new()), &mut data, &mut len) };
        assert_eq!(status, MarmotStatus::Ok);
        assert!(data.is_null());
        assert_eq!(len, 0);
    }

    #[test]
    fn deliver_bytes_rejects_null_out() {
        let status =
            unsafe { deliver_bytes(Ok(vec![1]), std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(status, MarmotStatus::NullPointer);
    }

    #[test]
    fn deliver_bytes_maps_error() {
        let status = unsafe {
            deliver_bytes(
                Err(MarmotKitError::RuntimeStopping),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(status, MarmotStatus::RuntimeStopping);
    }
}
