//! Allocation and ownership helpers for the C ABI.
//!
//! Every heap object that crosses the boundary is created and destroyed
//! through this module so the `alloc-audit` test feature can prove that
//! deep-free implementations release everything they allocate.
//!
//! Ownership rules (documented in `marmot.h`):
//! - Strings returned as bare `char *` are freed with `marmot_string_free`.
//! - Structs returned by pointer are freed only with their type's
//!   `marmot_*_free` function, which deep-frees every field. Callers never
//!   free fields individually.
//! - `(ptr, len)` array fields are owned by their parent struct.

use std::ffi::{CString, c_char};

/// Deep-free for a `#[repr(C)]` mirror type: release every owned pointer
/// reachable from `self` without freeing `self`'s own storage.
///
/// # Safety
/// Must be called at most once per value, and only on values produced by
/// this crate's conversion code.
pub(crate) trait CFree {
    unsafe fn free_in_place(&mut self);
}

/// Scalar fields need no freeing; blanket impls keep generated code uniform.
macro_rules! no_free {
    ($($ty:ty),* $(,)?) => {
        $(impl CFree for $ty {
            unsafe fn free_in_place(&mut self) {}
        })*
    };
}
no_free!(bool, u8, u16, u32, u64, i8, i16, i32, i64, usize, f32, f64);

/// Owned C strings inside `(ptr, len)` arrays (e.g. `Vec<String>` mirrors).
impl CFree for *mut c_char {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(*self) };
    }
}

pub(crate) mod audit {
    #[cfg(feature = "alloc-audit")]
    use std::sync::atomic::{AtomicI64, Ordering};
    #[cfg(test)]
    use std::sync::{Mutex, MutexGuard};

    #[cfg(feature = "alloc-audit")]
    static LIVE: AtomicI64 = AtomicI64::new(0);

    /// The live-allocation counter is process-global, so allocating tests
    /// in different modules race each other when the harness runs them in
    /// parallel. Every allocating test takes this lock around its
    /// convert→assert→free window (with or without the alloc-audit
    /// feature, so test code needs no feature-conditional locking).
    #[cfg(test)]
    pub(crate) fn test_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(feature = "alloc-audit")]
    pub(crate) fn on_alloc() {
        LIVE.fetch_add(1, Ordering::SeqCst);
    }

    #[cfg(feature = "alloc-audit")]
    pub(crate) fn on_free() {
        let prev = LIVE.fetch_sub(1, Ordering::SeqCst);
        assert!(prev > 0, "alloc-audit: free without matching alloc");
    }

    /// Number of live FFI allocations. Tests assert this returns to its
    /// starting value after a convert→free roundtrip.
    #[cfg(all(test, feature = "alloc-audit"))]
    pub(crate) fn live_allocations() -> i64 {
        LIVE.load(Ordering::SeqCst)
    }
}

#[inline]
fn note_alloc() {
    #[cfg(feature = "alloc-audit")]
    audit::on_alloc();
}

#[inline]
fn note_free() {
    #[cfg(feature = "alloc-audit")]
    audit::on_free();
}

/// Convert an owned Rust string into an owned NUL-terminated C string.
///
/// The DTO surface never produces interior NUL bytes; if one ever appears
/// it is stripped rather than truncating the payload or panicking across
/// the boundary.
pub(crate) fn owned_c_string(value: String) -> *mut c_char {
    let cstring = CString::new(value).unwrap_or_else(|err| {
        let mut bytes = err.into_vec();
        bytes.retain(|&b| b != 0);
        CString::new(bytes).expect("NUL bytes were just stripped")
    });
    note_alloc();
    cstring.into_raw()
}

/// Free a string produced by [`owned_c_string`]. NULL is a no-op.
///
/// # Safety
/// `ptr` must be NULL or a pointer returned by [`owned_c_string`] that has
/// not been freed already.
pub(crate) unsafe fn free_c_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    note_free();
    drop(unsafe { CString::from_raw(ptr) });
}

/// Convert `Option<String>` into a nullable owned C string.
pub(crate) fn owned_opt_c_string(value: Option<String>) -> *mut c_char {
    value.map_or(std::ptr::null_mut(), owned_c_string)
}

/// Convert an owned `Vec<T>` of mirror values into an owned `(ptr, len)`
/// pair. Empty vectors become `(NULL, 0)` with no allocation.
pub(crate) fn owned_vec<T>(values: Vec<T>) -> (*mut T, usize) {
    if values.is_empty() {
        return (std::ptr::null_mut(), 0);
    }
    let len = values.len();
    note_alloc();
    let ptr = Box::into_raw(values.into_boxed_slice()) as *mut T;
    (ptr, len)
}

/// Deep-free a `(ptr, len)` pair produced by [`owned_vec`]: free each
/// element in place, then release the slice. `(NULL, 0)` is a no-op.
///
/// # Safety
/// `(ptr, len)` must be exactly as returned by [`owned_vec`] and not freed
/// already.
pub(crate) unsafe fn free_vec<T: CFree>(ptr: *mut T, len: usize) {
    if ptr.is_null() {
        return;
    }
    note_free();
    let mut boxed = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) };
    for item in boxed.iter_mut() {
        unsafe { item.free_in_place() };
    }
    drop(boxed);
}

/// Move a mirror value to the heap and hand ownership to C.
pub(crate) fn boxed<T>(value: T) -> *mut T {
    note_alloc();
    Box::into_raw(Box::new(value))
}

/// Deep-free a heap value produced by [`boxed`]. NULL is a no-op.
///
/// # Safety
/// `ptr` must be NULL or a pointer returned by [`boxed`] that has not been
/// freed already.
pub(crate) unsafe fn free_boxed<T: CFree>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }
    note_free();
    let mut boxed = unsafe { Box::from_raw(ptr) };
    unsafe { boxed.free_in_place() };
    drop(boxed);
}

/// Run a deep-free at the ABI boundary under `catch_unwind`, so a panic in a
/// `Drop`/free path never unwinds into C (which is undefined behavior). Frees
/// return `void` and cannot report a status, so a caught panic is swallowed.
pub(crate) fn free_guard(body: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
}

/// Convert an optional record into a nullable owned pointer.
pub(crate) fn boxed_opt<T>(value: Option<T>) -> *mut T {
    value.map_or(std::ptr::null_mut(), boxed)
}

/// Read a borrowed C string argument into an owned Rust `String`.
///
/// # Safety
/// `ptr` must be NULL or a valid NUL-terminated string.
pub(crate) unsafe fn required_str(ptr: *const c_char) -> Result<String, crate::MarmotStatus> {
    if ptr.is_null() {
        crate::status::set_last_error("required string argument was NULL");
        return Err(crate::MarmotStatus::NullPointer);
    }
    match unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str() {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => {
            crate::status::set_last_error("string argument was not valid UTF-8");
            Err(crate::MarmotStatus::InvalidUtf8)
        }
    }
}

/// Read a nullable C string argument into `Option<String>`.
///
/// # Safety
/// `ptr` must be NULL or a valid NUL-terminated string.
pub(crate) unsafe fn optional_str(
    ptr: *const c_char,
) -> Result<Option<String>, crate::MarmotStatus> {
    if ptr.is_null() {
        return Ok(None);
    }
    unsafe { required_str(ptr) }.map(Some)
}

/// Read a borrowed `(ptr, len)` array of C strings into `Vec<String>`.
/// `(NULL, 0)` is an empty list; NULL with a nonzero length is an error.
///
/// # Safety
/// When non-NULL, `ptr` must point to `len` valid NUL-terminated strings.
pub(crate) unsafe fn str_array(
    ptr: *const *const c_char,
    len: usize,
) -> Result<Vec<String>, crate::MarmotStatus> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(Vec::new());
        }
        crate::status::set_last_error("string array was NULL with nonzero length");
        return Err(crate::MarmotStatus::NullPointer);
    }
    let mut out = Vec::with_capacity(len);
    for i in 0..len {
        out.push(unsafe { required_str(*ptr.add(i)) }?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_roundtrip_strips_interior_nul() {
        let _guard = crate::memory::audit::test_lock();
        let ptr = owned_c_string("a\0b".to_string());
        let text = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(text, "ab");
        unsafe { free_c_string(ptr) };
    }

    #[test]
    fn free_guard_swallows_panics() {
        // A panic in a free/Drop path must never escape (unwinding into C is
        // UB). free_guard catches it; the test passing means it did not
        // propagate.
        free_guard(|| panic!("boom in a free path"));
    }

    #[test]
    fn empty_vec_is_null_without_allocation() {
        let _guard = crate::memory::audit::test_lock();
        let (ptr, len) = owned_vec::<u64>(Vec::new());
        assert!(ptr.is_null());
        assert_eq!(len, 0);
        unsafe { free_vec(ptr, len) };
    }

    #[cfg(feature = "alloc-audit")]
    #[test]
    fn audit_balance_returns_to_zero() {
        let _guard = crate::memory::audit::test_lock();
        let start = audit::live_allocations();
        let ptr = owned_c_string("hello".to_string());
        let (vec_ptr, vec_len) = owned_vec(vec![1u64, 2, 3]);
        let boxed_ptr = boxed(7u64);
        assert_eq!(audit::live_allocations(), start + 3);
        unsafe {
            free_c_string(ptr);
            free_vec(vec_ptr, vec_len);
            free_boxed(boxed_ptr);
        }
        assert_eq!(audit::live_allocations(), start);
    }
}
