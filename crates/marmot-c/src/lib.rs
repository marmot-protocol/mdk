//! C ABI bindings for the Marmot app runtime.
//!
//! This crate exposes the same surface as `marmot-uniffi` (the single
//! source of truth for FFI DTO shapes) through a stable C ABI:
//!
//! - Opaque handles: [`MarmotClient`] plus one handle per subscription.
//! - Every runtime record/enum has a `#[repr(C)]` mirror in [`types`],
//!   converted from the `…Ffi` types and released by a deep-free.
//! - Blocking calls: async runtime methods run on an embedded multi-thread
//!   tokio runtime via `block_on`. Push-based surfaces (subscriptions,
//!   agent streams) additionally offer callback registration.
//! - Errors: fallible functions return [`MarmotStatus`]; detail text for
//!   the current thread's most recent failure comes from
//!   [`marmot_last_error_message`].
//!
//! The C header `include/marmot.h` is generated with cbindgen (`just
//! c-header`) and checked in; CI diff-gates it against this source.

use std::ffi::c_char;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use marmot_uniffi::Marmot;

pub mod commands;
pub mod memory;
pub mod status;
pub mod subscriptions;
pub mod types;

pub use status::MarmotStatus;

use memory::{owned_c_string, required_str, str_array};
use status::set_last_error;

/// Opaque handle to a running Marmot client: the app runtime plus the
/// tokio runtime that drives it. Create with `marmot_client_new`, destroy
/// with `marmot_client_free`.
pub struct MarmotClient {
    pub(crate) runtime: tokio::runtime::Runtime,
    pub(crate) marmot: Arc<Marmot>,
}

impl MarmotClient {
    /// Run an async runtime call to completion on the embedded runtime.
    pub(crate) fn block_on<F: Future>(&self, fut: F) -> F::Output {
        self.runtime.block_on(fut)
    }
}

/// Catch panics at the ABI boundary: unwinding into C is undefined
/// behavior, so a caught panic becomes `MARMOT_STATUS_PANIC_CAUGHT`.
pub(crate) fn ffi_guard(body: impl FnOnce() -> MarmotStatus) -> MarmotStatus {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(status) => status,
        Err(panic) => {
            let detail = panic
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "panic at FFI boundary".to_string());
            set_last_error(detail);
            MarmotStatus::PanicCaught
        }
    }
}

/// Borrow-check a client handle argument.
pub(crate) unsafe fn client_ref<'a>(
    client: *const MarmotClient,
) -> Result<&'a MarmotClient, MarmotStatus> {
    if client.is_null() {
        set_last_error("client handle was NULL");
        return Err(MarmotStatus::NullPointer);
    }
    Ok(unsafe { &*client })
}

/// Write a value through a required out-pointer.
pub(crate) unsafe fn write_out<T>(out: *mut T, value: T) -> Result<(), MarmotStatus> {
    if out.is_null() {
        set_last_error("out-pointer argument was NULL");
        return Err(MarmotStatus::NullPointer);
    }
    unsafe { out.write(value) };
    Ok(())
}

/// Create a Marmot client rooted at `root_path`, connected to
/// `relay_urls` (`relay_urls_len` entries). On success writes the new
/// handle to `out_client`. Uses the platform keychain-backed account
/// store, matching the UniFFI constructor.
///
/// # Safety
/// `root_path` must be a valid NUL-terminated UTF-8 string; `relay_urls`
/// must point to `relay_urls_len` valid strings (or be NULL with length
/// 0); `out_client` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_client_new(
    root_path: *const c_char,
    relay_urls: *const *const c_char,
    relay_urls_len: usize,
    out_client: *mut *mut MarmotClient,
) -> MarmotStatus {
    ffi_guard(|| {
        let root_path = match unsafe { required_str(root_path) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let relay_urls = match unsafe { str_array(relay_urls, relay_urls_len) } {
            Ok(v) => v,
            Err(status) => return status,
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                set_last_error(format!("failed to build tokio runtime: {err}"));
                return MarmotStatus::Runtime;
            }
        };
        // Constructor is sync but spawns onto the runtime internally, so
        // enter the runtime context for the duration of the call.
        let guard = runtime.enter();
        let marmot = match Marmot::new(root_path, relay_urls) {
            Ok(m) => m,
            Err(err) => {
                drop(guard);
                return status::status_from_error(&err);
            }
        };
        drop(guard);
        let client = memory::boxed(MarmotClient { runtime, marmot });
        match unsafe { write_out(out_client, client) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => {
                // Out-pointer was NULL; reclaim the handle we just made.
                unsafe { free_client(client) };
                status
            }
        }
    })
}

/// Start the runtime (reconcile accounts, start workers, subscribe
/// transport). Must be called before subscribing.
///
/// # Safety
/// `client` must be a live handle from `marmot_client_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_client_start(client: *const MarmotClient) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.start()) {
            Ok(()) => MarmotStatus::Ok,
            Err(err) => status::status_from_error(&err),
        }
    })
}

/// Shut the runtime down. Open subscriptions drain and report
/// `MARMOT_STATUS_CLOSED` from their next read.
///
/// # Safety
/// `client` must be a live handle from `marmot_client_new`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_client_shutdown(client: *const MarmotClient) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        client.block_on(client.marmot.shutdown());
        MarmotStatus::Ok
    })
}

/// Whether the runtime is currently shutting down. Writes to `out_stopping`.
///
/// # Safety
/// `client` must be a live handle; `out_stopping` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_client_is_stopping(
    client: *const MarmotClient,
    out_stopping: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(c) => c,
            Err(status) => return status,
        };
        let stopping = client.marmot.is_stopping();
        match unsafe { write_out(out_stopping, stopping) } {
            Ok(()) => MarmotStatus::Ok,
            Err(status) => status,
        }
    })
}

pub(crate) unsafe fn free_client(client: *mut MarmotClient) {
    if client.is_null() {
        return;
    }
    #[cfg(feature = "alloc-audit")]
    memory::audit::on_free();
    let client = unsafe { Box::from_raw(client) };
    // Dropping a tokio runtime from within one of its own worker threads
    // aborts; the shutdown_background escape hatch keeps free safe to call
    // from any thread (e.g. a callback thread, though callers shouldn't).
    let MarmotClient { runtime, marmot } = *client;
    drop(marmot);
    runtime.shutdown_background();
}

/// Destroy a client handle. Call `marmot_client_shutdown` first for a
/// graceful stop. NULL is a no-op. The handle must not be used afterwards.
///
/// # Safety
/// `client` must be NULL or a live handle from `marmot_client_new` that
/// has not been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_client_free(client: *mut MarmotClient) {
    let _ = ffi_guard(|| {
        unsafe { free_client(client) };
        MarmotStatus::Ok
    });
}

/// Return the detail message for the current thread's most recent failed
/// `marmot_*` call, or NULL if there is none. The returned string is an
/// owned copy: free it with `marmot_string_free`. Reading clears the slot.
#[unsafe(no_mangle)]
pub extern "C" fn marmot_last_error_message() -> *mut c_char {
    match std::panic::catch_unwind(status::take_last_error) {
        Ok(Some(message)) => owned_c_string(message),
        _ => std::ptr::null_mut(),
    }
}

/// Free a string returned by this library (`marmot_last_error_message`,
/// string out-params). NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a string returned by this library that has not
/// been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_string_free(s: *mut c_char) {
    let _ = ffi_guard(|| {
        unsafe { memory::free_c_string(s) };
        MarmotStatus::Ok
    });
}

/// Free a byte buffer returned by this library as a `(data, len)` pair (e.g.
/// `marmot_download_group_blossom_image`). `(NULL, 0)` is a no-op.
///
/// # Safety
/// `data`/`len` must be exactly a pair returned by this library that has not
/// been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_bytes_free(data: *mut u8, len: usize) {
    memory::free_guard(|| unsafe { memory::free_vec(data, len) });
}
