//! Host-supplied account-secret storage over a C callback vtable.
//!
//! `marmot_client_new` keeps account signing keys in the platform keychain.
//! A host that already owns an encrypted store (a desktop client with a
//! password-sealed vault, for example) fills in a [`MarmotSecretStore`] and
//! constructs with [`crate::marmot_client_new_with_secret_store`] instead.
//! The signing key crosses as secret-key hex; an account is identified by
//! its `label` plus `account_id_hex`.
//!
//! **Rules for the host, all of them load-bearing:**
//!
//! - **Thread safety.** The callbacks run on the runtime's worker threads
//!   and may run concurrently. `user_data` access must be synchronized.
//! - **No re-entry.** A callback must not call any `marmot_*` function on
//!   the same client. It runs while the account home holds its mutation
//!   lock, so re-entering deadlocks.
//! - **No unwinding.** A callback must return a status, never unwind. The
//!   callbacks are `extern "C"`, whose ABI aborts the process on an escaping
//!   unwind, so neither a C++ exception nor a Rust panic raised *inside* a
//!   callback can be recovered. Everything the library itself runs around
//!   the call (argument marshalling, status validation) is wrapped in
//!   `catch_unwind` and reported as a store failure instead.
//! - **Storage boundary, not a security boundary.** The plaintext key hex
//!   crosses in both directions. Rust holds it zeroizing for the shortest
//!   window it can, and hands the buffer returned by `load_secret` straight
//!   back to `free_secret`; protecting it at rest is the host's job.
//! - **Ownership.** The [`MarmotSecretStore`] struct is *copied* at
//!   construction, so the caller may free their copy as soon as the call
//!   returns. `user_data` must stay alive until `destroy` fires, which
//!   happens when the last runtime reference is released (at or shortly
//!   after `marmot_client_free`).

use std::ffi::{CStr, c_char, c_void};
use std::panic::AssertUnwindSafe;

use marmot_uniffi::{MarmotKitError, SecretStore};
use zeroize::Zeroizing;

use crate::MarmotStatus;
use crate::macros::c_enum;
use crate::status::set_last_error;

c_enum! {
    /// Status a [`MarmotSecretStore`] callback returns. Crosses as
    /// `uint32_t`; an out-of-range value is rejected as
    /// `MARMOT_STATUS_INVALID_ARGUMENT`.
    MarmotSecretStoreStatus {
        /// The operation succeeded.
        Ok,
        /// No credential is stored for this account. Only `load_secret`
        /// should report it; `remove_secret` on a missing credential
        /// succeeds.
        NotFound,
        /// The store exists but cannot be reached right now (locked vault,
        /// keystore unavailable). The runtime treats this as recoverable.
        Unavailable,
        /// Any other failure.
        Failed,
    }
}

/// `has_secret_for_label` / `has_secret_for_account_id`: write nonzero to
/// `out_present` when a credential exists.
pub type MarmotSecretStoreHasFn = Option<
    unsafe extern "C" fn(user_data: *mut c_void, key: *const c_char, out_present: *mut u8) -> u32,
>;

/// `write_secret`: persist `secret_key_hex`, replacing any existing
/// credential for this account.
pub type MarmotSecretStoreWriteFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        label: *const c_char,
        account_id_hex: *const c_char,
        secret_key_hex: *const c_char,
    ) -> u32,
>;

/// `load_secret`: write a NUL-terminated secret-key hex string to
/// `out_secret_key_hex`. The library copies it and returns the buffer to
/// `free_secret`.
pub type MarmotSecretStoreLoadFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        label: *const c_char,
        account_id_hex: *const c_char,
        out_secret_key_hex: *mut *mut c_char,
    ) -> u32,
>;

/// `remove_secret`: drop this account's credential. Removing a missing
/// credential succeeds.
pub type MarmotSecretStoreRemoveFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        label: *const c_char,
        account_id_hex: *const c_char,
    ) -> u32,
>;

/// `free_secret`: release a buffer this store returned from `load_secret`.
pub type MarmotSecretStoreFreeSecretFn =
    Option<unsafe extern "C" fn(user_data: *mut c_void, secret_key_hex: *mut c_char)>;

/// `destroy`: the library is done with `user_data`.
pub type MarmotSecretStoreDestroyFn = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Callback vtable for host-owned account-secret storage. Borrowed input:
/// the fields are copied at construction and the struct itself is never
/// retained or freed by the library. Every function pointer except
/// `destroy` is required.
///
/// See the module documentation for the thread-safety, re-entry, and
/// ownership rules a host must honor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MarmotSecretStore {
    /// Opaque host context passed to every callback. Must outlive the
    /// client; released by `destroy`.
    pub user_data: *mut c_void,
    pub has_secret_for_label: MarmotSecretStoreHasFn,
    pub has_secret_for_account_id: MarmotSecretStoreHasFn,
    pub write_secret: MarmotSecretStoreWriteFn,
    pub load_secret: MarmotSecretStoreLoadFn,
    pub remove_secret: MarmotSecretStoreRemoveFn,
    pub free_secret: MarmotSecretStoreFreeSecretFn,
    /// Optional; invoked once when the last runtime reference to the store
    /// is released. NULL means the host reclaims `user_data` itself.
    pub destroy: MarmotSecretStoreDestroyFn,
}

/// Adapts the C vtable to the UniFFI `SecretStore` trait.
///
/// `Send`/`Sync` rest on the documented host contract: the callbacks and
/// any access to `user_data` must be thread-safe, because the runtime
/// invokes them from worker threads, possibly concurrently.
pub(crate) struct CSecretStore {
    vtable: MarmotSecretStore,
}

unsafe impl Send for CSecretStore {}
unsafe impl Sync for CSecretStore {}

impl CSecretStore {
    /// Copy a caller-supplied vtable, rejecting a NULL struct or a missing
    /// required callback. The caller's struct is borrowed only for this
    /// call.
    ///
    /// # Safety
    /// `store` must be NULL or point to a valid `MarmotSecretStore`.
    pub(crate) unsafe fn from_c(store: *const MarmotSecretStore) -> Result<Self, MarmotStatus> {
        if store.is_null() {
            set_last_error("secret store argument was NULL");
            return Err(MarmotStatus::NullPointer);
        }
        let vtable = unsafe { *store };

        let required = [
            (
                "has_secret_for_label",
                vtable.has_secret_for_label.is_some(),
            ),
            (
                "has_secret_for_account_id",
                vtable.has_secret_for_account_id.is_some(),
            ),
            ("write_secret", vtable.write_secret.is_some()),
            ("load_secret", vtable.load_secret.is_some()),
            ("remove_secret", vtable.remove_secret.is_some()),
            ("free_secret", vtable.free_secret.is_some()),
        ];
        for (name, present) in required {
            if !present {
                set_last_error(format!("secret store callback {name} was NULL"));
                return Err(MarmotStatus::NullPointer);
            }
        }

        Ok(Self { vtable })
    }
}

impl Drop for CSecretStore {
    fn drop(&mut self) {
        let Some(destroy) = self.vtable.destroy else {
            return;
        };
        // A panic here would unwind out of a Drop the runtime is running;
        // the host has no way to receive it either way.
        crate::memory::free_guard(|| unsafe { destroy(self.vtable.user_data) });
    }
}

/// Invoke one host callback, translating a panic and the returned
/// discriminant into a typed error.
///
/// A caught panic becomes an opaque store failure rather than unwinding
/// through the runtime that called us. (A panic raised inside the
/// `extern "C"` callback itself aborts at its own ABI boundary and never
/// reaches here; this covers the marshalling around the call.)
fn guard(op: &str, call: impl FnOnce() -> u32) -> Result<(), MarmotKitError> {
    let raw =
        std::panic::catch_unwind(AssertUnwindSafe(call)).map_err(|_| MarmotKitError::Runtime {
            details: format!("host secret store panicked in {op}"),
        })?;

    match MarmotSecretStoreStatus::from_c(raw) {
        Ok(MarmotSecretStoreStatus::Ok) => Ok(()),
        Ok(MarmotSecretStoreStatus::NotFound) => Err(MarmotKitError::SecretNotFound {
            details: format!("host secret store has no credential ({op})"),
        }),
        Ok(MarmotSecretStoreStatus::Unavailable) => Err(MarmotKitError::KeystoreUnavailable {
            details: format!("host secret store unavailable ({op})"),
        }),
        Ok(MarmotSecretStoreStatus::Failed) => Err(MarmotKitError::Runtime {
            details: format!("host secret store failed ({op})"),
        }),
        Err(_) => Err(MarmotKitError::Runtime {
            details: format!("host secret store returned status {raw} out of range ({op})"),
        }),
    }
}

/// Borrow an owned Rust string as a NUL-terminated C string for the
/// duration of `call`. Labels and hex ids never contain interior NUL, so a
/// rejected conversion is a corrupt argument, not a truncation to hide.
fn with_c_str<R>(
    value: &str,
    op: &str,
    call: impl FnOnce(*const c_char) -> Result<R, MarmotKitError>,
) -> Result<R, MarmotKitError> {
    let owned = std::ffi::CString::new(value).map_err(|_| MarmotKitError::Runtime {
        details: format!("secret store argument contained a NUL byte ({op})"),
    })?;
    call(owned.as_ptr())
}

impl SecretStore for CSecretStore {
    fn has_secret_for_label(&self, label: String) -> Result<bool, MarmotKitError> {
        self.has(
            self.vtable.has_secret_for_label,
            &label,
            "has_secret_for_label",
        )
    }

    fn has_secret_for_account_id(&self, account_id_hex: String) -> Result<bool, MarmotKitError> {
        self.has(
            self.vtable.has_secret_for_account_id,
            &account_id_hex,
            "has_secret_for_account_id",
        )
    }

    fn write_secret(
        &self,
        label: String,
        account_id_hex: String,
        secret_key_hex: String,
    ) -> Result<(), MarmotKitError> {
        let write = self.vtable.write_secret.expect("checked in from_c");
        let secret_key_hex = Zeroizing::new(secret_key_hex);
        let user_data = self.vtable.user_data;

        with_c_str(&label, "write_secret", |label| {
            with_c_str(&account_id_hex, "write_secret", |account| {
                with_c_str(&secret_key_hex, "write_secret", |secret| {
                    guard("write_secret", || unsafe {
                        write(user_data, label, account, secret)
                    })
                })
            })
        })
    }

    fn load_secret(&self, label: String, account_id_hex: String) -> Result<String, MarmotKitError> {
        let load = self.vtable.load_secret.expect("checked in from_c");
        let free_secret = self.vtable.free_secret.expect("checked in from_c");
        let user_data = self.vtable.user_data;

        let secret_key_hex = with_c_str(&label, "load_secret", |label| {
            with_c_str(&account_id_hex, "load_secret", |account| {
                let mut out: *mut c_char = std::ptr::null_mut();
                guard("load_secret", || unsafe {
                    load(user_data, label, account, &raw mut out)
                })?;
                if out.is_null() {
                    return Err(MarmotKitError::Runtime {
                        details: "host secret store returned OK with a NULL secret".to_owned(),
                    });
                }

                // Copy into a zeroizing buffer and hand the host's buffer
                // back immediately: the plaintext exists in two places for
                // as short a window as the boundary allows.
                let copied = unsafe { CStr::from_ptr(out) }
                    .to_str()
                    .map(|text| Zeroizing::new(text.to_owned()))
                    .map_err(|_| MarmotKitError::Runtime {
                        details: "host secret store returned non-UTF-8 hex".to_owned(),
                    });
                crate::memory::free_guard(|| unsafe { free_secret(user_data, out) });
                copied
            })
        })?;

        Ok(secret_key_hex.to_string())
    }

    fn remove_secret(&self, label: String, account_id_hex: String) -> Result<(), MarmotKitError> {
        let remove = self.vtable.remove_secret.expect("checked in from_c");
        let user_data = self.vtable.user_data;

        with_c_str(&label, "remove_secret", |label| {
            with_c_str(&account_id_hex, "remove_secret", |account| {
                guard("remove_secret", || unsafe {
                    remove(user_data, label, account)
                })
            })
        })
    }
}

impl CSecretStore {
    /// Shared body of the two `has_*` probes: both take one key and write a
    /// `uint8_t` presence flag.
    fn has(
        &self,
        callback: MarmotSecretStoreHasFn,
        key: &str,
        op: &str,
    ) -> Result<bool, MarmotKitError> {
        let callback = callback.expect("checked in from_c");
        let user_data = self.vtable.user_data;

        with_c_str(key, op, |key| {
            let mut present: u8 = 0;
            guard(op, || unsafe { callback(user_data, key, &raw mut present) })?;
            Ok(crate::memory::c_bool(present))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Host-side state a test vtable operates on, reached through
    /// `user_data`.
    #[derive(Default)]
    struct HostState {
        entries: Mutex<Vec<(String, String)>>,
        freed: Mutex<usize>,
        destroyed: Mutex<bool>,
        /// Status every op returns instead of running, when set.
        forced_status: Mutex<Option<u32>>,
    }

    unsafe fn state<'a>(user_data: *mut c_void) -> &'a HostState {
        unsafe { &*(user_data as *const HostState) }
    }

    unsafe extern "C" fn has_label(
        user_data: *mut c_void,
        key: *const c_char,
        out_present: *mut u8,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap().to_owned();
        let present = host.entries.lock().unwrap().iter().any(|(k, _)| *k == key);
        unsafe { out_present.write(u8::from(present)) };
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn has_account(
        _user_data: *mut c_void,
        _key: *const c_char,
        out_present: *mut u8,
    ) -> u32 {
        unsafe { out_present.write(0) };
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn write_secret(
        user_data: *mut c_void,
        label: *const c_char,
        _account: *const c_char,
        secret: *const c_char,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let label = unsafe { CStr::from_ptr(label) }
            .to_str()
            .unwrap()
            .to_owned();
        let secret = unsafe { CStr::from_ptr(secret) }
            .to_str()
            .unwrap()
            .to_owned();
        host.entries.lock().unwrap().push((label, secret));
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn load_secret(
        user_data: *mut c_void,
        label: *const c_char,
        _account: *const c_char,
        out_secret: *mut *mut c_char,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let label = unsafe { CStr::from_ptr(label) }
            .to_str()
            .unwrap()
            .to_owned();
        let found = host
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| *k == label)
            .map(|(_, secret)| secret.clone());
        let Some(secret) = found else {
            return MarmotSecretStoreStatus::NotFound as u32;
        };
        // The host owns this allocation until free_secret hands it back.
        unsafe { out_secret.write(std::ffi::CString::new(secret).unwrap().into_raw()) };
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn remove_secret(
        user_data: *mut c_void,
        label: *const c_char,
        _account: *const c_char,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        let label = unsafe { CStr::from_ptr(label) }
            .to_str()
            .unwrap()
            .to_owned();
        host.entries.lock().unwrap().retain(|(k, _)| *k != label);
        MarmotSecretStoreStatus::Ok as u32
    }

    unsafe extern "C" fn free_secret(user_data: *mut c_void, secret: *mut c_char) {
        let host = unsafe { state(user_data) };
        *host.freed.lock().unwrap() += 1;
        drop(unsafe { std::ffi::CString::from_raw(secret) });
    }

    unsafe extern "C" fn destroy(user_data: *mut c_void) {
        *unsafe { state(user_data) }.destroyed.lock().unwrap() = true;
    }

    fn vtable(host: &HostState) -> MarmotSecretStore {
        MarmotSecretStore {
            user_data: std::ptr::from_ref(host) as *mut c_void,
            has_secret_for_label: Some(has_label),
            has_secret_for_account_id: Some(has_account),
            write_secret: Some(write_secret),
            load_secret: Some(load_secret),
            remove_secret: Some(remove_secret),
            free_secret: Some(free_secret),
            destroy: Some(destroy),
        }
    }

    fn store(host: &HostState) -> CSecretStore {
        let vtable = vtable(host);
        unsafe { CSecretStore::from_c(&raw const vtable) }.expect("valid vtable")
    }

    #[test]
    fn callback_store_roundtrips_a_secret() {
        let host = HostState::default();
        let store = store(&host);

        assert!(!store.has_secret_for_label("a".into()).unwrap());
        store
            .write_secret("a".into(), "ff".into(), "deadbeef".into())
            .unwrap();
        assert!(store.has_secret_for_label("a".into()).unwrap());
        assert_eq!(
            store.load_secret("a".into(), "ff".into()).unwrap(),
            "deadbeef"
        );
        // The host's buffer went straight back through free_secret.
        assert_eq!(*host.freed.lock().unwrap(), 1);

        store.remove_secret("a".into(), "ff".into()).unwrap();
        assert!(!store.has_secret_for_label("a".into()).unwrap());
        assert!(matches!(
            store.load_secret("a".into(), "ff".into()),
            Err(MarmotKitError::SecretNotFound { .. })
        ));
    }

    #[test]
    fn destroy_fires_once_when_the_store_is_released() {
        let host = HostState::default();
        drop(store(&host));
        assert!(*host.destroyed.lock().unwrap());
    }

    #[test]
    fn error_statuses_map_to_their_marmot_status() {
        let host = HostState::default();
        let store = store(&host);

        for (raw, expected) in [
            (
                MarmotSecretStoreStatus::NotFound,
                MarmotStatus::SecretNotFound,
            ),
            (
                MarmotSecretStoreStatus::Unavailable,
                MarmotStatus::KeystoreUnavailable,
            ),
            (MarmotSecretStoreStatus::Failed, MarmotStatus::Runtime),
        ] {
            *host.forced_status.lock().unwrap() = Some(raw as u32);
            let err = store
                .has_secret_for_label("a".into())
                .expect_err("forced failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
        }
    }

    #[test]
    fn an_out_of_range_status_is_rejected_as_invalid_argument() {
        // The discriminant validation itself is what the C caller sees as
        // MARMOT_STATUS_INVALID_ARGUMENT.
        assert_eq!(
            MarmotSecretStoreStatus::from_c(4),
            Err(MarmotStatus::InvalidArgument)
        );
        assert_eq!(
            MarmotSecretStoreStatus::from_c(u32::MAX),
            Err(MarmotStatus::InvalidArgument)
        );

        // An out-of-range status from a live callback surfaces as a store
        // failure rather than being read as a valid enum (which would be
        // undefined behavior).
        let host = HostState::default();
        let store = store(&host);
        *host.forced_status.lock().unwrap() = Some(4242);
        let err = store
            .has_secret_for_label("a".into())
            .expect_err("out-of-range status");
        assert!(err.to_string().contains("out of range"), "{err}");
    }

    #[test]
    fn a_panic_around_a_callback_is_caught_and_reported() {
        // A panic must never unwind out of the store adapter into the
        // runtime worker that called it. (A panic inside the `extern "C"`
        // callback itself aborts at its own ABI boundary and is
        // unreachable from here, which is exactly why the host contract
        // forbids unwinding.)
        let err = guard("load_secret", || panic!("marshalling blew up"))
            .expect_err("panic must not escape");
        assert!(err.to_string().contains("panicked"), "{err}");
    }

    #[test]
    fn a_missing_required_callback_is_rejected() {
        let host = HostState::default();
        let mut vtable = vtable(&host);
        vtable.load_secret = None;
        assert_eq!(
            unsafe { CSecretStore::from_c(&raw const vtable) }.err(),
            Some(MarmotStatus::NullPointer)
        );
        assert_eq!(
            unsafe { CSecretStore::from_c(std::ptr::null()) }.err(),
            Some(MarmotStatus::NullPointer)
        );
    }
}
