//! Host-supplied account-secret storage over a C callback vtable.
//!
//! `marmot_client_new` keeps account signing keys in the platform keychain.
//! A host that already owns an encrypted store (a desktop client with a
//! password-sealed vault, for example) fills in a [`MarmotSecretStore`] and
//! constructs with [`crate::marmot_client_new_with_secret_store`] instead.
//! The signing key crosses as secret-key hex; an account is identified by
//! a borrowed credential receipt containing its label, account, home, owner,
//! and credential kind. Hosts must retain receipt retirement metadata.
//!
//! **Rules for the host, all of them load-bearing:**
//!
//! - **Thread safety.** Pending wipe replay can invoke callbacks on the
//!   constructor's calling thread. Callbacks can also run on runtime workers
//!   and may run concurrently. `user_data` access must be synchronized.
//! - **No re-entry.** A callback must not call any `marmot_*` function on
//!   the same client or mutate the same account root through another client.
//!   Account-home mutation is coordinated across independently opened handles,
//!   so re-entering can deadlock.
//! - **No unwinding.** A callback must return a status, never unwind. The
//!   callbacks are `extern "C"`, whose ABI aborts the process on an escaping
//!   unwind, so neither a C++ exception nor a Rust panic raised *inside* a
//!   callback can be recovered. Everything the library itself runs around
//!   the call (argument marshalling, status validation) is wrapped in
//!   `catch_unwind` and reported as a store failure instead.
//! - **Storage boundary, not a security boundary.** The plaintext key hex
//!   crosses in both directions. Rust holds it zeroizing for the shortest
//!   window it can, and hands buffers returned by acquisition or loading
//!   back to `free_secret` on every status; protecting keys at rest is the host's job.
//! - **Ownership.** The [`MarmotSecretStore`] struct is *copied* at
//!   construction, so the caller may free their copy as soon as the call
//!   returns. `user_data` must stay alive until `destroy` fires, which
//!   happens when the last runtime reference is released (at or shortly
//!   after `marmot_client_free`). A constructor that returns anything but
//!   `MARMOT_STATUS_OK` never calls `destroy` — construction took no
//!   ownership, and reclaiming `user_data` stays the host's job.

use std::ffi::{CStr, c_char, c_void};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};

use marmot_uniffi::{
    AcquiredSecret, MarmotKitError, SecretClaimMode, SecretCredential, SecretCredentialKind,
    SecretOrigin, SecretReleaseMode, SecretReleaseOutcome, SecretStore,
};
use zeroize::Zeroizing;

use crate::MarmotStatus;
use crate::macros::c_enum;
use crate::status::set_last_error;

c_enum! {
    /// Status a [`MarmotSecretStore`] callback returns. Crosses as
    /// `uint32_t`. An out-of-range value is rejected, and surfaces to the
    /// caller as a store failure, with detail in `marmot_last_error_message`.
    /// A callback's return travels
    /// back through the runtime's typed errors, so it cannot become
    /// `MARMOT_STATUS_INVALID_ARGUMENT`, which is reserved for values the
    /// caller passes *in*.
    MarmotSecretStoreStatus {
        /// The operation succeeded.
        Ok,
        /// No credential or discoverable source exists. Releasing an
        /// already retired receipt succeeds.
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

/// Return the vault's stable, nonsecret UTF-8 identity, including while locked.
/// Different vaults/services require different IDs, preserved across restarts.
/// Keep the credential target fixed until `destroy`; switching vaults/tenants
/// requires a new store context with a different namespace.
/// Write an owned NUL-terminated string to `out_namespace`; the library returns
/// every non-NULL output through `free_secret`, even on failure.
pub type MarmotSecretStoreCleanupNamespaceFn =
    Option<unsafe extern "C" fn(user_data: *mut c_void, out_namespace: *mut *mut c_char) -> u32>;

c_enum! {
    /// Credential purpose. Fields and callback arguments cross as uint32_t.
    MarmotSecretCredentialKind from SecretCredentialKind { Signing, ExternalDatabase, Nip46Session }
}
c_enum! {
    /// Whether acquisition creates material, adopts it, or permits either.
    MarmotSecretClaimMode from SecretClaimMode {
        /// Require a proposal and reject discoverable material.
        CreateOnly,
        /// Require an existing managed source; any proposal must match it.
        AdoptOnly,
        /// Adopt matching managed material, or create from a proposal.
        CreateOrAdopt,
        /// Explicitly permit legacy lookup and retain its cleanup pointer.
        MigrateLegacy,
    }
}
c_enum! {
    /// Original acquisition result, unchanged by same-owner retries.
    MarmotSecretOrigin from SecretOrigin { Created, Existing }
}
c_enum! {
    /// Retire and delete this receipt, or preserve it until a new adoption.
    MarmotSecretReleaseMode from SecretReleaseMode { DeleteIfUnowned, Preserve }
}
c_enum! {
    /// PendingLegacy confirms managed retirement/deletion; only raw legacy cleanup is unresolved.
    MarmotSecretReleaseOutcome from SecretReleaseOutcome { Released, PendingLegacy }
}

/// Borrowed receipt identity. All strings and this record are valid only
/// during the callback and must not be retained. `kind` is a
/// MarmotSecretCredentialKind discriminant, not a C enum field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MarmotSecretCredential {
    pub label: *const c_char,
    pub account_id_hex: *const c_char,
    pub home_id: *const c_char,
    pub owner_id: *const c_char,
    pub kind: u32,
}

/// Acquire an immutable owner receipt. NULL `proposed_hex` means no proposal.
/// Write an allocated secret and MarmotSecretOrigin tag on success. Every
/// non-NULL secret output is returned through free_secret on every status.
/// Same-owner retries preserve material and origin. Retired owners cannot
/// acquire again. Signing secrets must derive the requested account ID.
/// Signing discovery is shared by account ID; auxiliary discovery is scoped
/// to the home and account. Ordinary modes must not inspect raw legacy keys.
/// Return MARMOT_SECRET_STORE_STATUS_NOT_FOUND only if there is no usable
/// source and no committed or pending receipt for this owner. If a lookup or
/// write is uncertain, return a different failure so the runtime keeps the
/// owner for recovery.
pub type MarmotSecretStoreAcquireFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        claim_mode: u32,
        proposed_hex: *const c_char,
        out_secret_key_hex: *mut *mut c_char,
        out_origin: *mut u32,
    ) -> u32,
>;

/// Load only this active owner's copy; return NOT_FOUND when absent, including retired owners.
/// Write allocated NUL-terminated secret-key hex to `out_secret_key_hex`. The library returns
/// every non-NULL output to `free_secret`, including failure and decode errors.
pub type MarmotSecretStoreLoadFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        out_secret_key_hex: *mut *mut c_char,
    ) -> u32,
>;

/// Retire only this receipt. Preserve retains a source until a new owner
/// durably adopts it; repeating an old release cannot resurrect that source.
/// Write a MarmotSecretReleaseOutcome tag on success.
/// PendingLegacy requires completed managed retirement and deletion. Return a
/// failure status for uncertain or failed managed deletion, not PendingLegacy.
pub type MarmotSecretStoreReleaseFn = Option<
    unsafe extern "C" fn(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        release_mode: u32,
        out_outcome: *mut u32,
    ) -> u32,
>;

/// Replay durable retirement cleanup without deleting another owner's copy.
pub type MarmotSecretStoreReconcileFn = Option<unsafe extern "C" fn(user_data: *mut c_void) -> u32>;

/// `free_secret`: release a buffer returned by `acquire_secret`, `load_secret` or
/// `cleanup_namespace`. Namespace buffers contain no secret material.
pub type MarmotSecretStoreFreeSecretFn =
    Option<unsafe extern "C" fn(user_data: *mut c_void, secret_key_hex: *mut c_char)>;

/// `destroy`: the library is done with `user_data`.
pub type MarmotSecretStoreDestroyFn = Option<unsafe extern "C" fn(user_data: *mut c_void)>;

/// Callback vtable for host-owned account-secret storage. Borrowed input:
/// the fields are copied at construction and the struct itself is never
/// retained or freed by the library. Every function pointer except
/// `destroy` is required.
///
/// Callbacks can run on runtime workers or synchronously on a calling thread,
/// including during pending wipe replay in a constructor. Callbacks may run
/// concurrently. Synchronize access to `user_data` and do not call `marmot_*`
/// functions on this client or mutate the same account root from a callback.
/// The library returns every non-NULL namespace or secret buffer to
/// `free_secret`, even if the callback reports failure.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MarmotSecretStore {
    /// Opaque host context passed to every callback. On successful open, keep
    /// it valid until the last runtime reference to the store is released.
    pub user_data: *mut c_void,
    pub cleanup_namespace: MarmotSecretStoreCleanupNamespaceFn,
    pub has_secret_for_label: MarmotSecretStoreHasFn,
    pub has_secret_for_account_id: MarmotSecretStoreHasFn,
    pub acquire_secret: MarmotSecretStoreAcquireFn,
    pub load_secret: MarmotSecretStoreLoadFn,
    pub release_secret: MarmotSecretStoreReleaseFn,
    pub reconcile_cleanup: MarmotSecretStoreReconcileFn,
    pub free_secret: MarmotSecretStoreFreeSecretFn,
    /// Optional; invoked once when the last runtime reference to the store
    /// is released. NULL means the host reclaims `user_data` itself.
    pub destroy: MarmotSecretStoreDestroyFn,
}

/// Adapts the C vtable to the UniFFI `SecretStore` trait.
///
/// `Send`/`Sync` rest on the documented host contract: the callbacks and
/// any access to `user_data` must be thread-safe, because the runtime
/// invokes them on constructor callers and workers, possibly concurrently.
pub(crate) struct CSecretStore {
    vtable: MarmotSecretStore,
    /// Set once the client handle reaches the caller. Construction can
    /// still fail after the vtable is accepted (bad `root_path`, runtime
    /// build, store open); `destroy` must not fire on that path, or a host
    /// that reclaims `user_data` after the failed call frees it twice.
    armed: AtomicBool,
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
            ("cleanup_namespace", vtable.cleanup_namespace.is_some()),
            (
                "has_secret_for_label",
                vtable.has_secret_for_label.is_some(),
            ),
            (
                "has_secret_for_account_id",
                vtable.has_secret_for_account_id.is_some(),
            ),
            ("acquire_secret", vtable.acquire_secret.is_some()),
            ("load_secret", vtable.load_secret.is_some()),
            ("release_secret", vtable.release_secret.is_some()),
            ("reconcile_cleanup", vtable.reconcile_cleanup.is_some()),
            ("free_secret", vtable.free_secret.is_some()),
        ];
        for (name, present) in required {
            if !present {
                set_last_error(format!("secret store callback {name} was NULL"));
                return Err(MarmotStatus::NullPointer);
            }
        }

        Ok(Self {
            vtable,
            armed: AtomicBool::new(false),
        })
    }

    /// Take ownership of `user_data`: from here on `destroy` fires when the
    /// last runtime reference goes away.
    pub(crate) fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

impl Drop for CSecretStore {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
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

fn with_credential<R>(
    value: &SecretCredential,
    op: &str,
    call: impl FnOnce(*const MarmotSecretCredential) -> Result<R, MarmotKitError>,
) -> Result<R, MarmotKitError> {
    with_c_str(&value.label, op, |label| {
        with_c_str(&value.account_id_hex, op, |account_id_hex| {
            with_c_str(&value.home_id, op, |home_id| {
                with_c_str(&value.owner_id, op, |owner_id| {
                    let kind = MarmotSecretCredentialKind::from(value.kind) as u32;
                    call(&MarmotSecretCredential {
                        label,
                        account_id_hex,
                        home_id,
                        owner_id,
                        kind,
                    })
                })
            })
        })
    })
}

impl SecretStore for CSecretStore {
    fn cleanup_namespace(&self) -> Result<String, MarmotKitError> {
        let callback = self.vtable.cleanup_namespace.expect("checked in from_c");
        let free_secret = self.vtable.free_secret.expect("checked in from_c");
        let user_data = self.vtable.user_data;
        let mut out = std::ptr::null_mut();
        let status = guard("cleanup_namespace", || unsafe {
            callback(user_data, &raw mut out)
        });
        let namespace = status.and_then(|()| {
            if out.is_null() {
                return Err(MarmotKitError::Runtime {
                    details: "host secret store returned OK with a NULL namespace".to_owned(),
                });
            }
            unsafe { CStr::from_ptr(out) }
                .to_str()
                .map(str::to_owned)
                .map_err(|_| MarmotKitError::Runtime {
                    details: "host secret store returned a non-UTF-8 namespace".to_owned(),
                })
        });
        if !out.is_null() {
            crate::memory::free_guard(|| unsafe { free_secret(user_data, out) });
        }
        namespace
    }

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

    fn acquire_secret(
        &self,
        credential: SecretCredential,
        mode: SecretClaimMode,
        proposed: Option<String>,
    ) -> Result<AcquiredSecret, MarmotKitError> {
        let callback = self.vtable.acquire_secret.expect("checked in from_c");
        let proposed = proposed
            .map(|value| {
                let mut value = Zeroizing::new(value.into_bytes());
                if value.contains(&0) {
                    return Err(MarmotKitError::Runtime {
                        details: "secret store proposal contained a NUL byte".into(),
                    });
                }
                if value.len() == value.capacity() {
                    let mut terminated = Zeroizing::new(Vec::with_capacity(value.len() + 1));
                    terminated.extend_from_slice(&value);
                    terminated.push(0);
                    return Ok(terminated);
                }
                value.push(0);
                Ok(value)
            })
            .transpose()?;
        let mode = MarmotSecretClaimMode::from(mode) as u32;
        with_credential(&credential, "acquire_secret", |credential| {
            let mut out = std::ptr::null_mut();
            let mut origin = u32::MAX;
            let status = guard("acquire_secret", || unsafe {
                callback(
                    self.vtable.user_data,
                    credential,
                    mode,
                    proposed
                        .as_ref()
                        .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
                    &raw mut out,
                    &raw mut origin,
                )
            });
            let mut secret = self.secret_output(out, status)?;
            let origin = match MarmotSecretOrigin::from_c(origin) {
                Ok(MarmotSecretOrigin::Created) => SecretOrigin::Created,
                Ok(MarmotSecretOrigin::Existing) => SecretOrigin::Existing,
                Err(_) => {
                    return Err(MarmotKitError::Runtime {
                        details: "host secret store returned an invalid origin tag".into(),
                    });
                }
            };
            Ok(AcquiredSecret {
                secret_key_hex: std::mem::take(&mut *secret),
                origin,
            })
        })
    }

    fn load_secret(&self, credential: SecretCredential) -> Result<String, MarmotKitError> {
        let callback = self.vtable.load_secret.expect("checked in from_c");
        with_credential(&credential, "load_secret", |credential| {
            let mut out = std::ptr::null_mut();
            let status = guard("load_secret", || unsafe {
                callback(self.vtable.user_data, credential, &raw mut out)
            });
            let mut secret = self.secret_output(out, status)?;
            Ok(std::mem::take(&mut *secret))
        })
    }

    fn release_secret(
        &self,
        credential: SecretCredential,
        mode: SecretReleaseMode,
    ) -> Result<SecretReleaseOutcome, MarmotKitError> {
        let callback = self.vtable.release_secret.expect("checked in from_c");
        let mode = MarmotSecretReleaseMode::from(mode) as u32;
        with_credential(&credential, "release_secret", |credential| {
            let mut outcome = u32::MAX;
            guard("release_secret", || unsafe {
                callback(self.vtable.user_data, credential, mode, &raw mut outcome)
            })?;
            match MarmotSecretReleaseOutcome::from_c(outcome) {
                Ok(MarmotSecretReleaseOutcome::Released) => Ok(SecretReleaseOutcome::Released),
                Ok(MarmotSecretReleaseOutcome::PendingLegacy) => {
                    Ok(SecretReleaseOutcome::PendingLegacy)
                }
                Err(_) => Err(MarmotKitError::Runtime {
                    details: "host secret store returned an invalid release outcome tag".into(),
                }),
            }
        })
    }

    fn reconcile_cleanup(&self) -> Result<(), MarmotKitError> {
        let callback = self.vtable.reconcile_cleanup.expect("checked in from_c");
        guard("reconcile_cleanup", || unsafe {
            callback(self.vtable.user_data)
        })
    }
}

impl CSecretStore {
    fn secret_output(
        &self,
        out: *mut c_char,
        status: Result<(), MarmotKitError>,
    ) -> Result<Zeroizing<String>, MarmotKitError> {
        let copied = status.and_then(|()| {
            if out.is_null() {
                return Err(MarmotKitError::Runtime {
                    details: "host secret store returned OK with a NULL secret".into(),
                });
            }
            unsafe { CStr::from_ptr(out) }
                .to_str()
                .map(|text| Zeroizing::new(text.to_owned()))
                .map_err(|_| MarmotKitError::Runtime {
                    details: "host secret store returned non-UTF-8 hex".into(),
                })
        });
        if !out.is_null() {
            let free = self.vtable.free_secret.expect("checked in from_c");
            crate::memory::free_guard(|| unsafe { free(self.vtable.user_data, out) });
        }
        copied
    }

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
use crate::secret_store as host_abi;

#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/support/owned_store.rs"]
pub(crate) mod fixture;

#[cfg(test)]
pub(crate) fn fixture_store() -> std::sync::Arc<CSecretStore> {
    let data = Box::into_raw(Box::new(fixture::MemoryVault::default()));
    let mut table = unsafe { &*data }.table();
    table.user_data = data.cast();
    table.destroy = Some(fixture::MemoryVault::destroy_box);
    let store = match unsafe { CSecretStore::from_c(&table) } {
        Ok(store) => store,
        Err(status) => {
            unsafe { fixture::MemoryVault::destroy_box(data.cast()) };
            panic!("complete fixture vtable rejected: {status:?}");
        }
    };
    store.arm();
    std::sync::Arc::new(store)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Host-side state a test vtable operates on, reached through
    /// `user_data`.
    #[derive(Default)]
    struct HostState {
        namespace: std::sync::OnceLock<String>,
        namespace_bytes: Mutex<Option<Vec<u8>>>,
        namespace_null: AtomicBool,
        vault: fixture::MemoryVault,
        output_bytes: Mutex<Option<Vec<u8>>>,
        output_null: AtomicBool,
        origin_tag: Mutex<Option<u32>>,
        outcome_tag: Mutex<Option<u32>>,
        outputs_initialized: AtomicBool,
        freed: Mutex<usize>,
        destroyed: Mutex<bool>,
        /// Status every op returns instead of running, when set.
        forced_status: Mutex<Option<u32>>,
    }

    unsafe fn state<'a>(user_data: *mut c_void) -> &'a HostState {
        unsafe { &*(user_data as *const HostState) }
    }

    unsafe extern "C" fn cleanup_namespace(user_data: *mut c_void, out: *mut *mut c_char) -> u32 {
        let host = unsafe { state(user_data) };
        if !host.namespace_null.load(Ordering::SeqCst) {
            let namespace = host
                .namespace
                .get_or_init(|| nostr::prelude::Keys::generate().public_key().to_hex());
            let bytes = host.namespace_bytes.lock().unwrap();
            let bytes = bytes.as_deref().unwrap_or(namespace.as_bytes());
            unsafe { out.write(std::ffi::CString::new(bytes).unwrap().into_raw()) };
        }
        host.forced_status
            .lock()
            .unwrap()
            .unwrap_or(MarmotSecretStoreStatus::Ok as u32)
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
        let table = host.vault.table();
        unsafe { table.has_secret_for_label.unwrap()(table.user_data, key, out_present) }
    }

    unsafe extern "C" fn has_account(
        user_data: *mut c_void,
        key: *const c_char,
        out_present: *mut u8,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let table = host.vault.table();
        unsafe { table.has_secret_for_account_id.unwrap()(table.user_data, key, out_present) }
    }

    unsafe extern "C" fn acquire_secret(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        mode: u32,
        proposed: *const c_char,
        out: *mut *mut c_char,
        origin: *mut u32,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        host.outputs_initialized.store(
            unsafe { (*out).is_null() && *origin == u32::MAX },
            Ordering::SeqCst,
        );
        let forced = *host.forced_status.lock().unwrap();
        let bytes = host.output_bytes.lock().unwrap();
        if forced.is_some() || bytes.is_some() || host.output_null.load(Ordering::SeqCst) {
            if !host.output_null.load(Ordering::SeqCst) {
                unsafe {
                    out.write(
                        std::ffi::CString::new(bytes.as_deref().unwrap_or(b"allocated failure"))
                            .unwrap()
                            .into_raw(),
                    )
                };
            }
            unsafe { origin.write(MarmotSecretOrigin::Created as u32) };
            return forced.unwrap_or(MarmotSecretStoreStatus::Ok as u32);
        }
        let table = host.vault.table();
        let status = unsafe {
            table.acquire_secret.unwrap()(table.user_data, credential, mode, proposed, out, origin)
        };
        if let Some(tag) = *host.origin_tag.lock().unwrap() {
            unsafe { origin.write(tag) };
        }
        status
    }

    unsafe extern "C" fn load_secret(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        out: *mut *mut c_char,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        host.outputs_initialized
            .store(unsafe { (*out).is_null() }, Ordering::SeqCst);
        let forced = *host.forced_status.lock().unwrap();
        let bytes = host.output_bytes.lock().unwrap();
        if forced.is_some() || bytes.is_some() || host.output_null.load(Ordering::SeqCst) {
            if !host.output_null.load(Ordering::SeqCst) {
                unsafe {
                    out.write(
                        std::ffi::CString::new(bytes.as_deref().unwrap_or(b"allocated failure"))
                            .unwrap()
                            .into_raw(),
                    )
                };
            }
            return forced.unwrap_or(MarmotSecretStoreStatus::Ok as u32);
        }
        let table = host.vault.table();
        unsafe { table.load_secret.unwrap()(table.user_data, credential, out) }
    }

    unsafe extern "C" fn release_secret(
        user_data: *mut c_void,
        credential: *const MarmotSecretCredential,
        mode: u32,
        outcome: *mut u32,
    ) -> u32 {
        let host = unsafe { state(user_data) };
        host.outputs_initialized
            .store(unsafe { *outcome == u32::MAX }, Ordering::SeqCst);
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let table = host.vault.table();
        let status =
            unsafe { table.release_secret.unwrap()(table.user_data, credential, mode, outcome) };
        if let Some(tag) = *host.outcome_tag.lock().unwrap() {
            unsafe { outcome.write(tag) };
        }
        status
    }

    unsafe extern "C" fn reconcile_cleanup(user_data: *mut c_void) -> u32 {
        let host = unsafe { state(user_data) };
        if let Some(status) = *host.forced_status.lock().unwrap() {
            return status;
        }
        let table = host.vault.table();
        unsafe { table.reconcile_cleanup.unwrap()(table.user_data) }
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
            cleanup_namespace: Some(cleanup_namespace),
            has_secret_for_label: Some(has_label),
            has_secret_for_account_id: Some(has_account),
            acquire_secret: Some(acquire_secret),
            load_secret: Some(load_secret),
            release_secret: Some(release_secret),
            reconcile_cleanup: Some(reconcile_cleanup),
            free_secret: Some(free_secret),
            destroy: Some(destroy),
        }
    }

    fn store(host: &HostState) -> CSecretStore {
        let vtable = vtable(host);
        unsafe { CSecretStore::from_c(&raw const vtable) }.expect("valid vtable")
    }

    #[test]
    fn namespace_buffers_are_freed() {
        let host = HostState::default();
        host.namespace.set("fixture-vault-λ".to_owned()).unwrap();
        let store = store(&host);
        assert_eq!(store.cleanup_namespace().unwrap(), "fixture-vault-λ");
        assert_eq!(store.cleanup_namespace().unwrap(), "fixture-vault-λ");
        assert_eq!(*host.freed.lock().unwrap(), 2);

        *host.namespace_bytes.lock().unwrap() = Some(vec![0xff]);
        assert!(
            matches!(store.cleanup_namespace(), Err(MarmotKitError::Runtime { details }) if details == "host secret store returned a non-UTF-8 namespace")
        );
        assert_eq!(*host.freed.lock().unwrap(), 3);

        host.namespace_null.store(true, Ordering::SeqCst);
        assert!(
            matches!(store.cleanup_namespace(), Err(MarmotKitError::Runtime { details }) if details == "host secret store returned OK with a NULL namespace")
        );
        assert_eq!(*host.freed.lock().unwrap(), 3);
        host.namespace_null.store(false, Ordering::SeqCst);
        *host.namespace_bytes.lock().unwrap() = Some(b"valid failure namespace".to_vec());

        for (raw, expected, expected_details) in [
            (
                MarmotSecretStoreStatus::NotFound as u32,
                MarmotStatus::SecretNotFound,
                "host secret store has no credential (cleanup_namespace)",
            ),
            (
                MarmotSecretStoreStatus::Unavailable as u32,
                MarmotStatus::KeystoreUnavailable,
                "host secret store unavailable (cleanup_namespace)",
            ),
            (
                MarmotSecretStoreStatus::Failed as u32,
                MarmotStatus::Runtime,
                "host secret store failed (cleanup_namespace)",
            ),
            (
                u32::MAX,
                MarmotStatus::Runtime,
                "host secret store returned status 4294967295 out of range (cleanup_namespace)",
            ),
        ] {
            *host.forced_status.lock().unwrap() = Some(raw);
            let freed = *host.freed.lock().unwrap();
            let error = store
                .cleanup_namespace()
                .expect_err("callback failure must propagate");
            assert_eq!(crate::status::status_from_error(&error), expected);
            match error {
                MarmotKitError::SecretNotFound { details }
                | MarmotKitError::KeystoreUnavailable { details }
                | MarmotKitError::Runtime { details } => assert_eq!(details, expected_details),
                other => panic!("unexpected callback error: {other:?}"),
            }
            assert_eq!(*host.freed.lock().unwrap(), freed + 1);
        }
    }

    #[test]
    fn callback_store_roundtrips_a_secret() {
        let host = HostState::default();
        let store = store(&host);
        let keys = nostr::prelude::Keys::generate();
        let secret = keys.secret_key().to_secret_hex();
        let credential = credential(&keys.public_key().to_hex());

        assert!(!store.has_secret_for_label("a".into()).unwrap());
        let acquired = store
            .acquire_secret(
                credential.clone(),
                SecretClaimMode::CreateOnly,
                Some(secret.clone()),
            )
            .unwrap();
        assert_eq!(acquired.secret_key_hex, secret);
        assert!(matches!(acquired.origin, SecretOrigin::Created));
        assert!(host.outputs_initialized.load(Ordering::SeqCst));
        assert!(store.has_secret_for_label("a".into()).unwrap());
        assert!(
            store
                .has_secret_for_account_id(keys.public_key().to_hex())
                .unwrap()
        );
        assert_eq!(store.load_secret(credential.clone()).unwrap(), secret);
        assert!(host.outputs_initialized.load(Ordering::SeqCst));
        assert_eq!(*host.freed.lock().unwrap(), 2);
        let retry = store
            .acquire_secret(
                credential.clone(),
                SecretClaimMode::CreateOnly,
                Some(secret.clone()),
            )
            .unwrap();
        assert_eq!(retry.secret_key_hex, secret);
        assert!(matches!(retry.origin, SecretOrigin::Created));

        assert!(matches!(
            store
                .release_secret(credential.clone(), SecretReleaseMode::Preserve)
                .unwrap(),
            SecretReleaseOutcome::Released
        ));
        assert!(host.outputs_initialized.load(Ordering::SeqCst));
        let mut adopted = credential.clone();
        adopted.home_id = "33".repeat(32);
        adopted.owner_id = "44".repeat(32);
        let acquired = store
            .acquire_secret(adopted.clone(), SecretClaimMode::AdoptOnly, None)
            .unwrap();
        assert_eq!(acquired.secret_key_hex, secret);
        assert!(matches!(acquired.origin, SecretOrigin::Existing));
        store
            .release_secret(credential.clone(), SecretReleaseMode::Preserve)
            .unwrap();
        assert_eq!(store.load_secret(adopted.clone()).unwrap(), secret);

        store
            .release_secret(adopted, SecretReleaseMode::DeleteIfUnowned)
            .unwrap();
        store.reconcile_cleanup().unwrap();
        assert!(!store.has_secret_for_label("a".into()).unwrap());
        assert!(matches!(
            store.load_secret(credential.clone()),
            Err(MarmotKitError::SecretNotFound { .. })
        ));
        assert!(matches!(
            store.acquire_secret(credential, SecretClaimMode::CreateOnly, Some(secret)),
            Err(MarmotKitError::Runtime { .. })
        ));
    }

    fn credential(account: &str) -> SecretCredential {
        SecretCredential {
            label: "a".into(),
            account_id_hex: account.into(),
            home_id: "11".repeat(32),
            owner_id: "22".repeat(32),
            kind: SecretCredentialKind::Signing,
        }
    }

    #[test]
    fn destroy_fires_once_when_the_store_is_released() {
        let host = HostState::default();
        let store = store(&host);
        store.arm();
        drop(store);
        assert!(*host.destroyed.lock().unwrap());
    }

    #[test]
    fn destroy_is_suppressed_when_construction_never_armed_the_store() {
        // A constructor that fails after accepting the vtable drops the
        // store unarmed; the host still owns user_data.
        let host = HostState::default();
        drop(store(&host));
        assert!(!*host.destroyed.lock().unwrap());
    }

    #[test]
    fn error_statuses_map_to_their_marmot_status() {
        let host = HostState::default();
        let store = store(&host);

        for (raw, expected) in [
            (
                MarmotSecretStoreStatus::NotFound as u32,
                MarmotStatus::SecretNotFound,
            ),
            (
                MarmotSecretStoreStatus::Unavailable as u32,
                MarmotStatus::KeystoreUnavailable,
            ),
            (
                MarmotSecretStoreStatus::Failed as u32,
                MarmotStatus::Runtime,
            ),
            (u32::MAX, MarmotStatus::Runtime),
        ] {
            *host.forced_status.lock().unwrap() = Some(raw);
            let err = store
                .has_secret_for_label("a".into())
                .expect_err("forced failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
            let credential = credential(&"ff".repeat(32));
            let freed = *host.freed.lock().unwrap();
            let err = store
                .load_secret(credential.clone())
                .expect_err("allocated failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
            assert!(host.outputs_initialized.load(Ordering::SeqCst));
            assert_eq!(*host.freed.lock().unwrap(), freed + 1);
            let err = store
                .acquire_secret(credential.clone(), SecretClaimMode::AdoptOnly, None)
                .err()
                .expect("allocated failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
            assert!(host.outputs_initialized.load(Ordering::SeqCst));
            assert_eq!(*host.freed.lock().unwrap(), freed + 2);
            let err = store
                .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
                .expect_err("forced release failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
            assert!(host.outputs_initialized.load(Ordering::SeqCst));
            let err = store
                .reconcile_cleanup()
                .expect_err("forced cleanup failure");
            assert_eq!(crate::status::status_from_error(&err), expected);
        }
    }

    #[test]
    fn callback_outputs_are_checked() {
        let host = HostState::default();
        let store = store(&host);
        let keys = nostr::prelude::Keys::generate();
        let credential = credential(&keys.public_key().to_hex());
        let secret = keys.secret_key().to_secret_hex();

        *host.output_bytes.lock().unwrap() = Some(vec![0xff]);
        for acquire in [false, true] {
            let freed = *host.freed.lock().unwrap();
            let error = if acquire {
                store
                    .acquire_secret(
                        credential.clone(),
                        SecretClaimMode::CreateOnly,
                        Some(secret.clone()),
                    )
                    .map(|value| value.secret_key_hex)
            } else {
                store.load_secret(credential.clone())
            }
            .expect_err("invalid UTF-8 output");
            assert!(
                matches!(error, MarmotKitError::Runtime { details } if details == "host secret store returned non-UTF-8 hex")
            );
            assert_eq!(*host.freed.lock().unwrap(), freed + 1);
            assert!(host.outputs_initialized.load(Ordering::SeqCst));
        }
        *host.output_bytes.lock().unwrap() = None;
        host.output_null.store(true, Ordering::SeqCst);
        for acquire in [false, true] {
            let freed = *host.freed.lock().unwrap();
            let error = if acquire {
                store
                    .acquire_secret(
                        credential.clone(),
                        SecretClaimMode::CreateOnly,
                        Some(secret.clone()),
                    )
                    .map(|value| value.secret_key_hex)
            } else {
                store.load_secret(credential.clone())
            }
            .expect_err("NULL output");
            assert!(
                matches!(error, MarmotKitError::Runtime { details } if details == "host secret store returned OK with a NULL secret")
            );
            assert_eq!(*host.freed.lock().unwrap(), freed);
        }
        host.output_null.store(false, Ordering::SeqCst);

        *host.origin_tag.lock().unwrap() = Some(u32::MAX);
        let freed = *host.freed.lock().unwrap();
        let error = store
            .acquire_secret(
                credential.clone(),
                SecretClaimMode::CreateOnly,
                Some(secret),
            )
            .err()
            .expect("invalid origin");
        assert!(
            matches!(error, MarmotKitError::Runtime { details } if details == "host secret store returned an invalid origin tag")
        );
        assert_eq!(*host.freed.lock().unwrap(), freed + 1);
        *host.outcome_tag.lock().unwrap() = Some(MarmotSecretReleaseOutcome::PendingLegacy as u32);
        assert!(matches!(
            store
                .release_secret(credential.clone(), SecretReleaseMode::DeleteIfUnowned)
                .unwrap(),
            SecretReleaseOutcome::PendingLegacy
        ));
        *host.outcome_tag.lock().unwrap() = Some(u32::MAX);
        let error = store
            .release_secret(credential, SecretReleaseMode::DeleteIfUnowned)
            .expect_err("invalid outcome");
        assert!(
            matches!(error, MarmotKitError::Runtime { details } if details == "host secret store returned an invalid release outcome tag")
        );
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
        assert!(matches!(&err, MarmotKitError::Runtime { .. }));
        assert_eq!(
            crate::status::status_from_error(&err),
            MarmotStatus::Runtime
        );
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
        let remove: [fn(&mut MarmotSecretStore); 8] = [
            |v| v.cleanup_namespace = None,
            |v| v.has_secret_for_label = None,
            |v| v.has_secret_for_account_id = None,
            |v| v.acquire_secret = None,
            |v| v.load_secret = None,
            |v| v.release_secret = None,
            |v| v.reconcile_cleanup = None,
            |v| v.free_secret = None,
        ];
        for remove in remove {
            let mut vtable = vtable(&host);
            remove(&mut vtable);
            assert_eq!(
                unsafe { CSecretStore::from_c(&raw const vtable) }.err(),
                Some(MarmotStatus::NullPointer)
            );
        }
        assert_eq!(
            unsafe { CSecretStore::from_c(std::ptr::null()) }.err(),
            Some(MarmotStatus::NullPointer)
        );
    }
}
