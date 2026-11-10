//! C handles over the shared MDK NIP-46 session.

use std::ffi::c_char;
use std::sync::{Arc, Weak};

use marmot_uniffi::{Marmot, Nip46ErrorFfi, Nip46SessionFfi, Nip46StateFfi, Nip46StatusFfi};

use crate::macros::{c_enum, c_mirror};
use crate::memory::{self, CFree, required_str, str_array};
use crate::status::{MarmotStatus, set_last_error, status_from_error};
use crate::types::account::MarmotAccountSummary;
use crate::{MarmotClient, block_on_handle, client_ref, ffi_guard, preflight_out_ptr};

c_enum! {
    /// Shared signer lifecycle state. Approval is an intermediate auth challenge.
    MarmotNip46State from Nip46StateFfi {
        Unavailable,
        PermissionApproval,
        Connecting,
        Ready,
        Approval,
        Disconnected,
        Cancelled,
        LoggedOut,
        Reconnecting,
        Listening,
    }
}

c_enum! {
    /// Privacy-safe signer error vocabulary; distinct from the legacy status code.
    MarmotNip46Error from Nip46ErrorFfi {
        Invalid,
        ProxyConfig,
        Unavailable,
        RelayPublish,
        Rejected,
        Mismatch,
        Timeout,
        Cancelled,
        LoggedOut,
        Unsupported,
        PermissionApprovalRequired,
        Storage,
        Busy,
        Disconnected,
        RequestNotFound,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MarmotNip46Error {
    fn default() -> Self {
        Self::Invalid
    }
}

c_mirror! {
    /// Local shared signer snapshot without keys, pairing URI, or request payload.
    /// Only read last_error when has_last_error is true. Strings are nullable.
    MarmotNip46Status from Nip46StatusFfi, free marmot_nip46_status_free {
        copy state: MarmotNip46State,
        opt_copy has_last_error/last_error: MarmotNip46Error,
        opt_str auth_url,
        opt_str request_id,
        copy generation: u64,
    }
}

/// Opaque per-account remote signer. The creating client must outlive this handle.
/// Free releases only this handle; attached sessions remain owned by MDK.
/// Cancellation is thread-safe; free must not race an in-flight call.
pub struct MarmotNip46Session {
    inner: Arc<Nip46SessionFfi>,
    owner: Weak<Marmot>,
    runtime: tokio::runtime::Handle,
}

pub(crate) fn status_from_nip46_error(error: &Nip46ErrorFfi) -> MarmotStatus {
    set_last_error(error.to_string());
    match error {
        Nip46ErrorFfi::Invalid | Nip46ErrorFfi::ProxyConfig | Nip46ErrorFfi::RequestNotFound => {
            MarmotStatus::InvalidArgument
        }
        Nip46ErrorFfi::Timeout => MarmotStatus::Timeout,
        Nip46ErrorFfi::Rejected
        | Nip46ErrorFfi::Cancelled
        | Nip46ErrorFfi::PermissionApprovalRequired => MarmotStatus::ExternalSignerRejected,
        Nip46ErrorFfi::Mismatch => MarmotStatus::ExternalSignerMismatch,
        Nip46ErrorFfi::Busy => MarmotStatus::RuntimeBusy,
        Nip46ErrorFfi::Storage => MarmotStatus::Runtime,
        Nip46ErrorFfi::Unavailable
        | Nip46ErrorFfi::RelayPublish
        | Nip46ErrorFfi::LoggedOut
        | Nip46ErrorFfi::Unsupported
        | Nip46ErrorFfi::Disconnected => MarmotStatus::ExternalSignerUnavailable,
    }
}

unsafe fn session_ref<'a>(
    session: *const MarmotNip46Session,
) -> Result<&'a MarmotNip46Session, MarmotStatus> {
    if session.is_null() {
        set_last_error("NIP-46 session was NULL");
        return Err(MarmotStatus::NullPointer);
    }
    Ok(unsafe { &*session })
}

fn check_owner(client: &MarmotClient, session: &MarmotNip46Session) -> Result<(), MarmotStatus> {
    if Weak::ptr_eq(&Arc::downgrade(&client.marmot), &session.owner) {
        Ok(())
    } else {
        set_last_error("NIP-46 session belongs to another client");
        Err(MarmotStatus::InvalidArgument)
    }
}

fn owned_session(client: &MarmotClient, inner: Arc<Nip46SessionFfi>) -> MarmotNip46Session {
    MarmotNip46Session {
        inner,
        owner: Arc::downgrade(&client.marmot),
        runtime: client.runtime.handle().clone(),
    }
}

unsafe fn string_out(out: *mut *mut c_char, result: Result<String, Nip46ErrorFfi>) -> MarmotStatus {
    match result {
        Ok(value) => {
            unsafe { out.write(memory::owned_c_string(value)) };
            MarmotStatus::Ok
        }
        Err(error) => status_from_nip46_error(&error),
    }
}

/// Create an offline shared session from a bunker URI, pairing config, or export.
/// Explicitly review and approve permissions before obtaining a pairing URI or connecting.
/// # Safety
/// Client and config must be valid for the call; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_new(
    client: *const MarmotClient,
    config_json: *const c_char,
    out: *mut *mut MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let config = match unsafe { required_str(config_json) } {
            Ok(config) => config,
            Err(status) => return status,
        };
        match client.marmot.nip46_new(config) {
            Ok(session) => {
                unsafe { out.write(memory::boxed(owned_session(client, session))) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Get the pairing URI without network IO. Treat it as a credential.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_uri(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe { string_out(out, session.inner.uri()) }
    })
}

/// Start listening before displaying a client-initiated pairing URI. Run off UI.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_pairing_offer(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe {
            string_out(
                out,
                block_on_handle(&session.runtime, session.inner.pairing_offer()),
            )
        }
    })
}

/// Connect and pin the account identity. Run off the UI thread.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_connect(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe {
            string_out(
                out,
                block_on_handle(&session.runtime, session.inner.connect()),
            )
        }
    })
}

/// Export secret restart credentials for an optional encrypted-vault backup.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_export(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe { string_out(out, session.inner.export()) }
    })
}

/// Log in and persist the shared session in MDK's configured secret store.
/// NULL/0 inbox relays use the default relays.
/// # Safety
/// All pointers must be valid for the call. Free out with marmot_account_summary_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_login(
    client: *const MarmotClient,
    session: *const MarmotNip46Session,
    default_relays: *const *const c_char,
    default_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_len: usize,
    inbox_relays: *const *const c_char,
    inbox_len: usize,
    out: *mut *mut MarmotAccountSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        if let Err(status) = check_owner(client, session) {
            return status;
        }
        let defaults = match unsafe { str_array(default_relays, default_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        let bootstrap = match unsafe { str_array(bootstrap_relays, bootstrap_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        let inbox = match unsafe { str_array(inbox_relays, inbox_len) } {
            Ok(relays) => relays,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.nip46_login(
            session.inner.clone(),
            defaults,
            bootstrap,
            inbox,
        )) {
            Ok(summary) => {
                unsafe { out.write(memory::boxed(MarmotAccountSummary::from(summary))) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Attach an imported session to an existing external account and persist it.
/// # Safety
/// Client, account_ref, and session must be live and belong to the same client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_register(
    client: *const MarmotClient,
    account_ref: *const c_char,
    session: *const MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        if let Err(status) = check_owner(client, session) {
            return status;
        }
        let account = match unsafe { required_str(account_ref) } {
            Ok(account) => account,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.nip46_register(account, session.inner.clone())) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_error(&error),
        }
    })
}

/// Read compatibility JSON status without network access or secret payloads.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_state(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe { string_out(out, session.inner.state_json()) }
    })
}

/// Read typed local status, including cancellation and rejection distinctions.
/// # Safety
/// Session must be live; out writable. Free with marmot_nip46_status_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_status(
    session: *const MarmotNip46Session,
    out: *mut *mut MarmotNip46Status,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        unsafe {
            out.write(memory::boxed(MarmotNip46Status::from(
                session.inner.status(),
            )))
        };
        MarmotStatus::Ok
    })
}

/// Review the required permission version and grants as JSON before approval.
/// # Safety
/// Session must be live; out writable. Free with marmot_string_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_review_grants(
    session: *const MarmotNip46Session,
    out: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let permissions = session.inner.review_permissions();
        let json = serde_json::json!({"version":permissions.version,"grants":permissions.grants});
        unsafe { string_out(out, Ok(json.to_string())) }
    })
}

/// Approve exactly the reviewed permission version and grants after user consent.
/// # Safety
/// Session and borrowed grant strings must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_approve_grants(
    session: *const MarmotNip46Session,
    version: u32,
    grants: *const *const c_char,
    grants_len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let grants = match unsafe { str_array(grants, grants_len) } {
            Ok(grants) => grants,
            Err(status) => return status,
        };
        match block_on_handle(
            &session.runtime,
            session.inner.approve_permissions(version, grants),
        ) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_nip46_error(&error),
        }
    })
}

/// Check the remote signer through its shared transport. Run off the UI thread.
/// # Safety
/// Session must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_ping(session: *const MarmotNip46Session) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        match block_on_handle(&session.runtime, session.inner.ping()) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_nip46_error(&error),
        }
    })
}

/// Interrupt transport work while permitting explicit reconnect.
/// # Safety
/// Session must be live; may race operations, but not free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_disconnect(
    session: *const MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        session.inner.disconnect();
        MarmotStatus::Ok
    })
}

/// Cancel only the request identified by the current status snapshot.
/// # Safety
/// Session and request_id must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_cancel_request(
    session: *const MarmotNip46Session,
    request_id: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let id = match unsafe { required_str(request_id) } {
            Ok(id) => id,
            Err(status) => return status,
        };
        match session.inner.cancel_request(id) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_nip46_error(&error),
        }
    })
}

/// Acknowledge a matching auth challenge without completing its pending RPC.
/// # Safety
/// Session and request_id must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_complete_auth(
    session: *const MarmotNip46Session,
    request_id: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        let id = match unsafe { required_str(request_id) } {
            Ok(id) => id,
            Err(status) => return status,
        };
        match session.inner.complete_auth(id) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_nip46_error(&error),
        }
    })
}

/// Restore MDK-owned credentials without a host-exported descriptor.
/// # Safety
/// Client and account_ref must be valid; out writable. Free with marmot_nip46_free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_resume(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out: *mut *mut MarmotNip46Session,
) -> MarmotStatus {
    ffi_guard(|| {
        if let Err(status) = unsafe { preflight_out_ptr(out) } {
            return status;
        }
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let account = match unsafe { required_str(account_ref) } {
            Ok(account) => account,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.nip46_resume(account)) {
            Ok(session) => {
                unsafe { out.write(memory::boxed(owned_session(client, session))) };
                MarmotStatus::Ok
            }
            Err(error) => status_from_error(&error),
        }
    })
}

/// Detach the account session and remove its MDK-owned credentials.
/// # Safety
/// Client and account_ref must be valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_remove(
    client: *const MarmotClient,
    account_ref: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = match unsafe { client_ref(client) } {
            Ok(client) => client,
            Err(status) => return status,
        };
        let account = match unsafe { required_str(account_ref) } {
            Ok(account) => account,
            Err(status) => return status,
        };
        match client.block_on(client.marmot.nip46_remove(account)) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_error(&error),
        }
    })
}

/// Permanently interrupt the shared session, including identity-proof callbacks.
/// This affects the account signer and every handle sharing this session.
/// # Safety
/// Session must be NULL or live; may race operations, but not free.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_cancel(session: *const MarmotNip46Session) {
    memory::free_guard(|| {
        if let Some(session) = unsafe { session.as_ref() } {
            session.inner.cancel();
        }
    });
}

/// Attempt bounded courtesy logout and erase local communication credentials.
/// # Safety
/// Session must be live. This does not replace MDK account signout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_logout(session: *const MarmotNip46Session) -> MarmotStatus {
    ffi_guard(|| {
        let session = match unsafe { session_ref(session) } {
            Ok(session) => session,
            Err(status) => return status,
        };
        match block_on_handle(&session.runtime, session.inner.logout()) {
            Ok(()) => MarmotStatus::Ok,
            Err(error) => status_from_nip46_error(&error),
        }
    })
}

impl CFree for MarmotNip46Session {
    unsafe fn free_in_place(&mut self) {}
}

/// Release only this handle without cancelling the shared session or logging out.
/// MDK retains attached sessions. An unbound session stops when its final owner drops.
/// Persisted credentials are unchanged; use marmot_nip46_cancel for terminal cancellation.
/// # Safety
/// Session must be NULL or uniquely owned; no other call may be in flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_nip46_free(session: *mut MarmotNip46Session) {
    memory::free_guard(|| unsafe { memory::free_boxed(session) });
}

#[cfg(test)]
mod tests;
