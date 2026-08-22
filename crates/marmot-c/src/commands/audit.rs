//! Forensic audit-log settings, listing, upload, and tracker commands.

use std::ffi::c_char;

use crate::memory::required_str;
use crate::status::MarmotStatus;
use crate::types::audit::{
    MarmotAuditLogDeleteResult, MarmotAuditLogFileList, MarmotAuditLogSettings,
    MarmotAuditLogTrackerConfig, MarmotAuditLogTrackerUpdateResult, MarmotAuditLogUploadResult,
};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::deliver;

/// Local forensic audit-log recording settings. Recording is opt-in and only
/// applies to account sessions opened after the setting is enabled.
///
/// # Safety
/// `client` must be a live handle; `out_settings` must be a valid pointer.
/// Free the result with `marmot_audit_log_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_settings(
    client: *const MarmotClient,
    out_settings: *mut *mut MarmotAuditLogSettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver(client.marmot.audit_log_settings(), out_settings) }
    })
}

/// Persist local forensic audit-log recording settings and return the stored
/// value.
///
/// Blocking: toggling the switch is applied to any already-running account
/// sessions in place — enabling starts a live recorder, disabling stops it
/// and closes the file, no session reopen required.
///
/// # Safety
/// `client` must be a live handle; `settings` a valid borrowed struct (never
/// freed by the library); `out_settings` a valid pointer. Free the result
/// with `marmot_audit_log_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_audit_log_settings(
    client: *const MarmotClient,
    settings: *const MarmotAuditLogSettings,
    out_settings: *mut *mut MarmotAuditLogSettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        if settings.is_null() {
            crate::status::set_last_error("settings argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let settings = try_arg!(unsafe { (*settings).to_ffi() });
        unsafe {
            deliver(
                client.block_on(client.marmot.set_audit_log_settings(settings)),
                out_settings,
            )
        }
    })
}

/// Supply non-persisted audit tracker upload metadata: optional Goggles
/// upload URL override, bearer token from the host app, and optional human
/// source labels.
///
/// The returned config confirms what was stored but never echoes the bearer
/// token back across FFI: secrets flow in, not out.
///
/// # Safety
/// `client` must be a live handle; `config` a valid borrowed struct (never
/// freed by the library) whose non-NULL string fields are valid
/// NUL-terminated strings; `out_config` a valid pointer. Free the result
/// with `marmot_audit_log_tracker_config_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_audit_log_tracker_config(
    client: *const MarmotClient,
    config: *const MarmotAuditLogTrackerConfig,
    out_config: *mut *mut MarmotAuditLogTrackerConfig,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        if config.is_null() {
            crate::status::set_last_error("config argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let config = try_arg!(unsafe { (*config).to_ffi() });
        unsafe {
            deliver(
                client.marmot.set_audit_log_tracker_config(config),
                out_config,
            )
        }
    })
}

/// Local JSONL audit logs available for explicit forensic upload.
///
/// # Safety
/// `client` must be a live handle; `out_list` must be a valid pointer.
/// Free the result with `marmot_audit_log_file_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_files(
    client: *const MarmotClient,
    out_list: *mut *mut MarmotAuditLogFileList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver(client.marmot.audit_log_files(), out_list) }
    })
}

/// POST one selected JSONL audit log to a forensic analyzer endpoint.
///
/// # Safety
/// `client` must be a live handle; `path` and `endpoint` valid strings;
/// `out_result` a valid pointer. Free the result with
/// `marmot_audit_log_upload_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_post_audit_log_file(
    client: *const MarmotClient,
    path: *const c_char,
    endpoint: *const c_char,
    out_result: *mut *mut MarmotAuditLogUploadResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let path = try_arg!(unsafe { required_str(path) });
        let endpoint = try_arg!(unsafe { required_str(endpoint) });
        unsafe {
            deliver(
                client.block_on(client.marmot.post_audit_log_file(path, endpoint)),
                out_result,
            )
        }
    })
}

/// Delete one local JSONL audit log file (e.g. behind a "clear audit log"
/// button).
///
/// When forensic audit logging is on and a session for the file's account is
/// live, the recorder rotates to a fresh file and keeps recording, so the
/// result's `still_recording` is `true`. When audit logging is off, or no
/// session is recording this file, it is simply removed and
/// `still_recording` is `false`. Pass a `path` from
/// `marmot_audit_log_files`.
///
/// # Safety
/// `client` must be a live handle; `path` a valid string; `out_result` a
/// valid pointer. Free the result with
/// `marmot_audit_log_delete_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_delete_audit_log_file(
    client: *const MarmotClient,
    path: *const c_char,
    out_result: *mut *mut MarmotAuditLogDeleteResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let path = try_arg!(unsafe { required_str(path) });
        unsafe {
            deliver(
                client.block_on(client.marmot.delete_audit_log_file(path)),
                out_result,
            )
        }
    })
}

/// POST all local audit logs to the configured tracker when audit logging is
/// enabled. This is safe for host apps to call unconditionally; disabled or
/// unconfigured states return a structured skip result.
///
/// # Safety
/// `client` must be a live handle; `out_result` a valid pointer. Free the
/// result with `marmot_audit_log_tracker_update_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_post_audit_log_tracker_update(
    client: *const MarmotClient,
    out_result: *mut *mut MarmotAuditLogTrackerUpdateResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe {
            deliver(
                client.block_on(client.marmot.post_audit_log_tracker_update()),
                out_result,
            )
        }
    })
}
