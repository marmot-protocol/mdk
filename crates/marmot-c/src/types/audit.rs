//! C mirrors of the audit conversions (`marmot-uniffi/src/conversions/audit.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    AuditDataModeFfi, AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogSettingsFfi,
    AuditLogTrackerConfigFfi, AuditLogTrackerUpdateResultFfi, AuditLogUploadResultFfi,
    AuditLogUploadSourceFfi,
};

use crate::MarmotStatus;
use crate::memory::{
    CFree, free_boxed, free_c_string, free_vec, optional_str, owned_c_string, owned_opt_c_string,
    owned_vec,
};

/// Forensic audit data mode exposed to host apps.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotAuditDataMode {
    /// Default safety posture: obfuscated/hashed identifiers, no plaintext.
    ObfuscatedSensitiveData,
    /// Explicit opt-in: decrypted content and full identifiers where useful.
    FullData,
}

impl From<AuditDataModeFfi> for MarmotAuditDataMode {
    fn from(value: AuditDataModeFfi) -> Self {
        match value {
            AuditDataModeFfi::ObfuscatedSensitiveData => Self::ObfuscatedSensitiveData,
            AuditDataModeFfi::FullData => Self::FullData,
        }
    }
}

impl MarmotAuditDataMode {
    /// Read a caller-supplied input enum into the Ffi enum.
    pub(crate) fn to_ffi(self) -> AuditDataModeFfi {
        match self {
            Self::ObfuscatedSensitiveData => AuditDataModeFfi::ObfuscatedSensitiveData,
            Self::FullData => AuditDataModeFfi::FullData,
        }
    }
}

impl CFree for MarmotAuditDataMode {
    unsafe fn free_in_place(&mut self) {}
}

/// One local JSONL forensic audit log file available for explicit upload
/// or deletion.
#[repr(C)]
pub struct MarmotAuditLogFile {
    pub account_ref: *mut c_char,
    pub path: *mut c_char,
    pub file_name: *mut c_char,
    pub size_bytes: u64,
    /// `modified_at_ms` is only meaningful when `has_modified_at_ms` is true.
    pub has_modified_at_ms: bool,
    pub modified_at_ms: u64,
}

impl From<AuditLogFileFfi> for MarmotAuditLogFile {
    fn from(value: AuditLogFileFfi) -> Self {
        Self {
            account_ref: owned_c_string(value.account_ref),
            path: owned_c_string(value.path),
            file_name: owned_c_string(value.file_name),
            size_bytes: value.size_bytes,
            has_modified_at_ms: value.modified_at_ms.is_some(),
            modified_at_ms: value.modified_at_ms.unwrap_or_default(),
        }
    }
}

impl CFree for MarmotAuditLogFile {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.account_ref);
            free_c_string(self.path);
            free_c_string(self.file_name);
        }
    }
}

/// Free a single audit log file root. NULL is a no-op.
///
/// # Safety
/// `file` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_file_free(file: *mut MarmotAuditLogFile) {
    unsafe { free_boxed(file) };
}

/// Owned list of audit log files (`marmot_audit_log_files`).
#[repr(C)]
pub struct MarmotAuditLogFileList {
    pub items: *mut MarmotAuditLogFile,
    pub len: usize,
}

impl From<Vec<AuditLogFileFfi>> for MarmotAuditLogFileList {
    fn from(value: Vec<AuditLogFileFfi>) -> Self {
        let (items, len) = owned_vec(value.into_iter().map(Into::into).collect());
        Self { items, len }
    }
}

impl CFree for MarmotAuditLogFileList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.items, self.len) };
    }
}

/// Free a list returned by `marmot_audit_log_files`. NULL is a no-op.
///
/// # Safety
/// `list` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_file_list_free(list: *mut MarmotAuditLogFileList) {
    unsafe { free_boxed(list) };
}

/// Result of POSTing one JSONL audit log to a forensic analyzer endpoint.
#[repr(C)]
pub struct MarmotAuditLogUploadResult {
    pub path: *mut c_char,
    /// HTTP status code returned by the analyzer endpoint.
    pub status: u16,
    pub bytes_sent: u64,
}

impl From<AuditLogUploadResultFfi> for MarmotAuditLogUploadResult {
    fn from(value: AuditLogUploadResultFfi) -> Self {
        Self {
            path: owned_c_string(value.path),
            status: value.status,
            bytes_sent: value.bytes_sent,
        }
    }
}

impl CFree for MarmotAuditLogUploadResult {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_c_string(self.path) };
    }
}

/// Free an upload result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_upload_result_free(
    result: *mut MarmotAuditLogUploadResult,
) {
    unsafe { free_boxed(result) };
}

/// Result of deleting one local JSONL audit log file.
#[repr(C)]
pub struct MarmotAuditLogDeleteResult {
    /// `true` when a live recorder was rotated and is already recording to a
    /// fresh file; `false` when the file was simply removed (no live recorder,
    /// or audit logging off).
    pub still_recording: bool,
}

impl From<AuditLogDeleteResultFfi> for MarmotAuditLogDeleteResult {
    fn from(value: AuditLogDeleteResultFfi) -> Self {
        Self {
            still_recording: value.still_recording,
        }
    }
}

impl CFree for MarmotAuditLogDeleteResult {
    unsafe fn free_in_place(&mut self) {}
}

/// Free a delete result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_delete_result_free(
    result: *mut MarmotAuditLogDeleteResult,
) {
    unsafe { free_boxed(result) };
}

/// Result of POSTing all local audit logs to the configured tracker.
/// Disabled or unconfigured states are structured skips, not errors.
#[repr(C)]
pub struct MarmotAuditLogTrackerUpdateResult {
    /// Whether forensic audit logging was enabled when the update ran.
    pub enabled: bool,
    pub uploaded: *mut MarmotAuditLogUploadResult,
    pub uploaded_len: usize,
    /// Why the update was skipped, when it was. Nullable.
    pub skipped_reason: *mut c_char,
}

impl From<AuditLogTrackerUpdateResultFfi> for MarmotAuditLogTrackerUpdateResult {
    fn from(value: AuditLogTrackerUpdateResultFfi) -> Self {
        let (uploaded, uploaded_len) =
            owned_vec(value.uploaded.into_iter().map(Into::into).collect());
        Self {
            enabled: value.enabled,
            uploaded,
            uploaded_len,
            skipped_reason: owned_opt_c_string(value.skipped_reason),
        }
    }
}

impl CFree for MarmotAuditLogTrackerUpdateResult {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.uploaded, self.uploaded_len);
            free_c_string(self.skipped_reason);
        }
    }
}

/// Free a tracker update result root. NULL is a no-op.
///
/// # Safety
/// `result` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_tracker_update_result_free(
    result: *mut MarmotAuditLogTrackerUpdateResult,
) {
    unsafe { free_boxed(result) };
}

/// Local forensic audit-log recording settings. Recording is opt-in. Used
/// both as a return value (owned; free the root) and as a borrowed input to
/// `marmot_set_audit_log_settings` (caller-owned; this library never frees
/// input structs).
#[repr(C)]
pub struct MarmotAuditLogSettings {
    pub enabled: bool,
    pub data_mode: MarmotAuditDataMode,
}

impl From<AuditLogSettingsFfi> for MarmotAuditLogSettings {
    fn from(value: AuditLogSettingsFfi) -> Self {
        Self {
            enabled: value.enabled,
            data_mode: value.data_mode.into(),
        }
    }
}

impl MarmotAuditLogSettings {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory. Infallible today (scalar fields only);
    /// the `Result` shape keeps command call sites uniform.
    pub(crate) fn to_ffi(&self) -> Result<AuditLogSettingsFfi, MarmotStatus> {
        Ok(AuditLogSettingsFfi {
            enabled: self.enabled,
            data_mode: self.data_mode.to_ffi(),
        })
    }
}

impl CFree for MarmotAuditLogSettings {
    unsafe fn free_in_place(&mut self) {}
}

/// Free settings returned by this library. Never call on structs you
/// allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `settings` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_settings_free(settings: *mut MarmotAuditLogSettings) {
    unsafe { free_boxed(settings) };
}

/// Optional human source labels attached to tracker uploads. All fields
/// nullable.
#[repr(C)]
pub struct MarmotAuditLogUploadSource {
    pub device_label: *mut c_char,
    pub platform: *mut c_char,
    pub app_version: *mut c_char,
}

impl From<AuditLogUploadSourceFfi> for MarmotAuditLogUploadSource {
    fn from(value: AuditLogUploadSourceFfi) -> Self {
        Self {
            device_label: owned_opt_c_string(value.device_label),
            platform: owned_opt_c_string(value.platform),
            app_version: owned_opt_c_string(value.app_version),
        }
    }
}

impl MarmotAuditLogUploadSource {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogUploadSourceFfi, MarmotStatus> {
        Ok(AuditLogUploadSourceFfi {
            device_label: unsafe { optional_str(self.device_label) }?,
            platform: unsafe { optional_str(self.platform) }?,
            app_version: unsafe { optional_str(self.app_version) }?,
        })
    }
}

impl CFree for MarmotAuditLogUploadSource {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.device_label);
            free_c_string(self.platform);
            free_c_string(self.app_version);
        }
    }
}

/// Tracker upload config supplied by the host app. Write-only across the
/// boundary: `authorization_bearer_token` is accepted as input but the
/// config returned by `marmot_set_audit_log_tracker_config` never echoes it
/// back — secrets flow in, not out. Used both as a return value (owned; free
/// the root) and as a borrowed input (caller-owned; this library never frees
/// input structs).
#[repr(C)]
pub struct MarmotAuditLogTrackerConfig {
    /// Optional Goggles upload URL override. Nullable.
    pub endpoint: *mut c_char,
    /// Bearer token from the host app. Nullable. Always NULL on returned
    /// configs.
    pub authorization_bearer_token: *mut c_char,
    pub source: MarmotAuditLogUploadSource,
}

impl From<AuditLogTrackerConfigFfi> for MarmotAuditLogTrackerConfig {
    fn from(value: AuditLogTrackerConfigFfi) -> Self {
        Self {
            endpoint: owned_opt_c_string(value.endpoint),
            authorization_bearer_token: owned_opt_c_string(value.authorization_bearer_token),
            source: value.source.into(),
        }
    }
}

impl MarmotAuditLogTrackerConfig {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogTrackerConfigFfi, MarmotStatus> {
        Ok(AuditLogTrackerConfigFfi {
            endpoint: unsafe { optional_str(self.endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            source: unsafe { self.source.to_ffi() }?,
        })
    }
}

impl CFree for MarmotAuditLogTrackerConfig {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.endpoint);
            free_c_string(self.authorization_bearer_token);
            self.source.free_in_place();
        }
    }
}

/// Free a tracker config returned by this library. Never call on structs
/// you allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `config` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_audit_log_tracker_config_free(
    config: *mut MarmotAuditLogTrackerConfig,
) {
    unsafe { free_boxed(config) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    #[test]
    fn audit_log_file_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAuditLogFile = AuditLogFileFfi {
            account_ref: "alpha".into(),
            path: "/logs/alpha/audit-1.jsonl".into(),
            file_name: "audit-1.jsonl".into(),
            size_bytes: 4096,
            modified_at_ms: Some(1_700_000_000_000),
        }
        .into();
        assert_eq!(mirror.size_bytes, 4096);
        assert!(mirror.has_modified_at_ms);
        assert_eq!(mirror.modified_at_ms, 1_700_000_000_000);
        assert!(!mirror.path.is_null());
        let root = boxed(mirror);
        unsafe { marmot_audit_log_file_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn audit_log_file_list_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let list: MarmotAuditLogFileList = vec![AuditLogFileFfi {
            account_ref: "alpha".into(),
            path: "/logs/alpha/audit-1.jsonl".into(),
            file_name: "audit-1.jsonl".into(),
            size_bytes: 1,
            modified_at_ms: None,
        }]
        .into();
        assert_eq!(list.len, 1);
        let first = unsafe { &*list.items };
        assert!(!first.has_modified_at_ms);
        assert_eq!(first.modified_at_ms, 0);
        let root = boxed(list);
        unsafe { marmot_audit_log_file_list_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn upload_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAuditLogUploadResult = AuditLogUploadResultFfi {
            path: "/logs/alpha/audit-1.jsonl".into(),
            status: 201,
            bytes_sent: 999,
        }
        .into();
        assert_eq!(mirror.status, 201);
        assert_eq!(mirror.bytes_sent, 999);
        let root = boxed(mirror);
        unsafe { marmot_audit_log_upload_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn delete_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAuditLogDeleteResult = AuditLogDeleteResultFfi {
            still_recording: true,
        }
        .into();
        assert!(mirror.still_recording);
        let root = boxed(mirror);
        unsafe { marmot_audit_log_delete_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn tracker_update_result_deep_roundtrip() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAuditLogTrackerUpdateResult = AuditLogTrackerUpdateResultFfi {
            enabled: true,
            uploaded: vec![
                AuditLogUploadResultFfi {
                    path: "/logs/a.jsonl".into(),
                    status: 200,
                    bytes_sent: 10,
                },
                AuditLogUploadResultFfi {
                    path: "/logs/b.jsonl".into(),
                    status: 200,
                    bytes_sent: 20,
                },
            ],
            skipped_reason: Some("partially throttled".into()),
        }
        .into();
        assert!(mirror.enabled);
        assert_eq!(mirror.uploaded_len, 2);
        assert!(!mirror.skipped_reason.is_null());
        let root = boxed(mirror);
        unsafe { marmot_audit_log_tracker_update_result_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn settings_roundtrip_both_modes() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let full: MarmotAuditLogSettings = AuditLogSettingsFfi {
            enabled: true,
            data_mode: AuditDataModeFfi::FullData,
        }
        .into();
        assert!(full.enabled);
        assert_eq!(full.data_mode, MarmotAuditDataMode::FullData);
        let ffi = full.to_ffi().expect("scalar fields");
        assert!(matches!(ffi.data_mode, AuditDataModeFfi::FullData));

        let obfuscated: MarmotAuditLogSettings = AuditLogSettingsFfi {
            enabled: false,
            data_mode: AuditDataModeFfi::ObfuscatedSensitiveData,
        }
        .into();
        assert_eq!(
            obfuscated.data_mode,
            MarmotAuditDataMode::ObfuscatedSensitiveData
        );
        let ffi = obfuscated.to_ffi().expect("scalar fields");
        assert!(matches!(
            ffi.data_mode,
            AuditDataModeFfi::ObfuscatedSensitiveData
        ));

        let root = boxed(full);
        unsafe { marmot_audit_log_settings_free(root) };
        let root = boxed(obfuscated);
        unsafe { marmot_audit_log_settings_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn tracker_config_deep_roundtrip_and_borrowed_read() {
        #[cfg(feature = "alloc-audit")]
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let owned: MarmotAuditLogTrackerConfig = AuditLogTrackerConfigFfi {
            endpoint: Some("https://goggles.example/upload".into()),
            authorization_bearer_token: Some("bearer-token".into()),
            source: AuditLogUploadSourceFfi {
                device_label: Some("test-device".into()),
                platform: Some("linux".into()),
                app_version: Some("1.2.3".into()),
            },
        }
        .into();
        let ffi = unsafe { owned.to_ffi() }.expect("valid strings");
        assert_eq!(
            ffi.endpoint.as_deref(),
            Some("https://goggles.example/upload")
        );
        assert_eq!(
            ffi.authorization_bearer_token.as_deref(),
            Some("bearer-token")
        );
        assert_eq!(ffi.source.device_label.as_deref(), Some("test-device"));
        assert_eq!(ffi.source.platform.as_deref(), Some("linux"));
        assert_eq!(ffi.source.app_version.as_deref(), Some("1.2.3"));
        let root = boxed(owned);
        unsafe { marmot_audit_log_tracker_config_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_and_none_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let list: MarmotAuditLogFileList = Vec::<AuditLogFileFfi>::new().into();
        assert!(list.items.is_null());
        assert_eq!(list.len, 0);
        let root = boxed(list);
        unsafe { marmot_audit_log_file_list_free(root) };

        let update: MarmotAuditLogTrackerUpdateResult = AuditLogTrackerUpdateResultFfi {
            enabled: false,
            uploaded: vec![],
            skipped_reason: None,
        }
        .into();
        assert!(update.uploaded.is_null());
        assert_eq!(update.uploaded_len, 0);
        assert!(update.skipped_reason.is_null());
        let root = boxed(update);
        unsafe { marmot_audit_log_tracker_update_result_free(root) };

        let config: MarmotAuditLogTrackerConfig = AuditLogTrackerConfigFfi {
            endpoint: None,
            authorization_bearer_token: None,
            source: AuditLogUploadSourceFfi {
                device_label: None,
                platform: None,
                app_version: None,
            },
        }
        .into();
        assert!(config.endpoint.is_null());
        assert!(config.authorization_bearer_token.is_null());
        assert!(config.source.device_label.is_null());
        let ffi = unsafe { config.to_ffi() }.expect("all NULL is valid");
        assert_eq!(ffi.endpoint, None);
        assert_eq!(ffi.source.platform, None);
        let root = boxed(config);
        unsafe { marmot_audit_log_tracker_config_free(root) };
    }
}
