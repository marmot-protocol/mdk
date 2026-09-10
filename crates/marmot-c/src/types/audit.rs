//! C mirrors of the forensic audit-log conversions.

use marmot_uniffi::conversions::{
    AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogSettingsFfi, AuditLogTrackerConfigV4Ffi,
    AuditLogTrackerUpdateResultFfi, AuditLogUploadResultFfi, AuditLogUploadSourceV4Ffi,
};

use crate::MarmotStatus;
use crate::macros::c_mirror;
use crate::memory::{c_bool, optional_str};

c_mirror! {
    /// Audit-log recorder settings. Also a borrowed input to
    /// `marmot_set_audit_log_settings`.
    MarmotAuditLogSettings from AuditLogSettingsFfi,
    free marmot_audit_log_settings_free {
        /// Boolean as `uint8_t`: nonzero is enabled.
        copy enabled: u8,
    }
}

impl MarmotAuditLogSettings {
    pub(crate) fn to_ffi(&self) -> AuditLogSettingsFfi {
        AuditLogSettingsFfi {
            enabled: c_bool(self.enabled),
        }
    }
}

/// Legacy ABI input. `device_label` is ignored and always returned NULL.
/// Use the v4 config entry point to supply a system hardware model.
#[repr(C)]
pub struct MarmotAuditLogUploadSource {
    pub device_label: *mut std::ffi::c_char,
    pub platform: *mut std::ffi::c_char,
    pub app_version: *mut std::ffi::c_char,
}

impl From<AuditLogUploadSourceV4Ffi> for MarmotAuditLogUploadSource {
    fn from(value: AuditLogUploadSourceV4Ffi) -> Self {
        Self {
            device_label: std::ptr::null_mut(),
            platform: crate::memory::owned_opt_c_string(value.platform),
            app_version: crate::memory::owned_opt_c_string(value.app_version),
        }
    }
}

impl crate::memory::CFree for MarmotAuditLogUploadSource {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            crate::memory::free_c_string(self.device_label);
            crate::memory::free_c_string(self.platform);
            crate::memory::free_c_string(self.app_version);
        }
    }
}

impl MarmotAuditLogUploadSource {
    /// # Safety
    /// Platform and app_version must be NULL or valid NUL-terminated strings.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogUploadSourceV4Ffi, MarmotStatus> {
        Ok(AuditLogUploadSourceV4Ffi {
            hardware_model: None,
            platform: unsafe { optional_str(self.platform) }?,
            app_version: unsafe { optional_str(self.app_version) }?,
        })
    }
}

c_mirror! {
    /// V4 provenance. Hardware model must be system-sourced, never a device name.
    MarmotAuditLogUploadSourceV4 from AuditLogUploadSourceV4Ffi {
        opt_str hardware_model,
        opt_str platform,
        opt_str app_version,
    }
}

impl MarmotAuditLogUploadSourceV4 {
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogUploadSourceV4Ffi, MarmotStatus> {
        Ok(AuditLogUploadSourceV4Ffi {
            hardware_model: unsafe { optional_str(self.hardware_model) }?,
            platform: unsafe { optional_str(self.platform) }?,
            app_version: unsafe { optional_str(self.app_version) }?,
        })
    }
}

c_mirror! {
    /// V4 tracker input/output. Credentials are redacted from returned values.
    MarmotAuditLogTrackerConfigV4 from AuditLogTrackerConfigV4Ffi,
    free marmot_audit_log_tracker_config_v4_free {
        opt_str endpoint,
        opt_str authorization_bearer_token,
        rec source: MarmotAuditLogUploadSourceV4,
    }
}

impl MarmotAuditLogTrackerConfigV4 {
    /// # Safety
    /// Every non-NULL string must be valid.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogTrackerConfigV4Ffi, MarmotStatus> {
        Ok(AuditLogTrackerConfigV4Ffi {
            endpoint: unsafe { optional_str(self.endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            source: unsafe { self.source.to_ffi() }?,
        })
    }
}

c_mirror! {
    /// Audit-log tracker endpoint config. Also a borrowed input to
    /// `marmot_set_audit_log_tracker_config`.
    MarmotAuditLogTrackerConfig from AuditLogTrackerConfigV4Ffi,
    free marmot_audit_log_tracker_config_free {
        opt_str endpoint,
        opt_str authorization_bearer_token,
        rec source: MarmotAuditLogUploadSource,
    }
}

impl MarmotAuditLogTrackerConfig {
    /// # Safety
    /// Every non-NULL string must be valid.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogTrackerConfigV4Ffi, MarmotStatus> {
        Ok(AuditLogTrackerConfigV4Ffi {
            endpoint: unsafe { optional_str(self.endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            source: unsafe { self.source.to_ffi() }?,
        })
    }
}

c_mirror! {
    /// One on-disk audit-log file.
    MarmotAuditLogFile from AuditLogFileFfi,
    free marmot_audit_log_file_free,
    list(MarmotAuditLogFileList, marmot_audit_log_file_list_free) {
        str account_ref,
        str path,
        str file_name,
        copy size_bytes: u64,
        opt_copy has_modified_at_ms/modified_at_ms: u64,
    }
}

c_mirror! {
    /// Result of uploading one audit-log file.
    MarmotAuditLogUploadResult from AuditLogUploadResultFfi,
    free marmot_audit_log_upload_result_free {
        str path,
        copy status: u16,
        copy bytes_sent: u64,
    }
}

c_mirror! {
    /// Result of deleting one audit-log file.
    MarmotAuditLogDeleteResult from AuditLogDeleteResultFfi,
    free marmot_audit_log_delete_result_free {
        /// `true` when a live recorder was rotated and is already
        /// recording to a fresh file; `false` when the file was simply
        /// removed.
        copy still_recording: bool,
    }
}

c_mirror! {
    /// Result of a tracker-driven upload pass.
    MarmotAuditLogTrackerUpdateResult from AuditLogTrackerUpdateResultFfi,
    free marmot_audit_log_tracker_update_result_free {
        copy enabled: bool,
        vec uploaded/uploaded_len: MarmotAuditLogUploadResult,
        opt_str skipped_reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::CFree;
    use std::ffi::CString;

    #[test]
    fn legacy_device_label_is_never_reinterpreted_as_hardware_model() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let name = CString::new("PRIVATE_DEVICE_NAME").unwrap();
        let platform = CString::new("linux").unwrap();
        let version = CString::new("test").unwrap();
        let source = MarmotAuditLogUploadSource {
            device_label: name.as_ptr().cast_mut(),
            platform: platform.as_ptr().cast_mut(),
            app_version: version.as_ptr().cast_mut(),
        };
        let ffi = unsafe { source.to_ffi() }.unwrap();
        assert!(ffi.hardware_model.is_none());
        assert_eq!(ffi.platform.as_deref(), Some("linux"));
        assert_eq!(ffi.app_version.as_deref(), Some("test"));
        let mut returned = MarmotAuditLogUploadSource::from(ffi);
        assert!(returned.device_label.is_null());
        unsafe { returned.free_in_place() };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn v4_hardware_model_survives_c_conversion_and_deep_free() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let config = AuditLogTrackerConfigV4Ffi {
            endpoint: Some("https://example.com/audit".into()),
            authorization_bearer_token: None,
            source: AuditLogUploadSourceV4Ffi {
                hardware_model: Some("iPhone17,3".into()),
                platform: Some("ios".into()),
                app_version: Some("test".into()),
            },
        };
        let mut c = MarmotAuditLogTrackerConfigV4::from(config);
        let returned = unsafe { c.to_ffi() }.unwrap();
        assert_eq!(
            returned.source.hardware_model.as_deref(),
            Some("iPhone17,3")
        );
        assert_eq!(returned.source.platform.as_deref(), Some("ios"));
        assert_eq!(returned.source.app_version.as_deref(), Some("test"));
        unsafe { c.free_in_place() };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
