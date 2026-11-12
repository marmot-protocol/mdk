//! C mirrors of the forensic audit-log conversions.

use marmot_uniffi::conversions::{
    AuditDeliveryBacklogV5Ffi, AuditDeliveryFailureKindV5Ffi, AuditDeliveryFailureV5Ffi,
    AuditDeliveryStatusV5Ffi, AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogRetentionFfi,
    AuditLogSettingsFfi, AuditLogTrackerConfigV4Ffi, AuditLogTrackerUpdateResultFfi,
    AuditLogTrackerUpdateResultV5Ffi, AuditLogUploadResultFfi, AuditLogUploadSourceV4Ffi,
    AuditOtlpConfigV5Ffi, AuditOtlpTrackerResultV5Ffi,
};

use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
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

c_mirror! {
    /// Local audit-log retention policy. Also a borrowed input to
    /// `marmot_set_audit_log_retention`.
    MarmotAuditLogRetention from AuditLogRetentionFfi,
    free marmot_audit_log_retention_free {
        /// Maximum file age in days, 1 to 30.
        copy max_age_days: u32,
        /// Per-account size budget in bytes, at least 16 MiB.
        copy max_bytes_per_account: u64,
    }
}

impl MarmotAuditLogRetention {
    pub(crate) fn to_ffi(&self) -> AuditLogRetentionFfi {
        AuditLogRetentionFfi {
            max_age_days: self.max_age_days,
            max_bytes_per_account: self.max_bytes_per_account,
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

c_mirror! {
    /// Write-only v5 OTLP delivery configuration. Credentials are redacted in
    /// the returned copy; the host owns the borrowed input strings.
    MarmotAuditOtlpConfigV5 from AuditOtlpConfigV5Ffi,
    free marmot_audit_otlp_config_v5_free {
        copy enabled: bool,
        opt_str destination,
        opt_str endpoint,
        opt_str authorization_bearer_token,
        copy allow_loopback_dev: bool,
    }
}

impl MarmotAuditOtlpConfigV5 {
    /// # Safety
    /// Optional fields must be valid NUL-terminated strings when non-NULL.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditOtlpConfigV5Ffi, MarmotStatus> {
        Ok(AuditOtlpConfigV5Ffi {
            enabled: c_bool(self.enabled as u8),
            destination: unsafe { optional_str(self.destination) }?,
            endpoint: unsafe { optional_str(self.endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            allow_loopback_dev: c_bool(self.allow_loopback_dev as u8),
        })
    }
}

c_mirror! {
    /// Result of one v5 OTLP tracker pass.
    MarmotAuditOtlpTrackerResultV5 from AuditOtlpTrackerResultV5Ffi {
        copy accepted_batches: u64,
        copy pending_accounts: u64,
        copy blocked_accounts: u64,
        copy idle_accounts: u64,
        opt_str skipped_reason,
    }
}

c_mirror! {
    /// Additive tracker result with independent v4 and v5 outcomes.
    MarmotAuditLogTrackerUpdateResultV5 from AuditLogTrackerUpdateResultV5Ffi,
    free marmot_audit_log_tracker_update_result_v5_free {
        copy enabled: bool,
        vec v4_uploaded/v4_uploaded_len: MarmotAuditLogUploadResult,
        opt_str v4_skipped_reason,
        opt_rec v5: MarmotAuditOtlpTrackerResultV5,
    }
}

c_enum! {
    /// Why the most recent v5 delivery attempt for an account failed.
    MarmotAuditDeliveryFailureKindV5 from AuditDeliveryFailureKindV5Ffi {
        StateOverLimit,
        TooManyOpenFiles,
        LocalIo,
        LocalBlocked,
        ReceiverBlocked,
        ReceiverRejected,
        ReceiverRetryable,
        NoResponse,
        Internal,
    }
}

c_mirror! {
    /// The most recent v5 delivery failure; `http_status` is set when the
    /// receiver answered.
    MarmotAuditDeliveryFailureV5 from AuditDeliveryFailureV5Ffi {
        copy kind: MarmotAuditDeliveryFailureKindV5,
        opt_copy has_http_status/http_status: u16,
        copy at_ms: u64,
    }
}

c_mirror! {
    /// Undelivered local v5 audit data, as measured at `observed_at_ms`.
    MarmotAuditDeliveryBacklogV5 from AuditDeliveryBacklogV5Ffi {
        copy undelivered_bytes: u64,
        copy undelivered_segments: u64,
        copy gaps: u64,
        opt_copy has_oldest_undelivered_at_ms/oldest_undelivered_at_ms: u64,
        copy observed_at_ms: u64,
    }
}

c_mirror! {
    /// Per-account v5 OTLP audit delivery status.
    MarmotAuditDeliveryStatusV5 from AuditDeliveryStatusV5Ffi,
    free marmot_audit_delivery_status_v5_free,
    list(MarmotAuditDeliveryStatusV5List, marmot_audit_delivery_status_v5_list_free) {
        str account_ref,
        copy destination_configured: bool,
        opt_copy has_last_success_at_ms/last_success_at_ms: u64,
        opt_rec last_failure: MarmotAuditDeliveryFailureV5,
        copy consecutive_failures: u64,
        copy rejected_batches: u64,
        copy paused: bool,
        opt_rec backlog: MarmotAuditDeliveryBacklogV5,
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

    #[test]
    fn delivery_status_carries_failure_kind_http_status_and_backlog_then_deep_frees() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();
        let status = |kind, http_status| AuditDeliveryStatusV5Ffi {
            account_ref: "alice".into(),
            destination_configured: true,
            last_success_at_ms: None,
            last_failure: Some(AuditDeliveryFailureV5Ffi {
                kind,
                http_status,
                at_ms: 7,
            }),
            consecutive_failures: 3,
            rejected_batches: 0,
            paused: http_status.is_some(),
            backlog: Some(AuditDeliveryBacklogV5Ffi {
                undelivered_bytes: 1024,
                undelivered_segments: 2,
                gaps: 1,
                oldest_undelivered_at_ms: Some(5),
                observed_at_ms: 6,
            }),
        };
        let mut list = MarmotAuditDeliveryStatusV5List::from(vec![
            status(AuditDeliveryFailureKindV5Ffi::ReceiverBlocked, Some(401)),
            status(AuditDeliveryFailureKindV5Ffi::StateOverLimit, None),
        ]);
        let rows = unsafe { std::slice::from_raw_parts(list.items, list.len) };
        let blocked = unsafe { &*rows[0].last_failure };
        assert!(matches!(
            blocked.kind,
            MarmotAuditDeliveryFailureKindV5::ReceiverBlocked
        ));
        assert!(blocked.has_http_status);
        assert_eq!(blocked.http_status, 401);
        assert!(rows[0].paused);
        let local = unsafe { &*rows[1].last_failure };
        assert!(matches!(
            local.kind,
            MarmotAuditDeliveryFailureKindV5::StateOverLimit
        ));
        assert!(!local.has_http_status);
        assert!(!rows[1].has_last_success_at_ms);
        let backlog = unsafe { &*rows[1].backlog };
        assert_eq!(backlog.undelivered_bytes, 1024);
        assert_eq!(backlog.undelivered_segments, 2);
        assert_eq!(backlog.gaps, 1);
        assert!(backlog.has_oldest_undelivered_at_ms);
        assert_eq!(backlog.oldest_undelivered_at_ms, 5);
        unsafe { list.free_in_place() };
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }
}
