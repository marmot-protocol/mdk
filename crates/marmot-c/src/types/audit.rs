//! C mirrors of the forensic audit-log conversions.

use marmot_uniffi::conversions::{
    AuditDataModeFfi, AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogSettingsFfi,
    AuditLogTrackerConfigFfi, AuditLogTrackerUpdateResultFfi, AuditLogUploadResultFfi,
    AuditLogUploadSourceFfi,
};

use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{c_bool, optional_str};

c_enum! {
    /// Audit-log content posture.
    MarmotAuditDataMode from AuditDataModeFfi {
        /// Default safety posture: obfuscated/hashed identifiers, no
        /// plaintext.
        ObfuscatedSensitiveData,
        /// Explicit opt-in: decrypted content and full identifiers.
        FullData,
    }
}

impl From<MarmotAuditDataMode> for AuditDataModeFfi {
    fn from(value: MarmotAuditDataMode) -> Self {
        match value {
            MarmotAuditDataMode::ObfuscatedSensitiveData => Self::ObfuscatedSensitiveData,
            MarmotAuditDataMode::FullData => Self::FullData,
        }
    }
}

c_mirror! {
    /// Audit-log recorder settings. Also a borrowed input to
    /// `marmot_set_audit_log_settings`.
    MarmotAuditLogSettings from AuditLogSettingsFfi,
    free marmot_audit_log_settings_free {
        /// Boolean as `uint8_t`: nonzero is enabled.
        copy enabled: u8,
        /// `MarmotAuditDataMode` discriminant.
        enum_val data_mode: MarmotAuditDataMode,
    }
}

impl MarmotAuditLogSettings {
    pub(crate) fn to_ffi(&self) -> Result<AuditLogSettingsFfi, MarmotStatus> {
        Ok(AuditLogSettingsFfi {
            enabled: c_bool(self.enabled),
            data_mode: MarmotAuditDataMode::from_c(self.data_mode)?.into(),
        })
    }
}

c_mirror! {
    /// Optional device/app provenance attached to tracker uploads.
    /// Borrowed input inside `MarmotAuditLogTrackerConfig`.
    MarmotAuditLogUploadSource from AuditLogUploadSourceFfi {
        opt_str device_label,
        opt_str platform,
        opt_str app_version,
    }
}

impl MarmotAuditLogUploadSource {
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

c_mirror! {
    /// Audit-log tracker endpoint config. Also a borrowed input to
    /// `marmot_set_audit_log_tracker_config`.
    MarmotAuditLogTrackerConfig from AuditLogTrackerConfigFfi,
    free marmot_audit_log_tracker_config_free {
        opt_str endpoint,
        opt_str authorization_bearer_token,
        rec source: MarmotAuditLogUploadSource,
    }
}

impl MarmotAuditLogTrackerConfig {
    /// # Safety
    /// Every non-NULL string must be valid.
    pub(crate) unsafe fn to_ffi(&self) -> Result<AuditLogTrackerConfigFfi, MarmotStatus> {
        Ok(AuditLogTrackerConfigFfi {
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
