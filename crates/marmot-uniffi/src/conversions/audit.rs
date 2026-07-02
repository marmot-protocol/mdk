//! Audit-log file, settings, upload, and tracker FFI conversions.

use marmot_app::{
    AuditDataMode, AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings, AuditLogTrackerConfig,
    AuditLogTrackerUpdateResult, AuditLogUploadResult, AuditLogUploadSource,
};

/// Forensic audit data mode exposed to host apps.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum AuditDataModeFfi {
    /// Default safety posture: obfuscated/hashed identifiers, no plaintext.
    ObfuscatedSensitiveData,
    /// Explicit opt-in: decrypted content and full identifiers where useful.
    FullData,
}

impl From<AuditDataMode> for AuditDataModeFfi {
    fn from(value: AuditDataMode) -> Self {
        match value {
            AuditDataMode::ObfuscatedSensitiveData => Self::ObfuscatedSensitiveData,
            AuditDataMode::FullData => Self::FullData,
        }
    }
}

impl From<AuditDataModeFfi> for AuditDataMode {
    fn from(value: AuditDataModeFfi) -> Self {
        match value {
            AuditDataModeFfi::ObfuscatedSensitiveData => Self::ObfuscatedSensitiveData,
            AuditDataModeFfi::FullData => Self::FullData,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogFileFfi {
    pub account_ref: String,
    pub path: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub modified_at_ms: Option<u64>,
}

impl From<AuditLogFile> for AuditLogFileFfi {
    fn from(value: AuditLogFile) -> Self {
        Self {
            account_ref: value.account_ref,
            path: value.path,
            file_name: value.file_name,
            size_bytes: value.size_bytes,
            modified_at_ms: value.modified_at_ms,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogUploadResultFfi {
    pub path: String,
    pub status: u16,
    pub bytes_sent: u64,
}

impl From<AuditLogUploadResult> for AuditLogUploadResultFfi {
    fn from(value: AuditLogUploadResult) -> Self {
        Self {
            path: value.path,
            status: value.status,
            bytes_sent: value.bytes_sent,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogDeleteResultFfi {
    /// `true` when a live recorder was rotated and is already recording to a
    /// fresh file; `false` when the file was simply removed (no live recorder,
    /// or audit logging off).
    pub still_recording: bool,
}

impl From<AuditLogDeleteOutcome> for AuditLogDeleteResultFfi {
    fn from(value: AuditLogDeleteOutcome) -> Self {
        Self {
            still_recording: value.still_recording,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogTrackerUpdateResultFfi {
    pub enabled: bool,
    pub uploaded: Vec<AuditLogUploadResultFfi>,
    pub skipped_reason: Option<String>,
}

impl From<AuditLogTrackerUpdateResult> for AuditLogTrackerUpdateResultFfi {
    fn from(value: AuditLogTrackerUpdateResult) -> Self {
        Self {
            enabled: value.enabled,
            uploaded: value.uploaded.into_iter().map(Into::into).collect(),
            skipped_reason: value.skipped_reason,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogSettingsFfi {
    pub enabled: bool,
    pub data_mode: AuditDataModeFfi,
}

impl From<AuditLogSettings> for AuditLogSettingsFfi {
    fn from(value: AuditLogSettings) -> Self {
        Self {
            enabled: value.enabled,
            data_mode: value.data_mode.into(),
        }
    }
}

impl From<AuditLogSettingsFfi> for AuditLogSettings {
    fn from(value: AuditLogSettingsFfi) -> Self {
        Self {
            enabled: value.enabled,
            data_mode: value.data_mode.into(),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogUploadSourceFfi {
    pub device_label: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
}

impl From<AuditLogUploadSourceFfi> for AuditLogUploadSource {
    fn from(value: AuditLogUploadSourceFfi) -> Self {
        Self {
            device_label: value.device_label,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

impl From<AuditLogUploadSource> for AuditLogUploadSourceFfi {
    fn from(value: AuditLogUploadSource) -> Self {
        Self {
            device_label: value.device_label,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogTrackerConfigFfi {
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub source: AuditLogUploadSourceFfi,
}

impl From<AuditLogTrackerConfigFfi> for AuditLogTrackerConfig {
    fn from(value: AuditLogTrackerConfigFfi) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            source: value.source.into(),
        }
    }
}

impl From<AuditLogTrackerConfig> for AuditLogTrackerConfigFfi {
    fn from(value: AuditLogTrackerConfig) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            source: value.source.into(),
        }
    }
}
