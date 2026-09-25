//! Audit-log file, settings, upload, and tracker FFI conversions.

use marmot_app::{
    AuditLogDeleteOutcome, AuditLogFile, AuditLogSettings, AuditLogTrackerConfig,
    AuditLogTrackerUpdateResult, AuditLogUploadResult, AuditLogUploadSource,
    AuditOtlpTrackerResult,
};

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
        let skipped_reason = match &value.v5 {
            Some(v5) if v5.blocked_accounts > 0 => {
                Some("v5 audit delivery blocked; inspect v5 tracker result".to_owned())
            }
            Some(v5) if v5.pending_accounts > 0 => {
                Some("v5 audit delivery pending; inspect v5 tracker result".to_owned())
            }
            Some(v5) if v5.accepted_batches > 0 => None,
            _ => value.skipped_reason,
        };
        Self {
            enabled: value.enabled,
            uploaded: value.uploaded.into_iter().map(Into::into).collect(),
            skipped_reason,
        }
    }
}

/// Additive result for v5-aware hosts; the historical result and C layout stay
/// unchanged while the new result reports the OTLP path independently.
#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogTrackerUpdateResultV5Ffi {
    pub enabled: bool,
    pub v4_uploaded: Vec<AuditLogUploadResultFfi>,
    pub v4_skipped_reason: Option<String>,
    pub v5: Option<AuditOtlpTrackerResultV5Ffi>,
}

impl From<AuditLogTrackerUpdateResult> for AuditLogTrackerUpdateResultV5Ffi {
    fn from(value: AuditLogTrackerUpdateResult) -> Self {
        Self {
            enabled: value.enabled,
            v4_uploaded: value.uploaded.into_iter().map(Into::into).collect(),
            v4_skipped_reason: value.skipped_reason,
            v5: value.v5.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditOtlpTrackerResultV5Ffi {
    pub accepted_batches: u64,
    pub pending_accounts: u64,
    pub blocked_accounts: u64,
    pub idle_accounts: u64,
    pub skipped_reason: Option<String>,
}

impl From<AuditOtlpTrackerResult> for AuditOtlpTrackerResultV5Ffi {
    fn from(value: AuditOtlpTrackerResult) -> Self {
        Self {
            accepted_batches: value.accepted_batches,
            pending_accounts: value.pending_accounts,
            blocked_accounts: value.blocked_accounts,
            idle_accounts: value.idle_accounts,
            skipped_reason: value.skipped_reason,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct AuditOtlpConfigV5Ffi {
    pub enabled: bool,
    pub destination: Option<String>,
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub allow_loopback_dev: bool,
}

impl std::fmt::Debug for AuditOtlpConfigV5Ffi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditOtlpConfigV5Ffi")
            .field("enabled", &self.enabled)
            .field("destination", &self.destination)
            .field("endpoint", &self.endpoint)
            .field(
                "authorization_bearer_token",
                &self
                    .authorization_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("allow_loopback_dev", &self.allow_loopback_dev)
            .finish()
    }
}

impl AuditOtlpConfigV5Ffi {
    pub(crate) fn redacted(mut self) -> Self {
        self.authorization_bearer_token = None;
        self
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogSettingsFfi {
    pub enabled: bool,
}

impl From<AuditLogSettings> for AuditLogSettingsFfi {
    fn from(value: AuditLogSettings) -> Self {
        Self {
            enabled: value.enabled,
        }
    }
}

impl From<AuditLogSettingsFfi> for AuditLogSettings {
    fn from(value: AuditLogSettingsFfi) -> Self {
        Self {
            enabled: value.enabled,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AuditLogUploadSourceV4Ffi {
    /// System model identifier; never a user-assigned device name, hostname, or serial number.
    pub hardware_model: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
}

impl From<AuditLogUploadSourceV4Ffi> for AuditLogUploadSource {
    fn from(value: AuditLogUploadSourceV4Ffi) -> Self {
        Self {
            hardware_model: value.hardware_model,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

impl From<AuditLogUploadSource> for AuditLogUploadSourceV4Ffi {
    fn from(value: AuditLogUploadSource) -> Self {
        Self {
            hardware_model: value.hardware_model,
            platform: value.platform,
            app_version: value.app_version,
        }
    }
}

/// V4 tracker config. The versioned type name changes the UniFFI method checksum
/// so old generated bindings cannot reinterpret device labels as hardware models.
/// Write-only across FFI:
/// `authorization_bearer_token` is accepted here but never returned back to
/// the host — [`redacted`](Self::redacted) strips it — and the hand-written
/// `Debug` impl below never prints it.
#[derive(Clone, uniffi::Record)]
pub struct AuditLogTrackerConfigV4Ffi {
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub source: AuditLogUploadSourceV4Ffi,
}

impl std::fmt::Debug for AuditLogTrackerConfigV4Ffi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogTrackerConfigV4Ffi")
            .field("endpoint", &self.endpoint)
            .field(
                "authorization_bearer_token",
                &self
                    .authorization_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("source", &self.source)
            .finish()
    }
}

impl From<AuditLogTrackerConfigV4Ffi> for AuditLogTrackerConfig {
    fn from(value: AuditLogTrackerConfigV4Ffi) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            source: value.source.into(),
        }
    }
}

impl AuditLogTrackerConfigV4Ffi {
    /// The stored config with the bearer token stripped, for returning across
    /// FFI: secrets flow in through setters but are never handed back out.
    pub(crate) fn redacted(value: AuditLogTrackerConfig) -> Self {
        Self {
            endpoint: value.endpoint,
            authorization_bearer_token: None,
            source: value.source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "super-secret-bearer-token";

    fn config_with_token() -> AuditLogTrackerConfigV4Ffi {
        AuditLogTrackerConfigV4Ffi {
            endpoint: Some("https://goggles.example/upload".to_owned()),
            authorization_bearer_token: Some(TOKEN.to_owned()),
            source: AuditLogUploadSourceV4Ffi {
                hardware_model: Some("TestModel".to_owned()),
                platform: None,
                app_version: None,
            },
        }
    }

    #[test]
    fn audit_tracker_config_debug_redacts_bearer_token() {
        let rendered = format!("{:?}", config_with_token());
        assert!(!rendered.contains(TOKEN), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // Non-secret fields stay visible for diagnostics.
        assert!(rendered.contains("goggles.example"), "{rendered}");
    }

    #[test]
    fn audit_tracker_config_redacted_strips_bearer_token() {
        let stored: AuditLogTrackerConfig = config_with_token().into();
        let returned = AuditLogTrackerConfigV4Ffi::redacted(stored);
        assert_eq!(returned.authorization_bearer_token, None);
        assert_eq!(
            returned.endpoint.as_deref(),
            Some("https://goggles.example/upload")
        );
    }

    #[test]
    fn v5_otlp_config_debug_and_result_never_echo_token() {
        let config = AuditOtlpConfigV5Ffi {
            enabled: true,
            destination: Some("audit-gateway".to_owned()),
            endpoint: Some("https://collector.example/v1/logs".to_owned()),
            authorization_bearer_token: Some(TOKEN.to_owned()),
            allow_loopback_dev: false,
        };
        assert!(!format!("{config:?}").contains(TOKEN));
        let returned = config.redacted();
        assert!(returned.authorization_bearer_token.is_none());
        assert!(returned.enabled);
    }

    #[test]
    fn legacy_tracker_result_does_not_report_empty_success_when_v5_is_pending() {
        let result = AuditLogTrackerUpdateResult {
            enabled: true,
            uploaded: vec![],
            skipped_reason: Some("audit log tracker endpoint missing".to_owned()),
            v5: Some(AuditOtlpTrackerResult {
                pending_accounts: 1,
                ..Default::default()
            }),
        };
        let legacy: AuditLogTrackerUpdateResultFfi = result.clone().into();
        assert!(
            legacy
                .skipped_reason
                .unwrap()
                .contains("v5 audit delivery pending")
        );
        let versioned: AuditLogTrackerUpdateResultV5Ffi = result.into();
        assert_eq!(versioned.v5.unwrap().pending_accounts, 1);
    }
}
