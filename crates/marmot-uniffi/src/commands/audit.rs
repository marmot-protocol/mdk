//! Forensic audit-log settings, listing, upload, and tracker commands.

use crate::Marmot;
use crate::conversions::{
    AuditLogDeleteResultFfi, AuditLogFileFfi, AuditLogSettingsFfi, AuditLogTrackerConfigV4Ffi,
    AuditLogTrackerUpdateResultFfi, AuditLogTrackerUpdateResultV5Ffi, AuditLogUploadResultFfi,
    AuditOtlpConfigV5Ffi,
};
use crate::errors::MarmotKitError;
use marmot_app::audit_otlp_sender::AuditOtlpSender;

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Local forensic audit-log recording settings. Recording is opt-in and only
    /// applies to account sessions opened after the setting is enabled.
    pub fn audit_log_settings(&self) -> Result<AuditLogSettingsFfi, MarmotKitError> {
        Ok(self.runtime.audit_log_settings()?.into())
    }

    /// Persist local forensic audit-log recording settings and return the stored
    /// value.
    ///
    /// Async because toggling the switch is applied to any already-running
    /// account sessions in place: enabling starts a live recorder, disabling
    /// stops it and closes the file — no session reopen required.
    pub async fn set_audit_log_settings(
        &self,
        settings: AuditLogSettingsFfi,
    ) -> Result<AuditLogSettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_audit_log_settings(settings.into())
            .await?
            .into())
    }

    /// Supply non-persisted audit tracker upload metadata: optional Goggles
    /// upload URL override, bearer token from the host app, and optional system
    /// hardware model, platform, and app version.
    ///
    /// The returned config confirms what was stored but never echoes the
    /// bearer token back across FFI: secrets flow in, not out.
    pub fn set_audit_log_tracker_config(
        &self,
        config: AuditLogTrackerConfigV4Ffi,
    ) -> Result<AuditLogTrackerConfigV4Ffi, MarmotKitError> {
        Ok(AuditLogTrackerConfigV4Ffi::redacted(
            self.runtime.set_audit_log_tracker_config(config.into())?,
        ))
    }

    /// Configure the v5 audit OTLP destination in memory. The token is
    /// write-only; disabling clears it. This does not enable recording.
    pub fn set_audit_otlp_config_v5(
        &self,
        mut config: AuditOtlpConfigV5Ffi,
    ) -> Result<AuditOtlpConfigV5Ffi, MarmotKitError> {
        let sender = if config.enabled {
            let destination = config
                .destination
                .clone()
                .ok_or_else(invalid_audit_otlp_config)?;
            let endpoint = config
                .endpoint
                .clone()
                .ok_or_else(invalid_audit_otlp_config)?;
            let token = config
                .authorization_bearer_token
                .take()
                .ok_or_else(invalid_audit_otlp_config)?;
            Some(
                if config.allow_loopback_dev {
                    AuditOtlpSender::for_loopback_dev(destination, endpoint, token)
                } else {
                    AuditOtlpSender::new(destination, endpoint, token)
                }
                .map_err(|_| invalid_audit_otlp_config())?,
            )
        } else {
            None
        };
        self.runtime.set_audit_otlp_sender(sender)?;
        Ok(config.redacted())
    }

    /// Local JSONL audit logs available for explicit forensic upload.
    pub fn audit_log_files(&self) -> Result<Vec<AuditLogFileFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .audit_log_files()?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// POST one selected JSONL audit log to a forensic analyzer endpoint.
    pub async fn post_audit_log_file(
        &self,
        path: String,
        endpoint: String,
    ) -> Result<AuditLogUploadResultFfi, MarmotKitError> {
        Ok(self
            .runtime
            .post_audit_log_file(&path, &endpoint)
            .await?
            .into())
    }

    /// Delete one local JSONL audit log file (e.g. behind a "clear audit log"
    /// button).
    ///
    /// When forensic audit logging is on and a session for the file's account
    /// is live, the recorder rotates to a fresh file and keeps recording, so
    /// the result's `still_recording` is `true`. When audit logging is off, or
    /// no session is recording this file, it is simply removed and
    /// `still_recording` is `false`. Pass a `path` from `audit_log_files()`.
    pub async fn delete_audit_log_file(
        &self,
        path: String,
    ) -> Result<AuditLogDeleteResultFfi, MarmotKitError> {
        Ok(self.runtime.delete_audit_log_file(&path).await?.into())
    }

    /// POST all local audit logs to the configured tracker when audit logging is
    /// enabled. This is safe for host apps to call unconditionally; disabled or
    /// unconfigured states return a structured skip result.
    pub async fn post_audit_log_tracker_update(
        &self,
    ) -> Result<AuditLogTrackerUpdateResultFfi, MarmotKitError> {
        Ok(self.runtime.post_audit_log_tracker_update().await?.into())
    }

    /// Run the same manual tracker pass with separate v4 and v5 results.
    pub async fn post_audit_log_tracker_update_v5(
        &self,
    ) -> Result<AuditLogTrackerUpdateResultV5Ffi, MarmotKitError> {
        Ok(self.runtime.post_audit_log_tracker_update().await?.into())
    }
}

fn invalid_audit_otlp_config() -> MarmotKitError {
    MarmotKitError::Runtime {
        details: "invalid audit OTLP sender configuration".to_owned(),
    }
}
