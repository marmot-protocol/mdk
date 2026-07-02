//! Relay-list, relay-health, and relay-telemetry commands.

use crate::conversions::{RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi};
use crate::errors::MarmotKitError;
use crate::{Marmot, conversions};

#[uniffi::export(async_runtime = "tokio")]
impl Marmot {
    /// Per-account relay lists: the NIP-65 and inbox lists the account has
    /// published, plus the configured default/bootstrap sets.
    pub fn account_relay_lists(
        &self,
        account_ref: String,
    ) -> Result<conversions::AccountRelayListsFfi, MarmotKitError> {
        let account = self.runtime.accounts().resolve(&account_ref)?;
        let status = self.app.account_relay_list_status(&account.label)?;
        Ok(status.into())
    }

    /// Live relay-plane connection health (connected / connecting /
    /// disconnected counts, etc.) for the relay diagnostics view.
    pub async fn relay_health(&self) -> conversions::RelayHealthFfi {
        let shared = self.runtime.shared_services();
        shared.relay_plane().relay_health().await.into()
    }

    /// Device-wide relay telemetry export settings. Export is opt-in and stays
    /// inert until `export_enabled` is true and runtime/default config supplies
    /// a valid OTLP endpoint, bearer token, and resource attributes.
    pub fn relay_telemetry_settings(&self) -> Result<RelayTelemetrySettingsFfi, MarmotKitError> {
        Ok(self.runtime.relay_telemetry_settings()?.into())
    }

    /// Stable random identifier for this app install, suitable for the OTLP
    /// `service.instance.id` resource attribute. Separate from audit-log device
    /// identity.
    pub fn telemetry_install_id(&self) -> Result<String, MarmotKitError> {
        Ok(self.runtime.telemetry_install_id()?)
    }

    /// Supply non-persisted OTLP runtime metadata: optional metrics URL
    /// override, bearer token from the host app's build-time secret, and
    /// resource attributes from the platform shell.
    pub async fn set_relay_telemetry_runtime_config(
        &self,
        config: RelayTelemetryRuntimeConfigFfi,
    ) -> Result<(), MarmotKitError> {
        self.runtime
            .set_relay_telemetry_runtime_config(config.into())?;
        Ok(())
    }

    /// Persist device-wide relay telemetry export settings and return the
    /// normalized settings that were stored.
    pub async fn set_relay_telemetry_settings(
        &self,
        settings: RelayTelemetrySettingsFfi,
    ) -> Result<RelayTelemetrySettingsFfi, MarmotKitError> {
        Ok(self
            .runtime
            .set_relay_telemetry_settings(settings.into())?
            .into())
    }
}
