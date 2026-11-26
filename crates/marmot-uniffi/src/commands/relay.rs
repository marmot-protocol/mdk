//! Relay-list, relay-health, and relay-telemetry commands.

use crate::conversions::{
    RelayEndpointClassificationFfi, RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi,
};
use crate::errors::MarmotKitError;
use crate::{Marmot, conversions};

#[marmot_uniffi_macros::on_tokio_runtime]
#[uniffi::export]
impl Marmot {
    /// Hostnames the relay plane will never dial or adopt.
    pub fn retired_relay_hosts(&self) -> Vec<String> {
        marmot_app::retired_relay_hosts()
    }

    /// Classify relay URLs using the same policy enforced at the dial boundary.
    ///
    /// Results preserve input order and cardinality so clients can batch the
    /// NIP-65 and inbox lists and associate every decision with its source URL.
    pub fn classify_relay_endpoints(
        &self,
        endpoints: Vec<String>,
    ) -> Vec<RelayEndpointClassificationFfi> {
        self.runtime
            .shared_services()
            .relay_plane()
            .classify_relay_endpoints(endpoints)
            .into_iter()
            .map(Into::into)
            .collect()
    }

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

    /// Read configured relays and the account's current connection state without dialing.
    pub async fn account_relay_liveness(
        &self,
        account_ref: String,
    ) -> Result<Vec<conversions::RelayLivenessFfi>, MarmotKitError> {
        Ok(self
            .runtime
            .account_relay_liveness(&account_ref)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// The account's relay health from its held lists, the relay policy and
    /// this process's inbox checks: one row per relay its inbox and NIP-65
    /// lists name, and warnings about invitations sent through its published
    /// inbox list. Local read; never dials. Re-read on `RelayHealthChanged`.
    pub async fn account_relay_health(
        &self,
        account_ref: String,
    ) -> Result<conversions::AccountRelayHealthFfi, MarmotKitError> {
        Ok(self
            .runtime
            .account_relay_health(&account_ref)
            .await?
            .into())
    }

    /// Check whether the account's inbox relays serve its inbox, and return
    /// the account's relay health after it. The account's worker runs it: one
    /// bounded read per allowed inbox relay (at most 16, 15 seconds each) on
    /// a connection of its own, answered with the signer the worker holds; a
    /// remote or host signer may be asked to sign a relay's authentication
    /// challenge. A relay the policy refuses is never dialed. Refused at once
    /// with `RelayCheckRunning` while a check of the account runs; without a
    /// running account worker it fails as the account not being active and
    /// dials nothing. A check no relay answered changes nothing. The returned
    /// health is the answer; `RelayHealthChanged` follows a changed answer
    /// from the worker.
    pub async fn check_account_relays(
        &self,
        account_ref: String,
    ) -> Result<conversions::AccountRelayHealthFfi, MarmotKitError> {
        Ok(self
            .runtime
            .check_account_relays(&account_ref)
            .await?
            .into())
    }

    /// Watch complete account-scoped snapshots; slow readers may skip intermediate states.
    pub async fn subscribe_relay_liveness(
        &self,
        account_ref: String,
    ) -> Result<std::sync::Arc<crate::RelayLivenessSubscription>, MarmotKitError> {
        Ok(crate::RelayLivenessSubscription::new(
            self.runtime.subscribe_relay_liveness(&account_ref).await?,
        ))
    }

    /// Attempt a configured relay connection and return its next observed state.
    pub async fn reconnect_relay(
        &self,
        account_ref: String,
        url: String,
    ) -> Result<conversions::RelayLivenessFfi, MarmotKitError> {
        Ok(self
            .runtime
            .reconnect_relay(&account_ref, &url)
            .await?
            .into())
    }

    /// Consent-bound random OTLP identifier, stable until revocation. Requires
    /// a current combined grant; never use this value in product events.
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

    /// Deprecated consent control. Use `set_usage_diagnostics_consent` instead.
    /// Enable requires a combined grant; disable revokes both exporters.
    /// This compatibility setter still updates the telemetry interval.
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
