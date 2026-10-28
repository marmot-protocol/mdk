//! Usage-diagnostics consent persistence and headless-host configuration (#2627).
//!
//! `MarmotApp` keeps the consent receipt and the telemetry install id in shared storage, and
//! restores them into the product collector, which holds the consent state and its permits. This
//! module reaches the collector only through the wiring surface. It takes the collector's locks in
//! their order: the consent lock across the whole change ([`wiring::consent_change`]), and the
//! state lock inside each step.

use crate::conversions::usage_diagnostics_settings_from_storage;
use crate::wiring::{self, ReceiptRevisions};
use crate::{
    AppError, DiagnosticsPermit, MarmotApp, ProductAnalyticsError, ProductAnalyticsMetadata,
    ProductAnalyticsRuntimeConfig, UsageDiagnosticsDecision, UsageDiagnosticsSettings,
};

impl MarmotApp {
    /// Opaque, revocable grant for direct diagnostic exporter integrations.
    pub fn usage_diagnostics_permit(&self) -> Result<DiagnosticsPermit, AppError> {
        self.product_analytics
            .permit()
            .ok_or_else(|| ProductAnalyticsError::ConsentRequired.into())
    }

    pub fn usage_diagnostics_settings(&self) -> Result<UsageDiagnosticsSettings, AppError> {
        let r = self.shared_storage()?.usage_diagnostics_settings()?;
        let mut receipt = usage_diagnostics_settings_from_storage(&r);
        if receipt.decision == UsageDiagnosticsDecision::Granted
            && wiring::requires_acceptance(
                &self.product_analytics,
                &ReceiptRevisions {
                    policy: r.policy_revision,
                    registry: r.registry_revision,
                    scope: r.scope_revision,
                },
            )
        {
            receipt.decision = UsageDiagnosticsDecision::AcceptanceRequired;
        }
        Ok(receipt)
    }
    pub(crate) fn stored_usage_diagnostics_settings(
        &self,
    ) -> Result<UsageDiagnosticsSettings, AppError> {
        let r = self.shared_storage()?.usage_diagnostics_settings()?;
        Ok(usage_diagnostics_settings_from_storage(&r))
    }

    pub(crate) fn restore_usage_diagnostics(&self) -> Result<(), AppError> {
        let consent = wiring::consent_change(&self.product_analytics);
        let restored = (|| {
            let receipt = self.usage_diagnostics_settings()?;
            let id = self
                .shared_storage()?
                .telemetry_install_id()?
                .unwrap_or_default();
            Ok::<_, AppError>((receipt, id))
        })();
        match restored {
            Ok((receipt, id)) => {
                wiring::set_receipt(&self.product_analytics, receipt, id);
                Ok(())
            }
            Err(error) => {
                wiring::revoke_memory(&self.product_analytics);
                consent.fail_closed();
                Err(error)
            }
        }
    }

    pub fn set_usage_diagnostics_consent(
        &self,
        enabled: bool,
    ) -> Result<UsageDiagnosticsSettings, AppError> {
        let consent = wiring::consent_change(&self.product_analytics);
        let old_id = if enabled && self.product_analytics.permit().is_some() {
            self.telemetry_install_id().ok()
        } else {
            None
        };
        wiring::revoke_memory(&self.product_analytics);
        // Fail closed until the complete durable write and receipt reload succeed.
        consent.fail_closed();
        let storage = self.shared_storage()?;
        let mut r = storage.usage_diagnostics_settings()?;
        let stamp = consent.receipt_stamp();
        r.decision = if enabled { 2 } else { 1 };
        r.policy_revision = stamp.revisions.policy;
        r.registry_revision = stamp.revisions.registry;
        r.scope_revision = stamp.revisions.scope;
        r.updated_at_ms = stamp.updated_at_ms;
        let id = enabled.then(|| old_id.unwrap_or_else(wiring::generate_telemetry_install_id));
        storage.set_usage_diagnostics_settings(&r, id.as_deref())?;
        let receipt = self.stored_usage_diagnostics_settings()?;
        consent.persisted();
        wiring::set_receipt(
            &self.product_analytics,
            receipt.clone(),
            id.unwrap_or_default(),
        );
        Ok(receipt)
    }
}

/// Configure optional headless-host analytics from its environment. Invalid analytics
/// settings never prevent the host from opening or disable its diagnostic pipeline.
pub fn configure_product_analytics_from_environment(
    runtime: &crate::MarmotAppRuntime,
    host_surface: &str,
) {
    configure_product_analytics_from_values(runtime, host_surface, |name| std::env::var(name).ok());
}

fn configure_product_analytics_from_values(
    runtime: &crate::MarmotAppRuntime,
    host_surface: &str,
    get: impl Fn(&str) -> Option<String>,
) {
    let endpoint = get("MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT");
    let key = get("MARMOT_PRODUCT_ANALYTICS_APP_KEY");
    if endpoint.is_none() && key.is_none() {
        return;
    }
    let config = ProductAnalyticsRuntimeConfig {
        events_endpoint: endpoint,
        app_key: key,
        operator: get("MARMOT_PRODUCT_ANALYTICS_OPERATOR").unwrap_or_default(),
        allow_loopback: get("MARMOT_PRODUCT_ANALYTICS_ALLOW_LOOPBACK").as_deref() == Some("1"),
        registry: Vec::new(),
        metadata: ProductAnalyticsMetadata {
            app_version: env!("CARGO_PKG_VERSION").into(),
            os_family: std::env::consts::OS.into(),
            os_major_version: String::new(),
            device_class: "headless".into(),
            host_surface: host_surface.into(),
            environment: get("MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT")
                .unwrap_or_else(|| "development".into()),
            is_debug: cfg!(debug_assertions),
        },
    };
    if runtime
        .set_product_analytics_runtime_config(config)
        .is_err()
    {
        tracing::warn!(
            target: "marmot_app::product_analytics",
            method = "configure_product_analytics_from_environment",
            error_code = "invalid_product_analytics_configuration",
            "optional product analytics configuration rejected"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_optional_host_environment_preserves_an_existing_diagnostic_grant() {
        for (operator, environment) in [("", "staging"), ("operator", "invalid")] {
            let tmp = tempfile::tempdir().unwrap();
            let app = crate::MarmotApp::with_relay(tmp.path(), "wss://relay.example");
            let runtime = app.clone().runtime();
            runtime.set_usage_diagnostics_consent(true).unwrap();
            let before = runtime.stored_usage_diagnostics_settings().unwrap();
            let permit = app.usage_diagnostics_permit().unwrap();
            configure_product_analytics_from_values(&runtime, "agent", |name| match name {
                "MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT" => {
                    Some("https://analytics.example/api/v0/events".into())
                }
                "MARMOT_PRODUCT_ANALYTICS_APP_KEY" => Some("A-SH-secret".into()),
                "MARMOT_PRODUCT_ANALYTICS_OPERATOR" => Some(operator.into()),
                "MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT" => Some(environment.into()),
                _ => None,
            });
            assert!(permit.valid());
            assert_eq!(runtime.stored_usage_diagnostics_settings().unwrap(), before);
            assert!(!app.product_analytics.config_ready());
        }
    }
}
