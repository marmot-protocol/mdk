//! The wiring surface `marmot-app` runs the collectors and exporters through (#2627).
//!
//! Applying consent receipts, silencing, the telemetry origin, the collector's runtime
//! configuration, the product delivery worker, the exporters' runtime config and the audit sender's
//! destination. Only `marmot-app` calls it; recording goes through [`crate::Observer`]'s views. Hosts
//! never see it, so the collector and the exporter types they can name gain no method.

use std::future::Future;

use crate::audit_otlp_sender::AuditOtlpSender;
use crate::export_config::RelayTelemetryRuntimeConfig;
use crate::{
    ProductAnalytics, ProductAnalyticsError, ProductAnalyticsRuntimeConfig,
    UsageDiagnosticsSettings,
};

pub use crate::product_analytics::consent::{ConsentChange, ReceiptRevisions, ReceiptStamp};

/// Silence the collector (a deployment without diagnostics) or lift it.
pub fn silence(collector: &ProductAnalytics, silent: bool) {
    collector.silence(silent);
}

/// Revoke the in-memory grant: every permit already issued stops being valid.
pub fn revoke_memory(collector: &ProductAnalytics) {
    collector.revoke_memory();
}

/// Apply a consent receipt and the install id it was granted under.
pub fn set_receipt(
    collector: &ProductAnalytics,
    receipt: UsageDiagnosticsSettings,
    diagnostic_id: String,
) {
    collector.set_receipt(receipt, diagnostic_id);
}

/// Take the consent lock for a consent change. See [`ConsentChange`].
pub fn consent_change(collector: &ProductAnalytics) -> ConsentChange<'_> {
    collector.consent_change()
}

/// Whether a granted receipt saved under `saved` must be accepted again.
pub fn requires_acceptance(collector: &ProductAnalytics, saved: &ReceiptRevisions) -> bool {
    collector.requires_acceptance(saved)
}

/// Whether an OTLP collector rejected relay telemetry under the current grant.
pub fn telemetry_rejected(collector: &ProductAnalytics) -> bool {
    collector.telemetry_rejected()
}

pub fn clear_telemetry_rejection(collector: &ProductAnalytics) {
    collector.clear_telemetry_rejection();
}

/// Configure the collector for the host's product endpoint and registry.
pub fn configure(
    collector: &ProductAnalytics,
    config: ProductAnalyticsRuntimeConfig,
    scope: String,
) -> Result<(), ProductAnalyticsError> {
    collector.configure(config, scope)
}

/// Bind the collector's export scope to the relay-telemetry endpoint's origin.
pub fn telemetry_origin(collector: &ProductAnalytics, endpoint: Option<&str>) {
    collector.telemetry_origin(endpoint);
}

/// Seal the open window as partial before a flush.
pub fn seal_partial(collector: &ProductAnalytics) {
    collector.seal_partial();
}

/// The product delivery worker for the executor to run. It stops when the grant it started under
/// is revoked.
pub fn delivery_worker(
    collector: &ProductAnalytics,
    relay_plane: transport_nostr::MarmotRelayPlane,
) -> impl Future<Output = ()> + Send + 'static {
    collector.clone().run(relay_plane)
}

/// A random version-4 UUID for the telemetry install id `marmot-app` persists.
pub fn generate_telemetry_install_id() -> String {
    crate::product_analytics::generate_telemetry_install_id()
}

/// Trim and validate the host's relay-telemetry runtime config.
pub fn normalize_runtime_config(
    config: RelayTelemetryRuntimeConfig,
) -> Result<RelayTelemetryRuntimeConfig, String> {
    config.normalize()
}

/// The stable destination identity an audit OTLP sender delivers to.
pub fn audit_destination(sender: &AuditOtlpSender) -> &str {
    sender.destination()
}
