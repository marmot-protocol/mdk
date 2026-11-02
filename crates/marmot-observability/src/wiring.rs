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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::product_analytics::fixtures::configured;
    use crate::{ProductRecorder, UsageDiagnosticsDecision, permit_valid};
    use std::sync::atomic::Ordering;

    fn grant(collector: &ProductAnalytics) {
        set_receipt(
            collector,
            UsageDiagnosticsSettings {
                decision: UsageDiagnosticsDecision::Granted,
                ..Default::default()
            },
            generate_telemetry_install_id(),
        );
    }

    #[test]
    fn consent_transaction_stays_closed_until_persisted_and_rechecks_each_revision() {
        let (collector, clock) = configured();
        let product = ProductRecorder::from(collector.clone());
        let saved = {
            let change = consent_change(&collector);
            let stamp = change.receipt_stamp();
            assert_eq!(stamp.updated_at_ms, 1_800_000);
            assert_eq!(stamp.revisions.policy, crate::USAGE_DIAGNOSTICS_POLICY);
            stamp.revisions
        };
        assert!(!requires_acceptance(&collector, &saved));
        for changed in [
            ReceiptRevisions {
                policy: "old-policy".into(),
                registry: saved.registry.clone(),
                scope: saved.scope.clone(),
            },
            ReceiptRevisions {
                policy: saved.policy.clone(),
                registry: "old-registry".into(),
                scope: saved.scope.clone(),
            },
            ReceiptRevisions {
                policy: saved.policy.clone(),
                registry: saved.registry.clone(),
                scope: "old-scope".into(),
            },
        ] {
            assert!(requires_acceptance(&collector, &changed));
        }
        grant(&collector);
        let old = product.permit().unwrap();
        {
            let change = consent_change(&collector);
            revoke_memory(&collector);
            change.fail_closed();
            grant(&collector);
            assert!(product.permit().is_none());
            assert!(requires_acceptance(&collector, &saved));
            change.persisted();
        }
        assert!(!permit_valid(&old));
        let current = product.permit().unwrap();
        assert!(permit_valid(&current));
        assert!(!requires_acceptance(&collector, &saved));
        silence(&collector, true);
        assert!(!permit_valid(&current));
        assert!(product.permit().is_none());
        silence(&collector, false);
        assert!(product.permit().is_some());
        assert!(!permit_valid(&current));

        clock.wall.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(
            consent_change(&collector).receipt_stamp().updated_at_ms,
            i64::MAX
        );
    }

    #[test]
    fn scope_changes_revoke_permits_while_same_origin_paths_preserve_them() {
        let (collector, _) = configured();
        let product = ProductRecorder::from(collector.clone());
        telemetry_origin(&collector, Some("https://collector.example/first"));
        grant(&collector);
        let old = product.permit().unwrap();
        let saved = consent_change(&collector).receipt_stamp().revisions;
        telemetry_origin(
            &collector,
            Some("https://collector.example/second?mode=test"),
        );
        assert!(permit_valid(&old));
        assert!(!requires_acceptance(&collector, &saved));

        telemetry_origin(&collector, Some("https://other.example/v1/metrics"));
        assert!(!permit_valid(&old));
        assert!(requires_acceptance(&collector, &saved));
        let rebound = consent_change(&collector).receipt_stamp().revisions;
        assert!(!requires_acceptance(&collector, &rebound));
        let current = product.permit().unwrap();
        let mut config = collector.config_for_test();
        config.operator = "other_operator".into();
        configure(&collector, config, "http://127.0.0.1:9876".into()).unwrap();
        assert!(!permit_valid(&current));
        assert!(requires_acceptance(&collector, &rebound));

        #[cfg(feature = "otlp-export")]
        {
            product.permit().unwrap().reject_telemetry();
            assert!(telemetry_rejected(&collector));
            clear_telemetry_rejection(&collector);
            assert!(!telemetry_rejected(&collector));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn delivery_worker_stops_when_its_grant_is_revoked() {
        let (collector, _) = configured();
        grant(&collector);
        let worker = delivery_worker(
            &collector,
            transport_nostr::MarmotRelayPlane::full_history(),
        );
        tokio::pin!(worker);
        // Poll the real worker into its wait, then revoke the grant it captured.
        tokio::select! {
            biased;
            () = &mut worker => panic!("worker stopped while consent was granted"),
            () = tokio::task::yield_now() => {}
        }
        revoke_memory(&collector);
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut worker)
            .await
            .expect("revoked worker must terminate without waiting for its next minute tick");
    }
}
