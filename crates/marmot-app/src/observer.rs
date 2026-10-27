//! The one recording handle `marmot-app` reports through (#2627).
//!
//! `MarmotApp` owns the collector side: the [`ProductAnalytics`] collector with its
//! usage-diagnostics consent state. Each runtime holds an [`Observer`] that shares that collector
//! and adds the runtime's own [`AppPerformanceTelemetry`] recorder, which forwards the operations
//! product analytics reports to the same collector. Two runtimes built from one app therefore
//! share consent and product events, and keep separate performance snapshots.
//!
//! Recording takes outcome values, never `marmot-app`'s error type: a performance outcome, a
//! product outcome from the closed catalogue, and a storage-failure kind. `marmot-app` converts
//! its own errors into them in `app_outcome`.

use crate::{AppPerformanceTelemetry, ProductAnalytics};

#[derive(Clone, Debug, Default)]
pub(crate) struct Observer {
    product: ProductAnalytics,
    performance: AppPerformanceTelemetry,
}

impl Observer {
    /// A runtime's handle: the app's collector, shared, and a performance recorder of its own.
    /// The recorder's snapshots carry the process-wide SQLCipher migration probe `(runs, skips)`
    /// that `sqlcipher_probe_counters` reads.
    pub(crate) fn sharing(
        product: &ProductAnalytics,
        sqlcipher_probe_counters: fn() -> (u64, u64),
    ) -> Self {
        Self {
            product: product.clone(),
            performance: AppPerformanceTelemetry::with_product_analytics(product.clone())
                .with_sqlcipher_probe_counters(sqlcipher_probe_counters),
        }
    }

    /// The shared product collector and its consent state.
    pub(crate) fn product(&self) -> &ProductAnalytics {
        &self.product
    }

    /// This handle's performance recorder.
    pub(crate) fn performance(&self) -> &AppPerformanceTelemetry {
        &self.performance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_handle_snapshots_the_probe_counters_it_is_handed() {
        let observer = Observer::sharing(&ProductAnalytics::default(), || (3, 5));
        let snapshot = observer.performance().snapshot();
        assert_eq!(
            (
                snapshot.sqlcipher_migration_probe_runs,
                snapshot.sqlcipher_migration_probe_skips
            ),
            (3, 5)
        );
        let unwired = Observer::default().performance().snapshot();
        assert_eq!(
            (
                unwired.sqlcipher_migration_probe_runs,
                unwired.sqlcipher_migration_probe_skips
            ),
            (0, 0)
        );
    }
}
