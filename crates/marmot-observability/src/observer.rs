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
//!
//! The recorders are views. [`ProductRecorder`] and [`PerformanceRecorder`] wrap the collector and
//! the performance recorder hosts can name, add the recording methods only `marmot-app` calls, and
//! deref to the wrapped type for its public methods. Hosts never see the views, so the types they
//! name gain no method. Starting workers, consent, silencing and the telemetry origin are not
//! recording; they are on [`crate::wiring`].

use std::ops::Deref;
use std::time::Duration;

use crate::app_telemetry::AppPerformanceOperation;
use crate::app_telemetry::runtime::{Observation, Outcome};
use crate::{
    AppPerformanceTelemetry, DiagnosticsPermit, ProductAnalytics, ProductFamily,
    ProductObservation, ProductUnit, RuntimePerformanceOperation, SyncFailureClassification,
};

pub use crate::product_analytics::observed::{
    ObservedOperation, confirmed_or_failure, send_outcome, success_or_failure,
};
pub use crate::product_analytics::recording::{ProductBacklogSource, StorageFailureKind};

#[derive(Clone, Debug, Default)]
pub struct Observer {
    product: ProductRecorder,
    performance: PerformanceRecorder,
}

impl Observer {
    /// A runtime's handle: the app's collector, shared, and a performance recorder of its own.
    pub fn sharing(product: &ProductRecorder) -> Self {
        Self {
            product: product.clone(),
            performance: PerformanceRecorder(AppPerformanceTelemetry::with_product_analytics(
                product.0.clone(),
            )),
        }
    }

    /// The shared product collector and its consent state.
    pub fn product(&self) -> &ProductRecorder {
        &self.product
    }

    /// This handle's performance recorder.
    pub fn performance(&self) -> &PerformanceRecorder {
        &self.performance
    }
}

/// The product collector, with the recording methods `marmot-app` calls.
#[derive(Clone, Debug, Default)]
pub struct ProductRecorder(ProductAnalytics);

impl Deref for ProductRecorder {
    type Target = ProductAnalytics;

    fn deref(&self) -> &ProductAnalytics {
        &self.0
    }
}

#[cfg(any(test, feature = "test-support"))]
impl From<ProductAnalytics> for ProductRecorder {
    fn from(collector: ProductAnalytics) -> Self {
        Self(collector)
    }
}

impl ProductRecorder {
    pub fn permit(&self) -> Option<DiagnosticsPermit> {
        self.0.permit()
    }

    pub fn observe(
        &self,
        family: ProductFamily,
        operation: &str,
        outcome: &str,
        unit: ProductUnit,
        duration: Option<Duration>,
    ) {
        self.0.observe(family, operation, outcome, unit, duration);
    }

    pub fn storage_failure(
        &self,
        permit: Option<&DiagnosticsPermit>,
        failure: impl Into<Option<StorageFailureKind>>,
    ) {
        self.0.storage_failure(permit, failure);
    }

    pub fn backlog_source(&self) -> ProductBacklogSource {
        self.0.backlog_source()
    }

    /// Begin an operation whose outcome a rule picks from the result of the work it runs.
    pub fn observed(
        &self,
        family: ProductFamily,
        operation: &'static str,
        unit: ProductUnit,
    ) -> ObservedOperation {
        self.0.observed(family, operation, unit)
    }

    /// Begin an operation `marmot-app` records more than an outcome on. Hosts begin theirs with
    /// the collector's public `begin`.
    pub fn operation(
        &self,
        family: ProductFamily,
        operation: &'static str,
        unit: ProductUnit,
    ) -> Option<ProductOperation> {
        self.0.begin(family, operation, unit).map(ProductOperation)
    }
}

/// Whether a permit still holds the grant it was issued under.
pub fn permit_valid(permit: &DiagnosticsPermit) -> bool {
    permit.valid()
}

/// A product operation `marmot-app` began, with the samples and counts it records on it.
/// Dropping it unfinished records cancellation, as a host's observation does.
pub struct ProductOperation(ProductObservation);

impl ProductOperation {
    pub fn counts_only(self) -> Self {
        Self(self.0.counts_only())
    }

    pub fn discard(self) {
        self.0.discard();
    }

    pub fn count(&self, outcome: &str, unit: ProductUnit, count: u64) {
        self.0.count(outcome, unit, count);
    }

    pub fn directory_sample(&self, outcome: &str, source: &str, count: u64) {
        self.0.directory_sample(outcome, source, count);
    }

    pub fn duration_sample(&self, outcome: &str, duration: Duration) {
        self.0.duration_sample(outcome, duration);
    }

    pub fn finish(self, outcome: &str) {
        self.0.finish(outcome);
    }

    pub fn finish_with_duration(self, outcome: &str, duration: Duration) {
        self.0.finish_with_duration(outcome, duration);
    }
}

/// A runtime's performance recorder, with the recording methods `marmot-app` calls.
#[derive(Clone, Debug, Default)]
pub struct PerformanceRecorder(AppPerformanceTelemetry);

impl Deref for PerformanceRecorder {
    type Target = AppPerformanceTelemetry;

    fn deref(&self) -> &AppPerformanceTelemetry {
        &self.0
    }
}

/// A recorder over `telemetry`'s counters, for a caller handed only the recorder hosts name.
/// Clones share their counters, so what it records shows in `telemetry`'s snapshots.
impl From<&AppPerformanceTelemetry> for PerformanceRecorder {
    fn from(telemetry: &AppPerformanceTelemetry) -> Self {
        Self(telemetry.clone())
    }
}

impl PerformanceRecorder {
    pub fn record(&self, operation: AppPerformanceOperation, duration: Duration, success: bool) {
        self.0.record(operation, duration, success);
    }

    pub fn record_media(
        &self,
        operation: AppPerformanceOperation,
        duration: Duration,
        success: bool,
        media_type: &str,
    ) {
        self.0
            .record_media(operation, duration, success, media_type);
    }

    pub fn record_classified_result(
        &self,
        operation: AppPerformanceOperation,
        duration: Duration,
        failure: Option<SyncFailureClassification>,
    ) {
        self.0
            .record_classified_result(operation, duration, failure);
    }

    pub fn record_runtime(
        &self,
        operation: RuntimePerformanceOperation,
        duration: Duration,
        outcome: Outcome,
    ) {
        self.0.record_runtime(operation, duration, outcome);
    }

    pub fn observe(&self, operation: RuntimePerformanceOperation) -> Observation {
        self.0.observe(operation)
    }

    pub async fn measure_app<T, E>(
        &self,
        operation: RuntimePerformanceOperation,
        work: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E>
    where
        for<'e> Outcome: From<&'e E>,
    {
        self.0.measure_app(operation, work).await
    }
}

#[cfg(all(test, feature = "product-analytics-export"))]
mod tests {
    use super::*;
    use crate::product_analytics::fixtures::{configured, grant};
    use std::sync::atomic::Ordering;

    #[test]
    fn recording_views_preserve_operation_samples_and_share_revocation() {
        let (collector, clock) = configured();
        grant(&collector);
        clock.mono.store(1000, Ordering::Relaxed);
        let product = ProductRecorder::from(collector.clone());
        let first = Observer::sharing(&product);
        let second = Observer::sharing(&product);
        let permit = first.product().permit().unwrap();

        first.performance().record(
            AppPerformanceOperation::AppStart,
            Duration::from_millis(10),
            true,
        );
        assert_eq!(first.performance().snapshot().app_start.attempts, 1);
        assert_eq!(second.performance().snapshot().app_start.attempts, 0);
        first.product().observe(
            ProductFamily::Maintenance,
            "sweep",
            "performed",
            ProductUnit::Transition,
            None,
        );
        let output = second
            .product()
            .observed(
                ProductFamily::Maintenance,
                "self_update",
                ProductUnit::Attempt,
            )
            .run(|| Ok::<_, ()>(17), success_or_failure);
        assert_eq!(output, Ok(17));

        let counts = first
            .product()
            .operation(
                ProductFamily::Maintenance,
                "retention",
                ProductUnit::Attempt,
            )
            .unwrap()
            .counts_only();
        counts.count("success", ProductUnit::Action, 2);
        drop(counts);
        first
            .product()
            .operation(
                ProductFamily::Maintenance,
                "key_package",
                ProductUnit::Attempt,
            )
            .unwrap()
            .discard();
        first
            .product()
            .operation(ProductFamily::Maintenance, "deferred", ProductUnit::Attempt)
            .unwrap()
            .finish("success");
        second
            .product()
            .operation(ProductFamily::Maintenance, "capacity", ProductUnit::Attempt)
            .unwrap()
            .finish_with_duration("failure", Duration::from_millis(250));
        let directory = second
            .product()
            .operation(ProductFamily::Directory, "key_package", ProductUnit::Action)
            .unwrap()
            .counts_only();
        directory.directory_sample("success", "cache", 3);
        directory.duration_sample("success", Duration::from_millis(25));
        drop(directory);
        first
            .product()
            .storage_failure(Some(&permit), StorageFailureKind::Busy);
        let backlog = second.product().backlog_source();
        backlog.sample(&permit, ProductFamily::Maintenance, "pending", 8);

        assert_eq!(first.product().status().queued_events, 0);
        crate::wiring::seal_partial(&collector);
        assert_eq!(first.product().status().queued_events, 11);
        let payloads = collector.test_payloads();
        assert!(payloads.iter().all(|row| row["props"]["partial"] == "true"));
        let find = |event: &str, operation: &str, unit: &str| {
            let rows = payloads
                .iter()
                .filter(|row| {
                    row["eventName"] == event
                        && row["props"]["operation"] == operation
                        && row["props"]["unit"] == unit
                })
                .collect::<Vec<_>>();
            assert_eq!(rows.len(), 1, "{event}/{operation}/{unit}");
            rows[0]
        };
        for (operation, unit, count, outcome) in [
            ("sweep", "transition", "1", "performed"),
            ("self_update", "attempt", "1", "success"),
            ("retention", "action", "2", "success"),
            ("deferred", "attempt", "1", "success"),
            ("capacity", "attempt", "1", "failure"),
        ] {
            let row = find("mdk_maintenance_summary", operation, unit);
            assert_eq!(row["props"]["count_bucket"], count);
            assert_eq!(row["props"]["outcome"], outcome);
        }
        let startup = find("mdk_runtime_summary", "startup", "attempt");
        assert_eq!(startup["props"]["count_bucket"], "1");
        assert_eq!(startup["props"]["duration_bucket"], "le_10ms");
        assert_eq!(
            find("mdk_maintenance_summary", "capacity", "attempt")["props"]["duration_bucket"],
            "le_250ms"
        );
        assert_eq!(
            payloads
                .iter()
                .filter(|row| row["eventName"] == "mdk_maintenance_summary")
                .count(),
            6,
            "count-only and discarded tickets must not add cancellation samples"
        );
        assert!(!payloads.iter().any(|row| {
            row["eventName"] == "mdk_maintenance_summary"
                && row["props"]["operation"] == "key_package"
        }));
        let directory_rows = payloads
            .iter()
            .filter(|row| row["eventName"] == "mdk_directory_summary")
            .collect::<Vec<_>>();
        assert_eq!(directory_rows.len(), 2);
        let source = directory_rows
            .iter()
            .find(|row| row["props"]["source"] == "cache")
            .unwrap();
        assert_eq!(source["props"]["count_bucket"], "3_5");
        let duration = directory_rows
            .iter()
            .find(|row| row["props"]["duration_bucket"] == "le_25ms")
            .unwrap();
        assert_eq!(duration["props"]["count_bucket"], "1");
        assert_eq!(
            find("mdk_storage_summary", "busy", "attempt")["props"]["outcome"],
            "failure"
        );
        assert_eq!(
            find("mdk_maintenance_summary", "pending", "backlog")["props"]["count_bucket"],
            "6_10"
        );

        crate::wiring::revoke_memory(&collector);
        assert!(!permit_valid(&permit));
        assert!(first.product().permit().is_none());
        assert!(second.product().permit().is_none());
        assert!(
            second
                .product()
                .operation(ProductFamily::Maintenance, "sweep", ProductUnit::Attempt)
                .is_none()
        );
        assert!(collector.test_payloads().is_empty());
    }
}
