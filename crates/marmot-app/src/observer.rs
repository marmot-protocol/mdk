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
