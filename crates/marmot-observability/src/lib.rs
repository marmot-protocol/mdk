//! The code that ships Marmot diagnostics off the device: the relay-telemetry OTLP exporter,
//! product analytics with its usage-diagnostics consent state, the app-performance recorder, the
//! audit OTLP sender and the audit upload's HTTP half, the collector dial-safety helper they share,
//! and the exporters' resolved configuration (mdk#2627).
//!
//! `marmot-app` records through [`Observer`], runs the collectors through [`wiring`], and
//! re-exports the types hosts name at their `marmot_app::` paths.
//!
//! The root re-exports are the surface. Three modules stay public because their path is part of
//! it: `marmot-app` re-exports [`product_analytics`] and [`audit_otlp_sender`] as modules hosts
//! name, and [`wiring`]'s functions read only qualified.

mod app_telemetry;
pub mod audit_otlp_sender;
mod audit_upload;
mod collector_host_safety;
mod export_config;
mod observer;
pub mod product_analytics;
mod relay_telemetry_export;
pub mod wiring;

pub use app_telemetry::runtime::{Observation, Outcome};
pub use app_telemetry::{
    AppPerformanceOperation, AppPerformanceOperationSnapshot, AppPerformanceSnapshot,
    AppPerformanceTelemetry, HostPerformanceOperation, HostPerformanceOutcome,
    RuntimePerformanceOperation, RuntimePerformanceSnapshot, SyncErrorClass,
    SyncFailureClassification, SyncFailureCount, SyncFailureStage, bounded_advisory_step,
    hand_in_sqlcipher_probe_counters,
};
pub use audit_otlp_sender::{AuditOtlpSendResult, AuditOtlpSender, AuditOtlpSenderConfigError};
pub use audit_upload::{
    AUDIT_LOG_UPLOAD_MAX_BYTES, AuditSnapshotPost, AuditSnapshotReceipt, AuditUploadCheckpoint,
    AuditUploadError, AuditUploadOutcome, AuditUploadSnapshot, ListedAuditFile,
    invalid_audit_upload, post_audit_upload_snapshot, system_time_ms,
    validate_audit_upload_endpoint,
};
pub use collector_host_safety::{
    CollectorRequestError, HttpClientBuilder, PinnedCollector, hand_in_http_builder, pin_with,
    system_resolve,
};
pub use export_config::{
    AuditLogUploadSource, DEFAULT_EXPORT_INTERVAL, RelayTelemetryExportConfig,
    RelayTelemetryResource, RelayTelemetryRuntimeConfig, endpoint_transport_allowed, trim_optional,
};
pub use observer::{
    ObservedOperation, Observer, PerformanceRecorder, ProductBacklogSource, ProductOperation,
    ProductRecorder, StorageFailureKind, confirmed_or_failure, permit_valid, send_outcome,
    success_or_failure,
};
pub use product_analytics::*;
pub use relay_telemetry_export::{
    ExportHistogram, ExportMetricPoint, ExportMetricValue, RelayExportError,
    RelayTelemetryExportBatch, RelayTelemetryExporter, build_export_batch,
    build_export_batch_with_app_performance, metric_names,
};

// What only `marmot-app`'s tests reach, including every type their signatures name.
#[cfg(any(test, feature = "test-support"))]
pub use collector_host_safety::{CONNECT_TIMEOUT, REQUEST_TIMEOUT, resolve_with_for_test};
#[cfg(all(
    any(test, feature = "test-support"),
    feature = "product-analytics-export"
))]
pub use product_analytics::fixtures::test_product_collector;
#[cfg(any(test, feature = "test-support"))]
pub use product_analytics::fixtures::{FakeClock, configured, grant};
