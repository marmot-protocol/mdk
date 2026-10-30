//! The code that ships Marmot diagnostics off the device: the relay-telemetry OTLP exporter,
//! product analytics with its usage-diagnostics consent state, the app-performance recorder, the
//! audit OTLP sender and the audit upload's HTTP half, the collector dial-safety helper they share,
//! and the exporters' resolved configuration (mdk#2627).
//!
//! `marmot-app` records through [`observer::Observer`], runs the collectors through [`wiring`], and
//! re-exports the types hosts name at their `marmot_app::` paths.

pub mod app_telemetry;
pub mod audit_otlp_sender;
pub mod audit_upload;
pub mod collector_host_safety;
pub mod export_config;
#[cfg(any(test, feature = "test-support"))]
pub mod observability_test_support;
pub mod observer;
pub mod product_analytics;
mod relay_telemetry_export;
pub mod wiring;

pub use app_telemetry::{
    AppPerformanceOperationSnapshot, AppPerformanceSnapshot, AppPerformanceTelemetry,
    HostPerformanceOperation, HostPerformanceOutcome, RuntimePerformanceOperation,
    RuntimePerformanceSnapshot, SyncErrorClass, SyncFailureClassification, SyncFailureCount,
    SyncFailureStage,
};
pub use export_config::{
    AuditLogUploadSource, RelayTelemetryExportConfig, RelayTelemetryResource,
    RelayTelemetryRuntimeConfig,
};
pub use product_analytics::*;
pub use relay_telemetry_export::{
    ExportHistogram, ExportMetricPoint, ExportMetricValue, RelayExportError,
    RelayTelemetryExportBatch, RelayTelemetryExporter, build_export_batch,
    build_export_batch_with_app_performance, metric_names,
};
