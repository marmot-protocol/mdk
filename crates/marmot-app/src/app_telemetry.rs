//! Aggregate app-performance telemetry for the opt-in export path.
//!
//! This module intentionally mirrors the relay telemetry privacy model: samples
//! are cumulative counters and fixed-bucket millisecond histograms only. There
//! are no fields for account, group, message, relay, URL, pubkey, payload, or
//! key material.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use transport_nostr_adapter::{DurationHistogramSnapshot, HistogramBucket};

const APP_DURATION_BUCKET_BOUNDS_MS: [u64; 27] = [
    1, 2, 5, 10, 20, 30, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 7500,
    10000, 15000, 20000, 30000, 60000, 120000, 300000,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppPerformanceOperation {
    AppStart,
    DirectorySubscriptionSync,
    AccountReconcile,
    AccountOpen,
    AccountCatchUp,
    AccountSync,
    OutboundMessageSend,
    MediaUpload,
    MediaDownload,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPerformanceOperationSnapshot {
    /// Operation attempts since process start.
    pub attempts: u64,
    /// Successful operations since process start.
    pub successes: u64,
    /// Failed operations since process start.
    pub failures: u64,
    /// Operation duration histogram in local monotonic milliseconds.
    pub duration_ms: DurationHistogramSnapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPerformanceSnapshot {
    pub app_start: AppPerformanceOperationSnapshot,
    pub directory_subscription_sync: AppPerformanceOperationSnapshot,
    pub account_reconcile: AppPerformanceOperationSnapshot,
    pub account_open: AppPerformanceOperationSnapshot,
    pub account_catch_up: AppPerformanceOperationSnapshot,
    pub account_sync: AppPerformanceOperationSnapshot,
    pub outbound_message_send: AppPerformanceOperationSnapshot,
    pub media_upload: AppPerformanceOperationSnapshot,
    pub media_download: AppPerformanceOperationSnapshot,
}

#[derive(Clone, Debug, Default)]
pub struct AppPerformanceTelemetry {
    inner: Arc<Mutex<AppPerformanceTelemetryInner>>,
}

#[derive(Clone, Debug, Default)]
struct AppPerformanceTelemetryInner {
    app_start: AppPerformanceOperationTelemetry,
    directory_subscription_sync: AppPerformanceOperationTelemetry,
    account_reconcile: AppPerformanceOperationTelemetry,
    account_open: AppPerformanceOperationTelemetry,
    account_catch_up: AppPerformanceOperationTelemetry,
    account_sync: AppPerformanceOperationTelemetry,
    outbound_message_send: AppPerformanceOperationTelemetry,
    media_upload: AppPerformanceOperationTelemetry,
    media_download: AppPerformanceOperationTelemetry,
}

#[derive(Clone, Debug, Default)]
struct AppPerformanceOperationTelemetry {
    attempts: u64,
    successes: u64,
    failures: u64,
    duration_ms: DurationHistogram,
}

#[derive(Clone, Debug)]
struct DurationHistogram {
    buckets: [u64; APP_DURATION_BUCKET_BOUNDS_MS.len()],
    overflow: u64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; APP_DURATION_BUCKET_BOUNDS_MS.len()],
            overflow: 0,
        }
    }
}

impl DurationHistogram {
    fn record(&mut self, duration: Duration) {
        let delta_ms = duration.as_millis().min(u64::MAX as u128) as u64;
        for (idx, bound) in APP_DURATION_BUCKET_BOUNDS_MS.iter().enumerate() {
            if delta_ms <= *bound {
                self.buckets[idx] += 1;
                return;
            }
        }
        self.overflow += 1;
    }

    fn snapshot(&self) -> DurationHistogramSnapshot {
        DurationHistogramSnapshot {
            buckets: APP_DURATION_BUCKET_BOUNDS_MS
                .iter()
                .zip(self.buckets.iter())
                .map(|(bound, count)| HistogramBucket {
                    upper_bound_ms: *bound,
                    count: *count,
                })
                .collect(),
            overflow_count: self.overflow,
        }
    }
}

impl AppPerformanceOperationTelemetry {
    fn record(&mut self, duration: Duration, success: bool) {
        self.attempts += 1;
        if success {
            self.successes += 1;
        } else {
            self.failures += 1;
        }
        self.duration_ms.record(duration);
    }

    fn snapshot(&self) -> AppPerformanceOperationSnapshot {
        AppPerformanceOperationSnapshot {
            attempts: self.attempts,
            successes: self.successes,
            failures: self.failures,
            duration_ms: self.duration_ms.snapshot(),
        }
    }
}

impl AppPerformanceTelemetry {
    pub(crate) fn record(
        &self,
        operation: AppPerformanceOperation,
        duration: Duration,
        success: bool,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match operation {
            AppPerformanceOperation::AppStart => inner.app_start.record(duration, success),
            AppPerformanceOperation::DirectorySubscriptionSync => {
                inner.directory_subscription_sync.record(duration, success)
            }
            AppPerformanceOperation::AccountReconcile => {
                inner.account_reconcile.record(duration, success);
            }
            AppPerformanceOperation::AccountOpen => inner.account_open.record(duration, success),
            AppPerformanceOperation::AccountCatchUp => {
                inner.account_catch_up.record(duration, success);
            }
            AppPerformanceOperation::AccountSync => inner.account_sync.record(duration, success),
            AppPerformanceOperation::OutboundMessageSend => {
                inner.outbound_message_send.record(duration, success);
            }
            AppPerformanceOperation::MediaUpload => inner.media_upload.record(duration, success),
            AppPerformanceOperation::MediaDownload => {
                inner.media_download.record(duration, success);
            }
        }
    }

    pub fn snapshot(&self) -> AppPerformanceSnapshot {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        AppPerformanceSnapshot {
            app_start: inner.app_start.snapshot(),
            directory_subscription_sync: inner.directory_subscription_sync.snapshot(),
            account_reconcile: inner.account_reconcile.snapshot(),
            account_open: inner.account_open.snapshot(),
            account_catch_up: inner.account_catch_up.snapshot(),
            account_sync: inner.account_sync.snapshot(),
            outbound_message_send: inner.outbound_message_send.snapshot(),
            media_upload: inner.media_upload.snapshot(),
            media_download: inner.media_download.snapshot(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_success_failure_counts_and_duration_buckets() {
        let telemetry = AppPerformanceTelemetry::default();

        telemetry.record(
            AppPerformanceOperation::AppStart,
            Duration::from_millis(50),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::AppStart,
            Duration::from_millis(400_000),
            false,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.app_start.attempts, 2);
        assert_eq!(snapshot.app_start.successes, 1);
        assert_eq!(snapshot.app_start.failures, 1);
        assert_eq!(snapshot.app_start.duration_ms.sample_count(), 2);
        assert!(
            snapshot
                .app_start
                .duration_ms
                .buckets
                .iter()
                .any(|bucket| bucket.upper_bound_ms == 50 && bucket.count == 1)
        );
        assert_eq!(snapshot.app_start.duration_ms.overflow_count, 1);
    }
}
