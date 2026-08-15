//! Host-app performance telemetry commands.

use std::time::Duration;

use crate::Marmot;
use crate::conversions::{
    AppPerformanceSnapshotFfi, HostPerformanceOperationFfi, HostPerformanceOutcomeFfi,
};

#[uniffi::export]
impl Marmot {
    /// Record one approved host-app milestone.
    ///
    /// The operation is a closed enum and the exported metrics carry no
    /// caller-supplied labels.
    pub fn record_host_performance(
        &self,
        operation: HostPerformanceOperationFfi,
        duration_ms: u64,
        outcome: HostPerformanceOutcomeFfi,
    ) {
        self.runtime.record_host_performance(
            operation.into(),
            Duration::from_millis(duration_ms),
            outcome.into(),
        );
    }

    /// Read the process-wide app-performance snapshot for debug/diagnostics
    /// surfaces and on-demand support dumps.
    ///
    /// Read-only and privacy-safe by construction: cumulative counters and
    /// fixed-bucket millisecond histograms per reviewed operation, with no
    /// account, group, message, relay, URL, pubkey, payload, or key material.
    pub fn app_performance_snapshot(&self) -> AppPerformanceSnapshotFfi {
        self.runtime.app_performance_snapshot().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_performance_snapshot_crosses_the_ffi_boundary() {
        // Mirrors draft_round_trip_crosses_runtime_and_ffi_boundaries: poll
        // the app-runtime chain on a thread with enough stack for debug
        // builds.
        let test_thread = std::thread::Builder::new()
            .name("ffi-app-performance-snapshot".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(|| {
                let test_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                test_runtime.block_on(async {
                    let root = tempfile::tempdir().expect("tempdir");
                    let app = marmot_app::MarmotApp::with_relays(
                        root.path(),
                        vec!["wss://relay.example".to_owned()],
                    );
                    let runtime = app.runtime();
                    let kit = Marmot { app, runtime };

                    kit.record_host_performance(
                        HostPerformanceOperationFfi::SplashReady,
                        250,
                        HostPerformanceOutcomeFfi::Success,
                    );

                    let snapshot = kit.app_performance_snapshot();
                    assert_eq!(snapshot.host_splash_ready.attempts, 1);
                    assert_eq!(snapshot.host_splash_ready.successes, 1);
                    assert_eq!(snapshot.host_splash_ready.duration_ms.sum_ms, 250);
                    assert_eq!(snapshot.group_invite_members.attempts, 0);
                });
            })
            .unwrap();
        test_thread.join().unwrap();
    }
}
