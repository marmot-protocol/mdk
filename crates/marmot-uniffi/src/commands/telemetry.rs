//! Host-app performance telemetry commands.

use std::time::Duration;

use crate::Marmot;
use crate::conversions::{HostPerformanceOperationFfi, HostPerformanceOutcomeFfi};

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
}
