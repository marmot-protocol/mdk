//! Host-app performance telemetry value types.

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostPerformanceOperationFfi {
    SplashReady,
    ForegroundLocalReady,
}

/// One fixed-bucket duration histogram bucket.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DurationHistogramBucketFfi {
    /// Inclusive upper bound of the bucket, in milliseconds.
    pub upper_bound_ms: u64,
    /// Samples whose duration fell in this bucket.
    pub count: u64,
}

/// Aggregate duration histogram: counts, bounds, and a saturating
/// millisecond sum only.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DurationHistogramSnapshotFfi {
    /// Buckets ordered by ascending upper bound.
    pub buckets: Vec<DurationHistogramBucketFfi>,
    /// Samples whose duration exceeded the largest bucket bound.
    pub overflow_count: u64,
    /// Saturating sum of all observed durations, in milliseconds.
    pub sum_ms: u64,
}

/// Cumulative counters and duration histogram for one reviewed operation.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AppPerformanceOperationSnapshotFfi {
    /// Operation attempts since process start.
    pub attempts: u64,
    /// Successful operations since process start.
    pub successes: u64,
    /// Failed operations since process start.
    pub failures: u64,
    /// Duration histogram in local monotonic milliseconds.
    pub duration_ms: DurationHistogramSnapshotFfi,
}

impl From<marmot_app::AppPerformanceOperationSnapshot> for AppPerformanceOperationSnapshotFfi {
    fn from(value: marmot_app::AppPerformanceOperationSnapshot) -> Self {
        Self {
            attempts: value.attempts,
            successes: value.successes,
            failures: value.failures,
            duration_ms: DurationHistogramSnapshotFfi {
                buckets: value
                    .duration_ms
                    .buckets
                    .iter()
                    .map(|bucket| DurationHistogramBucketFfi {
                        upper_bound_ms: bucket.upper_bound_ms,
                        count: bucket.count,
                    })
                    .collect(),
                overflow_count: value.duration_ms.overflow_count,
                sum_ms: value.duration_ms.sum_ms,
            },
        }
    }
}

/// Process-wide app-performance snapshot for host debug/diagnostics surfaces.
///
/// Aggregate counters and fixed-bucket histograms per reviewed operation only:
/// no account, group, message, relay, URL, pubkey, payload, or key material.
///
/// The field-per-operation layout is deliberate: it mirrors
/// `marmot_app::AppPerformanceSnapshot` exactly, so adding a phase to the app
/// telemetry fails this conversion's exhaustive struct literal until the FFI
/// surface is reviewed and updated in lockstep.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct AppPerformanceSnapshotFfi {
    pub app_start: AppPerformanceOperationSnapshotFfi,
    pub directory_subscription_sync: AppPerformanceOperationSnapshotFfi,
    pub account_reconcile: AppPerformanceOperationSnapshotFfi,
    pub account_open: AppPerformanceOperationSnapshotFfi,
    pub account_session_open: AppPerformanceOperationSnapshotFfi,
    pub account_group_hydration: AppPerformanceOperationSnapshotFfi,
    pub account_profile_load: AppPerformanceOperationSnapshotFfi,
    pub account_group_read_snapshot: AppPerformanceOperationSnapshotFfi,
    pub account_transport_activation: AppPerformanceOperationSnapshotFfi,
    pub account_subscription_registration: AppPerformanceOperationSnapshotFfi,
    pub account_catch_up: AppPerformanceOperationSnapshotFfi,
    pub account_sync: AppPerformanceOperationSnapshotFfi,
    pub account_setup_advisory_step: AppPerformanceOperationSnapshotFfi,
    /// Interrupted-migration recovery probes executed since process start.
    /// Process-wide aggregate: no account, path, or key information.
    pub sqlcipher_migration_probe_runs: u64,
    /// Existing-database opens that skipped the recovery probe via a cached
    /// verdict since process start.
    pub sqlcipher_migration_probe_skips: u64,
    pub outbound_message_send: AppPerformanceOperationSnapshotFfi,
    pub group_create_queue_wait: AppPerformanceOperationSnapshotFfi,
    pub group_create_key_package_lookup: AppPerformanceOperationSnapshotFfi,
    pub group_create_image_upload: AppPerformanceOperationSnapshotFfi,
    pub group_create_mls_prepare_persist: AppPerformanceOperationSnapshotFfi,
    pub group_create_welcome_publish: AppPerformanceOperationSnapshotFfi,
    pub group_create_local_projection_save: AppPerformanceOperationSnapshotFfi,
    pub group_create_subscription_refresh: AppPerformanceOperationSnapshotFfi,
    pub group_create_post_mutation_catch_up: AppPerformanceOperationSnapshotFfi,
    pub group_create_total_caller_latency: AppPerformanceOperationSnapshotFfi,
    pub group_invite_members: AppPerformanceOperationSnapshotFfi,
    pub group_invite_key_package_lookup: AppPerformanceOperationSnapshotFfi,
    pub group_invite_routing_refresh: AppPerformanceOperationSnapshotFfi,
    pub group_invite_pre_send_sync: AppPerformanceOperationSnapshotFfi,
    pub group_invite_engine_publish: AppPerformanceOperationSnapshotFfi,
    pub group_invite_local_refresh: AppPerformanceOperationSnapshotFfi,
    pub group_invite_notification_trigger: AppPerformanceOperationSnapshotFfi,
    pub group_invite_post_mutation_catch_up: AppPerformanceOperationSnapshotFfi,
    pub group_promote_admin: AppPerformanceOperationSnapshotFfi,
    pub group_details_read: AppPerformanceOperationSnapshotFfi,
    pub group_mls_state_read: AppPerformanceOperationSnapshotFfi,
    pub group_roster_read: AppPerformanceOperationSnapshotFfi,
    pub group_accept_invite: AppPerformanceOperationSnapshotFfi,
    pub media_upload: AppPerformanceOperationSnapshotFfi,
    pub media_download: AppPerformanceOperationSnapshotFfi,
    pub host_splash_ready: AppPerformanceOperationSnapshotFfi,
    pub host_foreground_local_ready: AppPerformanceOperationSnapshotFfi,
}

impl From<marmot_app::AppPerformanceSnapshot> for AppPerformanceSnapshotFfi {
    fn from(value: marmot_app::AppPerformanceSnapshot) -> Self {
        // Deliberately exhaustive: a new `AppPerformanceSnapshot` field must
        // fail this literal until the FFI record grows the same field.
        Self {
            app_start: value.app_start.into(),
            directory_subscription_sync: value.directory_subscription_sync.into(),
            account_reconcile: value.account_reconcile.into(),
            account_open: value.account_open.into(),
            account_session_open: value.account_session_open.into(),
            account_group_hydration: value.account_group_hydration.into(),
            account_profile_load: value.account_profile_load.into(),
            account_group_read_snapshot: value.account_group_read_snapshot.into(),
            account_transport_activation: value.account_transport_activation.into(),
            account_subscription_registration: value.account_subscription_registration.into(),
            account_catch_up: value.account_catch_up.into(),
            account_sync: value.account_sync.into(),
            account_setup_advisory_step: value.account_setup_advisory_step.into(),
            sqlcipher_migration_probe_runs: value.sqlcipher_migration_probe_runs,
            sqlcipher_migration_probe_skips: value.sqlcipher_migration_probe_skips,
            outbound_message_send: value.outbound_message_send.into(),
            group_create_queue_wait: value.group_create_queue_wait.into(),
            group_create_key_package_lookup: value.group_create_key_package_lookup.into(),
            group_create_image_upload: value.group_create_image_upload.into(),
            group_create_mls_prepare_persist: value.group_create_mls_prepare_persist.into(),
            group_create_welcome_publish: value.group_create_welcome_publish.into(),
            group_create_local_projection_save: value.group_create_local_projection_save.into(),
            group_create_subscription_refresh: value.group_create_subscription_refresh.into(),
            group_create_post_mutation_catch_up: value.group_create_post_mutation_catch_up.into(),
            group_create_total_caller_latency: value.group_create_total_caller_latency.into(),
            group_invite_members: value.group_invite_members.into(),
            group_invite_key_package_lookup: value.group_invite_key_package_lookup.into(),
            group_invite_routing_refresh: value.group_invite_routing_refresh.into(),
            group_invite_pre_send_sync: value.group_invite_pre_send_sync.into(),
            group_invite_engine_publish: value.group_invite_engine_publish.into(),
            group_invite_local_refresh: value.group_invite_local_refresh.into(),
            group_invite_notification_trigger: value.group_invite_notification_trigger.into(),
            group_invite_post_mutation_catch_up: value.group_invite_post_mutation_catch_up.into(),
            group_promote_admin: value.group_promote_admin.into(),
            group_details_read: value.group_details_read.into(),
            group_mls_state_read: value.group_mls_state_read.into(),
            group_roster_read: value.group_roster_read.into(),
            group_accept_invite: value.group_accept_invite.into(),
            media_upload: value.media_upload.into(),
            media_download: value.media_download.into(),
            host_splash_ready: value.host_splash_ready.into(),
            host_foreground_local_ready: value.host_foreground_local_ready.into(),
        }
    }
}

impl From<HostPerformanceOperationFfi> for marmot_app::HostPerformanceOperation {
    fn from(value: HostPerformanceOperationFfi) -> Self {
        match value {
            HostPerformanceOperationFfi::SplashReady => Self::SplashReady,
            HostPerformanceOperationFfi::ForegroundLocalReady => Self::ForegroundLocalReady,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum HostPerformanceOutcomeFfi {
    Success,
    Failure,
}

impl From<HostPerformanceOutcomeFfi> for marmot_app::HostPerformanceOutcome {
    fn from(value: HostPerformanceOutcomeFfi) -> Self {
        match value {
            HostPerformanceOutcomeFfi::Success => Self::Success,
            HostPerformanceOutcomeFfi::Failure => Self::Failure,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn app_performance_snapshot_ffi_mirrors_counts_and_histogram_buckets() {
        let telemetry = marmot_app::AppPerformanceTelemetry::default();
        telemetry.record_host_performance(
            marmot_app::HostPerformanceOperation::SplashReady,
            Duration::from_millis(100),
            marmot_app::HostPerformanceOutcome::Success,
        );
        telemetry.record_host_performance(
            marmot_app::HostPerformanceOperation::ForegroundLocalReady,
            Duration::from_millis(7_500),
            marmot_app::HostPerformanceOutcome::Failure,
        );
        let snapshot = telemetry.snapshot();

        let ffi = AppPerformanceSnapshotFfi::from(snapshot.clone());

        assert_eq!(ffi.host_splash_ready.attempts, 1);
        assert_eq!(ffi.host_splash_ready.successes, 1);
        assert_eq!(ffi.host_splash_ready.failures, 0);
        assert_eq!(ffi.host_splash_ready.duration_ms.sum_ms, 100);
        assert!(
            ffi.host_splash_ready
                .duration_ms
                .buckets
                .iter()
                .any(|bucket| bucket.upper_bound_ms == 100 && bucket.count == 1)
        );
        assert_eq!(ffi.host_foreground_local_ready.attempts, 1);
        assert_eq!(ffi.host_foreground_local_ready.failures, 1);
        assert_eq!(ffi.host_foreground_local_ready.duration_ms.sum_ms, 7_500);
        // Untouched operations cross the boundary as zeros, not omissions.
        assert_eq!(ffi.group_accept_invite.attempts, 0);
        assert_eq!(ffi.group_create_total_caller_latency.attempts, 0);
        assert_eq!(ffi.group_roster_read.attempts, 0);
        // Process-wide counters mirror the source snapshot exactly.
        assert_eq!(
            ffi.sqlcipher_migration_probe_runs,
            snapshot.sqlcipher_migration_probe_runs
        );
        assert_eq!(
            ffi.sqlcipher_migration_probe_skips,
            snapshot.sqlcipher_migration_probe_skips
        );
    }

    #[test]
    fn host_performance_enums_preserve_every_variant() {
        assert!(matches!(
            marmot_app::HostPerformanceOperation::from(
                HostPerformanceOperationFfi::ForegroundLocalReady
            ),
            marmot_app::HostPerformanceOperation::ForegroundLocalReady
        ));
        assert!(matches!(
            marmot_app::HostPerformanceOutcome::from(HostPerformanceOutcomeFfi::Failure),
            marmot_app::HostPerformanceOutcome::Failure
        ));
    }
}
