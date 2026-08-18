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
    pub account_worker_readiness: AppPerformanceOperationSnapshotFfi,
    pub account_session_open: AppPerformanceOperationSnapshotFfi,
    pub account_group_hydration: AppPerformanceOperationSnapshotFfi,
    pub account_profile_load: AppPerformanceOperationSnapshotFfi,
    pub account_group_read_snapshot: AppPerformanceOperationSnapshotFfi,
    pub account_transport_activation: AppPerformanceOperationSnapshotFfi,
    pub account_subscription_registration: AppPerformanceOperationSnapshotFfi,
    pub account_catch_up: AppPerformanceOperationSnapshotFfi,
    pub account_sync: AppPerformanceOperationSnapshotFfi,
    pub account_setup_advisory_step: AppPerformanceOperationSnapshotFfi,
    pub account_bootstrap_relay_and_follow_publish: AppPerformanceOperationSnapshotFfi,
    pub account_default_profile_publish: AppPerformanceOperationSnapshotFfi,
    pub account_initial_key_package_publish: AppPerformanceOperationSnapshotFfi,
    /// Overlap between initial KeyPackage publication and initial sync. A
    /// successful zero-duration sample means publication completed before
    /// sync began; it is not a missing duration sample.
    pub account_initial_sync_overlap: AppPerformanceOperationSnapshotFfi,
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
    pub group_invite_welcome_publish: AppPerformanceOperationSnapshotFfi,
    pub group_invite_post_mutation_catch_up: AppPerformanceOperationSnapshotFfi,
    pub group_promote_admin: AppPerformanceOperationSnapshotFfi,
    pub group_details_read: AppPerformanceOperationSnapshotFfi,
    pub chat_list_row_read: AppPerformanceOperationSnapshotFfi,
    pub existing_direct_conversation_read: AppPerformanceOperationSnapshotFfi,
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
        // Destructure the source with no `..` so a new
        // `AppPerformanceSnapshot` field fails compilation here — not just
        // when the destination record is edited — until the FFI surface is
        // reviewed and grows the same field in lockstep.
        let marmot_app::AppPerformanceSnapshot {
            app_start,
            directory_subscription_sync,
            account_reconcile,
            account_open,
            account_worker_readiness,
            account_session_open,
            account_group_hydration,
            account_profile_load,
            account_group_read_snapshot,
            account_transport_activation,
            account_subscription_registration,
            account_catch_up,
            account_sync,
            account_setup_advisory_step,
            account_bootstrap_relay_and_follow_publish,
            account_default_profile_publish,
            account_initial_key_package_publish,
            account_initial_sync_overlap,
            sqlcipher_migration_probe_runs,
            sqlcipher_migration_probe_skips,
            outbound_message_send,
            group_create_queue_wait,
            group_create_key_package_lookup,
            group_create_image_upload,
            group_create_mls_prepare_persist,
            group_create_welcome_publish,
            group_create_local_projection_save,
            group_create_subscription_refresh,
            group_create_post_mutation_catch_up,
            group_create_total_caller_latency,
            group_invite_members,
            group_invite_key_package_lookup,
            group_invite_routing_refresh,
            group_invite_pre_send_sync,
            group_invite_engine_publish,
            group_invite_local_refresh,
            group_invite_notification_trigger,
            group_invite_welcome_publish,
            group_invite_post_mutation_catch_up,
            group_promote_admin,
            group_details_read,
            chat_list_row_read,
            existing_direct_conversation_read,
            group_mls_state_read,
            group_roster_read,
            group_accept_invite,
            media_upload,
            media_download,
            host_splash_ready,
            host_foreground_local_ready,
        } = value;
        Self {
            app_start: app_start.into(),
            directory_subscription_sync: directory_subscription_sync.into(),
            account_reconcile: account_reconcile.into(),
            account_open: account_open.into(),
            account_worker_readiness: account_worker_readiness.into(),
            account_session_open: account_session_open.into(),
            account_group_hydration: account_group_hydration.into(),
            account_profile_load: account_profile_load.into(),
            account_group_read_snapshot: account_group_read_snapshot.into(),
            account_transport_activation: account_transport_activation.into(),
            account_subscription_registration: account_subscription_registration.into(),
            account_catch_up: account_catch_up.into(),
            account_sync: account_sync.into(),
            account_setup_advisory_step: account_setup_advisory_step.into(),
            account_bootstrap_relay_and_follow_publish: account_bootstrap_relay_and_follow_publish
                .into(),
            account_default_profile_publish: account_default_profile_publish.into(),
            account_initial_key_package_publish: account_initial_key_package_publish.into(),
            account_initial_sync_overlap: account_initial_sync_overlap.into(),
            sqlcipher_migration_probe_runs,
            sqlcipher_migration_probe_skips,
            outbound_message_send: outbound_message_send.into(),
            group_create_queue_wait: group_create_queue_wait.into(),
            group_create_key_package_lookup: group_create_key_package_lookup.into(),
            group_create_image_upload: group_create_image_upload.into(),
            group_create_mls_prepare_persist: group_create_mls_prepare_persist.into(),
            group_create_welcome_publish: group_create_welcome_publish.into(),
            group_create_local_projection_save: group_create_local_projection_save.into(),
            group_create_subscription_refresh: group_create_subscription_refresh.into(),
            group_create_post_mutation_catch_up: group_create_post_mutation_catch_up.into(),
            group_create_total_caller_latency: group_create_total_caller_latency.into(),
            group_invite_members: group_invite_members.into(),
            group_invite_key_package_lookup: group_invite_key_package_lookup.into(),
            group_invite_routing_refresh: group_invite_routing_refresh.into(),
            group_invite_pre_send_sync: group_invite_pre_send_sync.into(),
            group_invite_engine_publish: group_invite_engine_publish.into(),
            group_invite_local_refresh: group_invite_local_refresh.into(),
            group_invite_notification_trigger: group_invite_notification_trigger.into(),
            group_invite_welcome_publish: group_invite_welcome_publish.into(),
            group_invite_post_mutation_catch_up: group_invite_post_mutation_catch_up.into(),
            group_promote_admin: group_promote_admin.into(),
            group_details_read: group_details_read.into(),
            chat_list_row_read: chat_list_row_read.into(),
            existing_direct_conversation_read: existing_direct_conversation_read.into(),
            group_mls_state_read: group_mls_state_read.into(),
            group_roster_read: group_roster_read.into(),
            group_accept_invite: group_accept_invite.into(),
            media_upload: media_upload.into(),
            media_download: media_download.into(),
            host_splash_ready: host_splash_ready.into(),
            host_foreground_local_ready: host_foreground_local_ready.into(),
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
        assert_eq!(ffi.account_worker_readiness.attempts, 0);
        assert_eq!(ffi.account_bootstrap_relay_and_follow_publish.attempts, 0);
        assert_eq!(ffi.account_default_profile_publish.attempts, 0);
        assert_eq!(ffi.account_initial_key_package_publish.attempts, 0);
        assert_eq!(ffi.account_initial_sync_overlap.attempts, 0);
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
