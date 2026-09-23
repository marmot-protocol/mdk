//! C mirrors of the app-performance telemetry conversions.
//!
//! Every counter here is an aggregate: no account, group, relay, or path
//! information crosses this surface.

use marmot_uniffi::conversions::{
    AppPerformanceOperationSnapshotFfi, AppPerformanceSnapshotFfi, DurationHistogramBucketFfi,
    DurationHistogramSnapshotFfi, HostPerformanceOperationFfi, HostPerformanceOutcomeFfi,
    RuntimePerformanceSnapshotFfi,
};

use crate::macros::{c_enum, c_mirror};

c_enum! {
    /// Host-side operation a UI can time and report back.
    MarmotHostPerformanceOperation from HostPerformanceOperationFfi {
        SplashReady,
        ForegroundLocalReady,
        OutboundMessageVisible,
        InboundMessageVisible,
        ConversationLocalVisible,
        ConversationComposerReady,
        LinuxStartupBeforeVault,
        LinuxStartupAfterVault,
        WindowInit,
        FontsInit,
        RuntimeInit,
        AccountLoad,
        AccountSwitch,
        FrameUpdate,
        FrameLayout,
        FrameDraw,
        FramePresent,
        LinuxFramePostPresent,
        LinuxFrameUntilPresent,
        LinuxFrameIdleWait,
        ChatListLoad,
        ContactsLoad,
        ArchivedChatListLoad,
        ProfileLoad,
        ProfileRead,
        TimelineOpen,
        TimelinePage,
        TimelineHandoff,
        TimelineApply,
        MessageSend,
        MessageSearch,
        ConversationSearch,
        MediaQueueWait,
        MediaPrepare,
        MediaLoad,
        MediaCacheRead,
        MediaDecode,
        MediaApply,
        LinuxVaultDeriveKey,
        LinuxVaultOpen,
        LinuxVaultCreate,
        LinuxVaultPersist,
        SettingsSave,
    }
}

impl From<MarmotHostPerformanceOperation> for HostPerformanceOperationFfi {
    fn from(value: MarmotHostPerformanceOperation) -> Self {
        match value {
            MarmotHostPerformanceOperation::OutboundMessageVisible => Self::OutboundMessageVisible,
            MarmotHostPerformanceOperation::InboundMessageVisible => Self::InboundMessageVisible,
            MarmotHostPerformanceOperation::SplashReady => Self::SplashReady,
            MarmotHostPerformanceOperation::ConversationComposerReady => {
                Self::ConversationComposerReady
            }
            MarmotHostPerformanceOperation::ConversationLocalVisible => {
                Self::ConversationLocalVisible
            }
            MarmotHostPerformanceOperation::ForegroundLocalReady => Self::ForegroundLocalReady,
            MarmotHostPerformanceOperation::LinuxStartupBeforeVault => {
                Self::LinuxStartupBeforeVault
            }
            MarmotHostPerformanceOperation::LinuxStartupAfterVault => Self::LinuxStartupAfterVault,
            MarmotHostPerformanceOperation::WindowInit => Self::WindowInit,
            MarmotHostPerformanceOperation::FontsInit => Self::FontsInit,
            MarmotHostPerformanceOperation::RuntimeInit => Self::RuntimeInit,
            MarmotHostPerformanceOperation::AccountLoad => Self::AccountLoad,
            MarmotHostPerformanceOperation::AccountSwitch => Self::AccountSwitch,
            MarmotHostPerformanceOperation::FrameUpdate => Self::FrameUpdate,
            MarmotHostPerformanceOperation::FrameLayout => Self::FrameLayout,
            MarmotHostPerformanceOperation::FrameDraw => Self::FrameDraw,
            MarmotHostPerformanceOperation::FramePresent => Self::FramePresent,
            MarmotHostPerformanceOperation::LinuxFramePostPresent => Self::LinuxFramePostPresent,
            MarmotHostPerformanceOperation::LinuxFrameUntilPresent => Self::LinuxFrameUntilPresent,
            MarmotHostPerformanceOperation::LinuxFrameIdleWait => Self::LinuxFrameIdleWait,
            MarmotHostPerformanceOperation::ChatListLoad => Self::ChatListLoad,
            MarmotHostPerformanceOperation::ContactsLoad => Self::ContactsLoad,
            MarmotHostPerformanceOperation::ArchivedChatListLoad => Self::ArchivedChatListLoad,
            MarmotHostPerformanceOperation::ProfileLoad => Self::ProfileLoad,
            MarmotHostPerformanceOperation::ProfileRead => Self::ProfileRead,
            MarmotHostPerformanceOperation::TimelineOpen => Self::TimelineOpen,
            MarmotHostPerformanceOperation::TimelinePage => Self::TimelinePage,
            MarmotHostPerformanceOperation::TimelineHandoff => Self::TimelineHandoff,
            MarmotHostPerformanceOperation::TimelineApply => Self::TimelineApply,
            MarmotHostPerformanceOperation::MessageSend => Self::MessageSend,
            MarmotHostPerformanceOperation::MessageSearch => Self::MessageSearch,
            MarmotHostPerformanceOperation::ConversationSearch => Self::ConversationSearch,
            MarmotHostPerformanceOperation::MediaQueueWait => Self::MediaQueueWait,
            MarmotHostPerformanceOperation::MediaPrepare => Self::MediaPrepare,
            MarmotHostPerformanceOperation::MediaLoad => Self::MediaLoad,
            MarmotHostPerformanceOperation::MediaCacheRead => Self::MediaCacheRead,
            MarmotHostPerformanceOperation::MediaDecode => Self::MediaDecode,
            MarmotHostPerformanceOperation::MediaApply => Self::MediaApply,
            MarmotHostPerformanceOperation::LinuxVaultDeriveKey => Self::LinuxVaultDeriveKey,
            MarmotHostPerformanceOperation::LinuxVaultOpen => Self::LinuxVaultOpen,
            MarmotHostPerformanceOperation::LinuxVaultCreate => Self::LinuxVaultCreate,
            MarmotHostPerformanceOperation::LinuxVaultPersist => Self::LinuxVaultPersist,
            MarmotHostPerformanceOperation::SettingsSave => Self::SettingsSave,
        }
    }
}

c_enum! {
    /// How a reported host operation ended.
    MarmotHostPerformanceOutcome from HostPerformanceOutcomeFfi {
        Success,
        Failure,
        Cancelled,
        Timeout,
        Unavailable,
    }
}

impl From<MarmotHostPerformanceOutcome> for HostPerformanceOutcomeFfi {
    fn from(value: MarmotHostPerformanceOutcome) -> Self {
        match value {
            MarmotHostPerformanceOutcome::Success => Self::Success,
            MarmotHostPerformanceOutcome::Failure => Self::Failure,
            MarmotHostPerformanceOutcome::Unavailable => Self::Unavailable,
            MarmotHostPerformanceOutcome::Timeout => Self::Timeout,
            MarmotHostPerformanceOutcome::Cancelled => Self::Cancelled,
        }
    }
}

c_mirror! {
    /// One duration-histogram bucket.
    MarmotDurationHistogramBucket from DurationHistogramBucketFfi {
        copy upper_bound_ms: u64,
        copy count: u64,
    }
}

c_mirror! {
    /// Duration distribution for one operation.
    MarmotDurationHistogramSnapshot from DurationHistogramSnapshotFfi {
        vec buckets/buckets_len: MarmotDurationHistogramBucket,
        /// Samples past the last bucket's upper bound.
        copy overflow_count: u64,
        copy sum_ms: u64,
    }
}

c_mirror! {
    /// Attempt/success/failure counts plus timings for one operation.
    MarmotAppPerformanceOperationSnapshot from AppPerformanceOperationSnapshotFfi {
        copy attempts: u64,
        copy successes: u64,
        copy failures: u64,
        rec duration_ms: MarmotDurationHistogramSnapshot,
    }
}

c_mirror! {
    /// Bounded runtime timings and unfinished operation counts.
    MarmotRuntimePerformanceSnapshot from RuntimePerformanceSnapshotFfi {
        str operation,
        copy started: u64,
        copy completed: u64,
        copy successes: u64,
        copy failures: u64,
        copy cancelled: u64,
        copy timeouts: u64,
        copy not_ready: u64,
        copy in_flight: u64,
        copy oldest_tracked_in_flight_ms: u64,
        copy untracked_in_flight: u64,
        rec duration_ms: MarmotDurationHistogramSnapshot,
    }
}

c_mirror! {
    /// Process-wide performance counters. Free with
    /// `marmot_app_performance_snapshot_free`.
    MarmotAppPerformanceSnapshot from AppPerformanceSnapshotFfi,
    free marmot_app_performance_snapshot_free {
        rec app_start: MarmotAppPerformanceOperationSnapshot,
        rec directory_subscription_sync: MarmotAppPerformanceOperationSnapshot,
        rec account_reconcile: MarmotAppPerformanceOperationSnapshot,
        rec account_open: MarmotAppPerformanceOperationSnapshot,
        rec account_worker_readiness: MarmotAppPerformanceOperationSnapshot,
        rec account_session_open: MarmotAppPerformanceOperationSnapshot,
        rec account_group_hydration: MarmotAppPerformanceOperationSnapshot,
        rec account_profile_load: MarmotAppPerformanceOperationSnapshot,
        rec account_group_read_snapshot: MarmotAppPerformanceOperationSnapshot,
        rec account_transport_activation: MarmotAppPerformanceOperationSnapshot,
        rec account_subscription_registration: MarmotAppPerformanceOperationSnapshot,
        rec account_catch_up: MarmotAppPerformanceOperationSnapshot,
        rec account_sync: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_advisory_step: MarmotAppPerformanceOperationSnapshot,
        rec account_bootstrap_relay_and_follow_publish: MarmotAppPerformanceOperationSnapshot,
        rec account_default_profile_publish: MarmotAppPerformanceOperationSnapshot,
        rec account_initial_key_package_publish: MarmotAppPerformanceOperationSnapshot,
        /// Overlap between initial KeyPackage publication and initial
        /// sync. A successful zero-duration sample means publication
        /// finished before sync began; it is not a missing sample.
        rec account_initial_sync_overlap: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_identity_local: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_storage_local: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_profile_local: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_key_package_local: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_local_ready_handoff: MarmotAppPerformanceOperationSnapshot,
        rec account_setup_network_ready: MarmotAppPerformanceOperationSnapshot,
        /// Interrupted-migration recovery probes since process start.
        copy sqlcipher_migration_probe_runs: u64,
        /// Existing-database opens that skipped the probe via a cached
        /// verdict since process start.
        copy sqlcipher_migration_probe_skips: u64,
        rec inbound_delivery_projection: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_send: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_queue_wait: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_local_projection: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_local_accept: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_publish: MarmotAppPerformanceOperationSnapshot,
        rec outbound_message_response: MarmotAppPerformanceOperationSnapshot,
        rec host_outbound_message_visible: MarmotAppPerformanceOperationSnapshot,
        rec host_inbound_message_visible: MarmotAppPerformanceOperationSnapshot,

        rec group_create_queue_wait: MarmotAppPerformanceOperationSnapshot,
        rec group_create_key_package_lookup: MarmotAppPerformanceOperationSnapshot,
        rec group_member_key_package_prewarm: MarmotAppPerformanceOperationSnapshot,
        rec group_create_key_package_cache_reuse: MarmotAppPerformanceOperationSnapshot,
        rec group_create_key_package_network_resolution: MarmotAppPerformanceOperationSnapshot,
        rec group_create_image_preprocess: MarmotAppPerformanceOperationSnapshot,
        rec group_create_image_upload: MarmotAppPerformanceOperationSnapshot,
        rec group_create_mls_prepare_persist: MarmotAppPerformanceOperationSnapshot,
        rec group_create_pending_welcome_index: MarmotAppPerformanceOperationSnapshot,
        rec group_create_welcome_publish: MarmotAppPerformanceOperationSnapshot,
        rec group_create_local_projection_save: MarmotAppPerformanceOperationSnapshot,
        rec group_create_response_handoff: MarmotAppPerformanceOperationSnapshot,
        rec group_create_subscription_refresh: MarmotAppPerformanceOperationSnapshot,
        rec group_create_post_mutation_catch_up: MarmotAppPerformanceOperationSnapshot,
        rec group_create_total_caller_latency: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_members: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_key_package_lookup: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_routing_refresh: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_pre_send_sync: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_engine_publish: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_local_refresh: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_notification_trigger: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_welcome_publish: MarmotAppPerformanceOperationSnapshot,
        rec group_invite_post_mutation_catch_up: MarmotAppPerformanceOperationSnapshot,
        rec group_promote_admin: MarmotAppPerformanceOperationSnapshot,
        rec group_details_read: MarmotAppPerformanceOperationSnapshot,
        rec group_conversation_snapshot_read: MarmotAppPerformanceOperationSnapshot,
        rec chat_list_row_read: MarmotAppPerformanceOperationSnapshot,
        rec existing_direct_conversation_read: MarmotAppPerformanceOperationSnapshot,
        rec group_mls_state_read: MarmotAppPerformanceOperationSnapshot,
        rec group_roster_read: MarmotAppPerformanceOperationSnapshot,
        rec group_accept_invite: MarmotAppPerformanceOperationSnapshot,
        rec media_upload: MarmotAppPerformanceOperationSnapshot,
        rec media_download: MarmotAppPerformanceOperationSnapshot,
        rec media_download_queue_wait: MarmotAppPerformanceOperationSnapshot,
        rec media_download_preparation: MarmotAppPerformanceOperationSnapshot,
        rec media_download_host_setup: MarmotAppPerformanceOperationSnapshot,
        rec media_download_response_headers: MarmotAppPerformanceOperationSnapshot,
        rec media_download_first_byte: MarmotAppPerformanceOperationSnapshot,
        rec media_download_body_transfer: MarmotAppPerformanceOperationSnapshot,
        rec media_download_locator_failover: MarmotAppPerformanceOperationSnapshot,
        rec media_download_ciphertext_verify: MarmotAppPerformanceOperationSnapshot,
        rec media_download_decrypt: MarmotAppPerformanceOperationSnapshot,
        rec media_download_plaintext_verify: MarmotAppPerformanceOperationSnapshot,
        rec host_splash_ready: MarmotAppPerformanceOperationSnapshot,
        rec host_foreground_local_ready: MarmotAppPerformanceOperationSnapshot,
        vec runtime_operations/runtime_operations_len: MarmotRuntimePerformanceSnapshot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::CFree;

    #[test]
    fn runtime_snapshot_deep_free_reclaims_name_and_histogram() {
        let _guard = crate::memory::audit::test_lock();
        #[cfg(feature = "alloc-audit")]
        let before = crate::memory::audit::live_allocations();
        let mut mirror: MarmotRuntimePerformanceSnapshot = RuntimePerformanceSnapshotFfi {
            operation: "conversation_open".into(),
            started: 3,
            completed: 2,
            successes: 1,
            failures: 0,
            cancelled: 1,
            timeouts: 0,
            not_ready: 0,
            in_flight: 1,
            oldest_tracked_in_flight_ms: 500,
            untracked_in_flight: 0,
            duration_ms: DurationHistogramSnapshotFfi {
                buckets: vec![DurationHistogramBucketFfi {
                    upper_bound_ms: 50,
                    count: 2,
                }],
                overflow_count: 0,
                sum_ms: 100,
            },
        }
        .into();
        assert_eq!(mirror.in_flight, 1);
        assert_eq!(mirror.duration_ms.buckets_len, 1);
        unsafe {
            mirror.free_in_place();
        }
        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), before);
    }
}
