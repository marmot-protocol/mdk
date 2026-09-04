//! Aggregate app-performance telemetry for the opt-in export path.
//!
//! This module intentionally mirrors the relay telemetry privacy model: samples
//! are cumulative counters and fixed-bucket millisecond histograms only. There
//! are no fields for account, group, message, relay, URL, pubkey, payload, or
//! key material.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    AccountWorkerReadiness,
    AccountSessionOpen,
    AccountGroupHydration,
    AccountProfileLoad,
    AccountGroupReadSnapshot,
    AccountTransportActivation,
    AccountSubscriptionRegistration,
    AccountCatchUp,
    AccountSync,
    AccountSetupAdvisoryStep,
    AccountBootstrapRelayAndFollowPublish,
    AccountDefaultProfilePublish,
    AccountInitialKeyPackagePublish,
    /// Time during which the initial KeyPackage publication and initial sync
    /// overlap. The setup-priority path deliberately serializes them, so its
    /// successful sample is zero; a non-zero sample would mean a future path
    /// allowed both network phases to run concurrently.
    AccountInitialSyncOverlap,
    AccountSetupIdentityLocal,
    AccountSetupStorageLocal,
    AccountSetupProfileLocal,
    AccountSetupKeyPackageLocal,
    AccountSetupLocalReadyHandoff,
    AccountSetupNetworkReady,
    OutboundMessageSend,
    GroupCreateQueueWait,
    GroupCreateKeyPackageLookup,
    GroupMemberKeyPackagePrewarm,
    GroupCreateKeyPackageCacheReuse,
    GroupCreateKeyPackageNetworkResolution,
    GroupCreateImagePreprocess,
    GroupCreateImageUpload,
    GroupCreateMlsPreparePersist,
    GroupCreatePendingWelcomeIndex,
    GroupCreateWelcomePublish,
    GroupCreateLocalProjectionSave,
    GroupCreateResponseHandoff,
    GroupCreateSubscriptionRefresh,
    GroupCreatePostMutationCatchUp,
    GroupCreateTotalCallerLatency,
    GroupInviteMembers,
    GroupInviteKeyPackageLookup,
    GroupInviteRoutingRefresh,
    GroupInvitePreSendSync,
    GroupInviteEnginePublish,
    GroupInviteLocalRefresh,
    GroupInviteNotificationTrigger,
    GroupInviteWelcomePublish,
    GroupInvitePostMutationCatchUp,
    GroupPromoteAdmin,
    GroupDetailsRead,
    GroupConversationSnapshotRead,
    ChatListRowRead,
    ExistingDirectConversationRead,
    GroupMlsStateRead,
    GroupRosterRead,
    GroupAcceptInvite,
    MediaUpload,
    MediaDownload,
    MediaDownloadQueueWait,
    MediaDownloadPreparation,
    MediaDownloadHostSetup,
    MediaDownloadResponseHeaders,
    MediaDownloadFirstByte,
    MediaDownloadBodyTransfer,
    MediaDownloadLocatorFailover,
    MediaDownloadCiphertextVerify,
    MediaDownloadDecrypt,
    MediaDownloadPlaintextVerify,
    HostSplashReady,
    HostForegroundLocalReady,
}

/// Host-app milestones accepted by [`AppPerformanceTelemetry::record_host_performance`].
///
/// This is deliberately a closed enum rather than a caller-supplied metric or
/// label name. Adding an operation therefore requires an MDK review and cannot
/// silently create unbounded Prometheus cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPerformanceOperation {
    SplashReady,
    ForegroundLocalReady,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPerformanceOutcome {
    Success,
    Failure,
}

/// Fixed sync/catch-up boundary at which an attempt stopped.
///
/// These values are exported verbatim as the `failure_stage` attribute. Keep
/// this enum closed: accepting caller-provided strings would make metric
/// cardinality and privacy impossible to review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncFailureStage {
    TransportActivation,
    GroupSubscriptionSync,
    RelayReceive,
    CgkaIngest,
    StatePersist,
    AccountWorker,
    Unknown,
}

impl SyncFailureStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransportActivation => "transport_activation",
            Self::GroupSubscriptionSync => "group_subscription_sync",
            Self::RelayReceive => "relay_receive",
            Self::CgkaIngest => "cgka_ingest",
            Self::StatePersist => "state_persist",
            Self::AccountWorker => "account_worker",
            Self::Unknown => "unknown",
        }
    }
}

/// Fixed broad cause for a sync/catch-up failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncErrorClass {
    Timeout,
    TransportClosed,
    RelayDirectory,
    Protocol,
    Crypto,
    Storage,
    Cancelled,
    Unknown,
}

impl SyncErrorClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::TransportClosed => "transport_closed",
            Self::RelayDirectory => "relay_directory",
            Self::Protocol => "protocol",
            Self::Crypto => "crypto",
            Self::Storage => "storage",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

/// Privacy-safe, bounded classification attached only to failed account sync
/// and catch-up counter samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SyncFailureClassification {
    pub failure_stage: SyncFailureStage,
    pub error_class: SyncErrorClass,
}

impl SyncFailureClassification {
    pub const UNKNOWN: Self = Self {
        failure_stage: SyncFailureStage::Unknown,
        error_class: SyncErrorClass::Unknown,
    };

    pub const fn new(failure_stage: SyncFailureStage, error_class: SyncErrorClass) -> Self {
        Self {
            failure_stage,
            error_class,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncFailureCount {
    pub classification: SyncFailureClassification,
    pub count: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPerformanceOperationSnapshot {
    /// Operation attempts since process start.
    pub attempts: u64,
    /// Successful operations since process start.
    pub successes: u64,
    /// Failed operations since process start.
    pub failures: u64,
    /// Bounded failure breakdown. Empty for operations other than account sync
    /// and catch-up and for snapshots written by older MDK versions.
    #[serde(default)]
    pub failure_classifications: Vec<SyncFailureCount>,
    /// Operation duration histogram in local monotonic milliseconds.
    pub duration_ms: DurationHistogramSnapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppPerformanceSnapshot {
    pub app_start: AppPerformanceOperationSnapshot,
    pub directory_subscription_sync: AppPerformanceOperationSnapshot,
    pub account_reconcile: AppPerformanceOperationSnapshot,
    pub account_open: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_worker_readiness: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_session_open: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_group_hydration: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_profile_load: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_group_read_snapshot: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_transport_activation: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_subscription_registration: AppPerformanceOperationSnapshot,
    pub account_catch_up: AppPerformanceOperationSnapshot,
    pub account_sync: AppPerformanceOperationSnapshot,
    pub account_setup_advisory_step: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_bootstrap_relay_and_follow_publish: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_default_profile_publish: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_initial_key_package_publish: AppPerformanceOperationSnapshot,
    /// Overlap between initial KeyPackage publication and initial sync. A
    /// successful zero-duration sample is the intentional setup-priority
    /// sentinel: KeyPackage publication completed before sync began.
    #[serde(default)]
    pub account_initial_sync_overlap: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_identity_local: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_storage_local: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_profile_local: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_key_package_local: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_local_ready_handoff: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub account_setup_network_ready: AppPerformanceOperationSnapshot,
    /// Interrupted-migration recovery probes executed since process start. Each
    /// probe is a full keyed SQLCipher open paying the passphrase KDF; the
    /// healthy steady state skips it via the cached v2-open verdict (mdk#1439).
    /// Process-wide aggregate: no account, path, or key information.
    #[serde(default)]
    pub sqlcipher_migration_probe_runs: u64,
    /// Existing-database opens that skipped the recovery probe via a cached
    /// v2-open verdict since process start. Each skip avoided one full
    /// passphrase KDF derivation (mdk#1439).
    #[serde(default)]
    pub sqlcipher_migration_probe_skips: u64,
    pub outbound_message_send: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_queue_wait: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_key_package_lookup: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_member_key_package_prewarm: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_key_package_cache_reuse: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_key_package_network_resolution: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_image_preprocess: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_image_upload: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_mls_prepare_persist: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_pending_welcome_index: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_welcome_publish: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_local_projection_save: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_response_handoff: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_subscription_refresh: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_post_mutation_catch_up: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_create_total_caller_latency: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_members: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_key_package_lookup: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_routing_refresh: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_pre_send_sync: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_engine_publish: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_local_refresh: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_notification_trigger: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_welcome_publish: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_invite_post_mutation_catch_up: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_promote_admin: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_details_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_conversation_snapshot_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub chat_list_row_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub existing_direct_conversation_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_mls_state_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_roster_read: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub group_accept_invite: AppPerformanceOperationSnapshot,
    pub media_upload: AppPerformanceOperationSnapshot,
    pub media_download: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_queue_wait: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_preparation: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_host_setup: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_response_headers: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_first_byte: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_body_transfer: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_locator_failover: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_ciphertext_verify: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_decrypt: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub media_download_plaintext_verify: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub host_splash_ready: AppPerformanceOperationSnapshot,
    #[serde(default)]
    pub host_foreground_local_ready: AppPerformanceOperationSnapshot,
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
    account_worker_readiness: AppPerformanceOperationTelemetry,
    account_session_open: AppPerformanceOperationTelemetry,
    account_group_hydration: AppPerformanceOperationTelemetry,
    account_profile_load: AppPerformanceOperationTelemetry,
    account_group_read_snapshot: AppPerformanceOperationTelemetry,
    account_transport_activation: AppPerformanceOperationTelemetry,
    account_subscription_registration: AppPerformanceOperationTelemetry,
    account_catch_up: AppPerformanceOperationTelemetry,
    account_sync: AppPerformanceOperationTelemetry,
    account_setup_advisory_step: AppPerformanceOperationTelemetry,
    account_bootstrap_relay_and_follow_publish: AppPerformanceOperationTelemetry,
    account_default_profile_publish: AppPerformanceOperationTelemetry,
    account_initial_key_package_publish: AppPerformanceOperationTelemetry,
    account_initial_sync_overlap: AppPerformanceOperationTelemetry,
    account_setup_identity_local: AppPerformanceOperationTelemetry,
    account_setup_storage_local: AppPerformanceOperationTelemetry,
    account_setup_profile_local: AppPerformanceOperationTelemetry,
    account_setup_key_package_local: AppPerformanceOperationTelemetry,
    account_setup_local_ready_handoff: AppPerformanceOperationTelemetry,
    account_setup_network_ready: AppPerformanceOperationTelemetry,
    outbound_message_send: AppPerformanceOperationTelemetry,
    group_create_queue_wait: AppPerformanceOperationTelemetry,
    group_create_key_package_lookup: AppPerformanceOperationTelemetry,
    group_member_key_package_prewarm: AppPerformanceOperationTelemetry,
    group_create_key_package_cache_reuse: AppPerformanceOperationTelemetry,
    group_create_key_package_network_resolution: AppPerformanceOperationTelemetry,
    group_create_image_preprocess: AppPerformanceOperationTelemetry,
    group_create_image_upload: AppPerformanceOperationTelemetry,
    group_create_mls_prepare_persist: AppPerformanceOperationTelemetry,
    group_create_pending_welcome_index: AppPerformanceOperationTelemetry,
    group_create_welcome_publish: AppPerformanceOperationTelemetry,
    group_create_local_projection_save: AppPerformanceOperationTelemetry,
    group_create_response_handoff: AppPerformanceOperationTelemetry,
    group_create_subscription_refresh: AppPerformanceOperationTelemetry,
    group_create_post_mutation_catch_up: AppPerformanceOperationTelemetry,
    group_create_total_caller_latency: AppPerformanceOperationTelemetry,
    group_invite_members: AppPerformanceOperationTelemetry,
    group_invite_key_package_lookup: AppPerformanceOperationTelemetry,
    group_invite_routing_refresh: AppPerformanceOperationTelemetry,
    group_invite_pre_send_sync: AppPerformanceOperationTelemetry,
    group_invite_engine_publish: AppPerformanceOperationTelemetry,
    group_invite_local_refresh: AppPerformanceOperationTelemetry,
    group_invite_notification_trigger: AppPerformanceOperationTelemetry,
    group_invite_welcome_publish: AppPerformanceOperationTelemetry,
    group_invite_post_mutation_catch_up: AppPerformanceOperationTelemetry,
    group_promote_admin: AppPerformanceOperationTelemetry,
    group_details_read: AppPerformanceOperationTelemetry,
    group_conversation_snapshot_read: AppPerformanceOperationTelemetry,
    chat_list_row_read: AppPerformanceOperationTelemetry,
    existing_direct_conversation_read: AppPerformanceOperationTelemetry,
    group_mls_state_read: AppPerformanceOperationTelemetry,
    group_roster_read: AppPerformanceOperationTelemetry,
    group_accept_invite: AppPerformanceOperationTelemetry,
    media_upload: AppPerformanceOperationTelemetry,
    media_download: AppPerformanceOperationTelemetry,
    media_download_queue_wait: AppPerformanceOperationTelemetry,
    media_download_preparation: AppPerformanceOperationTelemetry,
    media_download_host_setup: AppPerformanceOperationTelemetry,
    media_download_response_headers: AppPerformanceOperationTelemetry,
    media_download_first_byte: AppPerformanceOperationTelemetry,
    media_download_body_transfer: AppPerformanceOperationTelemetry,
    media_download_locator_failover: AppPerformanceOperationTelemetry,
    media_download_ciphertext_verify: AppPerformanceOperationTelemetry,
    media_download_decrypt: AppPerformanceOperationTelemetry,
    media_download_plaintext_verify: AppPerformanceOperationTelemetry,
    host_splash_ready: AppPerformanceOperationTelemetry,
    host_foreground_local_ready: AppPerformanceOperationTelemetry,
}

#[derive(Clone, Debug, Default)]
struct AppPerformanceOperationTelemetry {
    attempts: u64,
    successes: u64,
    failures: u64,
    failure_classifications: BTreeMap<SyncFailureClassification, u64>,
    duration_ms: DurationHistogram,
}

#[derive(Clone, Debug)]
struct DurationHistogram {
    buckets: [u64; APP_DURATION_BUCKET_BOUNDS_MS.len()],
    overflow: u64,
    sum_ms: u64,
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; APP_DURATION_BUCKET_BOUNDS_MS.len()],
            overflow: 0,
            sum_ms: 0,
        }
    }
}

impl DurationHistogram {
    fn record(&mut self, duration: Duration) {
        let delta_ms = duration.as_millis().min(u64::MAX as u128) as u64;
        self.sum_ms = self.sum_ms.saturating_add(delta_ms);
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
            sum_ms: self.sum_ms,
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

    fn record_with_failure(
        &mut self,
        duration: Duration,
        success: bool,
        failure: Option<SyncFailureClassification>,
    ) {
        self.record(duration, success);
        if !success {
            let classification = failure.unwrap_or(SyncFailureClassification::UNKNOWN);
            *self
                .failure_classifications
                .entry(classification)
                .or_default() += 1;
        }
    }

    fn snapshot(&self) -> AppPerformanceOperationSnapshot {
        AppPerformanceOperationSnapshot {
            attempts: self.attempts,
            successes: self.successes,
            failures: self.failures,
            failure_classifications: self
                .failure_classifications
                .iter()
                .map(|(classification, count)| SyncFailureCount {
                    classification: *classification,
                    count: *count,
                })
                .collect(),
            duration_ms: self.duration_ms.snapshot(),
        }
    }
}

impl AppPerformanceTelemetry {
    /// Record one closed, reviewed operation as a process-wide count and
    /// fixed-bucket duration sample without accepting dynamic attributes.
    pub(crate) fn record(
        &self,
        operation: AppPerformanceOperation,
        duration: Duration,
        success: bool,
    ) {
        if matches!(
            operation,
            AppPerformanceOperation::AccountSync | AppPerformanceOperation::AccountCatchUp
        ) {
            debug_assert!(
                false,
                "account sync/catch-up must use record_sync_result with a bounded failure classification"
            );
            return;
        }
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
            AppPerformanceOperation::AccountWorkerReadiness => {
                inner.account_worker_readiness.record(duration, success);
            }
            AppPerformanceOperation::AccountSessionOpen => {
                inner.account_session_open.record(duration, success);
            }
            AppPerformanceOperation::AccountGroupHydration => {
                inner.account_group_hydration.record(duration, success);
            }
            AppPerformanceOperation::AccountProfileLoad => {
                inner.account_profile_load.record(duration, success);
            }
            AppPerformanceOperation::AccountGroupReadSnapshot => {
                inner.account_group_read_snapshot.record(duration, success);
            }
            AppPerformanceOperation::AccountTransportActivation => {
                inner.account_transport_activation.record(duration, success);
            }
            AppPerformanceOperation::AccountSubscriptionRegistration => {
                inner
                    .account_subscription_registration
                    .record(duration, success);
            }
            AppPerformanceOperation::AccountCatchUp | AppPerformanceOperation::AccountSync => {}
            AppPerformanceOperation::AccountSetupAdvisoryStep => {
                inner.account_setup_advisory_step.record(duration, success)
            }
            AppPerformanceOperation::AccountBootstrapRelayAndFollowPublish => inner
                .account_bootstrap_relay_and_follow_publish
                .record(duration, success),
            AppPerformanceOperation::AccountDefaultProfilePublish => inner
                .account_default_profile_publish
                .record(duration, success),
            AppPerformanceOperation::AccountInitialKeyPackagePublish => inner
                .account_initial_key_package_publish
                .record(duration, success),
            AppPerformanceOperation::AccountInitialSyncOverlap => {
                inner.account_initial_sync_overlap.record(duration, success)
            }
            AppPerformanceOperation::AccountSetupIdentityLocal => {
                inner.account_setup_identity_local.record(duration, success)
            }
            AppPerformanceOperation::AccountSetupStorageLocal => {
                inner.account_setup_storage_local.record(duration, success)
            }
            AppPerformanceOperation::AccountSetupProfileLocal => {
                inner.account_setup_profile_local.record(duration, success)
            }
            AppPerformanceOperation::AccountSetupKeyPackageLocal => inner
                .account_setup_key_package_local
                .record(duration, success),
            AppPerformanceOperation::AccountSetupLocalReadyHandoff => inner
                .account_setup_local_ready_handoff
                .record(duration, success),
            AppPerformanceOperation::AccountSetupNetworkReady => {
                inner.account_setup_network_ready.record(duration, success)
            }
            AppPerformanceOperation::OutboundMessageSend => {
                inner.outbound_message_send.record(duration, success);
            }
            AppPerformanceOperation::GroupCreateQueueWait => {
                inner.group_create_queue_wait.record(duration, success);
            }
            AppPerformanceOperation::GroupCreateKeyPackageLookup => {
                inner
                    .group_create_key_package_lookup
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupMemberKeyPackagePrewarm => {
                inner
                    .group_member_key_package_prewarm
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateKeyPackageCacheReuse => {
                inner
                    .group_create_key_package_cache_reuse
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateKeyPackageNetworkResolution => {
                inner
                    .group_create_key_package_network_resolution
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateImagePreprocess => {
                inner
                    .group_create_image_preprocess
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateImageUpload => {
                inner.group_create_image_upload.record(duration, success);
            }
            AppPerformanceOperation::GroupCreateMlsPreparePersist => {
                inner
                    .group_create_mls_prepare_persist
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreatePendingWelcomeIndex => {
                inner
                    .group_create_pending_welcome_index
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateWelcomePublish => {
                inner.group_create_welcome_publish.record(duration, success);
            }
            AppPerformanceOperation::GroupCreateLocalProjectionSave => {
                inner
                    .group_create_local_projection_save
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateResponseHandoff => {
                inner
                    .group_create_response_handoff
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateSubscriptionRefresh => {
                inner
                    .group_create_subscription_refresh
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreatePostMutationCatchUp => {
                inner
                    .group_create_post_mutation_catch_up
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupCreateTotalCallerLatency => {
                inner
                    .group_create_total_caller_latency
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupInviteMembers => {
                inner.group_invite_members.record(duration, success);
            }
            AppPerformanceOperation::GroupInviteKeyPackageLookup => {
                inner
                    .group_invite_key_package_lookup
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupInviteRoutingRefresh => {
                inner.group_invite_routing_refresh.record(duration, success);
            }
            AppPerformanceOperation::GroupInvitePreSendSync => {
                inner.group_invite_pre_send_sync.record(duration, success);
            }
            AppPerformanceOperation::GroupInviteEnginePublish => {
                inner.group_invite_engine_publish.record(duration, success);
            }
            AppPerformanceOperation::GroupInviteLocalRefresh => {
                inner.group_invite_local_refresh.record(duration, success);
            }
            AppPerformanceOperation::GroupInviteNotificationTrigger => {
                inner
                    .group_invite_notification_trigger
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupInviteWelcomePublish => {
                inner.group_invite_welcome_publish.record(duration, success);
            }
            AppPerformanceOperation::GroupInvitePostMutationCatchUp => {
                inner
                    .group_invite_post_mutation_catch_up
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupPromoteAdmin => {
                inner.group_promote_admin.record(duration, success);
            }
            AppPerformanceOperation::GroupDetailsRead => {
                inner.group_details_read.record(duration, success);
            }
            AppPerformanceOperation::GroupConversationSnapshotRead => {
                inner
                    .group_conversation_snapshot_read
                    .record(duration, success);
            }
            AppPerformanceOperation::ChatListRowRead => {
                inner.chat_list_row_read.record(duration, success);
            }
            AppPerformanceOperation::ExistingDirectConversationRead => {
                inner
                    .existing_direct_conversation_read
                    .record(duration, success);
            }
            AppPerformanceOperation::GroupMlsStateRead => {
                inner.group_mls_state_read.record(duration, success);
            }
            AppPerformanceOperation::GroupRosterRead => {
                inner.group_roster_read.record(duration, success);
            }
            AppPerformanceOperation::GroupAcceptInvite => {
                inner.group_accept_invite.record(duration, success);
            }
            AppPerformanceOperation::MediaUpload => inner.media_upload.record(duration, success),
            AppPerformanceOperation::MediaDownload => {
                inner.media_download.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadQueueWait => {
                inner.media_download_queue_wait.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadPreparation => {
                inner.media_download_preparation.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadHostSetup => {
                inner.media_download_host_setup.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadResponseHeaders => {
                inner
                    .media_download_response_headers
                    .record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadFirstByte => {
                inner.media_download_first_byte.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadBodyTransfer => {
                inner.media_download_body_transfer.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadLocatorFailover => {
                inner
                    .media_download_locator_failover
                    .record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadCiphertextVerify => {
                inner
                    .media_download_ciphertext_verify
                    .record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadDecrypt => {
                inner.media_download_decrypt.record(duration, success);
            }
            AppPerformanceOperation::MediaDownloadPlaintextVerify => {
                inner
                    .media_download_plaintext_verify
                    .record(duration, success);
            }
            AppPerformanceOperation::HostSplashReady => {
                inner.host_splash_ready.record(duration, success);
            }
            AppPerformanceOperation::HostForegroundLocalReady => {
                inner.host_foreground_local_ready.record(duration, success);
            }
        }
    }

    /// Record a terminal account sync/catch-up result with its bounded failure
    /// classification. Successful samples carry no failure attributes.
    pub(crate) fn record_sync_result(
        &self,
        operation: AppPerformanceOperation,
        duration: Duration,
        failure: Option<SyncFailureClassification>,
    ) {
        debug_assert!(matches!(
            operation,
            AppPerformanceOperation::AccountSync | AppPerformanceOperation::AccountCatchUp
        ));
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let target = match operation {
            AppPerformanceOperation::AccountSync => &mut inner.account_sync,
            AppPerformanceOperation::AccountCatchUp => &mut inner.account_catch_up,
            _ => return,
        };
        target.record_with_failure(duration, failure.is_none(), failure);
    }

    /// Record one approved host-app milestone without accepting arbitrary
    /// metric names, label names, or label values.
    pub fn record_host_performance(
        &self,
        operation: HostPerformanceOperation,
        duration: Duration,
        outcome: HostPerformanceOutcome,
    ) {
        let operation = match operation {
            HostPerformanceOperation::SplashReady => AppPerformanceOperation::HostSplashReady,
            HostPerformanceOperation::ForegroundLocalReady => {
                AppPerformanceOperation::HostForegroundLocalReady
            }
        };
        self.record(
            operation,
            duration,
            matches!(outcome, HostPerformanceOutcome::Success),
        );
    }

    /// Return cumulative process-wide aggregates suitable for the opt-in
    /// telemetry and host-FFI boundaries.
    pub fn snapshot(&self) -> AppPerformanceSnapshot {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (sqlcipher_migration_probe_runs, sqlcipher_migration_probe_skips) =
            crate::sqlcipher::sqlcipher_migration_probe_counters();
        AppPerformanceSnapshot {
            app_start: inner.app_start.snapshot(),
            directory_subscription_sync: inner.directory_subscription_sync.snapshot(),
            account_reconcile: inner.account_reconcile.snapshot(),
            account_open: inner.account_open.snapshot(),
            account_worker_readiness: inner.account_worker_readiness.snapshot(),
            account_session_open: inner.account_session_open.snapshot(),
            account_group_hydration: inner.account_group_hydration.snapshot(),
            account_profile_load: inner.account_profile_load.snapshot(),
            account_group_read_snapshot: inner.account_group_read_snapshot.snapshot(),
            account_transport_activation: inner.account_transport_activation.snapshot(),
            account_subscription_registration: inner.account_subscription_registration.snapshot(),
            account_catch_up: inner.account_catch_up.snapshot(),
            account_sync: inner.account_sync.snapshot(),
            account_setup_advisory_step: inner.account_setup_advisory_step.snapshot(),
            account_bootstrap_relay_and_follow_publish: inner
                .account_bootstrap_relay_and_follow_publish
                .snapshot(),
            account_default_profile_publish: inner.account_default_profile_publish.snapshot(),
            account_initial_key_package_publish: inner
                .account_initial_key_package_publish
                .snapshot(),
            account_initial_sync_overlap: inner.account_initial_sync_overlap.snapshot(),
            account_setup_identity_local: inner.account_setup_identity_local.snapshot(),
            account_setup_storage_local: inner.account_setup_storage_local.snapshot(),
            account_setup_profile_local: inner.account_setup_profile_local.snapshot(),
            account_setup_key_package_local: inner.account_setup_key_package_local.snapshot(),
            account_setup_local_ready_handoff: inner.account_setup_local_ready_handoff.snapshot(),
            account_setup_network_ready: inner.account_setup_network_ready.snapshot(),
            sqlcipher_migration_probe_runs,
            sqlcipher_migration_probe_skips,
            outbound_message_send: inner.outbound_message_send.snapshot(),
            group_create_queue_wait: inner.group_create_queue_wait.snapshot(),
            group_create_key_package_lookup: inner.group_create_key_package_lookup.snapshot(),
            group_member_key_package_prewarm: inner.group_member_key_package_prewarm.snapshot(),
            group_create_key_package_cache_reuse: inner
                .group_create_key_package_cache_reuse
                .snapshot(),
            group_create_key_package_network_resolution: inner
                .group_create_key_package_network_resolution
                .snapshot(),
            group_create_image_preprocess: inner.group_create_image_preprocess.snapshot(),
            group_create_image_upload: inner.group_create_image_upload.snapshot(),
            group_create_mls_prepare_persist: inner.group_create_mls_prepare_persist.snapshot(),
            group_create_pending_welcome_index: inner.group_create_pending_welcome_index.snapshot(),
            group_create_welcome_publish: inner.group_create_welcome_publish.snapshot(),
            group_create_local_projection_save: inner.group_create_local_projection_save.snapshot(),
            group_create_response_handoff: inner.group_create_response_handoff.snapshot(),
            group_create_subscription_refresh: inner.group_create_subscription_refresh.snapshot(),
            group_create_post_mutation_catch_up: inner
                .group_create_post_mutation_catch_up
                .snapshot(),
            group_create_total_caller_latency: inner.group_create_total_caller_latency.snapshot(),
            group_invite_members: inner.group_invite_members.snapshot(),
            group_invite_key_package_lookup: inner.group_invite_key_package_lookup.snapshot(),
            group_invite_routing_refresh: inner.group_invite_routing_refresh.snapshot(),
            group_invite_pre_send_sync: inner.group_invite_pre_send_sync.snapshot(),
            group_invite_engine_publish: inner.group_invite_engine_publish.snapshot(),
            group_invite_local_refresh: inner.group_invite_local_refresh.snapshot(),
            group_invite_notification_trigger: inner.group_invite_notification_trigger.snapshot(),
            group_invite_welcome_publish: inner.group_invite_welcome_publish.snapshot(),
            group_invite_post_mutation_catch_up: inner
                .group_invite_post_mutation_catch_up
                .snapshot(),
            group_promote_admin: inner.group_promote_admin.snapshot(),
            group_details_read: inner.group_details_read.snapshot(),
            group_conversation_snapshot_read: inner.group_conversation_snapshot_read.snapshot(),
            chat_list_row_read: inner.chat_list_row_read.snapshot(),
            existing_direct_conversation_read: inner.existing_direct_conversation_read.snapshot(),
            group_mls_state_read: inner.group_mls_state_read.snapshot(),
            group_roster_read: inner.group_roster_read.snapshot(),
            group_accept_invite: inner.group_accept_invite.snapshot(),
            media_upload: inner.media_upload.snapshot(),
            media_download: inner.media_download.snapshot(),
            media_download_queue_wait: inner.media_download_queue_wait.snapshot(),
            media_download_preparation: inner.media_download_preparation.snapshot(),
            media_download_host_setup: inner.media_download_host_setup.snapshot(),
            media_download_response_headers: inner.media_download_response_headers.snapshot(),
            media_download_first_byte: inner.media_download_first_byte.snapshot(),
            media_download_body_transfer: inner.media_download_body_transfer.snapshot(),
            media_download_locator_failover: inner.media_download_locator_failover.snapshot(),
            media_download_ciphertext_verify: inner.media_download_ciphertext_verify.snapshot(),
            media_download_decrypt: inner.media_download_decrypt.snapshot(),
            media_download_plaintext_verify: inner.media_download_plaintext_verify.snapshot(),
            host_splash_ready: inner.host_splash_ready.snapshot(),
            host_foreground_local_ready: inner.host_foreground_local_ready.snapshot(),
        }
    }
}

/// Run a best-effort account-setup step under a hard time cap. A capped step
/// behaves exactly like its error path — the caller proceeds without it — and
/// the cap firing is traced and recorded as a failed
/// [`AppPerformanceOperation::AccountSetupAdvisoryStep`] sample, so the cap
/// value can be validated against the fleet rather than the one device it was
/// tuned on.
pub(crate) async fn bounded_advisory_step<F: std::future::Future>(
    telemetry: &AppPerformanceTelemetry,
    cap: Duration,
    step: &'static str,
    future: F,
) -> Option<F::Output> {
    let started = Instant::now();
    match tokio::time::timeout(cap, future).await {
        Ok(value) => {
            telemetry.record(
                AppPerformanceOperation::AccountSetupAdvisoryStep,
                started.elapsed(),
                true,
            );
            Some(value)
        }
        Err(_) => {
            tracing::debug!(
                target: "marmot_app::app_telemetry",
                method = "bounded_advisory_step",
                step,
                cap_ms = cap.as_millis() as u64,
                "advisory account-setup step hit its time cap"
            );
            telemetry.record(
                AppPerformanceOperation::AccountSetupAdvisoryStep,
                started.elapsed(),
                false,
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountCatchUpFailure, AppError, ClassifiedSyncFailure, SyncSummary};
    use cgka_traits::TransportAdapterError;
    use cgka_traits::error::EngineError;
    use cgka_traits::storage::StorageError;

    fn classified(stage: SyncFailureStage, error: AppError) -> SyncFailureClassification {
        ClassifiedSyncFailure::at_stage(SyncSummary::default(), error, stage).classification()
    }

    #[test]
    fn sync_failure_classification_is_typed_bounded_and_propagates() {
        let cases = [
            (
                classified(
                    SyncFailureStage::AccountWorker,
                    AppError::AccountWorkerResponseTimedOut,
                ),
                SyncFailureClassification::new(
                    SyncFailureStage::AccountWorker,
                    SyncErrorClass::Timeout,
                ),
            ),
            (
                classified(
                    SyncFailureStage::RelayReceive,
                    AppError::Transport(TransportAdapterError::Closed),
                ),
                SyncFailureClassification::new(
                    SyncFailureStage::RelayReceive,
                    SyncErrorClass::TransportClosed,
                ),
            ),
            (
                classified(
                    SyncFailureStage::GroupSubscriptionSync,
                    AppError::Transport(TransportAdapterError::Subscription(
                        "raw relay detail must not become an attribute".into(),
                    )),
                ),
                SyncFailureClassification::new(
                    SyncFailureStage::GroupSubscriptionSync,
                    SyncErrorClass::Unknown,
                ),
            ),
            (
                classified(
                    SyncFailureStage::CgkaIngest,
                    AppError::Account(marmot_account::AccountError::Engine(
                        EngineError::InvalidWelcome,
                    )),
                ),
                SyncFailureClassification::new(
                    SyncFailureStage::CgkaIngest,
                    SyncErrorClass::Protocol,
                ),
            ),
            (
                classified(
                    SyncFailureStage::StatePersist,
                    AppError::Storage(StorageError::Backend(
                        "/private/account.sqlite secret detail".into(),
                    )),
                ),
                SyncFailureClassification::new(
                    SyncFailureStage::StatePersist,
                    SyncErrorClass::Storage,
                ),
            ),
            (
                classified(
                    SyncFailureStage::Unknown,
                    AppError::BlockingTask("untyped raw failure".into()),
                ),
                SyncFailureClassification::UNKNOWN,
            ),
        ];
        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }

        let child = cases[3].0;
        let propagated = AppError::AccountCatchUp(AccountCatchUpFailure::new(
            "runtime catch-up failed: attacker-controlled detail".into(),
            child,
        ));
        assert_eq!(propagated.sync_error_class(), child.error_class);

        let telemetry = AppPerformanceTelemetry::default();
        telemetry.record_sync_result(
            AppPerformanceOperation::AccountSync,
            Duration::from_millis(1),
            Some(child),
        );
        telemetry.record_sync_result(
            AppPerformanceOperation::AccountCatchUp,
            Duration::from_millis(2),
            Some(child),
        );
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.account_sync.attempts, 1);
        assert_eq!(snapshot.account_sync.successes, 0);
        assert_eq!(snapshot.account_sync.failures, 1);
        assert_eq!(snapshot.account_catch_up.attempts, 1);
        assert_eq!(snapshot.account_catch_up.successes, 0);
        assert_eq!(snapshot.account_catch_up.failures, 1);
        assert_eq!(
            snapshot.account_sync.failure_classifications[0].classification,
            child
        );
        assert_eq!(
            snapshot.account_catch_up.failure_classifications[0].classification,
            child
        );

        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("attacker-controlled"));
        assert!(!serialized.contains("account.sqlite"));
        assert!(!serialized.contains("raw relay detail"));
    }

    #[test]
    #[should_panic(
        expected = "account sync/catch-up must use record_sync_result with a bounded failure classification"
    )]
    fn generic_record_rejects_classified_sync_operations() {
        AppPerformanceTelemetry::default().record(
            AppPerformanceOperation::AccountSync,
            Duration::from_millis(1),
            false,
        );
    }

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
        telemetry.record(
            AppPerformanceOperation::GroupInviteMembers,
            Duration::from_millis(750),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::AccountTransportActivation,
            Duration::from_millis(5_000),
            false,
        );
        telemetry.record(
            AppPerformanceOperation::AccountSubscriptionRegistration,
            Duration::from_millis(250),
            true,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.app_start.attempts, 2);
        assert_eq!(snapshot.app_start.successes, 1);
        assert_eq!(snapshot.app_start.failures, 1);
        assert_eq!(snapshot.app_start.duration_ms.sample_count(), 2);
        assert_eq!(snapshot.app_start.duration_ms.sum_ms, 400_050);
        assert_eq!(snapshot.group_invite_members.attempts, 1);
        assert_eq!(snapshot.group_invite_members.successes, 1);
        assert_eq!(snapshot.group_invite_members.failures, 0);
        assert_eq!(snapshot.group_invite_members.duration_ms.sample_count(), 1);
        assert_eq!(snapshot.group_invite_members.duration_ms.sum_ms, 750);
        assert_eq!(snapshot.account_transport_activation.failures, 1);
        assert_eq!(
            snapshot.account_transport_activation.duration_ms.sum_ms,
            5_000
        );
        assert_eq!(snapshot.account_subscription_registration.successes, 1);
        assert_eq!(
            snapshot
                .account_subscription_registration
                .duration_ms
                .sum_ms,
            250
        );
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

    #[test]
    fn records_account_open_stage_operations() {
        let telemetry = AppPerformanceTelemetry::default();
        for (operation, duration_ms) in [
            (AppPerformanceOperation::AccountWorkerReadiness, 10),
            (AppPerformanceOperation::AccountSessionOpen, 120),
            (AppPerformanceOperation::AccountGroupHydration, 80),
            (AppPerformanceOperation::AccountProfileLoad, 15),
            (AppPerformanceOperation::AccountGroupReadSnapshot, 40),
            (
                AppPerformanceOperation::AccountBootstrapRelayAndFollowPublish,
                55,
            ),
            (AppPerformanceOperation::AccountDefaultProfilePublish, 35),
            (AppPerformanceOperation::AccountInitialKeyPackagePublish, 25),
            (AppPerformanceOperation::AccountInitialSyncOverlap, 0),
            (AppPerformanceOperation::AccountSetupIdentityLocal, 1),
            (AppPerformanceOperation::AccountSetupStorageLocal, 2),
            (AppPerformanceOperation::AccountSetupProfileLocal, 3),
            (AppPerformanceOperation::AccountSetupKeyPackageLocal, 4),
            (AppPerformanceOperation::AccountSetupLocalReadyHandoff, 5),
            (AppPerformanceOperation::AccountSetupNetworkReady, 6),
        ] {
            telemetry.record(operation, Duration::from_millis(duration_ms), true);
        }

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.account_worker_readiness.duration_ms.sum_ms, 10);
        assert_eq!(snapshot.account_session_open.successes, 1);
        assert_eq!(snapshot.account_session_open.duration_ms.sum_ms, 120);
        assert_eq!(snapshot.account_group_hydration.successes, 1);
        assert_eq!(snapshot.account_group_hydration.duration_ms.sum_ms, 80);
        assert_eq!(snapshot.account_profile_load.successes, 1);
        assert_eq!(snapshot.account_profile_load.duration_ms.sum_ms, 15);
        assert_eq!(snapshot.account_group_read_snapshot.successes, 1);
        assert_eq!(snapshot.account_group_read_snapshot.duration_ms.sum_ms, 40);
        assert_eq!(
            snapshot
                .account_bootstrap_relay_and_follow_publish
                .duration_ms
                .sum_ms,
            55
        );
        assert_eq!(
            snapshot.account_default_profile_publish.duration_ms.sum_ms,
            35
        );
        assert_eq!(
            snapshot
                .account_initial_key_package_publish
                .duration_ms
                .sum_ms,
            25
        );
        assert_eq!(snapshot.account_initial_sync_overlap.successes, 1);
        assert_eq!(snapshot.account_initial_sync_overlap.duration_ms.sum_ms, 0);
        assert_eq!(snapshot.account_setup_identity_local.duration_ms.sum_ms, 1);
        assert_eq!(snapshot.account_setup_storage_local.duration_ms.sum_ms, 2);
        assert_eq!(snapshot.account_setup_profile_local.duration_ms.sum_ms, 3);
        assert_eq!(
            snapshot.account_setup_key_package_local.duration_ms.sum_ms,
            4
        );
        assert_eq!(
            snapshot
                .account_setup_local_ready_handoff
                .duration_ms
                .sum_ms,
            5
        );
        assert_eq!(snapshot.account_setup_network_ready.duration_ms.sum_ms, 6);
    }

    #[test]
    fn records_each_generated_account_setup_stage_and_outcome() {
        let telemetry = AppPerformanceTelemetry::default();
        for (operation, duration_ms) in [
            (AppPerformanceOperation::AccountSetupIdentityLocal, 1),
            (AppPerformanceOperation::AccountSetupStorageLocal, 2),
            (AppPerformanceOperation::AccountSetupProfileLocal, 3),
            (AppPerformanceOperation::AccountSetupKeyPackageLocal, 4),
            (AppPerformanceOperation::AccountSetupLocalReadyHandoff, 5),
            (AppPerformanceOperation::AccountSetupNetworkReady, 6),
        ] {
            telemetry.record(operation, Duration::from_millis(duration_ms), true);
            telemetry.record(operation, Duration::from_millis(duration_ms), false);
        }

        let snapshot = telemetry.snapshot();
        for (stage, expected_sum_ms) in [
            (snapshot.account_setup_identity_local, 2),
            (snapshot.account_setup_storage_local, 4),
            (snapshot.account_setup_profile_local, 6),
            (snapshot.account_setup_key_package_local, 8),
            (snapshot.account_setup_local_ready_handoff, 10),
            (snapshot.account_setup_network_ready, 12),
        ] {
            assert_eq!(stage.attempts, 2);
            assert_eq!(stage.successes, 1);
            assert_eq!(stage.failures, 1);
            assert_eq!(stage.duration_ms.sum_ms, expected_sum_ms);
        }
    }

    #[test]
    fn records_each_group_create_stage() {
        let telemetry = AppPerformanceTelemetry::default();
        let operations = [
            AppPerformanceOperation::GroupCreateQueueWait,
            AppPerformanceOperation::GroupCreateKeyPackageLookup,
            AppPerformanceOperation::GroupMemberKeyPackagePrewarm,
            AppPerformanceOperation::GroupCreateKeyPackageCacheReuse,
            AppPerformanceOperation::GroupCreateKeyPackageNetworkResolution,
            AppPerformanceOperation::GroupCreateImagePreprocess,
            AppPerformanceOperation::GroupCreateImageUpload,
            AppPerformanceOperation::GroupCreateMlsPreparePersist,
            AppPerformanceOperation::GroupCreatePendingWelcomeIndex,
            AppPerformanceOperation::GroupCreateWelcomePublish,
            AppPerformanceOperation::GroupCreateLocalProjectionSave,
            AppPerformanceOperation::GroupCreateResponseHandoff,
            AppPerformanceOperation::GroupCreateSubscriptionRefresh,
            AppPerformanceOperation::GroupCreatePostMutationCatchUp,
            AppPerformanceOperation::GroupCreateTotalCallerLatency,
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            telemetry.record(operation, Duration::from_millis(index as u64 + 1), true);
        }

        let snapshot = telemetry.snapshot();
        for stage in [
            snapshot.group_create_queue_wait,
            snapshot.group_create_key_package_lookup,
            snapshot.group_member_key_package_prewarm,
            snapshot.group_create_key_package_cache_reuse,
            snapshot.group_create_key_package_network_resolution,
            snapshot.group_create_image_preprocess,
            snapshot.group_create_image_upload,
            snapshot.group_create_mls_prepare_persist,
            snapshot.group_create_pending_welcome_index,
            snapshot.group_create_welcome_publish,
            snapshot.group_create_local_projection_save,
            snapshot.group_create_response_handoff,
            snapshot.group_create_subscription_refresh,
            snapshot.group_create_post_mutation_catch_up,
            snapshot.group_create_total_caller_latency,
        ] {
            assert_eq!(stage.attempts, 1);
            assert_eq!(stage.successes, 1);
            assert_eq!(stage.duration_ms.sample_count(), 1);
        }
    }

    #[test]
    fn records_group_accept_invite_operation() {
        let telemetry = AppPerformanceTelemetry::default();
        telemetry.record(
            AppPerformanceOperation::GroupAcceptInvite,
            Duration::from_millis(30),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::GroupAcceptInvite,
            Duration::from_millis(70),
            false,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.group_accept_invite.attempts, 2);
        assert_eq!(snapshot.group_accept_invite.successes, 1);
        assert_eq!(snapshot.group_accept_invite.failures, 1);
        assert!(
            snapshot
                .group_accept_invite
                .failure_classifications
                .is_empty(),
            "generic operation failures must not populate sync classifications"
        );
        assert_eq!(snapshot.group_accept_invite.duration_ms.sample_count(), 2);
        assert_eq!(snapshot.group_accept_invite.duration_ms.sum_ms, 100);
    }

    /// Every media phase is retained as an aggregate operation with no dynamic
    /// classification surface.
    #[test]
    fn records_each_media_download_phase_without_dynamic_labels() {
        let telemetry = AppPerformanceTelemetry::default();
        for (operation, duration_ms) in [
            (AppPerformanceOperation::MediaDownloadQueueWait, 1),
            (AppPerformanceOperation::MediaDownloadPreparation, 2),
            (AppPerformanceOperation::MediaDownloadHostSetup, 3),
            (AppPerformanceOperation::MediaDownloadResponseHeaders, 4),
            (AppPerformanceOperation::MediaDownloadFirstByte, 5),
            (AppPerformanceOperation::MediaDownloadBodyTransfer, 6),
            (AppPerformanceOperation::MediaDownloadLocatorFailover, 7),
            (AppPerformanceOperation::MediaDownloadCiphertextVerify, 8),
            (AppPerformanceOperation::MediaDownloadDecrypt, 9),
            (AppPerformanceOperation::MediaDownloadPlaintextVerify, 10),
        ] {
            telemetry.record(operation, Duration::from_millis(duration_ms), true);
        }

        let snapshot = telemetry.snapshot();
        for phase in [
            snapshot.media_download_queue_wait,
            snapshot.media_download_preparation,
            snapshot.media_download_host_setup,
            snapshot.media_download_response_headers,
            snapshot.media_download_first_byte,
            snapshot.media_download_body_transfer,
            snapshot.media_download_locator_failover,
            snapshot.media_download_ciphertext_verify,
            snapshot.media_download_decrypt,
            snapshot.media_download_plaintext_verify,
        ] {
            assert_eq!(phase.attempts, 1);
            assert_eq!(phase.successes, 1);
            assert_eq!(phase.failures, 0);
            assert_eq!(phase.duration_ms.sample_count(), 1);
        }
    }

    #[test]
    fn records_chat_list_row_read_operation() {
        let telemetry = AppPerformanceTelemetry::default();
        telemetry.record(
            AppPerformanceOperation::ChatListRowRead,
            Duration::from_millis(4),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::ChatListRowRead,
            Duration::from_millis(9),
            false,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.chat_list_row_read.attempts, 2);
        assert_eq!(snapshot.chat_list_row_read.successes, 1);
        assert_eq!(snapshot.chat_list_row_read.failures, 1);
        assert_eq!(snapshot.chat_list_row_read.duration_ms.sample_count(), 2);
        assert_eq!(snapshot.chat_list_row_read.duration_ms.sum_ms, 13);
    }

    #[test]
    fn records_group_conversation_snapshot_read_operation() {
        let telemetry = AppPerformanceTelemetry::default();
        telemetry.record(
            AppPerformanceOperation::GroupConversationSnapshotRead,
            Duration::from_millis(6),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::GroupConversationSnapshotRead,
            Duration::from_millis(10),
            false,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.group_conversation_snapshot_read.attempts, 2);
        assert_eq!(snapshot.group_conversation_snapshot_read.successes, 1);
        assert_eq!(snapshot.group_conversation_snapshot_read.failures, 1);
        assert_eq!(
            snapshot
                .group_conversation_snapshot_read
                .duration_ms
                .sample_count(),
            2
        );
        assert_eq!(
            snapshot.group_conversation_snapshot_read.duration_ms.sum_ms,
            16
        );
    }

    #[test]
    fn records_existing_direct_conversation_read_operation() {
        let telemetry = AppPerformanceTelemetry::default();
        telemetry.record(
            AppPerformanceOperation::ExistingDirectConversationRead,
            Duration::from_millis(5),
            true,
        );
        telemetry.record(
            AppPerformanceOperation::ExistingDirectConversationRead,
            Duration::from_millis(8),
            false,
        );

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.existing_direct_conversation_read.attempts, 2);
        assert_eq!(snapshot.existing_direct_conversation_read.successes, 1);
        assert_eq!(snapshot.existing_direct_conversation_read.failures, 1);
        assert_eq!(
            snapshot
                .existing_direct_conversation_read
                .duration_ms
                .sample_count(),
            2
        );
        assert_eq!(
            snapshot
                .existing_direct_conversation_read
                .duration_ms
                .sum_ms,
            13
        );
    }

    #[test]
    fn records_each_closed_host_performance_operation() {
        let telemetry = AppPerformanceTelemetry::default();
        for (operation, duration_ms, outcome) in [
            (
                HostPerformanceOperation::SplashReady,
                100,
                HostPerformanceOutcome::Success,
            ),
            (
                HostPerformanceOperation::ForegroundLocalReady,
                200,
                HostPerformanceOutcome::Success,
            ),
        ] {
            telemetry.record_host_performance(
                operation,
                Duration::from_millis(duration_ms),
                outcome,
            );
        }

        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.host_splash_ready.successes, 1);
        assert_eq!(snapshot.host_splash_ready.duration_ms.sum_ms, 100);
        assert_eq!(snapshot.host_foreground_local_ready.successes, 1);
        assert_eq!(snapshot.host_foreground_local_ready.duration_ms.sum_ms, 200);
    }

    #[tokio::test]
    async fn bounded_advisory_step_returns_the_value_and_records_success() {
        let telemetry = AppPerformanceTelemetry::default();
        let value =
            bounded_advisory_step(&telemetry, Duration::from_secs(5), "test_step", async { 7 })
                .await;
        assert_eq!(value, Some(7));
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.account_setup_advisory_step.attempts, 1);
        assert_eq!(snapshot.account_setup_advisory_step.successes, 1);
        assert_eq!(snapshot.account_setup_advisory_step.failures, 0);
    }

    #[tokio::test]
    async fn bounded_advisory_step_caps_a_stalled_future_and_records_the_cap() {
        let telemetry = AppPerformanceTelemetry::default();
        let value: Option<()> = bounded_advisory_step(
            &telemetry,
            Duration::from_millis(50),
            "test_step",
            std::future::pending(),
        )
        .await;
        assert_eq!(value, None);
        let snapshot = telemetry.snapshot();
        assert_eq!(snapshot.account_setup_advisory_step.attempts, 1);
        assert_eq!(snapshot.account_setup_advisory_step.successes, 0);
        assert_eq!(snapshot.account_setup_advisory_step.failures, 1);
    }

    #[test]
    fn snapshot_carries_the_process_wide_sqlcipher_probe_counters() {
        // The counters are process-global atomics shared with every test in
        // this process, so bracket the snapshot between two direct reads
        // instead of asserting exact values.
        let telemetry = AppPerformanceTelemetry::default();
        let before = crate::sqlcipher::sqlcipher_migration_probe_counters();
        let snapshot = telemetry.snapshot();
        let after = crate::sqlcipher::sqlcipher_migration_probe_counters();

        assert!(before.0 <= snapshot.sqlcipher_migration_probe_runs);
        assert!(snapshot.sqlcipher_migration_probe_runs <= after.0);
        assert!(before.1 <= snapshot.sqlcipher_migration_probe_skips);
        assert!(snapshot.sqlcipher_migration_probe_skips <= after.1);
    }
}
