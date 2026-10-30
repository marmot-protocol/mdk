use std::time::Duration;

use marmot_session::MaintenanceTiming;

use crate::deployment::{MarmotDeployment, OpenRankingProvider};
use crate::export_config::{
    AuditLogUploadSource, DEFAULT_EXPORT_INTERVAL, RelayTelemetryExportConfig,
    RelayTelemetryRuntimeConfig, endpoint_transport_allowed, trim_optional,
};
use serde::{Deserialize, Serialize};

const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
const COMPILED_RELAY_TELEMETRY_OTLP_ENDPOINT: Option<&str> =
    option_env!("MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT");
const COMPILED_AUDIT_LOG_TRACKER_ENDPOINT: Option<&str> =
    option_env!("MARMOT_AUDIT_LOG_TRACKER_ENDPOINT");

/// Policy for advancing the account's durable transport cursor
/// (`last_transport_timestamp`) from ingested deliveries.
///
/// A runtime-construction policy, not a per-call switch: it is fixed on
/// [`MarmotAppConfig`] and applies to every account client the resulting
/// `MarmotApp`/`MarmotAppRuntime` opens for that construction's lifetime.
///
/// * [`Advance`](Self::Advance) — the default, normal posture: every ingested
///   kind-445 advances the in-memory cursor (clamp-then-monotonic-max, see
///   `client/sync.rs`). A completed transport drain promotes that candidate to
///   the durable floor; isolated live-delivery projection saves retain the last
///   drain checkpoint so a later bounded-queue overflow cannot strand an older
///   delivery below an already-persisted newest-first cursor.
/// * [`Frozen`](Self::Frozen) — the wake-collection posture (iOS NSE,
///   notification reply/mark-read actions: full runtimes with a sub-second
///   drain budget on cold sockets). A `Frozen` pass still ingests, decrypts,
///   and projects everything; it only cannot move the durable floor. The
///   in-memory cursor never advances, so every `save_state` writes back the
///   loaded value, and the save-time clamp-then-max merge in
///   `storage_sqlite::save_account_projection_state` guarantees that write can
///   never lower a cursor a concurrent `Advance` runtime has moved. The cursor
///   is still *loaded* and still derives the subscription `since` floor —
///   `Frozen` means "never advance", not "no cursor". Worst case is bounded
///   redelivery on the next `Advance` catch-up, absorbed by seen-id dedup.
///
/// `Frozen` severs the cursor ratchet at the wake-collection trigger:
/// a wake pass that drains for a fraction of a second on cold sockets must
/// not persist a floor above events it never had time to receive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CursorPersistence {
    /// Ingested deliveries advance the durable cursor (default).
    #[default]
    Advance,
    /// The durable cursor never advances; the pass still ingests and projects.
    Frozen,
}

/// Chooses who supplies automatic attachment demand. Fixed before workers start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AttachmentAcquisitionMode {
    #[default]
    NativeAutomatic,
    /// Host demand and runtime-only permission are both required. Starts denied.
    HostManaged,
}

/// Automatic attachment policy. Downloaded bodies are retained in the
/// account's encrypted media store with no byte quota: free disk above
/// `minimum_free_disk_bytes` is the only gate (mdk#2314).
/// Sent bodies are kept there too, under the same free-disk gate.
/// `retained_bytes_per_account` only bounds the promotion of legacy database
/// copies of sent attachments staged by earlier releases. No automatic
/// eviction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentAcquisitionPolicy {
    pub retained_bytes_per_account: u64,
    pub minimum_free_disk_bytes: u64,
    pub maximum_transfer_bytes: u64,
}
impl Default for AttachmentAcquisitionPolicy {
    fn default() -> Self {
        Self {
            retained_bytes_per_account: 2 * 1024 * 1024 * 1024,
            minimum_free_disk_bytes: 256 * 1024 * 1024,
            maximum_transfer_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    /// Destination for private moderation reports to the deployment's moderation team.
    /// `None` leaves reporting unconfigured. An invalid value is rejected whole at first use
    /// and also leaves reporting unconfigured; see `MarmotApp::set_moderation_report_config`.
    pub moderation_report_config: Option<crate::ModerationReportConfig>,
    /// Optional public client label for newly prepared KeyPackage events, published
    /// trimmed as the only value of one `client` tag. None, or a label that is blank
    /// or longer than 64 bytes once trimmed, leaves publications untagged; signed
    /// retries retain their original tags.
    pub key_package_client_name: Option<String>,
    /// Optional short name of the platform this device runs on, such as
    /// `iOS`, which it writes with `key_package_client_name` into its own
    /// entry in its device group's roster (mdk#2628 3.6). None, or a name
    /// blank or longer than 64 bytes once trimmed, writes none.
    pub device_platform: Option<String>,
    /// Automatic acquisition defaults on with bounded resource limits.
    /// None disables automatic acquisition; frozen runtimes always disable it.
    /// Per-account native policy overrides are durable.
    pub attachment_acquisition: Option<AttachmentAcquisitionPolicy>,
    /// Demand and permission ownership, fixed before runtime workers start.
    pub attachment_acquisition_mode: AttachmentAcquisitionMode,
    /// Disable exporters for short-lived command processes. Frozen cursors always disable them.
    pub usage_diagnostics_silent: bool,
    pub directory_max_future_skew: Duration,
    /// Host-configured WebSocket relays used for Nostr directory reads such as
    /// relay-list and KeyPackage discovery.
    ///
    /// These are deliberately separate from the app's operational relay URLs,
    /// allowing a host to use different relay sets for discovery and message
    /// delivery. Empty preserves the historical behavior of falling back to
    /// the operational relay set.
    pub directory_relay_urls: Vec<String>,
    /// The services this deployment's users rely on: recovery relays,
    /// discovery indexers, media and image servers, Open Ranking, the
    /// KeyPackage client preference, the moderation label namespace and the
    /// keychain service. The default is [`MarmotDeployment::neutral`]; White
    /// Noise hosts use [`MarmotAppConfig::white_noise`].
    pub deployment: MarmotDeployment,
    pub service_endpoints: MarmotServiceEndpoints,
    /// Durable transport-cursor persistence policy. Defaults to
    /// [`CursorPersistence::Advance`]; wake-collection runtimes (NSE,
    /// notification actions) opt in to [`CursorPersistence::Frozen`] at
    /// construction. See the enum docs for the full semantics.
    pub cursor_persistence: CursorPersistence,
    /// Dev/test gate for loopback-HTTP blob endpoints. A loopback-HTTP endpoint
    /// (e.g. `http://127.0.0.1:PORT`) is VALID component state for everyone, but
    /// local destination policy forbids contacting it unless explicitly
    /// configured for dev/test. Defaults to `false` so production builds treat
    /// such endpoints as unusable rather than issuing requests to the local
    /// host. This does not affect V2 component validity; frozen V1 reference
    /// validation retains its own legacy unsafe-host rule.
    pub allow_loopback_blob_endpoints: bool,
    /// Dev/test gate for loopback relay endpoints (e.g. `ws://127.0.0.1:PORT`,
    /// an in-process `MockRelay`). A loopback relay URL is VALID
    /// routing/relay-list state, but production MUST NOT open a socket to one;
    /// the relay-safety chokepoint rejects non-public relay hosts before they
    /// reach the pool. Public relays always require `wss://`; this gate admits
    /// `ws://` only for loopback — private/link-local/CGNAT and public plaintext
    /// relay hosts stay rejected even when it is set. Defaults to `false`; test
    /// harnesses set `true`. Mirrors `allow_loopback_blob_endpoints`; does not
    /// affect routing-component validity (decode still accepts `ws://`).
    pub allow_loopback_relay_endpoints: bool,
    /// Dev/test override for the convergence settlement quiescence window, in
    /// milliseconds. `None` (the default) uses the protocol-pinned value
    /// (`settlement_quiescence_ms = 1000`). Honored only when the explicit
    /// `test-policy-overrides` feature is enabled; normal debug and release
    /// builds ignore it so hosts cannot fork the pinned v1 baseline (mdk#970).
    pub dev_settlement_quiescence_ms: Option<u64>,
    /// Dev/test-only delay added after the engine-reported convergence cutoff
    /// before the account worker runs scheduled convergence. `None` (the
    /// default) adds no delay. Honored only with `test-policy-overrides`; this
    /// lets integration tests hold the precise post-cutoff/pre-scheduler state
    /// without changing protocol timing in normal builds.
    pub dev_scheduled_convergence_delay_ms: Option<u64>,
    /// Dev/test override for own-leaf maintenance scheduling: the quiet window,
    /// post-join and manual contention jitter, end-of-stored-events timeout,
    /// and post-EOSE grace. `None` (the default) keeps the production windows.
    /// Honored only with `test-policy-overrides`; normal debug and release
    /// builds ignore it so hosts cannot shorten the anti-contention delays.
    pub dev_maintenance_timing: Option<MaintenanceTiming>,
    /// Dev/test-only delay applied before each startup hydration-pipeline
    /// batch (mdk#1161). `None` (the default) adds no delay. Honored only
    /// with `test-policy-overrides`; this lets integration tests hold groups
    /// in the seeded not-yet-hydrated state while asserting the persisted
    /// chat projection and per-group read behavior, without changing startup
    /// timing in normal builds. Commands are still served during the delay.
    pub dev_startup_hydration_batch_delay_ms: Option<u64>,
    /// Dev/test-only override that forces group-read snapshot capture to fail.
    /// Honored only with `test-policy-overrides`; this exercises the account
    /// worker's degraded catch-up path without corrupting a real database.
    pub dev_force_group_read_snapshot_failure: bool,
    /// Dev/test-only override that fails the app projection transaction after
    /// a founding group is already canonical. Honored only with
    /// `test-policy-overrides`; restart tests use it to exercise the sole
    /// remaining post-canonical write boundary.
    pub dev_fail_create_local_projection: bool,
    /// Dev/test-only switch that advertises the device roster
    /// (`marmot.account.device-roster.v1`), so this device can create and join
    /// its account's device group (mdk#2628 item 3.1). Honored only with
    /// `test-policy-overrides` until the roster's spec merges.
    pub dev_device_groups: bool,
    /// Dev/test-only override that fails invite local projection refresh.
    /// Honored only with `test-policy-overrides`; this proves a canonical
    /// invite still returns success and attempts Welcome fanout.
    pub dev_fail_invite_local_refresh: bool,
    /// Dev/test-only override for the base interval a recovery attempt waits
    /// before an automatic seam may start another
    /// ([`crate::EPOCH_BACKFILL_RETRY_BACKOFF`]). Honored only with
    /// `test-policy-overrides`; this lets a test exercise both sides of the
    /// cooldown without spending it in wall-clock.
    pub dev_epoch_backfill_retry_backoff_ms: Option<u64>,
    /// Dev/test-only override for how long a group wedged at one stalled epoch
    /// must wait between paced re-arms
    /// ([`crate::client::epoch_stall::EPOCH_STALL_WEDGE_REARM_INTERVAL_MS`]).
    /// Honored only with `test-policy-overrides`; the production interval is an
    /// hour, so this is the only way a test can reach the second and third
    /// re-arm of a frozen device without sleeping through them.
    pub dev_epoch_stall_wedge_rearm_interval_ms: Option<u64>,
    /// Dev/test-only fault injected before the next delivery after this many
    /// completed catch-up deliveries. Honored only with
    /// `test-policy-overrides`; this exercises truthful partial-progress
    /// reporting when delivery N+1 fails before ingest.
    pub dev_fail_sync_before_delivery: Option<u64>,
    /// Dev/test-only fault injected before checkpointing an accumulated sync
    /// prefix after more than this many deliveries completed. Honored only with
    /// `test-policy-overrides`; this verifies that an uncommitted batch is
    /// excluded from the completed prefix and replayed from the engine outbox.
    pub dev_fail_sync_before_boundary_save: Option<u64>,
    /// Dev/test-only fault injected after staging an application-event
    /// acknowledgement during inbound delivery projection. Honored only with
    /// `test-policy-overrides`; this exercises retention of the already-applied
    /// event summary when a later step in the same delivery fails.
    pub dev_fail_ingest_after_application_event_ack: bool,
    /// Dev/test-only fault injected at the no-inbound engine-event drain
    /// (`drain_pending_session_events`). Honored only with
    /// `test-policy-overrides`. The production failures of that step —
    /// a resumed outbound fanout whose publish never lands, a storage read
    /// behind its projection loop — all originate below the app boundary and
    /// have no external driver, so this stands in for them when a caller's
    /// handling of that error is what is under test.
    pub dev_fail_pending_session_event_drain: bool,
    /// Dev/test-only one-shot fault injected after published
    /// application-message source retention is finalized but before its
    /// durable fanout is acknowledged.
    /// Honored only with `test-policy-overrides`; this exercises the recovery
    /// boundary where projection is committed but fanout cleanup must retry.
    pub dev_fail_published_app_message_acknowledgement: bool,
    /// Accounts to search outward from when the searcher's own web of trust is
    /// empty, as pubkey hex.
    ///
    /// A brand-new account follows nobody and shares no group, so a
    /// personalized search over it can only ever answer "nothing". Seeding a
    /// well-connected account gives the traversal somewhere to start. Those
    /// people are not close to the searcher in any measurable sense, so their
    /// matches are reported at `OFF_GRAPH_SEARCH_RADIUS` rather than presented
    /// as follows -- see that constant for why the distinction is load-bearing.
    ///
    /// Empty by default: whose network to fall back to is a deployment
    /// decision, not protocol behaviour, and it is only consulted when the
    /// searcher has no graph of their own.
    pub directory_search_fallback_seeds: Vec<String>,
}

/// Compiled or app-level default collector URLs for product analytics,
/// production telemetry export and forensic audit-log tracker uploads.
/// Deployment services such as media servers and Open Ranking live on
/// [`MarmotDeployment`].
///
/// Defaults are intentionally separate from bearer tokens. Host apps supply
/// credentials at runtime, while the MDK/Marmot build owns stable
/// first-party URLs. `MarmotAppConfig::default()` reads these from
/// `MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT`,
/// `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` and
/// `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` at compile time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarmotServiceEndpoints {
    pub product_analytics_events_endpoint: Option<String>,
    pub relay_telemetry_otlp_endpoint: Option<String>,
    pub audit_log_tracker_endpoint: Option<String>,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            key_package_client_name: None,
            device_platform: None,
            attachment_acquisition: Some(AttachmentAcquisitionPolicy::default()),
            attachment_acquisition_mode: AttachmentAcquisitionMode::default(),
            moderation_report_config: None,
            usage_diagnostics_silent: false,
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
            directory_relay_urls: Vec::new(),
            deployment: MarmotDeployment::neutral(),
            service_endpoints: MarmotServiceEndpoints::compiled(),
            cursor_persistence: CursorPersistence::Advance,
            allow_loopback_blob_endpoints: false,
            allow_loopback_relay_endpoints: false,
            dev_settlement_quiescence_ms: None,
            dev_scheduled_convergence_delay_ms: None,
            dev_maintenance_timing: None,
            dev_startup_hydration_batch_delay_ms: None,
            dev_force_group_read_snapshot_failure: false,
            dev_fail_create_local_projection: false,
            dev_device_groups: false,
            dev_fail_invite_local_refresh: false,
            dev_epoch_backfill_retry_backoff_ms: None,
            dev_epoch_stall_wedge_rearm_interval_ms: None,
            dev_fail_sync_before_delivery: None,
            dev_fail_sync_before_boundary_save: None,
            dev_fail_ingest_after_application_event_ack: false,
            dev_fail_pending_session_event_drain: false,
            dev_fail_published_app_message_acknowledgement: false,
            directory_search_fallback_seeds: Vec::new(),
        }
    }
}

impl MarmotAppConfig {
    /// The default configuration with White Noise's deployment
    /// ([`MarmotDeployment::white_noise`]). [`Default`] is neutral: it
    /// configures no deployment service.
    pub fn white_noise() -> Self {
        Self {
            deployment: MarmotDeployment::white_noise(),
            ..Self::default()
        }
    }

    /// Select native or host-managed demand before constructing a runtime.
    pub fn with_attachment_acquisition_mode(mut self, mode: AttachmentAcquisitionMode) -> Self {
        self.attachment_acquisition_mode = mode;
        self
    }

    pub fn with_key_package_client_name(mut self, name: Option<String>) -> Self {
        self.key_package_client_name = name;
        self
    }

    pub fn with_device_platform(mut self, platform: Option<String>) -> Self {
        self.device_platform = platform;
        self
    }

    pub fn with_directory_max_future_skew(mut self, skew: Duration) -> Self {
        self.directory_max_future_skew = skew;
        self
    }

    /// Configure relays used only for Nostr directory and KeyPackage reads.
    pub fn with_directory_relay_urls(mut self, relay_urls: Vec<String>) -> Self {
        self.directory_relay_urls = relay_urls;
        self
    }

    /// Use `deployment` for every deployment service; see [`MarmotDeployment`].
    pub fn with_deployment(mut self, deployment: MarmotDeployment) -> Self {
        self.deployment = deployment.normalize();
        self
    }

    pub fn with_recovery_operated_relays(mut self, relay_urls: Vec<String>) -> Self {
        self.deployment.recovery_operated_relays = relay_urls;
        self.deployment = self.deployment.normalize();
        self
    }

    pub fn with_service_endpoints(mut self, endpoints: MarmotServiceEndpoints) -> Self {
        self.service_endpoints = endpoints.normalize();
        self
    }

    /// Set the durable transport-cursor persistence policy. Defaults to
    /// [`CursorPersistence::Advance`]; wake-collection runtimes (NSE,
    /// notification actions) construct with [`CursorPersistence::Frozen`] so a
    /// sub-second drain can never ratchet the durable `since` floor past
    /// events it did not receive.
    pub fn with_cursor_persistence(mut self, policy: CursorPersistence) -> Self {
        self.cursor_persistence = policy;
        self
    }

    /// Enable acting on loopback-HTTP blob endpoints for dev/test. Off by
    /// default; production builds must leave this unset.
    pub fn with_allow_loopback_blob_endpoints(mut self, allow: bool) -> Self {
        self.allow_loopback_blob_endpoints = allow;
        self
    }

    /// Enable opening relay connections to loopback endpoints for dev/test
    /// (e.g. an in-process `MockRelay`). Admits loopback only; private/
    /// link-local/CGNAT hosts stay rejected. Off by default; production builds
    /// must leave this unset.
    pub fn with_allow_loopback_relay_endpoints(mut self, allow: bool) -> Self {
        self.allow_loopback_relay_endpoints = allow;
        self
    }

    /// Configure the private moderation-report destination (per build flavor).
    pub fn with_moderation_report_config(
        mut self,
        config: Option<crate::ModerationReportConfig>,
    ) -> Self {
        self.moderation_report_config = config;
        self
    }

    /// Set the accounts to fall back to when a searcher's own graph is empty.
    /// See [`Self::directory_search_fallback_seeds`].
    pub fn with_directory_search_fallback_seeds(mut self, seeds: Vec<String>) -> Self {
        self.directory_search_fallback_seeds = seeds;
        self
    }

    /// Configure or disable the optional Open Ranking discovery tier.
    ///
    /// Passing `None` or an empty relay list disables the tier. This is a
    /// construction-time privacy/availability choice; personal graph search
    /// remains available either way.
    pub fn with_open_ranking_provider(
        mut self,
        search_endpoint: Option<String>,
        profile_relays: Vec<String>,
    ) -> Self {
        self.deployment.open_ranking = search_endpoint.map(|search_endpoint| OpenRankingProvider {
            search_endpoint,
            profile_relays,
        });
        self.deployment = self.deployment.normalize();
        self
    }

    /// Dev/test override for the convergence settlement quiescence window (ms).
    /// Off by default (the protocol-pinned `1000` ms is used). Normal builds
    /// ignore this field; explicit test harnesses set `0` for instant settlement.
    pub fn with_dev_settlement_quiescence_ms(mut self, ms: u64) -> Self {
        self.dev_settlement_quiescence_ms = Some(ms);
        self
    }

    /// Add a test-only delay between the engine cutoff and the account
    /// worker's scheduled convergence pass. Normal builds ignore this field.
    pub fn with_dev_scheduled_convergence_delay_ms(mut self, ms: u64) -> Self {
        self.dev_scheduled_convergence_delay_ms = Some(ms);
        self
    }

    /// Test-only override for own-leaf maintenance scheduling windows, for
    /// harnesses that drive maintenance sweeps explicitly. Normal builds
    /// ignore this field and keep the production quiet window and jitter.
    pub fn with_dev_maintenance_timing(mut self, timing: MaintenanceTiming) -> Self {
        self.dev_maintenance_timing = Some(timing);
        self
    }

    /// Add a test-only delay before each startup hydration-pipeline batch
    /// (mdk#1161). Normal builds ignore this field.
    pub fn with_dev_startup_hydration_batch_delay_ms(mut self, ms: u64) -> Self {
        self.dev_startup_hydration_batch_delay_ms = Some(ms);
        self
    }

    /// Force group-read snapshot capture to fail in test-policy builds.
    /// Normal builds ignore this field.
    pub fn with_dev_force_group_read_snapshot_failure(mut self, enabled: bool) -> Self {
        self.dev_force_group_read_snapshot_failure = enabled;
        self
    }

    pub fn with_dev_fail_create_local_projection(mut self, enabled: bool) -> Self {
        self.dev_fail_create_local_projection = enabled;
        self
    }

    /// Advertise the device roster in test-policy builds. Normal builds ignore
    /// this field.
    pub fn with_dev_device_groups(mut self, enabled: bool) -> Self {
        self.dev_device_groups = enabled;
        self
    }

    /// Fail invite local projection refresh in test-policy builds.
    /// Normal builds ignore this field.
    pub fn with_dev_fail_invite_local_refresh(mut self, enabled: bool) -> Self {
        self.dev_fail_invite_local_refresh = enabled;
        self
    }

    /// Pace unconfirmed epoch-gap backfill retries `ms` apart in test-policy
    /// builds. Normal builds ignore this field.
    pub fn with_dev_epoch_backfill_retry_backoff_ms(mut self, ms: u64) -> Self {
        self.dev_epoch_backfill_retry_backoff_ms = Some(ms);
        self
    }

    /// Pace a wedged group's same-epoch backfill re-arms `ms` apart in
    /// test-policy builds. Normal builds ignore this field.
    pub fn with_dev_epoch_stall_wedge_rearm_interval_ms(mut self, ms: u64) -> Self {
        self.dev_epoch_stall_wedge_rearm_interval_ms = Some(ms);
        self
    }

    /// Fail before the next catch-up delivery after `deliveries` completed in
    /// test-policy builds. Normal builds ignore this field.
    pub fn with_dev_fail_sync_before_delivery(mut self, deliveries: u64) -> Self {
        self.dev_fail_sync_before_delivery = Some(deliveries);
        self
    }

    /// Fail before checkpointing a sync prefix after more than
    /// `completed_deliveries` were accumulated in test-policy builds. Normal
    /// builds ignore this field.
    pub fn with_dev_fail_sync_before_boundary_save(mut self, completed_deliveries: u64) -> Self {
        self.dev_fail_sync_before_boundary_save = Some(completed_deliveries);
        self
    }

    /// Fail after staging an inbound application-event acknowledgement in
    /// test-policy builds. Normal builds ignore this field.
    pub fn with_dev_fail_ingest_after_application_event_ack(mut self) -> Self {
        self.dev_fail_ingest_after_application_event_ack = true;
        self
    }

    /// Fail the no-inbound engine-event drain in test-policy builds. Normal
    /// builds ignore this field.
    pub fn with_dev_fail_pending_session_event_drain(mut self) -> Self {
        self.dev_fail_pending_session_event_drain = true;
        self
    }

    /// Fail the next published application-message acknowledgement in
    /// test-policy builds. Normal builds ignore this field.
    pub fn with_dev_fail_published_app_message_acknowledgement(mut self) -> Self {
        self.dev_fail_published_app_message_acknowledgement = true;
        self
    }
}

impl MarmotServiceEndpoints {
    pub fn compiled() -> Self {
        Self {
            product_analytics_events_endpoint: option_env!(
                "MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT"
            )
            .map(str::to_owned),
            relay_telemetry_otlp_endpoint: COMPILED_RELAY_TELEMETRY_OTLP_ENDPOINT
                .map(str::to_owned),
            audit_log_tracker_endpoint: COMPILED_AUDIT_LOG_TRACKER_ENDPOINT.map(str::to_owned),
        }
        .normalize()
    }

    pub fn normalize(mut self) -> Self {
        self.product_analytics_events_endpoint =
            trim_optional(self.product_analytics_events_endpoint);
        self.relay_telemetry_otlp_endpoint = trim_optional(self.relay_telemetry_otlp_endpoint);
        self.audit_log_tracker_endpoint = trim_optional(self.audit_log_tracker_endpoint);
        self
    }
}

const MIN_EXPORT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_EXPORT_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTelemetrySettings {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

/// Hand-written `Debug` below redacts `authorization_bearer_token` (the audit
/// upload credential) so a `{:?}` never prints it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AuditLogTrackerConfig {
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub source: AuditLogUploadSource,
}

impl std::fmt::Debug for AuditLogTrackerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogTrackerConfig")
            .field("endpoint", &self.endpoint)
            .field(
                "authorization_bearer_token",
                &self
                    .authorization_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("source", &self.source)
            .finish()
    }
}

impl AuditLogTrackerConfig {
    pub(crate) fn normalize(mut self) -> Result<Self, String> {
        self.endpoint = trim_optional(self.endpoint);
        self.authorization_bearer_token = trim_optional(self.authorization_bearer_token);
        self.source = AuditLogUploadSource {
            hardware_model: trim_optional(self.source.hardware_model),
            platform: trim_optional(self.source.platform),
            app_version: trim_optional(self.source.app_version),
        };
        if self
            .endpoint
            .as_deref()
            .is_some_and(|endpoint| !endpoint_transport_allowed(endpoint))
        {
            return Err(
                "audit log tracker endpoint must be https, or loopback http for local testing"
                    .to_owned(),
            );
        }
        Ok(self)
    }

    pub(crate) fn resolved_endpoint(&self, endpoints: &MarmotServiceEndpoints) -> Option<String> {
        self.endpoint
            .clone()
            .or_else(|| endpoints.audit_log_tracker_endpoint.clone())
            .and_then(|endpoint| trim_optional(Some(endpoint)))
    }

    pub(crate) fn upload_allowed_with_endpoints(&self, endpoints: &MarmotServiceEndpoints) -> bool {
        self.resolved_endpoint(endpoints)
            .as_deref()
            .is_some_and(endpoint_transport_allowed)
            && self
                .authorization_bearer_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty())
    }
}

impl Default for RelayTelemetrySettings {
    fn default() -> Self {
        Self {
            export_enabled: false,
            export_interval_seconds: DEFAULT_EXPORT_INTERVAL.as_secs(),
        }
    }
}

impl RelayTelemetrySettings {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let interval = Duration::from_secs(self.export_interval_seconds);
        if interval < MIN_EXPORT_INTERVAL || interval > MAX_EXPORT_INTERVAL {
            return Err(format!(
                "relay telemetry export interval must be between {} and {} seconds",
                MIN_EXPORT_INTERVAL.as_secs(),
                MAX_EXPORT_INTERVAL.as_secs()
            ));
        }
        Ok(())
    }

    pub fn export_config(&self) -> RelayTelemetryExportConfig {
        self.export_config_with_runtime(RelayTelemetryRuntimeConfig::default())
    }

    pub fn export_config_with_runtime(
        &self,
        runtime: RelayTelemetryRuntimeConfig,
    ) -> RelayTelemetryExportConfig {
        self.export_config_with_runtime_and_endpoints(runtime, &MarmotServiceEndpoints::default())
    }

    pub fn export_config_with_runtime_and_endpoints(
        &self,
        runtime: RelayTelemetryRuntimeConfig,
        endpoints: &MarmotServiceEndpoints,
    ) -> RelayTelemetryExportConfig {
        RelayTelemetryExportConfig {
            enabled: self.export_enabled,
            endpoint: trim_optional(endpoints.relay_telemetry_otlp_endpoint.clone()),
            interval: Duration::from_secs(self.export_interval_seconds),
            authorization_bearer_token: None,
            resource: None,
        }
        .with_runtime_config(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export_config::RelayTelemetryResource;

    #[test]
    fn cursor_persistence_defaults_to_advance_and_is_opt_in() {
        // Only wake-collection runtimes (NSE, notification actions) may opt in
        // to the frozen posture; every other construction must keep advancing
        // the durable cursor or catch-up floors would stop tracking delivery.
        assert_eq!(
            MarmotAppConfig::default().cursor_persistence,
            CursorPersistence::Advance
        );
        assert_eq!(
            MarmotAppConfig::default()
                .with_cursor_persistence(CursorPersistence::Frozen)
                .cursor_persistence,
            CursorPersistence::Frozen
        );
    }

    #[test]
    fn allow_loopback_blob_endpoints_defaults_off_and_is_opt_in() {
        // Production builds must not act on loopback-HTTP blob endpoints unless a
        // host app explicitly opts in for dev/test.
        assert!(!MarmotAppConfig::default().allow_loopback_blob_endpoints);
        assert!(
            MarmotAppConfig::default()
                .with_allow_loopback_blob_endpoints(true)
                .allow_loopback_blob_endpoints
        );
    }

    #[test]
    fn open_ranking_provider_is_configurable_and_can_be_disabled() {
        assert_eq!(MarmotAppConfig::default().deployment.open_ranking, None);
        let default = MarmotAppConfig::white_noise();
        assert_eq!(
            default.deployment.open_ranking,
            MarmotDeployment::white_noise().open_ranking
        );

        let disabled = default.clone().with_open_ranking_provider(None, Vec::new());
        assert_eq!(disabled.deployment.open_ranking, None);
        let no_relays =
            default.with_open_ranking_provider(Some("https://rank.example".to_owned()), Vec::new());
        assert_eq!(no_relays.deployment.open_ranking, None);
    }

    #[test]
    fn telemetry_settings_default_to_opted_out_export_config() {
        let settings = RelayTelemetrySettings::default();

        assert!(!settings.export_enabled);
        assert_eq!(settings.export_interval_seconds, 60);
        assert_eq!(
            settings.export_config(),
            RelayTelemetryExportConfig::disabled()
        );
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn telemetry_settings_reject_zero_interval() {
        let settings = RelayTelemetrySettings {
            export_interval_seconds: 0,
            ..Default::default()
        };

        assert!(settings.validate().is_err());
    }

    #[test]
    fn telemetry_settings_reject_out_of_range_intervals() {
        assert!(
            RelayTelemetrySettings {
                export_interval_seconds: 9,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RelayTelemetrySettings {
                export_interval_seconds: 3_601,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            RelayTelemetrySettings {
                export_interval_seconds: 10,
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn runtime_config_builders_normalize_export_inputs() {
        let runtime = RelayTelemetryRuntimeConfig {
            otlp_endpoint: Some(" https://otlp.example.org/v1/metrics ".to_owned()),
            authorization_bearer_token: Some(" token ".to_owned()),
            resource: Some(RelayTelemetryResource {
                service_version: " 1.4.2 ".to_owned(),
                service_instance_id: " 8e1ca50b-05a2-4c31-a31c-1e69c75a9366 ".to_owned(),
                deployment_environment: " staging ".to_owned(),
                tenant: " mdk-ios ".to_owned(),
                os_type: " ios ".to_owned(),
                os_version: " 17.5 ".to_owned(),
                device_model_identifier: Some(" iPhone15,2 ".to_owned()),
            }),
        };

        let config = RelayTelemetrySettings {
            export_enabled: true,
            export_interval_seconds: 60,
        }
        .export_config_with_runtime(runtime.clone());

        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://otlp.example.org/v1/metrics")
        );
        assert_eq!(config.authorization_bearer_token.as_deref(), Some("token"));
        let resource = config.resource.as_ref().unwrap();
        assert_eq!(resource.tenant, "mdk-ios");
        assert_eq!(resource.os_type, "ios");
        assert_eq!(
            resource.device_model_identifier.as_deref(),
            Some("iPhone15,2")
        );

        let config = RelayTelemetryExportConfig::enabled("https://fallback.example/v1/metrics")
            .with_runtime_config(runtime);
        assert_eq!(
            config.endpoint.as_deref(),
            Some("https://otlp.example.org/v1/metrics")
        );
        assert_eq!(config.authorization_bearer_token.as_deref(), Some("token"));
    }
}
