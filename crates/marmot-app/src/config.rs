use std::time::Duration;

use serde::{Deserialize, Serialize};

const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
const COMPILED_RELAY_TELEMETRY_OTLP_ENDPOINT: Option<&str> =
    option_env!("MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT");
const COMPILED_AUDIT_LOG_TRACKER_ENDPOINT: Option<&str> =
    option_env!("MARMOT_AUDIT_LOG_TRACKER_ENDPOINT");
const COMPILED_ENCRYPTED_MEDIA_BLOB_ENDPOINTS: Option<&str> =
    option_env!("MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS");
pub(crate) const DEFAULT_OPEN_RANKING_SEARCH_ENDPOINT: &str =
    "https://ranking.vertexlab.io/search/pubkeys";
pub(crate) const DEFAULT_OPEN_RANKING_PROFILE_RELAY: &str = "wss://relay.vertexlab.io";

/// Policy for advancing the account's durable transport cursor
/// (`last_transport_timestamp`) from ingested deliveries.
///
/// A runtime-construction policy, not a per-call switch: it is fixed on
/// [`MarmotAppConfig`] and applies to every account client the resulting
/// `MarmotApp`/`MarmotAppRuntime` opens for that construction's lifetime.
///
/// * [`Advance`](Self::Advance) — the default, normal posture: every ingested
///   kind-445 advances the in-memory cursor (clamp-then-monotonic-max, see
///   `client/sync.rs`) and `save_state` persists the advance.
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    pub directory_max_future_skew: Duration,
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
    /// Dev/test-only override that fails invite Welcome-intent recording.
    /// Honored only with `test-policy-overrides`; this proves a canonical
    /// invite still returns success and attempts Welcome fanout.
    pub dev_fail_invite_welcome_intent: bool,
    /// Dev/test-only override that fails the app projection transaction after
    /// a founding group is already canonical. Honored only with
    /// `test-policy-overrides`; restart tests use it to exercise the sole
    /// remaining post-canonical write boundary.
    pub dev_fail_create_local_projection: bool,
    /// Dev/test-only override that fails invite local projection refresh.
    /// Honored only with `test-policy-overrides`; this proves a canonical
    /// invite still returns success and attempts Welcome fanout.
    pub dev_fail_invite_local_refresh: bool,
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

/// Compiled or app-level default service URLs for production telemetry export,
/// forensic audit-log tracker uploads, media, and optional user discovery.
///
/// Defaults are intentionally separate from bearer tokens. Host apps supply
/// credentials at runtime, while the MDK/Marmot build owns stable
/// first-party URLs. `MarmotAppConfig::default()` reads these from
/// `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` and
/// `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` at compile time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarmotServiceEndpoints {
    pub relay_telemetry_otlp_endpoint: Option<String>,
    pub audit_log_tracker_endpoint: Option<String>,
    pub encrypted_media_blob_endpoints: Vec<String>,
    /// Public, unencrypted profile-image upload endpoint. The resulting URL is
    /// published in kind:0 metadata, so hosts with different privacy or
    /// availability requirements should override the built-in service.
    pub profile_image_blob_endpoint: Option<String>,
    /// Optional ORE-05 pubkey search endpoint. `None` disables off-graph
    /// provider discovery without affecting the personal graph search.
    pub open_ranking_search_endpoint: Option<String>,
    /// Relays used only to hydrate provider-returned pubkeys into signed kind-0
    /// profiles. An empty list disables provider discovery.
    pub open_ranking_profile_relays: Vec<String>,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
            service_endpoints: MarmotServiceEndpoints::compiled(),
            cursor_persistence: CursorPersistence::Advance,
            allow_loopback_blob_endpoints: false,
            allow_loopback_relay_endpoints: false,
            dev_settlement_quiescence_ms: None,
            dev_scheduled_convergence_delay_ms: None,
            dev_startup_hydration_batch_delay_ms: None,
            dev_force_group_read_snapshot_failure: false,
            dev_fail_invite_welcome_intent: false,
            dev_fail_create_local_projection: false,
            dev_fail_invite_local_refresh: false,
            dev_fail_sync_before_delivery: None,
            dev_fail_sync_before_boundary_save: None,
            dev_fail_ingest_after_application_event_ack: false,
            directory_search_fallback_seeds: Vec::new(),
        }
    }
}

impl MarmotAppConfig {
    pub fn with_directory_max_future_skew(mut self, skew: Duration) -> Self {
        self.directory_max_future_skew = skew;
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
        self.service_endpoints.open_ranking_search_endpoint = search_endpoint;
        self.service_endpoints.open_ranking_profile_relays = profile_relays;
        self.service_endpoints = self.service_endpoints.normalize();
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

    /// Fail invite Welcome-intent recording in test-policy builds.
    /// Normal builds ignore this field.
    pub fn with_dev_fail_invite_welcome_intent(mut self, enabled: bool) -> Self {
        self.dev_fail_invite_welcome_intent = enabled;
        self
    }

    pub fn with_dev_fail_create_local_projection(mut self, enabled: bool) -> Self {
        self.dev_fail_create_local_projection = enabled;
        self
    }

    /// Fail invite local projection refresh in test-policy builds.
    /// Normal builds ignore this field.
    pub fn with_dev_fail_invite_local_refresh(mut self, enabled: bool) -> Self {
        self.dev_fail_invite_local_refresh = enabled;
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
}

impl MarmotServiceEndpoints {
    pub fn compiled() -> Self {
        Self {
            relay_telemetry_otlp_endpoint: COMPILED_RELAY_TELEMETRY_OTLP_ENDPOINT
                .map(str::to_owned),
            audit_log_tracker_endpoint: COMPILED_AUDIT_LOG_TRACKER_ENDPOINT.map(str::to_owned),
            encrypted_media_blob_endpoints: COMPILED_ENCRYPTED_MEDIA_BLOB_ENDPOINTS
                .map(split_endpoint_list)
                .unwrap_or_default(),
            profile_image_blob_endpoint: Some(
                crate::media::DEFAULT_PROFILE_IMAGE_BLOSSOM_SERVER_URL.to_owned(),
            ),
            open_ranking_search_endpoint: Some(DEFAULT_OPEN_RANKING_SEARCH_ENDPOINT.to_owned()),
            open_ranking_profile_relays: vec![DEFAULT_OPEN_RANKING_PROFILE_RELAY.to_owned()],
        }
        .normalize()
    }

    pub fn normalize(mut self) -> Self {
        self.relay_telemetry_otlp_endpoint = trim_optional(self.relay_telemetry_otlp_endpoint);
        self.audit_log_tracker_endpoint = trim_optional(self.audit_log_tracker_endpoint);
        self.encrypted_media_blob_endpoints =
            normalize_endpoint_list(self.encrypted_media_blob_endpoints);
        self.profile_image_blob_endpoint = trim_optional(self.profile_image_blob_endpoint);
        self.open_ranking_search_endpoint = trim_optional(self.open_ranking_search_endpoint);
        self.open_ranking_profile_relays =
            normalize_endpoint_list(self.open_ranking_profile_relays);
        self
    }
}

/// Default export poll/push interval. Coarse on purpose: the data is
/// aggregate and cumulative, so a coarse window respects battery and metered
/// networks without losing resolution.
const DEFAULT_EXPORT_INTERVAL: Duration = Duration::from_secs(60);
const MIN_EXPORT_INTERVAL: Duration = Duration::from_secs(10);
const MAX_EXPORT_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayTelemetrySettings {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTelemetryResource {
    pub service_version: String,
    pub service_instance_id: String,
    pub deployment_environment: String,
    pub tenant: String,
    pub os_type: String,
    pub os_version: String,
    pub device_model_identifier: Option<String>,
}

/// Hand-written `Debug` below redacts `authorization_bearer_token` (the OTLP
/// push credential) so a `{:?}` never prints it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RelayTelemetryRuntimeConfig {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResource>,
}

impl std::fmt::Debug for RelayTelemetryRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTelemetryRuntimeConfig")
            .field("otlp_endpoint", &self.otlp_endpoint)
            .field(
                "authorization_bearer_token",
                &self
                    .authorization_bearer_token
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("resource", &self.resource)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditLogUploadSource {
    pub device_label: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
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

impl RelayTelemetryResource {
    fn has_required_attributes(&self) -> bool {
        [
            self.service_version.as_str(),
            self.service_instance_id.as_str(),
            self.deployment_environment.as_str(),
            self.tenant.as_str(),
            self.os_type.as_str(),
            self.os_version.as_str(),
        ]
        .into_iter()
        .all(|value| !value.trim().is_empty())
    }

    fn normalize(mut self) -> Result<Self, String> {
        self.service_version = trim_required("service.version", self.service_version)?;
        self.service_instance_id = trim_required("service.instance.id", self.service_instance_id)?;
        self.deployment_environment =
            trim_required("deployment.environment.name", self.deployment_environment)?;
        self.tenant = trim_required("tenant", self.tenant)?;
        self.os_type = trim_required("os.type", self.os_type)?;
        self.os_version = trim_required("os.version", self.os_version)?;
        self.device_model_identifier = self.device_model_identifier.and_then(|value| {
            let value = value.trim().to_owned();
            (!value.is_empty()).then_some(value)
        });
        Ok(self)
    }
}

impl RelayTelemetryRuntimeConfig {
    pub(crate) fn normalize(mut self) -> Result<Self, String> {
        self.otlp_endpoint = trim_optional(self.otlp_endpoint);
        self.authorization_bearer_token = trim_optional(self.authorization_bearer_token);
        self.resource = self
            .resource
            .map(RelayTelemetryResource::normalize)
            .transpose()?;
        Ok(self)
    }

    fn normalize_for_export(mut self) -> Self {
        self.otlp_endpoint = trim_optional(self.otlp_endpoint);
        self.authorization_bearer_token = trim_optional(self.authorization_bearer_token);
        self.resource = self
            .resource
            .and_then(|resource| RelayTelemetryResource::normalize(resource).ok());
        self
    }
}

impl AuditLogUploadSource {
    fn normalize(mut self) -> Self {
        self.device_label = trim_optional(self.device_label);
        self.platform = trim_optional(self.platform);
        self.app_version = trim_optional(self.app_version);
        self
    }
}

impl AuditLogTrackerConfig {
    pub(crate) fn normalize(mut self) -> Result<Self, String> {
        self.endpoint = trim_optional(self.endpoint);
        self.authorization_bearer_token = trim_optional(self.authorization_bearer_token);
        self.source = self.source.normalize();
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

fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn split_endpoint_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_endpoint_list(values: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim().to_owned();
        if !value.is_empty() && !normalized.iter().any(|existing| existing == &value) {
            normalized.push(value);
        }
    }
    normalized
}

fn trim_required(name: &str, value: String) -> Result<String, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
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
        let runtime = runtime.normalize_for_export();
        RelayTelemetryExportConfig {
            enabled: self.export_enabled,
            endpoint: runtime
                .otlp_endpoint
                .or_else(|| trim_optional(endpoints.relay_telemetry_otlp_endpoint.clone())),
            interval: Duration::from_secs(self.export_interval_seconds),
            authorization_bearer_token: runtime.authorization_bearer_token,
            resource: runtime.resource,
        }
    }
}

/// Opt-in configuration for relay-telemetry export.
///
/// Off by default. While `enabled` is `false` nothing is resolved or exported
/// and the app behaves exactly as today. This is the single opt-in switch that
/// gates relay-identity resolution and the OTLP exporter — see the privacy
/// contract in `docs/marmot-architecture/relay-observability.md`.
///
/// The `endpoint` must be the full first-party Marmot-operated OTLP/HTTP
/// metrics URL reached over TLS (`https`). Plain `http` is accepted only for
/// loopback collectors used in local testing, so anything that actually leaves
/// the device stays on TLS. Export is inert without an endpoint, and the
/// exporter is not constructed for a non-TLS, non-loopback endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayTelemetryExportConfig {
    /// Whether the user has opted in to relay-telemetry export. Off by default.
    pub enabled: bool,
    /// Full first-party OTLP/HTTP metrics URL. Must be `https`, except a
    /// loopback `http` collector for local testing. `None` keeps export inert
    /// even when `enabled`.
    pub endpoint: Option<String>,
    /// How often to poll the rollup and push.
    pub interval: Duration,
    /// Bearer token supplied by the host app at runtime from its build-time
    /// platform secret. Never persisted by Marmot.
    pub authorization_bearer_token: Option<String>,
    /// Resource attributes supplied by the host app at runtime. Never persisted
    /// by Marmot because these describe the binary/device shell.
    pub resource: Option<RelayTelemetryResource>,
}

impl Default for RelayTelemetryExportConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl RelayTelemetryExportConfig {
    /// A disabled (opt-out) configuration. This is also [`Default`].
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            interval: DEFAULT_EXPORT_INTERVAL,
            authorization_bearer_token: None,
            resource: None,
        }
    }

    /// An opted-in configuration pushing to `endpoint` at the default interval.
    pub fn enabled(endpoint: impl Into<String>) -> Self {
        Self {
            enabled: true,
            endpoint: Some(endpoint.into()),
            interval: DEFAULT_EXPORT_INTERVAL,
            authorization_bearer_token: None,
            resource: None,
        }
    }

    /// Override the poll/push interval.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_runtime_config(mut self, runtime: RelayTelemetryRuntimeConfig) -> Self {
        let runtime = runtime.normalize_for_export();
        self.endpoint = runtime.otlp_endpoint.or(self.endpoint);
        self.authorization_bearer_token = runtime.authorization_bearer_token;
        self.resource = runtime.resource;
        self
    }

    /// Whether export may actually run: opted in, an endpoint is configured, and
    /// that endpoint is reachable over TLS (`https`). Plain `http` is allowed
    /// only for loopback collectors used in local testing, so the privacy
    /// contract's TLS requirement holds for anything that leaves the device.
    ///
    /// This is the single gate condition shared by `telemetry_exporter` and
    /// relay-identity resolution.
    pub(crate) fn export_allowed(&self) -> bool {
        self.enabled
            && self
                .endpoint
                .as_deref()
                .is_some_and(endpoint_transport_allowed)
            && self
                .authorization_bearer_token
                .as_deref()
                .is_some_and(|token| !token.trim().is_empty())
            && self
                .resource
                .as_ref()
                .is_some_and(RelayTelemetryResource::has_required_attributes)
    }
}

/// Accept `https` for any host; accept `http` only for a loopback host (a local
/// test collector). Reject anything else, including unparseable endpoints.
pub(crate) fn endpoint_transport_allowed(endpoint: &str) -> bool {
    let Ok(url) = url::Url::parse(endpoint) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => url.host().is_some_and(host_is_loopback),
        _ => false,
    }
}

pub(crate) fn endpoint_host_is_loopback(endpoint: &str) -> bool {
    url::Url::parse(endpoint)
        .ok()
        .and_then(|url| url.host().map(host_is_loopback))
        .unwrap_or(false)
}

fn host_is_loopback(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(addr) => addr.is_loopback(),
        url::Host::Ipv6(addr) => addr.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let default = MarmotAppConfig::default();
        assert_eq!(
            default
                .service_endpoints
                .open_ranking_search_endpoint
                .as_deref(),
            Some(DEFAULT_OPEN_RANKING_SEARCH_ENDPOINT)
        );
        assert_eq!(
            default.service_endpoints.open_ranking_profile_relays,
            vec![DEFAULT_OPEN_RANKING_PROFILE_RELAY]
        );

        let disabled = default.with_open_ranking_provider(None, Vec::new());
        assert_eq!(
            disabled.service_endpoints.open_ranking_search_endpoint,
            None
        );
        assert!(
            disabled
                .service_endpoints
                .open_ranking_profile_relays
                .is_empty()
        );
    }

    fn runtime_config() -> RelayTelemetryRuntimeConfig {
        RelayTelemetryRuntimeConfig {
            otlp_endpoint: None,
            authorization_bearer_token: Some("token".to_owned()),
            resource: Some(RelayTelemetryResource {
                service_version: "1.4.2".to_owned(),
                service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
                deployment_environment: "staging".to_owned(),
                tenant: "mdk-ios".to_owned(),
                os_type: "ios".to_owned(),
                os_version: "17.5".to_owned(),
                device_model_identifier: None,
            }),
        }
    }

    #[test]
    fn export_allowed_requires_opt_in_endpoint_and_tls() {
        // Off by default, and an endpoint alone does not enable export.
        assert!(!RelayTelemetryExportConfig::disabled().export_allowed());
        assert!(
            !RelayTelemetryExportConfig {
                enabled: true,
                endpoint: None,
                authorization_bearer_token: Some("token".to_owned()),
                resource: runtime_config().resource,
                ..Default::default()
            }
            .export_allowed()
        );

        // https is accepted; plain http to a remote host is rejected.
        assert!(
            RelayTelemetryExportConfig::enabled("https://otlp.example.org/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            !RelayTelemetryExportConfig::enabled("http://otlp.example.org/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            !RelayTelemetryExportConfig::enabled("ftp://otlp.example.org/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            !RelayTelemetryExportConfig::enabled("not a url")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            !RelayTelemetryExportConfig::enabled("https://otlp.example.org/v1/metrics")
                .export_allowed()
        );

        // http is allowed only for loopback collectors (local testing).
        assert!(
            RelayTelemetryExportConfig::enabled("http://127.0.0.1:4318/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            RelayTelemetryExportConfig::enabled("http://[::1]:4318/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
        assert!(
            RelayTelemetryExportConfig::enabled("http://localhost:4318/v1/metrics")
                .with_runtime_config(runtime_config())
                .export_allowed()
        );
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
