//! Opt-in, bounded product observations. No account, message or transport identities enter this module.

use crate::{AppError, MarmotApp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

static CATALOGUE: std::sync::LazyLock<serde_json::Value> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../../docs/marmot-architecture/product-event-catalogue.json"
    ))
    .expect("checked-in product catalogue")
});

mod builtins;
mod catalogue;
pub use builtins::approved_host_product_schemas;
pub use catalogue::*;
#[cfg(feature = "product-analytics-export")]
mod delivery;
#[cfg(test)]
mod tests;

pub const USAGE_DIAGNOSTICS_DISCLOSURE: &str = "Optional usage and diagnostics helps the app operator understand feature use and reliability. Usage contains approved, bucketed activity and temporary session IDs, without message contents or account/group identifiers. Our Aptabase server receives your IP address, uses IP/user-agent information for daily activity grouping, and adds approximate country/region. Diagnostics includes a random installation identifier stable until you turn sharing off. Turning this off stops both pipelines; already transmitted data cannot be recalled. Audit logging is separate. Retention depends on the operator's verified deployment settings.";
pub const USAGE_DIAGNOSTICS_POLICY: &str = "usage-diagnostics-v1";
pub const PRODUCT_REGISTRY_VERSION: &str = "mdk-product-v1";
pub const PRODUCT_DURATION_BOUNDS_MS: [u64; 15] = [
    10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000, 60000, 300000, 900000, 3600000,
];
const WINDOW_SECONDS: u64 = 900;
const MAX_CELLS: usize = 256;
const MAX_EVENTS: usize = 512;
const MAX_QUEUE_BYTES: usize = 256 * 1024;
const MAX_EVENT_BYTES: usize = 2048;
const EVENT_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone, Debug, thiserror::Error)]
pub enum ProductAnalyticsError {
    #[error("usage and diagnostics consent required")]
    ConsentRequired,
    #[error("invalid product analytics configuration")]
    InvalidConfiguration,
    #[error("unregistered or invalid product observation")]
    InvalidEvent,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageDiagnosticsDecision {
    #[default]
    AcceptanceRequired,
    Declined,
    Granted,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageDiagnosticsSettings {
    pub decision: UsageDiagnosticsDecision,
    pub policy_revision: String,
    pub registry_revision: String,
    pub updated_at_ms: i64,
    pub previously_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductEventMode {
    Journey,
    Aggregate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductPropertyRule {
    Enum(Vec<String>),
    Boolean,
    CountBucket,
    DurationBucket,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductPropertySchema {
    pub name: String,
    pub rule: ProductPropertyRule,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductEventSchema {
    pub name: String,
    pub mode: ProductEventMode,
    pub properties: Vec<ProductPropertySchema>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductEvent {
    pub name: String,
    pub properties: BTreeMap<String, String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductAnalyticsActivity {
    Foreground,
    Background,
    AccountChanged,
    ForegroundNotification,
    ForegroundDeepLink,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProductRecordResult {
    Recorded,
    IgnoredDisabled,
    IgnoredUnconfigured,
    IgnoredDuplicate,
    DroppedCapacity,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticsExporterStatus {
    #[default]
    Disabled,
    ConsentRequired,
    Unconfigured,
    UnsupportedBuild,
    Ready,
    ConfigurationRejected,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageDiagnosticsStatus {
    pub consent: UsageDiagnosticsDecision,
    pub telemetry: DiagnosticsExporterStatus,
    pub product_analytics: DiagnosticsExporterStatus,
    pub queued_events: u64,
    pub dropped_events: u64,
    pub accepted_batches: u64,
    pub failed_batches: u64,
}

/// Trusted, build-defined metadata. No device model, locale or arbitrary resource map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAnalyticsMetadata {
    pub app_version: String,
    pub os_family: String,
    pub os_major_version: String,
    pub device_class: String,
    pub host_surface: String,
    pub environment: String,
    pub is_debug: bool,
}
/// Write-only ingestion configuration. App keys and endpoints never appear in Debug output.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductAnalyticsRuntimeConfig {
    pub events_endpoint: Option<String>,
    pub app_key: Option<String>,
    pub metadata: ProductAnalyticsMetadata,
    pub registry: Vec<ProductEventSchema>,
    pub allow_loopback: bool,
    /// Stable operator label shown in host consent disclosure; changing it requires acceptance.
    pub operator: String,
}
impl std::fmt::Debug for ProductAnalyticsRuntimeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductAnalyticsRuntimeConfig")
            .field("configured", &self.events_endpoint.is_some())
            .finish_non_exhaustive()
    }
}
impl ProductAnalyticsRuntimeConfig {
    fn validate(&self) -> Result<(), ProductAnalyticsError> {
        let invalid = || ProductAnalyticsError::InvalidConfiguration;
        if self.registry.len() > 32 {
            return Err(invalid());
        }
        let mut names = BTreeSet::new();
        for schema in &self.registry {
            if approved_host_product_schemas()
                .iter()
                .any(|v| v.name == schema.name)
                || !schema.name.starts_with("app_")
                || !label(&schema.name, 60)
                || !names.insert(&schema.name)
                || schema.properties.len() > 8
            {
                return Err(invalid());
            }
            let mut keys = BTreeSet::new();
            for prop in &schema.properties {
                if [
                    "account_id",
                    "group_id",
                    "message_id",
                    "pubkey",
                    "email",
                    "url",
                    "relay_url",
                    "ip",
                    "address",
                    "token",
                    "filename",
                    "hash",
                    "content",
                    "text",
                    "query",
                    "search_term",
                    "emoji",
                    "prompt",
                    "output",
                    "arguments",
                    "install_id",
                    "device_id",
                ]
                .contains(&prop.name.as_str())
                    || !label(&prop.name, 40)
                    || !keys.insert(&prop.name)
                    || matches!(
                        prop.name.as_str(),
                        "schema_version"
                            | "unit"
                            | "count_bucket"
                            | "partial"
                            | "duration_bucket"
                            | "device_class"
                            | "host_surface"
                            | "environment"
                    )
                {
                    return Err(invalid());
                }
                if let ProductPropertyRule::Enum(values) = &prop.rule
                    && (values.is_empty()
                        || values.len() > 16
                        || values.iter().any(|v| !label(v, 180))
                        || values.iter().collect::<BTreeSet<_>>().len() != values.len())
                {
                    return Err(invalid());
                }
            }
        }
        if let Some(endpoint) = &self.events_endpoint {
            let url =
                crate::config::parse_relay_telemetry_endpoint(endpoint).ok_or_else(invalid)?;
            if url.query().is_some()
                || (crate::config::endpoint_host_is_loopback(endpoint) && !self.allow_loopback)
            {
                return Err(invalid());
            }
        }
        if let Some(key) = &self.app_key
            && (key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(invalid());
        }
        if self.events_endpoint.is_some() && self.app_key.is_some() {
            let m = &self.metadata;
            if !label(&self.operator, 80)
                || m.app_version.is_empty()
                || m.app_version.len() > 50
                || !m
                    .app_version
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'.')
                || !matches!(
                    m.os_family.as_str(),
                    "ios" | "macos" | "android" | "linux" | "windows" | "other"
                )
                || m.os_major_version.len() > 4
                || !m.os_major_version.bytes().all(|b| b.is_ascii_digit())
                || !matches!(
                    m.device_class.as_str(),
                    "phone" | "tablet" | "desktop" | "headless" | "other"
                )
                || !matches!(
                    m.host_surface.as_str(),
                    "native" | "daemon" | "agent" | "other"
                )
                || !matches!(
                    m.environment.as_str(),
                    "production" | "staging" | "development"
                )
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
    fn ready(&self) -> bool {
        self.events_endpoint.is_some() && self.app_key.is_some()
    }
    fn registry_revision(&self) -> String {
        let mut registry = self.registry.clone();
        registry.sort_by(|a, b| a.name.cmp(&b.name));
        for s in &mut registry {
            s.properties.sort_by(|a, b| a.name.cmp(&b.name));
            for p in &mut s.properties {
                if let ProductPropertyRule::Enum(values) = &mut p.rule {
                    values.sort();
                }
            }
        }
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(
                PRODUCT_REGISTRY_VERSION,
                registry,
                approved_host_product_schemas(),
                ProductFamily::ALL
                    .iter()
                    .map(|family| (family.as_str(), family.operations()))
                    .collect::<Vec<_>>(),
                PRODUCT_OUTCOMES,
                PRODUCT_DURATION_BOUNDS_MS,
                CATALOGUE["events"]
                    .as_array()
                    .expect("catalogue events")
                    .iter()
                    .map(|event| {
                        (
                            &event["name"],
                            &event["mode"],
                            &event["properties"],
                            &event["units"],
                        )
                    })
                    .collect::<Vec<_>>(),
            ))
            .unwrap_or_default(),
        ))
    }
}
fn label(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn valid_property(rule: &ProductPropertyRule, value: &str) -> bool {
    match rule {
        ProductPropertyRule::Enum(values) => values.iter().any(|choice| choice == value),
        ProductPropertyRule::Boolean => matches!(value, "true" | "false"),
        ProductPropertyRule::CountBucket => [1, 2, 3, 6, 11, 21, 51, 101, 251, 1001]
            .iter()
            .any(|n| product_count_bucket(*n) == value),
        ProductPropertyRule::DurationBucket => PRODUCT_DURATION_BOUNDS_MS
            .iter()
            .copied()
            .chain([3600001])
            .any(|n| product_duration_bucket(Duration::from_millis(n)) == value),
    }
}
pub fn product_count_bucket(count: u64) -> &'static str {
    match count {
        0 => "0",
        1 => "1",
        2 => "2",
        3..=5 => "3_5",
        6..=10 => "6_10",
        11..=20 => "11_20",
        21..=50 => "21_50",
        51..=100 => "51_100",
        101..=250 => "101_250",
        251..=1000 => "251_1000",
        _ => "1001_plus",
    }
}
pub fn product_duration_bucket(duration: Duration) -> &'static str {
    const NAMES: [&str; 16] = [
        "le_10ms", "le_25ms", "le_50ms", "le_100ms", "le_250ms", "le_500ms", "le_1s", "le_2s",
        "le_5s", "le_10s", "le_30s", "le_1m", "le_5m", "le_15m", "le_60m", "gt_60m",
    ];
    NAMES[PRODUCT_DURATION_BOUNDS_MS
        .iter()
        .position(|v| duration.as_nanos() <= u128::from(*v) * 1_000_000)
        .unwrap_or(15)]
}

trait AnalyticsClock: Send + Sync {
    fn wall_seconds(&self) -> u64;
    fn monotonic(&self) -> Duration;
    fn uuid(&self) -> String;
}
struct SystemClock(Instant);
impl AnalyticsClock for SystemClock {
    fn wall_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
    fn monotonic(&self) -> Duration {
        self.0.elapsed()
    }
    fn uuid(&self) -> String {
        crate::generate_telemetry_install_id()
    }
}

/// Captures the grant; clones cannot become valid again after revocation.
#[derive(Clone)]
pub struct DiagnosticsPermit {
    #[cfg_attr(not(feature = "otlp-export"), allow(dead_code))]
    controller: Arc<Mutex<State>>,
    generation: u64,
    current: Arc<AtomicU64>,
    cancel: CancellationToken,
    pub(crate) diagnostic_id: String,
    #[cfg_attr(not(feature = "otlp-export"), allow(dead_code))]
    pub(crate) telemetry_rejected: Arc<AtomicBool>,
}
impl DiagnosticsPermit {
    #[cfg(feature = "otlp-export")]
    pub(crate) fn reject_telemetry(&self) {
        let _state = self
            .controller
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.valid() {
            self.telemetry_rejected.store(true, Ordering::Release);
        }
    }
    pub(crate) fn valid(&self) -> bool {
        self.current.load(Ordering::Acquire) == self.generation && !self.cancel.is_cancelled()
    }
    pub(crate) async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }
}
#[derive(Clone)]
pub struct ProductAnalytics {
    inner: Arc<Mutex<State>>,
    clock: Arc<dyn AnalyticsClock>,
    generation: Arc<AtomicU64>,
    pub(crate) telemetry_rejected: Arc<AtomicBool>,
    #[cfg_attr(not(feature = "product-analytics-export"), allow(dead_code))]
    send_lock: Arc<tokio::sync::Mutex<()>>,
    consent_lock: Arc<Mutex<()>>,
}
struct State {
    config: ProductAnalyticsRuntimeConfig,
    registry_revision: String,
    settings: UsageDiagnosticsSettings,
    diagnostic_id: String,
    scope: String,
    telemetry_origin: String,
    persistence_failed: bool,
    silent: bool,
    cancel: CancellationToken,
    granted_at: Duration,
    window: Option<(u64, Duration, bool)>,
    availability: Option<&'static str>,
    last_clock: Option<(u64, Duration)>,
    cells: BTreeMap<(String, BTreeMap<String, String>), u64>,
    backlog: BTreeMap<(String, BTreeMap<String, String>), BTreeMap<u64, u64>>,
    queue: VecDeque<QueuedEvent>,
    queue_bytes: usize,
    session: Option<(String, Duration, Duration)>,
    seen: BTreeSet<String>,
    foreground: bool,
    status: UsageDiagnosticsStatus,
}
#[derive(Clone)]
struct QueuedEvent {
    #[cfg_attr(not(feature = "product-analytics-export"), allow(dead_code))]
    payload: serde_json::Value,
    bytes: usize,
    created: Duration,
}
impl Default for ProductAnalytics {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                config: ProductAnalyticsRuntimeConfig::default(),
                registry_revision: ProductAnalyticsRuntimeConfig::default().registry_revision(),
                settings: UsageDiagnosticsSettings::default(),
                diagnostic_id: String::new(),
                scope: Self::scope(&ProductAnalyticsRuntimeConfig::default(), "", ""),
                telemetry_origin: String::new(),
                persistence_failed: false,
                silent: false,
                cancel: CancellationToken::new(),
                granted_at: Duration::ZERO,
                window: None,
                availability: None,
                last_clock: None,
                cells: BTreeMap::new(),
                backlog: BTreeMap::new(),
                queue: VecDeque::new(),
                queue_bytes: 0,
                session: None,
                seen: BTreeSet::new(),
                foreground: false,
                status: UsageDiagnosticsStatus::default(),
            })),
            clock: Arc::new(SystemClock(Instant::now())),
            generation: Arc::new(AtomicU64::new(0)),
            telemetry_rejected: Arc::new(AtomicBool::new(false)),
            send_lock: Arc::new(tokio::sync::Mutex::new(())),
            consent_lock: Arc::new(Mutex::new(())),
        }
    }
}
impl ProductAnalytics {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn invalidate(&self, s: &mut State) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        s.cancel.cancel();
        s.cancel = CancellationToken::new();
        s.queue.clear();
        s.queue_bytes = 0;
        s.cells.clear();
        s.backlog.clear();
        s.window = None;
        s.availability = None;
        s.session = None;
        s.seen.clear();
        s.last_clock = None;
        // Lifecycle state is not an observation. Preserve it across consent changes.
        s.diagnostic_id.clear();
    }
    pub(crate) fn permit(&self) -> Option<DiagnosticsPermit> {
        let s = self.lock();
        if s.silent
            || s.persistence_failed
            || s.settings.decision != UsageDiagnosticsDecision::Granted
        {
            return None;
        }
        Some(DiagnosticsPermit {
            controller: self.inner.clone(),
            generation: self.generation.load(Ordering::Acquire),
            current: self.generation.clone(),
            cancel: s.cancel.clone(),
            diagnostic_id: s.diagnostic_id.clone(),
            telemetry_rejected: self.telemetry_rejected.clone(),
        })
    }
    pub(crate) fn silence(&self, silent: bool) {
        let mut s = self.lock();
        if s.silent != silent {
            self.invalidate(&mut s);
            s.silent = silent;
        }
    }
    pub(crate) fn revoke_memory(&self) {
        let mut s = self.lock();
        self.invalidate(&mut s);
        s.settings.decision = UsageDiagnosticsDecision::Declined;
    }
    pub(crate) fn set_receipt(&self, receipt: UsageDiagnosticsSettings, diagnostic_id: String) {
        let mut s = self.lock();
        if s.settings.decision != UsageDiagnosticsDecision::Granted
            || receipt.decision != UsageDiagnosticsDecision::Granted
        {
            self.telemetry_rejected.store(false, Ordering::Release);
        }
        self.invalidate(&mut s);
        s.settings = receipt;
        s.diagnostic_id = diagnostic_id;
        s.granted_at = self.clock.monotonic();
    }
    pub(crate) fn configure(
        &self,
        config: ProductAnalyticsRuntimeConfig,
        scope: String,
    ) -> Result<(), ProductAnalyticsError> {
        config.validate()?;
        let registry_revision = config.registry_revision();
        let _consent = self.consent_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = self.lock();
        self.invalidate(&mut s);
        s.config = config;
        s.registry_revision = registry_revision;
        s.scope = Self::scope(&s.config, &scope, &s.telemetry_origin);
        s.status = UsageDiagnosticsStatus::default();
        Ok(())
    }
    fn scope(
        config: &ProductAnalyticsRuntimeConfig,
        product_origin: &str,
        telemetry_origin: &str,
    ) -> String {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(product_origin, telemetry_origin, &config.operator))
                .unwrap_or_default(),
        ))
    }
    pub(crate) fn telemetry_origin(&self, endpoint: Option<&str>) {
        let mut s = self.lock();
        let origin = endpoint
            .and_then(|v| url::Url::parse(v).ok())
            .map(|v| v.origin().ascii_serialization())
            .unwrap_or_default();
        if s.telemetry_origin != origin {
            self.invalidate(&mut s);
            s.telemetry_origin = origin;
        }
        let product = s
            .config
            .events_endpoint
            .as_deref()
            .and_then(|v| url::Url::parse(v).ok())
            .map(|v| v.origin().ascii_serialization())
            .unwrap_or_default();
        s.scope = Self::scope(&s.config, &product, &s.telemetry_origin);
    }
    pub fn settings(&self) -> UsageDiagnosticsSettings {
        self.lock().settings.clone()
    }
    pub fn status(&self) -> UsageDiagnosticsStatus {
        let s = self.lock();
        let mut status = s.status.clone();
        status.consent = s.settings.decision.clone();
        status.queued_events = s.queue.len() as u64;
        status.product_analytics = if s.persistence_failed
            || s.silent
            || s.settings.decision == UsageDiagnosticsDecision::Declined
        {
            DiagnosticsExporterStatus::Disabled
        } else if s.settings.decision != UsageDiagnosticsDecision::Granted {
            DiagnosticsExporterStatus::ConsentRequired
        } else if !cfg!(feature = "product-analytics-export") {
            DiagnosticsExporterStatus::UnsupportedBuild
        } else if !s.config.ready() {
            DiagnosticsExporterStatus::Unconfigured
        } else if status.product_analytics == DiagnosticsExporterStatus::ConfigurationRejected {
            DiagnosticsExporterStatus::ConfigurationRejected
        } else {
            DiagnosticsExporterStatus::Ready
        };
        status
    }
    fn enabled(s: &State) -> bool {
        cfg!(feature = "product-analytics-export")
            && !s.persistence_failed
            && !s.silent
            && s.settings.decision == UsageDiagnosticsDecision::Granted
            && s.config.ready()
            && s.status.product_analytics != DiagnosticsExporterStatus::ConfigurationRejected
    }
    fn advance(&self, s: &mut State) {
        let wall = self.clock.wall_seconds();
        let mono = self.clock.monotonic();
        let jump = s.last_clock.is_some_and(|(w, m)| {
            wall.abs_diff(w.saturating_add(mono.saturating_sub(m).as_secs())) > 60
        });
        if s.window.is_some_and(|(w, _, _)| w != wall / WINDOW_SECONDS) || jump {
            self.seal(s, jump);
        }
        s.last_clock = Some((wall, mono));
        if s.window.is_none() {
            s.window = Some((
                wall / WINDOW_SECONDS,
                mono,
                !wall.is_multiple_of(WINDOW_SECONDS),
            ));
        }
        while s
            .queue
            .front()
            .is_some_and(|e| mono.saturating_sub(e.created) >= EVENT_TTL)
        {
            self.drop_front(s);
        }
    }
    fn drop_front(&self, s: &mut State) {
        if let Some(e) = s.queue.pop_front() {
            s.queue_bytes -= e.bytes;
            s.status.dropped_events = s.status.dropped_events.saturating_add(1);
        }
    }
    fn enqueue(
        &self,
        s: &mut State,
        name: &str,
        props: BTreeMap<String, String>,
        session: &str,
        timestamp: u64,
    ) {
        let m = &s.config.metadata;
        let payload = serde_json::json!({"timestamp":chrono::DateTime::from_timestamp(timestamp as i64,0).unwrap_or_default().to_rfc3339_opts(chrono::SecondsFormat::Secs,true),"sessionId":session,"eventName":name,
            "systemProps":{"appVersion":m.app_version,"osName":m.os_family,"osVersion":m.os_major_version,"isDebug":m.is_debug,"sdkVersion":concat!("mdk@",env!("CARGO_PKG_VERSION"))},
            "props":props.into_iter().chain([("schema_version".into(),PRODUCT_REGISTRY_VERSION.into()),("device_class".into(),m.device_class.clone()),("host_surface".into(),m.host_surface.clone()),("environment".into(),m.environment.clone())]).collect::<BTreeMap<_,_>>()});
        if !self.valid_payload(&s.config, &payload) {
            s.status.dropped_events = s.status.dropped_events.saturating_add(1);
            return;
        }
        let bytes = serde_json::to_vec(&payload).map_or(MAX_EVENT_BYTES + 1, |b| b.len());
        if bytes > MAX_EVENT_BYTES {
            s.status.dropped_events = s.status.dropped_events.saturating_add(1);
            return;
        }
        while s.queue.len() >= MAX_EVENTS || s.queue_bytes + bytes > MAX_QUEUE_BYTES {
            self.drop_front(s);
        }
        s.queue_bytes += bytes;
        s.queue.push_back(QueuedEvent {
            payload,
            bytes,
            created: self.clock.monotonic(),
        });
    }
    fn valid_payload(
        &self,
        config: &ProductAnalyticsRuntimeConfig,
        payload: &serde_json::Value,
    ) -> bool {
        let Some(envelope) = payload.as_object() else {
            return false;
        };
        if envelope.len() != 5
            || envelope.keys().any(|key| {
                ![
                    "eventName",
                    "timestamp",
                    "sessionId",
                    "systemProps",
                    "props",
                ]
                .contains(&key.as_str())
            })
        {
            return false;
        }
        let metadata = &config.metadata;
        if payload["systemProps"]
            != serde_json::json!({
                "appVersion": metadata.app_version, "osName": metadata.os_family,
                "osVersion": metadata.os_major_version, "isDebug": metadata.is_debug,
                "sdkVersion": concat!("mdk@", env!("CARGO_PKG_VERSION")),
            })
        {
            return false;
        }
        let Some(name) = payload.get("eventName").and_then(|v| v.as_str()) else {
            return false;
        };
        let Some(session) = payload.get("sessionId").and_then(|v| v.as_str()) else {
            return false;
        };
        let Some(stamp) = payload
            .get("timestamp")
            .and_then(|v| v.as_str())
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        else {
            return false;
        };
        let now = self.clock.wall_seconds();
        let seconds = stamp.timestamp();
        if seconds < 0
            || seconds as u64 > now.saturating_add(600)
            || now.saturating_sub(seconds as u64) > 86400
        {
            return false;
        }
        if !label(name, 60)
            || session.len() != 36
            || session.as_bytes()[14] != b'4'
            || !matches!(session.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
            || !session.bytes().enumerate().all(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            })
        {
            return false;
        }
        let Some(props) = payload.get("props").and_then(|v| v.as_object()) else {
            return false;
        };
        let common = BTreeMap::from([
            ("schema_version", PRODUCT_REGISTRY_VERSION),
            ("device_class", metadata.device_class.as_str()),
            ("host_surface", metadata.host_surface.as_str()),
            ("environment", metadata.environment.as_str()),
        ]);
        if common
            .iter()
            .any(|(key, value)| props.get(*key).and_then(|v| v.as_str()) != Some(*value))
        {
            return false;
        }
        // Repeat the closed-schema check at serialization. Admission is not the
        // only privacy boundary: a future internal producer must not bypass it.
        let builtin = CATALOGUE["events"].as_array().and_then(|events| {
            events
                .iter()
                .find(|event| event["name"].as_str() == Some(name))
        });
        let host = config.registry.iter().find(|event| event.name == name);
        if builtin.is_none() && host.is_none() {
            return false;
        }
        if let Some(host) = host {
            if host
                .properties
                .iter()
                .any(|property| !props.contains_key(&property.name))
                || (host.mode == ProductEventMode::Aggregate
                    && ["count_bucket", "partial"]
                        .iter()
                        .any(|key| !props.contains_key(*key)))
            {
                return false;
            }
        } else if name.ends_with("_summary") {
            if ["operation", "unit", "count_bucket", "partial"]
                .iter()
                .any(|key| !props.contains_key(*key))
                || (!matches!(
                    props.get("unit").and_then(|value| value.as_str()),
                    Some("backlog" | "coverage")
                ) && (props.get("count_bucket").and_then(|value| value.as_str()) == Some("0")
                    || !props.contains_key("outcome")))
            {
                return false;
            }
        } else if name == "mdk_session_started" {
            if !props.contains_key("launch_reason") {
                return false;
            }
        } else if let Some(schema) = approved_host_product_schemas()
            .iter()
            .find(|schema| schema.name == name)
            && (schema
                .properties
                .iter()
                .any(|property| !props.contains_key(&property.name))
                || (schema.mode == ProductEventMode::Aggregate
                    && ["count_bucket", "partial"]
                        .iter()
                        .any(|key| !props.contains_key(*key))))
        {
            return false;
        }
        props.iter().all(|(key, value)| {
            let Some(value) = value.as_str() else {
                return false;
            };
            if !label(key, 40) || value.is_empty() || value.len() > 180 {
                return false;
            }
            if let Some(expected) = common.get(key.as_str()) {
                return value == *expected;
            }
            if let Some(event) = builtin {
                return event["properties"][key].as_array().is_some_and(|choices| {
                    choices.iter().any(|choice| choice.as_str() == Some(value))
                });
            }
            let Some(host) = host else { return false };
            if host.mode == ProductEventMode::Aggregate {
                if key == "partial" {
                    return matches!(value, "true" | "false");
                }
                if key == "count_bucket" {
                    return valid_property(&ProductPropertyRule::CountBucket, value);
                }
            }
            host.properties
                .iter()
                .find(|property| property.name == *key)
                .is_some_and(|property| valid_property(&property.rule, value))
        })
    }
    fn seal(&self, s: &mut State, partial: bool) {
        let Some((window, opened, first_partial)) = s.window.take() else {
            return;
        };
        if self.clock.monotonic().saturating_sub(opened) >= EVENT_TTL {
            s.status.dropped_events = s.status.dropped_events.saturating_add(s.cells.len() as u64);
            s.cells.clear();
            return;
        }
        let id = self.clock.uuid();
        s.cells.insert(
            (
                "mdk_runtime_summary".into(),
                BTreeMap::from([
                    ("operation".into(), "coverage".into()),
                    ("unit".into(), "coverage".into()),
                    (
                        "activity".into(),
                        if s.foreground {
                            "foreground"
                        } else {
                            "background"
                        }
                        .into(),
                    ),
                ]),
            ),
            1,
        );
        if let Some(availability) = s.availability {
            s.cells.insert(
                (
                    ProductFamily::Connectivity.as_str().into(),
                    BTreeMap::from([
                        ("operation".into(), "availability".into()),
                        ("outcome".into(), availability.into()),
                        ("unit".into(), "coverage".into()),
                    ]),
                ),
                1,
            );
        }
        let cells = std::mem::take(&mut s.cells);
        let backlog: Vec<_> = s
            .backlog
            .iter()
            .map(|(key, values)| {
                (
                    key.clone(),
                    values.values().fold(0u64, |sum, n| sum.saturating_add(*n)),
                )
            })
            .collect();
        for ((name, mut props), count) in cells.into_iter().chain(backlog) {
            props.insert("count_bucket".into(), product_count_bucket(count).into());
            props.insert("partial".into(), (partial || first_partial).to_string());
            self.enqueue(s, &name, props, &id, window * WINDOW_SECONDS);
        }
    }
    pub(crate) fn observe(
        &self,
        family: ProductFamily,
        operation: &str,
        outcome: &str,
        unit: ProductUnit,
        duration: Option<Duration>,
    ) {
        let permit = self.permit();
        self.observe_with_permit(permit.as_ref(), family, operation, outcome, unit, duration);
    }
    fn observe_with_permit(
        &self,
        permit: Option<&DiagnosticsPermit>,
        family: ProductFamily,
        operation: &str,
        outcome: &str,
        unit: ProductUnit,
        duration: Option<Duration>,
    ) {
        if !family.operations().contains(&operation) || !PRODUCT_OUTCOMES.contains(&outcome) {
            return;
        }
        let mut s = self.lock();
        if !permit.is_some_and(DiagnosticsPermit::valid)
            || !Self::enabled(&s)
            || duration.is_some_and(|d| d > self.clock.monotonic().saturating_sub(s.granted_at))
        {
            return;
        }
        self.advance(&mut s);
        let mut props = BTreeMap::from([
            ("operation".into(), operation.into()),
            ("outcome".into(), outcome.into()),
            ("unit".into(), unit.as_str().into()),
        ]);
        if let Some(d) = duration {
            props.insert("duration_bucket".into(), product_duration_bucket(d).into());
        }
        self.accumulate(&mut s, family.as_str(), props);
    }
    pub(crate) fn observe_media(
        &self,
        operation: &'static str,
        duration: Duration,
        success: bool,
        media_type: &str,
    ) {
        let Some(permit) = self.permit() else { return };
        let mut s = self.lock();
        if !permit.valid()
            || !Self::enabled(&s)
            || duration > self.clock.monotonic().saturating_sub(s.granted_at)
        {
            return;
        }
        self.advance(&mut s);
        let kind = if media_type.starts_with("image/") {
            "image"
        } else if media_type.starts_with("video/") {
            "video"
        } else if media_type.starts_with("audio/") {
            "audio"
        } else if media_type == "application/pdf" || media_type.starts_with("text/") {
            "document"
        } else {
            "other"
        };
        self.accumulate(
            &mut s,
            ProductFamily::Media.as_str(),
            BTreeMap::from([
                ("operation".into(), operation.into()),
                (
                    "outcome".into(),
                    if success { "success" } else { "failure" }.into(),
                ),
                ("unit".into(), "attempt".into()),
                (
                    "duration_bucket".into(),
                    product_duration_bucket(duration).into(),
                ),
                ("media_kind".into(), kind.into()),
            ]),
        );
    }
    pub(crate) fn observe_sync(
        &self,
        operation: &'static str,
        duration: Duration,
        failure: Option<crate::SyncFailureClassification>,
    ) {
        let Some(permit) = self.permit() else { return };
        let mut s = self.lock();
        if !permit.valid()
            || !Self::enabled(&s)
            || duration > self.clock.monotonic().saturating_sub(s.granted_at)
        {
            return;
        }
        self.advance(&mut s);
        let mut props = BTreeMap::from([
            ("operation".into(), operation.into()),
            (
                "outcome".into(),
                if failure.is_some() {
                    "failure"
                } else {
                    "success"
                }
                .into(),
            ),
            ("unit".into(), "attempt".into()),
            (
                "duration_bucket".into(),
                product_duration_bucket(duration).into(),
            ),
        ]);
        if let Some(failure) = failure {
            props.insert(
                "failure_stage".into(),
                failure.failure_stage.as_str().into(),
            );
            props.insert("error_class".into(), failure.error_class.as_str().into());
        }
        self.accumulate(&mut s, ProductFamily::Sync.as_str(), props);
        if let Some(failure) = failure {
            let operation = match failure.error_class {
                crate::SyncErrorClass::StorageBusy => Some("busy"),
                crate::SyncErrorClass::StorageCorruption => Some("corruption"),
                crate::SyncErrorClass::StorageCapacity => Some("capacity"),
                _ => None,
            };
            if let Some(operation) = operation {
                self.accumulate(
                    &mut s,
                    ProductFamily::Storage.as_str(),
                    BTreeMap::from([
                        ("operation".into(), operation.into()),
                        ("unit".into(), "attempt".into()),
                        ("outcome".into(), "failure".into()),
                    ]),
                );
            }
        }
    }
    pub(crate) fn observe_count(
        &self,
        permit: &DiagnosticsPermit,
        family: ProductFamily,
        operation: &str,
        outcome: &str,
        unit: ProductUnit,
        count: u64,
    ) {
        if count == 0
            || !family.operations().contains(&operation)
            || !PRODUCT_OUTCOMES.contains(&outcome)
        {
            return;
        }
        let mut s = self.lock();
        if !permit.valid() || !Self::enabled(&s) {
            return;
        }
        self.advance(&mut s);
        let props = BTreeMap::from([
            ("operation".into(), operation.into()),
            ("outcome".into(), outcome.into()),
            ("unit".into(), unit.as_str().into()),
        ]);
        self.accumulate(&mut s, family.as_str(), props.clone());
        if let Some(value) = s.cells.get_mut(&(family.as_str().into(), props)) {
            *value = value.saturating_add(count - 1);
        }
    }
    fn accumulate(&self, s: &mut State, name: &str, props: BTreeMap<String, String>) {
        let key = (name.to_owned(), props);
        if !s.cells.contains_key(&key) && s.cells.len() + s.backlog.len() >= MAX_CELLS - 3 {
            let key = (
                "mdk_runtime_summary".into(),
                BTreeMap::from([
                    ("operation".into(), "overflow".into()),
                    ("outcome".into(), "capacity".into()),
                    ("unit".into(), "attempt".into()),
                ]),
            );
            let count = s.cells.entry(key).or_default();
            *count = count.saturating_add(1);
            return;
        }
        let count = s.cells.entry(key).or_default();
        *count = count.saturating_add(1);
    }
    pub(crate) fn backlog(
        &self,
        permit: &DiagnosticsPermit,
        source: u64,
        family: ProductFamily,
        operation: &str,
        count: u64,
    ) {
        if !family.operations().contains(&operation) {
            return;
        }
        let mut s = self.lock();
        if !permit.valid() || !Self::enabled(&s) {
            return;
        }
        self.advance(&mut s);
        let key = (
            family.as_str().into(),
            BTreeMap::from([
                ("operation".into(), operation.into()),
                ("unit".into(), "backlog".into()),
            ]),
        );
        if s.backlog.contains_key(&key) || s.cells.len() + s.backlog.len() < MAX_CELLS - 3 {
            let values = s.backlog.entry(key).or_default();
            if values.contains_key(&source) || values.len() < MAX_CELLS {
                values.insert(source, count);
            }
        }
    }
    pub fn record(
        &self,
        event: ProductEvent,
    ) -> Result<ProductRecordResult, ProductAnalyticsError> {
        let mut s = self.lock();
        if s.silent || s.settings.decision != UsageDiagnosticsDecision::Granted {
            return Ok(ProductRecordResult::IgnoredDisabled);
        }
        if !Self::enabled(&s) {
            return Ok(ProductRecordResult::IgnoredUnconfigured);
        }
        let builtins = approved_host_product_schemas();
        let schema = s
            .config
            .registry
            .iter()
            .chain(builtins.iter())
            .find(|v| v.name == event.name)
            .ok_or(ProductAnalyticsError::InvalidEvent)?
            .clone();
        if event.properties.len() != schema.properties.len() {
            return Err(ProductAnalyticsError::InvalidEvent);
        }
        for rule in &schema.properties {
            let v = event
                .properties
                .get(&rule.name)
                .ok_or(ProductAnalyticsError::InvalidEvent)?;
            let valid = valid_property(&rule.rule, v);
            if !valid {
                return Err(ProductAnalyticsError::InvalidEvent);
            }
        }
        self.advance(&mut s);
        if schema.mode == ProductEventMode::Aggregate {
            if s.foreground {
                self.ensure_session(&mut s, "ordinary");
            }
            self.accumulate(&mut s, &event.name, event.properties);
            return Ok(ProductRecordResult::Recorded);
        }
        if !s.foreground {
            return Ok(ProductRecordResult::IgnoredDisabled);
        }
        self.ensure_session(&mut s, "ordinary");
        let key = match event.name.as_str() {
            "mdk_runtime_ready" => Some(event.name.clone()),
            "mdk_onboarding_step" => Some(format!(
                "mdk_onboarding_step:{}",
                event
                    .properties
                    .get("step")
                    .ok_or(ProductAnalyticsError::InvalidEvent)?
            )),
            "app_screen_viewed" => Some(
                serde_json::to_string(&event).map_err(|_| ProductAnalyticsError::InvalidEvent)?,
            ),
            _ => None,
        };
        if let Some(key) = key {
            if s.seen.contains(&key) {
                return Ok(ProductRecordResult::IgnoredDuplicate);
            }
            if s.seen.len() >= 256 {
                return Ok(ProductRecordResult::DroppedCapacity);
            }
            s.seen.insert(key);
        }
        let id = s.session.as_ref().map(|v| v.0.clone()).unwrap_or_default();
        self.enqueue(
            &mut s,
            &event.name,
            event.properties,
            &id,
            self.clock.wall_seconds() / 60 * 60,
        );
        Ok(ProductRecordResult::Recorded)
    }
    fn ensure_session(&self, s: &mut State, launch_reason: &str) {
        let now = self.clock.monotonic();
        if s.session.as_ref().is_none_or(|(_, start, last)| {
            now.saturating_sub(*start) >= Duration::from_secs(3600)
                || now.saturating_sub(*last) >= Duration::from_secs(1800)
        }) {
            let id = self.clock.uuid();
            s.seen.clear();
            s.session = Some((id.clone(), now, now));
            self.enqueue(
                s,
                "mdk_session_started",
                BTreeMap::from([("launch_reason".into(), launch_reason.into())]),
                &id,
                self.clock.wall_seconds() / 60 * 60,
            );
        }
        if let Some((_, _, last)) = &mut s.session {
            *last = now;
        }
    }
    pub fn activity(&self, activity: ProductAnalyticsActivity) {
        let mut s = self.lock();
        if !Self::enabled(&s) {
            match activity {
                ProductAnalyticsActivity::Foreground
                | ProductAnalyticsActivity::ForegroundNotification
                | ProductAnalyticsActivity::ForegroundDeepLink => s.foreground = true,
                ProductAnalyticsActivity::Background => s.foreground = false,
                ProductAnalyticsActivity::AccountChanged => {}
            }
            return;
        }
        self.advance(&mut s);
        match activity {
            ProductAnalyticsActivity::Foreground
            | ProductAnalyticsActivity::ForegroundNotification
            | ProductAnalyticsActivity::ForegroundDeepLink => {
                if !s.foreground && s.session.is_some() {
                    self.accumulate(
                        &mut s,
                        ProductFamily::Runtime.as_str(),
                        BTreeMap::from([
                            ("operation".into(), "resume".into()),
                            ("outcome".into(), "success".into()),
                            ("unit".into(), "action".into()),
                        ]),
                    );
                }
                if !s.foreground && (!s.cells.is_empty() || !s.backlog.is_empty()) {
                    self.seal(&mut s, true);
                }
                s.foreground = true;
                let reason = match activity {
                    ProductAnalyticsActivity::ForegroundNotification => "notification",
                    ProductAnalyticsActivity::ForegroundDeepLink => "deep_link",
                    _ => "ordinary",
                };
                self.ensure_session(&mut s, reason);
            }
            ProductAnalyticsActivity::Background => {
                if s.foreground {
                    self.seal(&mut s, true);
                }
                s.foreground = false;
            }
            ProductAnalyticsActivity::AccountChanged => {
                self.accumulate(
                    &mut s,
                    ProductFamily::Account.as_str(),
                    BTreeMap::from([
                        ("operation".into(), "switch".into()),
                        ("outcome".into(), "success".into()),
                        ("unit".into(), "action".into()),
                    ]),
                );
                self.seal(&mut s, true);
                s.session = None;
                s.seen.clear();
            }
        }
    }
    pub(crate) fn seal_partial(&self) {
        let mut s = self.lock();
        if Self::enabled(&s) {
            self.seal(&mut s, true);
        }
    }
    pub async fn flush(&self) {
        #[cfg(feature = "product-analytics-export")]
        {
            let Some(permit) = self.permit() else { return };
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                while permit.valid() && !self.lock().queue.is_empty() {
                    self.send_pending_with_permit(&permit).await;
                    if !Self::enabled(&self.lock()) {
                        break;
                    }
                }
            })
            .await;
        }
    }
    pub(crate) async fn run(self, relay_plane: crate::MarmotRelayPlane) {
        let Some(permit) = self.permit() else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {biased; _=permit.cancelled()=>break,_=interval.tick()=>{
                if Self::enabled(&self.lock()) {
                    let health = tokio::select! {biased; _=permit.cancelled()=>break, health=relay_plane.relay_health()=>health};
                    let mut s = self.lock();
                    if permit.valid() && Self::enabled(&s) {
                        self.advance(&mut s);
                        s.availability = Some(if health.connected == 0 { "none" }
                            else if health.connected < health.total_relays { "partial" } else { "available" });
                    }
                }
                #[cfg(feature="product-analytics-export")]
                self.send_pending_with_permit(&permit).await;
            }}
        }
    }
}

impl MarmotApp {
    /// Opaque, revocable grant for direct diagnostic exporter integrations.
    pub fn usage_diagnostics_permit(&self) -> Result<DiagnosticsPermit, AppError> {
        self.product_analytics
            .permit()
            .ok_or_else(|| ProductAnalyticsError::ConsentRequired.into())
    }

    pub fn usage_diagnostics_settings(&self) -> Result<UsageDiagnosticsSettings, AppError> {
        let mut receipt = self.stored_usage_diagnostics_settings()?;
        let r = self.shared_storage()?.usage_diagnostics_settings()?;
        let state = self.product_analytics.lock();
        if receipt.decision == UsageDiagnosticsDecision::Granted
            && (state.persistence_failed
                || r.policy_revision != USAGE_DIAGNOSTICS_POLICY
                || r.registry_revision != state.registry_revision
                || r.scope_revision != state.scope)
        {
            receipt.decision = UsageDiagnosticsDecision::AcceptanceRequired;
        }
        Ok(receipt)
    }
    pub(crate) fn stored_usage_diagnostics_settings(
        &self,
    ) -> Result<UsageDiagnosticsSettings, AppError> {
        let r = self.shared_storage()?.usage_diagnostics_settings()?;
        Ok(UsageDiagnosticsSettings {
            decision: match r.decision {
                1 => UsageDiagnosticsDecision::Declined,
                2 => UsageDiagnosticsDecision::Granted,
                _ => UsageDiagnosticsDecision::AcceptanceRequired,
            },
            policy_revision: r.policy_revision,
            registry_revision: r.registry_revision,
            updated_at_ms: r.updated_at_ms,
            previously_enabled: r.previously_enabled,
        })
    }
    pub(crate) fn restore_usage_diagnostics(&self) -> Result<(), AppError> {
        let _consent = self
            .product_analytics
            .consent_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let r = self.shared_storage()?.usage_diagnostics_settings()?;
        let mut receipt = self.usage_diagnostics_settings()?;
        let state = self.product_analytics.lock();
        if r.decision == 2
            && (state.persistence_failed
                || r.policy_revision != USAGE_DIAGNOSTICS_POLICY
                || r.registry_revision != state.registry_revision
                || r.scope_revision != state.scope)
        {
            receipt.decision = UsageDiagnosticsDecision::AcceptanceRequired;
        }
        drop(state);
        self.product_analytics.set_receipt(
            receipt,
            self.shared_storage()?
                .telemetry_install_id()?
                .unwrap_or_default(),
        );
        Ok(())
    }
    pub fn set_usage_diagnostics_consent(
        &self,
        enabled: bool,
    ) -> Result<UsageDiagnosticsSettings, AppError> {
        let _consent = self
            .product_analytics
            .consent_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let old_id = if enabled && self.product_analytics.permit().is_some() {
            self.telemetry_install_id().ok()
        } else {
            None
        };
        self.product_analytics.revoke_memory();
        // Fail closed until the complete durable write and receipt reload succeed.
        self.product_analytics.lock().persistence_failed = true;
        let storage = self.shared_storage()?;
        let mut r = storage.usage_diagnostics_settings()?;
        let state = self.product_analytics.lock();
        r.decision = if enabled { 2 } else { 1 };
        r.policy_revision = USAGE_DIAGNOSTICS_POLICY.into();
        r.registry_revision = state.registry_revision.clone();
        r.scope_revision = state.scope.clone();
        r.updated_at_ms = self
            .product_analytics
            .clock
            .wall_seconds()
            .saturating_mul(1000)
            .min(i64::MAX as u64) as i64;
        drop(state);
        let id = enabled.then(|| old_id.unwrap_or_else(crate::generate_telemetry_install_id));
        storage.set_usage_diagnostics_settings(&r, id.as_deref())?;
        let receipt = self.stored_usage_diagnostics_settings()?;
        self.product_analytics.lock().persistence_failed = false;
        self.product_analytics
            .set_receipt(receipt.clone(), id.unwrap_or_default());
        Ok(receipt)
    }
}

impl std::fmt::Debug for ProductAnalytics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductAnalytics").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) fn test_permit() -> DiagnosticsPermit {
    let c = ProductAnalytics::default();
    c.set_receipt(
        UsageDiagnosticsSettings {
            decision: UsageDiagnosticsDecision::Granted,
            ..Default::default()
        },
        crate::generate_telemetry_install_id(),
    );
    c.permit().unwrap()
}

/// An operation ticket carries only a revocable generation and a monotonic start.
/// Dropping it before completion records cancellation, never a raw error.
pub struct ProductObservation {
    collector: ProductAnalytics,
    permit: DiagnosticsPermit,
    started: Duration,
    family: ProductFamily,
    operation: &'static str,
    unit: ProductUnit,
    finished: bool,
}
impl ProductObservation {
    pub(crate) fn counts_only(mut self) -> Self {
        self.finished = true;
        self
    }
    pub(crate) fn discard(mut self) {
        self.finished = true;
    }
    pub(crate) fn count(&self, outcome: &str, unit: ProductUnit, count: u64) {
        self.collector.observe_count(
            &self.permit,
            self.family,
            self.operation,
            outcome,
            unit,
            count,
        );
    }
    /// Attribute only the finite origin of a directory result, never an endpoint.
    pub(crate) fn directory_sample(&self, outcome: &str, source: &str, count: u64) {
        if self.family != ProductFamily::Directory
            || !["cache", "network", "mixed"].contains(&source)
            || !PRODUCT_OUTCOMES.contains(&outcome)
            || count == 0
        {
            return;
        }
        let mut state = self.collector.lock();
        if !self.permit.valid() || !ProductAnalytics::enabled(&state) {
            return;
        }
        self.collector.advance(&mut state);
        let props = BTreeMap::from([
            ("operation".into(), self.operation.into()),
            ("outcome".into(), outcome.into()),
            ("unit".into(), self.unit.as_str().into()),
            ("source".into(), source.into()),
        ]);
        self.collector
            .accumulate(&mut state, self.family.as_str(), props.clone());
        if let Some(value) = state.cells.get_mut(&(self.family.as_str().into(), props)) {
            *value = value.saturating_add(count - 1);
        }
    }
    pub(crate) fn duration_sample(&self, outcome: &str, duration: Duration) {
        self.collector.observe_with_permit(
            Some(&self.permit),
            self.family,
            self.operation,
            outcome,
            self.unit,
            Some(duration),
        );
    }
    pub fn finish(self, outcome: &str) {
        let duration = self
            .collector
            .clock
            .monotonic()
            .saturating_sub(self.started);
        self.finish_with_duration(outcome, duration);
    }
    pub(crate) fn finish_with_duration(mut self, outcome: &str, duration: Duration) {
        self.finished = true;
        self.collector.observe_with_permit(
            Some(&self.permit),
            self.family,
            self.operation,
            outcome,
            self.unit,
            Some(duration),
        );
    }
}
impl Drop for ProductObservation {
    fn drop(&mut self) {
        if !self.finished && self.permit.valid() {
            self.collector.observe_with_permit(
                Some(&self.permit),
                self.family,
                self.operation,
                "cancelled",
                self.unit,
                Some(
                    self.collector
                        .clock
                        .monotonic()
                        .saturating_sub(self.started),
                ),
            );
        }
    }
}
impl ProductAnalytics {
    /// Called only at a canonical failing command boundary, with its admission generation.
    pub(crate) fn storage_failure(&self, permit: Option<&DiagnosticsPermit>, error: &AppError) {
        let Some(permit) = permit else {
            return;
        };
        // A forwarded sync failure is already owned by the sync completion observation.
        if matches!(error, AppError::AccountCatchUp(_)) {
            return;
        }
        let operation = match error.sync_error_class() {
            crate::app_telemetry::SyncErrorClass::StorageBusy => "busy",
            crate::app_telemetry::SyncErrorClass::StorageCorruption => "corruption",
            crate::app_telemetry::SyncErrorClass::StorageCapacity => "capacity",
            _ => return,
        };
        self.observe_count(
            permit,
            ProductFamily::Storage,
            operation,
            "failure",
            ProductUnit::Attempt,
            1,
        );
    }
    pub fn begin(
        &self,
        family: ProductFamily,
        operation: &'static str,
        unit: ProductUnit,
    ) -> Option<ProductObservation> {
        if !Self::enabled(&self.lock()) {
            return None;
        }
        Some(ProductObservation {
            collector: self.clone(),
            permit: self.permit()?,
            started: self.clock.monotonic(),
            family,
            operation,
            unit,
            finished: false,
        })
    }
}

pub(crate) struct ProductBacklogSource {
    id: u64,
    collector: ProductAnalytics,
}
impl ProductBacklogSource {
    pub(crate) fn sample(
        &self,
        permit: &DiagnosticsPermit,
        family: ProductFamily,
        operation: &str,
        count: u64,
    ) {
        self.collector
            .backlog(permit, self.id, family, operation, count);
    }
}
impl Drop for ProductBacklogSource {
    fn drop(&mut self) {
        let mut state = self.collector.lock();
        for values in state.backlog.values_mut() {
            values.remove(&self.id);
        }
        state.backlog.retain(|_, values| !values.is_empty());
    }
}
impl ProductAnalytics {
    pub(crate) fn backlog_source(&self) -> ProductBacklogSource {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        ProductBacklogSource {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
            collector: self.clone(),
        }
    }
}

#[cfg(all(test, feature = "product-analytics-export"))]
impl ProductAnalytics {
    pub(crate) fn test_payloads(&self) -> Vec<serde_json::Value> {
        self.seal_partial();
        self.lock()
            .queue
            .iter()
            .map(|row| row.payload.clone())
            .collect()
    }
}

#[cfg(all(test, feature = "product-analytics-export"))]
pub(crate) fn test_product_collector() -> ProductAnalytics {
    tests::configured().0
}

/// Configure optional headless-host analytics from its environment. Invalid analytics
/// settings never prevent the host from opening or disable its diagnostic pipeline.
pub fn configure_product_analytics_from_environment(
    runtime: &crate::MarmotAppRuntime,
    host_surface: &str,
) {
    configure_product_analytics_from_values(runtime, host_surface, |name| std::env::var(name).ok());
}

fn configure_product_analytics_from_values(
    runtime: &crate::MarmotAppRuntime,
    host_surface: &str,
    get: impl Fn(&str) -> Option<String>,
) {
    let endpoint = get("MARMOT_PRODUCT_ANALYTICS_EVENTS_ENDPOINT");
    let key = get("MARMOT_PRODUCT_ANALYTICS_APP_KEY");
    if endpoint.is_none() && key.is_none() {
        return;
    }
    let config = ProductAnalyticsRuntimeConfig {
        events_endpoint: endpoint,
        app_key: key,
        operator: get("MARMOT_PRODUCT_ANALYTICS_OPERATOR").unwrap_or_default(),
        allow_loopback: get("MARMOT_PRODUCT_ANALYTICS_ALLOW_LOOPBACK").as_deref() == Some("1"),
        registry: Vec::new(),
        metadata: ProductAnalyticsMetadata {
            app_version: env!("CARGO_PKG_VERSION").into(),
            os_family: std::env::consts::OS.into(),
            os_major_version: String::new(),
            device_class: "headless".into(),
            host_surface: host_surface.into(),
            environment: get("MARMOT_PRODUCT_ANALYTICS_ENVIRONMENT")
                .unwrap_or_else(|| "development".into()),
            is_debug: cfg!(debug_assertions),
        },
    };
    if runtime
        .set_product_analytics_runtime_config(config)
        .is_err()
    {
        tracing::warn!(target: "marmot_app::product_analytics", method = "configure_product_analytics_from_environment",
            error_code = "invalid_product_analytics_configuration", "optional product analytics configuration rejected");
    }
}
