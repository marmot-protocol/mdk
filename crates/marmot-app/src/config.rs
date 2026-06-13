use std::time::Duration;

use serde::{Deserialize, Serialize};

const DEFAULT_DIRECTORY_MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
const COMPILED_RELAY_TELEMETRY_OTLP_ENDPOINT: Option<&str> =
    option_env!("MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT");
const COMPILED_AUDIT_LOG_TRACKER_ENDPOINT: Option<&str> =
    option_env!("MARMOT_AUDIT_LOG_TRACKER_ENDPOINT");
const COMPILED_ENCRYPTED_MEDIA_BLOB_ENDPOINTS: Option<&str> =
    option_env!("MARMOT_ENCRYPTED_MEDIA_BLOB_ENDPOINTS");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarmotAppConfig {
    pub directory_max_future_skew: Duration,
    pub service_endpoints: MarmotServiceEndpoints,
    /// Dev/test gate for loopback-HTTP blob endpoints. A loopback-HTTP endpoint
    /// (e.g. `http://127.0.0.1:PORT`) is VALID component state for everyone, but
    /// per group-encrypted-media-v1.md a client MUST NOT upload to or download
    /// from one unless explicitly configured for dev/test. Defaults to `false`
    /// so production builds treat such endpoints as unusable rather than issuing
    /// requests to the local host. This does not affect component validity
    /// (decode still accepts loopback endpoints).
    pub allow_loopback_blob_endpoints: bool,
    /// Dev/test override for the convergence settlement quiescence window, in
    /// milliseconds. `None` (the default) uses the protocol-pinned value
    /// (`settlement_quiescence_ms = 1000`); a client MUST NOT ship a non-default
    /// value (spec/implementation-model.md, "Convergence Policy Overrides").
    /// Test harnesses set `Some(0)` for deterministic, instant settlement.
    pub dev_settlement_quiescence_ms: Option<u64>,
}

/// Compiled or app-level default service URLs for production telemetry export
/// and forensic audit-log tracker uploads.
///
/// Defaults are intentionally separate from bearer tokens. Host apps supply
/// credentials at runtime, while the Dark Matter/Marmot build owns stable
/// first-party URLs. `MarmotAppConfig::default()` reads these from
/// `MARMOT_RELAY_TELEMETRY_OTLP_ENDPOINT` and
/// `MARMOT_AUDIT_LOG_TRACKER_ENDPOINT` at compile time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MarmotServiceEndpoints {
    pub relay_telemetry_otlp_endpoint: Option<String>,
    pub audit_log_tracker_endpoint: Option<String>,
    pub encrypted_media_blob_endpoints: Vec<String>,
}

impl Default for MarmotAppConfig {
    fn default() -> Self {
        Self {
            directory_max_future_skew: DEFAULT_DIRECTORY_MAX_FUTURE_SKEW,
            service_endpoints: MarmotServiceEndpoints::compiled(),
            allow_loopback_blob_endpoints: false,
            dev_settlement_quiescence_ms: None,
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

    /// Enable acting on loopback-HTTP blob endpoints for dev/test. Off by
    /// default; production builds must leave this unset.
    pub fn with_allow_loopback_blob_endpoints(mut self, allow: bool) -> Self {
        self.allow_loopback_blob_endpoints = allow;
        self
    }

    /// Dev/test override for the convergence settlement quiescence window (ms).
    /// Off by default (the protocol-pinned `1000` ms is used); production builds
    /// must leave this unset. Test harnesses set `0` for instant settlement.
    pub fn with_dev_settlement_quiescence_ms(mut self, ms: u64) -> Self {
        self.dev_settlement_quiescence_ms = Some(ms);
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
        }
        .normalize()
    }

    pub fn normalize(mut self) -> Self {
        self.relay_telemetry_otlp_endpoint = trim_optional(self.relay_telemetry_otlp_endpoint);
        self.audit_log_tracker_endpoint = trim_optional(self.audit_log_tracker_endpoint);
        self.encrypted_media_blob_endpoints =
            normalize_endpoint_list(self.encrypted_media_blob_endpoints);
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayTelemetryRuntimeConfig {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResource>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLogUploadSource {
    pub account_label: Option<String>,
    pub device_label: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditLogTrackerConfig {
    pub endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub source: AuditLogUploadSource,
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
        self.account_label = trim_optional(self.account_label);
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

    fn runtime_config() -> RelayTelemetryRuntimeConfig {
        RelayTelemetryRuntimeConfig {
            otlp_endpoint: None,
            authorization_bearer_token: Some("token".to_owned()),
            resource: Some(RelayTelemetryResource {
                service_version: "1.4.2".to_owned(),
                service_instance_id: "8e1ca50b-05a2-4c31-a31c-1e69c75a9366".to_owned(),
                deployment_environment: "staging".to_owned(),
                tenant: "darkmatter-ios".to_owned(),
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
                tenant: " darkmatter-ios ".to_owned(),
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
        assert_eq!(resource.tenant, "darkmatter-ios");
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
