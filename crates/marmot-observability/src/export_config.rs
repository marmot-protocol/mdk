//! The exporters' resolved configuration (#2627): the relay-telemetry export
//! config with its resource and runtime config, the audit upload source, and
//! the structural gates every collector endpoint passes.
//!
//! `marmot-app` keeps the settings that resolve against its service endpoints
//! (`RelayTelemetrySettings`, `AuditLogTrackerConfig`) and builds these values
//! from them.

use std::time::Duration;

/// Default export poll/push interval. Coarse on purpose: the data is
/// aggregate and cumulative, so a coarse window respects battery and metered
/// networks without losing resolution.
pub const DEFAULT_EXPORT_INTERVAL: Duration = Duration::from_secs(60);

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
    /// System model identifier; never a user-assigned device name, hostname, or serial number.
    pub hardware_model: Option<String>,
    pub platform: Option<String>,
    pub app_version: Option<String>,
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
        self.service_instance_id = self.service_instance_id.trim().to_owned();
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

pub fn trim_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn trim_required(name: &str, value: String) -> Result<String, String> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(value)
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
    /// This is the single gate condition shared by the exporter constructor
    /// (`RelayTelemetryExporter::new`) and relay-identity resolution.
    pub(crate) fn export_allowed(&self) -> bool {
        self.enabled
            && self
                .endpoint
                .as_deref()
                .is_some_and(|endpoint| parse_relay_telemetry_endpoint(endpoint).is_some())
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

impl transport_nostr::RelayExportGate for RelayTelemetryExportConfig {
    fn export_allowed(&self) -> bool {
        RelayTelemetryExportConfig::export_allowed(self)
    }
}

/// Structural gate shared by exporter construction and each OTLP dial attempt.
/// Keep the exact `localhost`/loopback-IP test contract; do not admit subdomains
/// or grant loopback access because an ordinary hostname resolves there.
pub(crate) fn parse_relay_telemetry_endpoint(endpoint: &str) -> Option<url::Url> {
    let url = url::Url::parse(endpoint).ok()?;
    let host = url.host()?;
    if url.port_or_known_default()? == 0
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !matches!(url.scheme(), "https" | "http")
        || (url.scheme() == "http" && !host_is_loopback(host))
    {
        return None;
    }
    Some(url)
}

/// Accept `https` for any host; accept `http` only for a loopback host (a local
/// test collector). Reject anything else, including unparseable endpoints.
pub fn endpoint_transport_allowed(endpoint: &str) -> bool {
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
    fn runtime_config_debug_redacts_the_bearer_token() {
        let mut config = runtime_config();
        config.authorization_bearer_token = Some("private-bearer-sentinel".into());
        for debug in [format!("{config:?}"), format!("{config:#?}")] {
            assert!(!debug.contains("private-bearer-sentinel"));
            assert!(debug.contains("<redacted>"));
        }
        config.authorization_bearer_token = None;
        assert!(format!("{config:?}").contains("authorization_bearer_token: None"));
    }

    #[test]
    fn runtime_normalization_trims_inputs_and_names_invalid_required_fields() {
        let mut config = runtime_config();
        config.otlp_endpoint = Some(" https://collector.example/metrics ".into());
        config.authorization_bearer_token = Some(" secret ".into());
        let resource = config.resource.as_mut().unwrap();
        resource.service_version = " 1.4.2 ".into();
        resource.service_instance_id = " host-identity ".into();
        resource.deployment_environment = " staging ".into();
        resource.tenant = " mdk-ios ".into();
        resource.os_type = " ios ".into();
        resource.os_version = " 17.5 ".into();
        resource.device_model_identifier = Some(" model-id ".into());
        let normalized = crate::wiring::normalize_runtime_config(config).unwrap();
        assert_eq!(
            normalized.otlp_endpoint.as_deref(),
            Some("https://collector.example/metrics")
        );
        assert_eq!(
            normalized.authorization_bearer_token.as_deref(),
            Some("secret")
        );
        let resource = normalized.resource.as_ref().unwrap();
        assert_eq!(resource.service_version, "1.4.2");
        assert_eq!(resource.service_instance_id, "host-identity");
        assert_eq!(resource.deployment_environment, "staging");
        assert_eq!(resource.tenant, "mdk-ios");
        assert_eq!(resource.os_type, "ios");
        assert_eq!(resource.os_version, "17.5");
        assert_eq!(
            resource.device_model_identifier.as_deref(),
            Some("model-id")
        );
        let mut blank_optional = normalized;
        blank_optional.otlp_endpoint = Some(" ".into());
        blank_optional.authorization_bearer_token = Some(" ".into());
        blank_optional
            .resource
            .as_mut()
            .unwrap()
            .device_model_identifier = Some(" ".into());
        let normalized = crate::wiring::normalize_runtime_config(blank_optional).unwrap();
        assert_eq!(normalized.otlp_endpoint, None);
        assert_eq!(normalized.authorization_bearer_token, None);
        assert_eq!(normalized.resource.unwrap().device_model_identifier, None);

        for (case, field) in [
            "service.version",
            "deployment.environment.name",
            "tenant",
            "os.type",
            "os.version",
        ]
        .into_iter()
        .enumerate()
        {
            let mut config = runtime_config();
            let resource = config.resource.as_mut().unwrap();
            match case {
                0 => resource.service_version = " ".into(),
                1 => resource.deployment_environment = " ".into(),
                2 => resource.tenant = " ".into(),
                3 => resource.os_type = " ".into(),
                _ => resource.os_version = " ".into(),
            }
            assert_eq!(
                crate::wiring::normalize_runtime_config(config.clone()).unwrap_err(),
                format!("{field} must not be empty")
            );
            // The non-fallible export builder also fails closed for an invalid resource.
            let export = RelayTelemetryExportConfig::enabled("https://collector.example/metrics")
                .with_runtime_config(config);
            assert_eq!(export.resource, None);
            assert!(!export.export_allowed());
        }
    }

    #[test]
    fn relay_export_gate_is_the_export_allowed_check() {
        use transport_nostr::RelayExportGate;
        let configs = [
            RelayTelemetryExportConfig::disabled(),
            RelayTelemetryExportConfig {
                enabled: true,
                ..Default::default()
            },
            RelayTelemetryExportConfig::enabled("https://otlp.example/v1/metrics")
                .with_runtime_config(runtime_config()),
        ];
        let gates = configs
            .iter()
            .map(RelayExportGate::export_allowed)
            .collect::<Vec<_>>();
        assert_eq!(gates, [false, false, true]);
        for config in &configs {
            assert_eq!(
                RelayExportGate::export_allowed(config),
                config.export_allowed()
            );
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
    fn relay_telemetry_host_safety_rejects_invalid_structure() {
        for endpoint in [
            "https://user:password@collector.example/v1/metrics",
            "https://user@collector.example/v1/metrics",
            "https://collector.example/v1/metrics#fragment",
            "https://collector.example:0/v1/metrics",
            "https://collector.example:65536/v1/metrics",
            "https:///",
            "file:///v1/metrics",
            "http://collector.example/v1/metrics",
            "http://10.0.0.1/v1/metrics",
            "http://dev.localhost/v1/metrics",
        ] {
            let mut config =
                RelayTelemetryExportConfig::enabled(endpoint).with_runtime_config(runtime_config());
            config.endpoint = Some(endpoint.to_owned());
            assert!(!config.export_allowed(), "accepted invalid structure");
        }
    }
}
