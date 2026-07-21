//! Relay telemetry, relay-list, and relay-health FFI conversions.

use marmot_app::{
    AccountRelayListState, AccountRelayListStatus, MissingRelayListKind, RelayPlaneHealth,
    RelayTelemetryResource, RelayTelemetryRuntimeConfig, RelayTelemetrySettings,
};

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetrySettingsFfi {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

impl From<RelayTelemetrySettings> for RelayTelemetrySettingsFfi {
    fn from(value: RelayTelemetrySettings) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

impl From<RelayTelemetrySettingsFfi> for RelayTelemetrySettings {
    fn from(value: RelayTelemetrySettingsFfi) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetryResourceFfi {
    pub service_version: String,
    pub service_instance_id: String,
    pub deployment_environment: String,
    pub tenant: String,
    pub os_type: String,
    pub os_version: String,
    pub device_model_identifier: Option<String>,
}

impl From<RelayTelemetryResourceFfi> for RelayTelemetryResource {
    fn from(value: RelayTelemetryResourceFfi) -> Self {
        Self {
            service_version: value.service_version,
            service_instance_id: value.service_instance_id,
            deployment_environment: value.deployment_environment,
            tenant: value.tenant,
            os_type: value.os_type,
            os_version: value.os_version,
            device_model_identifier: value.device_model_identifier,
        }
    }
}

/// Relay-telemetry runtime config supplied by the host app. The hand-written
/// `Debug` impl below redacts `authorization_bearer_token` (the OTLP push
/// credential) so a `{:?}` never prints it.
#[derive(Clone, uniffi::Record)]
pub struct RelayTelemetryRuntimeConfigFfi {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResourceFfi>,
}

impl std::fmt::Debug for RelayTelemetryRuntimeConfigFfi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayTelemetryRuntimeConfigFfi")
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

impl From<RelayTelemetryRuntimeConfigFfi> for RelayTelemetryRuntimeConfig {
    fn from(value: RelayTelemetryRuntimeConfigFfi) -> Self {
        Self {
            otlp_endpoint: value.otlp_endpoint,
            authorization_bearer_token: value.authorization_bearer_token,
            resource: value.resource.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayListFfi {
    pub kind: u64,
    pub relays: Vec<String>,
}

impl From<AccountRelayListState> for RelayListFfi {
    fn from(value: AccountRelayListState) -> Self {
        Self {
            kind: value.kind,
            relays: value.relays,
        }
    }
}

/// A relay list the account is missing, as a stable typed variant clients
/// localize without parsing strings (mdk#565).
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum MissingRelayListKindFfi {
    /// NIP-65 relay list — where this account publishes (outbox/write-side).
    Nip65,
    /// Marmot inbox relay list — where this account receives (inbox/read-side).
    Inbox,
}

impl From<MissingRelayListKind> for MissingRelayListKindFfi {
    fn from(value: MissingRelayListKind) -> Self {
        match value {
            MissingRelayListKind::Nip65 => Self::Nip65,
            MissingRelayListKind::Inbox => Self::Inbox,
        }
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct AccountRelayListsFfi {
    pub complete: bool,
    pub missing: Vec<MissingRelayListKindFfi>,
    pub default_relays: Vec<String>,
    pub bootstrap_relays: Vec<String>,
    pub nip65: RelayListFfi,
    pub inbox: RelayListFfi,
}

impl From<AccountRelayListStatus> for AccountRelayListsFfi {
    fn from(value: AccountRelayListStatus) -> Self {
        Self {
            complete: value.complete,
            missing: value.missing.into_iter().map(Into::into).collect(),
            default_relays: value.default_relays,
            bootstrap_relays: value.bootstrap_relays,
            nip65: value.nip65.into(),
            inbox: value.inbox.into(),
        }
    }
}

/// Live relay-plane connection health for the diagnostics view.
#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayHealthFfi {
    pub sdk_backed: bool,
    pub total_relays: u32,
    pub initialized: u32,
    pub pending: u32,
    pub connecting: u32,
    pub connected: u32,
    pub disconnected: u32,
    pub terminated: u32,
    pub banned: u32,
    pub sleeping: u32,
    pub connection_attempts: u32,
    pub connection_successes: u32,
}

impl From<RelayPlaneHealth> for RelayHealthFfi {
    fn from(value: RelayPlaneHealth) -> Self {
        Self {
            sdk_backed: value.sdk_backed,
            total_relays: super::saturating_u32(value.total_relays),
            initialized: super::saturating_u32(value.initialized),
            pending: super::saturating_u32(value.pending),
            connecting: super::saturating_u32(value.connecting),
            connected: super::saturating_u32(value.connected),
            disconnected: super::saturating_u32(value.disconnected),
            terminated: super::saturating_u32(value.terminated),
            banned: super::saturating_u32(value.banned),
            sleeping: super::saturating_u32(value.sleeping),
            connection_attempts: super::saturating_u32(value.connection_attempts),
            connection_successes: super::saturating_u32(value.connection_successes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_telemetry_config_debug_redacts_bearer_token() {
        let config = RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: Some("https://otlp.example/v1/metrics".to_owned()),
            authorization_bearer_token: Some("super-secret-otlp-token".to_owned()),
            resource: None,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret-otlp-token"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("otlp.example"), "{rendered}");
    }
}
