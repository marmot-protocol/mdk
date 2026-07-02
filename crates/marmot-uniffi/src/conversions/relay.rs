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

#[derive(Clone, Debug, uniffi::Record)]
pub struct RelayTelemetryRuntimeConfigFfi {
    pub otlp_endpoint: Option<String>,
    pub authorization_bearer_token: Option<String>,
    pub resource: Option<RelayTelemetryResourceFfi>,
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
/// localize without parsing strings (darkmatter#565).
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
            total_relays: value.total_relays as u32,
            initialized: value.initialized as u32,
            pending: value.pending as u32,
            connecting: value.connecting as u32,
            connected: value.connected as u32,
            disconnected: value.disconnected as u32,
            terminated: value.terminated as u32,
            banned: value.banned as u32,
            sleeping: value.sleeping as u32,
            connection_attempts: value.connection_attempts as u32,
            connection_successes: value.connection_successes as u32,
        }
    }
}
