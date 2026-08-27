//! C mirrors of the relay-list, relay-health, and telemetry conversions.

use marmot_uniffi::conversions::{
    AccountRelayListsFfi, MissingRelayListKindFfi, RelayEndpointClassificationFfi,
    RelayEndpointPolicyFfi, RelayHealthFfi, RelayListFfi, RelayTelemetryResourceFfi,
    RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi,
};

use crate::MarmotStatus;
use crate::macros::{c_enum, c_mirror};
use crate::memory::{c_bool, optional_str, required_str};

c_mirror! {
    /// One published relay list (`kind` is the Nostr event kind).
    MarmotRelayList from RelayListFfi {
        copy kind: u64,
        str_vec relays/relays_len,
    }
}

c_enum! {
    /// Which relay list is missing from an incomplete account relay setup.
    MarmotMissingRelayListKind from MissingRelayListKindFfi {
        /// NIP-65 relay list — where this account publishes (outbox).
        Nip65,
        /// Marmot inbox relay list — where this account receives (inbox).
        Inbox,
    }
}

c_mirror! {
    /// The account's full relay-list state.
    MarmotAccountRelayLists from AccountRelayListsFfi,
    free marmot_account_relay_lists_free {
        copy complete: bool,
        vec missing/missing_len: MarmotMissingRelayListKind,
        str_vec default_relays/default_relays_len,
        str_vec bootstrap_relays/bootstrap_relays_len,
        rec nip65: MarmotRelayList,
        rec inbox: MarmotRelayList,
    }
}

c_mirror! {
    /// Aggregate relay-pool health counters (no per-relay identities).
    MarmotRelayHealth from RelayHealthFfi,
    free marmot_relay_health_free {
        copy sdk_backed: bool,
        copy total_relays: u32,
        copy initialized: u32,
        copy pending: u32,
        copy connecting: u32,
        copy connected: u32,
        copy disconnected: u32,
        copy terminated: u32,
        copy banned: u32,
        copy sleeping: u32,
        copy connection_attempts: u32,
        copy connection_successes: u32,
        copy notification_forwarder_running: bool,
        copy notification_forwarder_restarts: u64,
        copy notification_forwarder_lag_incidents: u64,
        copy notification_forwarder_lagged_notifications: u64,
        copy notification_forwarder_panics: u64,
        copy notification_forwarder_unexpected_exits: u64,
    }
}

c_mirror! {
    /// Relay-telemetry export settings. Also a borrowed input to
    /// `marmot_set_relay_telemetry_settings`.
    MarmotRelayTelemetrySettings from RelayTelemetrySettingsFfi,
    free marmot_relay_telemetry_settings_free {
        /// Boolean as `uint8_t`: nonzero enables export.
        copy export_enabled: u8,
        copy export_interval_seconds: u64,
    }
}

impl MarmotRelayTelemetrySettings {
    pub(crate) fn to_ffi(&self) -> RelayTelemetrySettingsFfi {
        RelayTelemetrySettingsFfi {
            export_enabled: c_bool(self.export_enabled),
            export_interval_seconds: self.export_interval_seconds,
        }
    }
}

c_mirror! {
    /// OTLP resource attributes for relay-telemetry export. Borrowed input.
    MarmotRelayTelemetryResource from RelayTelemetryResourceFfi,
    free marmot_relay_telemetry_resource_free {
        str service_version,
        str service_instance_id,
        str deployment_environment,
        str tenant,
        str os_type,
        str os_version,
        opt_str device_model_identifier,
    }
}

impl MarmotRelayTelemetryResource {
    /// # Safety
    /// Every non-NULL field must be a valid NUL-terminated string.
    pub(crate) unsafe fn to_ffi(&self) -> Result<RelayTelemetryResourceFfi, MarmotStatus> {
        Ok(RelayTelemetryResourceFfi {
            service_version: unsafe { required_str(self.service_version) }?,
            service_instance_id: unsafe { required_str(self.service_instance_id) }?,
            deployment_environment: unsafe { required_str(self.deployment_environment) }?,
            tenant: unsafe { required_str(self.tenant) }?,
            os_type: unsafe { required_str(self.os_type) }?,
            os_version: unsafe { required_str(self.os_version) }?,
            device_model_identifier: unsafe { optional_str(self.device_model_identifier) }?,
        })
    }
}

c_mirror! {
    /// Runtime OTLP route config for relay telemetry. Borrowed input to
    /// `marmot_set_relay_telemetry_runtime_config`.
    MarmotRelayTelemetryRuntimeConfig from RelayTelemetryRuntimeConfigFfi,
    free marmot_relay_telemetry_runtime_config_free {
        opt_str otlp_endpoint,
        opt_str authorization_bearer_token,
        opt_rec resource: MarmotRelayTelemetryResource,
    }
}

impl MarmotRelayTelemetryRuntimeConfig {
    /// # Safety
    /// Non-NULL strings must be valid; `resource` NULL or a valid struct.
    pub(crate) unsafe fn to_ffi(&self) -> Result<RelayTelemetryRuntimeConfigFfi, MarmotStatus> {
        let resource = if self.resource.is_null() {
            None
        } else {
            Some(unsafe { (*self.resource).to_ffi() }?)
        };
        Ok(RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: unsafe { optional_str(self.otlp_endpoint) }?,
            authorization_bearer_token: unsafe { optional_str(self.authorization_bearer_token) }?,
            resource,
        })
    }
}

c_enum! {
    /// Whether a relay endpoint may be dialed.
    MarmotRelayEndpointPolicy from RelayEndpointPolicyFfi {
        Allowed,
        /// On the centralized retired-relay denylist; never dial it.
        Retired,
        /// Not a parseable relay URL.
        Invalid,
        /// Parseable but rejected by the host-safety dial discipline.
        Unsafe,
    }
}

c_mirror! {
    /// One endpoint's dial verdict. Free the list with
    /// `marmot_relay_endpoint_classification_list_free`.
    MarmotRelayEndpointClassification from RelayEndpointClassificationFfi,
    free marmot_relay_endpoint_classification_free,
    list(MarmotRelayEndpointClassificationList, marmot_relay_endpoint_classification_list_free) {
        /// The endpoint as the caller wrote it.
        str endpoint,
        /// Canonical form, NULL when the endpoint does not parse.
        opt_str normalized_endpoint,
        copy policy: MarmotRelayEndpointPolicy,
    }
}
