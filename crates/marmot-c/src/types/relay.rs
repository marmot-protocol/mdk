//! C mirrors of the relay conversions (`marmot-uniffi/src/conversions/relay.rs`).

use std::ffi::c_char;

use marmot_uniffi::conversions::{
    AccountRelayListsFfi, MissingRelayListKindFfi, RelayHealthFfi, RelayListFfi,
    RelayTelemetryResourceFfi, RelayTelemetryRuntimeConfigFfi, RelayTelemetrySettingsFfi,
};

use crate::MarmotStatus;
use crate::memory::{
    CFree, boxed_opt, free_boxed, free_c_string, free_vec, optional_str, owned_c_string,
    owned_opt_c_string, owned_vec, required_str,
};

/// Device-wide relay telemetry export settings. Export is opt-in and stays
/// inert until `export_enabled` is true and runtime/default config supplies a
/// valid OTLP endpoint, bearer token, and resource attributes. Used both as a
/// return value (owned; free the root) and as a borrowed input to
/// `marmot_set_relay_telemetry_settings` (caller-owned; this library never
/// frees input structs).
#[repr(C)]
pub struct MarmotRelayTelemetrySettings {
    pub export_enabled: bool,
    pub export_interval_seconds: u64,
}

impl From<RelayTelemetrySettingsFfi> for MarmotRelayTelemetrySettings {
    fn from(value: RelayTelemetrySettingsFfi) -> Self {
        Self {
            export_enabled: value.export_enabled,
            export_interval_seconds: value.export_interval_seconds,
        }
    }
}

impl MarmotRelayTelemetrySettings {
    /// Read a caller-owned input struct into the Ffi record. All fields are
    /// scalars, so this is infallible and touches no caller memory.
    pub(crate) fn to_ffi(&self) -> RelayTelemetrySettingsFfi {
        RelayTelemetrySettingsFfi {
            export_enabled: self.export_enabled,
            export_interval_seconds: self.export_interval_seconds,
        }
    }
}

impl CFree for MarmotRelayTelemetrySettings {
    unsafe fn free_in_place(&mut self) {}
}

/// Free a telemetry settings root returned by this library. Never call on
/// structs you allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `settings` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_telemetry_settings_free(
    settings: *mut MarmotRelayTelemetrySettings,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(settings) });
}

/// OTLP resource attributes supplied by the platform shell. Nested inside
/// `MarmotRelayTelemetryRuntimeConfig`; borrowed when used as input.
#[repr(C)]
pub struct MarmotRelayTelemetryResource {
    pub service_version: *mut c_char,
    pub service_instance_id: *mut c_char,
    pub deployment_environment: *mut c_char,
    pub tenant: *mut c_char,
    pub os_type: *mut c_char,
    pub os_version: *mut c_char,
    /// Device model identifier, when known. Nullable.
    pub device_model_identifier: *mut c_char,
}

impl From<RelayTelemetryResourceFfi> for MarmotRelayTelemetryResource {
    fn from(value: RelayTelemetryResourceFfi) -> Self {
        Self {
            service_version: owned_c_string(value.service_version),
            service_instance_id: owned_c_string(value.service_instance_id),
            deployment_environment: owned_c_string(value.deployment_environment),
            tenant: owned_c_string(value.tenant),
            os_type: owned_c_string(value.os_type),
            os_version: owned_c_string(value.os_version),
            device_model_identifier: owned_opt_c_string(value.device_model_identifier),
        }
    }
}

impl MarmotRelayTelemetryResource {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
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

impl CFree for MarmotRelayTelemetryResource {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.service_version);
            free_c_string(self.service_instance_id);
            free_c_string(self.deployment_environment);
            free_c_string(self.tenant);
            free_c_string(self.os_type);
            free_c_string(self.os_version);
            free_c_string(self.device_model_identifier);
        }
    }
}

/// Free a telemetry resource root returned by this library. Never call on
/// structs you allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `resource` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_telemetry_resource_free(
    resource: *mut MarmotRelayTelemetryResource,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(resource) });
}

/// Non-persisted OTLP runtime metadata supplied by the host app: optional
/// metrics URL override, bearer token from the host app's build-time secret,
/// and resource attributes from the platform shell. Borrowed input to
/// `marmot_set_relay_telemetry_runtime_config` (caller-owned; this library
/// never frees input structs). `authorization_bearer_token` is the OTLP push
/// credential and is never logged or echoed back by this library.
#[repr(C)]
pub struct MarmotRelayTelemetryRuntimeConfig {
    /// Metrics endpoint URL override. Nullable.
    pub otlp_endpoint: *mut c_char,
    /// OTLP push credential. Nullable.
    pub authorization_bearer_token: *mut c_char,
    /// Resource attributes from the platform shell. Nullable.
    pub resource: *mut MarmotRelayTelemetryResource,
}

impl From<RelayTelemetryRuntimeConfigFfi> for MarmotRelayTelemetryRuntimeConfig {
    fn from(value: RelayTelemetryRuntimeConfigFfi) -> Self {
        Self {
            otlp_endpoint: owned_opt_c_string(value.otlp_endpoint),
            authorization_bearer_token: owned_opt_c_string(value.authorization_bearer_token),
            resource: boxed_opt(value.resource.map(Into::into)),
        }
    }
}

impl MarmotRelayTelemetryRuntimeConfig {
    /// Read a caller-owned input struct into the Ffi record without taking
    /// ownership of any caller memory.
    ///
    /// # Safety
    /// Every non-NULL string field must be a valid NUL-terminated string, and
    /// `resource` must be NULL or point to a valid
    /// `MarmotRelayTelemetryResource`.
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

impl CFree for MarmotRelayTelemetryRuntimeConfig {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_c_string(self.otlp_endpoint);
            free_c_string(self.authorization_bearer_token);
            free_boxed(self.resource);
        }
    }
}

/// Free a runtime config root returned by this library. Never call on
/// structs you allocated yourself as inputs. NULL is a no-op.
///
/// # Safety
/// `config` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_telemetry_runtime_config_free(
    config: *mut MarmotRelayTelemetryRuntimeConfig,
) {
    crate::memory::free_guard(|| unsafe { free_boxed(config) });
}

/// One published relay list (NIP-65 or Marmot inbox) for an account.
#[repr(C)]
pub struct MarmotRelayList {
    /// Nostr event kind of the published list.
    pub kind: u64,
    pub relays: *mut *mut c_char,
    pub relays_len: usize,
}

impl From<RelayListFfi> for MarmotRelayList {
    fn from(value: RelayListFfi) -> Self {
        let (relays, relays_len) = owned_vec(
            value
                .relays
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            kind: value.kind,
            relays,
            relays_len,
        }
    }
}

impl CFree for MarmotRelayList {
    unsafe fn free_in_place(&mut self) {
        unsafe { free_vec(self.relays, self.relays_len) };
    }
}

/// A relay list the account is missing, as a stable typed variant clients
/// localize without parsing strings.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarmotMissingRelayListKind {
    /// NIP-65 relay list — where this account publishes (outbox/write-side).
    Nip65,
    /// Marmot inbox relay list — where this account receives (inbox/read-side).
    Inbox,
}

impl From<MissingRelayListKindFfi> for MarmotMissingRelayListKind {
    fn from(value: MissingRelayListKindFfi) -> Self {
        match value {
            MissingRelayListKindFfi::Nip65 => Self::Nip65,
            MissingRelayListKindFfi::Inbox => Self::Inbox,
        }
    }
}

impl CFree for MarmotMissingRelayListKind {
    unsafe fn free_in_place(&mut self) {}
}

/// Per-account relay lists: the NIP-65 and inbox lists the account has
/// published, plus the configured default/bootstrap sets
/// (`marmot_account_relay_lists`).
#[repr(C)]
pub struct MarmotAccountRelayLists {
    /// Whether both required relay lists have been published.
    pub complete: bool,
    pub missing: *mut MarmotMissingRelayListKind,
    pub missing_len: usize,
    pub default_relays: *mut *mut c_char,
    pub default_relays_len: usize,
    pub bootstrap_relays: *mut *mut c_char,
    pub bootstrap_relays_len: usize,
    pub nip65: MarmotRelayList,
    pub inbox: MarmotRelayList,
}

impl From<AccountRelayListsFfi> for MarmotAccountRelayLists {
    fn from(value: AccountRelayListsFfi) -> Self {
        let (missing, missing_len) = owned_vec(value.missing.into_iter().map(Into::into).collect());
        let (default_relays, default_relays_len) = owned_vec(
            value
                .default_relays
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        let (bootstrap_relays, bootstrap_relays_len) = owned_vec(
            value
                .bootstrap_relays
                .into_iter()
                .map(owned_c_string)
                .collect::<Vec<_>>(),
        );
        Self {
            complete: value.complete,
            missing,
            missing_len,
            default_relays,
            default_relays_len,
            bootstrap_relays,
            bootstrap_relays_len,
            nip65: value.nip65.into(),
            inbox: value.inbox.into(),
        }
    }
}

impl CFree for MarmotAccountRelayLists {
    unsafe fn free_in_place(&mut self) {
        unsafe {
            free_vec(self.missing, self.missing_len);
            free_vec(self.default_relays, self.default_relays_len);
            free_vec(self.bootstrap_relays, self.bootstrap_relays_len);
            self.nip65.free_in_place();
            self.inbox.free_in_place();
        }
    }
}

/// Free an account relay lists root. NULL is a no-op.
///
/// # Safety
/// `lists` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_relay_lists_free(lists: *mut MarmotAccountRelayLists) {
    crate::memory::free_guard(|| unsafe { free_boxed(lists) });
}

/// Live relay-plane connection health for the diagnostics view
/// (`marmot_relay_health`).
#[repr(C)]
pub struct MarmotRelayHealth {
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

impl From<RelayHealthFfi> for MarmotRelayHealth {
    fn from(value: RelayHealthFfi) -> Self {
        Self {
            sdk_backed: value.sdk_backed,
            total_relays: value.total_relays,
            initialized: value.initialized,
            pending: value.pending,
            connecting: value.connecting,
            connected: value.connected,
            disconnected: value.disconnected,
            terminated: value.terminated,
            banned: value.banned,
            sleeping: value.sleeping,
            connection_attempts: value.connection_attempts,
            connection_successes: value.connection_successes,
        }
    }
}

impl CFree for MarmotRelayHealth {
    unsafe fn free_in_place(&mut self) {}
}

/// Free a relay health root. NULL is a no-op.
///
/// # Safety
/// `health` must be NULL or an unfreed pointer returned by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_health_free(health: *mut MarmotRelayHealth) {
    crate::memory::free_guard(|| unsafe { free_boxed(health) });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::boxed;

    fn sample_resource() -> RelayTelemetryResourceFfi {
        RelayTelemetryResourceFfi {
            service_version: "1.2.3".into(),
            service_instance_id: "install-42".into(),
            deployment_environment: "production".into(),
            tenant: "acme".into(),
            os_type: "linux".into(),
            os_version: "7.0".into(),
            device_model_identifier: Some("Burrow-9".into()),
        }
    }

    fn sample_account_relay_lists() -> AccountRelayListsFfi {
        AccountRelayListsFfi {
            complete: false,
            missing: vec![
                MissingRelayListKindFfi::Nip65,
                MissingRelayListKindFfi::Inbox,
            ],
            default_relays: vec!["wss://default.example".into()],
            bootstrap_relays: vec!["wss://boot-a.example".into(), "wss://boot-b.example".into()],
            nip65: RelayListFfi {
                kind: 10002,
                relays: vec!["wss://write.example".into()],
            },
            inbox: RelayListFfi {
                kind: 10050,
                relays: vec!["wss://read.example".into()],
            },
        }
    }

    #[test]
    fn telemetry_settings_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();

        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotRelayTelemetrySettings = RelayTelemetrySettingsFfi {
            export_enabled: true,
            export_interval_seconds: 900,
        }
        .into();
        assert!(mirror.export_enabled);
        assert_eq!(mirror.export_interval_seconds, 900);
        let ffi = mirror.to_ffi();
        assert!(ffi.export_enabled);
        assert_eq!(ffi.export_interval_seconds, 900);
        let root = boxed(mirror);
        unsafe { marmot_relay_telemetry_settings_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn telemetry_resource_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();

        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotRelayTelemetryResource = sample_resource().into();
        let ffi = unsafe { mirror.to_ffi() }.expect("valid strings");
        assert_eq!(ffi.service_version, "1.2.3");
        assert_eq!(ffi.tenant, "acme");
        assert_eq!(ffi.device_model_identifier.as_deref(), Some("Burrow-9"));
        let root = boxed(mirror);
        unsafe { marmot_relay_telemetry_resource_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn telemetry_runtime_config_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();

        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotRelayTelemetryRuntimeConfig = RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: Some("https://otlp.example/v1/metrics".into()),
            authorization_bearer_token: Some("secret-token".into()),
            resource: Some(sample_resource()),
        }
        .into();
        assert!(!mirror.otlp_endpoint.is_null());
        assert!(!mirror.authorization_bearer_token.is_null());
        assert!(!mirror.resource.is_null());
        let ffi = unsafe { mirror.to_ffi() }.expect("valid input");
        assert_eq!(
            ffi.otlp_endpoint.as_deref(),
            Some("https://otlp.example/v1/metrics")
        );
        assert_eq!(
            ffi.authorization_bearer_token.as_deref(),
            Some("secret-token")
        );
        assert_eq!(
            ffi.resource.expect("resource present").service_instance_id,
            "install-42"
        );
        let root = boxed(mirror);
        unsafe { marmot_relay_telemetry_runtime_config_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn account_relay_lists_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();

        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotAccountRelayLists = sample_account_relay_lists().into();
        assert!(!mirror.complete);
        assert_eq!(mirror.missing_len, 2);
        assert_eq!(
            unsafe { *mirror.missing },
            MarmotMissingRelayListKind::Nip65
        );
        assert_eq!(mirror.default_relays_len, 1);
        assert_eq!(mirror.bootstrap_relays_len, 2);
        assert_eq!(mirror.nip65.kind, 10002);
        assert_eq!(mirror.nip65.relays_len, 1);
        assert_eq!(mirror.inbox.kind, 10050);
        assert_eq!(mirror.inbox.relays_len, 1);
        let root = boxed(mirror);
        unsafe { marmot_account_relay_lists_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn relay_health_deep_roundtrip() {
        let _guard = crate::memory::audit::test_lock();

        #[cfg(feature = "alloc-audit")]
        let start = crate::memory::audit::live_allocations();

        let mirror: MarmotRelayHealth = RelayHealthFfi {
            sdk_backed: true,
            total_relays: 8,
            initialized: 8,
            pending: 1,
            connecting: 2,
            connected: 3,
            disconnected: 1,
            terminated: 1,
            banned: 0,
            sleeping: 0,
            connection_attempts: 21,
            connection_successes: 20,
        }
        .into();
        assert!(mirror.sdk_backed);
        assert_eq!(mirror.total_relays, 8);
        assert_eq!(mirror.connected, 3);
        assert_eq!(mirror.connection_successes, 20);
        let root = boxed(mirror);
        unsafe { marmot_relay_health_free(root) };

        #[cfg(feature = "alloc-audit")]
        assert_eq!(crate::memory::audit::live_allocations(), start);
    }

    #[test]
    fn empty_and_none_convert_to_null() {
        let _guard = crate::memory::audit::test_lock();
        let config: MarmotRelayTelemetryRuntimeConfig = RelayTelemetryRuntimeConfigFfi {
            otlp_endpoint: None,
            authorization_bearer_token: None,
            resource: None,
        }
        .into();
        assert!(config.otlp_endpoint.is_null());
        assert!(config.authorization_bearer_token.is_null());
        assert!(config.resource.is_null());
        let ffi = unsafe { config.to_ffi() }.expect("all-NULL input is valid");
        assert_eq!(ffi.otlp_endpoint, None);
        assert_eq!(ffi.authorization_bearer_token, None);
        assert!(ffi.resource.is_none());
        let config_root = boxed(config);
        unsafe { marmot_relay_telemetry_runtime_config_free(config_root) };

        let lists: MarmotAccountRelayLists = AccountRelayListsFfi {
            complete: true,
            missing: vec![],
            default_relays: vec![],
            bootstrap_relays: vec![],
            nip65: RelayListFfi {
                kind: 10002,
                relays: vec![],
            },
            inbox: RelayListFfi {
                kind: 10050,
                relays: vec![],
            },
        }
        .into();
        assert!(lists.missing.is_null());
        assert_eq!(lists.missing_len, 0);
        assert!(lists.default_relays.is_null());
        assert!(lists.bootstrap_relays.is_null());
        assert!(lists.nip65.relays.is_null());
        assert_eq!(lists.nip65.relays_len, 0);
        let lists_root = boxed(lists);
        unsafe { marmot_account_relay_lists_free(lists_root) };
    }
}
