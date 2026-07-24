//! Relay-list, relay-health, and relay-telemetry commands.

use std::ffi::c_char;

use crate::memory::required_str;
use crate::status::MarmotStatus;
use crate::types::relay::{
    MarmotAccountRelayLists, MarmotRelayHealth, MarmotRelayTelemetryRuntimeConfig,
    MarmotRelayTelemetrySettings,
};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::{deliver, deliver_string, deliver_unit};

/// Per-account relay lists: the NIP-65 and inbox lists the account has
/// published, plus the configured default/bootstrap sets.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_lists` a valid pointer. Free the result with
/// `marmot_account_relay_lists_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_relay_lists(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_lists: *mut *mut MarmotAccountRelayLists,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe { deliver(client.marmot.account_relay_lists(account_ref), out_lists) }
    })
}

/// Live relay-plane connection health (connected / connecting /
/// disconnected counts, etc.) for the relay diagnostics view.
///
/// # Safety
/// `client` must be a live handle; `out_health` a valid pointer. Free
/// the result with `marmot_relay_health_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_health(
    client: *const MarmotClient,
    out_health: *mut *mut MarmotRelayHealth,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe {
            deliver(
                Ok(client.block_on(client.marmot.relay_health())),
                out_health,
            )
        }
    })
}

/// Device-wide relay telemetry export settings. Export is opt-in and stays
/// inert until `export_enabled` is true and runtime/default config supplies
/// a valid OTLP endpoint, bearer token, and resource attributes.
///
/// # Safety
/// `client` must be a live handle; `out_settings` a valid pointer. Free
/// the result with `marmot_relay_telemetry_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_relay_telemetry_settings(
    client: *const MarmotClient,
    out_settings: *mut *mut MarmotRelayTelemetrySettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver(client.marmot.relay_telemetry_settings(), out_settings) }
    })
}

/// Stable random identifier for this app install, suitable for the OTLP
/// `service.instance.id` resource attribute. Separate from audit-log device
/// identity.
///
/// # Safety
/// `client` must be a live handle; `out_install_id` a valid pointer. Free
/// the result with `marmot_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_telemetry_install_id(
    client: *const MarmotClient,
    out_install_id: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver_string(client.marmot.telemetry_install_id(), out_install_id) }
    })
}

/// Supply non-persisted OTLP runtime metadata: optional metrics URL
/// override, bearer token from the host app's build-time secret, and
/// resource attributes from the platform shell.
///
/// # Safety
/// `client` must be a live handle; `config` must point to a valid
/// caller-owned `MarmotRelayTelemetryRuntimeConfig` (never freed by the
/// library).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_relay_telemetry_runtime_config(
    client: *const MarmotClient,
    config: *const MarmotRelayTelemetryRuntimeConfig,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        if config.is_null() {
            crate::status::set_last_error("config argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let config = try_arg!(unsafe { (*config).to_ffi() });
        deliver_unit(client.block_on(client.marmot.set_relay_telemetry_runtime_config(config)))
    })
}

/// Persist device-wide relay telemetry export settings and return the
/// normalized settings that were stored.
///
/// # Safety
/// `client` must be a live handle; `settings` must point to a valid
/// caller-owned `MarmotRelayTelemetrySettings` (never freed by the
/// library); `out_settings` a valid pointer. Free the result with
/// `marmot_relay_telemetry_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_relay_telemetry_settings(
    client: *const MarmotClient,
    settings: *const MarmotRelayTelemetrySettings,
    out_settings: *mut *mut MarmotRelayTelemetrySettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        if settings.is_null() {
            crate::status::set_last_error("settings argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let settings = unsafe { (*settings).to_ffi() };
        unsafe {
            deliver(
                client.block_on(client.marmot.set_relay_telemetry_settings(settings)),
                out_settings,
            )
        }
    })
}
