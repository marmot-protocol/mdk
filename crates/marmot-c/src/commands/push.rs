//! Native-push registration and group push-debug commands.

use std::ffi::c_char;

use crate::memory::{optional_str, required_str};
use crate::status::MarmotStatus;
use crate::types::push::{MarmotGroupPushDebugInfo, MarmotPushPlatform, MarmotPushRegistration};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::{deliver, deliver_opt, deliver_unit};

/// The account's current local native-push registration, if any. Writes
/// NULL with `MARMOT_STATUS_OK` when no registration exists — callers
/// distinguish "absent" from failure by the status code.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_registration` a valid pointer. Free a non-NULL result with
/// `marmot_push_registration_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_push_registration(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_registration: *mut *mut MarmotPushRegistration,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_opt(
                client.marmot.push_registration(account_ref),
                out_registration,
            )
        }
    })
}

/// Create or update the account's native-push registration for a device
/// token. Only a privacy-safe fingerprint of `raw_token` is ever returned
/// or stored in the registration record.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `raw_token`, and
/// `server_pubkey_hex` valid strings; `relay_hint` a valid string or NULL;
/// `out_registration` a valid pointer. Free the result with
/// `marmot_push_registration_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_upsert_push_registration(
    client: *const MarmotClient,
    account_ref: *const c_char,
    platform: MarmotPushPlatform,
    raw_token: *const c_char,
    server_pubkey_hex: *const c_char,
    relay_hint: *const c_char,
    out_registration: *mut *mut MarmotPushRegistration,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let raw_token = try_arg!(unsafe { required_str(raw_token) });
        let server_pubkey_hex = try_arg!(unsafe { required_str(server_pubkey_hex) });
        let relay_hint = try_arg!(unsafe { optional_str(relay_hint) });
        unsafe {
            deliver(
                client.block_on(client.marmot.upsert_push_registration(
                    account_ref,
                    platform.to_ffi(),
                    raw_token,
                    server_pubkey_hex,
                    relay_hint,
                )),
                out_registration,
            )
        }
    })
}

/// Remove the account's local native-push registration.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_clear_push_registration(
    client: *const MarmotClient,
    account_ref: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        deliver_unit(client.block_on(client.marmot.clear_push_registration(account_ref)))
    })
}

/// Aggregated push-token diagnostics for one group: token counts, the
/// local member's registration state, and every cached member token entry.
///
/// `group_id_hex` is the hex of the opaque MLS `GroupId` bytes (variable
/// length), not the 32-byte Nostr routing id.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_info` a valid pointer. Free the result with
/// `marmot_group_push_debug_info_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_push_debug_info(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_info: *mut *mut MarmotGroupPushDebugInfo,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .group_push_debug_info(account_ref, group_id_hex),
                ),
                out_info,
            )
        }
    })
}
