//! Notification settings, catch-up, and background-collection commands.

use std::ffi::c_char;

use crate::memory::required_str;
use crate::status::MarmotStatus;
use crate::types::notification::{
    MarmotBackgroundNotificationCollection, MarmotNotificationSettings,
    MarmotNotificationWakeSource,
};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::{deliver, deliver_unit};

/// The account's current notification preferences.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_settings` a valid pointer. Free the result with
/// `marmot_notification_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_notification_settings(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_settings: *mut *mut MarmotNotificationSettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.marmot.notification_settings(account_ref),
                out_settings,
            )
        }
    })
}

/// Enable or disable locally rendered notifications for the account.
/// Returns the updated settings.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_settings` a valid pointer. Free the result with
/// `marmot_notification_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_local_notifications_enabled(
    client: *const MarmotClient,
    account_ref: *const c_char,
    enabled: bool,
    out_settings: *mut *mut MarmotNotificationSettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client
                    .marmot
                    .set_local_notifications_enabled(account_ref, enabled),
                out_settings,
            )
        }
    })
}

/// Enable or disable native push (APNs/FCM) delivery for the account.
/// Returns the updated settings.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_settings` a valid pointer. Free the result with
/// `marmot_notification_settings_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_native_push_enabled(
    client: *const MarmotClient,
    account_ref: *const c_char,
    enabled: bool,
    out_settings: *mut *mut MarmotNotificationSettings,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.set_native_push_enabled(account_ref, enabled)),
                out_settings,
            )
        }
    })
}

/// Catch up all accounts on missed events (explicit foreground catch-up).
///
/// # Safety
/// `client` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_catch_up_accounts(client: *const MarmotClient) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        deliver_unit(client.block_on(client.marmot.catch_up_accounts()))
    })
}

/// Run a bounded background notification collection pass after a platform
/// wake (`source`), waiting at most `max_wait_ms` milliseconds. Infallible:
/// collection failures are reported inside the returned record's `status`
/// and `error` fields.
///
/// # Safety
/// `client` must be a live handle; `out_collection` a valid pointer. Free
/// the result with `marmot_background_notification_collection_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_collect_notifications_after_wake(
    client: *const MarmotClient,
    max_wait_ms: u32,
    source: MarmotNotificationWakeSource,
    out_collection: *mut *mut MarmotBackgroundNotificationCollection,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let source = source.to_ffi();
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .collect_notifications_after_wake(max_wait_ms, source),
                ),
                out_collection,
            )
        }
    })
}
