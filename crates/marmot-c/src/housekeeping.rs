//! Background housekeeping mode (mdk#2923): hold cleanup of finished and
//! expired work while the host app is in the background.
use crate::commands::{deliver_scalar, deliver_unit, try_arg};
use crate::macros::c_enum;
use crate::memory::required_str;
use crate::{MarmotClient, MarmotStatus, client_ref, ffi_guard, preflight_out};
use marmot_uniffi::conversions::*;
use std::ffi::c_char;

c_enum! {
    /// Whether an account's housekeeping runs. Background holds cleanup of
    /// finished and expired work (apart from a run every 12 hours); messaging
    /// is unaffected. Normal is the default, and what a cold start uses.
    MarmotHousekeepingMode from HousekeepingModeFfi {
        Normal,
        Background,
    }
}

/// Writes the account's housekeeping mode as a MarmotHousekeepingMode
/// discriminant.
/// # Safety
/// Client and string must be live; out must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_housekeeping_mode(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_mode: *mut u32,
) -> MarmotStatus {
    ffi_guard(|| {
        try_arg!(unsafe { preflight_out(out_mode) });
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_scalar(
                client
                    .marmot
                    .housekeeping_mode(account)
                    .map(|mode| MarmotHousekeepingMode::from(mode) as u32),
                out_mode,
            )
        }
    })
}

/// Sets the account's housekeeping mode (a MarmotHousekeepingMode
/// discriminant). Background holds the prune sweeps, the media-store sweep,
/// the housekeeping batch, the avatar pass, the content report backfill and
/// legacy message promotion, each still run once every 12 hours; Normal runs
/// each held job once. Process-local: set it again after a cold start.
/// # Safety
/// Client and string must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_housekeeping_mode(
    client: *const MarmotClient,
    account_ref: *const c_char,
    mode: u32,
) -> MarmotStatus {
    ffi_guard(|| {
        let mode = try_arg!(MarmotHousekeepingMode::from_c(mode));
        let client = try_arg!(unsafe { client_ref(client) });
        let account = try_arg!(unsafe { required_str(account_ref) });
        let mode = match mode {
            MarmotHousekeepingMode::Normal => HousekeepingModeFfi::Normal,
            MarmotHousekeepingMode::Background => HousekeepingModeFfi::Background,
        };
        deliver_unit(client.marmot.set_housekeeping_mode(account, mode))
    })
}
