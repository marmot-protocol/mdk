//! Account lifecycle, key-package, relay-list, and profile commands.

use std::ffi::c_char;

use crate::memory::{required_str, str_array};
use crate::status::MarmotStatus;
use crate::types::account::{
    MarmotAccountKeyPackageList, MarmotAccountSummary, MarmotAccountSummaryList,
    MarmotAccountUnreadList, MarmotSignOutOutcome, MarmotUserProfileMetadata, MarmotWipeOutcome,
};
use crate::types::common::MarmotStringList;
use crate::types::relay::MarmotAccountRelayLists;
use crate::{MarmotClient, client_ref, ffi_guard};

use super::{deliver, deliver_scalar, deliver_string, deliver_unit};

/// Shorthand used by every command wrapper: validate + read an argument,
/// or return the argument's status code from the enclosing function.
macro_rules! try_arg {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err(status) => return status,
        }
    };
}
pub(crate) use try_arg;

/// List every account known to this device.
///
/// # Safety
/// `client` must be a live handle; `out_list` must be a valid pointer.
/// Free the result with `marmot_account_summary_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_list_accounts(
    client: *const MarmotClient,
    out_list: *mut *mut MarmotAccountSummaryList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver(client.marmot.list_accounts(), out_list) }
    })
}

/// Per-account unread aggregates for the account-switcher badge.
///
/// # Safety
/// `client` must be a live handle; `out_list` must be a valid pointer.
/// Free the result with `marmot_account_unread_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_unread_summary(
    client: *const MarmotClient,
    out_list: *mut *mut MarmotAccountUnreadList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        unsafe { deliver(client.marmot.account_unread_summary(), out_list) }
    })
}

/// Remove an account and its local state from this device.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_remove_account(
    client: *const MarmotClient,
    account_ref: *const c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        deliver_unit(client.block_on(client.marmot.remove_account(account_ref)))
    })
}

/// Destructive sign-out: leave groups, delete relay KeyPackages, wipe
/// local state. Every stage is reported in the outcome.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_outcome` a valid pointer. Free with `marmot_wipe_outcome_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_sign_out_and_wipe(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_outcome: *mut *mut MarmotWipeOutcome,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.sign_out_and_wipe(account_ref)),
                out_outcome,
            )
        }
    })
}

/// Non-destructive sign-out: deactivate the account on this device,
/// keeping all local state so it can sign back in later. When
/// `delete_key_packages` is true, relay-published KeyPackages get
/// NIP-09 deletions.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_outcome` a valid pointer. Free with `marmot_sign_out_outcome_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_sign_out(
    client: *const MarmotClient,
    account_ref: *const c_char,
    delete_key_packages: bool,
    out_outcome: *mut *mut MarmotSignOutOutcome,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.sign_out(account_ref, delete_key_packages)),
                out_outcome,
            )
        }
    })
}

/// Create a brand-new Nostr identity, store its secret in the platform
/// keychain, and publish initial relay lists + key package.
///
/// # Safety
/// `client` must be a live handle; relay arrays must hold `len` valid
/// strings (or be NULL with len 0); `out_summary` must be valid. Free
/// with `marmot_account_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_create_identity(
    client: *const MarmotClient,
    default_relays: *const *const c_char,
    default_relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_summary: *mut *mut MarmotAccountSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let default_relays = try_arg!(unsafe { str_array(default_relays, default_relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .create_identity(default_relays, bootstrap_relays),
                ),
                out_summary,
            )
        }
    })
}

/// Log in with an existing identity: an `nsec` (private key) for a
/// local-signing account, or an `npub` to track a public identity.
///
/// # Safety
/// Same as `marmot_create_identity`, plus `identity` must be a valid
/// string. Free with `marmot_account_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_login(
    client: *const MarmotClient,
    identity: *const c_char,
    default_relays: *const *const c_char,
    default_relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_summary: *mut *mut MarmotAccountSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let identity = try_arg!(unsafe { required_str(identity) });
        let default_relays = try_arg!(unsafe { str_array(default_relays, default_relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .login(identity, default_relays, bootstrap_relays),
                ),
                out_summary,
            )
        }
    })
}

/// Re-activate a non-destructively signed-out local account.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_summary` valid. Free with `marmot_account_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_sign_in_account(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_summary: *mut *mut MarmotAccountSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.sign_in_account(account_ref)),
                out_summary,
            )
        }
    })
}

/// Publish NIP-65 + inbox relay lists for the account.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string; relay
/// arrays must hold `len` valid strings (or NULL with len 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_publish_relay_lists(
    client: *const MarmotClient,
    account_ref: *const c_char,
    default_relays: *const *const c_char,
    default_relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let default_relays = try_arg!(unsafe { str_array(default_relays, default_relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        deliver_unit(client.block_on(client.marmot.publish_relay_lists(
            account_ref,
            default_relays,
            bootstrap_relays,
        )))
    })
}

/// The account's NIP-65 relay list.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_list` valid. Free with `marmot_string_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_nip65_relays(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_list: *mut *mut MarmotStringList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe { deliver(client.marmot.account_nip65_relays(account_ref), out_list) }
    })
}

/// The account's inbox relay list.
///
/// # Safety
/// Same as `marmot_account_nip65_relays`. Free with
/// `marmot_string_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_inbox_relays(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_list: *mut *mut MarmotStringList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe { deliver(client.marmot.account_inbox_relays(account_ref), out_list) }
    })
}

/// Local + relay-published KeyPackages for the account.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string; the
/// relay array must hold `len` valid strings (or NULL with len 0);
/// `out_list` valid. Free with `marmot_account_key_package_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_account_key_packages(
    client: *const MarmotClient,
    account_ref: *const c_char,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_list: *mut *mut MarmotAccountKeyPackageList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .account_key_packages(account_ref, bootstrap_relays),
                ),
                out_list,
            )
        }
    })
}

/// Publish a fresh KeyPackage. Writes the number of relays that accepted
/// the publish to `out_accepted`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_accepted` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_publish_new_key_package(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_accepted: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.publish_new_key_package(account_ref)),
                out_accepted,
            )
        }
    })
}

/// Re-publish the latest cached KeyPackage when possible, otherwise
/// publish a fresh one. Writes the accepting-relay count.
///
/// # Safety
/// Same as `marmot_publish_new_key_package`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_republish_key_package(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_accepted: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.republish_key_package(account_ref)),
                out_accepted,
            )
        }
    })
}

/// Publish a NIP-09 deletion for a KeyPackage event. Writes the
/// accepting-relay count.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `event_id_hex`
/// valid strings; the relay array must hold `len` valid strings (or
/// NULL with len 0); `out_accepted` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_delete_account_key_package(
    client: *const MarmotClient,
    account_ref: *const c_char,
    event_id_hex: *const c_char,
    relays: *const *const c_char,
    relays_len: usize,
    out_accepted: *mut u64,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let event_id_hex = try_arg!(unsafe { required_str(event_id_hex) });
        let relays = try_arg!(unsafe { str_array(relays, relays_len) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.delete_account_key_package(
                    account_ref,
                    event_id_hex,
                    relays,
                )),
                out_accepted,
            )
        }
    })
}

/// Replace the account's NIP-65 relay list and publish it.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string; relay
/// arrays valid per `marmot_publish_relay_lists`; `out_lists` valid.
/// Free with `marmot_account_relay_lists_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_account_nip65_relays(
    client: *const MarmotClient,
    account_ref: *const c_char,
    relays: *const *const c_char,
    relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_lists: *mut *mut MarmotAccountRelayLists,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let relays = try_arg!(unsafe { str_array(relays, relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.set_account_nip65_relays(
                    account_ref,
                    relays,
                    bootstrap_relays,
                )),
                out_lists,
            )
        }
    })
}

/// Replace the account's inbox relay list and publish it.
///
/// # Safety
/// Same as `marmot_set_account_nip65_relays`. Free with
/// `marmot_account_relay_lists_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_account_inbox_relays(
    client: *const MarmotClient,
    account_ref: *const c_char,
    relays: *const *const c_char,
    relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_lists: *mut *mut MarmotAccountRelayLists,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let relays = try_arg!(unsafe { str_array(relays, relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.set_account_inbox_relays(
                    account_ref,
                    relays,
                    bootstrap_relays,
                )),
                out_lists,
            )
        }
    })
}

/// Export the account's raw private key as `nsec1…` bech32.
///
/// SENSITIVE: the reveal is audit-logged and permanently marks the
/// account's key-security byte as handled-insecurely. Free the returned
/// string with `marmot_string_free` as soon as it has been displayed;
/// the library cannot zero caller-held copies.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_nsec` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_reveal_nsec(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_nsec: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe { deliver_string(client.marmot.reveal_nsec(account_ref), out_nsec) }
    })
}

/// Export the account's private key NIP-49-encrypted under `passphrase`.
/// Free the result with `marmot_string_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `passphrase` valid
/// strings; `out_encrypted` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_export_encrypted_secret_key(
    client: *const MarmotClient,
    account_ref: *const c_char,
    passphrase: *const c_char,
    out_encrypted: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let passphrase = try_arg!(unsafe { required_str(passphrase) });
        unsafe {
            deliver_string(
                client
                    .marmot
                    .export_encrypted_secret_key(account_ref, passphrase),
                out_encrypted,
            )
        }
    })
}

/// Publish the account's kind:0 profile metadata. The returned profile is
/// what was actually published (server-applied defaults reflected).
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `profile` a valid borrowed struct (never freed by the library); relay
/// arrays valid per `marmot_publish_relay_lists`; `out_profile` valid.
/// Free the result with `marmot_user_profile_metadata_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_publish_user_profile(
    client: *const MarmotClient,
    account_ref: *const c_char,
    profile: *const MarmotUserProfileMetadata,
    default_relays: *const *const c_char,
    default_relays_len: usize,
    bootstrap_relays: *const *const c_char,
    bootstrap_relays_len: usize,
    out_profile: *mut *mut MarmotUserProfileMetadata,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        if profile.is_null() {
            crate::status::set_last_error("profile argument was NULL");
            return MarmotStatus::NullPointer;
        }
        let profile = try_arg!(unsafe { (*profile).to_ffi() });
        let default_relays = try_arg!(unsafe { str_array(default_relays, default_relays_len) });
        let bootstrap_relays =
            try_arg!(unsafe { str_array(bootstrap_relays, bootstrap_relays_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.publish_user_profile(
                    account_ref,
                    profile,
                    default_relays,
                    bootstrap_relays,
                )),
                out_profile,
            )
        }
    })
}
