//! Group lifecycle, membership, admin, profile, and MLS-state commands.

use std::ffi::c_char;

use crate::memory::{optional_str, required_str, str_array};
use crate::status::MarmotStatus;
use crate::types::account::MarmotSendSummary;
use crate::types::group::{
    MarmotAppBlobEndpoint, MarmotAppGroupMemberRecordList, MarmotAppGroupMlsState,
    MarmotAppGroupRecord, MarmotAppQuarantinedGroupList, MarmotGroupDetails,
    MarmotGroupInviteDeclineResult, MarmotGroupManagementState, MarmotGroupMutationResult,
    MarmotMemberRef,
};
use crate::{MarmotClient, client_ref, ffi_guard};

use super::account::try_arg;
use super::{deliver, deliver_bytes, deliver_scalar, deliver_string};

/// Create a new MLS group with `name` and the given members. Members are
/// referenced by `npub` or hex account id. Writes the new group id as a hex
/// string.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `name` valid strings;
/// `member_refs` must hold `member_refs_len` valid strings (or be NULL with
/// len 0); `description` NULL or a valid string; `out_group_id_hex` valid.
/// Free the result with `marmot_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_create_group(
    client: *const MarmotClient,
    account_ref: *const c_char,
    name: *const c_char,
    member_refs: *const *const c_char,
    member_refs_len: usize,
    description: *const c_char,
    out_group_id_hex: *mut *mut c_char,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let name = try_arg!(unsafe { required_str(name) });
        let member_refs = try_arg!(unsafe { str_array(member_refs, member_refs_len) });
        let description = try_arg!(unsafe { optional_str(description) });
        unsafe {
            deliver_string(
                client.block_on(client.marmot.create_group(
                    account_ref,
                    name,
                    member_refs,
                    description,
                )),
                out_group_id_hex,
            )
        }
    })
}

/// Normalize a member reference for group-management UI. Accepts hex,
/// `npub`, `nostr:npub...`, and `marmot://profile/...` references.
///
/// # Safety
/// `client` must be a live handle; `member_ref` a valid string;
/// `out_member_ref` valid. Free with `marmot_member_ref_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_normalize_member_ref(
    client: *const MarmotClient,
    member_ref: *const c_char,
    out_member_ref: *mut *mut MarmotMemberRef,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        unsafe {
            deliver(
                client.marmot.normalize_member_ref(member_ref),
                out_member_ref,
            )
        }
    })
}

/// Membership roster for `group_id_hex`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_list` valid. Free with
/// `marmot_app_group_member_record_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_members(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_list: *mut *mut MarmotAppGroupMemberRecordList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.group_members(account_ref, group_id_hex)),
                out_list,
            )
        }
    })
}

/// Group plus enriched member rows for detail screens.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_details` valid. Free with `marmot_group_details_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_details(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_details: *mut *mut MarmotGroupDetails,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.group_details(account_ref, group_id_hex)),
                out_details,
            )
        }
    })
}

/// Current caller permissions plus per-member action availability.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_state` valid. Free with
/// `marmot_group_management_state_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_management_state(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_state: *mut *mut MarmotGroupManagementState,
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
                        .group_management_state(account_ref, group_id_hex),
                ),
                out_state,
            )
        }
    })
}

/// Invite members (by `npub` or hex account id) into the group. Requires
/// the caller to be an admin.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `member_refs` must hold `member_refs_len` valid strings (or be
/// NULL with len 0); `out_summary` valid. Free with
/// `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_invite_members(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_refs: *const *const c_char,
    member_refs_len: usize,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_refs = try_arg!(unsafe { str_array(member_refs, member_refs_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.invite_members(
                    account_ref,
                    group_id_hex,
                    member_refs,
                )),
                out_summary,
            )
        }
    })
}

/// Remove members from the group. Requires the caller to be an admin;
/// preflight rejects self-removal and removing the last admin.
///
/// # Safety
/// Same as `marmot_invite_members`. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_remove_members(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_refs: *const *const c_char,
    member_refs_len: usize,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_refs = try_arg!(unsafe { str_array(member_refs, member_refs_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.remove_members(
                    account_ref,
                    group_id_hex,
                    member_refs,
                )),
                out_summary,
            )
        }
    })
}

/// Leave the group as the active account. Admins must self-demote first.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_summary` valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_leave_group(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.leave_group(account_ref, group_id_hex)),
                out_summary,
            )
        }
    })
}

/// Delete this group's local app data without performing an MLS leave. The
/// caller should cancel any active UI subscriptions for the group before
/// invoking the wipe. The runtime removes the active transport route, then
/// transactionally drops the chat-list/account projection, plaintext app
/// events, timeline rows, agent-stream projection rows, push-token rows,
/// and cached encrypted-media epoch secrets. MLS/OpenMLS group state is
/// left intact; a future fresh group delivery can recreate a local chat
/// row. Writes true if any local rows or a live route were removed.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_removed` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_delete_group_local(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_removed: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_scalar(
                client.block_on(client.marmot.delete_group_local(account_ref, group_id_hex)),
                out_removed,
            )
        }
    })
}

/// Set the per-group disappearing-message retention.
/// `disappearing_message_secs` of `0` disables expiry; any positive value
/// is the retention window in seconds.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_summary` valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_update_message_retention(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    disappearing_message_secs: u64,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.update_message_retention(
                    account_ref,
                    group_id_hex,
                    disappearing_message_secs,
                )),
                out_summary,
            )
        }
    })
}

/// Accept a pending group invite; writes the now-confirmed group record.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_group` valid. Free with `marmot_app_group_record_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_accept_group_invite(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_group: *mut *mut MarmotAppGroupRecord,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.accept_group_invite(account_ref, group_id_hex)),
                out_group,
            )
        }
    })
}

/// Decline a pending group invite; writes the updated group record plus
/// the publish summary of the decline.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_result` valid. Free with
/// `marmot_group_invite_decline_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_decline_group_invite(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_result: *mut *mut MarmotGroupInviteDeclineResult,
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
                        .decline_group_invite(account_ref, group_id_hex),
                ),
                out_result,
            )
        }
    })
}

/// Update the group's name and/or description. NULL leaves a field
/// unchanged.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `name` and `description` NULL or valid strings; `out_summary`
/// valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_update_group_profile(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    name: *const c_char,
    description: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let name = try_arg!(unsafe { optional_str(name) });
        let description = try_arg!(unsafe { optional_str(description) });
        unsafe {
            deliver(
                client.block_on(client.marmot.update_group_profile(
                    account_ref,
                    group_id_hex,
                    name,
                    description,
                )),
                out_summary,
            )
        }
    })
}

/// Set (or clear, with `url` NULL) the group's URL-based avatar
/// (`marmot.group.avatar-url.v1`). The URL is validated (https-only, no
/// localhost/private hosts) and normalized before it is committed.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `url`, `dim`, and `thumbhash` NULL or valid strings;
/// `out_summary` valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_update_group_avatar_url(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    url: *const c_char,
    dim: *const c_char,
    thumbhash: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let url = try_arg!(unsafe { optional_str(url) });
        let dim = try_arg!(unsafe { optional_str(dim) });
        let thumbhash = try_arg!(unsafe { optional_str(thumbhash) });
        unsafe {
            deliver(
                client.block_on(client.marmot.update_group_avatar_url(
                    account_ref,
                    group_id_hex,
                    url,
                    dim,
                    thumbhash,
                )),
                out_summary,
            )
        }
    })
}

/// Replace the group's encrypted-media default blob endpoints as a full
/// `marmot.group.encrypted-media.v1` component update. Requires the caller
/// to be an admin.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `endpoints` must point to `endpoints_len` valid caller-owned
/// structs (or be NULL with len 0) — the library never frees or retains
/// them; `out_summary` valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_replace_encrypted_media_blob_endpoints(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    endpoints: *const MarmotAppBlobEndpoint,
    endpoints_len: usize,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let endpoints = if endpoints_len == 0 {
            Vec::new()
        } else {
            if endpoints.is_null() {
                crate::status::set_last_error("endpoints argument was NULL with non-zero length");
                return MarmotStatus::NullPointer;
            }
            let borrowed = unsafe { std::slice::from_raw_parts(endpoints, endpoints_len) };
            let mut converted = Vec::with_capacity(endpoints_len);
            for endpoint in borrowed {
                converted.push(try_arg!(unsafe { endpoint.to_ffi() }));
            }
            converted
        };
        unsafe {
            deliver(
                client.block_on(client.marmot.replace_encrypted_media_blob_endpoints(
                    account_ref,
                    group_id_hex,
                    endpoints,
                )),
                out_summary,
            )
        }
    })
}

/// Fetch, verify, and decrypt the group's Blossom-hosted encrypted image,
/// writing the plaintext bytes to `out_data`/`out_len`. The image hash comes
/// from `MarmotAppGroupRecord.image_hash_hex`. Needs a relay/Blossom, so it
/// fails offline. Free the buffer with `marmot_bytes_free`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_data` and `out_len` valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_download_group_blossom_image(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_data: *mut *mut u8,
    out_len: *mut usize,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_bytes(
                client.block_on(
                    client
                        .marmot
                        .download_group_blossom_image(account_ref, group_id_hex),
                ),
                out_data,
                out_len,
            )
        }
    })
}

/// Grant admin rights to `member_ref` (npub or hex). Requires the caller
/// to be an admin; publishes a group state update.
///
/// # Safety
/// `client` must be a live handle; `account_ref`, `group_id_hex`, and
/// `member_ref` valid strings; `out_summary` valid. Free with
/// `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_promote_admin(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_ref: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .promote_admin(account_ref, group_id_hex, member_ref),
                ),
                out_summary,
            )
        }
    })
}

/// Revoke `member_ref`'s admin rights.
///
/// # Safety
/// Same as `marmot_promote_admin`. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_demote_admin(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_ref: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        unsafe {
            deliver(
                client.block_on(
                    client
                        .marmot
                        .demote_admin(account_ref, group_id_hex, member_ref),
                ),
                out_summary,
            )
        }
    })
}

/// Step down as an admin of `group_id_hex` (demote the active account).
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_summary` valid. Free with `marmot_send_summary_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_self_demote_admin(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_summary: *mut *mut MarmotSendSummary,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.self_demote_admin(account_ref, group_id_hex)),
                out_summary,
            )
        }
    })
}

/// `marmot_invite_members` plus refreshed group details and management
/// state in one round trip.
///
/// # Safety
/// Same as `marmot_invite_members`; `out_result` valid. Free with
/// `marmot_group_mutation_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_invite_members_detailed(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_refs: *const *const c_char,
    member_refs_len: usize,
    out_result: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_refs = try_arg!(unsafe { str_array(member_refs, member_refs_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.invite_members_detailed(
                    account_ref,
                    group_id_hex,
                    member_refs,
                )),
                out_result,
            )
        }
    })
}

/// `marmot_remove_members` plus refreshed group details and management
/// state in one round trip.
///
/// # Safety
/// Same as `marmot_remove_members`; `out_result` valid. Free with
/// `marmot_group_mutation_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_remove_members_detailed(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_refs: *const *const c_char,
    member_refs_len: usize,
    out_result: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_refs = try_arg!(unsafe { str_array(member_refs, member_refs_len) });
        unsafe {
            deliver(
                client.block_on(client.marmot.remove_members_detailed(
                    account_ref,
                    group_id_hex,
                    member_refs,
                )),
                out_result,
            )
        }
    })
}

/// `marmot_promote_admin` plus refreshed group details and management
/// state in one round trip.
///
/// # Safety
/// Same as `marmot_promote_admin`; `out_result` valid. Free with
/// `marmot_group_mutation_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_promote_admin_detailed(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_ref: *const c_char,
    out_result: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.promote_admin_detailed(
                    account_ref,
                    group_id_hex,
                    member_ref,
                )),
                out_result,
            )
        }
    })
}

/// `marmot_demote_admin` plus refreshed group details and management state
/// in one round trip.
///
/// # Safety
/// Same as `marmot_demote_admin`; `out_result` valid. Free with
/// `marmot_group_mutation_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_demote_admin_detailed(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    member_ref: *const c_char,
    out_result: *mut *mut MarmotGroupMutationResult,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        let member_ref = try_arg!(unsafe { required_str(member_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.demote_admin_detailed(
                    account_ref,
                    group_id_hex,
                    member_ref,
                )),
                out_result,
            )
        }
    })
}

/// `marmot_self_demote_admin` plus refreshed group details and management
/// state in one round trip.
///
/// # Safety
/// Same as `marmot_self_demote_admin`; `out_result` valid. Free with
/// `marmot_group_mutation_result_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_self_demote_admin_detailed(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_result: *mut *mut MarmotGroupMutationResult,
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
                        .self_demote_admin_detailed(account_ref, group_id_hex),
                ),
                out_result,
            )
        }
    })
}

/// Current MLS state (epoch, member count, required components) for the
/// conversation developer/debug view.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_state` valid. Free with `marmot_app_group_mls_state_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_group_mls_state(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_state: *mut *mut MarmotAppGroupMlsState,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.group_mls_state(account_ref, group_id_hex)),
                out_state,
            )
        }
    })
}

/// Stored groups that failed session-open hydration and were skipped so
/// the rest of the account could open. These groups are not in the live
/// roster and otherwise vanish from the account with no explanation;
/// surface them in a per-group recovery flow distinct from healthy and
/// archived groups, using `reason` to pick the per-reason guidance, and
/// offer `marmot_retry_hydrate_quarantined_group`.
///
/// # Safety
/// `client` must be a live handle; `account_ref` a valid string;
/// `out_list` valid. Free with `marmot_app_quarantined_group_list_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_quarantined_groups(
    client: *const MarmotClient,
    account_ref: *const c_char,
    out_list: *mut *mut MarmotAppQuarantinedGroupList,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        unsafe {
            deliver(
                client.block_on(client.marmot.quarantined_groups(account_ref)),
                out_list,
            )
        }
    })
}

/// Re-attempt hydration of a single quarantined group.
///
/// Non-destructive, user-initiated recovery for a transiently-bad group
/// (e.g. a partial DB restore that has since completed). Writes `true` if
/// the group recovered and is now a live chat (it leaves the quarantine
/// list and reappears in the chat list), `false` if it is still unhealthy
/// and stays quarantined. Errors with the unknown-group status if the id
/// is not currently quarantined.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_recovered` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_retry_hydrate_quarantined_group(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    out_recovered: *mut bool,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver_scalar(
                client.block_on(
                    client
                        .marmot
                        .retry_hydrate_quarantined_group(account_ref, group_id_hex),
                ),
                out_recovered,
            )
        }
    })
}

/// Flag a group archived (or restore it). Local-only projection state —
/// it does not change membership or publish anything. The chats list
/// filters archived groups unless `include_archived` is set.
///
/// # Safety
/// `client` must be a live handle; `account_ref` and `group_id_hex` valid
/// strings; `out_group` valid. Free with `marmot_app_group_record_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn marmot_set_group_archived(
    client: *const MarmotClient,
    account_ref: *const c_char,
    group_id_hex: *const c_char,
    archived: bool,
    out_group: *mut *mut MarmotAppGroupRecord,
) -> MarmotStatus {
    ffi_guard(|| {
        let client = try_arg!(unsafe { client_ref(client) });
        let account_ref = try_arg!(unsafe { required_str(account_ref) });
        let group_id_hex = try_arg!(unsafe { required_str(group_id_hex) });
        unsafe {
            deliver(
                client.block_on(client.marmot.set_group_archived(
                    account_ref,
                    group_id_hex,
                    archived,
                )),
                out_group,
            )
        }
    })
}
