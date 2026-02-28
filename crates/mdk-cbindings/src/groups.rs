//! Group management functions.

use std::os::raw::c_char;

use nostr::Event;

use mdk_core::groups::{NostrGroupConfigData, NostrGroupDataUpdate};

use crate::error::{self, MdkError};
use crate::types::{
    self, MdkHandle, cstr_to_str, ffi_try_unwind_safe, lock_handle, parse_group_id, parse_json,
    parse_public_keys, parse_relay_urls, to_json, write_cstring_to,
};

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// JSON envelope for `CreateGroupResult`.
#[derive(serde::Serialize)]
struct CreateGroupResultJson {
    group: serde_json::Value,
    welcome_rumors_json: Vec<String>,
}

/// JSON envelope for `UpdateGroupResult`.
#[derive(serde::Serialize)]
struct UpdateGroupResultJson {
    evolution_event_json: String,
    welcome_rumors_json: Option<Vec<String>>,
    mls_group_id: String,
}

/// JSON representation of a group data update (for input parsing).
#[derive(serde::Deserialize)]
struct GroupDataUpdateJson {
    name: Option<String>,
    description: Option<String>,
    image_hash: Option<Option<Vec<u8>>>,
    image_key: Option<Option<Vec<u8>>>,
    image_nonce: Option<Option<Vec<u8>>>,
    relays: Option<Vec<String>>,
    admins: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn serialize_update_result(
    result: mdk_core::groups::UpdateGroupResult,
) -> Result<String, MdkError> {
    let evolution_json = serde_json::to_string(&result.evolution_event)
        .map_err(|e| error::invalid_input(&format!("Failed to serialize evolution event: {e}")))?;

    let welcome_rumors: Option<Vec<String>> = result
        .welcome_rumors
        .map(|rumors| {
            rumors
                .iter()
                .map(|r| {
                    serde_json::to_string(r).map_err(|e| {
                        error::invalid_input(&format!("Failed to serialize welcome rumor: {e}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    to_json(&UpdateGroupResultJson {
        evolution_event_json: evolution_json,
        welcome_rumors_json: welcome_rumors,
        mls_group_id: hex::encode(result.mls_group_id.as_slice()),
    })
}

fn vec_to_array<const N: usize>(v: Option<Vec<u8>>) -> Result<Option<[u8; N]>, MdkError> {
    match v {
        Some(bytes) if bytes.len() == N => {
            let mut arr = [0u8; N];
            arr.copy_from_slice(&bytes);
            Ok(Some(arr))
        }
        Some(bytes) => Err(error::invalid_input(&format!(
            "Expected {N} bytes, got {} bytes",
            bytes.len()
        ))),
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Get all groups as a JSON array.
///
/// # Safety
///
/// `h` must be a valid handle. `out_json` must not be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_groups(h: *mut MdkHandle, out_json: *mut *mut c_char) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let groups = lock_handle(handle)?
            .get_groups()
            .map_err(error::from_mdk_error)?;
        let json = to_json(&groups)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get a single group by MLS group ID (hex).
///
/// On success, `*out_json` receives the group JSON or `"null"` if not found.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_group(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let group = lock_handle(handle)?
            .get_group(&gid)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&group)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get members of a group as a JSON array of hex-encoded public keys.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_members(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let members = lock_handle(handle)?
            .get_members(&gid)
            .map_err(error::from_mdk_error)?;
        let hex_keys: Vec<String> = members.iter().map(|pk| pk.to_hex()).collect();
        let json = to_json(&hex_keys)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get group IDs that need a self-update, as a JSON array of hex strings.
///
/// # Parameters
///
/// * `threshold_secs` — Groups whose last rotation is older than this are included.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_groups_needing_self_update(
    h: *mut MdkHandle,
    threshold_secs: u64,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let ids = lock_handle(handle)?
            .groups_needing_self_update(threshold_secs)
            .map_err(error::from_mdk_error)?;
        let hex_ids: Vec<String> = ids.iter().map(|id| hex::encode(id.as_slice())).collect();
        let json = to_json(&hex_ids)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Create a new group.
///
/// # Parameters
///
/// * `creator_pk`          — Hex-encoded creator public key.
/// * `key_packages_json`   — JSON array of key-package event JSON strings.
/// * `name`                — Group name.
/// * `description`         — Group description.
/// * `relays_json`         — JSON array of relay URL strings.
/// * `admins_json`         — JSON array of admin public key hex strings.
/// * `out_json`            — On success, receives a `CreateGroupResult` JSON.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_group(
    h: *mut MdkHandle,
    creator_pk: *const c_char,
    key_packages_json: *const c_char,
    name: *const c_char,
    description: *const c_char,
    relays_json: *const c_char,
    admins_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };

        let creator = types::parse_public_key(unsafe { cstr_to_str(creator_pk) }?)?;
        let name_str = unsafe { cstr_to_str(name) }?.to_string();
        let desc_str = unsafe { cstr_to_str(description) }?.to_string();
        let relay_urls = parse_relay_urls(unsafe { cstr_to_str(relays_json) }?)?;
        let admin_pks = parse_public_keys(unsafe { cstr_to_str(admins_json) }?)?;

        let kp_jsons: Vec<String> = parse_json(
            unsafe { cstr_to_str(key_packages_json) }?,
            "key packages JSON array",
        )?;
        let kp_events: Vec<Event> = kp_jsons
            .iter()
            .map(|j| parse_json(j, "key package event JSON"))
            .collect::<Result<Vec<_>, _>>()?;

        let config = NostrGroupConfigData::new(
            name_str, desc_str, None, // image_hash
            None, // image_key
            None, // image_nonce
            relay_urls, admin_pks,
        );

        let mdk = lock_handle(handle)?;
        let result = mdk
            .create_group(&creator, kp_events, config)
            .map_err(error::from_mdk_error)?;

        let welcome_rumors: Vec<String> = result
            .welcome_rumors
            .iter()
            .map(|r| {
                serde_json::to_string(r).map_err(|e| {
                    error::invalid_input(&format!("Failed to serialize welcome rumor: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let group_json = serde_json::to_value(&result.group)
            .map_err(|e| error::invalid_input(&format!("Failed to serialize group: {e}")))?;

        let out = CreateGroupResultJson {
            group: group_json,
            welcome_rumors_json: welcome_rumors,
        };
        let json = to_json(&out)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Add members to a group.
///
/// # Parameters
///
/// * `key_packages_json` — JSON array of key-package event JSON strings.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_add_members(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    key_packages_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;

        let kp_jsons: Vec<String> = parse_json(
            unsafe { cstr_to_str(key_packages_json) }?,
            "key packages JSON array",
        )?;
        let kp_events: Vec<Event> = kp_jsons
            .iter()
            .map(|j| parse_json(j, "key package event JSON"))
            .collect::<Result<Vec<_>, _>>()?;

        let mdk = lock_handle(handle)?;
        let result = mdk
            .add_members(&gid, &kp_events)
            .map_err(error::from_mdk_error)?;
        let json = serialize_update_result(result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Remove members from a group.
///
/// # Parameters
///
/// * `pubkeys_json` — JSON array of hex-encoded public key strings.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_remove_members(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    pubkeys_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let pks = parse_public_keys(unsafe { cstr_to_str(pubkeys_json) }?)?;

        let mdk = lock_handle(handle)?;
        let result = mdk
            .remove_members(&gid, &pks)
            .map_err(error::from_mdk_error)?;
        let json = serialize_update_result(result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Update group data (name, description, image, relays, admins).
///
/// # Parameters
///
/// * `update_json` — JSON object with optional fields: `name`, `description`,
///   `image_hash`, `image_key`, `image_nonce`, `relays`, `admins`.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_update_group_data(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    update_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let update: GroupDataUpdateJson = parse_json(
            unsafe { cstr_to_str(update_json) }?,
            "group data update JSON",
        )?;

        let mut group_update = NostrGroupDataUpdate::new();
        if let Some(name) = update.name {
            group_update = group_update.name(name);
        }
        if let Some(desc) = update.description {
            group_update = group_update.description(desc);
        }
        if let Some(ih) = update.image_hash {
            group_update = group_update.image_hash(vec_to_array::<32>(ih)?);
        }
        if let Some(ik) = update.image_key {
            group_update = group_update.image_key(vec_to_array::<32>(ik)?);
        }
        if let Some(inonce) = update.image_nonce {
            group_update = group_update.image_nonce(vec_to_array::<12>(inonce)?);
        }
        if let Some(relays) = update.relays {
            let urls: Vec<nostr::RelayUrl> = relays
                .iter()
                .map(|r| {
                    nostr::RelayUrl::parse(r)
                        .map_err(|e| error::invalid_input(&format!("Invalid relay URL: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            group_update = group_update.relays(urls);
        }
        if let Some(admins) = update.admins {
            let pks: Vec<nostr::PublicKey> = admins
                .iter()
                .map(|a| types::parse_public_key(a))
                .collect::<Result<Vec<_>, _>>()?;
            group_update = group_update.admins(pks);
        }

        let mdk = lock_handle(handle)?;
        let result = mdk
            .update_group_data(&gid, group_update)
            .map_err(error::from_mdk_error)?;
        let json = serialize_update_result(result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Perform a self-update (key rotation) for a group.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_self_update(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;

        let mdk = lock_handle(handle)?;
        let result = mdk.self_update(&gid).map_err(error::from_mdk_error)?;
        let json = serialize_update_result(result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Create a proposal to leave the group.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_leave_group(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;

        let mdk = lock_handle(handle)?;
        let result = mdk.leave_group(&gid).map_err(error::from_mdk_error)?;
        let json = serialize_update_result(result)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Merge pending commit for a group.
///
/// # Safety
///
/// `h` and `mls_group_id` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_merge_pending_commit(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        lock_handle(handle)?
            .merge_pending_commit(&gid)
            .map_err(error::from_mdk_error)
    })
}

/// Clear pending commit for a group (rollback to pre-commit state).
///
/// # Safety
///
/// `h` and `mls_group_id` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_clear_pending_commit(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        lock_handle(handle)?
            .clear_pending_commit(&gid)
            .map_err(error::from_mdk_error)
    })
}

/// Sync group metadata from MLS state.
///
/// # Safety
///
/// `h` and `mls_group_id` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_sync_group_metadata(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        lock_handle(handle)?
            .sync_group_metadata_from_mls(&gid)
            .map_err(error::from_mdk_error)
    })
}

/// Get relays for a group as a JSON array of URL strings.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_relays(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        if h.is_null() {
            return Err(error::null_pointer("handle"));
        }
        if out_json.is_null() {
            return Err(error::null_pointer("out_json"));
        }
        let handle = unsafe { &*h };
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let relays = lock_handle(handle)?
            .get_relays(&gid)
            .map_err(error::from_mdk_error)?;
        let urls: Vec<String> = relays.iter().map(|r| r.to_string()).collect();
        let json = to_json(&urls)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}
