//! Message functions.

use std::os::raw::c_char;

use nostr::{Event, EventBuilder, Kind, PublicKey, Tag};

use mdk_core::messages::MessageProcessingResult;
use mdk_storage_traits::groups::Pagination as MessagePagination;

use crate::error::{self, MdkError};
use crate::types::{
    MdkHandle, cstr_to_str, deref_handle, ffi_try_unwind_safe, lock_handle, parse_event_id,
    parse_group_id, parse_json, parse_public_key, parse_sort_order, require_non_null,
    serialize_update_result, to_json, write_cstring_to,
};

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Tagged-union JSON for `ProcessMessageResult`.
#[derive(serde::Serialize)]
struct ProcessMessageResultJson {
    #[serde(rename = "type")]
    result_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mls_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Create a message in a group.
///
/// # Parameters
///
/// * `mls_group_id` — Hex-encoded MLS group ID.
/// * `sender_pk`    — Hex-encoded sender public key.
/// * `content`      — Message content string.
/// * `kind`         — Nostr event kind (numeric).
/// * `tags_json`    — Optional JSON array of tag arrays, e.g.
///   `[["p","hex..."],["e","hex..."]]`. Pass null for no tags.
/// * `out_json`     — On success, receives the serialised Nostr event JSON.
///
/// # Safety
///
/// All non-null pointer arguments must be valid C strings.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_create_message(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    sender_pk: *const c_char,
    content: *const c_char,
    kind: u16,
    tags_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let sender: PublicKey = parse_public_key(unsafe { cstr_to_str(sender_pk) }?)?;
        let content_str = unsafe { cstr_to_str(content) }?;

        let mut builder = EventBuilder::new(Kind::Custom(kind), content_str);

        if !tags_json.is_null() {
            let tag_vecs: Vec<Vec<String>> =
                parse_json(unsafe { cstr_to_str(tags_json) }?, "tags JSON")?;
            let tags: Vec<Tag> = tag_vecs
                .into_iter()
                .map(|tv| {
                    Tag::parse(tv)
                        .map_err(|e| error::invalid_input(&format!("Failed to parse tag: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.tags(tags);
        }

        let rumor = builder.build(sender);
        let mdk = lock_handle(handle)?;
        let event = mdk
            .create_message(&gid, rumor)
            .map_err(error::from_mdk_error)?;

        let event_json = serde_json::to_string(&event)
            .map_err(|e| error::invalid_input(&format!("Failed to serialize event: {e}")))?;
        unsafe { write_cstring_to(out_json, event_json) }
    })
}

/// Process an incoming MLS message.
///
/// On success, `*out_json` receives a tagged-union JSON object with a `"type"`
/// field indicating the result variant (e.g. `"ApplicationMessage"`,
/// `"Proposal"`, `"PendingProposal"`, `"Commit"`, etc.).
///
/// # Safety
///
/// All pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_process_message(
    h: *mut MdkHandle,
    event_json: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let event: Event = parse_json(unsafe { cstr_to_str(event_json) }?, "event JSON")?;

        let mdk = lock_handle(handle)?;
        let result = mdk.process_message(&event).map_err(error::from_mdk_error)?;

        let json_obj = match result {
            MessageProcessingResult::ApplicationMessage(msg) => {
                let msg_val = serde_json::to_value(&msg).map_err(|e| {
                    error::invalid_input(&format!("Failed to serialize message: {e}"))
                })?;
                ProcessMessageResultJson {
                    result_type: "ApplicationMessage".to_string(),
                    message: Some(msg_val),
                    result: None,
                    mls_group_id: None,
                    reason: None,
                }
            }
            MessageProcessingResult::Proposal(update) => {
                let update_val = serialize_update_result(update)?;
                ProcessMessageResultJson {
                    result_type: "Proposal".to_string(),
                    message: None,
                    result: Some(update_val),
                    mls_group_id: None,
                    reason: None,
                }
            }
            MessageProcessingResult::PendingProposal { mls_group_id } => ProcessMessageResultJson {
                result_type: "PendingProposal".to_string(),
                message: None,
                result: None,
                mls_group_id: Some(hex::encode(mls_group_id.as_slice())),
                reason: None,
            },
            MessageProcessingResult::ExternalJoinProposal { mls_group_id } => {
                ProcessMessageResultJson {
                    result_type: "ExternalJoinProposal".to_string(),
                    message: None,
                    result: None,
                    mls_group_id: Some(hex::encode(mls_group_id.as_slice())),
                    reason: None,
                }
            }
            MessageProcessingResult::Commit { mls_group_id } => ProcessMessageResultJson {
                result_type: "Commit".to_string(),
                message: None,
                result: None,
                mls_group_id: Some(hex::encode(mls_group_id.as_slice())),
                reason: None,
            },
            MessageProcessingResult::Unprocessable { mls_group_id } => ProcessMessageResultJson {
                result_type: "Unprocessable".to_string(),
                message: None,
                result: None,
                mls_group_id: Some(hex::encode(mls_group_id.as_slice())),
                reason: None,
            },
            MessageProcessingResult::IgnoredProposal {
                mls_group_id,
                reason,
            } => ProcessMessageResultJson {
                result_type: "IgnoredProposal".to_string(),
                message: None,
                result: None,
                mls_group_id: Some(hex::encode(mls_group_id.as_slice())),
                reason: Some(reason),
            },
            MessageProcessingResult::PreviouslyFailed => ProcessMessageResultJson {
                result_type: "PreviouslyFailed".to_string(),
                message: None,
                result: None,
                mls_group_id: None,
                reason: None,
            },
        };

        let json = to_json(&json_obj)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get messages for a group with optional pagination.
///
/// # Parameters
///
/// * `limit`      — Maximum number of messages to return.  **`0` is a sentinel
///   value meaning "no limit"** (the storage layer's default applies, typically
///   1000). Any positive value is used as a literal cap.
/// * `offset`     — Number of messages to skip from the beginning of the result
///   set.  **`0` is a sentinel value meaning "no offset"** (start from the
///   first matching message). Any positive value skips that many rows.
/// * `sort_order` — Optional: `"created_at_first"` or `"processed_at_first"`.
///   Null = default (`created_at_first`).
///
/// When both `limit` and `offset` are `0` and `sort_order` is null, no
/// pagination object is created and the storage layer returns its default
/// result set.
///
/// On success, `*out_json` receives a JSON array of message objects.
///
/// # Safety
///
/// All pointer arguments must be valid. `sort_order` may be null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_messages(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    limit: u32,
    offset: u32,
    sort_order: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let sort = parse_sort_order(sort_order)?;

        let limit_opt = match limit {
            0 => None,
            n => Some(n as usize),
        };
        let offset_opt = match offset {
            0 => None,
            n => Some(n as usize),
        };

        let pagination = match (limit_opt, offset_opt, sort) {
            (None, None, None) => None,
            _ => {
                let mut p = MessagePagination::new(limit_opt, offset_opt);
                p.sort_order = sort;
                Some(p)
            }
        };

        let messages = lock_handle(handle)?
            .get_messages(&gid, pagination)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&messages)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get a single message by event ID within a group.
///
/// On success, `*out_json` receives the message JSON or `"null"`.
///
/// # Safety
///
/// All pointer arguments must be valid.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_message(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    event_id: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let eid = parse_event_id(unsafe { cstr_to_str(event_id) }?)?;

        let msg = lock_handle(handle)?
            .get_message(&gid, &eid)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&msg)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}

/// Get the most recent message in a group under the given sort order.
///
/// # Parameters
///
/// * `sort_order` — Required: `"created_at_first"` or `"processed_at_first"`.
///
/// # Safety
///
/// All pointer arguments must be valid. `sort_order` must not be null.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mdk_get_last_message(
    h: *mut MdkHandle,
    mls_group_id: *const c_char,
    sort_order: *const c_char,
    out_json: *mut *mut c_char,
) -> MdkError {
    ffi_try_unwind_safe(|| {
        let handle = deref_handle!(h);
        require_non_null!(out_json, "out_json");
        let gid = parse_group_id(unsafe { cstr_to_str(mls_group_id) }?)?;
        let sort = parse_sort_order(sort_order)?
            .ok_or_else(|| error::invalid_input("sort_order is required"))?;

        let msg = lock_handle(handle)?
            .get_last_message(&gid, sort)
            .map_err(error::from_mdk_error)?;
        let json = to_json(&msg)?;
        unsafe { write_cstring_to(out_json, json) }
    })
}
