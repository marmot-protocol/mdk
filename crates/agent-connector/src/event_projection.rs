//! Runtime/debug event projection into control events, inbound replay cursor, and catch-up driver.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agent_control::{
    AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX, AGENT_CONTROL_REFERENCED_TEXT_MAX_CHARS,
    AGENT_CONTROL_STREAM_STATUS_STARTED, AgentControlActor, AgentControlAttachmentSummary,
    AgentControlEvent, AgentControlMediaLocator, AgentControlMediaRef, AgentControlMessage,
    AgentControlReferencedMessage, AgentControlReferencedMessageAvailability,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, GROUP_SYSTEM_DATA_NAME, GROUP_SYSTEM_EVENT_VERSION,
    GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
    GROUP_SYSTEM_TYPE_DISAPPEARING_TIMER_CHANGED, GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED,
    GROUP_SYSTEM_TYPE_GROUP_DISBANDED, GROUP_SYSTEM_TYPE_GROUP_RENAMED,
    GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT,
    GROUP_SYSTEM_TYPE_MEMBER_REMOVED, GroupSystemEvent, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT,
    MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, MARMOT_APP_EVENT_KIND_REACTION, STREAM_TAG,
    group_system_canonical_id,
};

/// Nostr pubkey-mention tag name. A `["p", <account-pubkey-hex>]` tag means that
/// account was mentioned/addressed in the message.
const PUBKEY_MENTION_TAG: &str = "p";

/// Whether the message mentions the given account. Marmot clients address a
/// member with an inline `nostr:<pubkey-hex>` reference in the body (the account
/// id IS the Nostr pubkey hex), so check the plaintext for that; also honor a
/// `["p", <pubkey-hex>]` tag in case a client emits one. Used to let a channel
/// gate group replies on being addressed.
pub(crate) fn message_mentions_account(
    tags: &[Vec<String>],
    plaintext: &str,
    account_id_hex: &str,
) -> bool {
    if account_id_hex.is_empty() {
        return false;
    }
    // Authoritative signal: a Marmot mention carries a `["p", <pubkey-hex>]` tag
    // for the mentioned account. This is present regardless of how the inline
    // text encodes the reference, so it is the reliable check.
    let tagged = tags.iter().any(|tag| {
        tag.first().is_some_and(|name| name == PUBKEY_MENTION_TAG)
            && tag
                .get(1)
                .is_some_and(|value| value.eq_ignore_ascii_case(account_id_hex))
    });
    if tagged {
        return true;
    }
    // Fallback for a p-tag-less mention: an inline NIP-21 `nostr:` reference to
    // the account hex in the body, or the visible bech32 (`npub`) forms parsed
    // by marmot-markdown (`nostr:npub1…` and bare `@npub1…`).
    // `nprofile` mentions still rely on the p-tag above.
    let scan_input = mention_plaintext_scan_input(plaintext);
    if plaintext_has_nostr_hex_ref(scan_input, account_id_hex) {
        return true;
    }
    marmot_app::npub_for_account_id(account_id_hex)
        .is_ok_and(|npub| plaintext_scan_has_visible_npub_ref(scan_input, &npub))
}

/// Whether `plaintext` contains a `nostr:<hex>` token that is not glued to
/// surrounding token characters (so `nostr:<hex>junk` does NOT match the
/// reference). Case-insensitive on both sides.
fn plaintext_has_nostr_hex_ref(plaintext: &str, reference: &str) -> bool {
    plaintext_has_prefixed_ref(plaintext, "nostr:", reference)
}

/// Upper bound for the plaintext scanned for visible `npub` mention tokens.
/// Mention classification runs on attacker-controlled inbound plaintext during
/// live delivery and replay, so keep the per-message work bounded even though
/// the scanner below is linear. Mirrors the UniFFI Markdown cap/frame size.
const MAX_MENTION_PLAINTEXT_SCAN_BYTES: usize =
    cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize;

/// Scan `plaintext` for a visible npub mention token for the account.
///
/// This deliberately avoids `marmot_markdown::parse`: the parser has
/// super-linear behavior on hostile emphasis/bracket input, and this caller is
/// fed decrypted inbound message plaintext from other group members. The mention
/// decision only needs the visible Nostr token shapes that the Markdown surface
/// recognizes (`@npub1…`, `nostr:npub1…`, and bare `npub1…`), so a bounded
/// token-boundary scan is enough and keeps replay/live drain work predictable
/// (mdk#663).
fn plaintext_scan_has_visible_npub_ref(plaintext: &str, npub: &str) -> bool {
    let bytes = plaintext.as_bytes();
    let npub_bytes = npub.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if let Some(end) = skip_markdown_image(bytes, i) {
            i = end;
            continue;
        }
        if is_visible_at_npub_ref(bytes, i, npub_bytes)
            || is_visible_nostr_npub_ref(bytes, i, npub_bytes)
            || is_visible_bare_npub_ref(bytes, i, npub_bytes)
        {
            return true;
        }
        i += 1;
    }

    false
}

/// Cap the scan input on a UTF-8 boundary so replay never spends unbounded time
/// on one hostile message.
fn mention_plaintext_scan_input(plaintext: &str) -> &str {
    if plaintext.len() <= MAX_MENTION_PLAINTEXT_SCAN_BYTES {
        return plaintext;
    }
    let mut end = MAX_MENTION_PLAINTEXT_SCAN_BYTES;
    while !plaintext.is_char_boundary(end) {
        end -= 1;
    }
    &plaintext[..end]
}

fn skip_markdown_image(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i..i + 2) != Some(b"![") {
        return None;
    }
    let alt_end = match find_unescaped_byte(bytes, i + 2, b']') {
        Some(end) => end,
        // A malformed image opener is not a visible mention container, and
        // skipping the rest avoids rescanning the same hostile prefix.
        None => return Some(bytes.len()),
    };
    match bytes.get(alt_end + 1) {
        Some(b'(') => Some(skip_inline_link_destination(bytes, alt_end + 2)),
        Some(b'[') => Some(skip_reference_label(bytes, alt_end + 2)),
        _ => None,
    }
}

fn skip_inline_link_destination(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i = (i + 2).min(bytes.len()),
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                if depth == 0 {
                    return i + 1;
                }
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    bytes.len()
}

fn skip_reference_label(bytes: &[u8], start: usize) -> usize {
    find_unescaped_byte(bytes, start, b']').map_or(bytes.len(), |end| end + 1)
}

fn find_unescaped_byte(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn is_visible_at_npub_ref(bytes: &[u8], i: usize, npub: &[u8]) -> bool {
    bytes.get(i) == Some(&b'@')
        && bytes.get(i + 1..i + 1 + npub.len()) == Some(npub)
        && mention_left_boundary_ok(before_byte(bytes, i))
        && mention_right_boundary_ok(bytes.get(i + 1 + npub.len()).copied())
}

fn is_visible_nostr_npub_ref(bytes: &[u8], i: usize, npub: &[u8]) -> bool {
    bytes.get(i..i + 6) == Some(b"nostr:")
        && bytes.get(i + 6..i + 6 + npub.len()) == Some(npub)
        && mention_left_boundary_ok(before_byte(bytes, i))
        && mention_right_boundary_ok(bytes.get(i + 6 + npub.len()).copied())
}

fn is_visible_bare_npub_ref(bytes: &[u8], i: usize, npub: &[u8]) -> bool {
    bytes.get(i..i + npub.len()) == Some(npub)
        && before_byte(bytes, i) != Some(b'@')
        && !(i >= 6 && bytes.get(i - 6..i) == Some(b"nostr:"))
        && mention_left_boundary_ok(before_byte(bytes, i))
        && mention_right_boundary_ok(bytes.get(i + npub.len()).copied())
}

fn before_byte(bytes: &[u8], i: usize) -> Option<u8> {
    i.checked_sub(1).and_then(|prev| bytes.get(prev).copied())
}

fn mention_left_boundary_ok(prev: Option<u8>) -> bool {
    prev.is_none_or(token_boundary_ok)
}

fn mention_right_boundary_ok(next: Option<u8>) -> bool {
    next.is_none_or(token_boundary_ok)
}

fn plaintext_has_prefixed_ref(plaintext: &str, prefix: &str, reference: &str) -> bool {
    let body = plaintext.to_ascii_lowercase();
    let needle = format!("{prefix}{}", reference.to_ascii_lowercase());
    body.match_indices(&needle).any(|(start, _)| {
        let end = start + needle.len();
        let before_ok = start == 0 || token_boundary_ok(body.as_bytes()[start - 1]);
        let after_ok = end == body.len() || token_boundary_ok(body.as_bytes()[end]);
        before_ok && after_ok
    })
}

fn token_boundary_ok(b: u8) -> bool {
    !matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'/')
}

/// The replied-to message id from the first `e` tag, if present. The tag value is
/// sender-controlled, so it is normalized + validated as hex (a malformed value is
/// dropped rather than passed through as a reply/delete target).
pub(crate) fn reply_target_from_tags(tags: &[Vec<String>]) -> Option<String> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|name| name == EVENT_REF_TAG))
        .and_then(|tag| tag.get(1))
        .and_then(|value| normalize_hex(value).ok())
}

/// Project every parseable `imeta` media tag into a control-plane media ref.
/// Each tag is parsed by the authoritative app-runtime parser; a tag that fails
/// structural validation is dropped (it would be unfetchable anyway) rather than
/// failing the whole message. Loopback-HTTP locators are rejected here (the
/// connector serves real deployments), matching the runtime download policy.
pub(crate) fn media_refs_from_tags(
    tags: &[Vec<String>],
    source_epoch: u64,
) -> Vec<AgentControlMediaRef> {
    tags.iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| {
            marmot_app::media_attachment_from_imeta_tag(tag, Some(source_epoch), false).ok()
        })
        .map(|reference| AgentControlMediaRef {
            media_type: reference.media_type,
            file_name: reference.file_name,
            ciphertext_sha256: reference.ciphertext_sha256,
            plaintext_sha256: reference.plaintext_sha256,
            nonce_hex: reference.nonce_hex,
            version: reference.version,
            source_epoch: reference.source_epoch,
            locators: reference
                .locators
                .into_iter()
                .map(|locator| AgentControlMediaLocator {
                    kind: locator.kind,
                    value: locator.value,
                })
                .collect(),
            dim: reference.dim,
            thumbhash: reference.thumbhash,
        })
        .collect()
}
use cgka_traits::engine::GroupStateChange;
use cgka_traits::{GroupId, engine::GroupEvent};
use marmot_app::{AppError, AppMessageRecord, MarmotAppEvent, MarmotAppRuntime};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, broadcast};

use crate::reconcile_telemetry::{ReconcileSource, ReconcileTelemetry};
use crate::validation::normalize_hex;

pub(crate) fn control_actor(
    account_id_hex: impl Into<String>,
    display_name: Option<String>,
    self_account_id_hex: &str,
) -> AgentControlActor {
    let account_id_hex = account_id_hex.into();
    AgentControlActor {
        is_self: account_id_hex == self_account_id_hex,
        account_id_hex,
        display_name,
    }
}

pub(crate) fn attachment_summaries_from_tags(
    tags: &[Vec<String>],
    source_epoch: Option<u64>,
) -> (Vec<AgentControlAttachmentSummary>, bool) {
    let mut summaries = tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("imeta"))
        .filter_map(|tag| {
            marmot_app::media_attachment_from_imeta_tag(tag, source_epoch, false)
                .ok()
                .map(|media| AgentControlAttachmentSummary {
                    media_type: media.media_type,
                    file_name: media.file_name,
                    dim: media.dim,
                })
        })
        .collect::<Vec<_>>();
    let truncated = summaries.len() > AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX;
    summaries.truncate(AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX);
    (summaries, truncated)
}

fn bounded_text_excerpt(text: &str) -> (String, bool) {
    let mut chars = text.chars();
    let excerpt = chars
        .by_ref()
        .take(AGENT_CONTROL_REFERENCED_TEXT_MAX_CHARS)
        .collect::<String>();
    (excerpt, chars.next().is_some())
}

fn referenced_message(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    self_account_id_hex: &str,
    group_id_hex: &str,
    message_id_hex: String,
) -> Result<AgentControlReferencedMessage, AppError> {
    let raw = runtime.message_by_id(account_ref, group_id_hex, &message_id_hex)?;
    let target = runtime.message_target(account_ref, group_id_hex, &message_id_hex)?;
    let availability = match target.as_ref() {
        None => AgentControlReferencedMessageAvailability::Missing,
        Some(target) if target.invalidated => {
            AgentControlReferencedMessageAvailability::Invalidated
        }
        Some(target) if target.deleted => AgentControlReferencedMessageAvailability::Deleted,
        Some(_) => AgentControlReferencedMessageAvailability::Available,
    };
    let sender = target
        .as_ref()
        .map(|target| control_actor(target.sender.clone(), None, self_account_id_hex))
        .or_else(|| {
            raw.as_ref()
                .map(|raw| control_actor(raw.sender.clone(), None, self_account_id_hex))
        });
    let recorded_at = raw.as_ref().map(|raw| raw.recorded_at);

    // Deleted and invalidated targets intentionally retain only attribution
    // metadata. Their plaintext and attachment metadata are never projected.
    let (text_excerpt, text_truncated, attachments, attachments_truncated) =
        if availability == AgentControlReferencedMessageAvailability::Available {
            let (text_excerpt, text_truncated) =
                bounded_text_excerpt(&target.as_ref().expect("available target").plaintext);
            let (attachments, attachments_truncated) = raw.as_ref().map_or_else(
                || (Vec::new(), false),
                |raw| attachment_summaries_from_tags(&raw.tags, raw.source_epoch),
            );
            (
                Some(text_excerpt),
                text_truncated,
                attachments,
                attachments_truncated,
            )
        } else {
            (None, false, Vec::new(), false)
        };

    Ok(AgentControlReferencedMessage {
        message_id_hex,
        availability,
        sender,
        recorded_at,
        text_excerpt,
        text_truncated,
        attachments,
        attachments_truncated,
    })
}

fn available_target_context(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    self_account_id_hex: &str,
    group_id_hex: &str,
    target_message_id_hex: &str,
) -> Result<Option<AgentControlReferencedMessage>, AppError> {
    let Some(raw_target) =
        runtime.message_by_id(account_ref, group_id_hex, target_message_id_hex)?
    else {
        return Ok(None);
    };
    if raw_target.kind != MARMOT_APP_EVENT_KIND_CHAT || raw_target.invalidated {
        return Ok(None);
    }
    let context = referenced_message(
        runtime,
        account_ref,
        self_account_id_hex,
        group_id_hex,
        target_message_id_hex.to_owned(),
    )?;
    Ok(
        (context.availability == AgentControlReferencedMessageAvailability::Available)
            .then_some(context),
    )
}

fn project_durable_record(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    account_id_hex: &str,
    record: AppMessageRecord,
    sender_display_name: Option<String>,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Result<Option<AgentControlEvent>, AppError> {
    if !inbound_filter_matches(
        account_filter,
        account_id_hex,
        group_filter,
        &record.group_id_hex,
    ) {
        return Ok(None);
    }

    if record.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM {
        // Only locally synthesized group-system timeline rows represent the live
        // `GroupEvent::GroupStateChanged` signal. Ignore sent/received kind-1210 app events.
        if record.direction != "system" || record.invalidated {
            return Ok(None);
        }
        let Some((change, detail)) = GroupSystemEvent::parse(&record.plaintext)
            .ok()
            .as_ref()
            .and_then(group_system_control_parts)
        else {
            return Ok(None);
        };
        return Ok(Some(AgentControlEvent::GroupStateChanged {
            account_id_hex: account_id_hex.to_owned(),
            group_id_hex: record.group_id_hex,
            change: change.to_owned(),
            detail,
        }));
    }

    if record.direction != "received" || record.sender == account_id_hex || record.invalidated {
        return Ok(None);
    }
    let actor = control_actor(record.sender.clone(), sender_display_name, account_id_hex);
    let group_id_hex = record.group_id_hex.clone();

    match record.kind {
        MARMOT_APP_EVENT_KIND_CHAT => {
            let mentions_self =
                message_mentions_account(&record.tags, &record.plaintext, account_id_hex);
            let reply_to = match reply_target_from_tags(&record.tags) {
                Some(target_message_id_hex) => Some(referenced_message(
                    runtime,
                    account_ref,
                    account_id_hex,
                    &group_id_hex,
                    target_message_id_hex,
                )?),
                None => None,
            };
            let media = media_refs_from_tags(&record.tags, record.source_epoch.unwrap_or_default());
            Ok(Some(AgentControlEvent::InboundMessage {
                account_id_hex: account_id_hex.to_owned(),
                group_id_hex,
                message: AgentControlMessage {
                    message_id_hex: record.message_id_hex,
                    sender: actor,
                    text: record.plaintext,
                    recorded_at: record.recorded_at,
                    media,
                },
                mentions_self,
                reply_to,
            }))
        }
        MARMOT_APP_EVENT_KIND_EDIT => {
            let Some(target_message_id_hex) = reply_target_from_tags(&record.tags) else {
                return Ok(None);
            };
            let Some(raw_target) =
                runtime.message_by_id(account_ref, &group_id_hex, &target_message_id_hex)?
            else {
                return Ok(None);
            };
            if raw_target.kind != MARMOT_APP_EVENT_KIND_CHAT
                || raw_target.sender != record.sender
                || raw_target.invalidated
            {
                return Ok(None);
            }
            let Some(target) = available_target_context(
                runtime,
                account_ref,
                account_id_hex,
                &group_id_hex,
                &target_message_id_hex,
            )?
            else {
                return Ok(None);
            };
            Ok(Some(AgentControlEvent::MessageEdited {
                account_id_hex: account_id_hex.to_owned(),
                group_id_hex,
                event_id_hex: record.message_id_hex,
                target_message_id_hex,
                actor,
                replacement_text: record.plaintext,
                recorded_at: record.recorded_at,
                target,
            }))
        }
        MARMOT_APP_EVENT_KIND_REACTION => {
            let Some(target_message_id_hex) = reply_target_from_tags(&record.tags) else {
                return Ok(None);
            };
            let Some(target) = available_target_context(
                runtime,
                account_ref,
                account_id_hex,
                &group_id_hex,
                &target_message_id_hex,
            )?
            else {
                return Ok(None);
            };
            Ok(Some(AgentControlEvent::ReactionAdded {
                account_id_hex: account_id_hex.to_owned(),
                group_id_hex,
                event_id_hex: record.message_id_hex,
                target_message_id_hex,
                actor,
                emoji: record.plaintext,
                recorded_at: record.recorded_at,
                target,
            }))
        }
        MARMOT_APP_EVENT_KIND_DELETE => {
            let Some(deleted_event_id_hex) = reply_target_from_tags(&record.tags) else {
                return Ok(None);
            };
            let Some(deleted_event) =
                runtime.message_by_id(account_ref, &group_id_hex, &deleted_event_id_hex)?
            else {
                return Ok(None);
            };

            if deleted_event.kind == MARMOT_APP_EVENT_KIND_REACTION {
                // The materialized timeline accepts reaction removal only from
                // the original reaction author; moderation grants do not apply.
                if deleted_event.sender != record.sender || deleted_event.invalidated {
                    return Ok(None);
                }
                let Some(target_message_id_hex) = reply_target_from_tags(&deleted_event.tags)
                else {
                    return Ok(None);
                };
                let Some(target) = available_target_context(
                    runtime,
                    account_ref,
                    account_id_hex,
                    &group_id_hex,
                    &target_message_id_hex,
                )?
                else {
                    return Ok(None);
                };
                return Ok(Some(AgentControlEvent::ReactionRemoved {
                    account_id_hex: account_id_hex.to_owned(),
                    group_id_hex,
                    event_id_hex: record.message_id_hex,
                    reaction_event_id_hex: deleted_event_id_hex,
                    target_message_id_hex,
                    actor,
                    emoji: deleted_event.plaintext,
                    recorded_at: record.recorded_at,
                    target,
                }));
            }

            if deleted_event.kind != MARMOT_APP_EVENT_KIND_CHAT
                || deleted_event.invalidated
                || (deleted_event.sender != record.sender && !record.moderation_grant)
            {
                return Ok(None);
            }
            let target = referenced_message(
                runtime,
                account_ref,
                account_id_hex,
                &group_id_hex,
                deleted_event_id_hex.clone(),
            )?;
            if target.availability != AgentControlReferencedMessageAvailability::Deleted {
                return Ok(None);
            }
            Ok(Some(AgentControlEvent::MessageDeleted {
                account_id_hex: account_id_hex.to_owned(),
                group_id_hex,
                event_id_hex: record.message_id_hex,
                target_message_id_hex: deleted_event_id_hex,
                actor,
                recorded_at: record.recorded_at,
                target,
            }))
        }
        _ => Ok(None),
    }
}

pub(crate) fn control_event_from_runtime_event_with_runtime(
    runtime: &MarmotAppRuntime,
    event: MarmotAppEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Result<Option<AgentControlEvent>, AppError> {
    match event {
        MarmotAppEvent::MessageReceived(update) => {
            let Some(group_id_hex) = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            ) else {
                return Ok(None);
            };
            let Some(record) = runtime.message_by_id(
                &update.account_label,
                &group_id_hex,
                &update.message.message_id_hex,
            )?
            else {
                // Durable rows are authoritative for the agent feed. Retention
                // pruning or convergence invalidation can remove a row between
                // commit and broadcast; falling back to the in-memory plaintext
                // here would re-expose content the durable projection has already
                // discarded.
                return Ok(None);
            };
            project_durable_record(
                runtime,
                &update.account_label,
                &update.account_id_hex,
                record,
                update.message.sender_display_name,
                account_filter,
                group_filter,
            )
        }
        MarmotAppEvent::AgentStreamStarted(update) => {
            if update.message.kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
                return Ok(None);
            }
            let Some(group_id_hex) = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            ) else {
                return Ok(None);
            };
            let Some(stream_id_hex) = update
                .message
                .tags
                .iter()
                .find(|tag| tag.first().is_some_and(|name| name == STREAM_TAG))
                .and_then(|tag| tag.get(1))
                .and_then(|stream_id_hex| normalize_hex(stream_id_hex).ok())
            else {
                return Ok(None);
            };
            Ok(Some(AgentControlEvent::StreamUpdate {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                stream_id_hex,
                status: AGENT_CONTROL_STREAM_STATUS_STARTED.to_owned(),
            }))
        }
        MarmotAppEvent::GroupEvent(group_event) => match group_event.event {
            GroupEvent::GroupJoined {
                group_id,
                via_welcome,
                welcomer,
            } => {
                let group_id_hex = hex::encode(group_id.as_slice());
                if !inbound_filter_matches(
                    account_filter,
                    &group_event.account_id_hex,
                    group_filter,
                    &group_id_hex,
                ) {
                    return Ok(None);
                }
                Ok(Some(AgentControlEvent::GroupInvite {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                    welcomer_account_id_hex: welcomer.map(|member| hex::encode(member.as_slice())),
                }))
            }
            GroupEvent::GroupStateChanged {
                group_id, change, ..
            } => {
                let group_id_hex = hex::encode(group_id.as_slice());
                if !inbound_filter_matches(
                    account_filter,
                    &group_event.account_id_hex,
                    group_filter,
                    &group_id_hex,
                ) {
                    return Ok(None);
                }
                // Map to a coarse change kind. Privacy: the subject member's
                // pubkey is NEVER surfaced; only a rename carries a detail (the
                // new group display name, which is operationally visible).
                let (change, detail) = match change {
                    GroupStateChange::MemberAdded { .. } => ("member_added", None),
                    GroupStateChange::MemberRemoved { .. } => ("member_removed", None),
                    GroupStateChange::MemberLeft { .. } => ("member_left", None),
                    GroupStateChange::AdminAdded { .. } => ("admin_added", None),
                    GroupStateChange::AdminRemoved { .. } => ("admin_removed", None),
                    GroupStateChange::GroupRenamed { name, .. } => ("group_renamed", Some(name)),
                    GroupStateChange::GroupAvatarChanged => ("group_avatar_changed", None),
                    GroupStateChange::MessageRetentionChanged { .. } => {
                        ("disappearing_timer_changed", None)
                    }
                    GroupStateChange::GroupDisbanded => ("group_disbanded", None),
                };
                Ok(Some(AgentControlEvent::GroupStateChanged {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    change: change.to_owned(),
                    detail,
                }))
            }
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

/// Return the durable storage row id that corresponds to a live runtime event, when the
/// storage-backed replay can later project the same fact. Recording this id for live delivery
/// lets replay recover genuinely dropped chat/delete/group-state events without duplicating facts
/// this subscription already emitted.
pub(crate) fn runtime_replay_dedup_key(event: &MarmotAppEvent) -> Option<String> {
    match event {
        MarmotAppEvent::MessageReceived(update) => matches!(
            update.message.kind,
            MARMOT_APP_EVENT_KIND_CHAT
                | MARMOT_APP_EVENT_KIND_DELETE
                | MARMOT_APP_EVENT_KIND_EDIT
                | MARMOT_APP_EVENT_KIND_REACTION
        )
        .then(|| update.message.message_id_hex.clone()),
        MarmotAppEvent::GroupEvent(group_event) => {
            if let GroupEvent::GroupStateChanged {
                group_id,
                epoch,
                actor,
                change,
                ..
            } = &group_event.event
            {
                group_state_change_replay_id(group_id, epoch.0, actor.as_ref(), change)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn group_state_change_replay_id(
    group_id: &GroupId,
    epoch: u64,
    actor: Option<&cgka_traits::MemberId>,
    change: &GroupStateChange,
) -> Option<String> {
    group_system_canonical_id(group_id, epoch, actor, change).ok()
}

fn group_system_control_parts(event: &GroupSystemEvent) -> Option<(&'static str, Option<String>)> {
    if event.v != GROUP_SYSTEM_EVENT_VERSION {
        return None;
    }
    match event.system_type.as_str() {
        GROUP_SYSTEM_TYPE_MEMBER_ADDED => Some(("member_added", None)),
        GROUP_SYSTEM_TYPE_MEMBER_REMOVED => Some(("member_removed", None)),
        GROUP_SYSTEM_TYPE_MEMBER_LEFT => Some(("member_left", None)),
        GROUP_SYSTEM_TYPE_ADMIN_ADDED => Some(("admin_added", None)),
        GROUP_SYSTEM_TYPE_ADMIN_REMOVED => Some(("admin_removed", None)),
        GROUP_SYSTEM_TYPE_GROUP_RENAMED => Some((
            "group_renamed",
            event.data_str(GROUP_SYSTEM_DATA_NAME).map(str::to_owned),
        )),
        GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED => Some(("group_avatar_changed", None)),
        GROUP_SYSTEM_TYPE_DISAPPEARING_TIMER_CHANGED => Some(("disappearing_timer_changed", None)),
        GROUP_SYSTEM_TYPE_GROUP_DISBANDED => Some(("group_disbanded", None)),
        _ => None,
    }
}

pub(crate) fn control_event_from_debug_event(
    event: AgentControlEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    let (account_id_hex, group_id_hex) = match &event {
        AgentControlEvent::MessageEdited {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::MessageDeleted {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::ReactionAdded {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::ReactionRemoved {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::GroupStateChanged {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::GroupInvite {
            account_id_hex,
            group_id_hex,
            ..
        }
        | AgentControlEvent::StreamUpdate {
            account_id_hex,
            group_id_hex,
            ..
        } => (account_id_hex, group_id_hex),
        // ResyncRequired carries optional account/group scope and is never produced by the
        // debug-inject path; apply the subscription filters against whatever scope it carries.
        AgentControlEvent::ResyncRequired {
            account_id_hex,
            group_id_hex,
            ..
        } => {
            let account_ok = match (account_filter, account_id_hex.as_deref()) {
                (Some(filter), Some(value)) => filter == value,
                _ => true,
            };
            let group_ok = match (group_filter, group_id_hex.as_deref()) {
                (Some(filter), Some(value)) => filter == value,
                _ => true,
            };
            return (account_ok && group_ok).then_some(event);
        }
    };
    inbound_filter_matches(account_filter, account_id_hex, group_filter, group_id_hex)
        .then_some(event)
}

fn inbound_event_group_id_hex(
    account_filter: Option<&str>,
    account_id_hex: &str,
    group_filter: Option<&str>,
    group_id: &GroupId,
    sender_account_id_hex: &str,
) -> Option<String> {
    let group_id_hex = hex::encode(group_id.as_slice());
    if inbound_filter_matches(account_filter, account_id_hex, group_filter, &group_id_hex)
        && sender_account_id_hex != account_id_hex
    {
        Some(group_id_hex)
    } else {
        None
    }
}

fn inbound_filter_matches(
    account_filter: Option<&str>,
    account_id_hex: &str,
    group_filter: Option<&str>,
    group_id_hex: &str,
) -> bool {
    account_filter.is_none_or(|filter| filter == account_id_hex)
        && group_filter.is_none_or(|filter| filter == group_id_hex)
}

/// Build a `ResyncRequired` control event scoped to this subscription's filters. Emitted when the
/// inbound broadcast channel lags and drops events: the dropped inbound messages are gone for good
/// (catch-up never re-emits already-broadcast messages), so the agent must re-query its own state.
pub(crate) fn resync_required_event(
    account_filter: Option<&str>,
    group_filter: Option<&str>,
    dropped_events: u64,
) -> AgentControlEvent {
    AgentControlEvent::ResyncRequired {
        account_id_hex: account_filter.map(str::to_owned),
        group_id_hex: group_filter.map(str::to_owned),
        dropped_events,
    }
}

/// Project a stored app-message record into the same control event the live path emits, or
/// `None` if the stored row is not relevant to this subscription. Replay covers the durable event
/// kinds the live inbound stream surfaces: inbound chat messages, accepted edits, reactions,
/// reaction removals and message deletions, plus synthesized kind-1210 group-system rows for
/// authenticated group-state changes. Other app-event kinds remain ignored until they have
/// explicit agent-control semantics.
pub(crate) fn inbound_message_event_from_record_with_runtime(
    runtime: &MarmotAppRuntime,
    account_ref: &str,
    account_id_hex: &str,
    record: AppMessageRecord,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Result<Option<AgentControlEvent>, AppError> {
    debug_assert_ne!(
        MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
    );
    project_durable_record(
        runtime,
        account_ref,
        account_id_hex,
        record,
        // Storage replay has no directory join; display name is best-effort live-only.
        None,
        account_filter,
        group_filter,
    )
}

/// Bounded set of durable replay row ids already delivered on a subscription, used to dedup
/// storage-backed replay against live delivery (and against itself) after broadcast lag. Keeps a
/// FIFO of recent ids so a long-lived subscription cannot grow memory without bound; once the
/// capacity is reached the oldest id is evicted. The capacity comfortably exceeds the broadcast
/// channel depth, so every row that could plausibly be re-queried after a single overflow is still
/// tracked.
pub(crate) struct DeliveredInboundCursor {
    capacity: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl DeliveredInboundCursor {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    pub(crate) fn contains(&self, message_id_hex: &str) -> bool {
        self.seen.contains(message_id_hex)
    }

    pub(crate) fn record(&mut self, message_id_hex: String) {
        if self.seen.contains(&message_id_hex) {
            return;
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(message_id_hex.clone());
        self.order.push_back(message_id_hex);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum InboundCatchUpEvent {
    Completed,
}

/// Cadence for the catch-up safety net. Production builds use
/// [`crate::INBOUND_CATCH_UP_BASE_INTERVAL`] / [`crate::INBOUND_CATCH_UP_MAX_INTERVAL`];
/// tests inject shorter intervals to exercise the adaptive schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InboundCatchUpSchedule {
    pub(crate) base: Duration,
    pub(crate) max: Duration,
}

/// One shared catch-up driver for every live `SubscribeInbound` subscription
/// (mdk#574). The driver's scheduled passes are a *safety net*: steady-state
/// delivery is push-driven through each account worker's live receive loop, so
/// a pass exists to heal silent notification gaps, not to fetch messages —
/// which is why the net may back off when nothing is happening (mdk#1380).
///
/// Scheduling discipline:
/// - Subscription initial catch-ups arrive out-of-band through
///   [`Self::request`] and run promptly (serialization lock coalesces them).
/// - Scheduled passes start at `base` after the first subscription and double
///   after every pass that observed no qualifying runtime activity, capped at
///   `max`.
/// - Qualifying activity — any runtime event except `AccountError` (errors can
///   be our own failing passes and must not self-stimulate), or a lagged event
///   stream — resets the interval to `base`. Activity observed while the
///   driver was sleeping wakes a pass immediately, but only once the previous
///   pass is at least `base` old, so a busy account never escalates BEYOND the
///   base cadence.
/// - A failed pass keeps backing off (relay outage: the per-worker reconnect
///   backoff owns transport repair); recovery surfaces as activity events.
/// - The driver quiesces when the last subscription drops, exactly as before.
#[derive(Clone)]
pub(crate) struct InboundCatchUpDriver {
    runtime: MarmotAppRuntime,
    /// Serializes scheduled and explicit catch-up passes. `pub(crate)` so the
    /// regression harness can hold a pass queued behind the lock and prove the
    /// schedule preserves delayed cadence afterwards (mdk#1380 review).
    pub(crate) lock: Arc<AsyncMutex<()>>,
    events: broadcast::Sender<InboundCatchUpEvent>,
    pub(crate) started: Arc<AtomicBool>,
    pub(crate) active: Arc<AtomicU64>,
    schedule: InboundCatchUpSchedule,
    telemetry: Arc<ReconcileTelemetry>,
    /// Test-only activity channel override. Production drivers subscribe to the
    /// runtime event broadcast; tests inject a channel they can publish
    /// synthetic events into.
    activity_override: Option<broadcast::Sender<MarmotAppEvent>>,
}

impl InboundCatchUpDriver {
    pub(crate) fn new(runtime: MarmotAppRuntime, telemetry: Arc<ReconcileTelemetry>) -> Self {
        Self::with_schedule(
            runtime,
            telemetry,
            InboundCatchUpSchedule {
                base: crate::INBOUND_CATCH_UP_BASE_INTERVAL,
                max: crate::INBOUND_CATCH_UP_MAX_INTERVAL,
            },
        )
    }

    pub(crate) fn with_schedule(
        runtime: MarmotAppRuntime,
        telemetry: Arc<ReconcileTelemetry>,
        schedule: InboundCatchUpSchedule,
    ) -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            runtime,
            lock: Arc::new(AsyncMutex::new(())),
            events,
            started: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
            schedule,
            telemetry,
            activity_override: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn override_activity_for_test(
        mut self,
        activity: broadcast::Sender<MarmotAppEvent>,
    ) -> Self {
        self.activity_override = Some(activity);
        self
    }

    fn spawn(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let driver = self.clone();
        tokio::spawn(async move {
            driver.run().await;
        });
    }

    fn activity_receiver(&self) -> broadcast::Receiver<MarmotAppEvent> {
        match &self.activity_override {
            Some(sender) => sender.subscribe(),
            None => self.runtime.subscribe(),
        }
    }

    async fn run(self) {
        let mut activity = self.activity_receiver();
        // First scheduled pass fires one base interval after spawn, unchanged
        // from the pre-adaptive driver (the subscription's own initial request
        // covers the "catch up now" case).
        let mut interval = self
            .schedule
            .base
            .max(Duration::from_millis(1))
            .min(self.schedule.max);
        // Deadlines anchor at pass COMPLETION, preserving the old
        // `MissedTickBehavior::Delay` semantics: a pass that runs long (or
        // queues behind an explicit request on the serialization lock) inserts
        // the full interval before the next pass instead of firing
        // back-to-back (mdk#1380 review).
        let mut last_pass_completed = tokio::time::Instant::now();
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                self.started.store(false, Ordering::Release);
                if self.active.load(Ordering::Acquire) == 0 {
                    break;
                }
                if self
                    .started
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    break;
                }
            }
            let deadline = last_pass_completed + interval;
            let wake = wait_for_catch_up_wake(
                deadline,
                last_pass_completed,
                &self.schedule,
                &mut activity,
            )
            .await;
            // A pass that observed activity since the previous pass began —
            // the wake reason itself, plus anything buffered while the pass
            // ran — keeps the next pass at the base interval.
            let observed_activity =
                matches!(wake, CatchUpWake::Activity) || drain_pending_activity(&mut activity);
            let result = self.scheduled_pass(observed_activity).await;
            last_pass_completed = tokio::time::Instant::now();
            match result {
                Ok(()) if observed_activity => {
                    interval = self
                        .schedule
                        .base
                        .max(Duration::from_millis(1))
                        .min(self.schedule.max);
                }
                Ok(()) => interval = (interval * 2).min(self.schedule.max),
                Err(()) => interval = (interval * 2).min(self.schedule.max),
            }
        }
    }

    /// Run one scheduled catch-up pass, recording aggregate telemetry and a
    /// per-pass tracing event (source/duration/result/accounts considered).
    async fn scheduled_pass(&self, observed_activity: bool) -> Result<(), ()> {
        let started = tokio::time::Instant::now();
        let _guard = self.lock.lock().await;
        ReconcileTelemetry::bump(&self.telemetry.catch_up_passes_started);
        let result = self.runtime.catch_up_accounts_reporting().await;
        match &result {
            Ok(summary) => {
                ReconcileTelemetry::bump(&self.telemetry.catch_up_passes_completed);
                ReconcileTelemetry::add(
                    &self.telemetry.catch_up_accounts_considered,
                    summary.accounts_considered,
                );
                if observed_activity {
                    ReconcileTelemetry::bump(&self.telemetry.catch_up_passes_with_activity);
                }
                let _ = self.events.send(InboundCatchUpEvent::Completed);
                tracing::debug!(
                    target: "agent_connector",
                    method = "inbound_catch_up_scheduled_pass",
                    source = ReconcileSource::InboundCatchUp.as_str(),
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "ok",
                    observed_activity,
                    accounts_considered = summary.accounts_considered,
                    "scheduled inbound catch-up pass completed"
                );
                Ok(())
            }
            Err(_) => {
                ReconcileTelemetry::bump(&self.telemetry.catch_up_passes_failed);
                tracing::warn!(
                    target: "agent_connector",
                    method = "inbound_catch_up_scheduled_pass",
                    source = ReconcileSource::InboundCatchUp.as_str(),
                    duration_ms = started.elapsed().as_millis() as u64,
                    result = "error",
                    error_code = "catch_up_failed",
                    "scheduled inbound catch-up pass failed"
                );
                Err(())
            }
        }
    }

    pub(crate) fn subscribe(
        &self,
    ) -> (
        broadcast::Receiver<InboundCatchUpEvent>,
        InboundCatchUpSubscription,
    ) {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.spawn();
        (
            self.events.subscribe(),
            InboundCatchUpSubscription {
                active: self.active.clone(),
            },
        )
    }

    /// Run one out-of-band catch-up (a subscription's initial pass). Explicit
    /// requests are not counted as scheduled passes and do not perturb the
    /// adaptive schedule: the activity they surface arrives as runtime events,
    /// which reset the net through the usual path.
    pub(crate) async fn request(&self) -> Result<(), AppError> {
        ReconcileTelemetry::bump(&self.telemetry.catch_up_explicit_requests);
        let _guard = self.lock.lock().await;
        let result = self.runtime.catch_up_accounts().await;
        if result.is_ok() {
            let _ = self.events.send(InboundCatchUpEvent::Completed);
        } else {
            tracing::warn!(
                target: "agent_connector",
                method = "inbound_catch_up_request",
                error_code = "catch_up_failed",
                "inbound catch-up request failed"
            );
        }
        result
    }
}

/// What ended the wait between scheduled passes.
enum CatchUpWake {
    Timer,
    Activity,
}

/// Wait until `deadline`, returning early ([`CatchUpWake::Activity`]) when
/// qualifying runtime activity arrives. Activity noticed less than the base
/// interval after `last_pass_started` is deferred to that base boundary: a
/// busy account stays at the base cadence (never one pass per event), while a
/// backed-off (quiet) driver notices fresh work promptly (mdk#1380).
async fn wait_for_catch_up_wake(
    deadline: tokio::time::Instant,
    last_pass_started: tokio::time::Instant,
    schedule: &InboundCatchUpSchedule,
    activity: &mut broadcast::Receiver<MarmotAppEvent>,
) -> CatchUpWake {
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    let base = schedule.base.max(Duration::from_millis(1));
    // The cadence floor follows the previous pass start. The scheduled
    // deadline never precedes it (interval >= base).
    let cadence_floor = last_pass_started + base;
    loop {
        tokio::select! {
            _ = &mut timer => return CatchUpWake::Timer,
            event = activity.recv() => {
                let qualifying = match event {
                    Ok(event) => event_counts_as_catch_up_activity(&event),
                    // A lagged stream means events were evicted while we waited:
                    // conservatively treat as activity. A closed stream (runtime
                    // shut down) leaves only the timer; the pass fails and the
                    // driver's own backoff governs.
                    Err(broadcast::error::RecvError::Lagged(_)) => true,
                    Err(broadcast::error::RecvError::Closed) => false,
                };
                if !qualifying {
                    continue;
                }
                if tokio::time::Instant::now() >= cadence_floor {
                    return CatchUpWake::Activity;
                }
                // Too soon for an immediate pass: absorb this activity and run
                // at the cadence floor instead of discarding the signal.
                tokio::time::sleep_until(cadence_floor).await;
                return CatchUpWake::Activity;
            }
        }
    }
}

/// Drain buffered runtime events non-blockingly after a pass; any qualifying
/// event (or lag) counts as activity observed during the pass.
fn drain_pending_activity(activity: &mut broadcast::Receiver<MarmotAppEvent>) -> bool {
    loop {
        match activity.try_recv() {
            Ok(event) => {
                if event_counts_as_catch_up_activity(&event) {
                    return true;
                }
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => return true,
            Err(broadcast::error::TryRecvError::Empty)
            | Err(broadcast::error::TryRecvError::Closed) => return false,
        }
    }
}

/// Which runtime events mean "state changed, the safety net should be hot
/// again". Everything except `AccountError`: account errors may be produced by
/// the driver's own failing passes, and counting them would pin the net at the
/// base interval for the duration of an outage (mdk#1380).
fn event_counts_as_catch_up_activity(event: &MarmotAppEvent) -> bool {
    !matches!(event, MarmotAppEvent::AccountError(_))
}

pub(crate) struct InboundCatchUpSubscription {
    active: Arc<AtomicU64>,
}

impl Drop for InboundCatchUpSubscription {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}
