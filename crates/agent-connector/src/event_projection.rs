//! Runtime/debug event projection into control events, inbound replay cursor, and catch-up driver.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use agent_control::{
    AGENT_CONTROL_STREAM_STATUS_STARTED, AgentControlEvent, AgentControlMediaLocator,
    AgentControlMediaRef,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, GROUP_SYSTEM_DATA_NAME, GROUP_SYSTEM_EVENT_VERSION,
    GROUP_SYSTEM_TYPE_ADMIN_ADDED, GROUP_SYSTEM_TYPE_ADMIN_REMOVED,
    GROUP_SYSTEM_TYPE_DISAPPEARING_TIMER_CHANGED, GROUP_SYSTEM_TYPE_GROUP_AVATAR_CHANGED,
    GROUP_SYSTEM_TYPE_GROUP_RENAMED, GROUP_SYSTEM_TYPE_MEMBER_ADDED, GROUP_SYSTEM_TYPE_MEMBER_LEFT,
    GROUP_SYSTEM_TYPE_MEMBER_REMOVED, GroupSystemEvent, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    STREAM_TAG, group_system_canonical_id,
};

/// Nostr pubkey-mention tag name. A `["p", <account-pubkey-hex>]` tag means that
/// account was mentioned/addressed in the message.
const PUBKEY_MENTION_TAG: &str = "p";

/// Whether the message mentions the given account. Marmot clients address a
/// member with an inline `nostr:<pubkey-hex>` reference in the body (the account
/// id IS the Nostr pubkey hex), so check the plaintext for that; also honor a
/// `["p", <pubkey-hex>]` tag in case a client emits one. Used to let a channel
/// gate group replies on being addressed.
fn message_mentions_account(tags: &[Vec<String>], plaintext: &str, account_id_hex: &str) -> bool {
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
    if plaintext_has_nostr_hex_ref(plaintext, account_id_hex) {
        return true;
    }
    marmot_app::npub_for_account_id(account_id_hex)
        .is_ok_and(|npub| plaintext_has_visible_npub_ref(plaintext, &npub))
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

/// Whether `plaintext` contains a visible npub mention token for the account.
///
/// This deliberately avoids `marmot_markdown::parse`: the parser has
/// super-linear behavior on hostile emphasis/bracket input, and this caller is
/// fed decrypted inbound message plaintext from other group members. The mention
/// decision only needs the visible Nostr token shapes that the Markdown surface
/// recognizes (`@npub1…`, `nostr:npub1…`, and bare `npub1…`), so a bounded
/// token-boundary scan is enough and keeps replay/live drain work predictable
/// (darkmatter#663).
fn plaintext_has_visible_npub_ref(plaintext: &str, npub: &str) -> bool {
    plaintext_scan_has_visible_npub_ref(mention_plaintext_scan_input(plaintext), npub)
}

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
fn reply_target_from_tags(tags: &[Vec<String>]) -> Option<String> {
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
fn media_refs_from_tags(tags: &[Vec<String>], source_epoch: u64) -> Vec<AgentControlMediaRef> {
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
use tokio::sync::{Mutex as AsyncMutex, broadcast};

use crate::INBOUND_CATCH_UP_INTERVAL;
use crate::validation::normalize_hex;

pub(crate) fn control_event_from_runtime_event(
    event: MarmotAppEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    match event {
        MarmotAppEvent::MessageReceived(update) => {
            // A kind-5 deletion from another member retracts an earlier message;
            // surface it as a distinct control event (the `e` tag is the target).
            if update.message.kind == MARMOT_APP_EVENT_KIND_DELETE {
                let group_id_hex = inbound_event_group_id_hex(
                    account_filter,
                    &update.account_id_hex,
                    group_filter,
                    &update.message.group_id,
                    &update.message.sender,
                )?;
                let target_message_id_hex = reply_target_from_tags(&update.message.tags)?;
                return Some(AgentControlEvent::MessageDeleted {
                    account_id_hex: update.account_id_hex,
                    group_id_hex,
                    target_message_id_hex,
                    sender_account_id_hex: update.message.sender,
                });
            }
            // Only kind-9 chat/media is conversational input. Edits, reactions,
            // and telemetry need explicit control semantics before they can
            // safely influence an agent prompt.
            if update.message.kind != MARMOT_APP_EVENT_KIND_CHAT {
                return None;
            }
            let group_id_hex = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            )?;
            let mentions_self = message_mentions_account(
                &update.message.tags,
                &update.message.plaintext,
                &update.account_id_hex,
            );
            let reply_to_message_id_hex = reply_target_from_tags(&update.message.tags);
            let media = media_refs_from_tags(&update.message.tags, update.message.source_epoch);
            Some(AgentControlEvent::InboundMessage {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                message_id_hex: update.message.message_id_hex,
                sender_account_id_hex: update.message.sender,
                text: update.message.plaintext,
                mentions_self,
                reply_to_message_id_hex,
                sender_display_name: update.message.sender_display_name,
                media,
            })
        }
        MarmotAppEvent::AgentStreamStarted(update) => {
            if update.message.kind != MARMOT_APP_EVENT_KIND_AGENT_STREAM_START {
                return None;
            }
            let group_id_hex = inbound_event_group_id_hex(
                account_filter,
                &update.account_id_hex,
                group_filter,
                &update.message.group_id,
                &update.message.sender,
            )?;
            let stream_id_hex = update
                .message
                .tags
                .iter()
                .find(|tag| tag.first().is_some_and(|name| name == STREAM_TAG))
                .and_then(|tag| tag.get(1))
                .and_then(|stream_id_hex| normalize_hex(stream_id_hex).ok())?;
            Some(AgentControlEvent::StreamUpdate {
                account_id_hex: update.account_id_hex,
                group_id_hex,
                stream_id_hex,
                status: AGENT_CONTROL_STREAM_STATUS_STARTED.to_owned(),
            })
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
                    return None;
                }
                Some(AgentControlEvent::GroupInvite {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    via_welcome_message_id_hex: hex::encode(via_welcome.as_slice()),
                    welcomer_account_id_hex: welcomer.map(|member| hex::encode(member.as_slice())),
                })
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
                    return None;
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
                };
                Some(AgentControlEvent::GroupStateChanged {
                    account_id_hex: group_event.account_id_hex,
                    group_id_hex,
                    change: change.to_owned(),
                    detail,
                })
            }
            _ => None,
        },
        _ => None,
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
            MARMOT_APP_EVENT_KIND_CHAT | MARMOT_APP_EVENT_KIND_DELETE
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
        _ => None,
    }
}

pub(crate) fn control_event_from_debug_event(
    event: AgentControlEvent,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    let (account_id_hex, group_id_hex) = match &event {
        AgentControlEvent::MessageDeleted {
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
/// kinds the live inbound stream surfaces: inbound chat messages, inbound kind-5 deletes, and
/// synthesized kind-1210 group-system rows for authenticated group-state changes. Other app-event
/// kinds remain ignored until they have explicit agent-control semantics.
pub(crate) fn inbound_message_event_from_record(
    account_id_hex: &str,
    record: AppMessageRecord,
    account_filter: Option<&str>,
    group_filter: Option<&str>,
) -> Option<AgentControlEvent> {
    debug_assert_ne!(
        MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
    );
    if !inbound_filter_matches(
        account_filter,
        account_id_hex,
        group_filter,
        &record.group_id_hex,
    ) {
        return None;
    }

    if record.kind == MARMOT_APP_EVENT_KIND_GROUP_SYSTEM {
        // Only locally synthesized group-system timeline rows represent the live
        // `GroupEvent::GroupStateChanged` signal. Ignore sent/received kind-1210 app events.
        if record.direction != "system" {
            return None;
        }
        let group_system = GroupSystemEvent::parse(&record.plaintext).ok()?;
        let (change, detail) = group_system_control_parts(&group_system)?;
        return Some(AgentControlEvent::GroupStateChanged {
            account_id_hex: account_id_hex.to_owned(),
            group_id_hex: record.group_id_hex,
            change: change.to_owned(),
            detail,
        });
    }

    if record.direction != "received" {
        return None;
    }
    // The live MessageReceived path drops messages whose sender is the subscribed account itself.
    if record.sender == account_id_hex {
        return None;
    }

    if record.kind == MARMOT_APP_EVENT_KIND_DELETE {
        let target_message_id_hex = reply_target_from_tags(&record.tags)?;
        return Some(AgentControlEvent::MessageDeleted {
            account_id_hex: account_id_hex.to_owned(),
            group_id_hex: record.group_id_hex,
            target_message_id_hex,
            sender_account_id_hex: record.sender,
        });
    }

    if record.kind != MARMOT_APP_EVENT_KIND_CHAT {
        return None;
    }
    let mentions_self = message_mentions_account(&record.tags, &record.plaintext, account_id_hex);
    let reply_to_message_id_hex = reply_target_from_tags(&record.tags);
    let media = media_refs_from_tags(&record.tags, record.source_epoch.unwrap_or(0));
    Some(AgentControlEvent::InboundMessage {
        account_id_hex: account_id_hex.to_owned(),
        group_id_hex: record.group_id_hex,
        message_id_hex: record.message_id_hex,
        sender_account_id_hex: record.sender,
        text: record.plaintext,
        mentions_self,
        reply_to_message_id_hex,
        // Storage replay has no directory join; display name is best-effort live-only.
        sender_display_name: None,
        media,
    })
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

#[derive(Clone)]
pub(crate) struct InboundCatchUpDriver {
    runtime: MarmotAppRuntime,
    lock: Arc<AsyncMutex<()>>,
    events: broadcast::Sender<InboundCatchUpEvent>,
    pub(crate) started: Arc<AtomicBool>,
    pub(crate) active: Arc<AtomicU64>,
}

impl InboundCatchUpDriver {
    pub(crate) fn new(runtime: MarmotAppRuntime) -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            runtime,
            lock: Arc::new(AsyncMutex::new(())),
            events,
            started: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicU64::new(0)),
        }
    }

    fn spawn(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + INBOUND_CATCH_UP_INTERVAL,
                INBOUND_CATCH_UP_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                if driver.active.load(Ordering::Acquire) == 0 {
                    driver.started.store(false, Ordering::Release);
                    if driver.active.load(Ordering::Acquire) == 0 {
                        break;
                    }
                    if driver
                        .started
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = driver.request().await;
            }
        });
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

    pub(crate) async fn request(&self) -> Result<(), AppError> {
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

pub(crate) struct InboundCatchUpSubscription {
    active: Arc<AtomicU64>,
}

impl Drop for InboundCatchUpSubscription {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}
