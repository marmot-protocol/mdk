use cgka_traits::agent_text_stream::{
    AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN, AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN,
};
use cgka_traits::app_event::{
    AGENT_ACTIVITY_STATUS_TAG, AGENT_OPERATION_NAME_TAG, AGENT_OPERATION_STATUS_TAG,
    AGENT_OPERATION_TYPE_TAG, EVENT_REF_TAG, GROUP_SYSTEM_TYPE_TAG,
    MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG,
    STREAM_BROKER_TAG, STREAM_CHUNKS_TAG, STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_ROUTE_TAG,
    STREAM_START_TAG, STREAM_TAG, STREAM_TYPE_TAG,
};
use nostr::nips::nip21::Nip21;
use serde_json::{Map, Value, json};

use crate::ids::parse_account_id_hex;
use crate::{AgentTextStreamFinishRequest, AppError, MediaAttachmentReference};
use crate::{MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL, MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE};

/// Nostr pubkey-reference (`p`) tag name.
pub(crate) const PUBKEY_REF_TAG: &str = "p";

/// Upper bound for app-internal Markdown mention scans over untrusted message
/// plaintext. The sender stores the full content, but p-tag derivation only
/// parses this bounded prefix so one hostile message cannot force unbounded
/// synchronous Markdown work before send/classification (darkmatter#654).
const MAX_MARKDOWN_MENTION_SCAN_BYTES: usize = AGENT_TEXT_STREAM_MAX_PLAINTEXT_FRAME_LEN as usize;

/// Extract the mentioned pubkey hex from a token following a `nostr:` scheme (or
/// a bare hex/npub), covering NIP-21 `npub` + `nprofile` and a raw hex pubkey.
/// Event/coordinate references (`note`/`nevent`/`naddr`) are not pubkey mentions.
pub(crate) fn mention_pubkey_hex(token: &str) -> Option<String> {
    if let Ok(parsed) = Nip21::parse(&format!("nostr:{token}")) {
        return match parsed {
            Nip21::Pubkey(pubkey) => Some(pubkey.to_hex()),
            Nip21::Profile(profile) => Some(profile.public_key.to_hex()),
            _ => None,
        };
    }
    // Non-NIP-21 fallback: a bare hex pubkey or bare npub.
    parse_account_id_hex(token).ok()
}

/// Extract pubkey mentions from inline nostr entities in message content.
///
/// Derived from the `marmot-markdown` tokenizer's mention/URI tokens, which
/// recognize **both** bare `@npub1…` handles (`Inline::NostrMention`) and
/// explicit `nostr:<hrp>1…` URIs (`Inline::NostrUri`) — the same display
/// surface a client renders as a mention. Scanning the raw `"nostr:"`
/// substring missed bare `@npub1…` mentions (the form clients actually emit),
/// so those never got a `p`-tag on send or classified on receive
/// (darkmatter#617). Event/coordinate references (`note`/`nevent`/`naddr`) and
/// unparseable tokens are ignored.
pub(crate) fn inline_mention_pubkey_hexes(content: &str) -> Vec<String> {
    let mut hexes = Vec::new();
    for block in &marmot_markdown::parse(markdown_mention_scan_input(content)).blocks {
        collect_block_mention_hexes(block, &mut hexes);
    }
    hexes
}

fn markdown_mention_scan_input(content: &str) -> &str {
    if content.len() <= MAX_MARKDOWN_MENTION_SCAN_BYTES {
        return content;
    }
    let mut end = MAX_MARKDOWN_MENTION_SCAN_BYTES;
    while !content.is_char_boundary(end) {
        end -= 1;
    }
    &content[..end]
}

fn collect_block_mention_hexes(block: &marmot_markdown::Block, out: &mut Vec<String>) {
    use marmot_markdown::Block;
    match block {
        Block::Paragraph { inlines } | Block::Heading { inlines, .. } => {
            collect_inline_mention_hexes(inlines, out);
        }
        Block::BlockQuote { blocks } => {
            for block in blocks {
                collect_block_mention_hexes(block, out);
            }
        }
        Block::List { items, .. } => {
            for item in items {
                for block in &item.blocks {
                    collect_block_mention_hexes(block, out);
                }
            }
        }
        Block::Table { header, rows, .. } => {
            for cell in header {
                collect_inline_mention_hexes(&cell.inlines, out);
            }
            for row in rows {
                for cell in row {
                    collect_inline_mention_hexes(&cell.inlines, out);
                }
            }
        }
        // Code blocks, math blocks, and thematic breaks carry no inline
        // mentions.
        Block::ThematicBreak | Block::CodeBlock { .. } | Block::MathBlock { .. } => {}
    }
}

fn collect_inline_mention_hexes(inlines: &[marmot_markdown::Inline], out: &mut Vec<String>) {
    use marmot_markdown::Inline;
    for inline in inlines {
        match inline {
            Inline::NostrMention(entity) | Inline::NostrUri(entity) => {
                if let Some(hex) = mention_pubkey_hex(&entity.bech32) {
                    out.push(hex);
                }
            }
            Inline::Emph(children)
            | Inline::Strong(children)
            | Inline::Strikethrough(children)
            | Inline::Link { children, .. } => collect_inline_mention_hexes(children, out),
            Inline::Image { alt, .. } => collect_inline_mention_hexes(alt, out),
            Inline::Text(_)
            | Inline::SoftBreak
            | Inline::HardBreak
            | Inline::Code(_)
            | Inline::Autolink { .. }
            | Inline::Math(_) => {}
        }
    }
}

/// Derive NIP-27 `["p", <pubkey-hex>]` tags from inline nostr mentions in
/// message content (both bare `@npub1…` handles and explicit `nostr:<hrp>1…`
/// URIs). Each distinct mentioned pubkey gets one tag (in first-seen order);
/// event references and unparseable tokens are ignored. This is how a Marmot
/// client makes a mention discoverable (a p-tag alongside the inline
/// reference), per NIP-27.
fn mention_p_tags(content: &str) -> Vec<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    let mut tags = Vec::new();
    for hex in inline_mention_pubkey_hexes(content) {
        if seen.insert(hex.clone()) {
            tags.push(vec![PUBKEY_REF_TAG.to_owned(), hex]);
        }
    }
    tags
}

/// Value of the `stream-type` tag on an agent text stream start event.
const STREAM_TYPE_TEXT: &str = "text";
/// Value of the `route` tag on a brokered QUIC agent text stream start event.
pub(crate) const STREAM_ROUTE_QUIC: &str = "quic";
/// `final-kind` tag value: the kind of the eventual stream-final chat message.
const STREAM_FINAL_KIND_CHAT: &str = "9";

/// A structured outgoing app message, resolved into a [`MarmotInnerEvent`] by
/// the account worker, which owns the authoring account id and the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppMessageIntent {
    Chat {
        content: String,
    },
    Reaction {
        target_message_id: String,
        emoji: String,
    },
    Unreact {
        target_message_id: String,
    },
    Reply {
        target_message_id: String,
        text: String,
    },
    Edit {
        target_message_id: String,
        content: String,
    },
    Delete {
        target_message_id: String,
    },
    Media {
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
    },
    StreamStart {
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
    },
    StreamFinal {
        request: AgentTextStreamFinishRequest,
    },
    AgentActivity {
        status: String,
        text: String,
        reply_to_message_id: Option<String>,
        extra: Option<Value>,
    },
    AgentOperation {
        event_type: String,
        status: String,
        operation_id: Option<String>,
        run_id: Option<String>,
        turn_id: Option<String>,
        name: Option<String>,
        text: String,
        preview: Option<String>,
        details: Option<Value>,
        sequence: Option<u64>,
        ok: Option<bool>,
        duration_ms: Option<u64>,
        reply_to_message_id: Option<String>,
    },
    GroupSystem {
        system_type: String,
        text: String,
        data: Option<Value>,
    },
    PushTokenUpdate {
        content: String,
    },
    PushTokenRemoval {
        content: String,
    },
}

/// Build the inner Marmot app event for `intent`, authored by `sender_pubkey_hex`
/// at `created_at`. `Unreact` must be resolved to a `Delete` of the reaction
/// event id before this is called.
pub(crate) fn build_inner_event(
    intent: &AppMessageIntent,
    sender_pubkey_hex: &str,
    created_at: u64,
) -> Result<MarmotInnerEvent, AppError> {
    let event = |kind, tags, content| {
        MarmotInnerEvent::new(
            sender_pubkey_hex.to_owned(),
            created_at,
            kind,
            tags,
            content,
        )
    };
    match intent {
        AppMessageIntent::Chat { content } => Ok(event(
            MARMOT_APP_EVENT_KIND_CHAT,
            mention_p_tags(content),
            content.clone(),
        )),
        AppMessageIntent::Reaction {
            target_message_id,
            emoji,
        } => {
            validate_message_ref(target_message_id)?;
            if emoji.trim().is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "reaction add requires a non-empty emoji".into(),
                ));
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_REACTION,
                vec![event_ref_tag(target_message_id)],
                emoji.clone(),
            ))
        }
        AppMessageIntent::Reply {
            target_message_id,
            text,
        } => {
            validate_message_ref(target_message_id)?;
            if text.trim().is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "reply requires non-empty text".into(),
                ));
            }
            let mut tags = vec![
                event_ref_tag(target_message_id),
                vec![QUOTE_REF_TAG.to_owned(), target_message_id.clone()],
            ];
            tags.extend(mention_p_tags(text));
            Ok(event(MARMOT_APP_EVENT_KIND_CHAT, tags, text.clone()))
        }
        AppMessageIntent::Edit {
            target_message_id,
            content,
        } => {
            validate_message_ref(target_message_id)?;
            if content.trim().is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "edit requires non-empty content".into(),
                ));
            }
            let mut tags = vec![event_ref_tag(target_message_id)];
            tags.extend(mention_p_tags(content));
            Ok(event(MARMOT_APP_EVENT_KIND_EDIT, tags, content.clone()))
        }
        AppMessageIntent::Unreact { .. } | AppMessageIntent::Delete { .. } => {
            let target_message_id = match intent {
                AppMessageIntent::Delete { target_message_id }
                | AppMessageIntent::Unreact { target_message_id } => target_message_id,
                _ => unreachable!(),
            };
            validate_message_ref(target_message_id)?;
            Ok(event(
                MARMOT_APP_EVENT_KIND_DELETE,
                vec![event_ref_tag(target_message_id)],
                String::new(),
            ))
        }
        AppMessageIntent::Media {
            attachments,
            caption,
        } => {
            if attachments.is_empty() {
                return Err(AppError::InvalidAppMessagePayload(
                    "media message requires at least one attachment".into(),
                ));
            }
            let source_epoch = attachments[0].source_epoch;
            for attachment in attachments {
                // Structural + group-policy validation of outbound attachments
                // happens in `Client::send_media_attachments`, which holds the
                // group's `allowed_locator_kinds`. Here we only enforce the
                // cross-attachment invariant that one message shares a single
                // source epoch.
                if attachment.source_epoch != source_epoch {
                    return Err(AppError::InvalidAppMessagePayload(
                        "media attachments in one message must share a source epoch".into(),
                    ));
                }
            }
            let mut tags: Vec<Vec<String>> = attachments
                .iter()
                .map(MediaAttachmentReference::imeta_tag)
                .collect();
            if let Some(caption) = caption {
                tags.extend(mention_p_tags(caption));
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                tags,
                caption.clone().unwrap_or_default(),
            ))
        }
        AppMessageIntent::StreamStart {
            stream_id,
            quic_candidates,
        } => {
            let stream_id_hex = hex::encode(stream_id);
            if stream_id.len() != AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream id must be 32 bytes".into(),
                ));
            }
            let brokers: Vec<&String> = quic_candidates
                .iter()
                .filter(|candidate| !candidate.trim().is_empty())
                .collect();
            if brokers.is_empty() {
                return Err(AppError::AgentStreamMissingCandidate);
            }
            let mut tags = vec![
                vec![STREAM_TAG.to_owned(), stream_id_hex],
                vec![STREAM_TYPE_TAG.to_owned(), STREAM_TYPE_TEXT.to_owned()],
                vec![
                    STREAM_FINAL_KIND_TAG.to_owned(),
                    STREAM_FINAL_KIND_CHAT.to_owned(),
                ],
                vec![STREAM_ROUTE_TAG.to_owned(), STREAM_ROUTE_QUIC.to_owned()],
            ];
            tags.extend(
                brokers
                    .into_iter()
                    .map(|candidate| vec![STREAM_BROKER_TAG.to_owned(), candidate.clone()]),
            );
            Ok(event(
                MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
                tags,
                String::new(),
            ))
        }
        AppMessageIntent::StreamFinal { request } => {
            if request.stream_id.len() != AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream id must be 32 bytes".into(),
                ));
            }
            let start_event_id = hex::decode(&request.start_event_id).map_err(|_| {
                AppError::InvalidAppMessagePayload(
                    "agent text stream start event id must be 32-byte hex".into(),
                )
            })?;
            if start_event_id.len() != 32 {
                return Err(AppError::InvalidAppMessagePayload(
                    "agent text stream start event id must be 32-byte hex".into(),
                ));
            }
            let tags = vec![
                vec![STREAM_TAG.to_owned(), hex::encode(&request.stream_id)],
                vec![STREAM_START_TAG.to_owned(), request.start_event_id.clone()],
                vec![
                    STREAM_HASH_TAG.to_owned(),
                    hex::encode(request.transcript_hash),
                ],
                vec![
                    STREAM_CHUNKS_TAG.to_owned(),
                    request.chunk_count.to_string(),
                ],
            ];
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                tags,
                request.final_text_or_reference.clone(),
            ))
        }
        AppMessageIntent::AgentActivity {
            status,
            text,
            reply_to_message_id,
            extra,
        } => {
            let status = validate_non_empty_field(status, "agent activity status")?;
            let mut tags = vec![vec![AGENT_ACTIVITY_STATUS_TAG.to_owned(), status.clone()]];
            if let Some(target_message_id) = optional_message_ref(reply_to_message_id)? {
                tags.push(event_ref_tag(&target_message_id));
            }
            let mut content = app_payload_base(status.clone(), text.clone());
            if let Some(extra) = extra {
                content.insert("extra".to_owned(), extra.clone());
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY,
                tags,
                Value::Object(content).to_string(),
            ))
        }
        AppMessageIntent::AgentOperation {
            event_type,
            status,
            operation_id,
            run_id,
            turn_id,
            name,
            text,
            preview,
            details,
            sequence,
            ok,
            duration_ms,
            reply_to_message_id,
        } => {
            let event_type = validate_non_empty_field(event_type, "agent operation type")?;
            let status = validate_non_empty_field(status, "agent operation status")?;
            let mut tags = vec![
                vec![AGENT_OPERATION_TYPE_TAG.to_owned(), event_type.clone()],
                vec![AGENT_OPERATION_STATUS_TAG.to_owned(), status.clone()],
            ];
            if let Some(name) = optional_non_empty_field(name) {
                tags.push(vec![AGENT_OPERATION_NAME_TAG.to_owned(), name.to_owned()]);
            }
            if let Some(target_message_id) = optional_message_ref(reply_to_message_id)? {
                tags.push(event_ref_tag(&target_message_id));
            }
            let mut content = app_payload_base(status.clone(), text.clone());
            content.insert("event_type".to_owned(), Value::String(event_type));
            if let Some(operation_id) = optional_non_empty_field(operation_id) {
                content.insert(
                    "operation_id".to_owned(),
                    Value::String(operation_id.to_owned()),
                );
            }
            if let Some(run_id) = optional_non_empty_field(run_id) {
                content.insert("run_id".to_owned(), Value::String(run_id.to_owned()));
            }
            if let Some(turn_id) = optional_non_empty_field(turn_id) {
                content.insert("turn_id".to_owned(), Value::String(turn_id.to_owned()));
            }
            if let Some(name) = optional_non_empty_field(name) {
                content.insert("name".to_owned(), Value::String(name.to_owned()));
            }
            if let Some(preview) = optional_non_empty_field(preview) {
                content.insert("preview".to_owned(), Value::String(preview.to_owned()));
            }
            if let Some(details) = details {
                content.insert("details".to_owned(), details.clone());
            }
            if let Some(sequence) = sequence {
                content.insert("sequence".to_owned(), json!(sequence));
            }
            if let Some(ok) = ok {
                content.insert("ok".to_owned(), json!(ok));
            }
            if let Some(duration_ms) = duration_ms {
                content.insert("duration_ms".to_owned(), json!(duration_ms));
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
                tags,
                Value::Object(content).to_string(),
            ))
        }
        AppMessageIntent::GroupSystem {
            system_type,
            text,
            data,
        } => {
            let system_type = validate_non_empty_field(system_type, "group system type")?;
            let mut content = Map::new();
            content.insert("v".to_owned(), json!(1));
            content.insert("system_type".to_owned(), Value::String(system_type.clone()));
            content.insert("text".to_owned(), Value::String(text.clone()));
            if let Some(data) = data {
                content.insert("data".to_owned(), data.clone());
            }
            Ok(event(
                MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
                vec![vec![GROUP_SYSTEM_TYPE_TAG.to_owned(), system_type]],
                Value::Object(content).to_string(),
            ))
        }
        AppMessageIntent::PushTokenUpdate { content } => Ok(event(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_UPDATE,
            vec![vec!["v".to_owned(), crate::PUSH_VERSION.to_owned()]],
            content.clone(),
        )),
        AppMessageIntent::PushTokenRemoval { content } => Ok(event(
            MARMOT_APP_EVENT_KIND_PUSH_TOKEN_REMOVAL,
            vec![vec!["v".to_owned(), crate::PUSH_VERSION.to_owned()]],
            content.clone(),
        )),
    }
}

fn event_ref_tag(target_message_id: &str) -> Vec<String> {
    vec![EVENT_REF_TAG.to_owned(), target_message_id.to_owned()]
}

fn validate_message_ref(target_message_id: &str) -> Result<(), AppError> {
    if target_message_id.trim().is_empty() {
        return Err(AppError::InvalidAppMessagePayload(
            "target message id cannot be empty".into(),
        ));
    }
    Ok(())
}

fn validate_non_empty_field(value: &str, field: &str) -> Result<String, AppError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(AppError::InvalidAppMessagePayload(format!(
            "{field} cannot be empty"
        )));
    }
    Ok(trimmed.to_owned())
}

fn optional_non_empty_field(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional_message_ref(value: &Option<String>) -> Result<Option<String>, AppError> {
    let Some(value) = optional_non_empty_field(value) else {
        return Ok(None);
    };
    validate_message_ref(value)?;
    Ok(Some(value.to_owned()))
}

fn app_payload_base(kind_or_status: String, text: String) -> Map<String, Value> {
    let mut content = Map::new();
    content.insert("v".to_owned(), json!(1));
    content.insert("status".to_owned(), Value::String(kind_or_status));
    content.insert("text".to_owned(), Value::String(text));
    content
}

/// Encode a built inner event into MLS application-message plaintext bytes.
pub(crate) fn encode_inner_event(event: &MarmotInnerEvent) -> Result<Vec<u8>, AppError> {
    event
        .encode()
        .map_err(|err| AppError::InvalidAppMessagePayload(err.to_string()))
}

/// True when an inner event is a kind-9 chat that finalizes an agent text
/// stream (it carries a `stream` tag plus a `stream-start` or `stream-hash`
/// tag). Such events flow as normal timeline messages, not start signals.
pub fn is_stream_final_event(kind: u64, tags: &[Vec<String>]) -> bool {
    kind == MARMOT_APP_EVENT_KIND_CHAT
        && tag_value(tags, STREAM_TAG).is_some()
        && (tag_value(tags, STREAM_START_TAG).is_some()
            || tag_value(tags, STREAM_HASH_TAG).is_some())
}

/// First value of the named tag (`tag[0] == name` -> `tag[1]`).
pub fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

/// All values of the named tag across every matching tag entry.
pub fn tag_values<'a>(tags: &'a [Vec<String>], name: &str) -> Vec<&'a str> {
    tags.iter()
        .filter(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .filter_map(|tag| tag.get(1))
        .map(String::as_str)
        .collect()
}

#[cfg(test)]
mod mention_tests {
    use super::*;
    use crate::ids::{nprofile_for_account_id, npub_for_account_id};

    fn valid_pubkey_hex() -> String {
        nostr::Keys::generate().public_key().to_hex()
    }

    #[test]
    fn mention_p_tags_handles_nostr_uri_npub_and_nprofile() {
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        let nprofile = nprofile_for_account_id(&hex, &[]).unwrap();
        // NIP-27 `nostr:` URIs carry bech32 entities (npub/nprofile), which the
        // markdown tokenizer renders as mentions.
        for token in [npub.as_str(), nprofile.as_str()] {
            let content = format!("hey nostr:{token} how are you?");
            assert_eq!(
                mention_p_tags(&content),
                vec![vec!["p".to_owned(), hex.clone()]],
                "mention token form failed: {token}"
            );
        }
    }

    #[test]
    fn mention_p_tags_ignores_nostr_uri_with_raw_hex() {
        // `nostr:<raw-hex>` is not a NIP-21 URI (those carry bech32 entities,
        // never raw hex), so the markdown tokenizer leaves it as literal text
        // and never renders it as a mention. p-tag derivation tracks that
        // display surface, so it yields no p-tag (darkmatter#617).
        let hex = valid_pubkey_hex();
        assert!(mention_p_tags(&format!("hey nostr:{hex} how are you?")).is_empty());
    }

    #[test]
    fn mention_p_tags_dedups_same_pubkey_and_ignores_plain_text() {
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        // Same pubkey referenced twice (bare `@npub1…` then `nostr:npub1…`)
        // collapses to one p-tag.
        let content = format!("ping @{npub} ... and again nostr:{npub}");
        assert_eq!(mention_p_tags(&content), vec![vec!["p".to_owned(), hex]]);
        assert!(mention_p_tags("plain text, no mentions here").is_empty());
        assert!(mention_p_tags("a dangling nostr: with no token").is_empty());
    }

    #[test]
    fn mention_p_tags_covers_bare_npub_mention() {
        // Clients insert mentions as the bare `@npub1…` form (no `nostr:`),
        // which the markdown tokenizer renders as a mention. That form must
        // still get its NIP-27 `p`-tag on send. Regression for darkmatter#617.
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        let content = format!("hey @{npub} how are you?");
        assert_eq!(mention_p_tags(&content), vec![vec!["p".to_owned(), hex]]);
    }

    #[test]
    fn chat_intent_p_tags_the_inline_mention() {
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        let intent = AppMessageIntent::Chat {
            content: format!("yo nostr:{npub}"),
        };
        let event = build_inner_event(&intent, &valid_pubkey_hex(), 0).unwrap();
        assert!(event.tags.contains(&vec!["p".to_owned(), hex]));
    }

    #[test]
    fn reply_intent_keeps_e_q_and_adds_mention_p_tag() {
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        let target = "ff".repeat(32);
        let intent = AppMessageIntent::Reply {
            target_message_id: target.clone(),
            text: format!("re nostr:{npub}"),
        };
        let event = build_inner_event(&intent, &valid_pubkey_hex(), 0).unwrap();
        assert!(
            event
                .tags
                .contains(&vec![EVENT_REF_TAG.to_owned(), target.clone()])
        );
        assert!(event.tags.contains(&vec![QUOTE_REF_TAG.to_owned(), target]));
        assert!(event.tags.contains(&vec!["p".to_owned(), hex]));
    }

    #[test]
    fn mention_scan_input_cap_preserves_utf8_boundary() {
        let input = format!("{}🦫", "a".repeat(MAX_MARKDOWN_MENTION_SCAN_BYTES - 1));
        let capped = markdown_mention_scan_input(&input);
        assert_eq!(capped, "a".repeat(MAX_MARKDOWN_MENTION_SCAN_BYTES - 1));
        assert!(capped.is_char_boundary(capped.len()));
    }

    #[test]
    fn mention_p_tags_caps_pathological_markdown_before_parsing() {
        let hex = valid_pubkey_hex();
        let npub = npub_for_account_id(&hex).unwrap();
        let input = format!(
            "{}{} @{npub}",
            "[".repeat(MAX_MARKDOWN_MENTION_SCAN_BYTES + 1024),
            "]".repeat(MAX_MARKDOWN_MENTION_SCAN_BYTES + 1024)
        );
        assert!(mention_p_tags(&input).is_empty());
    }
}
