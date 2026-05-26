use cgka_traits::agent_text_stream::AGENT_TEXT_STREAM_PROFILE_STREAM_ID_LEN;
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
    MarmotAppEvent as MarmotInnerEvent, QUOTE_REF_TAG, STREAM_BROKER_TAG, STREAM_CHUNKS_TAG,
    STREAM_FINAL_KIND_TAG, STREAM_HASH_TAG, STREAM_ROUTE_TAG, STREAM_START_TAG, STREAM_TAG,
    STREAM_TYPE_TAG,
};

use crate::{AgentTextStreamFinishRequest, AppError, MediaReference};

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
    Delete {
        target_message_id: String,
    },
    Media {
        reference: MediaReference,
        caption: Option<String>,
    },
    StreamStart {
        stream_id: Vec<u8>,
        quic_candidates: Vec<String>,
    },
    StreamFinal {
        request: AgentTextStreamFinishRequest,
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
            Vec::new(),
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
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                vec![
                    event_ref_tag(target_message_id),
                    vec![QUOTE_REF_TAG.to_owned(), target_message_id.clone()],
                ],
                text.clone(),
            ))
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
        AppMessageIntent::Media { reference, caption } => {
            reference.validate()?;
            Ok(event(
                MARMOT_APP_EVENT_KIND_CHAT,
                vec![reference.imeta_tag()],
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
