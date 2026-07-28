//! Read-only materialized-timeline projection for agent-control clients.

use agent_control::{
    AGENT_CONTROL_TIMELINE_DEFAULT_LIMIT, AGENT_CONTROL_TIMELINE_MAX_LIMIT,
    AGENT_CONTROL_TIMELINE_REACTIONS_MAX, AGENT_CONTROL_TIMELINE_TEXT_MAX_CHARS,
    AgentControlEnvelope, AgentControlResponse, AgentControlTimelineCursor,
    AgentControlTimelineMessage, AgentControlTimelineMessageAvailability,
    AgentControlTimelineReaction, MAX_AGENT_CONTROL_FRAME_BYTES,
};
use marmot_app::{TimelineMessageQuery, TimelineMessageRecord, TimelinePagination};

use crate::AgentConnector;
use crate::error::ConnectorError;
use crate::event_projection::{attachment_summaries_from_tags, control_actor};
use crate::validation::normalize_hex;

const TIMELINE_ATTACHMENT_FIELD_MAX_CHARS: usize = 512;
const TIMELINE_REACTION_EMOJI_MAX_CHARS: usize = 64;

impl AgentConnector {
    pub(crate) fn timeline_message_response(
        &self,
        account_id_hex: &str,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let message_id_hex = normalize_hex(message_id_hex)?;
        let message = self
            .runtime
            .timeline_message(&account.label, &group_id_hex, &message_id_hex)?
            .map(|record| timeline_message(record, &account.account_id_hex));
        Ok(AgentControlResponse::TimelineMessage {
            account_id_hex: account.account_id_hex,
            group_id_hex,
            message_id_hex,
            message,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn timeline_list_response(
        &self,
        request_id: Option<&str>,
        account_id_hex: &str,
        group_id_hex: &str,
        before: Option<AgentControlTimelineCursor>,
        after: Option<AgentControlTimelineCursor>,
        before_inclusive: bool,
        limit: Option<u32>,
    ) -> Result<AgentControlResponse, ConnectorError> {
        let account = self.local_account_for_account_id(account_id_hex)?;
        let group_id_hex = normalize_hex(group_id_hex)?;
        let before = before.map(normalize_cursor).transpose()?;
        let after = after.map(normalize_cursor).transpose()?;
        let limit = limit
            .unwrap_or(AGENT_CONTROL_TIMELINE_DEFAULT_LIMIT)
            .clamp(1, AGENT_CONTROL_TIMELINE_MAX_LIMIT);
        let page = self.runtime.timeline_messages_with_query(
            &account.label,
            TimelineMessageQuery {
                group_id_hex: Some(group_id_hex.clone()),
                search: None,
                pagination: TimelinePagination {
                    before: before.as_ref().map(|cursor| cursor.recorded_at),
                    before_message_id: before.as_ref().map(|cursor| cursor.message_id_hex.clone()),
                    before_inclusive,
                    after: after.as_ref().map(|cursor| cursor.recorded_at),
                    after_message_id: after.as_ref().map(|cursor| cursor.message_id_hex.clone()),
                    limit: Some(limit as usize),
                },
            },
        )?;
        bounded_timeline_page_response(
            request_id,
            AgentControlResponse::TimelinePage {
                account_id_hex: account.account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                messages: page
                    .messages
                    .into_iter()
                    .map(|record| timeline_message(record, &account.account_id_hex))
                    .collect(),
                has_more_before: page.has_more_before,
                has_more_after: page.has_more_after,
            },
            after.is_some(),
        )
    }
}

fn bounded_timeline_page_response(
    request_id: Option<&str>,
    mut response: AgentControlResponse,
    trim_from_back: bool,
) -> Result<AgentControlResponse, ConnectorError> {
    loop {
        // Size the exact envelope that handle_connection will write, including
        // the caller-supplied correlation id.
        let sizing_envelope =
            AgentControlEnvelope::new(request_id.map(str::to_owned), response.clone());
        let frame_len = serde_json::to_vec(&sizing_envelope)?.len() + 1;
        if frame_len <= MAX_AGENT_CONTROL_FRAME_BYTES {
            return Ok(response);
        }

        let AgentControlResponse::TimelinePage {
            messages,
            has_more_before,
            has_more_after,
            ..
        } = &mut response
        else {
            unreachable!("timeline page bounder requires a timeline_page response");
        };
        if messages.is_empty() {
            return Err(agent_control::AgentControlError::FrameTooLarge(frame_len).into());
        }
        // Storage returns rows in chronological order. For an `after` page,
        // discard the newest tail; otherwise discard the oldest head. This
        // preserves the rows nearest the requested cursor.
        if trim_from_back {
            messages.pop();
            *has_more_after = true;
        } else {
            messages.remove(0);
            *has_more_before = true;
        }
    }
}

fn normalize_cursor(
    mut cursor: AgentControlTimelineCursor,
) -> Result<AgentControlTimelineCursor, ConnectorError> {
    cursor.message_id_hex = normalize_hex(&cursor.message_id_hex)?;
    Ok(cursor)
}

fn timeline_message(
    record: TimelineMessageRecord,
    self_account_id_hex: &str,
) -> AgentControlTimelineMessage {
    let availability = if record.invalidation_status.is_some() {
        AgentControlTimelineMessageAvailability::Invalidated
    } else if record.deleted {
        AgentControlTimelineMessageAvailability::Deleted
    } else {
        AgentControlTimelineMessageAvailability::Available
    };
    let available = availability == AgentControlTimelineMessageAvailability::Available;
    let (text, text_truncated, attachments, attachments_truncated) = if available {
        let (text, text_truncated) = bounded_timeline_text(&record.plaintext);
        let (mut attachments, mut attachments_truncated) =
            attachment_summaries_from_tags(&record.tags, record.source_epoch);
        for attachment in &mut attachments {
            let (media_type, media_type_truncated) =
                bounded_string(&attachment.media_type, TIMELINE_ATTACHMENT_FIELD_MAX_CHARS);
            attachment.media_type = media_type;
            let (file_name, file_name_truncated) =
                bounded_string(&attachment.file_name, TIMELINE_ATTACHMENT_FIELD_MAX_CHARS);
            attachment.file_name = file_name;
            attachments_truncated |= file_name_truncated;
            if let Some(dim) = attachment.dim.as_deref() {
                let (dim, dim_truncated) = bounded_string(dim, TIMELINE_ATTACHMENT_FIELD_MAX_CHARS);
                attachment.dim = Some(dim);
                attachments_truncated |= dim_truncated;
            }
            attachments_truncated |= media_type_truncated;
        }
        (
            Some(text),
            text_truncated,
            attachments,
            attachments_truncated,
        )
    } else {
        (None, false, Vec::new(), false)
    };
    let reactions_len = record.reactions.user_reactions.len();
    let reactions = if available {
        record
            .reactions
            .user_reactions
            .into_iter()
            .take(AGENT_CONTROL_TIMELINE_REACTIONS_MAX)
            .map(|reaction| AgentControlTimelineReaction {
                reaction_message_id_hex: reaction.reaction_message_id_hex,
                actor: control_actor(reaction.sender, None, self_account_id_hex),
                emoji: bounded_string(&reaction.emoji, TIMELINE_REACTION_EMOJI_MAX_CHARS).0,
                reacted_at: reaction.reacted_at,
            })
            .collect()
    } else {
        Vec::new()
    };
    AgentControlTimelineMessage {
        message_id_hex: record.message_id_hex,
        sender: control_actor(record.sender, None, self_account_id_hex),
        direction: record.direction,
        kind: record.kind,
        recorded_at: record.timeline_at,
        observed_at: record.received_at,
        availability,
        text,
        text_truncated,
        reply_to_message_id_hex: record.reply_to_message_id_hex,
        attachments,
        attachments_truncated,
        reactions,
        reactions_truncated: available && reactions_len > AGENT_CONTROL_TIMELINE_REACTIONS_MAX,
    }
}

fn bounded_timeline_text(text: &str) -> (String, bool) {
    bounded_string(text, AGENT_CONTROL_TIMELINE_TEXT_MAX_CHARS)
}

fn bounded_string(text: &str, max_chars: usize) -> (String, bool) {
    let mut chars = text.chars();
    let excerpt = chars.by_ref().take(max_chars).collect::<String>();
    (excerpt, chars.next().is_some())
}

#[cfg(test)]
mod tests {
    use agent_control::{
        AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX, AgentControlActor, AgentControlAttachmentSummary,
        encode_frame,
    };
    use marmot_app::{TimelineMessageRecord, TimelineReactionSummary, TimelineUserReaction};

    use super::*;

    fn record() -> TimelineMessageRecord {
        TimelineMessageRecord {
            message_id_hex: "11".repeat(32),
            source_message_id_hex: Some("22".repeat(32)),
            source_epoch: Some(7),
            retention_seconds: None,
            retention_expires_at: None,
            direction: "received".to_owned(),
            group_id_hex: "33".repeat(32),
            sender: "44".repeat(32),
            plaintext: "hello".to_owned(),
            kind: 9,
            tags: Vec::new(),
            timeline_at: 42,
            received_at: 43,
            reply_to_message_id_hex: Some("55".repeat(32)),
            reply_preview: None,
            media: None,
            agent_text_stream: None,
            reactions: TimelineReactionSummary {
                by_emoji: Default::default(),
                user_reactions: vec![TimelineUserReaction {
                    reaction_message_id_hex: "66".repeat(32),
                    target_message_id_hex: "11".repeat(32),
                    sender: "77".repeat(32),
                    emoji: "👍".to_owned(),
                    reacted_at: 44,
                }],
            },
            deleted: false,
            deleted_by_message_id_hex: None,
            invalidation_status: None,
        }
    }

    #[test]
    fn available_timeline_message_keeps_durable_identity_and_reactions() {
        let message = timeline_message(record(), &"77".repeat(32));
        assert_eq!(
            message.availability,
            AgentControlTimelineMessageAvailability::Available
        );
        assert_eq!(message.text.as_deref(), Some("hello"));
        assert_eq!(message.reply_to_message_id_hex, Some("55".repeat(32)));
        assert_eq!(message.reactions.len(), 1);
        assert!(message.reactions[0].actor.is_self);
        assert_eq!(
            message.reactions[0].reaction_message_id_hex,
            "66".repeat(32)
        );
    }

    #[test]
    fn deleted_and_invalidated_timeline_messages_never_expose_content() {
        let mut deleted = record();
        deleted.deleted = true;
        deleted.tags = vec![vec!["imeta".to_owned(), "m image/png".to_owned()]];
        let deleted = timeline_message(deleted, &"aa".repeat(32));
        assert_eq!(
            deleted.availability,
            AgentControlTimelineMessageAvailability::Deleted
        );
        assert_eq!(deleted.text, None);
        assert!(deleted.attachments.is_empty());
        assert!(deleted.reactions.is_empty());

        let mut invalidated = record();
        invalidated.invalidation_status = Some("LosingBranch".to_owned());
        let invalidated = timeline_message(invalidated, &"aa".repeat(32));
        assert_eq!(
            invalidated.availability,
            AgentControlTimelineMessageAvailability::Invalidated
        );
        assert_eq!(invalidated.text, None);
        assert!(invalidated.reactions.is_empty());
    }

    fn large_timeline_message(index: usize) -> AgentControlTimelineMessage {
        let actor = AgentControlActor {
            account_id_hex: "44".repeat(32),
            display_name: None,
            is_self: false,
        };
        AgentControlTimelineMessage {
            message_id_hex: format!("{index:064x}"),
            sender: actor.clone(),
            direction: "received".to_owned(),
            kind: 9,
            recorded_at: index as u64,
            observed_at: index as u64,
            availability: AgentControlTimelineMessageAvailability::Available,
            text: Some("t".repeat(AGENT_CONTROL_TIMELINE_TEXT_MAX_CHARS)),
            text_truncated: true,
            reply_to_message_id_hex: None,
            attachments: (0..AGENT_CONTROL_REFERENCED_ATTACHMENTS_MAX)
                .map(|_| AgentControlAttachmentSummary {
                    media_type: "m".repeat(TIMELINE_ATTACHMENT_FIELD_MAX_CHARS),
                    file_name: "f".repeat(TIMELINE_ATTACHMENT_FIELD_MAX_CHARS),
                    dim: Some("d".repeat(TIMELINE_ATTACHMENT_FIELD_MAX_CHARS)),
                })
                .collect(),
            attachments_truncated: true,
            reactions: (0..AGENT_CONTROL_TIMELINE_REACTIONS_MAX)
                .map(|reaction| AgentControlTimelineReaction {
                    reaction_message_id_hex: format!("{reaction:064x}"),
                    actor: actor.clone(),
                    emoji: "e".repeat(TIMELINE_REACTION_EMOJI_MAX_CHARS),
                    reacted_at: reaction as u64,
                })
                .collect(),
            reactions_truncated: true,
        }
    }

    fn oversized_page() -> AgentControlResponse {
        AgentControlResponse::TimelinePage {
            account_id_hex: "11".repeat(32),
            group_id_hex: "22".repeat(32),
            messages: (0..AGENT_CONTROL_TIMELINE_MAX_LIMIT as usize)
                .map(large_timeline_message)
                .collect(),
            has_more_before: false,
            has_more_after: false,
        }
    }

    fn page_messages(response: &AgentControlResponse) -> &[AgentControlTimelineMessage] {
        let AgentControlResponse::TimelinePage { messages, .. } = response else {
            panic!("expected timeline_page response");
        };
        messages
    }

    #[test]
    fn oversized_before_page_keeps_newest_rows_nearest_cursor() {
        let response =
            bounded_timeline_page_response(Some("request-before"), oversized_page(), false)
                .unwrap();
        let messages = page_messages(&response);
        assert!(!messages.is_empty());
        assert!(messages.len() < AGENT_CONTROL_TIMELINE_MAX_LIMIT as usize);
        assert_ne!(messages[0].message_id_hex, format!("{:064x}", 0));
        assert_eq!(
            messages.last().unwrap().message_id_hex,
            format!("{:064x}", AGENT_CONTROL_TIMELINE_MAX_LIMIT - 1)
        );
        let AgentControlResponse::TimelinePage {
            has_more_before,
            has_more_after,
            ..
        } = &response
        else {
            unreachable!()
        };
        assert!(*has_more_before);
        assert!(!*has_more_after);
        assert!(
            encode_frame(&AgentControlEnvelope::new(
                Some("request-before".to_owned()),
                response
            ))
            .unwrap()
            .len()
                <= MAX_AGENT_CONTROL_FRAME_BYTES
        );
    }

    #[test]
    fn oversized_after_page_keeps_oldest_rows_nearest_cursor() {
        let response =
            bounded_timeline_page_response(Some("request-after"), oversized_page(), true).unwrap();
        let messages = page_messages(&response);
        assert!(!messages.is_empty());
        assert!(messages.len() < AGENT_CONTROL_TIMELINE_MAX_LIMIT as usize);
        assert_eq!(messages[0].message_id_hex, format!("{:064x}", 0));
        assert_ne!(
            messages.last().unwrap().message_id_hex,
            format!("{:064x}", AGENT_CONTROL_TIMELINE_MAX_LIMIT - 1)
        );
        let AgentControlResponse::TimelinePage {
            has_more_before,
            has_more_after,
            ..
        } = &response
        else {
            unreachable!()
        };
        assert!(!*has_more_before);
        assert!(*has_more_after);
        assert!(
            encode_frame(&AgentControlEnvelope::new(
                Some("request-after".to_owned()),
                response
            ))
            .unwrap()
            .len()
                <= MAX_AGENT_CONTROL_FRAME_BYTES
        );
    }

    #[test]
    fn page_budget_accounts_for_actual_request_id() {
        let short = bounded_timeline_page_response(Some("short"), oversized_page(), false).unwrap();
        let long_request_id = "r".repeat(100_000);
        let long = bounded_timeline_page_response(Some(&long_request_id), oversized_page(), false)
            .unwrap();

        assert!(page_messages(&long).len() < page_messages(&short).len());
        assert!(
            encode_frame(&AgentControlEnvelope::new(Some(long_request_id), long))
                .unwrap()
                .len()
                <= MAX_AGENT_CONTROL_FRAME_BYTES
        );
    }
}
