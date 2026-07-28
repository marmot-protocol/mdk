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
        let mut messages = page
            .messages
            .into_iter()
            .map(|record| timeline_message(record, &account.account_id_hex))
            .collect::<Vec<_>>();
        let mut has_more_before = page.has_more_before;
        let mut has_more_after = page.has_more_after;

        loop {
            let response = AgentControlResponse::TimelinePage {
                account_id_hex: account.account_id_hex.clone(),
                group_id_hex: group_id_hex.clone(),
                messages: messages.clone(),
                has_more_before,
                has_more_after,
            };
            // Keep a complete response envelope below the protocol frame cap. When a
            // requested page is too large, preserve the messages nearest the cursor
            // and expose the omitted side through the existing pagination flags.
            let sizing_envelope = AgentControlEnvelope::new(Some("0".repeat(64)), response.clone());
            if serde_json::to_vec(&sizing_envelope)?.len() < MAX_AGENT_CONTROL_FRAME_BYTES
                || messages.len() <= 1
            {
                return Ok(response);
            }
            if after.is_some() {
                messages.pop();
                has_more_after = true;
            } else {
                messages.remove(0);
                has_more_before = true;
            }
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
}
