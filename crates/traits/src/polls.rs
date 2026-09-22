//! Bounded Marmot profile of NIP-88 polls carried inside MLS app messages.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::app_event::{EVENT_REF_TAG, MarmotAppEvent};

pub const MARMOT_APP_EVENT_KIND_POLL_RESPONSE: u64 = 1018;
pub const MARMOT_APP_EVENT_KIND_POLL: u64 = 1068;
pub const POLL_OPTION_TAG: &str = "option";
pub const POLL_TYPE_TAG: &str = "polltype";
pub const POLL_ENDS_AT_TAG: &str = "endsAt";
pub const POLL_RESPONSE_TAG: &str = "response";
pub const POLL_MIN_OPTIONS: usize = 2;
pub const POLL_MAX_OPTIONS: usize = 10;
pub const POLL_MAX_QUESTION_BYTES: usize = 1_024;
pub const POLL_MAX_OPTION_BYTES: usize = 256;
pub const POLL_MAX_OPTION_ID_BYTES: usize = 64;
pub const POLL_MAX_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Bound total receive-side work while leaving room for NIP-88 relay hints and
/// future extension tags that this profile deliberately ignores.
pub const POLL_MAX_TAGS: usize = 32;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PollType {
    #[default]
    SingleChoice,
    MultipleChoice,
}

impl PollType {
    pub fn as_nip88(self) -> &'static str {
        match self {
            Self::SingleChoice => "singlechoice",
            Self::MultipleChoice => "multiplechoice",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollOptionDefinition {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollDefinition {
    pub question: String,
    pub options: Vec<PollOptionDefinition>,
    pub poll_type: PollType,
    pub ends_at: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollOptionResult {
    pub id: String,
    pub label: String,
    pub votes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollProjection {
    pub question: String,
    pub options: Vec<PollOptionResult>,
    pub poll_type: PollType,
    pub participants: u64,
    pub local_selection: Vec<String>,
    pub creator: String,
    pub ends_at: Option<u64>,
    pub open: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PollError {
    #[error("poll question is empty or exceeds the byte limit")]
    InvalidQuestion,
    #[error("poll must contain between {POLL_MIN_OPTIONS} and {POLL_MAX_OPTIONS} options")]
    InvalidOptionCount,
    #[error("poll option id is empty, duplicated, or malformed")]
    InvalidOptionId,
    #[error("poll option label is empty or exceeds the byte limit")]
    InvalidOptionLabel,
    #[error("poll contains an unsupported tag shape")]
    InvalidTags,
    #[error("poll type is unsupported")]
    InvalidPollType,
    #[error("poll deadline is invalid or exceeds the maximum lifetime")]
    InvalidDeadline,
    #[error("poll response target must be one lowercase 32-byte hex event id")]
    InvalidTarget,
    #[error("poll response contains an invalid selection")]
    InvalidSelection,
}

pub fn poll_tags(
    created_at: u64,
    question: &str,
    labels: &[String],
    poll_type: PollType,
    ends_at: Option<u64>,
) -> Result<Vec<Vec<String>>, PollError> {
    validate_question_and_labels(question, labels)?;
    validate_deadline(created_at, ends_at)?;
    let mut tags = labels
        .iter()
        .enumerate()
        .map(|(index, label)| vec![POLL_OPTION_TAG.to_owned(), index.to_string(), label.clone()])
        .collect::<Vec<_>>();
    tags.push(vec![
        POLL_TYPE_TAG.to_owned(),
        poll_type.as_nip88().to_owned(),
    ]);
    if let Some(ends_at) = ends_at {
        tags.push(vec![POLL_ENDS_AT_TAG.to_owned(), ends_at.to_string()]);
    }
    Ok(tags)
}

pub fn poll_response_tags(
    poll_event_id: &str,
    option_ids: &[String],
) -> Result<Vec<Vec<String>>, PollError> {
    validate_event_id(poll_event_id)?;
    validate_selection_shape(option_ids, POLL_MAX_OPTIONS)?;
    let mut tags = Vec::with_capacity(option_ids.len() + 1);
    tags.push(vec![EVENT_REF_TAG.to_owned(), poll_event_id.to_owned()]);
    tags.extend(
        option_ids
            .iter()
            .map(|id| vec![POLL_RESPONSE_TAG.to_owned(), id.clone()]),
    );
    Ok(tags)
}

pub fn parse_poll(event: &MarmotAppEvent) -> Result<PollDefinition, PollError> {
    if event.kind != MARMOT_APP_EVENT_KIND_POLL || event.tags.len() > POLL_MAX_TAGS {
        return Err(PollError::InvalidTags);
    }
    let mut options = Vec::new();
    let mut poll_type = None;
    let mut ends_at = None;
    for tag in &event.tags {
        match tag.first().map(String::as_str) {
            Some(POLL_OPTION_TAG) => {
                if tag.len() != 3 {
                    return Err(PollError::InvalidTags);
                }
                options.push(PollOptionDefinition {
                    id: tag[1].clone(),
                    label: tag[2].clone(),
                });
            }
            Some(POLL_TYPE_TAG) => {
                if tag.len() != 2 || poll_type.is_some() {
                    return Err(PollError::InvalidTags);
                }
                poll_type = Some(match tag[1].as_str() {
                    "singlechoice" => PollType::SingleChoice,
                    "multiplechoice" => PollType::MultipleChoice,
                    _ => return Err(PollError::InvalidPollType),
                });
            }
            Some(POLL_ENDS_AT_TAG) => {
                if tag.len() != 2 || ends_at.is_some() {
                    return Err(PollError::InvalidTags);
                }
                ends_at = Some(tag[1].parse().map_err(|_| PollError::InvalidDeadline)?);
            }
            // Marmot does not use NIP-88 relay hints for routing. Ignore them,
            // and other bounded extension tags, so newer senders degrade
            // forward-compatibly without weakening validation of known tags.
            _ => {}
        }
    }
    validate_question(&event.content)?;
    validate_options(&options)?;
    validate_deadline(event.created_at, ends_at)?;
    Ok(PollDefinition {
        question: event.content.clone(),
        options,
        poll_type: poll_type.unwrap_or_default(),
        ends_at,
    })
}

pub fn parse_poll_response(event: &MarmotAppEvent) -> Result<(String, Vec<String>), PollError> {
    if event.kind != MARMOT_APP_EVENT_KIND_POLL_RESPONSE
        || !event.content.is_empty()
        || event.tags.len() > POLL_MAX_TAGS
    {
        return Err(PollError::InvalidTags);
    }
    let mut target = None;
    let mut selections = Vec::new();
    for tag in &event.tags {
        match tag.first().map(String::as_str) {
            Some(EVENT_REF_TAG) => {
                if tag.len() != 2 || target.is_some() {
                    return Err(PollError::InvalidTags);
                }
                validate_event_id(&tag[1])?;
                target = Some(tag[1].clone());
            }
            Some(POLL_RESPONSE_TAG) => {
                if tag.len() != 2 {
                    return Err(PollError::InvalidTags);
                }
                selections.push(tag[1].clone());
            }
            _ => {}
        }
    }
    let target = target.ok_or(PollError::InvalidTarget)?;
    validate_selection_shape(&selections, POLL_MAX_OPTIONS)?;
    Ok((target, selections))
}

pub fn validate_poll_response(
    poll: &PollDefinition,
    poll_created_at: u64,
    response_created_at: u64,
    selections: &[String],
) -> Result<(), PollError> {
    if response_created_at < poll_created_at
        || poll
            .ends_at
            .is_some_and(|deadline| response_created_at > deadline)
    {
        return Err(PollError::InvalidDeadline);
    }
    let option_ids = poll
        .options
        .iter()
        .map(|option| option.id.clone())
        .collect::<Vec<_>>();
    validate_poll_selection(poll.poll_type, &option_ids, selections)
}

pub fn validate_poll_selection(
    poll_type: PollType,
    option_ids: &[String],
    selections: &[String],
) -> Result<(), PollError> {
    validate_selection_shape(selections, option_ids.len())?;
    if poll_type == PollType::SingleChoice && selections.len() != 1 {
        return Err(PollError::InvalidSelection);
    }
    let option_ids = option_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    if selections
        .iter()
        .any(|id| !option_ids.contains(id.as_str()))
    {
        return Err(PollError::InvalidSelection);
    }
    Ok(())
}

fn validate_question_and_labels(question: &str, labels: &[String]) -> Result<(), PollError> {
    validate_question(question)?;
    let options = labels
        .iter()
        .enumerate()
        .map(|(index, label)| PollOptionDefinition {
            id: index.to_string(),
            label: label.clone(),
        })
        .collect::<Vec<_>>();
    validate_options(&options)
}

fn validate_question(question: &str) -> Result<(), PollError> {
    validate_display_text(question, POLL_MAX_QUESTION_BYTES).map_err(|_| PollError::InvalidQuestion)
}

fn validate_options(options: &[PollOptionDefinition]) -> Result<(), PollError> {
    if !(POLL_MIN_OPTIONS..=POLL_MAX_OPTIONS).contains(&options.len()) {
        return Err(PollError::InvalidOptionCount);
    }
    let mut ids = HashSet::new();
    for option in options {
        if option.id.is_empty()
            || option.id.len() > POLL_MAX_OPTION_ID_BYTES
            || !option.id.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !ids.insert(option.id.as_str())
        {
            return Err(PollError::InvalidOptionId);
        }
        validate_display_text(&option.label, POLL_MAX_OPTION_BYTES)
            .map_err(|_| PollError::InvalidOptionLabel)?;
    }
    Ok(())
}

fn validate_display_text(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > max_bytes
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
                )
        })
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_deadline(created_at: u64, ends_at: Option<u64>) -> Result<(), PollError> {
    if let Some(ends_at) = ends_at {
        let lifetime = ends_at
            .checked_sub(created_at)
            .ok_or(PollError::InvalidDeadline)?;
        if lifetime == 0 || lifetime > POLL_MAX_LIFETIME_SECONDS {
            return Err(PollError::InvalidDeadline);
        }
    }
    Ok(())
}

fn validate_selection_shape(ids: &[String], max: usize) -> Result<(), PollError> {
    if ids.is_empty() || ids.len() > max {
        return Err(PollError::InvalidSelection);
    }
    let mut unique = HashSet::new();
    if ids.iter().any(|id| {
        id.is_empty()
            || id.len() > POLL_MAX_OPTION_ID_BYTES
            || !id.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !unique.insert(id.as_str())
    }) {
        return Err(PollError::InvalidSelection);
    }
    Ok(())
}

fn validate_event_id(value: &str) -> Result<(), PollError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(PollError::InvalidTarget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: u64, created_at: u64, tags: Vec<Vec<String>>, content: &str) -> MarmotAppEvent {
        MarmotAppEvent::new("11".repeat(32), created_at, kind, tags, content)
    }

    #[test]
    fn poll_round_trip_and_bounds() {
        let labels = vec!["Tea".to_owned(), "Coffee".to_owned()];
        let poll = event(
            MARMOT_APP_EVENT_KIND_POLL,
            100,
            poll_tags(100, "Drink?", &labels, PollType::SingleChoice, Some(200)).unwrap(),
            "Drink?",
        );
        let parsed = parse_poll(&poll).unwrap();
        assert_eq!(parsed.options[1].id, "1");
        assert_eq!(parsed.ends_at, Some(200));
        assert!(poll_tags(100, "Drink?", &labels, PollType::SingleChoice, Some(100)).is_err());
    }

    #[test]
    fn ignores_bounded_extension_tags_but_keeps_known_tags_strict() {
        let mut tags = poll_tags(
            100,
            "Drink?",
            &["Tea".to_owned(), "Coffee".to_owned()],
            PollType::MultipleChoice,
            None,
        )
        .unwrap();
        tags.push(vec!["relay".to_owned(), "wss://example.test".to_owned()]);
        tags.push(vec!["future-extension".to_owned(), "value".to_owned()]);
        assert!(parse_poll(&event(MARMOT_APP_EVENT_KIND_POLL, 100, tags, "Drink?")).is_ok());

        let malformed_known = vec![
            vec![POLL_OPTION_TAG.into(), "0".into()],
            vec![POLL_OPTION_TAG.into(), "1".into(), "Coffee".into()],
        ];
        assert_eq!(
            parse_poll(&event(
                MARMOT_APP_EVENT_KIND_POLL,
                100,
                malformed_known,
                "Drink?"
            )),
            Err(PollError::InvalidTags)
        );
    }

    #[test]
    fn send_side_rejects_duplicate_choices_and_bidi_text() {
        assert!(
            poll_tags(
                100,
                "Drink?",
                &["Tea".into(), "\u{202e}Coffee".into()],
                PollType::SingleChoice,
                None,
            )
            .is_err()
        );
        assert!(poll_response_tags(&"22".repeat(32), &["0".into(), "0".into()]).is_err());
    }

    #[test]
    fn response_parser_ignores_bounded_extension_tags() {
        let poll_id = "22".repeat(32);
        let response = event(
            MARMOT_APP_EVENT_KIND_POLL_RESPONSE,
            150,
            vec![
                vec![EVENT_REF_TAG.into(), poll_id.clone()],
                vec!["p".into(), "33".repeat(32)],
                vec![POLL_RESPONSE_TAG.into(), "0".into()],
            ],
            "",
        );
        assert_eq!(
            parse_poll_response(&response),
            Ok((poll_id, vec!["0".into()]))
        );
    }

    #[test]
    fn validates_single_and_multiple_responses() {
        let poll = PollDefinition {
            question: "Drink?".into(),
            options: vec![
                PollOptionDefinition {
                    id: "0".into(),
                    label: "Tea".into(),
                },
                PollOptionDefinition {
                    id: "1".into(),
                    label: "Coffee".into(),
                },
            ],
            poll_type: PollType::SingleChoice,
            ends_at: Some(200),
        };
        assert!(validate_poll_response(&poll, 100, 150, &["0".into()]).is_ok());
        assert!(validate_poll_response(&poll, 100, 150, &["0".into(), "1".into()]).is_err());
        assert!(validate_poll_response(&poll, 100, 201, &["0".into()]).is_err());
    }
}
