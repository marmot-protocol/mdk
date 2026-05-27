use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION, QUOTE_REF_TAG, STREAM_CHUNKS_TAG,
    STREAM_HASH_TAG, STREAM_START_TAG, STREAM_TAG,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_TIMELINE_LIMIT: usize = 50;
const MAX_TIMELINE_LIMIT: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAppEvent {
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub source_message_id_hex: Option<String>,
    pub direction: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub recorded_at: u64,
    pub received_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelinePagination {
    pub before: Option<u64>,
    pub before_message_id: Option<String>,
    pub after: Option<u64>,
    pub after_message_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelineMessageQuery {
    pub group_id_hex: Option<String>,
    pub search: Option<String>,
    pub pagination: TimelinePagination,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineMessageRecord {
    pub message_id_hex: String,
    pub source_message_id_hex: Option<String>,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub timeline_at: u64,
    pub received_at: u64,
    pub reply_to_message_id_hex: Option<String>,
    pub media: Option<Value>,
    pub agent_text_stream: Option<Value>,
    pub reactions: TimelineReactionSummary,
    pub deleted: bool,
    pub deleted_by_message_id_hex: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineReactionSummary {
    pub by_emoji: BTreeMap<String, Vec<String>>,
    pub user_reactions: Vec<TimelineUserReaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineUserReaction {
    pub reaction_message_id_hex: String,
    pub target_message_id_hex: String,
    pub sender: String,
    pub emoji: String,
    pub reacted_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelinePage {
    pub messages: Vec<TimelineMessageRecord>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

#[derive(Clone, Debug)]
struct RawAppEvent {
    group_id_hex: String,
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    direction: String,
    sender: String,
    plaintext: String,
    kind: u64,
    tags: Vec<Vec<String>>,
    recorded_at: u64,
    received_at: u64,
}

#[derive(Clone, Debug)]
struct TimelineRow {
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    direction: String,
    group_id_hex: String,
    sender: String,
    plaintext: String,
    kind: u64,
    tags: Vec<Vec<String>>,
    timeline_at: u64,
    received_at: u64,
    reply_to_message_id_hex: Option<String>,
    media: Option<Value>,
    agent_text_stream: Option<Value>,
    reactions: TimelineReactionSummary,
    deleted: bool,
    deleted_by_message_id_hex: Option<String>,
}

#[derive(Clone, Debug)]
struct StreamStartRow {
    group_id_hex: String,
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    sender: String,
    stream_id_hex: String,
    tags: Vec<Vec<String>>,
    started_at: u64,
    received_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CursorDirection {
    None,
    Before,
    After,
}

#[derive(Clone, Debug)]
struct ValidatedPagination {
    direction: CursorDirection,
    cursor_at: Option<u64>,
    cursor_message_id_hex: Option<String>,
    limit: usize,
}

impl SqliteAccountStorage {
    pub fn record_app_event(&self, event: &StoredAppEvent) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        tx.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                plaintext, kind, tags_json, recorded_at, received_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(group_id_hex, message_id_hex) DO UPDATE SET
                source_message_id_hex = excluded.source_message_id_hex,
                direction = excluded.direction,
                sender = excluded.sender,
                plaintext = excluded.plaintext,
                kind = excluded.kind,
                tags_json = excluded.tags_json,
                recorded_at = excluded.recorded_at,
                received_at = excluded.received_at,
                invalidated = 0,
                invalidation_reason = NULL",
            params![
                &event.group_id_hex,
                &event.message_id_hex,
                &event.source_message_id_hex,
                &event.direction,
                &event.sender,
                &event.plaintext,
                u64_to_i64(event.kind)?,
                tags_json(&event.tags)?,
                u64_to_i64(event.recorded_at)?,
                u64_to_i64(event.received_at)?,
            ],
        )
        .storage()?;
        rebuild_message_timeline_for_group_tx(&tx, &event.group_id_hex)?;
        tx.commit().storage()
    }

    pub fn invalidate_app_event_by_source(
        &self,
        source_message_id_hex: &str,
        reason: &str,
    ) -> StorageResult<bool> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let group_id_hex: Option<String> = tx
            .query_row(
                "SELECT group_id_hex FROM app_events WHERE source_message_id_hex = ?1",
                params![source_message_id_hex],
                |row| row.get(0),
            )
            .optional()
            .storage()?;
        let Some(group_id_hex) = group_id_hex else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE app_events
             SET invalidated = 1, invalidation_reason = ?2
             WHERE source_message_id_hex = ?1",
            params![source_message_id_hex, reason],
        )
        .storage()?;
        rebuild_message_timeline_for_group_tx(&tx, &group_id_hex)?;
        tx.commit().storage()?;
        Ok(true)
    }

    pub fn rebuild_message_timeline_for_group(&self, group_id_hex: &str) -> StorageResult<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        rebuild_message_timeline_for_group_tx(&tx, group_id_hex)?;
        tx.commit().storage()
    }

    pub fn message_timeline(&self, query: TimelineMessageQuery) -> StorageResult<TimelinePage> {
        let pagination = validate_pagination(&query.pagination)?;
        let (sql, params) = timeline_query_sql(&query, &pagination)?;
        let conn = self.lock()?;
        let mut stmt = conn.prepare(&sql).storage()?;
        let rows = stmt
            .query_map(
                rusqlite::params_from_iter(params.iter()),
                timeline_record_from_row,
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let has_extra = rows.len() > pagination.limit;
        let mut messages = rows.into_iter().take(pagination.limit).collect::<Vec<_>>();
        let (has_more_before, has_more_after) = match pagination.direction {
            CursorDirection::None => {
                messages.reverse();
                (has_extra, false)
            }
            CursorDirection::Before => {
                messages.reverse();
                (has_extra, true)
            }
            CursorDirection::After => (true, has_extra),
        };
        Ok(TimelinePage {
            messages,
            has_more_before,
            has_more_after,
        })
    }
}

pub(crate) fn rebuild_message_timeline_for_group_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<()> {
    let events = app_events_for_rebuild_tx(tx, group_id_hex)?;
    let (rows, stream_starts) = project_group_events(events);
    tx.execute(
        "DELETE FROM message_timeline WHERE group_id_hex = ?1",
        params![group_id_hex],
    )
    .storage()?;
    tx.execute(
        "DELETE FROM agent_stream_starts WHERE group_id_hex = ?1",
        params![group_id_hex],
    )
    .storage()?;
    for row in rows {
        tx.execute(
            "INSERT INTO message_timeline (
                group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                plaintext, kind, tags_json, timeline_at, received_at,
                reply_to_message_id_hex, media_json, agent_stream_json, reactions_json,
                deleted, deleted_by_message_id_hex
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                &row.group_id_hex,
                &row.message_id_hex,
                &row.source_message_id_hex,
                &row.direction,
                &row.sender,
                &row.plaintext,
                u64_to_i64(row.kind)?,
                tags_json(&row.tags)?,
                u64_to_i64(row.timeline_at)?,
                u64_to_i64(row.received_at)?,
                &row.reply_to_message_id_hex,
                optional_value_json(&row.media)?,
                optional_value_json(&row.agent_text_stream)?,
                reaction_summary_json(&row.reactions)?,
                if row.deleted { 1_i64 } else { 0_i64 },
                &row.deleted_by_message_id_hex,
            ],
        )
        .storage()?;
    }
    for start in stream_starts {
        tx.execute(
            "INSERT INTO agent_stream_starts (
                group_id_hex, message_id_hex, source_message_id_hex, sender, stream_id_hex,
                tags_json, started_at, received_at
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &start.group_id_hex,
                &start.message_id_hex,
                &start.source_message_id_hex,
                &start.sender,
                &start.stream_id_hex,
                tags_json(&start.tags)?,
                u64_to_i64(start.started_at)?,
                u64_to_i64(start.received_at)?,
            ],
        )
        .storage()?;
    }
    Ok(())
}

fn app_events_for_rebuild_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Vec<RawAppEvent>> {
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, source_message_id_hex, direction, sender,
                    plaintext, kind, tags_json, recorded_at, received_at
             FROM app_events
             WHERE group_id_hex = ?1
               AND invalidated = 0
             ORDER BY recorded_at, message_id_hex, insert_order",
        )
        .storage()?;
    stmt.query_map(params![group_id_hex], raw_event_from_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn validate_pagination(pagination: &TimelinePagination) -> StorageResult<ValidatedPagination> {
    if pagination.before.is_some() != pagination.before_message_id.is_some() {
        return Err(StorageError::Backend(
            "timeline pagination requires before and before_message_id together".to_owned(),
        ));
    }
    if pagination.after.is_some() != pagination.after_message_id.is_some() {
        return Err(StorageError::Backend(
            "timeline pagination requires after and after_message_id together".to_owned(),
        ));
    }
    if pagination.before.is_some() && pagination.after.is_some() {
        return Err(StorageError::Backend(
            "timeline pagination cannot use before and after cursors together".to_owned(),
        ));
    }
    let limit = pagination
        .limit
        .unwrap_or(DEFAULT_TIMELINE_LIMIT)
        .min(MAX_TIMELINE_LIMIT);
    let direction = if pagination.before.is_some() {
        CursorDirection::Before
    } else if pagination.after.is_some() {
        CursorDirection::After
    } else {
        CursorDirection::None
    };
    let (cursor_at, cursor_message_id_hex) = match direction {
        CursorDirection::Before => (pagination.before, pagination.before_message_id.clone()),
        CursorDirection::After => (pagination.after, pagination.after_message_id.clone()),
        CursorDirection::None => (None, None),
    };
    Ok(ValidatedPagination {
        direction,
        cursor_at,
        cursor_message_id_hex,
        limit,
    })
}

fn timeline_query_sql(
    query: &TimelineMessageQuery,
    pagination: &ValidatedPagination,
) -> StorageResult<(String, Vec<rusqlite::types::Value>)> {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    if let Some(group_id_hex) = &query.group_id_hex {
        clauses.push("group_id_hex = ?".to_owned());
        params.push(rusqlite::types::Value::Text(group_id_hex.clone()));
    }
    if let Some(search) = query
        .search
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        clauses.push("plaintext LIKE ? COLLATE NOCASE".to_owned());
        params.push(rusqlite::types::Value::Text(format!("%{search}%")));
    }
    match pagination.direction {
        CursorDirection::Before => {
            clauses
                .push("(timeline_at < ? OR (timeline_at = ? AND message_id_hex < ?))".to_owned());
            let cursor_at = u64_to_i64(pagination.cursor_at.unwrap_or_default())?;
            params.push(rusqlite::types::Value::Integer(cursor_at));
            params.push(rusqlite::types::Value::Integer(cursor_at));
            params.push(rusqlite::types::Value::Text(
                pagination.cursor_message_id_hex.clone().unwrap_or_default(),
            ));
        }
        CursorDirection::After => {
            clauses
                .push("(timeline_at > ? OR (timeline_at = ? AND message_id_hex > ?))".to_owned());
            let cursor_at = u64_to_i64(pagination.cursor_at.unwrap_or_default())?;
            params.push(rusqlite::types::Value::Integer(cursor_at));
            params.push(rusqlite::types::Value::Integer(cursor_at));
            params.push(rusqlite::types::Value::Text(
                pagination.cursor_message_id_hex.clone().unwrap_or_default(),
            ));
        }
        CursorDirection::None => {}
    }
    params.push(rusqlite::types::Value::Integer(
        i64::try_from(pagination.limit + 1).unwrap_or(i64::MAX),
    ));
    let where_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    };
    let order_sql = match pagination.direction {
        CursorDirection::After => "ORDER BY timeline_at ASC, message_id_hex ASC",
        CursorDirection::None | CursorDirection::Before => {
            "ORDER BY timeline_at DESC, message_id_hex DESC"
        }
    };
    Ok((
        format!(
            "SELECT message_id_hex, source_message_id_hex, direction, group_id_hex, sender,
                    plaintext, kind, tags_json, timeline_at, received_at,
                    reply_to_message_id_hex, media_json, agent_stream_json, reactions_json,
                    deleted, deleted_by_message_id_hex
             FROM message_timeline
             {where_sql}
             {order_sql}
             LIMIT ?"
        ),
        params,
    ))
}

fn project_group_events(events: Vec<RawAppEvent>) -> (Vec<TimelineRow>, Vec<StreamStartRow>) {
    let mut timeline = BTreeMap::<String, TimelineRow>::new();
    let mut stream_starts = Vec::new();
    let mut reactions = Vec::new();
    let mut deletes = Vec::new();

    for event in &events {
        match event.kind {
            MARMOT_APP_EVENT_KIND_CHAT => {
                timeline.insert(event.message_id_hex.clone(), timeline_row_from_chat(event));
            }
            MARMOT_APP_EVENT_KIND_AGENT_STREAM_START => {
                if let Some(stream_id_hex) = tag_value(&event.tags, STREAM_TAG) {
                    stream_starts.push(StreamStartRow {
                        group_id_hex: event.group_id_hex.clone(),
                        message_id_hex: event.message_id_hex.clone(),
                        source_message_id_hex: event.source_message_id_hex.clone(),
                        sender: event.sender.clone(),
                        stream_id_hex: stream_id_hex.to_owned(),
                        tags: event.tags.clone(),
                        started_at: event.recorded_at,
                        received_at: event.received_at,
                    });
                }
            }
            MARMOT_APP_EVENT_KIND_REACTION => reactions.push(event.clone()),
            MARMOT_APP_EVENT_KIND_DELETE => deletes.push(event.clone()),
            _ => {}
        }
    }

    let events_by_id = events
        .iter()
        .map(|event| (event.message_id_hex.clone(), event))
        .collect::<HashMap<_, _>>();
    let mut deleted_reaction_ids = HashSet::new();
    for delete in &deletes {
        for target in tag_values(&delete.tags, EVENT_REF_TAG) {
            if let Some(target_event) = events_by_id.get(target)
                && target_event.kind == MARMOT_APP_EVENT_KIND_REACTION
                && target_event.sender == delete.sender
            {
                deleted_reaction_ids.insert((*target).to_owned());
            }
        }
    }

    for reaction in reactions {
        if deleted_reaction_ids.contains(&reaction.message_id_hex) {
            continue;
        }
        let Some(target) = tag_value(&reaction.tags, EVENT_REF_TAG) else {
            continue;
        };
        let Some(row) = timeline.get_mut(target) else {
            continue;
        };
        let reaction_record = TimelineUserReaction {
            reaction_message_id_hex: reaction.message_id_hex.clone(),
            target_message_id_hex: target.to_owned(),
            sender: reaction.sender.clone(),
            emoji: reaction.plaintext.clone(),
            reacted_at: reaction.recorded_at,
        };
        row.reactions.user_reactions.push(reaction_record);
    }
    for row in timeline.values_mut() {
        row.reactions.user_reactions.sort_by(|a, b| {
            a.reacted_at
                .cmp(&b.reacted_at)
                .then_with(|| a.reaction_message_id_hex.cmp(&b.reaction_message_id_hex))
        });
        let mut by_emoji = BTreeMap::<String, BTreeSet<String>>::new();
        for reaction in &row.reactions.user_reactions {
            by_emoji
                .entry(reaction.emoji.clone())
                .or_default()
                .insert(reaction.sender.clone());
        }
        row.reactions.by_emoji = by_emoji
            .into_iter()
            .map(|(emoji, senders)| (emoji, senders.into_iter().collect()))
            .collect();
    }

    for delete in deletes {
        for target in tag_values(&delete.tags, EVENT_REF_TAG) {
            let Some(row) = timeline.get_mut(target) else {
                continue;
            };
            if row.sender != delete.sender {
                continue;
            }
            row.deleted = true;
            row.deleted_by_message_id_hex = Some(delete.message_id_hex.clone());
            row.plaintext.clear();
            row.media = None;
            row.agent_text_stream = None;
            row.reactions = TimelineReactionSummary::default();
        }
    }

    let mut rows = timeline.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.timeline_at
            .cmp(&b.timeline_at)
            .then_with(|| a.message_id_hex.cmp(&b.message_id_hex))
    });
    stream_starts.sort_by(|a, b| {
        a.started_at
            .cmp(&b.started_at)
            .then_with(|| a.message_id_hex.cmp(&b.message_id_hex))
    });
    (rows, stream_starts)
}

fn timeline_row_from_chat(event: &RawAppEvent) -> TimelineRow {
    TimelineRow {
        message_id_hex: event.message_id_hex.clone(),
        source_message_id_hex: event.source_message_id_hex.clone(),
        direction: event.direction.clone(),
        group_id_hex: event.group_id_hex.clone(),
        sender: event.sender.clone(),
        plaintext: event.plaintext.clone(),
        kind: event.kind,
        tags: event.tags.clone(),
        timeline_at: event.recorded_at,
        received_at: event.received_at,
        reply_to_message_id_hex: tag_value(&event.tags, QUOTE_REF_TAG)
            .or_else(|| tag_value(&event.tags, EVENT_REF_TAG))
            .map(ToOwned::to_owned),
        media: media_metadata(&event.tags),
        agent_text_stream: agent_stream_final_metadata(&event.tags),
        reactions: TimelineReactionSummary::default(),
        deleted: false,
        deleted_by_message_id_hex: None,
    }
}

fn media_metadata(tags: &[Vec<String>]) -> Option<Value> {
    let imeta = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
        .cloned()
        .collect::<Vec<_>>();
    (!imeta.is_empty()).then(|| json!({ "imeta": imeta }))
}

fn agent_stream_final_metadata(tags: &[Vec<String>]) -> Option<Value> {
    let stream_id_hex = tag_value(tags, STREAM_TAG)?;
    let mut value = json!({ "stream_id_hex": stream_id_hex });
    if let Some(start) = tag_value(tags, STREAM_START_TAG) {
        value["start_event_id"] = Value::String(start.to_owned());
    }
    if let Some(hash) = tag_value(tags, STREAM_HASH_TAG) {
        value["transcript_hash"] = Value::String(hash.to_owned());
    }
    if let Some(chunks) = tag_value(tags, STREAM_CHUNKS_TAG) {
        value["chunk_count"] = Value::String(chunks.to_owned());
    }
    Some(value)
}

fn tag_value<'a>(tags: &'a [Vec<String>], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .and_then(|tag| tag.get(1))
        .map(String::as_str)
}

fn tag_values<'a>(tags: &'a [Vec<String>], name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    tags.iter()
        .filter(move |tag| tag.first().is_some_and(|tag_name| tag_name == name))
        .filter_map(|tag| tag.get(1).map(String::as_str))
}

fn raw_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAppEvent> {
    Ok(RawAppEvent {
        group_id_hex: row.get(0)?,
        message_id_hex: row.get(1)?,
        source_message_id_hex: row.get(2)?,
        direction: row.get(3)?,
        sender: row.get(4)?,
        plaintext: row.get(5)?,
        kind: row.get::<_, i64>(6)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(7)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(err))
        })?,
        recorded_at: row.get::<_, i64>(8)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(9)?.try_into().unwrap_or_default(),
    })
}

fn timeline_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineMessageRecord> {
    Ok(TimelineMessageRecord {
        message_id_hex: row.get(0)?,
        source_message_id_hex: row.get(1)?,
        direction: row.get(2)?,
        group_id_hex: row.get(3)?,
        sender: row.get(4)?,
        plaintext: row.get(5)?,
        kind: row.get::<_, i64>(6)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(7)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(7, rusqlite::types::Type::Text, Box::new(err))
        })?,
        timeline_at: row.get::<_, i64>(8)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(9)?.try_into().unwrap_or_default(),
        reply_to_message_id_hex: row.get(10)?,
        media: optional_value_from_json(row.get::<_, Option<String>>(11)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                11,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?,
        agent_text_stream: optional_value_from_json(row.get::<_, Option<String>>(12)?).map_err(
            |err| {
                rusqlite::Error::FromSqlConversionFailure(
                    12,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            },
        )?,
        reactions: reaction_summary_from_json(row.get::<_, String>(13)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                13,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?,
        deleted: row.get::<_, i64>(14)? != 0,
        deleted_by_message_id_hex: row.get(15)?,
    })
}

fn tags_json(tags: &[Vec<String>]) -> StorageResult<String> {
    serde_json::to_string(tags).map_err(|err| StorageError::Serialization(err.to_string()))
}

fn tags_from_json(json: String) -> Result<Vec<Vec<String>>, serde_json::Error> {
    serde_json::from_str(&json)
}

fn optional_value_json(value: &Option<Value>) -> StorageResult<Option<String>> {
    value
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|err| StorageError::Serialization(err.to_string()))
}

fn optional_value_from_json(value: Option<String>) -> Result<Option<Value>, serde_json::Error> {
    value.map(|value| serde_json::from_str(&value)).transpose()
}

fn reaction_summary_json(summary: &TimelineReactionSummary) -> StorageResult<String> {
    serde_json::to_string(summary).map_err(|err| StorageError::Serialization(err.to_string()))
}

fn reaction_summary_from_json(json: String) -> Result<TimelineReactionSummary, serde_json::Error> {
    serde_json::from_str(&json)
}

fn u64_to_i64(value: u64) -> StorageResult<i64> {
    i64::try_from(value).map_err(|_| {
        StorageError::Serialization(format!("value does not fit in sqlite INTEGER: {value}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chat(id: &str, sender: &str, at: u64, plaintext: &str) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            direction: "received".to_owned(),
            sender: sender.to_owned(),
            plaintext: plaintext.to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            recorded_at: at,
            received_at: at,
        }
    }

    fn reaction(id: &str, sender: &str, target: &str, at: u64, emoji: &str) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            direction: "received".to_owned(),
            sender: sender.to_owned(),
            plaintext: emoji.to_owned(),
            kind: MARMOT_APP_EVENT_KIND_REACTION,
            tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
            recorded_at: at,
            received_at: at,
        }
    }

    fn delete(id: &str, sender: &str, target: &str, at: u64) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: id.to_owned(),
            source_message_id_hex: Some(format!("source-{id}")),
            direction: "received".to_owned(),
            sender: sender.to_owned(),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_DELETE,
            tags: vec![vec![EVENT_REF_TAG.to_owned(), target.to_owned()]],
            recorded_at: at,
            received_at: at,
        }
    }

    fn list(store: &SqliteAccountStorage) -> Vec<TimelineMessageRecord> {
        store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some("11".repeat(32)),
                ..TimelineMessageQuery::default()
            })
            .unwrap()
            .messages
    }

    #[test]
    fn pagination_rejects_half_and_double_cursors() {
        let store = SqliteAccountStorage::in_memory().unwrap();

        assert!(
            store
                .message_timeline(TimelineMessageQuery {
                    pagination: TimelinePagination {
                        before: Some(1),
                        ..TimelinePagination::default()
                    },
                    ..TimelineMessageQuery::default()
                })
                .is_err()
        );
        assert!(
            store
                .message_timeline(TimelineMessageQuery {
                    pagination: TimelinePagination {
                        before: Some(1),
                        before_message_id: Some("a".to_owned()),
                        after: Some(2),
                        after_message_id: Some("b".to_owned()),
                        limit: None,
                    },
                    ..TimelineMessageQuery::default()
                })
                .is_err()
        );
    }

    #[test]
    fn timeline_orders_tied_timestamps_by_message_id() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&chat("bb", "alice", 5, "second"))
            .unwrap();
        store
            .record_app_event(&chat("aa", "alice", 5, "first"))
            .unwrap();

        let messages = list(&store);

        assert_eq!(
            messages
                .iter()
                .map(|message| message.message_id_hex.as_str())
                .collect::<Vec<_>>(),
            vec!["aa", "bb"]
        );
    }

    #[test]
    fn orphan_reaction_applies_when_target_arrives() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&reaction("reaction-1", "bob", "target", 1, "+"))
            .unwrap();
        store
            .record_app_event(&chat("target", "alice", 2, "hello"))
            .unwrap();

        let message = list(&store).pop().unwrap();

        assert_eq!(
            message.reactions.by_emoji.get("+").cloned(),
            Some(vec!["bob".to_owned()])
        );
    }

    #[test]
    fn delete_requires_target_author_and_keeps_tombstone() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&delete("bad-delete", "mallory", "target", 1))
            .unwrap();
        store
            .record_app_event(&delete("good-delete", "alice", "target", 2))
            .unwrap();
        store
            .record_app_event(&chat("target", "alice", 3, "secret"))
            .unwrap();

        let message = list(&store).pop().unwrap();

        assert!(message.deleted);
        assert_eq!(
            message.deleted_by_message_id_hex.as_deref(),
            Some("good-delete")
        );
        assert_eq!(message.plaintext, "");
    }

    #[test]
    fn delete_retracts_reaction_by_reaction_author() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&chat("target", "alice", 1, "hello"))
            .unwrap();
        store
            .record_app_event(&reaction("reaction-1", "bob", "target", 2, "+"))
            .unwrap();
        store
            .record_app_event(&delete("delete-reaction", "bob", "reaction-1", 3))
            .unwrap();

        let message = list(&store).pop().unwrap();

        assert!(message.reactions.user_reactions.is_empty());
        assert!(message.reactions.by_emoji.is_empty());
    }

    #[test]
    fn stream_start_is_not_visible_but_stream_final_is_materialized() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let start = StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: "start".to_owned(),
            source_message_id_hex: Some("source-start".to_owned()),
            direction: "received".to_owned(),
            sender: "agent".to_owned(),
            plaintext: String::new(),
            kind: MARMOT_APP_EVENT_KIND_AGENT_STREAM_START,
            tags: vec![vec![STREAM_TAG.to_owned(), "aa".repeat(32)]],
            recorded_at: 1,
            received_at: 1,
        };
        let final_event = StoredAppEvent {
            group_id_hex: "11".repeat(32),
            message_id_hex: "final".to_owned(),
            source_message_id_hex: Some("source-final".to_owned()),
            direction: "received".to_owned(),
            sender: "agent".to_owned(),
            plaintext: "done".to_owned(),
            kind: MARMOT_APP_EVENT_KIND_CHAT,
            tags: vec![
                vec![STREAM_TAG.to_owned(), "aa".repeat(32)],
                vec![STREAM_START_TAG.to_owned(), "start".to_owned()],
            ],
            recorded_at: 2,
            received_at: 2,
        };

        store.record_app_event(&start).unwrap();
        store.record_app_event(&final_event).unwrap();

        let messages = list(&store);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].message_id_hex, "final");
        assert!(messages[0].agent_text_stream.is_some());
    }

    #[test]
    fn timeline_search_matches_plaintext_case_insensitively() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&chat("target", "alice", 1, "Hello There"))
            .unwrap();

        let page = store
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some("11".repeat(32)),
                search: Some("hello".to_owned()),
                ..TimelineMessageQuery::default()
            })
            .unwrap();

        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].message_id_hex, "target");
    }

    #[test]
    fn source_invalidation_retracts_projected_effects() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .record_app_event(&chat("target", "alice", 1, "hello"))
            .unwrap();

        assert!(
            store
                .invalidate_app_event_by_source("source-target", "losing_branch")
                .unwrap()
        );

        assert!(list(&store).is_empty());
    }
}
