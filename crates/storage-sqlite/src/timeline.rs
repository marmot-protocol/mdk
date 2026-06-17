use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    SqliteAccountStorage, SqliteResultExt, optional_u64_to_i64, tags_from_json, u64_to_i64,
};
use cgka_traits::app_event::{
    EVENT_REF_TAG, MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY, MARMOT_APP_EVENT_KIND_AGENT_OPERATION,
    MARMOT_APP_EVENT_KIND_AGENT_STREAM_START, MARMOT_APP_EVENT_KIND_CHAT,
    MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_EDIT, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
    MARMOT_APP_EVENT_KIND_REACTION, QUOTE_REF_TAG, STREAM_CHUNKS_TAG, STREAM_HASH_TAG,
    STREAM_START_TAG, STREAM_TAG,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, Transaction, params, params_from_iter};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_TIMELINE_LIMIT: usize = 50;
/// Largest number of rows a single timeline cursor query returns. A
/// materialized window kept above this cannot be re-fetched in one query, so
/// window owners should not exceed it.
pub const MAX_TIMELINE_LIMIT: usize = 200;
const SQLITE_BIND_PARAMETER_CHUNK: usize = 900;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAppEvent {
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub source_message_id_hex: Option<String>,
    pub source_epoch: Option<u64>,
    pub direction: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub recorded_at: u64,
    pub received_at: u64,
    /// Transport id of the commit that produced this row, when it is a
    /// locally-synthesized group system row (kind 1210). Non-unique: one commit
    /// can produce many rows. Enables `invalidate_app_events_by_origin_commit`
    /// when that commit loses a fork. `None` for all other event kinds.
    pub origin_commit_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TimelinePagination {
    pub before: Option<u64>,
    pub before_message_id: Option<String>,
    /// When true (only meaningful with a `before` cursor), the cursor is an
    /// inclusive upper bound: rows equal to `(before, before_message_id)` are
    /// returned, not just rows strictly older. Used to re-materialize a
    /// scrolled-back window ending exactly at its newest row without the
    /// descending `LIMIT` spending its budget on newer same-second rows.
    pub before_inclusive: bool,
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
    pub source_epoch: Option<u64>,
    pub direction: String,
    pub group_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub timeline_at: u64,
    pub received_at: u64,
    pub reply_to_message_id_hex: Option<String>,
    pub reply_preview: Option<TimelineReplyPreview>,
    pub media: Option<Value>,
    pub agent_text_stream: Option<Value>,
    pub reactions: TimelineReactionSummary,
    pub deleted: bool,
    pub deleted_by_message_id_hex: Option<String>,
    /// Set when convergence invalidated this message (e.g. it landed on a losing
    /// branch). The message is kept in the timeline as a "did not reach the group"
    /// tombstone instead of silently disappearing. Carries the engine invalidation
    /// reason (e.g. `LosingBranch`, `BeyondAnchor`). `None` for delivered messages.
    pub invalidation_status: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineReplyPreview {
    pub message_id_hex: String,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub media: Option<Value>,
    pub agent_text_stream: Option<Value>,
    pub deleted: bool,
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

/// A single materialized-timeline row resolved by id, carrying only the fields a
/// reaction-notification preview needs. Read from `message_timeline` (the
/// user-visible truth) rather than raw `app_events`, so deleted/invalidated
/// targets are reflected and their original plaintext is never leaked into a
/// preview by callers that honor `deleted`/`invalidated`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelineMessageTarget {
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub deleted: bool,
    /// True when `invalidation_status IS NOT NULL`, i.e. convergence invalidated
    /// the message (losing branch / beyond anchor) and it is kept as a tombstone.
    pub invalidated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineProjectionUpdate {
    pub group_id_hex: String,
    pub messages: Vec<TimelineMessageRecord>,
    pub changes: Vec<TimelineMessageChange>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineMessageChange {
    Upsert {
        trigger: TimelineUpdateTrigger,
        message: Box<TimelineMessageRecord>,
    },
    Remove {
        message_id_hex: String,
        reason: TimelineRemoveReason,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineUpdateTrigger {
    NewMessage,
    MessageEditedOrReprojected,
    ReactionAdded,
    ReactionRemoved,
    MessageDeleted,
    ReplyPreviewChanged,
    AgentStreamStarted,
    AgentStreamFinished,
    AgentActivity,
    AgentOperation,
    GroupSystem,
    DeliveryOrSendStateChanged,
    ReceiptChanged,
    SnapshotRefresh,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimelineRemoveReason {
    Invalidated,
    Cleared,
    Pruned,
    NoLongerMatchesQuery,
}

#[derive(Clone, Debug)]
struct RawAppEvent {
    group_id_hex: String,
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    source_epoch: Option<u64>,
    direction: String,
    sender: String,
    plaintext: String,
    kind: u64,
    tags: Vec<Vec<String>>,
    recorded_at: u64,
    received_at: u64,
    invalidated: bool,
    invalidation_reason: Option<String>,
}

#[derive(Clone, Debug)]
struct PrunedAppEvent {
    message_id_hex: String,
    kind: u64,
    tags: Vec<Vec<String>>,
}

#[derive(Clone, Debug)]
struct TimelineRow {
    message_id_hex: String,
    source_message_id_hex: Option<String>,
    source_epoch: Option<u64>,
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
    invalidation_status: Option<String>,
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
    /// Inclusive upper bound for a `Before` cursor (see
    /// [`TimelinePagination::before_inclusive`]); ignored for other directions.
    inclusive: bool,
    limit: usize,
}

impl SqliteAccountStorage {
    pub fn record_app_event(
        &self,
        event: &StoredAppEvent,
    ) -> StorageResult<TimelineProjectionUpdate> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let affected_message_ids = affected_timeline_message_ids_tx(&tx, event)?;
        let can_incrementally_project =
            !app_event_exists_tx(&tx, &event.group_id_hex, &event.message_id_hex)?
                && can_project_record_app_event_incrementally(event.kind);
        tx.execute(
            "INSERT INTO app_events (
                group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender,
                plaintext, kind, tags_json, recorded_at, received_at, origin_commit_id
             )
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(group_id_hex, message_id_hex) DO UPDATE SET
                source_message_id_hex = excluded.source_message_id_hex,
                source_epoch = excluded.source_epoch,
                direction = excluded.direction,
                sender = excluded.sender,
                plaintext = excluded.plaintext,
                kind = excluded.kind,
                tags_json = excluded.tags_json,
                recorded_at = excluded.recorded_at,
                received_at = excluded.received_at,
                origin_commit_id = COALESCE(excluded.origin_commit_id, app_events.origin_commit_id),
                invalidated = 0,
                invalidation_reason = NULL",
            params![
                &event.group_id_hex,
                &event.message_id_hex,
                &event.source_message_id_hex,
                optional_u64_to_i64(event.source_epoch)?,
                &event.direction,
                &event.sender,
                &event.plaintext,
                u64_to_i64(event.kind)?,
                tags_json(&event.tags)?,
                u64_to_i64(event.recorded_at)?,
                u64_to_i64(event.received_at)?,
                &event.origin_commit_id,
            ],
        )
        .storage()?;
        if can_incrementally_project {
            upsert_message_timeline_projection_for_message_tx(
                &tx,
                &event.group_id_hex,
                &event.message_id_hex,
            )?;
        } else {
            rebuild_message_timeline_for_group_tx(&tx, &event.group_id_hex)?;
        }
        let messages =
            timeline_records_by_ids_tx(&tx, &event.group_id_hex, affected_message_ids.clone())?;
        let changes =
            timeline_changes_for_event(&event.message_id_hex, event.kind, &event.tags, &messages);
        tx.commit().storage().map(|()| TimelineProjectionUpdate {
            group_id_hex: event.group_id_hex.clone(),
            messages,
            changes,
        })
    }

    pub fn invalidate_app_event_by_source(
        &self,
        source_message_id_hex: &str,
        reason: &str,
    ) -> StorageResult<Option<TimelineProjectionUpdate>> {
        self.invalidate_app_event(
            "SELECT group_id_hex, message_id_hex, kind, tags_json
             FROM app_events
             WHERE source_message_id_hex = ?1",
            "UPDATE app_events
             SET invalidated = 1, invalidation_reason = ?2
             WHERE source_message_id_hex = ?1",
            &[&source_message_id_hex],
            reason,
        )
    }

    /// Invalidate the app event addressed by `(group_id_hex, message_id_hex)`.
    ///
    /// The lookup MUST be group-scoped: inner app-event ids are NIP-01 hashes
    /// over (pubkey, created_at, kind, tags, content) with no group binding, so
    /// the same account sending identical content to two groups in the same
    /// second produces the same `message_id_hex` in both (the table's
    /// `UNIQUE(group_id_hex, message_id_hex)` constraint anticipates this). A
    /// `message_id_hex`-only predicate would invalidate — and then fail to
    /// rebuild — the unrelated group's copy. The composite predicate is also
    /// served by the uniqueness index, so the call is no longer a full scan.
    pub fn invalidate_app_event_by_message_id(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
        reason: &str,
    ) -> StorageResult<Option<TimelineProjectionUpdate>> {
        self.invalidate_app_event(
            "SELECT group_id_hex, message_id_hex, kind, tags_json
             FROM app_events
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            "UPDATE app_events
             SET invalidated = 1, invalidation_reason = ?3
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            &[&group_id_hex, &message_id_hex],
            reason,
        )
    }

    /// Invalidate every app event whose `origin_commit_id` matches the given
    /// commit. This is the **1:N** invalidation path used when fork recovery
    /// rolls a commit back: a single commit can have synthesized several
    /// kind-1210 group system rows, all of which must be invalidated together so
    /// a losing branch's rows do not persist as stale timeline history. Returns
    /// `None` when no rows reference the commit (e.g. the commit produced no
    /// system rows). Rows are kept (marked `invalidated`), matching the
    /// keep-invalidated-records storage invariant; `project_group_events`
    /// renders them as tombstones, and the emitted `TimelineMessageChange`s let
    /// live subscribers update.
    pub fn invalidate_app_events_by_origin_commit(
        &self,
        origin_commit_id: &str,
        reason: &str,
    ) -> StorageResult<Option<TimelineProjectionUpdate>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        // Fetch all rows the commit synthesized. They all share one group (a
        // commit belongs to a single group), so one rebuild + change set covers
        // them. `origin_commit_id` is non-unique by design (multi-row-per-commit).
        let rows: Vec<(String, String, u64, Vec<Vec<String>>)> = {
            let mut stmt = tx
                .prepare(
                    "SELECT group_id_hex, message_id_hex, kind, tags_json
                     FROM app_events
                     WHERE origin_commit_id = ?1",
                )
                .storage()?;
            stmt.query_map(params![origin_commit_id], |row| {
                let kind = row.get::<_, i64>(2)?.try_into().unwrap_or_default();
                let tags = tags_from_json(row.get::<_, String>(3)?).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok((row.get(0)?, row.get(1)?, kind, tags))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        let Some(group_id_hex) = rows.first().map(|(group_id_hex, ..)| group_id_hex.clone()) else {
            return Ok(None);
        };
        // Collect the set of timeline message ids affected across all matched
        // rows so we can diff before/after for the change set.
        let mut affected_message_ids = BTreeSet::new();
        for (row_group_id_hex, message_id_hex, kind, tags) in &rows {
            affected_message_ids.extend(affected_timeline_message_ids_for_parts_tx(
                &tx,
                row_group_id_hex,
                message_id_hex,
                *kind,
                tags,
            )?);
        }
        let before = timeline_records_by_ids_tx(&tx, &group_id_hex, affected_message_ids.clone())?;
        tx.execute(
            "UPDATE app_events
             SET invalidated = 1, invalidation_reason = ?2
             WHERE origin_commit_id = ?1",
            params![origin_commit_id, reason],
        )
        .storage()?;
        rebuild_message_timeline_for_group_tx(&tx, &group_id_hex)?;
        let messages =
            timeline_records_by_ids_tx(&tx, &group_id_hex, affected_message_ids.clone())?;
        // One change set covers all invalidated rows. Each invalidated row's own
        // message id anchors its change; pass each in turn and merge.
        let mut changes = Vec::new();
        for (_, message_id_hex, kind, tags) in &rows {
            changes.extend(timeline_changes_for_invalidation(
                message_id_hex,
                *kind,
                tags,
                &before,
                &messages,
            ));
        }
        dedup_timeline_changes(&mut changes);
        tx.commit().storage()?;
        Ok(Some(TimelineProjectionUpdate {
            group_id_hex,
            messages,
            changes,
        }))
    }

    /// Invalidate the single app-event row addressed by `lookup_params`.
    ///
    /// Both the SELECT and the UPDATE bind `lookup_params` positionally
    /// (`?1`, `?2`, ...); `reason` is bound as the trailing parameter, so the
    /// UPDATE's `invalidation_reason = ?N` placeholder must use the index one
    /// past the lookup params. Callers must pass a predicate that resolves to
    /// at most one row: a non-null `source_message_id_hex` is unique (partial
    /// index in 0004_app_timeline.rs), and `(group_id_hex, message_id_hex)` is
    /// unique by table constraint. `message_id_hex` alone is NOT unique — the
    /// same inner NIP-01 event id can appear in multiple groups — so the
    /// message-id path is group-scoped to avoid invalidating a different
    /// group's delivered copy and to let the lookup use the uniqueness index
    /// instead of a full table scan.
    fn invalidate_app_event(
        &self,
        select_sql: &str,
        update_sql: &str,
        lookup_params: &[&dyn rusqlite::ToSql],
        reason: &str,
    ) -> StorageResult<Option<TimelineProjectionUpdate>> {
        let mut conn = self.lock()?;
        let tx = conn.transaction().storage()?;
        let row: Option<(String, String, u64, Vec<Vec<String>>)> = tx
            .query_row(select_sql, lookup_params, |row| {
                let kind = row.get::<_, i64>(2)?.try_into().unwrap_or_default();
                let tags = tags_from_json(row.get::<_, String>(3)?).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok((row.get(0)?, row.get(1)?, kind, tags))
            })
            .optional()
            .storage()?;
        let Some((group_id_hex, message_id_hex, kind, tags)) = row else {
            return Ok(None);
        };
        let affected_message_ids = affected_timeline_message_ids_for_parts_tx(
            &tx,
            &group_id_hex,
            &message_id_hex,
            kind,
            &tags,
        )?;
        let before = timeline_records_by_ids_tx(&tx, &group_id_hex, affected_message_ids.clone())?;
        // The UPDATE shares the lookup predicate and appends `reason` last.
        let mut update_params: Vec<&dyn rusqlite::ToSql> = lookup_params.to_vec();
        update_params.push(&reason);
        tx.execute(update_sql, update_params.as_slice()).storage()?;
        rebuild_message_timeline_for_group_tx(&tx, &group_id_hex)?;
        let messages =
            timeline_records_by_ids_tx(&tx, &group_id_hex, affected_message_ids.clone())?;
        let changes =
            timeline_changes_for_invalidation(&message_id_hex, kind, &tags, &before, &messages);
        tx.commit().storage()?;
        Ok(Some(TimelineProjectionUpdate {
            group_id_hex,
            messages,
            changes,
        }))
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
        let rows = {
            let _span = tracing::debug_span!(
                target: "storage_sqlite::timeline",
                "timeline_select",
                method = "message_timeline"
            )
            .entered();
            let mut stmt = conn.prepare(&sql).storage()?;
            stmt.query_map(
                rusqlite::params_from_iter(params.iter()),
                timeline_record_from_row,
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
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
        {
            let _span = tracing::debug_span!(
                target: "storage_sqlite::timeline",
                "reply_preview_hydration",
                method = "message_timeline"
            )
            .entered();
            attach_reply_previews(&conn, &mut messages)?;
        }
        Ok(TimelinePage {
            messages,
            has_more_before,
            has_more_after,
        })
    }

    /// Resolve a single materialized-timeline row by `(group_id_hex,
    /// message_id_hex)` without scanning the timeline. Returns the small
    /// [`TimelineMessageTarget`] view (sender, plaintext, kind, deleted,
    /// invalidated) or `None` when the id is absent in that group. Used by the
    /// reaction-notification path to resolve the reacted-to message from the
    /// user-visible truth instead of raw `app_events`.
    pub fn timeline_message_target(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Option<TimelineMessageTarget>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT sender, plaintext, kind, deleted, invalidation_status
             FROM message_timeline
             WHERE group_id_hex = ?1 AND message_id_hex = ?2
             LIMIT 1",
            params![group_id_hex, message_id_hex],
            |row| {
                Ok(TimelineMessageTarget {
                    sender: row.get(0)?,
                    plaintext: row.get(1)?,
                    kind: row.get::<_, i64>(2)?.try_into().unwrap_or_default(),
                    deleted: row.get::<_, i64>(3)? != 0,
                    invalidated: row.get::<_, Option<String>>(4)?.is_some(),
                })
            },
        )
        .optional()
        .storage()
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
        upsert_message_timeline_row_tx(tx, &row)?;
    }
    for start in stream_starts {
        upsert_agent_stream_start_tx(tx, &start)?;
    }
    Ok(())
}

pub(crate) fn prune_app_events_before_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    cutoff_recorded_at: u64,
) -> StorageResult<usize> {
    let pruned_events = app_events_before_cutoff_tx(tx, group_id_hex, cutoff_recorded_at)?;
    if pruned_events.is_empty() {
        return Ok(0);
    }

    let mut pruned_message_ids = BTreeSet::new();
    let mut affected_message_ids = BTreeSet::new();
    for event in &pruned_events {
        pruned_message_ids.insert(event.message_id_hex.clone());
        affected_message_ids.extend(affected_timeline_message_ids_for_pruned_event_tx(
            tx,
            group_id_hex,
            &event.message_id_hex,
            event.kind,
            &event.tags,
        )?);
    }

    let pruned = tx
        .execute(
            "DELETE FROM app_events
             WHERE group_id_hex = ?1
               AND recorded_at < ?2",
            params![group_id_hex, u64_to_i64(cutoff_recorded_at)?],
        )
        .storage()?;

    delete_timeline_projection_rows_by_ids_tx(tx, group_id_hex, &pruned_message_ids)?;
    affected_message_ids.retain(|message_id| !pruned_message_ids.contains(message_id));
    for message_id in affected_message_ids {
        upsert_message_timeline_projection_for_message_tx(tx, group_id_hex, &message_id)?;
    }

    Ok(pruned)
}

fn can_project_record_app_event_incrementally(kind: u64) -> bool {
    matches!(
        kind,
        MARMOT_APP_EVENT_KIND_CHAT
            | MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
            | MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
            | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
            | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
    )
}

fn app_event_exists_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<bool> {
    let exists = tx
        .query_row(
            "SELECT 1
             FROM app_events
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group_id_hex, message_id_hex],
            |_| Ok(()),
        )
        .optional()
        .storage()?;
    Ok(exists.is_some())
}

fn upsert_message_timeline_projection_for_message_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<()> {
    tx.execute(
        "DELETE FROM agent_stream_starts
         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        params![group_id_hex, message_id_hex],
    )
    .storage()?;

    let Some((row, stream_start)) =
        project_single_message_timeline_tx(tx, group_id_hex, message_id_hex)?
    else {
        tx.execute(
            "DELETE FROM message_timeline
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group_id_hex, message_id_hex],
        )
        .storage()?;
        return Ok(());
    };

    upsert_message_timeline_row_tx(tx, &row)?;
    if let Some(stream_start) = stream_start {
        upsert_agent_stream_start_tx(tx, &stream_start)?;
    }
    Ok(())
}

fn project_single_message_timeline_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<(TimelineRow, Option<StreamStartRow>)>> {
    let Some(event) = tx
        .query_row(
            "SELECT group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender,
                    plaintext, kind, tags_json, recorded_at, received_at,
                    invalidated, invalidation_reason
             FROM app_events
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group_id_hex, message_id_hex],
            raw_event_from_row,
        )
        .optional()
        .storage()?
    else {
        return Ok(None);
    };

    let mut stream_start = None;
    let mut row = match event.kind {
        MARMOT_APP_EVENT_KIND_CHAT => timeline_row_from_chat(&event),
        MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
        | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
        | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
        | MARMOT_APP_EVENT_KIND_EDIT => timeline_row_from_app_event(&event),
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START => {
            let Some(stream_id_hex) = tag_value(&event.tags, STREAM_TAG) else {
                return Ok(None);
            };
            if !event.invalidated {
                stream_start = Some(StreamStartRow {
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
            timeline_row_from_stream_start(&event)
        }
        _ => return Ok(None),
    };

    if event.invalidated {
        row.invalidation_status = Some(invalidation_status(&event));
    }
    apply_targeted_modifiers_tx(tx, &mut row)?;
    Ok(Some((row, stream_start)))
}

fn apply_targeted_modifiers_tx(tx: &Transaction<'_>, row: &mut TimelineRow) -> StorageResult<()> {
    let reactions = app_events_targeting_message_tx(
        tx,
        &row.group_id_hex,
        MARMOT_APP_EVENT_KIND_REACTION,
        &row.message_id_hex,
    )?;
    let deleted_reaction_ids =
        deleted_reaction_ids_for_target_tx(tx, &row.group_id_hex, &reactions)?;
    for reaction in reactions {
        if deleted_reaction_ids.contains(&reaction.message_id_hex) {
            continue;
        }
        row.reactions.user_reactions.push(TimelineUserReaction {
            reaction_message_id_hex: reaction.message_id_hex.clone(),
            target_message_id_hex: row.message_id_hex.clone(),
            sender: reaction.sender.clone(),
            emoji: reaction.plaintext.clone(),
            reacted_at: reaction.recorded_at,
        });
    }
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

    let deletes = app_events_targeting_message_tx(
        tx,
        &row.group_id_hex,
        MARMOT_APP_EVENT_KIND_DELETE,
        &row.message_id_hex,
    )?;
    for delete in deletes {
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
    Ok(())
}

fn deleted_reaction_ids_for_target_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    reactions: &[RawAppEvent],
) -> StorageResult<HashSet<String>> {
    let mut deleted = HashSet::new();
    for reaction in reactions {
        let deletes = app_events_targeting_message_tx(
            tx,
            group_id_hex,
            MARMOT_APP_EVENT_KIND_DELETE,
            &reaction.message_id_hex,
        )?;
        if deletes
            .iter()
            .any(|delete| delete.sender == reaction.sender)
        {
            deleted.insert(reaction.message_id_hex.clone());
        }
    }
    Ok(deleted)
}

fn app_events_targeting_message_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    kind: u64,
    target_message_id_hex: &str,
) -> StorageResult<Vec<RawAppEvent>> {
    let target_pattern = json_string_like_pattern(target_message_id_hex)?;
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender,
                    plaintext, kind, tags_json, recorded_at, received_at,
                    invalidated, invalidation_reason
             FROM app_events
             WHERE group_id_hex = ?1
               AND kind = ?2
               AND invalidated = 0
               AND tags_json LIKE ?3 ESCAPE '\\'
             ORDER BY recorded_at, message_id_hex, insert_order",
        )
        .storage()?;
    let events = stmt
        .query_map(
            params![group_id_hex, u64_to_i64(kind)?, target_pattern],
            raw_event_from_row,
        )
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    Ok(events
        .into_iter()
        .filter(|event| {
            tag_values(&event.tags, EVENT_REF_TAG).any(|target| target == target_message_id_hex)
        })
        .collect())
}

fn upsert_message_timeline_row_tx(tx: &Transaction<'_>, row: &TimelineRow) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO message_timeline (
            group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender,
            plaintext, kind, tags_json, timeline_at, received_at,
            reply_to_message_id_hex, media_json, agent_stream_json, reactions_json,
            deleted, deleted_by_message_id_hex, invalidation_status
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(group_id_hex, message_id_hex) DO UPDATE SET
            source_message_id_hex = excluded.source_message_id_hex,
            source_epoch = excluded.source_epoch,
            direction = excluded.direction,
            sender = excluded.sender,
            plaintext = excluded.plaintext,
            kind = excluded.kind,
            tags_json = excluded.tags_json,
            timeline_at = excluded.timeline_at,
            received_at = excluded.received_at,
            reply_to_message_id_hex = excluded.reply_to_message_id_hex,
            media_json = excluded.media_json,
            agent_stream_json = excluded.agent_stream_json,
            reactions_json = excluded.reactions_json,
            deleted = excluded.deleted,
            deleted_by_message_id_hex = excluded.deleted_by_message_id_hex,
            invalidation_status = excluded.invalidation_status",
        params![
            &row.group_id_hex,
            &row.message_id_hex,
            &row.source_message_id_hex,
            optional_u64_to_i64(row.source_epoch)?,
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
            &row.invalidation_status,
        ],
    )
    .storage()?;
    Ok(())
}

fn upsert_agent_stream_start_tx(tx: &Transaction<'_>, start: &StreamStartRow) -> StorageResult<()> {
    tx.execute(
        "INSERT INTO agent_stream_starts (
            group_id_hex, message_id_hex, source_message_id_hex, sender, stream_id_hex,
            tags_json, started_at, received_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(group_id_hex, message_id_hex) DO UPDATE SET
            source_message_id_hex = excluded.source_message_id_hex,
            sender = excluded.sender,
            stream_id_hex = excluded.stream_id_hex,
            tags_json = excluded.tags_json,
            started_at = excluded.started_at,
            received_at = excluded.received_at",
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
    Ok(())
}

fn json_string_like_pattern(value: &str) -> StorageResult<String> {
    let quoted =
        serde_json::to_string(value).map_err(|err| StorageError::Serialization(err.to_string()))?;
    Ok(format!("%{}%", escape_like_literal(&quoted)))
}

fn escape_like_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn app_events_for_rebuild_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
) -> StorageResult<Vec<RawAppEvent>> {
    // Invalidated events are intentionally NOT filtered out here: convergence-
    // invalidated message-creating events are projected as tombstones (issue #111).
    // `project_group_events` skips applying invalidated modifier events (reactions,
    // deletes) so a losing-branch event never mutates canonical content.
    let mut stmt = tx
        .prepare(
            "SELECT group_id_hex, message_id_hex, source_message_id_hex, source_epoch, direction, sender,
                    plaintext, kind, tags_json, recorded_at, received_at,
                    invalidated, invalidation_reason
             FROM app_events
             WHERE group_id_hex = ?1
             ORDER BY recorded_at, message_id_hex, insert_order",
        )
        .storage()?;
    stmt.query_map(params![group_id_hex], raw_event_from_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn app_events_before_cutoff_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    cutoff_recorded_at: u64,
) -> StorageResult<Vec<PrunedAppEvent>> {
    let mut stmt = tx
        .prepare(
            "SELECT message_id_hex, kind, tags_json
             FROM app_events
             WHERE group_id_hex = ?1
               AND recorded_at < ?2
             ORDER BY recorded_at, message_id_hex, insert_order",
        )
        .storage()?;
    stmt.query_map(
        params![group_id_hex, u64_to_i64(cutoff_recorded_at)?],
        |row| {
            let tags = tags_from_json(row.get::<_, String>(2)?).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?;
            Ok(PrunedAppEvent {
                message_id_hex: row.get(0)?,
                kind: row.get::<_, i64>(1)?.try_into().unwrap_or_default(),
                tags,
            })
        },
    )
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn delete_timeline_projection_rows_by_ids_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_ids: &BTreeSet<String>,
) -> StorageResult<()> {
    if message_ids.is_empty() {
        return Ok(());
    }
    let message_ids = message_ids.iter().collect::<Vec<_>>();
    for table in ["message_timeline", "agent_stream_starts"] {
        for chunk in message_ids.chunks(SQLITE_BIND_PARAMETER_CHUNK) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut values = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 1);
            values.push(rusqlite::types::Value::Text(group_id_hex.to_owned()));
            values.extend(
                chunk
                    .iter()
                    .map(|message_id| rusqlite::types::Value::Text((*message_id).clone())),
            );
            tx.execute(
                &format!(
                    "DELETE FROM {table}
                     WHERE group_id_hex = ?
                       AND message_id_hex IN ({placeholders})"
                ),
                params_from_iter(values.iter()),
            )
            .storage()?;
        }
    }
    Ok(())
}

fn affected_timeline_message_ids_tx(
    tx: &Transaction<'_>,
    event: &StoredAppEvent,
) -> StorageResult<BTreeSet<String>> {
    affected_timeline_message_ids_for_parts_tx(
        tx,
        &event.group_id_hex,
        &event.message_id_hex,
        event.kind,
        &event.tags,
    )
}

fn affected_timeline_message_ids_for_parts_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
) -> StorageResult<BTreeSet<String>> {
    affected_timeline_message_ids_for_parts_with_options_tx(
        tx,
        group_id_hex,
        message_id_hex,
        kind,
        tags,
        true,
    )
}

fn affected_timeline_message_ids_for_pruned_event_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
) -> StorageResult<BTreeSet<String>> {
    // Pruning does not emit live timeline changes, and reply previews are
    // hydrated from message_timeline at read time. Re-project direct survivors
    // whose stored projection depended on the pruned row (reaction/delete/edit
    // targets), but do not scan retained replies just because their preview
    // target was pruned.
    affected_timeline_message_ids_for_parts_with_options_tx(
        tx,
        group_id_hex,
        message_id_hex,
        kind,
        tags,
        false,
    )
}

fn affected_timeline_message_ids_for_parts_with_options_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    include_reply_preview_dependents: bool,
) -> StorageResult<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    let mut reply_preview_targets = BTreeSet::new();
    match kind {
        MARMOT_APP_EVENT_KIND_CHAT
        | MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
        | MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
        | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
        | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM => {
            ids.insert(message_id_hex.to_owned());
            reply_preview_targets.insert(message_id_hex.to_owned());
        }
        MARMOT_APP_EVENT_KIND_EDIT => {
            // The edit row itself is the new timeline entry; its e-tag targets
            // are also affected so the original bubble re-renders with the
            // overlaid body the client computes from the edit chain.
            ids.insert(message_id_hex.to_owned());
            ids.extend(tag_values(tags, EVENT_REF_TAG).map(ToOwned::to_owned));
        }
        MARMOT_APP_EVENT_KIND_REACTION => {
            ids.extend(tag_values(tags, EVENT_REF_TAG).map(ToOwned::to_owned));
        }
        MARMOT_APP_EVENT_KIND_DELETE => {
            for target in tag_values(tags, EVENT_REF_TAG) {
                ids.insert(target.to_owned());
                reply_preview_targets.insert(target.to_owned());
                if let Some(reaction_target) =
                    reaction_target_message_id_tx(tx, group_id_hex, target)?
                {
                    ids.insert(reaction_target);
                }
            }
        }
        _ => {}
    }
    if include_reply_preview_dependents {
        let reply_targets = reply_preview_targets.into_iter().collect::<Vec<_>>();
        ids.extend(reply_message_ids_for_targets_tx(
            tx,
            group_id_hex,
            &reply_targets,
        )?);
    }
    Ok(ids)
}

fn timeline_changes_for_event(
    event_message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    messages: &[TimelineMessageRecord],
) -> Vec<TimelineMessageChange> {
    messages
        .iter()
        .cloned()
        .map(|message| TimelineMessageChange::Upsert {
            trigger: timeline_trigger_for_event_row(event_message_id_hex, kind, tags, &message),
            message: Box::new(message),
        })
        .collect()
}

fn timeline_changes_for_invalidation(
    event_message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    before: &[TimelineMessageRecord],
    messages: &[TimelineMessageRecord],
) -> Vec<TimelineMessageChange> {
    let before_by_id = before
        .iter()
        .map(|message| (message.message_id_hex.as_str(), message))
        .collect::<HashMap<_, _>>();
    let after_by_id = messages
        .iter()
        .map(|message| (message.message_id_hex.as_str(), message))
        .collect::<HashMap<_, _>>();
    let mut changes = messages
        .iter()
        .filter(|message| before_by_id.get(message.message_id_hex.as_str()) != Some(message))
        .cloned()
        .map(|message| TimelineMessageChange::Upsert {
            trigger: timeline_trigger_for_invalidation_row(
                event_message_id_hex,
                kind,
                tags,
                &message,
            ),
            message: Box::new(message),
        })
        .collect::<Vec<_>>();
    changes.extend(
        before
            .iter()
            .filter(|message| !after_by_id.contains_key(message.message_id_hex.as_str()))
            .map(|message_id_hex| TimelineMessageChange::Remove {
                message_id_hex: message_id_hex.message_id_hex.clone(),
                reason: TimelineRemoveReason::Invalidated,
            }),
    );
    changes
}

/// Deduplicate a merged change set produced by invalidating several rows that
/// share one origin commit. Because each invalidated row contributes a change
/// set computed against the same before/after timeline snapshots, the per-row
/// sets can overlap (e.g. a shared reply-preview target). Keep the first change
/// seen per `(message_id, variant)` so live subscribers receive one update per
/// affected message.
fn dedup_timeline_changes(changes: &mut Vec<TimelineMessageChange>) {
    let mut seen = HashSet::new();
    changes.retain(|change| {
        let key = match change {
            TimelineMessageChange::Upsert { message, .. } => (0u8, message.message_id_hex.clone()),
            TimelineMessageChange::Remove { message_id_hex, .. } => (1u8, message_id_hex.clone()),
        };
        seen.insert(key)
    });
}

fn timeline_trigger_for_invalidation_row(
    event_message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    row: &TimelineMessageRecord,
) -> TimelineUpdateTrigger {
    let event_targets = tag_values(tags, EVENT_REF_TAG).collect::<Vec<_>>();
    if row.message_id_hex != event_message_id_hex
        && row
            .reply_to_message_id_hex
            .as_deref()
            .is_some_and(|reply_target| {
                reply_target == event_message_id_hex
                    || event_targets.iter().any(|target| target == &reply_target)
            })
        && matches!(
            kind,
            MARMOT_APP_EVENT_KIND_CHAT
                | MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
                | MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
                | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
                | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                | MARMOT_APP_EVENT_KIND_DELETE
        )
    {
        return TimelineUpdateTrigger::ReplyPreviewChanged;
    }
    match kind {
        MARMOT_APP_EVENT_KIND_REACTION => TimelineUpdateTrigger::ReactionRemoved,
        MARMOT_APP_EVENT_KIND_DELETE => {
            if event_targets
                .iter()
                .any(|target| *target == row.message_id_hex)
            {
                TimelineUpdateTrigger::MessageEditedOrReprojected
            } else {
                TimelineUpdateTrigger::ReactionAdded
            }
        }
        _ => TimelineUpdateTrigger::MessageEditedOrReprojected,
    }
}

fn timeline_trigger_for_event_row(
    event_message_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    row: &TimelineMessageRecord,
) -> TimelineUpdateTrigger {
    let event_targets = tag_values(tags, EVENT_REF_TAG).collect::<Vec<_>>();
    if row.message_id_hex != event_message_id_hex
        && row
            .reply_to_message_id_hex
            .as_deref()
            .is_some_and(|reply_target| {
                reply_target == event_message_id_hex
                    || event_targets.iter().any(|target| target == &reply_target)
            })
        && matches!(
            kind,
            MARMOT_APP_EVENT_KIND_CHAT
                | MARMOT_APP_EVENT_KIND_AGENT_STREAM_START
                | MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
                | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
                | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
                | MARMOT_APP_EVENT_KIND_DELETE
        )
    {
        return TimelineUpdateTrigger::ReplyPreviewChanged;
    }
    match kind {
        MARMOT_APP_EVENT_KIND_CHAT => {
            if tag_value(tags, STREAM_TAG).is_some() && tag_value(tags, STREAM_START_TAG).is_some()
            {
                TimelineUpdateTrigger::AgentStreamFinished
            } else {
                TimelineUpdateTrigger::NewMessage
            }
        }
        MARMOT_APP_EVENT_KIND_AGENT_STREAM_START => TimelineUpdateTrigger::AgentStreamStarted,
        MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY => TimelineUpdateTrigger::AgentActivity,
        MARMOT_APP_EVENT_KIND_AGENT_OPERATION => TimelineUpdateTrigger::AgentOperation,
        MARMOT_APP_EVENT_KIND_GROUP_SYSTEM => TimelineUpdateTrigger::GroupSystem,
        MARMOT_APP_EVENT_KIND_REACTION => TimelineUpdateTrigger::ReactionAdded,
        MARMOT_APP_EVENT_KIND_DELETE => {
            if event_targets
                .iter()
                .any(|target| *target == row.message_id_hex)
            {
                TimelineUpdateTrigger::MessageDeleted
            } else {
                TimelineUpdateTrigger::ReactionRemoved
            }
        }
        _ => TimelineUpdateTrigger::MessageEditedOrReprojected,
    }
}

fn reply_message_ids_for_targets_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    target_message_ids: &[String],
) -> StorageResult<Vec<String>> {
    if target_message_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", target_message_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT message_id_hex
         FROM message_timeline
         WHERE group_id_hex = ?
           AND reply_to_message_id_hex IN ({placeholders})"
    );
    let mut values = Vec::<rusqlite::types::Value>::with_capacity(target_message_ids.len() + 1);
    values.push(rusqlite::types::Value::Text(group_id_hex.to_owned()));
    values.extend(
        target_message_ids
            .iter()
            .cloned()
            .map(rusqlite::types::Value::Text),
    );
    let mut stmt = tx.prepare(&sql).storage()?;
    stmt.query_map(params_from_iter(values.iter()), |row| row.get(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn reaction_target_message_id_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<String>> {
    let row: Option<(u64, Vec<Vec<String>>)> = tx
        .query_row(
            "SELECT kind, tags_json
             FROM app_events
             WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group_id_hex, message_id_hex],
            |row| {
                let kind = row.get::<_, i64>(0)?.try_into().unwrap_or_default();
                let tags = tags_from_json(row.get::<_, String>(1)?).map_err(|err| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Text,
                        Box::new(err),
                    )
                })?;
                Ok((kind, tags))
            },
        )
        .optional()
        .storage()?;
    let Some((kind, tags)) = row else {
        return Ok(None);
    };
    if kind != MARMOT_APP_EVENT_KIND_REACTION {
        return Ok(None);
    }
    Ok(tag_value(&tags, EVENT_REF_TAG).map(ToOwned::to_owned))
}

fn timeline_records_by_ids_tx(
    tx: &Transaction<'_>,
    group_id_hex: &str,
    message_ids: BTreeSet<String>,
) -> StorageResult<Vec<TimelineMessageRecord>> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = std::iter::repeat_n("?", message_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT message_id_hex, source_message_id_hex, source_epoch, direction, group_id_hex, sender,
                plaintext, kind, tags_json, timeline_at, received_at,
                reply_to_message_id_hex, media_json, agent_stream_json, reactions_json,
                deleted, deleted_by_message_id_hex, invalidation_status
         FROM message_timeline
         WHERE group_id_hex = ? AND message_id_hex IN ({placeholders})
         ORDER BY timeline_at ASC, message_id_hex ASC"
    );
    let mut params = Vec::<rusqlite::types::Value>::with_capacity(message_ids.len() + 1);
    params.push(rusqlite::types::Value::Text(group_id_hex.to_owned()));
    params.extend(message_ids.into_iter().map(rusqlite::types::Value::Text));
    let mut stmt = tx.prepare(&sql).storage()?;
    let mut messages = stmt
        .query_map(params_from_iter(params.iter()), timeline_record_from_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    attach_reply_previews(tx, &mut messages)?;
    Ok(messages)
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
        inclusive: pagination.before_inclusive,
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
            // An inclusive cursor returns the row equal to the bound too, so the
            // tie-break comparison flips from `<` to `<=`.
            let id_comparison = if pagination.inclusive { "<=" } else { "<" };
            clauses.push(format!(
                "(timeline_at < ? OR (timeline_at = ? AND message_id_hex {id_comparison} ?))"
            ));
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
            "SELECT message_id_hex, source_message_id_hex, source_epoch, direction, group_id_hex, sender,
                    plaintext, kind, tags_json, timeline_at, received_at,
                    reply_to_message_id_hex, media_json, agent_stream_json, reactions_json,
                    deleted, deleted_by_message_id_hex, invalidation_status
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
                let mut row = timeline_row_from_chat(event);
                if event.invalidated {
                    row.invalidation_status = Some(invalidation_status(event));
                }
                timeline.insert(event.message_id_hex.clone(), row);
            }
            MARMOT_APP_EVENT_KIND_AGENT_ACTIVITY
            | MARMOT_APP_EVENT_KIND_AGENT_OPERATION
            | MARMOT_APP_EVENT_KIND_GROUP_SYSTEM
            | MARMOT_APP_EVENT_KIND_EDIT => {
                let mut row = timeline_row_from_app_event(event);
                if event.invalidated {
                    row.invalidation_status = Some(invalidation_status(event));
                }
                timeline.insert(event.message_id_hex.clone(), row);
            }
            MARMOT_APP_EVENT_KIND_AGENT_STREAM_START => {
                if let Some(stream_id_hex) = tag_value(&event.tags, STREAM_TAG) {
                    let mut row = timeline_row_from_stream_start(event);
                    if event.invalidated {
                        row.invalidation_status = Some(invalidation_status(event));
                    }
                    timeline.insert(event.message_id_hex.clone(), row);
                    // An invalidated stream start is a tombstone, not a live stream,
                    // so it does not register an active stream-start row.
                    if !event.invalidated {
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
            }
            // Invalidated modifier events landed on a losing branch and MUST NOT
            // mutate canonical content, so they are skipped entirely.
            MARMOT_APP_EVENT_KIND_REACTION if !event.invalidated => reactions.push(event.clone()),
            MARMOT_APP_EVENT_KIND_DELETE if !event.invalidated => deletes.push(event.clone()),
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
        source_epoch: event.source_epoch,
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
        invalidation_status: None,
    }
}

fn timeline_row_from_app_event(event: &RawAppEvent) -> TimelineRow {
    TimelineRow {
        message_id_hex: event.message_id_hex.clone(),
        source_message_id_hex: event.source_message_id_hex.clone(),
        source_epoch: event.source_epoch,
        direction: event.direction.clone(),
        group_id_hex: event.group_id_hex.clone(),
        sender: event.sender.clone(),
        plaintext: event.plaintext.clone(),
        kind: event.kind,
        tags: event.tags.clone(),
        timeline_at: event.recorded_at,
        received_at: event.received_at,
        reply_to_message_id_hex: tag_value(&event.tags, EVENT_REF_TAG).map(ToOwned::to_owned),
        media: None,
        agent_text_stream: None,
        reactions: TimelineReactionSummary::default(),
        deleted: false,
        deleted_by_message_id_hex: None,
        invalidation_status: None,
    }
}

fn timeline_row_from_stream_start(event: &RawAppEvent) -> TimelineRow {
    TimelineRow {
        message_id_hex: event.message_id_hex.clone(),
        source_message_id_hex: event.source_message_id_hex.clone(),
        source_epoch: event.source_epoch,
        direction: event.direction.clone(),
        group_id_hex: event.group_id_hex.clone(),
        sender: event.sender.clone(),
        plaintext: event.plaintext.clone(),
        kind: event.kind,
        tags: event.tags.clone(),
        timeline_at: event.recorded_at,
        received_at: event.received_at,
        reply_to_message_id_hex: None,
        media: None,
        agent_text_stream: agent_stream_start_metadata(event),
        reactions: TimelineReactionSummary::default(),
        deleted: false,
        deleted_by_message_id_hex: None,
        invalidation_status: None,
    }
}

/// The projected invalidation status for an invalidated event: the engine
/// invalidation reason (e.g. `LosingBranch`) when present, falling back to a
/// generic marker so the tombstone is always distinguishable from a delivered row.
fn invalidation_status(event: &RawAppEvent) -> String {
    event
        .invalidation_reason
        .clone()
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "Invalidated".to_owned())
}

fn media_metadata(tags: &[Vec<String>]) -> Option<Value> {
    let imeta = tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "imeta"))
        .cloned()
        .collect::<Vec<_>>();
    (!imeta.is_empty()).then(|| json!({ "imeta": imeta }))
}

fn agent_stream_start_metadata(event: &RawAppEvent) -> Option<Value> {
    let stream_id_hex = tag_value(&event.tags, STREAM_TAG)?;
    Some(json!({
        "stream_id_hex": stream_id_hex,
        "start_event_id": event.message_id_hex,
        "status": "started"
    }))
}

fn agent_stream_final_metadata(tags: &[Vec<String>]) -> Option<Value> {
    let stream_id_hex = tag_value(tags, STREAM_TAG)?;
    let mut value = json!({ "stream_id_hex": stream_id_hex, "status": "finalized" });
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
        source_epoch: row
            .get::<_, Option<i64>>(3)?
            .and_then(|value| value.try_into().ok()),
        direction: row.get(4)?,
        sender: row.get(5)?,
        plaintext: row.get(6)?,
        kind: row.get::<_, i64>(7)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(8)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(err))
        })?,
        recorded_at: row.get::<_, i64>(9)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(10)?.try_into().unwrap_or_default(),
        invalidated: row.get::<_, i64>(11)? != 0,
        invalidation_reason: row.get(12)?,
    })
}

fn timeline_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineMessageRecord> {
    Ok(TimelineMessageRecord {
        message_id_hex: row.get(0)?,
        source_message_id_hex: row.get(1)?,
        source_epoch: row
            .get::<_, Option<i64>>(2)?
            .and_then(|value| value.try_into().ok()),
        direction: row.get(3)?,
        group_id_hex: row.get(4)?,
        sender: row.get(5)?,
        plaintext: row.get(6)?,
        kind: row.get::<_, i64>(7)?.try_into().unwrap_or_default(),
        tags: tags_from_json(row.get::<_, String>(8)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(8, rusqlite::types::Type::Text, Box::new(err))
        })?,
        timeline_at: row.get::<_, i64>(9)?.try_into().unwrap_or_default(),
        received_at: row.get::<_, i64>(10)?.try_into().unwrap_or_default(),
        reply_to_message_id_hex: row.get(11)?,
        reply_preview: None,
        media: optional_value_from_json(row.get::<_, Option<String>>(12)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                12,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?,
        agent_text_stream: optional_value_from_json(row.get::<_, Option<String>>(13)?).map_err(
            |err| {
                rusqlite::Error::FromSqlConversionFailure(
                    13,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            },
        )?,
        reactions: reaction_summary_from_json(row.get::<_, String>(14)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                14,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?,
        deleted: row.get::<_, i64>(15)? != 0,
        deleted_by_message_id_hex: row.get(16)?,
        invalidation_status: row.get(17)?,
    })
}

fn attach_reply_previews(
    conn: &Connection,
    messages: &mut [TimelineMessageRecord],
) -> StorageResult<()> {
    let targets = messages
        .iter()
        .filter_map(|message| {
            message
                .reply_to_message_id_hex
                .as_ref()
                .map(|target| (message.group_id_hex.clone(), target.clone()))
        })
        .collect::<HashSet<_>>();
    if targets.is_empty() {
        return Ok(());
    }

    let previews = load_reply_previews(conn, targets)?;

    for message in messages {
        let Some(target) = message.reply_to_message_id_hex.as_ref() else {
            continue;
        };
        message.reply_preview = previews
            .get(&(message.group_id_hex.clone(), target.clone()))
            .cloned();
    }
    Ok(())
}

fn load_reply_previews(
    conn: &Connection,
    targets: HashSet<(String, String)>,
) -> StorageResult<HashMap<(String, String), TimelineReplyPreview>> {
    let mut targets_by_group = BTreeMap::<String, Vec<String>>::new();
    for (group_id_hex, message_id_hex) in targets {
        targets_by_group
            .entry(group_id_hex)
            .or_default()
            .push(message_id_hex);
    }

    let mut previews = HashMap::new();
    for (group_id_hex, mut message_ids) in targets_by_group {
        message_ids.sort();
        message_ids.dedup();
        let placeholders = std::iter::repeat_n("?", message_ids.len())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT message_id_hex, sender, plaintext, kind, media_json, agent_stream_json, deleted
             FROM message_timeline
             WHERE group_id_hex = ? AND message_id_hex IN ({placeholders})"
        );
        let mut params = Vec::<rusqlite::types::Value>::with_capacity(message_ids.len() + 1);
        params.push(rusqlite::types::Value::Text(group_id_hex.clone()));
        params.extend(message_ids.into_iter().map(rusqlite::types::Value::Text));
        let mut stmt = conn.prepare(&sql).storage()?;
        let group_previews = stmt
            .query_map(params_from_iter(params.iter()), reply_preview_from_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        for preview in group_previews {
            previews.insert(
                (group_id_hex.clone(), preview.message_id_hex.clone()),
                preview,
            );
        }
    }
    Ok(previews)
}

fn reply_preview_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimelineReplyPreview> {
    Ok(TimelineReplyPreview {
        message_id_hex: row.get(0)?,
        sender: row.get(1)?,
        plaintext: row.get(2)?,
        kind: row.get::<_, i64>(3)?.try_into().unwrap_or_default(),
        media: optional_value_from_json(row.get::<_, Option<String>>(4)?).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(err))
        })?,
        agent_text_stream: optional_value_from_json(row.get::<_, Option<String>>(5)?).map_err(
            |err| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            },
        )?,
        deleted: row.get::<_, i64>(6)? != 0,
    })
}

fn tags_json(tags: &[Vec<String>]) -> StorageResult<String> {
    serde_json::to_string(tags).map_err(|err| StorageError::Serialization(err.to_string()))
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

#[cfg(test)]
mod tests;
