//! Derived attachment discovery. Protocol validation and acquisition policy live
//! above storage; a slot is not a promise that an attachment can be downloaded.
use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::{Connection, OptionalExtension, params_from_iter, types::Value};

/// Maximum number of attachment slots returned by one page.
pub const MAX_ATTACHMENT_HISTORY_PAGE: usize = 100;

/// One original imeta slot, including malformed slots for the app parser to reject.
/// No message body or complete album is loaded by this projection.
#[derive(Clone)]
pub struct AttachmentHistoryEntry {
    /// Source context for discovery: rejected reaction artwork has no Shared message.
    pub reaction_artwork: bool,
    pub message_id_hex: String,
    pub attachment_index: usize,
    pub source_message_id_hex: String,
    pub source_epoch: Option<u64>,
    pub sender: String,
    pub timeline_at: u64,
    pub received_at: u64,
    /// The original imeta array, or a malformed value. A corrupt container is null.
    pub slot: serde_json::Value,
    /// Only emoji tag arrays from this source message; never the message body or album.
    pub emoji_tags: Vec<Vec<String>>,
}

/// Opaque account/group version. Compare for equality, never interpret as a count.
/// Changes in other groups do not invalidate this version. Empty versions are
/// fenced by the store identity too. Group removal/recreation gets a new generation.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentHistoryVersion {
    store_epoch: Vec<u8>,
    group: String,
    generation: Option<Vec<u8>>,
    revision: i64,
    additions: i64,
}

impl AttachmentHistoryVersion {
    /// Whether previously loaded rows/boundaries must be discarded. An unequal
    /// version with `false` here signals additions only: callers may keep paging
    /// and choose when to refresh entries above their saved boundary.
    pub fn requires_restart_since(&self, previous: &Self) -> bool {
        self.store_epoch != previous.store_epoch
            || self.group != previous.group
            || self.generation != previous.generation
            || self.revision != previous.revision
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentHistoryCursor {
    version: AttachmentHistoryVersion,
    key: SortKey,
}

#[derive(Clone, PartialEq, Eq)]
struct SortKey {
    class: i64,
    primary: i64,
    phase: i64,
    at: i64,
    message: String,
    attachment_order: i64,
}

impl std::fmt::Debug for AttachmentHistoryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentHistoryEntry")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AttachmentHistoryVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentHistoryVersion")
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AttachmentHistoryCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentHistoryCursor")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct AttachmentHistoryPage {
    pub entries: Vec<AttachmentHistoryEntry>,
    pub version: AttachmentHistoryVersion,
    /// Present exactly when another page existed in this read snapshot.
    pub next_cursor: Option<AttachmentHistoryCursor>,
}

#[derive(Debug, thiserror::Error)]
pub enum AttachmentHistoryError {
    #[error(
        "attachment page limit must be between 1 and {}",
        MAX_ATTACHMENT_HISTORY_PAGE
    )]
    InvalidLimit,
    #[error("attachment cursor belongs to another account or group")]
    CursorMismatch,
    #[error("attachment history changed; replace loaded pages and restart")]
    StaleCursor,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

const KEY_COLUMNS: &str =
    "order_class,order_primary,order_phase,order_at,message_id_hex,attachment_order";

fn nonnegative(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

/// Seek the slot index and point-read only emoji metadata for the bounded result rows.
fn page_sql(cursor: bool) -> String {
    let seek = if cursor {
        format!(" AND ({KEY_COLUMNS}) < (?3,?4,?5,?6,?7,?8)")
    } else {
        String::new()
    };
    format!("SELECT {KEY_COLUMNS},
        EXISTS(SELECT 1 FROM app_events a WHERE a.group_id_hex=attachment_history.group_id_hex AND a.message_id_hex=attachment_history.message_id_hex AND a.kind=7) AS reaction_artwork,attachment_index,source_message_id_hex,source_epoch,sender,timeline_at,received_at,slot_json,
        (SELECT json_group_array(json(e.value)) FROM (SELECT tags_json FROM message_timeline WHERE group_id_hex=attachment_history.group_id_hex AND message_id_hex=attachment_history.message_id_hex
              UNION ALL SELECT tags_json FROM app_events WHERE group_id_hex=attachment_history.group_id_hex AND message_id_hex=attachment_history.message_id_hex AND kind=7) t,
            json_each(CASE WHEN json_valid(t.tags_json) THEN
                CASE WHEN json_type(t.tags_json)='array' THEN t.tags_json ELSE '[]' END
                ELSE '[]' END) e
         WHERE CASE WHEN e.type='array' THEN json_extract(e.value,'$[0]')='emoji' ELSE 0 END) AS emoji_tags_json
        FROM attachment_history INDEXED BY idx_attachment_history_page
        WHERE group_id_hex=?1 AND visible=1{seek}
        ORDER BY order_class DESC,order_primary DESC,order_phase DESC,order_at DESC,message_id_hex DESC,attachment_order DESC
        LIMIT ?2")
}

fn version_tx(
    conn: &Connection,
    group: &str,
) -> Result<AttachmentHistoryVersion, AttachmentHistoryError> {
    let store_epoch = conn
        .query_row_cached(
            "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
            [],
            |r| r.get(0),
        )
        .storage()?;
    let group_version: Option<(Vec<u8>, i64, i64)> = conn
        .query_row_cached(
            "SELECT generation,revision,additions FROM attachment_history_versions WHERE group_id_hex=?1",
            [group],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .storage()?;
    let (generation, revision, additions) =
        group_version.map_or((None, 0, 0), |(g, r, a)| (Some(g), r, a));
    Ok(AttachmentHistoryVersion {
        store_epoch,
        group: group.to_owned(),
        generation,
        revision,
        additions,
    })
}

impl SqliteAppStorage {
    /// Point-read at most 100 original slots from one live reaction. Source
    /// metadata is capped at 16 KiB and only definitions naming its content's
    /// shortcode are returned. No group history or message bodies are loaded.
    pub fn reaction_attachment_candidates(
        &self,
        group: &str,
        reaction: &str,
        now: u64,
    ) -> Result<Vec<AttachmentHistoryEntry>, StorageError> {
        self.connection.with_deferred_read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT 1 AS reaction_artwork,h.message_id_hex,h.attachment_index,h.source_message_id_hex,
                h.source_epoch,h.sender,h.timeline_at,h.received_at,h.slot_json,
                (SELECT json_group_array(json(e.value) ORDER BY CAST(e.key AS INTEGER)) FROM json_each(a.tags_json) e
                 WHERE CASE WHEN e.type='array' THEN json_extract(e.value,'$[0]')='emoji'
                   AND ':'||json_extract(e.value,'$[1]')||':'=a.plaintext ELSE 0 END) AS emoji_tags_json
                FROM app_events a CROSS JOIN attachment_history h
                  ON h.group_id_hex=a.group_id_hex AND h.message_id_hex=a.message_id_hex
                JOIN account_groups g ON g.group_id_hex=a.group_id_hex
                WHERE a.group_id_hex=?1 AND a.message_id_hex=?2 AND a.kind=7 AND a.invalidated=0
                  AND h.visible=1 AND g.pending_confirmation=0
                  AND length(CAST(a.tags_json AS BLOB))<=16384 AND json_valid(a.tags_json)
                  AND length(CAST(a.plaintext AS BLOB))<=64
                  AND h.attachment_index<100 AND length(CAST(h.slot_json AS BLOB))<=16384
                  AND (a.retention_expires_at IS NULL OR a.retention_expires_at>?3)
                ORDER BY h.attachment_index LIMIT 100").storage()?;
            stmt.query_map(rusqlite::params![group,reaction,crate::u64_to_i64(now)?],entry_from_row)
                .storage()?.collect::<Result<Vec<_>,_>>().storage()
        })
    }

    /// Cheap authoritative change signal, including after the final page.
    /// Compare for equality to discover changes, then use
    /// [`AttachmentHistoryVersion::requires_restart_since`] to distinguish an
    /// additions-only refresh from a required replacement of loaded rows.
    pub fn attachment_history_version(
        &self,
        group_id_hex: &str,
    ) -> Result<AttachmentHistoryVersion, AttachmentHistoryError> {
        self.connection
            .with_deferred_read(|conn| version_tx(conn, group_id_hex))
    }

    /// Read at most `limit` visible delivered attachment slots (1 through
    /// [`MAX_ATTACHMENT_HISTORY_PAGE`]), newest
    /// canonical message first and original attachment index ascending within an
    /// album. Uses an indexed seek and one consistent read snapshot; no engine,
    /// network, raw-history scan or acquisition is performed.
    ///
    /// Additions change the refresh version but keep existing cursors valid.
    /// Newer additions above a passed boundary require a separate refresh from
    /// None; older additions below it appear on subsequent pages. Paging a changing
    /// collection is not a fixed snapshot. Deletion, source replacement/reordering,
    /// visibility and group-generation changes invalidate cursors and loaded rows.
    /// Restart from None and replace old pages on StaleCursor; never append a fresh
    /// first page to an old collection. Local pending/failed sends, deleted and
    /// convergence-invalidated rows are excluded. Retention follows source pruning.
    pub fn attachment_history_page(
        &self,
        group_id_hex: &str,
        limit: usize,
        cursor: Option<&AttachmentHistoryCursor>,
    ) -> Result<AttachmentHistoryPage, AttachmentHistoryError> {
        if !(1..=MAX_ATTACHMENT_HISTORY_PAGE).contains(&limit) {
            return Err(AttachmentHistoryError::InvalidLimit);
        }
        self.connection.with_deferred_read(|conn| {
            let version = version_tx(conn, group_id_hex)?;
            if let Some(cursor) = cursor {
                if cursor.version.store_epoch != version.store_epoch
                    || cursor.version.group != version.group
                {
                    return Err(AttachmentHistoryError::CursorMismatch);
                }
                if version.requires_restart_since(&cursor.version) {
                    return Err(AttachmentHistoryError::StaleCursor);
                }
            }
            let mut params = vec![
                Value::Text(group_id_hex.to_owned()),
                Value::Integer((limit + 1) as i64),
            ];
            if let Some(cursor) = cursor {
                let k = &cursor.key;
                params.extend([
                    Value::Integer(k.class),
                    Value::Integer(k.primary),
                    Value::Integer(k.phase),
                    Value::Integer(k.at),
                    Value::Text(k.message.clone()),
                    Value::Integer(k.attachment_order),
                ]);
            }
            let mut stmt = conn.prepare_cached(&page_sql(cursor.is_some())).storage()?;
            let rows = stmt
                .query_map(params_from_iter(params), |r| {
                    let key = SortKey {
                        class: r.get(0)?,
                        primary: r.get(1)?,
                        phase: r.get(2)?,
                        at: r.get(3)?,
                        message: r.get(4)?,
                        attachment_order: r.get(5)?,
                    };
                    let entry = entry_from_row(r)?;
                    Ok((key, entry))
                })
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?;
            let has_more = rows.len() > limit;
            let mut entries = Vec::with_capacity(rows.len().min(limit));
            let mut last_key = None;
            for (key, entry) in rows.into_iter().take(limit) {
                last_key = Some(key);
                entries.push(entry);
            }
            let next_cursor = last_key
                .filter(|_| has_more)
                .map(|key| AttachmentHistoryCursor {
                    version: version.clone(),
                    key,
                });
            Ok(AttachmentHistoryPage {
                entries,
                version,
                next_cursor,
            })
        })
    }
}

/// Rebuild only reactions associated with one changed timeline row, or every
/// reaction after an existing whole-group rebuild. Modifier events remain in
/// app_events; this source projection never introduces timeline rows.
pub(crate) fn refresh_reaction_attachment_sources_tx(
    conn: &Connection,
    group: &str,
    target: Option<&str>,
) -> Result<(), StorageError> {
    // Earlier migration bodies also rebuild timelines. Their schema has no
    // reaction source view yet; migration 0167 performs the initial backfill.
    if !conn
        .query_row_cached(
            "SELECT EXISTS(SELECT 1 FROM cgka_schema_migrations WHERE version=167)",
            [],
            |r| r.get::<_, bool>(0),
        )
        .storage()?
    {
        return Ok(());
    }
    let ids = {
        let sql = if target.is_some() {
            "SELECT message_id_hex FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2 AND kind=7
             UNION SELECT a.message_id_hex FROM message_modifier_edges e CROSS JOIN app_events a
               ON a.group_id_hex=e.group_id_hex AND a.message_id_hex=e.modifier_message_id_hex
             WHERE e.group_id_hex=?1 AND e.target_message_id_hex=?2 AND e.kind=7 AND a.kind=7"
        } else {
            "SELECT message_id_hex FROM app_events WHERE group_id_hex=?1 AND kind=7 AND ?2 IS NULL"
        };
        // A changed target can have many plain reactions. Only actual artwork
        // candidates or prior sources need the per-source reconciliation work.
        let sql = format!("SELECT candidate.message_id_hex FROM ({sql}) candidate
            WHERE EXISTS(SELECT 1 FROM attachment_history h WHERE h.group_id_hex=?1 AND h.message_id_hex=candidate.message_id_hex)
               OR EXISTS(SELECT 1 FROM reaction_attachment_history_source s WHERE s.group_id_hex=?1 AND s.message_id_hex=candidate.message_id_hex)");
        let mut stmt = conn.prepare_cached(&sql).storage()?;
        stmt.query_map(rusqlite::params![group, target], |r| r.get::<_, String>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
    };
    for message in ids {
        // Keep unchanged slots and their jobs/cursors through target updates
        // and whole-timeline rebuilds. Only a changed source is replaced.
        conn.execute_cached("DELETE FROM attachment_history AS h WHERE group_id_hex=?1 AND message_id_hex=?2
            AND NOT EXISTS (SELECT 1 FROM reaction_attachment_history_source s
                WHERE s.group_id_hex=h.group_id_hex AND s.message_id_hex=h.message_id_hex
                  AND s.attachment_index=h.attachment_index AND s.source_message_id_hex=h.source_message_id_hex
                  AND s.source_epoch IS h.source_epoch AND s.sender=h.sender
                  AND s.timeline_at=h.timeline_at AND s.received_at=h.received_at
                  AND s.order_class=h.order_class AND s.order_primary=h.order_primary
                  AND s.order_phase=h.order_phase AND s.order_at=h.order_at
                  AND s.slot_json=h.slot_json AND s.visible=h.visible)",rusqlite::params![group,message]).storage()?;
        conn.execute_cached("INSERT OR IGNORE INTO attachment_history(group_id_hex,message_id_hex,attachment_index,source_message_id_hex,
            source_epoch,sender,timeline_at,received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
            SELECT * FROM reaction_attachment_history_source WHERE group_id_hex=?1 AND message_id_hex=?2",
            rusqlite::params![group,message]).storage()?;
        crate::app::attachment_acquisition::reconcile_attachment_acquisition_tx(
            conn,
            group,
            Some(&message),
        )?;
    }
    Ok(())
}

fn entry_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentHistoryEntry> {
    let slot_index = r.as_ref().column_index("slot_json")?;
    let json: String = r.get("slot_json")?;
    let slot = serde_json::from_str(&json).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            slot_index,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "attachment index contains invalid JSON",
            )),
        )
    })?;
    let emoji_tags =
        serde_json::from_str::<Vec<serde_json::Value>>(&r.get::<_, String>("emoji_tags_json")?)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|tag| serde_json::from_value(tag).ok())
            .collect();
    entry_with_metadata(r, slot, emoji_tags)
}

fn entry_with_metadata(
    r: &rusqlite::Row<'_>,
    slot: serde_json::Value,
    emoji_tags: Vec<Vec<String>>,
) -> rusqlite::Result<AttachmentHistoryEntry> {
    let attachment_index = r.as_ref().column_index("attachment_index")?;
    let source_epoch_index = r.as_ref().column_index("source_epoch")?;
    Ok(AttachmentHistoryEntry {
        reaction_artwork: r.get("reaction_artwork")?,
        message_id_hex: r.get("message_id_hex")?,
        attachment_index: usize::try_from(nonnegative(r, attachment_index)?)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(attachment_index, i64::MAX))?,
        source_message_id_hex: r.get("source_message_id_hex")?,
        source_epoch: r
            .get::<_, Option<i64>>("source_epoch")?
            .map(|v| {
                u64::try_from(v)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(source_epoch_index, v))
            })
            .transpose()?,
        sender: r.get("sender")?,
        timeline_at: nonnegative(r, r.as_ref().column_index("timeline_at")?)?,
        received_at: nonnegative(r, r.as_ref().column_index("received_at")?)?,
        emoji_tags,
        slot,
    })
}

mod account;
pub use account::*;

#[cfg(test)]
mod tests;
