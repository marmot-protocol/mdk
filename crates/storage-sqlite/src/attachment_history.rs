//! Derived attachment discovery. Protocol validation and acquisition policy live
//! above storage; a slot is not a promise that an attachment can be downloaded.
use crate::connection::CachedSql;
use crate::{SqliteAccountStorage, SqliteResultExt};
use cgka_traits::storage::StorageError;
use rusqlite::{Connection, OptionalExtension, params_from_iter, types::Value};

/// One original imeta slot, including malformed slots for the app parser to reject.
/// No message body or complete album is loaded by this projection.
#[derive(Clone)]
pub struct AttachmentHistoryEntry {
    pub message_id_hex: String,
    pub attachment_index: usize,
    pub source_message_id_hex: String,
    pub source_epoch: Option<u64>,
    pub sender: String,
    pub timeline_at: u64,
    pub received_at: u64,
    /// The original imeta array, or a malformed value. A corrupt container is null.
    pub slot: serde_json::Value,
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
    #[error("attachment page limit must be between 1 and 100")]
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

fn page_sql(cursor: bool) -> String {
    let seek = if cursor {
        format!(" AND ({KEY_COLUMNS}) < (?3,?4,?5,?6,?7,?8)")
    } else {
        String::new()
    };
    format!("SELECT {KEY_COLUMNS},attachment_index,source_message_id_hex,source_epoch,sender,timeline_at,received_at,slot_json
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
    let group_version: Option<(Vec<u8>, i64)> = conn
        .query_row_cached(
            "SELECT generation,revision FROM attachment_history_versions WHERE group_id_hex=?1",
            [group],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .storage()?;
    let (generation, revision) = group_version.map_or((None, 0), |(g, r)| (Some(g), r));
    Ok(AttachmentHistoryVersion {
        store_epoch,
        group: group.to_owned(),
        generation,
        revision,
    })
}

impl SqliteAccountStorage {
    /// Cheap authoritative refresh fence, including when the last page has no
    /// next cursor. A changed version requires replacing previously loaded rows.
    pub fn attachment_history_version(
        &self,
        group_id_hex: &str,
    ) -> Result<AttachmentHistoryVersion, AttachmentHistoryError> {
        self.connection
            .with_deferred_read(|conn| version_tx(conn, group_id_hex))
    }

    /// Read at most `limit` visible delivered attachment slots (1..=100), newest
    /// canonical message first and original attachment index ascending within an
    /// album. Uses an indexed seek and one consistent read snapshot; no engine,
    /// network, raw-history scan or acquisition is performed.
    ///
    /// Any relevant source/visibility change invalidates this group's cursors.
    /// Restart from None and replace old pages on StaleCursor; never append a fresh
    /// first page to an old collection. Local pending/failed sends, deleted and
    /// convergence-invalidated rows are excluded. Retention follows source pruning.
    pub fn attachment_history_page(
        &self,
        group_id_hex: &str,
        limit: usize,
        cursor: Option<&AttachmentHistoryCursor>,
    ) -> Result<AttachmentHistoryPage, AttachmentHistoryError> {
        if !(1..=100).contains(&limit) {
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
                if cursor.version != version {
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
                    let json: String = r.get(12)?;
                    let entry = AttachmentHistoryEntry {
                        message_id_hex: key.message.clone(),
                        attachment_index: usize::try_from(nonnegative(r, 6)?)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, i64::MAX))?,
                        source_message_id_hex: r.get(7)?,
                        source_epoch: r
                            .get::<_, Option<i64>>(8)?
                            .map(|v| {
                                u64::try_from(v)
                                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(8, v))
                            })
                            .transpose()?,
                        sender: r.get(9)?,
                        timeline_at: nonnegative(r, 10)?,
                        received_at: nonnegative(r, 11)?,
                        slot: serde_json::from_str(&json).unwrap_or(serde_json::Value::Null),
                    };
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

#[cfg(test)]
mod tests;
