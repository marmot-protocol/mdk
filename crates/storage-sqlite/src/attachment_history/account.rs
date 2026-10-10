//! Bounded account-local attachment discovery over the existing canonical slot index.
use super::*;

/// Empty selections mean every group/sender. Selections compose with inclusive date bounds.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AccountAttachmentQuery {
    pub groups: Vec<String>,
    pub senders: Vec<String>,
    pub after: Option<u64>,
    pub before: Option<u64>,
}
impl std::fmt::Debug for AccountAttachmentQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttachmentQuery")
            .finish_non_exhaustive()
    }
}
impl AccountAttachmentQuery {
    fn canonical(&self) -> Result<Self, AccountAttachmentHistoryError> {
        if self.groups.len() > 100
            || self.senders.len() > 100
            || self.after.is_some_and(|v| v > i64::MAX as u64)
            || self.before.is_some_and(|v| v > i64::MAX as u64)
            || matches!((self.after,self.before),(Some(a),Some(b)) if a>b)
        {
            return Err(AccountAttachmentHistoryError::InvalidQuery);
        }
        let mut result = self.clone();
        for group in &mut result.groups {
            if group.is_empty() || group.len() > 512 || hex::decode(&*group).is_err() {
                return Err(AccountAttachmentHistoryError::InvalidQuery);
            }
            group.make_ascii_lowercase();
        }
        for sender in &mut result.senders {
            if sender.len() != 64 || hex::decode(&*sender).is_err() {
                return Err(AccountAttachmentHistoryError::InvalidQuery);
            }
            sender.make_ascii_lowercase();
        }
        result.groups.sort();
        result.groups.dedup();
        result.senders.sort();
        result.senders.dedup();
        Ok(result)
    }
    fn accepts(&self, group: &str, sender: &str) -> bool {
        (self.groups.is_empty()
            || self
                .groups
                .binary_search_by(|v| v.as_str().cmp(group))
                .is_ok())
            && (self.senders.is_empty()
                || self
                    .senders
                    .binary_search_by(|v| v.as_str().cmp(sender))
                    .is_ok())
    }
}

#[derive(Clone)]
pub struct AccountAttachmentVersion {
    store_epoch: Vec<u8>,
    revision: i64,
    additions: i64,
    expiry_watermark: Option<u64>,
    pub next_expiry: Option<u64>,
}
impl PartialEq for AccountAttachmentVersion {
    fn eq(&self, other: &Self) -> bool {
        self.store_epoch == other.store_epoch
            && self.revision == other.revision
            && self.additions == other.additions
            && self.expiry_watermark == other.expiry_watermark
    }
}
impl Eq for AccountAttachmentVersion {}
impl AccountAttachmentVersion {
    /// Source/visibility/incarnation changes invalidate loaded rows; additions advertise a separate refresh.
    pub fn requires_restart_since(&self, previous: &Self) -> bool {
        self.store_epoch != previous.store_epoch
            || self.revision != previous.revision
            || self.expiry_watermark != previous.expiry_watermark
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AccountAttachmentCursor {
    version: AccountAttachmentVersion,
    query: AccountAttachmentQuery,
    key: (i64, String, String, i64),
}
macro_rules! private_formatter {
    ($ty:ty,$name:literal) => {
        impl std::fmt::Debug for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct($name).finish_non_exhaustive()
            }
        }
    };
}
private_formatter!(AccountAttachmentVersion, "AccountAttachmentVersion");
private_formatter!(AccountAttachmentCursor, "AccountAttachmentCursor");
#[derive(Clone)]
pub struct AccountAttachmentEntry {
    pub metadata_limited: bool,
    pub group_id_hex: String,
    pub attachment: AttachmentHistoryEntry,
}
#[derive(Clone, Debug)]
pub struct AccountAttachmentPage {
    pub entries: Vec<AccountAttachmentEntry>,
    pub version: AccountAttachmentVersion,
    pub next_cursor: Option<AccountAttachmentCursor>,
}
#[derive(Debug, thiserror::Error)]
pub enum AccountAttachmentHistoryError {
    #[error("invalid account attachment query")]
    InvalidQuery,
    #[error("attachment page limit must be between 1 and 100")]
    InvalidLimit,
    #[error("attachment cursor belongs to another account or query")]
    CursorMismatch,
    #[error("attachment history changed; restart")]
    RestartRequired,
    #[error("attachment metadata exceeds response bounds")]
    ResponseTooLarge,
    #[error(transparent)]
    Storage(#[from] StorageError),
}
fn clock() -> Result<u64, AccountAttachmentHistoryError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| StorageError::Backend("local clock unavailable".into()).into())
}
fn version(
    conn: &Connection,
    now: u64,
) -> Result<AccountAttachmentVersion, AccountAttachmentHistoryError> {
    let now = i64::try_from(now).map_err(|_| AccountAttachmentHistoryError::InvalidQuery)?;
    Ok(AccountAttachmentVersion {
        store_epoch: conn
            .query_row_cached(
                "SELECT store_epoch FROM chat_presentation_meta WHERE id=1",
                [],
                |r| r.get(0),
            )
            .storage()?,
        revision: conn
            .query_row_cached(
                "SELECT revision FROM account_attachment_history_version WHERE id=1",
                [],
                |r| r.get(0),
            )
            .storage()?,
        additions: conn
            .query_row_cached(
                "SELECT additions FROM account_attachment_history_version WHERE id=1",
                [],
                |r| r.get(0),
            )
            .storage()?,
        expiry_watermark: conn.query_row_cached("SELECT max(retention_expires_at) FROM attachment_history WHERE visible=1 AND retention_expires_at IS NOT NULL AND retention_expires_at<=?1",[now],|r|r.get::<_,Option<i64>>(0)).storage()?.map(|v|u64::try_from(v).map_err(|_|AccountAttachmentHistoryError::InvalidQuery)).transpose()?,
        next_expiry: conn.query_row_cached("SELECT min(retention_expires_at) FROM attachment_history WHERE visible=1 AND retention_expires_at IS NOT NULL AND retention_expires_at>?1",[now],|r|r.get::<_,Option<i64>>(0)).storage()?.map(|v|u64::try_from(v).map_err(|_|AccountAttachmentHistoryError::InvalidQuery)).transpose()?,
    })
}
const MAX_SLOT_BYTES: usize = 32 * 1024;
const MAX_PAGE_BYTES: usize = 512 * 1024;
fn sql(seek: bool) -> String {
    let seek = if seek {
        " AND (timeline_at,group_id_hex,message_id_hex,attachment_order)<(?4,?5,?6,?7)"
    } else {
        ""
    };
    format!("SELECT 0,timeline_at,0,timeline_at,message_id_hex,attachment_order,
        attachment_index,source_message_id_hex,source_epoch,sender,timeline_at,received_at,
        substr(slot_json,1,32769),substr((SELECT json_group_array(json(e.value)) FROM message_timeline t,
            json_each(CASE WHEN json_valid(t.tags_json) THEN CASE WHEN json_type(t.tags_json)='array' THEN t.tags_json ELSE '[]' END ELSE '[]' END)e
            WHERE t.group_id_hex=h.group_id_hex AND t.message_id_hex=h.message_id_hex
            AND CASE WHEN e.type='array' THEN json_extract(e.value,'$[0]')='emoji' ELSE 0 END),1,32769),group_id_hex,retention_expires_at
        FROM attachment_history h INDEXED BY idx_account_attachment_history_page
        WHERE visible=1 AND timeline_at>=?1 AND timeline_at<=?2{seek}
        ORDER BY timeline_at DESC,group_id_hex DESC,message_id_hex DESC,attachment_order DESC LIMIT ?3")
}
impl SqliteAccountStorage {
    /// Constant-work local refresh token. Source/visibility/role changes invalidate account cursors; additions advertise refresh.
    pub fn account_attachment_history_version(
        &self,
    ) -> Result<AccountAttachmentVersion, AccountAttachmentHistoryError> {
        self.account_attachment_history_version_at(clock()?)
    }
    /// Same-clock snapshot composition for bounded acquisition projections and retention tests.
    pub(crate) fn account_attachment_history_version_at(
        &self,
        now: u64,
    ) -> Result<AccountAttachmentVersion, AccountAttachmentHistoryError> {
        self.connection
            .with_deferred_read(|conn| version(conn, now))
    }
    /// Seek at most `limit` candidate slots, then apply group/sender selection without an account-wide filter scan.
    /// A filtered empty page may have a continuation. Never infer exhaustion from entries.len().
    /// The cursor binds account incarnation and canonical query; destructive changes require replacing loaded rows.
    /// Reads start no acquisition and return no message bodies. Metadata is bounded to 32 KiB per field / 512 KiB per page.
    pub fn account_attachment_history_page(
        &self,
        query: &AccountAttachmentQuery,
        limit: usize,
        cursor: Option<&AccountAttachmentCursor>,
    ) -> Result<AccountAttachmentPage, AccountAttachmentHistoryError> {
        if !(1..=100).contains(&limit) {
            return Err(AccountAttachmentHistoryError::InvalidLimit);
        }
        let now = clock()?;
        self.account_attachment_history_page_at(query, limit, cursor, now)
    }
    /// Clock-injected read for deterministic retention qualification.
    pub(crate) fn account_attachment_history_page_at(
        &self,
        query: &AccountAttachmentQuery,
        limit: usize,
        cursor: Option<&AccountAttachmentCursor>,
        now: u64,
    ) -> Result<AccountAttachmentPage, AccountAttachmentHistoryError> {
        if !(1..=100).contains(&limit) {
            return Err(AccountAttachmentHistoryError::InvalidLimit);
        }
        let query = query.canonical()?;
        self.connection.with_deferred_read(|conn| {
            let version = version(conn, now)?;
            if let Some(cursor) = cursor {
                if cursor.version.store_epoch != version.store_epoch || cursor.query != query {
                    return Err(AccountAttachmentHistoryError::CursorMismatch);
                }
                if version.requires_restart_since(&cursor.version) {
                    return Err(AccountAttachmentHistoryError::RestartRequired);
                }
            }
            let mut values = vec![
                Value::Integer(query.after.unwrap_or(0) as i64),
                Value::Integer(query.before.unwrap_or(i64::MAX as u64) as i64),
                Value::Integer((limit + 1) as i64),
            ];
            if let Some(cursor) = cursor {
                values.extend([
                    Value::Integer(cursor.key.0),
                    Value::Text(cursor.key.1.clone()),
                    Value::Text(cursor.key.2.clone()),
                    Value::Integer(cursor.key.3),
                ]);
            }
            let mut stmt = conn.prepare_cached(&sql(cursor.is_some())).storage()?;
            // No metadata read for the extra look-ahead row; it proves continuation only.
            let mut rows = stmt.query(params_from_iter(values)).storage()?;
            let mut entries = Vec::new();
            let mut key = None;
            let mut seen = 0;
            let mut more = false;
            let mut bytes = 0;
            while let Some(row) = rows.next().storage()? {
                if seen == limit {
                    more = true;
                    break;
                }
                seen += 1;
                let group: String = row.get(14).storage()?;
                let sender: String = row.get(9).storage()?;
                let current_key = (
                    row.get(1).storage()?,
                    group.clone(),
                    row.get(4).storage()?,
                    row.get(5).storage()?,
                );
                let expiry: Option<i64> = row.get(15).storage()?;
                if expiry.is_some_and(|v| v < 0 || v as u64 <= now)
                    || !query.accepts(&group, &sender)
                {
                    key = Some(current_key);
                    continue;
                }
                let slot: String = row.get(12).storage()?;
                let emojis: String = row.get(13).storage()?;
                let metadata_limited = slot.len() > MAX_SLOT_BYTES || emojis.len() > MAX_SLOT_BYTES;
                let cost = if metadata_limited {
                    group.len() + sender.len() + 256
                } else {
                    slot.len() + emojis.len() + group.len() + sender.len() + 256
                };
                if bytes + cost > MAX_PAGE_BYTES {
                    more = true;
                    break;
                }
                bytes += cost;
                let attachment = if metadata_limited {
                    entry_with_metadata(row, serde_json::Value::Null, Vec::new()).storage()?
                } else {
                    entry_from_row(row).storage()?
                };
                entries.push(AccountAttachmentEntry {
                    group_id_hex: group,
                    attachment,
                    metadata_limited,
                });
                key = Some(current_key);
            }
            Ok(AccountAttachmentPage {
                entries,
                next_cursor: key.filter(|_| more).map(|key| AccountAttachmentCursor {
                    version: version.clone(),
                    query,
                    key,
                }),
                version,
            })
        })
    }
}

impl std::fmt::Debug for AccountAttachmentEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountAttachmentEntry")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
