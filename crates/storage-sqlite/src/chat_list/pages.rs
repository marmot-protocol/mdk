//! Account-local navigation over the four chat lists. Runtime windows own live reconciliation.
//!
//! Migration 0070 maintains disposable query keys on `chat_list_rows` from account membership,
//! archive/invitation state, row read intent, pin order and engine operation/tombstone tables.
//! Left takes precedence over archive, including durable leave and active disband intent.
//! Engine records remain authoritative: the returned leaving/disbanding state is read through
//! using indexed keyed lookups in the same deferred transaction as the page.
//!
//! This is M1 of #1777. It intentionally does not change legacy APIs or implement runtime
//! subscriptions, selected-presentation preparation, rejoin/archive command orchestration,
//! effective screen badge values, account summaries or native bindings. Those follow in M2-M4.
//! Legacy summary eligibility is deliberately unchanged in M1; M3 must reuse list_scope = 0
//! and list_unread instead of adding another archive/terminal/invitation predicate.
use crate::connection::CachedSql;
use crate::{ChatListRow, SqliteAccountStorage, SqliteResultExt, deserialize};
use cgka_traits::storage::StorageError;
use cgka_traits::storage::{DisbandRequest, DisbandRequestStatus, LeaveRequest};
use rusqlite::{Connection, OptionalExtension, params_from_iter, types::Value};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatListView {
    /// Active, unarchived chats, including pending invitations.
    Chats,
    /// Chats with message or manual unread, excluding pending invitations.
    Unread,
    /// Archived chats that do not qualify for Left.
    Archived,
    /// Departed/disbanded groups and durably queued leave/active disband operations.
    Left,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatListPageDirection {
    Forward,
    Backward,
}

/// Opaque account-local boundary. Not a resumable cross-restart sync token.
/// Any navigation change in this account invalidates it, including changes in another view.
/// Staleness is normal under traffic: runtime windows must reconcile using stable anchors,
/// not retry the same cursor or append an independently recovered page to an old window.
#[derive(Clone, PartialEq, Eq)]
pub struct ChatListCursor {
    store_epoch: Vec<u8>,
    revision: i64,
    view: ChatListView,
    key: SortKey,
}

#[derive(Clone, PartialEq, Eq)]
struct SortKey {
    section: i64,
    pin: i64,
    activity: i64,
    group: String,
}

const KEY: &str = "(list_pin_section, list_pin_order, list_activity_order, group_id_hex)";
const KEY_COLUMNS: &str = "list_pin_section, list_pin_order, list_activity_order, group_id_hex";
const REVERSE: &str =
    "list_pin_section DESC, list_pin_order DESC, list_activity_order DESC, group_id_hex DESC";
impl ChatListView {
    fn predicate(self) -> &'static str {
        match self {
            Self::Chats => "list_scope = 0",
            Self::Unread => "list_scope = 0 AND list_unread = 1",
            Self::Archived => "list_scope = 1",
            Self::Left => "list_scope = 2",
        }
    }
    fn index(self) -> &'static str {
        if self == Self::Unread {
            "idx_chat_list_unread_page"
        } else {
            "idx_chat_list_page"
        }
    }
}

fn navigation_sql(
    view: ChatListView,
    relation: Option<&str>,
    direction: ChatListPageDirection,
    exists: bool,
) -> String {
    let boundary = relation
        .map(|op| format!(" AND {KEY} {op} (?1, ?2, ?3, ?4)"))
        .unwrap_or_default();
    let from = format!(
        "FROM chat_list_rows INDEXED BY {} WHERE {}{boundary}",
        view.index(),
        view.predicate()
    );
    if exists {
        return format!("SELECT EXISTS(SELECT 1 {from})");
    }
    let order = if direction == ChatListPageDirection::Forward {
        KEY_COLUMNS
    } else {
        REVERSE
    };
    format!(
        "SELECT {KEY_COLUMNS} {from} ORDER BY {order} LIMIT ?{}",
        if relation.is_some() { 5 } else { 1 }
    )
}

fn key_params(key: &SortKey) -> Vec<Value> {
    vec![
        key.section.into(),
        key.pin.into(),
        key.activity.into(),
        key.group.clone().into(),
    ]
}

fn has_rows(
    tx: &Connection,
    view: ChatListView,
    key: &SortKey,
    relation: &str,
) -> Result<bool, ChatListPageError> {
    Ok(tx
        .query_row_cached(
            &navigation_sql(view, Some(relation), ChatListPageDirection::Forward, true),
            params_from_iter(key_params(key)),
            |r| r.get(0),
        )
        .storage()?)
}

impl std::fmt::Debug for ChatListCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatListCursor").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct ChatListPageQuery {
    pub view: ChatListView,
    pub limit: usize,
    pub direction: ChatListPageDirection,
    pub cursor: Option<ChatListCursor>,
}

#[derive(Clone)]
pub struct ChatListPage {
    pub rows: Vec<ChatListRow>,
    pub first: Option<ChatListCursor>,
    pub last: Option<ChatListCursor>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ChatListPageError {
    #[error("chat page limit must be between 1 and 100")]
    InvalidLimit,
    #[error("chat cursor belongs to a different account store or view")]
    CursorMismatch,
    #[error("chat list ordering or membership changed; refresh the window")]
    StaleCursor,
    #[error("chat anchor is absent or no longer matches the selected view")]
    AnchorUnavailable,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl SqliteAccountStorage {
    /// Recover around a stable row after cursor invalidation, without replaying earlier pages.
    /// Includes the anchor at the beginning (Forward) or end (Backward) of the returned page.
    /// Anchor lookup, fresh boundaries and page read are one transaction, so unrelated traffic
    /// cannot invalidate the operation between resolving the anchor and reading its neighbors.
    /// An absent/nonmatching anchor returns AnchorUnavailable; the runtime can try a retained
    /// neighboring identity without inferring disappearance from an empty successful page.
    pub fn chat_list_page_from_anchor(
        &self,
        view: ChatListView,
        group: &str,
        limit: usize,
        direction: ChatListPageDirection,
    ) -> Result<ChatListPage, ChatListPageError> {
        self.read_chat_list_page(
            ChatListPageQuery {
                view,
                limit,
                direction,
                cursor: None,
            },
            Some(group),
        )
    }
    /// Read a raw storage page in one deferred transaction, without writes, preparation,
    /// network work, full-list hydration or unrelated lifecycle record decoding.
    /// Limits are 1..=100. With no cursor, Forward starts at the top and Backward at the end.
    /// Returned rows always follow display order. Any membership/order change conservatively
    /// invalidates existing cursors; runtime windows must refresh, never splice stale pages.
    /// Raw read intent is preserved here; screen-effective badge suppression belongs to the
    /// additive presented window contract, not a mutation of stored unread state.
    pub fn chat_list_page(
        &self,
        query: ChatListPageQuery,
    ) -> Result<ChatListPage, ChatListPageError> {
        self.read_chat_list_page(query, None)
    }
    fn read_chat_list_page(
        &self,
        mut query: ChatListPageQuery,
        anchor: Option<&str>,
    ) -> Result<ChatListPage, ChatListPageError> {
        if !(1..=100).contains(&query.limit) {
            return Err(ChatListPageError::InvalidLimit);
        }
        let conn = self.lock()?;
        let tx = conn.unchecked_transaction().storage()?;
        let (store_epoch, revision): (Vec<u8>, i64) = tx.query_row_cached(
            "SELECT p.store_epoch, n.revision FROM chat_presentation_meta p, chat_list_navigation_meta n WHERE p.id = 1 AND n.id = 1",
            [], |r|Ok((r.get(0)?, r.get(1)?))).storage()?;
        if let Some(cursor) = &query.cursor {
            if cursor.store_epoch != store_epoch || cursor.view != query.view {
                return Err(ChatListPageError::CursorMismatch);
            }
            if cursor.revision != revision {
                return Err(ChatListPageError::StaleCursor);
            }
        }
        if let Some(group) = anchor {
            let key = tx
                .query_row_cached(
                    &format!(
                        "SELECT {KEY_COLUMNS} FROM chat_list_rows WHERE group_id_hex = ?1 AND {}",
                        query.view.predicate()
                    ),
                    [group],
                    |r| {
                        Ok(SortKey {
                            section: r.get(0)?,
                            pin: r.get(1)?,
                            activity: r.get(2)?,
                            group: r.get(3)?,
                        })
                    },
                )
                .optional()
                .storage()?
                .ok_or(ChatListPageError::AnchorUnavailable)?;
            query.cursor = Some(ChatListCursor {
                store_epoch: store_epoch.clone(),
                revision,
                view: query.view,
                key,
            });
        }
        let relation = query
            .cursor
            .as_ref()
            .map(|_| match (query.direction, anchor.is_some()) {
                (ChatListPageDirection::Forward, true) => ">=",
                (ChatListPageDirection::Forward, false) => ">",
                (ChatListPageDirection::Backward, true) => "<=",
                (ChatListPageDirection::Backward, false) => "<",
            });
        let mut parameters = query
            .cursor
            .as_ref()
            .map(|c| key_params(&c.key))
            .unwrap_or_default();
        parameters.push((query.limit as i64).into());
        let mut statement = tx
            .prepare_cached(&navigation_sql(
                query.view,
                relation,
                query.direction,
                false,
            ))
            .storage()?;
        let mut keys = statement
            .query_map(params_from_iter(parameters), |r| {
                Ok(SortKey {
                    section: r.get(0)?,
                    pin: r.get(1)?,
                    activity: r.get(2)?,
                    group: r.get(3)?,
                })
            })
            .storage()?
            .collect::<rusqlite::Result<Vec<_>>>()
            .storage()?;
        drop(statement);
        if query.direction == ChatListPageDirection::Backward {
            keys.reverse();
        }
        let cursor = |key: &SortKey| ChatListCursor {
            store_epoch: store_epoch.clone(),
            revision,
            view: query.view,
            key: key.clone(),
        };
        let first = keys.first().map(&cursor);
        let last = keys.last().map(cursor);
        let (has_more_before, has_more_after) = match (keys.first(), keys.last()) {
            (Some(first), Some(last)) => (
                has_rows(&tx, query.view, first, "<")?,
                has_rows(&tx, query.view, last, ">")?,
            ),
            _ => match &query.cursor {
                Some(c) if query.direction == ChatListPageDirection::Forward => {
                    (has_rows(&tx, query.view, &c.key, "<=")?, false)
                }
                Some(c) => (false, has_rows(&tx, query.view, &c.key, ">=")?),
                None => (false, false),
            },
        };
        let rows = page_rows(&tx, &keys)?;
        tx.commit().storage()?;
        Ok(ChatListPage {
            rows,
            first,
            last,
            has_more_before,
            has_more_after,
        })
    }
}

fn page_rows_sql() -> String {
    // One bounded batch for row data and operation overlays. Keep expression indexes:
    // batching alone would still scan unrelated engine records without indexed joins.
    // json_each supplies at most 100 keys; row order is restored from navigation below.
    format!(
        "{} row.list_pin_position,
            leave_request.record AS page_leave_record,
            disband_request.record AS page_disband_record,
            EXISTS(SELECT 1 FROM cgka_disband_candidates
                WHERE lower(hex(group_id)) = lower(row.group_id_hex)) AS page_candidate
         {} {}
         LEFT JOIN cgka_leave_requests AS leave_request
            ON lower(hex(leave_request.group_id)) = lower(row.group_id_hex)
         LEFT JOIN cgka_disband_requests AS disband_request
            ON lower(hex(disband_request.group_id)) = lower(row.group_id_hex)
         WHERE row.group_id_hex IN (SELECT value FROM json_each(?1))",
        super::CHAT_LIST_PAGE_SELECT_LIST,
        super::CHAT_LIST_ROW_JOINS,
        super::CHAT_PIN_JOIN
    )
}

fn page_rows(tx: &Connection, keys: &[SortKey]) -> Result<Vec<ChatListRow>, ChatListPageError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let ids = keys.iter().map(|key| &key.group).collect::<Vec<_>>();
    let ids_json = serde_json::to_string(&ids)
        .map_err(|_| StorageError::Serialization("chat page key encoding failed".into()))?;
    let mut statement = tx.prepare_cached(&page_rows_sql()).storage()?;
    let now = super::unix_now_ms();
    let records = statement
        .query_map([ids_json], |r| {
            Ok((
                super::chat_list_row_from_row(r, now)?,
                r.get::<_, Option<Vec<u8>>>("page_leave_record")?,
                r.get::<_, Option<Vec<u8>>>("page_disband_record")?,
                r.get::<_, bool>("page_candidate")?,
            ))
        })
        .storage()?;
    let mut rows = HashMap::with_capacity(keys.len());
    for record in records {
        let (mut row, leave, disband, candidate) = record.storage()?;
        row.leave_requested_at_ms = leave
            .map(|b| deserialize::<LeaveRequest>(&b).map(|r| r.requested_at_ms))
            .transpose()?;
        row.disband_request = disband
            .map(|b| deserialize::<DisbandRequest>(&b))
            .transpose()?;
        row.disbanding = candidate
            || row
                .disband_request
                .as_ref()
                .is_some_and(|r| r.status == DisbandRequestStatus::Pending);
        rows.insert(row.group_id_hex.clone(), row);
    }
    keys.iter()
        .map(|key| {
            rows.remove(&key.group).ok_or_else(|| {
                StorageError::Backend("chat page row missing in read snapshot".into()).into()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
