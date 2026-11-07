//! Account-local navigation over the four chat lists. Runtime windows own live reconciliation.
//!
//! Every read happens inside one snapshot: the runtime window composes keyset seeks from a
//! resolved anchor in a single deferred transaction (`window.rs`). There is no cursor that
//! survives across reads; a window re-reads around a stable chat id instead.
//!
//! Migration 0072 maintains disposable query keys on `chat_list_rows` from account membership,
//! archive/invitation state, row read intent, pin order and engine operation/tombstone tables.
//! Left takes precedence over archive, including durable leave and active disband intent.
//! Engine records remain authoritative: the returned leaving/disbanding state is read through
//! using indexed keyed lookups in the same deferred transaction as the page.
//!
//! This is M1 of #1777. It intentionally does not change legacy APIs or implement runtime
//! subscriptions, selected-presentation preparation, rejoin/archive command orchestration,
//! effective screen badge values, account summaries or native bindings. Those follow in M2-M4.
//! Account attention reuses these keys and additionally counts active pending invitations;
//! the Unread list continues to exclude invitations.
use super::query::{ChatListQueryError, ChatListViewQuery, CompiledQuery};
use crate::base::connection::CachedSql;
use crate::{ChatListRow, SqliteResultExt, deserialize};
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

/// A row's position in display order. Valid only inside the read snapshot that produced it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SortKey {
    section: i64,
    pin: i64,
    activity: i64,
    group: String,
}

const KEY: &str = "(list_pin_section, list_pin_order, list_activity_order, group_id_hex)";
pub(super) const KEY_COLUMNS: &str =
    "list_pin_section, list_pin_order, list_activity_order, group_id_hex";
const REVERSE: &str =
    "list_pin_section DESC, list_pin_order DESC, list_activity_order DESC, group_id_hex DESC";
impl ChatListView {
    pub(super) fn predicate(self) -> &'static str {
        match self {
            Self::Chats => {
                "list_scope = 0 AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)"
            }
            Self::Unread => {
                "list_scope = 0 AND list_unread = 1 AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)"
            }
            Self::Archived => {
                "list_scope = 1 AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)"
            }
            Self::Left => {
                "list_scope = 2 AND group_id_hex NOT IN (SELECT group_id_hex FROM blocked_pending_invites)"
            }
        }
    }
    pub(super) fn index(self) -> &'static str {
        if self == Self::Unread {
            "idx_chat_list_unread_page"
        } else {
            "idx_chat_list_page"
        }
    }
}

// Filter parameters come first (`?1..?n`); boundary keys and the limit follow.
fn navigation_sql(
    query: &CompiledQuery,
    relation: Option<&str>,
    direction: ChatListPageDirection,
    exists: bool,
) -> String {
    let n = query.params.len();
    let boundary = relation
        .map(|op| {
            format!(
                " AND {KEY} {op} (?{}, ?{}, ?{}, ?{})",
                n + 1,
                n + 2,
                n + 3,
                n + 4
            )
        })
        .unwrap_or_default();
    let from = format!(
        "FROM chat_list_rows INDEXED BY {} WHERE {}{boundary}",
        query.view.index(),
        query.predicate
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
        n + if relation.is_some() { 5 } else { 1 }
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
    query: &CompiledQuery,
    key: &SortKey,
    relation: &str,
) -> Result<bool, ChatListPageError> {
    Ok(tx
        .query_row_cached(
            &navigation_sql(query, Some(relation), ChatListPageDirection::Forward, true),
            params_from_iter(query.params.iter().cloned().chain(key_params(key))),
            |r| r.get(0),
        )
        .storage()?)
}

/// One keyset seek inside a caller-held read snapshot. `boundary` comes from a page read
/// in the same snapshot; with none, Forward starts at the top and Backward at the end.
#[derive(Clone)]
pub(crate) struct PageQuery {
    pub(crate) query: ChatListViewQuery,
    pub(crate) limit: usize,
    pub(crate) direction: ChatListPageDirection,
    pub(crate) boundary: Option<SortKey>,
    /// The read's time (Unix ms): the `Muted` leaf and each row's `muted` use it.
    pub(crate) now_ms: i64,
}

#[derive(Clone)]
pub struct ChatListPage {
    pub rows: Vec<ChatListRow>,
    pub(crate) first: Option<SortKey>,
    pub(crate) last: Option<SortKey>,
    pub has_more_before: bool,
    pub has_more_after: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ChatListPageError {
    #[error(
        "chat window requires 1 to 200 rows, at most 200 anchors, and an anchor position within the window"
    )]
    InvalidWindowQuery,
    #[error("chat anchor is absent or no longer matches the selected query")]
    AnchorUnavailable,
    /// The query has a `Text` leaf and a chat in its view still has its
    /// presentation (and so its search text) pending. Nothing was read.
    #[error("chat-list search text is not ready")]
    SearchTextNotReady,
    #[error(transparent)]
    InvalidQuery(#[from] ChatListQueryError),
    #[error(transparent)]
    Storage(#[from] StorageError),
}

// The caller holds the connection guard and owns the snapshot. Runtime-window
// reads compose multiple seeks here without releasing it between boundaries.
// An anchor seek includes the anchor at the start (Forward) or end (Backward) of the page.
// An absent or nonmatching anchor returns AnchorUnavailable.
pub(super) fn read_page_tx(
    tx: &Connection,
    mut query: PageQuery,
    anchor: Option<&str>,
) -> Result<ChatListPage, ChatListPageError> {
    let compiled = query
        .query
        .compile(query.now_ms, super::query::QueryScope::Window)?;
    if let Some(group) = anchor {
        let key = tx
                .query_row_cached(
                    &format!(
                        "SELECT {KEY_COLUMNS} FROM chat_list_rows WHERE {} AND lower(group_id_hex) = lower(?{})",
                        compiled.predicate,
                        compiled.params.len() + 1
                    ),
                    params_from_iter(compiled.params.iter().cloned().chain([Value::from(group.to_owned())])),
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
        query.boundary = Some(key);
    }
    let relation = query
        .boundary
        .as_ref()
        .map(|_| match (query.direction, anchor.is_some()) {
            (ChatListPageDirection::Forward, true) => ">=",
            (ChatListPageDirection::Forward, false) => ">",
            (ChatListPageDirection::Backward, true) => "<=",
            (ChatListPageDirection::Backward, false) => "<",
        });
    let mut parameters = compiled.params.clone();
    parameters.extend(query.boundary.as_ref().map(key_params).unwrap_or_default());
    parameters.push((query.limit as i64).into());
    let mut statement = tx
        .prepare_cached(&navigation_sql(&compiled, relation, query.direction, false))
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
    let first = keys.first().cloned();
    let last = keys.last().cloned();
    let (has_more_before, has_more_after) = match (keys.first(), keys.last()) {
        (Some(first), Some(last)) => (
            has_rows(tx, &compiled, first, "<")?,
            has_rows(tx, &compiled, last, ">")?,
        ),
        _ => match &query.boundary {
            Some(key) if query.direction == ChatListPageDirection::Forward => {
                (has_rows(tx, &compiled, key, "<=")?, false)
            }
            Some(key) => (false, has_rows(tx, &compiled, key, ">=")?),
            None => (false, false),
        },
    };
    let rows = page_rows(tx, &keys, query.now_ms)?;
    Ok(ChatListPage {
        rows,
        first,
        last,
        has_more_before,
        has_more_after,
    })
}

fn page_rows_sql() -> String {
    // One bounded batch for row data and operation overlays. Keep expression indexes:
    // batching alone would still scan unrelated engine records without indexed joins.
    // json_each supplies at most 200 keys (the window cap); row order is restored from navigation below.
    format!(
        "{} row.list_pin_position AS pinned_position,
            {}
         {} {}
         {}
         WHERE row.group_id_hex IN (SELECT value FROM json_each(?1))",
        super::CHAT_LIST_PAGE_SELECT_LIST,
        crate::cross::views::CHAT_LIST_PAGE_ENGINE_COLUMNS,
        super::CHAT_LIST_ROW_JOINS,
        super::CHAT_PIN_JOIN,
        crate::cross::views::CHAT_LIST_PAGE_ENGINE_JOINS,
    )
}

fn page_rows(
    tx: &Connection,
    keys: &[SortKey],
    now: i64,
) -> Result<Vec<ChatListRow>, ChatListPageError> {
    if keys.is_empty() {
        return Ok(Vec::new());
    }
    let ids = keys.iter().map(|key| &key.group).collect::<Vec<_>>();
    let ids_json = serde_json::to_string(&ids)
        .map_err(|_| StorageError::Serialization("chat page key encoding failed".into()))?;
    let mut statement = tx.prepare_cached(&page_rows_sql()).storage()?;
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
