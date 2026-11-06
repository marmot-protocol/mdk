//! Atomic bounded navigation plus selected presentation for runtime-owned windows.
use super::pages::{PageQuery, read_page_tx};
use super::query::{ChatListCondition, ChatListViewQuery};
use crate::base::connection::CachedSql;
use crate::{
    ChatListPage, ChatListPageDirection, ChatListPageError, ChatPresentationVersion,
    PresentedChatListSnapshot, PresentedChatRow, SqliteAppStorage, SqliteResultExt,
};
use rusqlite::{Connection, OptionalExtension, params_from_iter, types::Value};

/// Internal foundation for a live runtime window; callers never splice old pages.
#[derive(Clone)]
pub struct ChatListWindowQuery {
    pub query: ChatListViewQuery,
    /// 1..=200 retained rows.
    pub limit: usize,
    /// Preferred stable anchor, followed by fallback neighbors, at most 200 keys.
    pub anchors: Vec<String>,
    pub before_anchor: usize,
    /// The read's time (Unix ms). A `Muted` leaf tests mute expiry against it,
    /// and each row's `muted` is evaluated at it, so rows and filter agree.
    pub now_ms: i64,
}

pub struct ChatListWindowRead {
    pub page: ChatListPage,
    pub snapshot: Option<PresentedChatListSnapshot>,
    /// Only these selected values need local preparation. No unrelated backfill barrier.
    pub pending_presentations: Vec<String>,
    pub anchor: Option<String>,
    /// For a query that tests `Muted`: the earliest mute expiry after `now_ms`
    /// among the chats in its view, visible or not. A live window re-reads then,
    /// when such a chat enters or leaves the query's matches.
    pub next_mute_expiry_ms: Option<i64>,
}

impl SqliteAppStorage {
    /// Rows, selections, boundaries and anchor choice share one read snapshot. Work is
    /// bounded by the window and retained fallback keys, never account size or history.
    /// Missing legacy base rows report NotFound rather than claiming a complete empty list;
    /// the existing bounded maintenance worker initializes those rows before a retry.
    pub fn read_chat_list_window(
        &self,
        query: ChatListWindowQuery,
    ) -> Result<ChatListWindowRead, ChatListPageError> {
        if !(1..=200).contains(&query.limit)
            || query.anchors.len() > 200
            || query.before_anchor >= query.limit
        {
            return Err(ChatListPageError::InvalidWindowQuery);
        }
        // A malformed query is a typed error, never a readiness wait.
        query.query.validate()?;
        self.connection.with_deferred_read(|conn| {
            let missing_base: bool = conn
                .query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM chat_presentation_row_work)",
                    [],
                    |r| r.get(0),
                )
                .storage()?;
            if missing_base {
                return Err(cgka_traits::storage::StorageError::NotFound.into());
            }
            let anchor = choose_anchor(conn, &query)?;
            let mut page = match &anchor {
                Some(anchor) => {
                    let mut before = read_page_tx(
                        conn,
                        PageQuery {
                            query: query.query.clone(),
                            limit: query.before_anchor + 1,
                            direction: ChatListPageDirection::Backward,
                            boundary: None,
                            now_ms: query.now_ms,
                        },
                        Some(anchor),
                    )?;
                    let remaining = query.limit - before.rows.len();
                    if remaining > 0 {
                        let after = read_page_tx(
                            conn,
                            PageQuery {
                                query: query.query.clone(),
                                limit: remaining,
                                direction: ChatListPageDirection::Forward,
                                boundary: before.last.clone(),
                                now_ms: query.now_ms,
                            },
                            None,
                        )?;
                        before.has_more_after = after.has_more_after;
                        if after.last.is_some() {
                            before.last = after.last;
                        }
                        before.rows.extend(after.rows);
                    }
                    before
                }
                None => read_page_tx(
                    conn,
                    PageQuery {
                        query: query.query.clone(),
                        limit: query.limit,
                        direction: ChatListPageDirection::Forward,
                        boundary: None,
                        now_ms: query.now_ms,
                    },
                    None,
                )?,
            };
            // Near the end fill unused capacity from before the window, retaining the anchor.
            // has_more_before excludes empty pages: a boundaryless backward read would
            // otherwise restart from the wrong end of the list.
            if page.rows.len() < query.limit && page.has_more_before {
                let mut before = read_page_tx(
                    conn,
                    PageQuery {
                        query: query.query.clone(),
                        limit: query.limit - page.rows.len(),
                        direction: ChatListPageDirection::Backward,
                        boundary: page.first.clone(),
                        now_ms: query.now_ms,
                    },
                    None,
                )?;
                page.has_more_before = before.has_more_before;
                if before.first.is_some() {
                    page.first = before.first;
                }
                before.rows.extend(page.rows);
                page.rows = before.rows;
            }
            let presentation_version = conn
                .query_row_cached(
                    "SELECT store_epoch, revision FROM chat_presentation_meta WHERE id=1",
                    [],
                    |r| {
                        Ok(ChatPresentationVersion {
                            store_epoch: r.get(0)?,
                            revision: crate::app::chat_presentation::nonnegative(r, 1)?,
                        })
                    },
                )
                .storage()?;
            let mut pending_presentations = Vec::new();
            let mut rows = Vec::with_capacity(page.rows.len());
            let mut statement = conn.prepare_cached("SELECT presentation_json, presentation_applied_source_revision != presentation_source_revision FROM chat_list_rows WHERE group_id_hex=?1").storage()?;
            for row in &page.rows {
                let (bytes, dirty): (Option<Vec<u8>>, bool) = statement
                    .query_row([&row.group_id_hex], |r| Ok((r.get(0)?, r.get(1)?)))
                    .storage()?;
                if let Some(bytes) = bytes {
                    let presentation = crate::app::chat_presentation::decode_retained(&bytes, dirty)?.presentation;
                    let avatar_asset = crate::app::avatar_cache::access::target_presentation(conn, &row.group_id_hex, None, &presentation.avatar, crate::base::codec::unix_now_seconds())?;
                    rows.push(PresentedChatRow {
                        draft_version: crate::app::message_drafts::revisioned::chat_list_version_tx(conn, &row.group_id_hex, &presentation_version.store_epoch)?,
                        preview: crate::app::chat_presentation::row_contract::selected_preview_tx(conn, row)?,
                        actions: crate::ChatListRowActions::for_row(row),
                        row: row.clone(), presentation, avatar_asset
                    });
                } else {
                    pending_presentations.push(row.group_id_hex.clone());
                }
            }
            drop(statement);
            let snapshot = pending_presentations
                .is_empty()
                .then_some(PresentedChatListSnapshot {
                    rows,
                    presentation_version,
                });
            let next_mute_expiry_ms = if query.query.references(ChatListCondition::Muted) {
                next_mute_expiry(conn, &query)?
            } else {
                None
            };
            Ok(ChatListWindowRead {
                page,
                snapshot,
                pending_presentations,
                anchor,
                next_mute_expiry_ms,
            })
        })
    }
}
fn choose_anchor(
    conn: &Connection,
    query: &ChatListWindowQuery,
) -> Result<Option<String>, ChatListPageError> {
    let compiled = query.query.compile(query.now_ms)?;
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT group_id_hex FROM chat_list_rows WHERE {} AND lower(group_id_hex)=lower(?{})",
            compiled.predicate,
            compiled.params.len() + 1
        ))
        .storage()?;
    for key in &query.anchors {
        let params = compiled
            .params
            .iter()
            .cloned()
            .chain([Value::from(key.clone())]);
        if let Some(key) = stmt
            .query_row(params_from_iter(params), |r| r.get(0))
            .optional()
            .storage()?
        {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Earliest timed mute after the read's time among chats in the query's view.
/// The view bounds which chats could ever match; the filter is not applied, so
/// a spare wake only re-reads an unchanged window. Walks the account's mute
/// rows, never message history.
fn next_mute_expiry(
    conn: &Connection,
    query: &ChatListWindowQuery,
) -> Result<Option<i64>, ChatListPageError> {
    // Unqualified view columns resolve to the innermost `chat_list_rows`.
    let sql = format!(
        "SELECT min(mute.muted_until_ms) FROM chat_notification_settings AS mute
         WHERE mute.muted_until_ms > ?1
           AND EXISTS(SELECT 1 FROM chat_list_rows
               WHERE chat_list_rows.group_id_hex = mute.group_id_hex AND {})",
        query.query.view.predicate()
    );
    Ok(conn
        .query_row_cached(&sql, [query.now_ms], |r| r.get(0))
        .storage()?)
}
