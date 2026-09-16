//! Atomic bounded navigation plus selected presentation for runtime-owned windows.
use super::pages::read_page_tx;
use crate::connection::CachedSql;
use crate::{
    ChatListPage, ChatListPageDirection, ChatListPageError, ChatListPageQuery, ChatListView,
    ChatPresentationVersion, PresentedChatListSnapshot, PresentedChatRow, SqliteAccountStorage,
    SqliteResultExt,
};
use rusqlite::{Connection, OptionalExtension};

/// Internal foundation for a live runtime window; callers never splice old pages.
#[derive(Clone)]
pub struct ChatListWindowQuery {
    pub view: ChatListView,
    /// 1..=200 retained rows.
    pub limit: usize,
    /// Preferred stable anchor, followed by fallback neighbors, at most 200 keys.
    pub anchors: Vec<String>,
    pub before_anchor: usize,
}

pub struct ChatListWindowRead {
    pub page: ChatListPage,
    pub snapshot: Option<PresentedChatListSnapshot>,
    /// Only these selected values need local preparation. No unrelated backfill barrier.
    pub pending_presentations: Vec<String>,
    pub anchor: Option<String>,
}

impl SqliteAccountStorage {
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
                        ChatListPageQuery {
                            view: query.view,
                            limit: query.before_anchor + 1,
                            direction: ChatListPageDirection::Backward,
                            cursor: None,
                        },
                        Some(anchor),
                    )?;
                    let remaining = query.limit - before.rows.len();
                    if remaining > 0 {
                        let after = read_page_tx(
                            conn,
                            ChatListPageQuery {
                                view: query.view,
                                limit: remaining,
                                direction: ChatListPageDirection::Forward,
                                cursor: before.last.clone(),
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
                    ChatListPageQuery {
                        view: query.view,
                        limit: query.limit,
                        direction: ChatListPageDirection::Forward,
                        cursor: None,
                    },
                    None,
                )?,
            };
            // Near the end fill unused capacity from before the window, retaining the anchor.
            // has_more_before excludes empty pages: a cursorless backward read would
            // otherwise restart from the wrong end of the list.
            if page.rows.len() < query.limit && page.has_more_before {
                let mut before = read_page_tx(
                    conn,
                    ChatListPageQuery {
                        view: query.view,
                        limit: query.limit - page.rows.len(),
                        direction: ChatListPageDirection::Backward,
                        cursor: page.first.clone(),
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
            let mut pending_presentations = Vec::new();
            let mut rows = Vec::with_capacity(page.rows.len());
            let mut statement = conn.prepare_cached("SELECT presentation_json, presentation_applied_source_revision != presentation_source_revision FROM chat_list_rows WHERE group_id_hex=?1").storage()?;
            for row in &page.rows {
                let (bytes, dirty): (Option<Vec<u8>>, bool) = statement
                    .query_row([&row.group_id_hex], |r| Ok((r.get(0)?, r.get(1)?)))
                    .storage()?;
                if let Some(bytes) = bytes {
                    let presentation = crate::chat_presentation::decode_retained(&bytes, dirty)?.presentation;
                    let avatar_asset = crate::avatar_cache::access::target_presentation(conn, &row.group_id_hex, None, &presentation.avatar, crate::codec::unix_now_seconds())?;
                    rows.push(PresentedChatRow { row: row.clone(), presentation, avatar_asset });
                } else {
                    pending_presentations.push(row.group_id_hex.clone());
                }
            }
            drop(statement);
            let presentation_version = conn
                .query_row_cached(
                    "SELECT store_epoch, revision FROM chat_presentation_meta WHERE id=1",
                    [],
                    |r| {
                        Ok(ChatPresentationVersion {
                            store_epoch: r.get(0)?,
                            revision: crate::chat_presentation::nonnegative(r, 1)?,
                        })
                    },
                )
                .storage()?;
            let snapshot = pending_presentations
                .is_empty()
                .then_some(PresentedChatListSnapshot {
                    rows,
                    presentation_version,
                });
            Ok(ChatListWindowRead {
                page,
                snapshot,
                pending_presentations,
                anchor,
            })
        })
    }
}
fn choose_anchor(
    conn: &Connection,
    query: &ChatListWindowQuery,
) -> Result<Option<String>, ChatListPageError> {
    let mut stmt = conn
        .prepare_cached(&format!(
            "SELECT group_id_hex FROM chat_list_rows WHERE lower(group_id_hex)=lower(?1) AND {}",
            query.view.predicate()
        ))
        .storage()?;
    for key in &query.anchors {
        if let Some(key) = stmt.query_row([key], |r| r.get(0)).optional().storage()? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}
