//! Each timeline row's and reply preview's place in a NIP-22 thread.
//!
//! Computed when rows are read, not stored: a thread message without an `E`
//! tag (White Noise Linux before the thread-message contract) finds its root
//! by walking its stored parents, and the answer improves as late parents
//! arrive without any reprojection.

use super::TimelineThreadRef;
use crate::SqliteResultExt;
use crate::base::connection::CachedSql;
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::storage::StorageResult;
use cgka_traits::{MARMOT_APP_EVENT_KIND_POLL, NIP22_COMMENT_KIND, thread_root_tag};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};

/// Ancestors a legacy root walk visits before it stops at the last one.
const MAX_LEGACY_THREAD_DEPTH: usize = 64;

/// Legacy roots already walked in one read, keyed by group and the message
/// walked from: one read can span groups that share an inner event id.
pub(super) type ThreadRootCache = HashMap<(String, String), String>;

/// A row's place in its thread, from its kind, tags and projected reply
/// target. A thread message's projected reply target is its parent, set only
/// when the projection recognized it as a comment.
pub(super) fn thread_ref(
    conn: &Connection,
    group_id_hex: &str,
    kind: u64,
    tags: &[Vec<String>],
    reply_to_message_id_hex: Option<&str>,
    legacy_roots: &mut ThreadRootCache,
) -> StorageResult<Option<TimelineThreadRef>> {
    let Some(own) = own_thread(kind, tags, reply_to_message_id_hex) else {
        return Ok(None);
    };
    let root_message_id_hex = match own.named_root {
        Some(root) => root.to_owned(),
        None => legacy_root(conn, group_id_hex, own.parent, legacy_roots)?,
    };
    Ok(Some(TimelineThreadRef {
        root_message_id_hex,
        parent_message_id_hex: own.parent.to_owned(),
    }))
}

struct OwnThread<'a> {
    named_root: Option<&'a str>,
    parent: &'a str,
}

/// What a row's own fields say about its thread: a thread message always has
/// a parent; a chat, sticker or poll joins a thread only by naming its root
/// with `E`, and answers its reply target or else that root.
fn own_thread<'a>(
    kind: u64,
    tags: &'a [Vec<String>],
    reply_to_message_id_hex: Option<&'a str>,
) -> Option<OwnThread<'a>> {
    let named_root = thread_root_tag(tags);
    match kind {
        NIP22_COMMENT_KIND => Some(OwnThread {
            named_root,
            parent: reply_to_message_id_hex?,
        }),
        MARMOT_APP_EVENT_KIND_CHAT | MARMOT_APP_EVENT_KIND_POLL => {
            let root = named_root?;
            Some(OwnThread {
                named_root,
                parent: reply_to_message_id_hex.unwrap_or(root),
            })
        }
        _ => None,
    }
}

/// The root of the thread `start` belongs to: the first stored ancestor that
/// names a root with `E`, or else the first one outside a thread. A missing
/// ancestor, or a cycle, ends the walk at the last id reached.
fn legacy_root(
    conn: &Connection,
    group_id_hex: &str,
    start: &str,
    cache: &mut ThreadRootCache,
) -> StorageResult<String> {
    let key = (group_id_hex.to_owned(), start.to_owned());
    if let Some(root) = cache.get(&key) {
        return Ok(root.clone());
    }
    let mut current = start.to_owned();
    let mut visited = HashSet::new();
    while visited.insert(current.clone()) && visited.len() <= MAX_LEGACY_THREAD_DEPTH {
        let Some((kind, tags, reply_to)) = stored_row(conn, group_id_hex, &current)? else {
            break;
        };
        let Some(own) = own_thread(kind, &tags, reply_to.as_deref()) else {
            break;
        };
        current = own.named_root.unwrap_or(own.parent).to_owned();
        if own.named_root.is_some() {
            break;
        }
    }
    cache.insert(key, current.clone());
    Ok(current)
}

type StoredRow = (u64, Vec<Vec<String>>, Option<String>);

fn stored_row(
    conn: &Connection,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<StoredRow>> {
    conn.query_row_cached(
        "SELECT kind, tags_json, reply_to_message_id_hex FROM message_timeline
         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        params![group_id_hex, message_id_hex],
        |row| {
            let kind = u64::try_from(row.get::<_, i64>(0)?).unwrap_or_default();
            // Scrubbed or damaged tags read as none: the walk then follows
            // the stored parent column alone.
            let tags = row
                .get::<_, String>(1)
                .ok()
                .and_then(|json| crate::tags_from_json(json).ok())
                .unwrap_or_default();
            Ok((kind, tags, row.get(2)?))
        },
    )
    .optional()
    .storage()
}
