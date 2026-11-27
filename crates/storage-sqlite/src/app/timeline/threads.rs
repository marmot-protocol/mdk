//! Each timeline row's and reply preview's place in a NIP-22 thread.
//!
//! Computed when rows are read, not stored: a thread message without an `E`
//! tag (White Noise Linux before the thread-message contract) finds its root
//! by walking its stored parents, and the answer improves as late parents
//! arrive without any reprojection.

use super::TimelineThreadRef;
use crate::SqliteResultExt;
use crate::base::connection::{CachedSql, canonical_group_id_hex};
use cgka_traits::app_event::MARMOT_APP_EVENT_KIND_CHAT;
use cgka_traits::storage::StorageResult;
use cgka_traits::{
    MARMOT_APP_EVENT_KIND_AGENT_ITEM, MARMOT_APP_EVENT_KIND_POLL, NIP22_COMMENT_KIND,
    agent_item_thread_parent, thread_root_tag,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};

/// Ancestors a legacy root walk visits before it stops at the last one.
const MAX_LEGACY_THREAD_DEPTH: usize = 64;

/// Legacy roots already walked in one read, keyed by group and the message
/// walked from: one read can span groups that share an inner event id.
pub(super) type ThreadRootCache = HashMap<(String, String), String>;

/// What a read row carries for placing it in its thread.
pub(super) struct ReadRow<'a> {
    pub(super) group_id_hex: &'a str,
    pub(super) message_id_hex: &'a str,
    pub(super) kind: u64,
    pub(super) tags: &'a [Vec<String>],
    pub(super) reply_to_message_id_hex: Option<&'a str>,
    pub(super) deleted: bool,
}

/// A row's place in its thread, from its kind, tags and projected reply
/// target. A thread message's projected reply target is its parent, set only
/// when the projection recognized it as a comment. A deleted row reads with
/// its tags masked, so its root comes from the tags stored for it: deletion
/// hides content, not where the row sits.
pub(super) fn thread_ref(
    conn: &Connection,
    row: &ReadRow<'_>,
    legacy_roots: &mut ThreadRootCache,
) -> StorageResult<Option<TimelineThreadRef>> {
    // Rule out rows that cannot be in a thread before reading stored tags.
    let may_join = match row.kind {
        NIP22_COMMENT_KIND => row.reply_to_message_id_hex.is_some(),
        MARMOT_APP_EVENT_KIND_CHAT
        | MARMOT_APP_EVENT_KIND_POLL
        | MARMOT_APP_EVENT_KIND_AGENT_ITEM => true,
        _ => false,
    };
    if !may_join {
        return Ok(None);
    }
    let stored_tags;
    let tags = if row.deleted {
        stored_tags = stored_row(conn, row.group_id_hex, row.message_id_hex)?
            .map(|(_, tags, _)| tags)
            .unwrap_or_default();
        &stored_tags
    } else {
        row.tags
    };
    let group_id_hex = row.group_id_hex;
    let Some(own) = own_thread(row.kind, tags, row.reply_to_message_id_hex) else {
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
/// with `E`, and answers its reply target or else that root. An agent item
/// joins with `E` too, and answers the parent its `e` names or else the root
/// (marmot-agents D-121); its reply target is a turn's starting message.
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
        MARMOT_APP_EVENT_KIND_AGENT_ITEM => Some(OwnThread {
            named_root,
            parent: agent_item_thread_parent(tags)?,
        }),
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
    let group_id_hex = canonical_group_id_hex(group_id_hex);
    let group_id_hex = group_id_hex.as_ref();
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

/// The kind and author of `root` as the nearest stored row, from `start` up
/// through its parents, names them: a row that names `root` with `E` and
/// carries a numeric `K` and a non-empty `P`. Places a new thread message
/// when the root itself is no longer stored.
pub(super) fn named_root_hint(
    conn: &Connection,
    group_id_hex: &str,
    start: &str,
    root: &str,
) -> StorageResult<Option<(u64, String)>> {
    let group_id_hex = canonical_group_id_hex(group_id_hex);
    let group_id_hex = group_id_hex.as_ref();
    let mut current = start.to_owned();
    let mut visited = HashSet::new();
    // `start` is the parent itself, one row below where the read walk that
    // found `root` began, so this walk may visit one row more.
    while visited.insert(current.clone()) && visited.len() <= MAX_LEGACY_THREAD_DEPTH + 1 {
        let Some((kind, tags, reply_to)) = stored_row(conn, group_id_hex, &current)? else {
            break;
        };
        if thread_root_tag(&tags) == Some(root) {
            let value = |name: &str| {
                tags.iter()
                    .find(|tag| tag.first().is_some_and(|tag_name| tag_name == name))
                    .and_then(|tag| tag.get(1))
            };
            let root_kind = value("K").and_then(|kind| kind.parse().ok());
            let author = value("P").filter(|author| !author.is_empty());
            if let (Some(root_kind), Some(author)) = (root_kind, author) {
                return Ok(Some((root_kind, author.clone())));
            }
        }
        let Some(own) = own_thread(kind, &tags, reply_to.as_deref()) else {
            break;
        };
        current = own.parent.to_owned();
    }
    Ok(None)
}

type StoredRow = (u64, Vec<Vec<String>>, Option<String>);

fn stored_row(
    conn: &Connection,
    group_id_hex: &str,
    message_id_hex: &str,
) -> StorageResult<Option<StoredRow>> {
    let group_id_hex = canonical_group_id_hex(group_id_hex);
    conn.query_row_cached(
        "SELECT kind, tags_json, reply_to_message_id_hex FROM message_timeline
         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        params![group_id_hex.as_ref(), message_id_hex],
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
