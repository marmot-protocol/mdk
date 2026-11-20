//! Placing a new thread message from this device's timeline rows.

use crate::AppError;
use crate::messages::ThreadPlacement;
use storage_sqlite::SqliteAppStorage;

/// The root and parent a thread message answering `parent_message_id` names.
/// The parent must be stored here and not deleted. Its typed thread field
/// gives the root; a parent outside any thread is the root itself. A root
/// this device no longer holds keeps the kind and author the parent's own
/// `K`/`P` tags carry.
pub(super) fn thread_placement(
    storage: &SqliteAppStorage,
    group_id_hex: &str,
    parent_message_id: &str,
) -> Result<ThreadPlacement, AppError> {
    let unavailable =
        |what: &str| AppError::InvalidAppMessagePayload(format!("thread {what} is unavailable"));
    let parent = storage
        .timeline_message(group_id_hex, parent_message_id)?
        .filter(|parent| !parent.deleted && !parent.sender.is_empty())
        .ok_or_else(|| unavailable("parent"))?;
    let Some(thread) = &parent.thread else {
        return Ok(ThreadPlacement {
            root_message_id: parent.message_id_hex.clone(),
            root_kind: parent.kind,
            root_author: parent.sender.clone(),
            parent_kind: parent.kind,
            parent_author: parent.sender,
        });
    };
    let root_message_id = thread.root_message_id_hex.clone();
    let stored_root = storage
        .timeline_message(group_id_hex, &root_message_id)?
        .filter(|root| !root.sender.is_empty())
        .map(|root| (root.kind, root.sender));
    let (root_kind, root_author) = match stored_root {
        Some(root) => root,
        None => {
            let tag = |name| crate::messages::tag_value(&parent.tags, name);
            let named_here = cgka_traits::thread_root_tag(&parent.tags) == Some(&root_message_id);
            match (
                named_here,
                tag("K").and_then(|kind| kind.parse().ok()),
                tag("P"),
            ) {
                (true, Some(kind), Some(author)) => (kind, author.to_owned()),
                _ => return Err(unavailable("root")),
            }
        }
    };
    Ok(ThreadPlacement {
        root_message_id,
        root_kind,
        root_author,
        parent_kind: parent.kind,
        parent_author: parent.sender,
    })
}
