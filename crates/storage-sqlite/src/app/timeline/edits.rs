//! One accepted-edit resolver for incremental projection, repair and history.
use super::*;
use crate::SqliteAppStorage;
use cgka_traits::agent_events::AGENT_ITEM_THREAD_ROOT_TAG;

/// NIP-22's tags that place an agent item in a thread: `E`/`K`/`P` name the
/// root, `e`/`k`/`p` the immediate parent (marmot-agents D-121).
const AGENT_ITEM_THREAD_TAGS: [&str; 6] = ["E", "K", "P", "e", "k", "p"];

fn is_agent_item_thread_tag(tag: &[String]) -> bool {
    tag.first()
        .is_some_and(|name| AGENT_ITEM_THREAD_TAGS.contains(&name.as_str()))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEditSummary {
    pub edit_count: u64,
    pub latest_edit_message_id_hex: String,
    pub edited_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEditVersion {
    pub message_id_hex: String,
    pub edited_at: u64,
    pub plaintext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimelineEditHistoryPage {
    /// Accepted versions, oldest first within this page. The first page is the latest page.
    pub versions: Vec<TimelineEditVersion>,
    pub has_more_before: bool,
}

pub(super) fn apply_group(rows: &mut BTreeMap<String, TimelineRow>, events: &[RawAppEvent]) {
    let (by_target, deleted) = edits_by_target(events);
    for (target, edits) in by_target {
        if let Some(row) = rows.get_mut(target) {
            let versions = resolve(row, edits.into_iter(), &deleted);
            apply(row, &versions);
        }
    }
}

/// Each target's edits, and the edits their own senders deleted.
fn edits_by_target(events: &[RawAppEvent]) -> (HashMap<&str, Vec<&RawAppEvent>>, HashSet<String>) {
    let mut by_target = HashMap::<&str, Vec<&RawAppEvent>>::new();
    let mut senders = HashMap::new();
    for edit in events
        .iter()
        .filter(|e| e.kind == MARMOT_APP_EVENT_KIND_EDIT)
    {
        senders.insert(edit.message_id_hex.as_str(), edit.sender.as_str());
        if let Some(target) = tag_value(&edit.tags, EVENT_REF_TAG) {
            by_target.entry(target).or_default().push(edit);
        }
    }
    let mut deleted = HashSet::new();
    for delete in events
        .iter()
        .filter(|e| e.kind == MARMOT_APP_EVENT_KIND_DELETE && !e.invalidated)
    {
        for id in tag_values(&delete.tags, EVENT_REF_TAG) {
            if senders
                .get(id)
                .is_some_and(|sender| *sender == delete.sender)
            {
                deleted.insert(id.to_owned());
            }
        }
    }
    (by_target, deleted)
}

/// Give each agent item this group holds edits of, but not the first event
/// of, its row: see [`held_agent_item_row`].
pub(super) fn add_held_agent_items(
    rows: &mut BTreeMap<String, TimelineRow>,
    events: &[RawAppEvent],
) {
    let stored = events
        .iter()
        .map(|event| event.message_id_hex.as_str())
        .collect::<HashSet<_>>();
    let (by_target, deleted) = edits_by_target(events);
    for (target, edits) in by_target {
        if !stored.contains(target)
            && let Some(row) = held_agent_item_row(target, edits.into_iter(), &deleted)
        {
            rows.insert(target.to_owned(), row);
        }
    }
}

/// The row of an agent item whose first event this device does not hold. A
/// member added to the group after the item began can never read that event
/// (marmot-agents D-124), and an edit carries the whole item, so the earliest
/// readable edit stands in for the first event, at its place in the timeline,
/// and every edit then applies to it as usual. Only that edit's sender's
/// edits count, as a first event's sender's would. The first event, should it
/// arrive (in a sibling's history, say), replaces the row.
pub(super) fn held_agent_item_row<'a>(
    target: &str,
    edits: impl Iterator<Item = &'a RawAppEvent>,
    deleted: &HashSet<String>,
) -> Option<TimelineRow> {
    let first = edits
        .filter(|e| {
            e.kind == MARMOT_APP_EVENT_KIND_EDIT
                && !e.invalidated
                && !deleted.contains(&e.message_id_hex)
                && sole_target(e) == Some(target)
                && cgka_traits::AgentItem::from_tags(&e.tags).is_ok()
        })
        .min_by(|a, b| {
            (a.recorded_at, &a.message_id_hex).cmp(&(b.recorded_at, &b.message_id_hex))
        })?;
    Some(timeline_row_from_app_event(&RawAppEvent {
        message_id_hex: target.to_owned(),
        kind: MARMOT_APP_EVENT_KIND_AGENT_ITEM,
        tags: first
            .tags
            .iter()
            .filter(|t| t.first().is_none_or(|name| name != EVENT_REF_TAG))
            .cloned()
            .collect(),
        ..first.clone()
    }))
}

/// The one message an edit names with its single `e` tag.
fn sole_target(edit: &RawAppEvent) -> Option<&str> {
    let mut targets = edit
        .tags
        .iter()
        .filter(|t| t.first().is_some_and(|name| name == EVENT_REF_TAG));
    let target = targets.next()?.get(1)?;
    targets.next().is_none().then_some(target.as_str())
}

/// One accepted edit. An edit of an agent item also carries the item's tags,
/// without the edit's own `e` tag, and the version they give it.
pub(super) struct AcceptedEdit {
    pub(super) version: TimelineEditVersion,
    agent_item: Option<(u64, Vec<Vec<String>>)>,
}

fn resolve<'a>(
    row: &TimelineRow,
    edits: impl Iterator<Item = &'a RawAppEvent>,
    deleted: &HashSet<String>,
) -> Vec<AcceptedEdit> {
    if !is_editable_message(row.kind, &row.tags) || row.invalidation_status.is_some() || row.deleted
    {
        return Vec::new();
    }
    let agent_item = row.kind == MARMOT_APP_EVENT_KIND_AGENT_ITEM;
    // The first event is version `v` of the item; an edit counts only with a
    // higher one, so an older version that arrives late changes nothing.
    let base_version = cgka_traits::AgentItem::from_tags(&row.tags).map_or(0, |item| item.version);
    let mut versions = edits
        .filter(|e| {
            !e.invalidated
                && e.sender == row.sender
                && e.group_id_hex == row.group_id_hex
                && !deleted.contains(&e.message_id_hex)
                && sole_target(e) == Some(row.message_id_hex.as_str())
        })
        .filter_map(|e| {
            let item = if agent_item {
                let version = cgka_traits::AgentItem::from_tags(&e.tags)
                    .ok()
                    .map(|item| item.version)
                    .filter(|version| *version > base_version)?;
                let tags = e
                    .tags
                    .iter()
                    .filter(|t| t.first().is_none_or(|name| name != EVENT_REF_TAG))
                    .cloned()
                    .collect();
                Some((version, tags))
            } else {
                None
            };
            Some(AcceptedEdit {
                version: TimelineEditVersion {
                    message_id_hex: e.message_id_hex.clone(),
                    edited_at: e.recorded_at,
                    plaintext: e.plaintext.clone(),
                },
                agent_item: item,
            })
        })
        .collect::<Vec<_>>();
    // An agent item keeps its highest version; `created_at` counts whole
    // seconds and cannot order versions sent within one (D-025). Chat edits
    // resolve by (second, event id).
    versions.sort_by(|a, b| {
        let key = |e: &AcceptedEdit| {
            (
                e.agent_item.as_ref().map(|(version, _)| *version),
                e.version.edited_at,
            )
        };
        (key(a), &a.version.message_id_hex).cmp(&(key(b), &b.version.message_id_hex))
    });
    versions
}

pub(super) fn accepted_versions_tx(
    conn: &Connection,
    row: &TimelineRow,
) -> StorageResult<Vec<AcceptedEdit>> {
    if !is_editable_message(row.kind, &row.tags) || row.invalidation_status.is_some() || row.deleted
    {
        return Ok(Vec::new());
    }
    let edits = app_events_targeting_message_tx(
        conn,
        &row.group_id_hex,
        MARMOT_APP_EVENT_KIND_EDIT,
        &row.message_id_hex,
    )?;
    let deleted = deleted_reaction_ids_for_target_tx(conn, &row.group_id_hex, &edits)?;
    Ok(resolve(row, edits.iter(), &deleted))
}

pub(super) fn apply(row: &mut TimelineRow, versions: &[AcceptedEdit]) {
    let Some(latest) = versions.last() else {
        return;
    };
    row.plaintext.clone_from(&latest.version.plaintext);
    if let Some((_, tags)) = &latest.agent_item {
        // A later version of an agent item replaces its content and tags. It
        // is the item changing state, not a correction, so the row is not
        // marked edited. An item never moves: one in a thread keeps the thread
        // tags of its first event, since an edit cannot carry the parent's
        // `e`, and one outside a thread cannot join one through an edit's `E`.
        let in_thread = cgka_traits::thread_root_tag(&row.tags).is_some();
        let placement = row
            .tags
            .iter()
            .filter(|tag| in_thread && is_agent_item_thread_tag(tag))
            .cloned()
            .collect::<Vec<_>>();
        row.tags = tags
            .iter()
            .filter(|tag| {
                if in_thread {
                    !is_agent_item_thread_tag(tag)
                } else {
                    tag.first()
                        .is_none_or(|name| name != AGENT_ITEM_THREAD_ROOT_TAG)
                }
            })
            .cloned()
            .chain(placement)
            .collect();
        row.reply_to_message_id_hex = cgka_traits::agent_item_reply_target(&row.tags);
        return;
    }
    row.edit = Some(TimelineEditSummary {
        edit_count: versions.len() as u64,
        latest_edit_message_id_hex: latest.version.message_id_hex.clone(),
        edited_at: latest.version.edited_at,
    });
}

impl SqliteAppStorage {
    /// Read accepted edit history separately from the bounded screen payload.
    /// A cursor is an exclusive (timestamp, id) key, so it survives removal of its event.
    /// Output is capped at 100; resolution work is scoped to this target's retained edits.
    pub fn message_edit_history(
        &self,
        group: &str,
        target: &str,
        before: Option<(u64, String)>,
        limit: usize,
    ) -> StorageResult<TimelineEditHistoryPage> {
        if !(1..=100).contains(&limit) {
            return Err(StorageError::Serialization(
                "edit history limit must be 1..=100".into(),
            ));
        }
        self.connection.with_deferred_read(|conn| {
            // Honor the same block/deletion boundary as visible timeline reads.
            let visible: bool = conn
                .query_row_cached(
                    "SELECT EXISTS(SELECT 1 FROM visible_message_timeline
                 WHERE group_id_hex=?1 AND message_id_hex=?2
                 AND deleted=0 AND invalidation_status IS NULL)",
                    params![group, target],
                    |r| r.get(0),
                )
                .storage()?;
            let empty = || TimelineEditHistoryPage {
                versions: vec![],
                has_more_before: false,
            };
            if !visible {
                return Ok(empty());
            }
            let Some(event) = raw_app_event_tx(conn, group, target)? else {
                return Ok(empty());
            };
            if event.invalidated {
                return Ok(empty());
            }
            // An agent item's versions are its states, not a correction history.
            if event.kind == MARMOT_APP_EVENT_KIND_AGENT_ITEM {
                return Ok(empty());
            }
            let row = timeline_row_from_chat(&event);
            let mut versions = accepted_versions_tx(conn, &row)?
                .into_iter()
                .map(|accepted| accepted.version)
                .collect::<Vec<_>>();
            if let Some((at, id)) = before {
                versions.retain(|v| (v.edited_at, v.message_id_hex.as_str()) < (at, id.as_str()));
            }
            let has_more_before = versions.len() > limit;
            if has_more_before {
                versions.drain(..versions.len() - limit);
            }
            Ok(TimelineEditHistoryPage {
                versions,
                has_more_before,
            })
        })
    }
}
