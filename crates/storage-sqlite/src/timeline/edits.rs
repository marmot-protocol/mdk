//! One accepted-edit resolver for incremental projection, repair and history.
use super::*;

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
    for (target, edits) in by_target {
        if let Some(row) = rows.get_mut(target) {
            let versions = resolve(row, edits.into_iter(), &deleted);
            apply(row, &versions);
        }
    }
}

fn resolve<'a>(
    row: &TimelineRow,
    edits: impl Iterator<Item = &'a RawAppEvent>,
    deleted: &HashSet<String>,
) -> Vec<TimelineEditVersion> {
    if row.kind != MARMOT_APP_EVENT_KIND_CHAT || row.invalidation_status.is_some() || row.deleted {
        return Vec::new();
    }
    let mut versions = edits
        .filter(|e| {
            let mut targets = e
                .tags
                .iter()
                .filter(|t| t.first().is_some_and(|name| name == EVENT_REF_TAG));
            !e.invalidated
                && e.sender == row.sender
                && e.group_id_hex == row.group_id_hex
                && !deleted.contains(&e.message_id_hex)
                && targets.next().and_then(|t| t.get(1)) == Some(&row.message_id_hex)
                && targets.next().is_none()
        })
        .map(|e| TimelineEditVersion {
            message_id_hex: e.message_id_hex.clone(),
            edited_at: e.recorded_at,
            plaintext: e.plaintext.clone(),
        })
        .collect::<Vec<_>>();
    versions
        .sort_by(|a, b| (a.edited_at, &a.message_id_hex).cmp(&(b.edited_at, &b.message_id_hex)));
    versions
}

pub(super) fn accepted_versions_tx(
    conn: &Connection,
    row: &TimelineRow,
) -> StorageResult<Vec<TimelineEditVersion>> {
    if row.kind != MARMOT_APP_EVENT_KIND_CHAT || row.invalidation_status.is_some() || row.deleted {
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

pub(super) fn apply(row: &mut TimelineRow, versions: &[TimelineEditVersion]) {
    if let Some(latest) = versions.last() {
        row.plaintext.clone_from(&latest.plaintext);
        row.edit = Some(TimelineEditSummary {
            edit_count: versions.len() as u64,
            latest_edit_message_id_hex: latest.message_id_hex.clone(),
            edited_at: latest.edited_at,
        });
    }
}

impl SqliteAccountStorage {
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
                 WHERE group_id_hex=?1 AND message_id_hex=?2 AND kind=9
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
            let row = timeline_row_from_chat(&event);
            let mut versions = accepted_versions_tx(conn, &row)?;
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
