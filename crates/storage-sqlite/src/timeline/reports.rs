//! Indexed report projections. Raw authenticated app events remain the authority.
use super::*;
use cgka_traits::app_event::{
    AppMessageAuthority, MARMOT_APP_EVENT_KIND_REMOVE, MARMOT_APP_EVENT_KIND_REPORT,
    MARMOT_APP_EVENT_KIND_REVIEW,
};
use cgka_traits::reporting::{ReportReason, parse_dismissal, parse_removal, parse_report};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModerationStatus {
    #[default]
    Unreported,
    Pending,
    Reviewed,
    Removed,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageModerationSummary {
    pub status: ModerationStatus,
    pub total_reports: u64,
    pub pending_reports: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedContent {
    pub message_id_hex: String,
    pub revision_id_hex: String,
    pub moderation: MessageModerationSummary,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedContentPage {
    pub items: Vec<ReportedContent>,
    pub next_cursor: Option<String>,
    pub pending_message_count: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReport {
    pub report_id_hex: String,
    pub message_id_hex: String,
    pub revision_id_hex: String,
    pub reporter: String,
    pub reason: ReportReason,
    pub explanation: String,
    pub reported_at: u64,
    pub dismissed_by_event_id: Option<String>,
    pub reviewing_admin: Option<String>,
    pub reported_text: Option<String>,
    pub reported_revision: Option<TimelineReplyPreview>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReportPage {
    pub removed_by_event_id: Option<String>,
    pub removing_account: Option<String>,
    pub removed_at: Option<u64>,
    pub current_message: Option<TimelineMessageRecord>,
    pub reports: Vec<ContentReport>,
    pub next_cursor: Option<String>,
}
fn summary(total: i64, pending: i64, removed: bool) -> MessageModerationSummary {
    MessageModerationSummary {
        status: if removed {
            ModerationStatus::Removed
        } else if pending > 0 {
            ModerationStatus::Pending
        } else if total > 0 {
            ModerationStatus::Reviewed
        } else {
            ModerationStatus::Unreported
        },
        total_reports: total.max(0) as u64,
        pending_reports: pending.max(0) as u64,
    }
}
fn raw(conn: &Connection, group: &str, id: &str) -> StorageResult<Option<RawAppEvent>> {
    conn.query_row_cached(
        "SELECT group_id_hex, message_id_hex, source_message_id_hex, source_epoch,
         direction, sender, plaintext, kind, tags_json, recorded_at, received_at,
         invalidated, invalidation_reason, moderation_grant
         FROM app_events WHERE group_id_hex = ?1 AND message_id_hex = ?2",
        params![group, id],
        raw_event_from_row,
    )
    .optional()
    .storage()
}

fn report_reference<'a>(
    conn: &Connection,
    event: &'a RawAppEvent,
) -> StorageResult<Option<cgka_traits::reporting::ReportReference<'a>>> {
    let allowed: bool = conn
        .query_row_cached(
            "SELECT reporting_allowed FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![event.group_id_hex, event.message_id_hex],
            |r| r.get(0),
        )
        .storage()?;
    if !allowed {
        return Ok(None);
    }
    let pruned: bool = conn
        .query_row_cached(
            "SELECT EXISTS (SELECT 1 FROM content_pruned_controls
         WHERE group_id_hex = ?1 AND message_id_hex = ?2)",
            params![event.group_id_hex, event.message_id_hex],
            |row| row.get(0),
        )
        .storage()?;
    Ok(parse_report(
        &event.tags,
        if pruned { "pruned" } else { &event.plaintext },
    ))
}

pub(super) fn refresh(conn: &Connection, group: &str, target: &str) -> StorageResult<()> {
    // Most timeline rows have no moderation state. Probe indexed keys before
    // loading raw content or edits, including when a non-chat event is projected.
    // Existing state must still be refreshed when its last report is withdrawn.
    let needs_refresh: bool = conn
        .query_row_cached(
            "SELECT EXISTS (
                SELECT 1 FROM message_modifier_edges
                WHERE group_id_hex = ?1 AND target_message_id_hex = ?2 AND kind = ?3
             ) OR EXISTS (
                SELECT 1 FROM message_timeline
                WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND deleted = 1
             ) OR EXISTS (
                SELECT 1 FROM content_moderation
                WHERE group_id_hex = ?1 AND message_id_hex = ?2
             )",
            params![group, target, u64_to_i64(MARMOT_APP_EVENT_KIND_REPORT)?],
            |row| row.get(0),
        )
        .storage()?;
    if !needs_refresh {
        return Ok(());
    }
    let Some(original) = raw(conn, group, target)?
        .filter(|e| e.kind == MARMOT_APP_EVENT_KIND_CHAT && !e.invalidated)
    else {
        conn.execute_cached(
            "DELETE FROM content_reports WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![group, target],
        )
        .storage()?;
        conn.execute_cached(
            "DELETE FROM content_moderation WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![group, target],
        )
        .storage()?;
        return Ok(());
    };
    let edits = app_events_targeting_message_tx(conn, group, MARMOT_APP_EVENT_KIND_EDIT, target)?;
    let mut revisions = BTreeSet::from([target.to_owned()]);
    for edit in &edits {
        if edit.sender == original.sender && tag_values(&edit.tags, "e").count() == 1 {
            revisions.insert(edit.message_id_hex.clone());
        }
    }
    // The reported revision remains stable, while the current revision follows
    // the shared accepted-edit projection (including retracted edits).
    let (latest, deleted) = conn
        .query_row_cached(
            "SELECT json_extract(edit_json, '$.latest_edit_message_id_hex'), deleted
             FROM message_timeline WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group, target],
            |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, bool>(1)?)),
        )
        .optional()
        .storage()?
        .unwrap_or((None, false));
    let latest = latest.unwrap_or_else(|| target.to_owned());
    let candidates =
        app_events_targeting_message_tx(conn, group, MARMOT_APP_EVENT_KIND_REPORT, target)?;
    // Group duplicates before applying dismissal: a new duplicate event can
    // never reopen a logical report already resolved under another event id.
    let mut logical: BTreeMap<(String, String), (ReportReason, Vec<&RawAppEvent>)> =
        BTreeMap::new();
    for report in &candidates {
        if let Some(reference) = report_reference(conn, report)?
            && reference.target == target
            && reference.author == original.sender
            && revisions.contains(reference.revision)
        {
            logical
                .entry((reference.revision.to_owned(), report.sender.clone()))
                .or_insert_with(|| (reference.reason, Vec::new()))
                .1
                .push(report);
        }
    }
    conn.execute_cached(
        "DELETE FROM content_reports WHERE group_id_hex=?1 AND message_id_hex=?2",
        params![group, target],
    )
    .storage()?;
    let mut pending = 0i64;
    let total = logical.len() as i64;
    for ((revision, reporter), (reason, mut duplicates)) in logical {
        duplicates.sort_by_key(|e| (e.recorded_at, &e.message_id_hex));
        let report = duplicates[0];
        let mut dismissals = Vec::new();
        for duplicate in duplicates {
            for decision in app_events_targeting_message_tx(
                conn,
                group,
                MARMOT_APP_EVENT_KIND_REVIEW,
                &duplicate.message_id_hex,
            )? {
                if decision.moderation_grant
                    && parse_dismissal(&decision.tags, &decision.plaintext).is_some()
                {
                    dismissals.push(decision);
                }
            }
        }
        dismissals.sort_by_key(|e| (e.recorded_at, e.message_id_hex.clone()));
        let dismissal = dismissals.first().map(|e| e.message_id_hex.as_str());
        if dismissal.is_none() && !deleted {
            pending += 1;
        }
        conn.execute_cached(
            "INSERT INTO content_reports (
                group_id_hex, report_id_hex, message_id_hex, revision_id_hex,
                reporter, reason, reported_at, dismissed_by
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                group,
                report.message_id_hex,
                target,
                revision,
                reporter,
                reason.as_str(),
                u64_to_i64(report.recorded_at)?,
                dismissal,
            ],
        )
        .storage()?;
    }
    if total == 0 && !deleted {
        conn.execute_cached(
            "DELETE FROM content_moderation WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![group, target],
        )
        .storage()?;
    } else {
        conn.execute_cached(
            "INSERT INTO content_moderation (
                group_id_hex, message_id_hex, revision_id_hex,
                total_reports, pending_reports, removed
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id_hex, message_id_hex) DO UPDATE SET
                revision_id_hex = excluded.revision_id_hex,
                total_reports = excluded.total_reports,
                pending_reports = excluded.pending_reports,
                removed = excluded.removed",
            params![group, target, latest, total, pending, deleted],
        )
        .storage()?;
    }
    Ok(())
}

pub(super) fn hydrate(
    conn: &Connection,
    messages: &mut [TimelineMessageRecord],
) -> StorageResult<()> {
    for message in messages.iter_mut() {
        // Accepted edits already determine the timeline body. The same metadata
        // determines its revision even when there is no moderation projection.
        message.revision_id_hex = message.edit.as_ref().map_or_else(
            || message.message_id_hex.clone(),
            |edit| edit.latest_edit_message_id_hex.clone(),
        );
        message.moderation = summary(0, 0, message.deleted);
    }
    let groups: BTreeSet<_> = messages.iter().map(|m| m.group_id_hex.clone()).collect();
    for group in groups {
        let ids: Vec<_> = messages
            .iter()
            .filter(|m| m.group_id_hex == group)
            .map(|m| &m.message_id_hex)
            .collect();
        let json = serde_json::to_string(&ids).map_err(|e| StorageError::Backend(e.to_string()))?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT message_id_hex, total_reports, pending_reports, removed
             FROM content_moderation
             WHERE group_id_hex = ?1 AND message_id_hex IN (SELECT value FROM json_each(?2))",
            )
            .storage()?;
        let entries = stmt
            .query_map(params![group, json], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        for (id, total, pending, removed) in entries {
            if let Some(message) = messages
                .iter_mut()
                .find(|m| m.group_id_hex == group && m.message_id_hex == id)
            {
                message.moderation = summary(total, pending, removed);
            }
        }
    }
    Ok(())
}

impl SqliteAccountStorage {
    /// Source authority is stored atomically with its dependent projections.
    pub fn record_app_event_with_source(
        &self,
        event: &StoredAppEvent,
        retention: Option<AppMessageRetentionDecision>,
        authority: Option<AppMessageAuthority>,
    ) -> StorageResult<TimelineProjectionUpdate> {
        self.record_app_event_inner(event, false, retention, Some(authority))
    }
    pub fn finalize_app_event_authority(
        &self,
        group: &str,
        id: &str,
        authority: Option<AppMessageAuthority>,
    ) -> StorageResult<Option<TimelineProjectionUpdate>> {
        let Some(authority) = authority else {
            return Ok(None);
        };
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let changed = conn
                .execute_cached(
                    "UPDATE app_events SET
                    authority_state = 2,
                    authority_context = ?3,
                    moderation_grant = CASE
                        WHEN kind = 5 AND authority_state = 0 THEN moderation_grant
                        WHEN kind IN (1985, 4891) THEN ?4
                        ELSE 0
                    END,
                    reporting_allowed = ?5
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND authority_state != 2",
                    params![
                        group,
                        id,
                        authority.source_context.as_slice(),
                        authority.moderation_grant,
                        authority.reporting_allowed,
                    ],
                )
                .storage()?;
            if changed == 0 {
                return Ok(None);
            }
            let Some((kind, tags)) = app_event_projection_parts_tx(&conn, group, id)? else {
                return Ok(None);
            };
            let ids = affected_timeline_message_ids_for_parts_tx(&conn, group, id, kind, &tags)?;
            for target in &ids {
                upsert_message_timeline_projection_for_message_tx(&conn, group, target)?;
            }
            let messages = timeline_records_by_ids_tx(&conn, group, ids)?;
            let changes = messages
                .iter()
                .cloned()
                .map(|message| TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::SnapshotRefresh,
                    message: Box::new(message),
                })
                .collect();
            Ok(Some(TimelineProjectionUpdate {
                group_id_hex: group.to_owned(),
                messages,
                changes,
            }))
        })
    }
    pub fn reported_content(
        &self,
        group: &str,
        pending_only: bool,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<ReportedContentPage> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 100);
        let mut stmt = conn
            .prepare_cached(
                "SELECT message_id_hex, revision_id_hex, total_reports, pending_reports, removed
             FROM content_moderation
             WHERE group_id_hex = ?1 AND total_reports > 0
               AND (?2 = 0 OR pending_reports > 0)
               AND (?3 IS NULL OR message_id_hex > ?3)
             ORDER BY message_id_hex LIMIT ?4",
            )
            .storage()?;
        let mut items = stmt
            .query_map(
                params![group, pending_only, after, (limit + 1) as i64],
                |r| {
                    Ok(ReportedContent {
                        message_id_hex: r.get(0)?,
                        revision_id_hex: r.get(1)?,
                        moderation: summary(r.get(2)?, r.get(3)?, r.get(4)?),
                    })
                },
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let next_cursor = if items.len() > limit {
            items.truncate(limit);
            items.last().map(|i| i.message_id_hex.clone())
        } else {
            None
        };
        let pending_message_count = conn
            .query_row_cached(
                "SELECT count(*) FROM content_moderation
             WHERE group_id_hex = ?1 AND pending_reports > 0",
                params![group],
                |row| row.get::<_, i64>(0),
            )
            .storage()? as u64;
        Ok(ReportedContentPage {
            items,
            next_cursor,
            pending_message_count,
        })
    }
    pub fn message_reports(
        &self,
        group: &str,
        target: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<ContentReportPage> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 100);
        let mut stmt = conn
            .prepare_cached(
                "SELECT r.report_id_hex, r.revision_id_hex, r.reporter, r.reason,
                    e.plaintext, r.reported_at, r.dismissed_by, d.sender,
                    CASE WHEN m.removed = 0 THEN v.plaintext ELSE NULL END
             FROM content_reports r
             JOIN app_events e
               ON e.group_id_hex = r.group_id_hex AND e.message_id_hex = r.report_id_hex
             JOIN content_moderation m
               ON m.group_id_hex = r.group_id_hex AND m.message_id_hex = r.message_id_hex
             LEFT JOIN app_events d
               ON d.group_id_hex = r.group_id_hex AND d.message_id_hex = r.dismissed_by
             LEFT JOIN app_events v
               ON v.group_id_hex = r.group_id_hex AND v.message_id_hex = r.revision_id_hex
             WHERE r.group_id_hex = ?1 AND r.message_id_hex = ?2
               AND (?3 IS NULL OR r.report_id_hex > ?3)
             ORDER BY r.report_id_hex LIMIT ?4",
            )
            .storage()?;
        let mut reports = stmt
            .query_map(params![group, target, after, (limit + 1) as i64], |r| {
                Ok(ContentReport {
                    report_id_hex: r.get(0)?,
                    message_id_hex: target.to_owned(),
                    revision_id_hex: r.get(1)?,
                    reporter: r.get(2)?,
                    reason: ReportReason::parse(&r.get::<_, String>(3)?)
                        .unwrap_or(ReportReason::Other),
                    explanation: r.get(4)?,
                    reported_at: r.get::<_, i64>(5)? as u64,
                    dismissed_by_event_id: r.get(6)?,
                    reviewing_admin: r.get(7)?,
                    reported_text: r.get(8)?,
                    reported_revision: None,
                })
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let next_cursor = if reports.len() > limit {
            reports.truncate(limit);
            reports.last().map(|r| r.report_id_hex.clone())
        } else {
            None
        };
        let current_message =
            timeline_records_by_ids_tx(&conn, group, BTreeSet::from([target.to_owned()]))?
                .into_iter()
                .next();
        for report in &mut reports {
            if current_message.as_ref().is_some_and(|m| !m.deleted)
                && let Some(revision) =
                    raw(&conn, group, &report.revision_id_hex)?.filter(|e| !e.invalidated)
            {
                let root = raw(&conn, group, target)?;
                let attachment_source = if revision.kind == MARMOT_APP_EVENT_KIND_EDIT {
                    root.as_ref().unwrap_or(&revision)
                } else {
                    &revision
                };
                let row = timeline_row_from_chat(attachment_source);
                report.reported_revision = Some(TimelineReplyPreview {
                    message_id_hex: report.revision_id_hex.clone(),
                    sender: revision.sender.clone(),
                    plaintext: revision.plaintext.clone(),
                    kind: MARMOT_APP_EVENT_KIND_CHAT,
                    source_epoch: attachment_source.source_epoch,
                    media: row.media,
                    agent_text_stream: row.agent_text_stream,
                    deleted: false,
                    invalidation_status: None,
                });
            }
        }
        let removed_by_event_id = current_message
            .as_ref()
            .and_then(|m| m.deleted_by_message_id_hex.clone());
        let removal = removed_by_event_id
            .as_ref()
            .map(|id| raw(&conn, group, id))
            .transpose()?
            .flatten();
        Ok(ContentReportPage {
            removed_by_event_id,
            removing_account: removal.as_ref().map(|e| e.sender.clone()),
            removed_at: removal.as_ref().map(|e| e.recorded_at),
            current_message,
            reports,
            next_cursor,
        })
    }
    pub fn report_target_author(
        &self,
        group: &str,
        target: &str,
        revision: &str,
    ) -> StorageResult<Option<String>> {
        let conn = self.lock()?;
        let Some(original) = raw(&conn, group, target)?
            .filter(|e| e.kind == MARMOT_APP_EVENT_KIND_CHAT && !e.invalidated)
        else {
            return Ok(None);
        };
        let removed: bool = conn
            .query_row_cached(
                "SELECT EXISTS (SELECT 1 FROM message_timeline
             WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND deleted = 1)",
                params![group, target],
                |row| row.get(0),
            )
            .storage()?;
        if removed {
            return Ok(None);
        };
        if revision == target {
            return Ok(Some(original.sender));
        };
        Ok(raw(&conn, group, revision)?
            .filter(|e| {
                !e.invalidated
                    && e.kind == MARMOT_APP_EVENT_KIND_EDIT
                    && e.sender == original.sender
                    && tag_values(&e.tags, "e").count() == 1
                    && tag_value(&e.tags, "e") == Some(target)
            })
            .map(|_| original.sender))
    }
    pub fn report_is_reviewable(&self, group: &str, id: &str) -> StorageResult<bool> {
        let conn = self.lock()?;
        let Some(event) = raw(&conn, group, id)?.filter(|e| !e.invalidated && e.kind == 1984)
        else {
            return Ok(false);
        };
        let Some(reference) = report_reference(&conn, &event)? else {
            return Ok(false);
        };
        let Some(original) = raw(&conn, group, reference.target)?
            .filter(|e| e.kind == 9 && !e.invalidated && e.sender == reference.author)
        else {
            return Ok(false);
        };
        if reference.revision == reference.target {
            return Ok(true);
        }
        Ok(
            raw(&conn, group, reference.revision)?.is_some_and(|revision| {
                revision.kind == MARMOT_APP_EVENT_KIND_EDIT
                    && !revision.invalidated
                    && revision.sender == original.sender
                    && tag_values(&revision.tags, "e").count() == 1
                    && tag_value(&revision.tags, "e") == Some(reference.target)
            }),
        )
    }
    pub fn own_report(
        &self,
        group: &str,
        target: &str,
        revision: &str,
        reporter: &str,
    ) -> StorageResult<Option<String>> {
        let conn = self.lock()?;
        // Includes pending local events so retrying during queued publication
        // does not produce a second submission.
        for event in
            app_events_targeting_message_tx(&conn, group, MARMOT_APP_EVENT_KIND_REPORT, target)?
        {
            if event.sender != reporter {
                continue;
            }
            let reference = match parse_report(&event.tags, &event.plaintext) {
                Some(reference) => Some(reference),
                None => report_reference(&conn, &event)?,
            };
            if reference.is_some_and(|reference| reference.revision == revision) {
                return Ok(Some(event.message_id_hex));
            }
        }
        Ok(None)
    }
}

/// Keep replay fencing only for targets with moderation evidence. Call this
/// after identifying retained controls and before deleting their projections.
pub(super) fn retain_expired_target(
    conn: &Connection,
    group: &str,
    target: &str,
) -> StorageResult<()> {
    conn.execute_cached(
        "INSERT OR IGNORE INTO content_expired_targets (group_id_hex, message_id_hex)
         SELECT ?1, ?2 WHERE EXISTS (
            SELECT 1 FROM content_moderation
            WHERE group_id_hex = ?1 AND message_id_hex = ?2
         ) OR EXISTS (
            SELECT 1 FROM content_reports
            WHERE group_id_hex = ?1 AND message_id_hex = ?2
         ) OR EXISTS (
            SELECT 1 FROM message_modifier_edges AS edges
            CROSS JOIN content_pruned_controls AS controls
              ON controls.group_id_hex = edges.group_id_hex
             AND controls.message_id_hex = edges.modifier_message_id_hex
            WHERE edges.group_id_hex = ?1 AND edges.target_message_id_hex = ?2
              AND edges.kind IN (5, 1984, 4891)
         )",
        params![group, target],
    )
    .storage()?;
    Ok(())
}

pub(super) fn target_expired(conn: &Connection, group: &str, id: &str) -> StorageResult<bool> {
    conn.query_row_cached(
        "SELECT EXISTS (SELECT 1 FROM content_expired_targets
         WHERE group_id_hex = ?1 AND message_id_hex = ?2)",
        params![group, id],
        |row| row.get(0),
    )
    .storage()
}

pub(super) fn rescrub_control(conn: &Connection, group: &str, id: &str) -> StorageResult<()> {
    let pruned: bool = conn
        .query_row_cached(
            "SELECT EXISTS (SELECT 1 FROM content_pruned_controls
         WHERE group_id_hex = ?1 AND message_id_hex = ?2)",
            params![group, id],
            |row| row.get(0),
        )
        .storage()?;
    if !pruned {
        return Ok(());
    }
    if let Some(event) = raw(conn, group, id)? {
        let tags = event
            .tags
            .into_iter()
            .filter_map(|mut tag| {
                let limit = match (event.kind, tag.first().map(String::as_str)) {
                    (1984, Some("e")) => 3,
                    (1984, Some("p" | "revision")) => 2,
                    (5 | 1985 | 4891, Some("e")) => 2,
                    (1985, Some("L")) => 2,
                    (1985, Some("l")) => 3,
                    (5, Some("k")) => 2,
                    _ => return None,
                };
                tag.truncate(limit);
                Some(tag)
            })
            .collect::<Vec<_>>();
        conn.execute_cached(
            "UPDATE app_events SET tags_json=?3 WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![
                group,
                id,
                serde_json::to_string(&tags).map_err(|e| StorageError::Backend(e.to_string()))?
            ],
        )
        .storage()?;
    }
    conn.execute_cached(
        "UPDATE app_events SET plaintext = zeroblob(length(plaintext))
         WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND kind != 4891",
        params![group, id],
    )
    .storage()?;
    conn.execute_cached(
        "UPDATE app_events SET
            plaintext = CASE WHEN kind = 4891 THEN plaintext ELSE '' END,
            retention_seconds = NULL,
            retention_expires_at = NULL
         WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND EXISTS (
            SELECT 1 FROM content_pruned_controls p
            WHERE p.group_id_hex = app_events.group_id_hex
              AND p.message_id_hex = app_events.message_id_hex
         )",
        params![group, id],
    )
    .storage()?;
    Ok(())
}
pub(super) fn retain_pruned_controls(
    conn: &Connection,
    group: &str,
    ids: &mut BTreeSet<String>,
) -> StorageResult<usize> {
    let mut retained = Vec::new();
    for id in ids.iter() {
        let Some(event) = raw(conn, group, id)? else {
            continue;
        };
        if event.kind == 5
            || (event.kind == 1985 && parse_dismissal(&event.tags, &event.plaintext).is_some())
            || (event.kind == 4891 && parse_removal(&event.tags, &event.plaintext).is_some())
            || (event.kind == 1984
                && (parse_report(&event.tags, &event.plaintext).is_some()
                    || report_reference(conn, &event)?.is_some()))
        {
            conn.execute_cached(
                "INSERT OR IGNORE INTO content_pruned_controls VALUES(?1,?2)",
                params![group, id],
            )
            .storage()?;
            rescrub_control(conn, group, id)?;
            retained.push(id.clone());
        }
    }
    let count = retained.len();
    for id in retained {
        ids.remove(&id);
    }
    Ok(count)
}
impl SqliteAccountStorage {
    /// Upgrade only the pre-migration prefix, committing progress with each
    /// bounded batch. Normal sync never scans account history.
    pub fn backfill_content_reports(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<TimelineProjectionUpdate>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let (after, through): (i64, i64) = conn.query_row_cached(
                "SELECT after_order, through_order FROM content_report_backfill WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).storage()?;
            if after >= through {
                return Ok(Vec::new());
            }
            let mut stmt = conn.prepare_cached(
                "SELECT group_id_hex, message_id_hex, source_message_id_hex, source_epoch,
                        direction, sender, plaintext, kind, tags_json, recorded_at, received_at,
                        invalidated, invalidation_reason, moderation_grant, insert_order
                 FROM app_events WHERE insert_order > ?1 AND insert_order <= ?2
                 ORDER BY insert_order LIMIT ?3",
            ).storage()?;
            let events = stmt.query_map(
                params![after, through, limit.clamp(1, 100) as i64],
                |row| Ok((raw_event_from_row(row)?, row.get::<_, i64>(14)?)),
            ).storage()?.collect::<Result<Vec<_>, _>>().storage()?;
            let mut affected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (event, _) in &events {
                backfill_authority_request(&conn, event)?;
                if matches!(event.kind, 1009 | 1984 | 1985 | 4891) {
                    for target in tag_values(&event.tags, "e") {
                        conn.execute_cached(
                            "INSERT OR IGNORE INTO message_modifier_edges (
                                group_id_hex, modifier_message_id_hex, target_message_id_hex,
                                kind, sender, recorded_at
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                            params![
                                event.group_id_hex, event.message_id_hex, target,
                                event.kind as i64, event.sender, event.recorded_at as i64,
                            ],
                        ).storage()?;
                    }
                }
                if matches!(event.kind, 1984 | 1985 | 4891) {
                    conn.execute_cached(
                        "DELETE FROM message_timeline
                         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
                        params![event.group_id_hex, event.message_id_hex],
                    ).storage()?;
                }
                let ids = affected_timeline_message_ids_for_parts_tx(
                    &conn, &event.group_id_hex, &event.message_id_hex, event.kind, &event.tags,
                )?;
                affected.entry(event.group_id_hex.clone()).or_default().extend(ids);
            }
            let mut updates = Vec::new();
            for (group, ids) in affected {
                for id in &ids {
                    upsert_message_timeline_projection_for_message_tx(&conn, &group, id)?;
                }
                let messages = timeline_records_by_ids_tx(&conn, &group, ids)?;
                let changes = messages.iter().cloned().map(|message| TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::SnapshotRefresh,
                    message: Box::new(message),
                }).collect();
                updates.push(TimelineProjectionUpdate {
                    group_id_hex: group, messages, changes,
                });
            }
            let cursor = events.last().map_or(through, |(_, order)| *order);
            conn.execute_cached(
                "UPDATE content_report_backfill SET after_order = ?1 WHERE singleton = 1",
                params![cursor],
            ).storage()?;
            Ok(updates)
        })
    }
}

// Historical custom controls had no source-policy verdict. Seed the same
// minimal retry ledger used by live delivery, without copying explanations.
fn backfill_authority_request(conn: &Connection, event: &RawAppEvent) -> StorageResult<()> {
    use cgka_traits::app_event::{MarmotAppEvent, PendingAppMessageAuthority};
    use sha2::{Digest, Sha256};
    if !matches!(
        event.kind,
        MARMOT_APP_EVENT_KIND_REPORT | MARMOT_APP_EVENT_KIND_REVIEW | MARMOT_APP_EVENT_KIND_REMOVE
    ) {
        return Ok(());
    }
    let unresolved: bool = conn
        .query_row_cached(
            "SELECT authority_state=1 FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![event.group_id_hex, event.message_id_hex],
            |row| row.get(0),
        )
        .storage()?;
    let (Some(source), Some(epoch)) = (&event.source_message_id_hex, event.source_epoch) else {
        return Ok(());
    };
    if !unresolved {
        return Ok(());
    }
    let (Ok(group), Ok(source), Ok(sender)) = (
        hex::decode(&event.group_id_hex),
        hex::decode(source),
        hex::decode(&event.sender),
    ) else {
        return Ok(());
    };
    let inner = MarmotAppEvent::new(
        &event.sender,
        event.recorded_at,
        event.kind,
        event.tags.clone(),
        &event.plaintext,
    );
    if inner.id != event.message_id_hex {
        return Ok(());
    }
    let payload = inner
        .encode()
        .map_err(|e| StorageError::Backend(e.to_string()))?;
    let (seconds, expires_at): (Option<i64>, Option<i64>) = conn.query_row_cached(
        "SELECT retention_seconds,retention_expires_at FROM app_events WHERE group_id_hex=?1 AND message_id_hex=?2",
        params![event.group_id_hex,event.message_id_hex],|r|Ok((r.get(0)?,r.get(1)?)),
    ).storage()?;
    let seconds = seconds.map(i64_to_u64).transpose()?;
    let expires_at = expires_at.map(i64_to_u64).transpose()?;
    let request = PendingAppMessageAuthority {
        group_id: cgka_traits::GroupId::new(group.clone()),
        message_id: cgka_traits::MessageId::new(source.clone()),
        epoch: cgka_traits::EpochId(epoch),
        sender: cgka_traits::MemberId::new(sender),
        payload_digest: Sha256::digest(payload).into(),
        retention: seconds.map(|retention_seconds| AppMessageRetentionDecision {
            retention_seconds,
            expires_at,
        }),
    };
    let record = crate::serialize(&request)?;
    conn.execute_cached(
        "INSERT OR IGNORE INTO pending_application_authority SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM cgka_messages WHERE id=?1 AND group_id=?2)",
        params![source,group,record],
    ).storage()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n: u8) -> String {
        hex::encode([n; 32])
    }
    fn event(n: u8, sender: u8, kind: u64, tags: Vec<Vec<String>>, text: &str) -> StoredAppEvent {
        StoredAppEvent {
            group_id_hex: id(99),
            message_id_hex: id(n),
            source_message_id_hex: Some(id(n)),
            source_epoch: Some(1),
            direction: "received".into(),
            sender: id(sender),
            plaintext: text.into(),
            kind,
            tags,
            recorded_at: n as u64,
            received_at: n as u64,
            origin_commit_id: None,
            moderation_grant: false,
        }
    }
    fn report(n: u8, reporter: u8, revision: u8) -> StoredAppEvent {
        event(
            n,
            reporter,
            1984,
            vec![
                vec!["e".into(), id(1), "spam".into()],
                vec!["p".into(), id(10)],
                vec!["revision".into(), id(revision)],
            ],
            "unwanted content",
        )
    }
    fn dismiss(n: u8, ids: &[u8]) -> StoredAppEvent {
        let namespace = cgka_traits::reporting::REPORT_REVIEW_NAMESPACE;
        let mut tags = vec![
            vec!["L".into(), namespace.into()],
            vec!["l".into(), "dismissed".into(), namespace.into()],
        ];
        tags.extend(ids.iter().map(|n| vec!["e".into(), id(*n)]));
        let mut e = event(n, 20, 1985, tags, "");
        e.moderation_grant = true;
        e
    }
    fn removal(n: u8, target: u8) -> StoredAppEvent {
        let mut e = event(
            n,
            20,
            4891,
            vec![vec!["e".into(), id(target)]],
            r#"{"v":1,"action":"remove"}"#,
        );
        e.moderation_grant = true;
        e
    }
    fn target() -> StoredAppEvent {
        event(1, 10, 9, vec![], "original")
    }
    fn page(s: &SqliteAccountStorage) -> ReportedContentPage {
        s.reported_content(&id(99), false, None, 100).unwrap()
    }
    fn moderation_rows(s: &SqliteAccountStorage) -> i64 {
        s.lock()
            .unwrap()
            .query_row("SELECT count(*) FROM content_moderation", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn unreported_edits_and_retractions_keep_revision_without_moderation_rows() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [
            target(),
            event(2, 10, 1009, vec![vec!["e".into(), id(1)]], "edited"),
            event(3, 11, 42, vec![], "custom event"),
        ] {
            s.record_app_event(&e).unwrap();
        }
        for rebuild in [false, true] {
            if rebuild {
                // Older projections mirrored every chat. Rebuilding clears those
                // empty rows without losing the current accepted revision.
                s.lock()
                    .unwrap()
                    .execute(
                        "INSERT INTO content_moderation VALUES (?1, ?2, ?2, 0, 0, 0)",
                        params![id(99), id(1)],
                    )
                    .unwrap();
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            assert_eq!(moderation_rows(&s), 0);
            let current = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert_eq!(current.plaintext, "edited");
            assert_eq!(current.revision_id_hex, id(2));
            assert_eq!(current.moderation, MessageModerationSummary::default());
            assert!(page(&s).items.is_empty());
        }
        s.record_app_event(&event(4, 10, 5, vec![vec!["e".into(), id(2)]], ""))
            .unwrap();
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            let current = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert_eq!(current.plaintext, "original");
            assert_eq!(current.revision_id_hex, id(1));
            assert_eq!(current.moderation, MessageModerationSummary::default());
            assert_eq!(moderation_rows(&s), 0);
        }
    }

    #[test]
    fn withdrawing_last_report_or_removal_clears_sparse_moderation_state() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        // An orphan report becomes materialized only after its target arrives.
        s.record_app_event(&report(2, 11, 1)).unwrap();
        assert_eq!(moderation_rows(&s), 0);
        s.record_app_event(&target()).unwrap();
        assert_eq!(moderation_rows(&s), 1);
        s.invalidate_app_event_by_source(&id(2), "losing_branch")
            .unwrap();
        assert_eq!(moderation_rows(&s), 0);
        assert!(
            s.message_reports(&id(99), &id(1), None, 10)
                .unwrap()
                .reports
                .is_empty()
        );
        assert_eq!(
            s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .moderation,
            MessageModerationSummary::default()
        );

        s.record_app_event(&removal(3, 1)).unwrap();
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            assert_eq!(moderation_rows(&s), 1);
            let current = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert_eq!(current.moderation.status, ModerationStatus::Removed);
            assert_eq!(current.moderation.total_reports, 0);
            assert!(page(&s).items.is_empty());
        }
        s.invalidate_app_event_by_source(&id(3), "losing_branch")
            .unwrap();
        assert_eq!(moderation_rows(&s), 0);
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
    }

    #[test]
    fn ordinary_refresh_is_one_bounded_read_for_chat_and_nonchat_events() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        use std::sync::atomic::{AtomicUsize, Ordering};

        static QUERIES: AtomicUsize = AtomicUsize::new(0);
        let s = SqliteAccountStorage::in_memory().unwrap();
        cgka_traits::StorageProvider::with_transaction(&s, |store| {
            for n in 1..=128 {
                store.record_app_event(&event(n, 10, 9, vec![], "ordinary chat"))?;
            }
            store.record_app_event(&event(200, 10, 42, vec![], "custom event"))?;
            Ok::<_, StorageError>(())
        })
        .unwrap();
        let conn = s.lock().unwrap();
        conn.flush_prepared_statement_cache();
        conn.trace_v2(
            TraceEventCodes::SQLITE_TRACE_PROFILE,
            Some(|event| {
                if let TraceEvent::Profile(stmt, _) = event {
                    assert!(stmt.sql().starts_with("SELECT EXISTS"));
                    assert!(stmt.get_status(rusqlite::StatementStatus::VmStep) < 128);
                    QUERIES.fetch_add(1, Ordering::Relaxed);
                }
            }),
        );
        refresh(&conn, &id(99), &id(1)).unwrap();
        refresh(&conn, &id(99), &id(200)).unwrap();
        conn.trace_v2(TraceEventCodes::empty(), None);
        assert_eq!(QUERIES.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn report_and_dismissal_converge_in_every_delivery_order() {
        let events = [target(), report(2, 11, 1), dismiss(3, &[2])];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            for i in order {
                s.record_app_event(&events[i]).unwrap();
            }
            let p = page(&s);
            assert_eq!(p.items.len(), 1);
            assert_eq!(p.items[0].moderation.status, ModerationStatus::Reviewed);
            assert_eq!(p.pending_message_count, 0);
            assert_eq!(
                s.message_timeline(TimelineMessageQuery::default())
                    .unwrap()
                    .messages
                    .len(),
                1
            );
            s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            assert_eq!(page(&s), p);
        }
    }
    #[test]
    fn duplicate_after_dismissal_does_not_reopen_but_new_reporter_does() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [
            target(),
            report(2, 11, 1),
            dismiss(3, &[2]),
            report(4, 11, 1),
        ] {
            s.record_app_event(&e).unwrap();
        }
        assert_eq!(page(&s).items[0].moderation.total_reports, 1);
        assert_eq!(page(&s).pending_message_count, 0);
        s.record_app_event(&report(5, 12, 1)).unwrap();
        assert_eq!(page(&s).items[0].moderation.pending_reports, 1);
        assert_eq!(page(&s).items[0].moderation.total_reports, 2);
    }
    #[test]
    fn revision_is_validated_and_original_report_survives_edit() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2, 11, 1), report(4, 11, 3)] {
            s.record_app_event(&e).unwrap();
        }
        assert_eq!(page(&s).items[0].moderation.total_reports, 1);
        s.record_app_event(&event(3, 10, 1009, vec![vec!["e".into(), id(1)]], "edited"))
            .unwrap();
        assert_eq!(page(&s).items[0].moderation.total_reports, 2);
        assert_eq!(page(&s).items[0].revision_id_hex, id(3));
        let details = s.message_reports(&id(99), &id(1), None, 100).unwrap();
        assert_eq!(
            details.reports[0].reported_text.as_deref(),
            Some("original")
        );
        assert_eq!(details.reports[1].reported_text.as_deref(), Some("edited"));
        let current = details.current_message.unwrap();
        assert_eq!(current.plaintext, "edited");
        assert_eq!(current.revision_id_hex, id(3));
        assert_eq!(current.edit.unwrap().latest_edit_message_id_hex, id(3));
        s.record_app_event(&event(5, 10, 5, vec![vec!["e".into(), id(3)]], ""))
            .unwrap();
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            let current = s
                .message_reports(&id(99), &id(1), None, 100)
                .unwrap()
                .current_message
                .unwrap();
            assert_eq!(current.plaintext, "original");
            assert_eq!(current.revision_id_hex, id(1));
            assert!(current.edit.is_none());
            assert_eq!(page(&s).items[0].revision_id_hex, id(1));
            assert_eq!(page(&s).items[0].moderation.total_reports, 2);
        }
    }
    #[test]
    fn removal_hides_all_revisions_and_review_content_even_after_rebuild() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        let mut delete = removal(5, 1);
        delete.moderation_grant = true;
        let mut target = target();
        target.tags.push(vec![
            "imeta".into(),
            "url https://example.com/image.png".into(),
            "m image/png".into(),
        ]);
        s.record_app_event(&target).unwrap();
        assert!(
            s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .media
                .is_some()
        );
        s.record_app_event(&event(6, 12, 9, vec![vec!["q".into(), id(1)]], "reply"))
            .unwrap();
        for e in [
            target,
            report(2, 11, 1),
            delete,
            event(3, 10, 1009, vec![vec!["e".into(), id(1)]], "edited"),
        ] {
            s.record_app_event(&e).unwrap();
        }
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            assert_eq!(
                page(&s).items[0].moderation.status,
                ModerationStatus::Removed
            );
            assert_eq!(page(&s).pending_message_count, 0);
            assert!(
                s.message_reports(&id(99), &id(1), None, 100)
                    .unwrap()
                    .reports[0]
                    .reported_text
                    .is_none()
            );
            assert!(
                s.message_timeline(TimelineMessageQuery::default())
                    .unwrap()
                    .messages
                    .iter()
                    .filter(|m| m.message_id_hex != id(6))
                    .all(|m| m.deleted && m.plaintext.is_empty() && m.media.is_none())
            );
            let reply = s
                .timeline_message(&id(99), &id(6))
                .unwrap()
                .unwrap()
                .reply_preview
                .unwrap();
            assert!(reply.deleted && reply.plaintext.is_empty() && reply.media.is_none());
            for search in ["original", "edited"] {
                assert!(
                    s.message_timeline(TimelineMessageQuery {
                        search: Some(search.into()),
                        ..Default::default()
                    })
                    .unwrap()
                    .messages
                    .is_empty()
                );
            }
        }
    }
    #[test]
    fn new_kind_five_is_author_only_but_existing_legacy_tombstones_survive() {
        let authority = Some(AppMessageAuthority {
            source_context: [1; 32],
            moderation_grant: true,
            reporting_allowed: true,
        });
        let mut deletion = event(2, 20, 5, vec![vec!["e".into(), id(1)]], "");
        deletion.moderation_grant = true;
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.record_app_event_with_source(&deletion, None, authority)
            .unwrap();
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
        s.record_app_event_with_source(
            &event(3, 10, 5, vec![vec!["e".into(), id(1)]], ""),
            None,
            authority,
        )
        .unwrap();
        assert!(
            s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
        let legacy = SqliteAccountStorage::in_memory().unwrap();
        legacy.record_app_event(&target()).unwrap();
        legacy.record_app_event(&deletion).unwrap();
        legacy
            .record_app_event_with_source(&deletion, None, None)
            .unwrap();
        legacy
            .record_app_event_with_source(&deletion, None, authority)
            .unwrap();
        legacy.rebuild_message_timeline_for_group(&id(99)).unwrap();
        assert!(
            legacy
                .timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
    }
    #[test]
    fn removal_before_target_and_edit_converges_and_invalidation_withdraws_it() {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            let events = [
                target(),
                event(3, 10, 1009, vec![vec!["e".into(), id(1)]], "edited"),
                removal(4, 1),
            ];
            for i in order {
                s.record_app_event(&events[i]).unwrap();
            }
            for rebuild in [false, true] {
                if rebuild {
                    s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                }
                assert!(
                    s.timeline_message(&id(99), &id(1))
                        .unwrap()
                        .unwrap()
                        .deleted,
                    "order {order:?}, rebuild {rebuild}"
                );
                assert!(s.timeline_message(&id(99), &id(3)).unwrap().is_none());
                assert!(
                    s.message_edit_history(&id(99), &id(1), None, 100)
                        .unwrap()
                        .versions
                        .is_empty()
                );
            }
            s.invalidate_app_event_by_source(&id(4), "losing_branch")
                .unwrap();
            assert!(
                !s.timeline_message(&id(99), &id(1))
                    .unwrap()
                    .unwrap()
                    .deleted
            );
        }
    }
    #[test]
    fn unauthorized_review_and_cross_group_or_wrong_author_reports_have_no_effect() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        let mut wrong = report(2, 11, 1);
        wrong.tags[1][1] = id(40);
        s.record_app_event(&wrong).unwrap();
        assert!(page(&s).items.is_empty());
        let mut cross = report(3, 11, 1);
        cross.group_id_hex = id(98);
        s.record_app_event(&cross).unwrap();
        assert!(page(&s).items.is_empty());
        s.record_app_event(&report(4, 11, 1)).unwrap();
        let mut review = dismiss(5, &[4]);
        review.moderation_grant = false;
        s.record_app_event(&review).unwrap();
        let mut unauthorized_removal = removal(6, 1);
        unauthorized_removal.sender = target().sender;
        unauthorized_removal.moderation_grant = false;
        s.record_app_event(&unauthorized_removal).unwrap();
        // A kind-4891 event always requires admin authority, even from the author.
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
        let mut cross_removal = removal(7, 1);
        cross_removal.group_id_hex = id(98);
        s.record_app_event(&cross_removal).unwrap();
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .deleted
        );
        assert_eq!(page(&s).pending_message_count, 1);
    }
    #[test]
    fn unknown_source_authority_can_resolve_without_freezing_a_denial() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2, 11, 1)] {
            s.record_app_event(&e).unwrap();
        }
        let review = dismiss(3, &[2]);
        s.record_app_event_with_source(&review, None, None).unwrap();
        assert_eq!(page(&s).pending_message_count, 1);
        s.finalize_app_event_authority(
            &id(99),
            &id(3),
            Some(AppMessageAuthority {
                source_context: [7; 32],
                reporting_allowed: true,
                moderation_grant: true,
            }),
        )
        .unwrap();
        assert_eq!(page(&s).pending_message_count, 0);
        s.record_app_event_with_source(
            &review,
            None,
            Some(AppMessageAuthority {
                source_context: [8; 32],
                reporting_allowed: true,
                moderation_grant: false,
            }),
        )
        .unwrap();
        assert_eq!(page(&s).pending_message_count, 0);
    }
    #[test]
    fn projection_failure_rolls_back_report_and_raw_event() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.lock().unwrap().execute_batch("CREATE TEMP TRIGGER reject_report BEFORE INSERT ON content_reports BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
        assert!(s.record_app_event(&report(2, 11, 1)).is_err());
        assert!(s.app_message(&id(99), &id(2)).unwrap().is_none());
        assert!(page(&s).items.is_empty());
    }
    #[test]
    fn review_invalidation_reopens_its_reports() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2, 11, 1), dismiss(3, &[2])] {
            s.record_app_event(&e).unwrap();
        }
        s.invalidate_app_event_by_source(&id(3), "losing_branch")
            .unwrap();
        assert_eq!(page(&s).pending_message_count, 1);
    }

    #[test]
    fn retention_prunes_explanations_without_reopening_or_resurrection() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        let mut report = report(2, 11, 1);
        report.tags[0][2] = "other".into();
        for e in [target(), report.clone(), dismiss(3, &[2])] {
            s.record_app_event(&e).unwrap();
        }
        {
            let conn = s.lock().unwrap();
            let mut ids = BTreeSet::from([id(2), id(3)]);
            retain_pruned_controls(&conn, &id(99), &mut ids).unwrap();
            assert!(ids.is_empty());
        }
        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
        assert_eq!(
            page(&s).items[0].moderation.status,
            ModerationStatus::Reviewed
        );
        assert_eq!(
            s.message_reports(&id(99), &id(1), None, 10)
                .unwrap()
                .reports[0]
                .explanation,
            ""
        );
        s.record_app_event(&report).unwrap();
        assert_eq!(
            s.message_reports(&id(99), &id(1), None, 10)
                .unwrap()
                .reports[0]
                .explanation,
            ""
        );
        let mut deletion = removal(4, 1);
        deletion.moderation_grant = true;
        s.record_app_event(&deletion).unwrap();
        {
            let conn = s.lock().unwrap();
            let mut ids = BTreeSet::from([id(4)]);
            retain_pruned_controls(&conn, &id(99), &mut ids).unwrap();
        }
        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
        assert_eq!(
            page(&s).items[0].moderation.status,
            ModerationStatus::Removed
        );
    }
    #[test]
    fn reports_pagination_is_bounded_and_concurrent_dismissals_converge() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        for n in 30..140 {
            s.record_app_event(&report(n, n, 1)).unwrap();
        }
        let first = s.message_reports(&id(99), &id(1), None, 10000).unwrap();
        assert_eq!(first.reports.len(), 100);
        let second = s
            .message_reports(&id(99), &id(1), first.next_cursor.as_deref(), 100)
            .unwrap();
        assert_eq!(second.reports.len(), 10);
        assert!(second.next_cursor.is_none());
        s.record_app_event(&dismiss(10, &[30])).unwrap();
        s.record_app_event(&dismiss(9, &[30])).unwrap();
        assert_eq!(
            s.message_reports(&id(99), &id(1), None, 1).unwrap().reports[0].dismissed_by_event_id,
            Some(id(9))
        );
        assert_eq!(page(&s).items[0].moderation.pending_reports, 109);
    }
    #[test]
    fn bounded_backfill_restores_preexisting_reports_and_progress() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2, 11, 1), dismiss(3, &[2])] {
            s.record_app_event(&e).unwrap();
        }
        {
            let conn = s.lock().unwrap();
            conn.execute_batch("DELETE FROM content_reports; DELETE FROM content_moderation; DELETE FROM message_modifier_edges WHERE kind IN (1984,1985,4891); UPDATE content_report_backfill SET after_order=0,through_order=(SELECT MAX(insert_order) FROM app_events)").unwrap();
        }
        for _ in 0..3 {
            s.backfill_content_reports(1).unwrap();
        }
        assert_eq!(
            page(&s).items[0].moderation.status,
            ModerationStatus::Reviewed
        );
        assert!(s.backfill_content_reports(1).unwrap().is_empty());
    }
    #[test]
    fn unresolved_report_retention_stays_scrubbed_after_authority_recovery() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        let mut report = report(2, 11, 1);
        report.tags[0][2] = "other".into();
        report.plaintext = "private explanation".into();
        s.record_app_event_with_source(&report, None, None).unwrap();
        {
            let conn = s.lock().unwrap();
            let mut ids = BTreeSet::from([id(2)]);
            retain_pruned_controls(&conn, &id(99), &mut ids).unwrap();
            assert!(ids.is_empty());
        }
        s.record_app_event_with_source(
            &report,
            None,
            Some(AppMessageAuthority {
                source_context: [1; 32],
                moderation_grant: false,
                reporting_allowed: true,
            }),
        )
        .unwrap();
        let details = s.message_reports(&id(99), &id(1), None, 10).unwrap();
        assert_eq!(details.reports.len(), 1);
        assert!(details.reports[0].explanation.is_empty());
    }
    #[test]
    fn legacy_controls_seed_minimal_authority_retries_during_bounded_backfill() {
        use crate::storage::test_support::{sample_group, sample_message};
        use cgka_traits::storage::{GroupStorage, MessageStorage};
        use cgka_traits::{GroupId, MessageId};
        let s = SqliteAccountStorage::in_memory().unwrap();
        let group = GroupId::new(vec![99; 32]);
        let source = MessageId::new(vec![50; 32]);
        s.put_group(&sample_group(group.clone(), 2, 3)).unwrap();
        s.put_message(&sample_message(source.clone(), group.clone(), 2))
            .unwrap();
        let mut report = report(2, 11, 1);
        let inner = cgka_traits::app_event::MarmotAppEvent::new(
            &report.sender,
            report.recorded_at,
            report.kind,
            report.tags.clone(),
            &report.plaintext,
        );
        report.message_id_hex = inner.id;
        report.source_message_id_hex = Some(hex::encode(source.as_slice()));
        report.source_epoch = Some(2);
        s.record_app_event(&target()).unwrap();
        s.record_app_event(&report).unwrap();
        s.lock().unwrap().execute_batch("UPDATE app_events SET authority_state=1,reporting_allowed=0,moderation_grant=0 WHERE kind IN (1984,1985,4891); DELETE FROM content_reports; DELETE FROM content_moderation; UPDATE content_report_backfill SET after_order=0,through_order=(SELECT MAX(insert_order) FROM app_events)").unwrap();
        for _ in 0..2 {
            s.backfill_content_reports(1).unwrap();
        }
        assert!(page(&s).items.is_empty());
        let retries = s.pending_application_authority_batch(None, 10).unwrap();
        assert_eq!(retries.len(), 1);
        assert_eq!(retries[0].message_id, source);
        assert_eq!(retries[0].group_id, group);
        assert!(
            !serde_json::to_string(&retries)
                .unwrap()
                .contains("plaintext")
        );
    }
    #[test]
    fn noneligible_source_reports_remain_outside_shared_queue() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.record_app_event_with_source(
            &report(2, 11, 1),
            None,
            Some(AppMessageAuthority {
                source_context: [0; 32],
                moderation_grant: false,
                reporting_allowed: false,
            }),
        )
        .unwrap();
        assert!(page(&s).items.is_empty());
    }

    #[test]
    fn personal_blocking_does_not_hide_reported_revision_from_review() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2, 11, 1)] {
            s.record_app_event(&e).unwrap();
        }
        s.lock()
            .unwrap()
            .execute("INSERT INTO user_blocks VALUES(?1,0,0)", params![id(10)])
            .unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        s.record_app_event(&event(
            3,
            10,
            1009,
            vec![vec!["e".into(), id(1)]],
            "late edit",
        ))
        .unwrap();
        assert!(s.timeline_message(&id(99), &id(3)).unwrap().is_none());
        let details = s.message_reports(&id(99), &id(1), None, 10).unwrap();
        let current = details.current_message.unwrap();
        assert_eq!(current.plaintext, "late edit");
        assert_eq!(current.revision_id_hex, id(3));
        assert_eq!(
            details.reports[0]
                .reported_revision
                .as_ref()
                .unwrap()
                .plaintext,
            "original"
        );
    }

    #[test]
    fn pending_local_report_is_reused_before_authority_is_finalized() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.record_app_event_with_source(&report(2, 11, 1), None, None)
            .unwrap();
        assert_eq!(
            s.own_report(&id(99), &id(1), &id(1), &id(11)).unwrap(),
            Some(id(2))
        );
        assert!(page(&s).items.is_empty());
    }

    #[test]
    fn mixed_review_targets_resolve_each_report_independently() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        let mut cross_target = target();
        cross_target.group_id_hex = id(98);
        cross_target.source_message_id_hex = Some(id(50));
        let mut cross_report = report(5, 12, 1);
        cross_report.group_id_hex = id(98);
        for e in [
            target(),
            report(2, 11, 1),
            event(4, 10, 9, vec![], "not a report"),
            cross_target,
            cross_report,
            dismiss(6, &[2, 3, 4, 5]),
        ] {
            s.record_app_event(&e).unwrap();
        }
        assert_eq!(
            page(&s).items[0].moderation.status,
            ModerationStatus::Reviewed
        );
        assert_eq!(page(&s).items[0].moderation.total_reports, 1);
        // The unknown reference remains in the control and applies on arrival.
        s.record_app_event(&report(3, 13, 1)).unwrap();
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                s.rebuild_message_timeline_for_group(&id(98)).unwrap();
            }
            let moderation = &page(&s).items[0].moderation;
            assert_eq!(moderation.status, ModerationStatus::Reviewed);
            assert_eq!(moderation.total_reports, 2);
            let details = s.message_reports(&id(99), &id(1), None, 10).unwrap();
            assert!(
                details
                    .reports
                    .iter()
                    .all(|r| r.dismissed_by_event_id == Some(id(6)))
            );
            let untouched = s.timeline_message(&id(99), &id(4)).unwrap().unwrap();
            assert_eq!(untouched.moderation.status, ModerationStatus::Unreported);
            assert!(!untouched.deleted);
            let cross = s.reported_content(&id(98), false, None, 10).unwrap();
            assert_eq!(cross.items[0].moderation.status, ModerationStatus::Pending);
            assert_eq!(cross.pending_message_count, 1);
        }
    }

    #[test]
    fn kind_five_cannot_withdraw_reports_reviews_or_removals() {
        for control_kind in [1984, 1985, 4891] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            s.record_app_event(&target()).unwrap();
            s.record_app_event(&report(2, 11, 1)).unwrap();
            let (control, expected_status, expected_pending) = match control_kind {
                1984 => (report(2, 11, 1), ModerationStatus::Pending, 1),
                1985 => (dismiss(3, &[2]), ModerationStatus::Reviewed, 0),
                4891 => (removal(4, 1), ModerationStatus::Removed, 0),
                _ => unreachable!(),
            };
            s.record_app_event(&control).unwrap();
            let mut deletion = event(
                10,
                0,
                5,
                vec![vec!["e".into(), control.message_id_hex.clone()]],
                "",
            );
            deletion.sender = control.sender.clone();
            s.record_app_event(&deletion).unwrap();
            for rebuild in [false, true] {
                if rebuild {
                    s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                }
                let moderation = &page(&s).items[0].moderation;
                assert_eq!(moderation.total_reports, 1);
                assert_eq!(moderation.pending_reports, expected_pending);
                assert_eq!(moderation.status, expected_status);
                let raw_control = raw(&s.lock().unwrap(), &id(99), &control.message_id_hex)
                    .unwrap()
                    .unwrap();
                assert!(!raw_control.invalidated);
            }
        }
    }

    #[test]
    fn expiry_and_explicit_erasure_keep_only_moderated_target_markers() {
        for expire_by_policy in [false, true] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            for n in [1, 3, 5].into_iter().chain(30..50) {
                let chat = event(n, 10, 9, vec![], "expiring chat");
                s.record_app_event_with_retention(
                    &chat,
                    Some(AppMessageRetentionDecision::new(chat.recorded_at, 1)),
                )
                .unwrap();
            }
            let authority = AppMessageAuthority {
                source_context: [7; 32],
                moderation_grant: false,
                reporting_allowed: true,
            };
            s.record_app_event_with_source(&report(2, 11, 1), None, Some(authority))
                .unwrap();
            let mut unresolved = report(4, 11, 3);
            unresolved.tags[0][1] = id(3);
            s.record_app_event_with_source(&unresolved, None, None)
                .unwrap();
            assert_eq!(moderation_rows(&s), 1);
            s.record_app_event(&removal(6, 5)).unwrap();
            if expire_by_policy {
                s.secure_prune_expired_app_events(&id(99), 100, "local", &|_, _| false)
                    .unwrap();
            } else {
                s.secure_prune_app_events_before(&id(99), 100, "local", &|_, _| false)
                    .unwrap();
            }
            {
                let conn = s.lock().unwrap();
                let mut stmt = conn.prepare(
                    "SELECT message_id_hex FROM content_expired_targets ORDER BY message_id_hex",
                ).unwrap();
                let ids = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                assert_eq!(ids, vec![id(1), id(3), id(5)]);
                let provenance: Vec<u8> = conn
                    .query_row(
                        "SELECT authority_context FROM app_events WHERE message_id_hex = ?1",
                        params![id(2)],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(provenance, authority.source_context);
            }
            assert_eq!(moderation_rows(&s), 0);
            assert!(
                s.message_timeline(TimelineMessageQuery::default())
                    .unwrap()
                    .messages
                    .is_empty()
            );
            // Both approved and unresolved reports retain only structural evidence.
            for n in [2, 4] {
                assert!(
                    s.app_message(&id(99), &id(n))
                        .unwrap()
                        .unwrap()
                        .plaintext
                        .is_empty()
                );
            }
            for n in [1, 3, 5] {
                s.record_app_event(&event(n, 10, 9, vec![], "late duplicate"))
                    .unwrap();
                assert!(s.timeline_message(&id(99), &id(n)).unwrap().is_none());
            }
        }
    }

    #[test]
    fn ordinary_erased_chat_has_no_moderation_replay_fence() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.secure_prune_app_events_before(&id(99), 2, "local", &|_, _| false)
            .unwrap();
        assert!(!target_expired(&s.lock().unwrap(), &id(99), &id(1)).unwrap());
        // Generic dedup/retention remains owned by the existing ingress rails.
        // The moderation projection does not veto an ordinary record operation.
        s.record_app_event(&target()).unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_some());
        assert_eq!(moderation_rows(&s), 0);
    }

    #[test]
    fn late_reports_cannot_retain_explanations_or_restore_expired_targets() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event(&target()).unwrap();
        s.record_app_event(&report(4, 11, 1)).unwrap();
        s.secure_prune_expired_app_events(&id(99), 10, "local", &|_, _| false)
            .unwrap();
        // Exercise the explicit erasure rail, which also records the marker.
        s.prune_app_events_before(&id(99), 2, "local", &|_, _| false)
            .unwrap();
        let e = report(2, 11, 1);
        s.record_app_event(&e).unwrap();
        assert!(
            s.app_message(&id(99), &id(2))
                .unwrap()
                .unwrap()
                .plaintext
                .is_empty()
        );
        s.record_app_event(&target()).unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        s.record_app_event(&event(
            3,
            10,
            1009,
            vec![vec!["e".into(), id(1)]],
            "late edit",
        ))
        .unwrap();
        assert!(s.timeline_message(&id(99), &id(3)).unwrap().is_none());
        assert!(page(&s).items.is_empty());
    }
}
