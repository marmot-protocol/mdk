//! Individual in-group reports and admin dismissal labels. No shared review workflow.
use super::*;
use cgka_traits::app_event::AppMessageAuthority;
use cgka_traits::reporting::{ReportReason, parse_dismissal, parse_removal, parse_report};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReport {
    pub report_id_hex: String,
    pub message_id_hex: String,
    pub message_author: String,
    pub reporter: String,
    pub reason: ReportReason,
    pub explanation: String,
    pub reported_at: u64,
    /// At least one authenticated admin labeled this specific report dismissed.
    pub dismissed: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentReportPage {
    pub reports: Vec<ContentReport>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDismissal {
    pub event_id_hex: String,
    pub admin: String,
    pub explanation: String,
    pub created_at: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDismissalPage {
    pub labels: Vec<ReportDismissal>,
    pub next_cursor: Option<String>,
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

// One row per event. References can arrive before their targets. If the target
// is available, a mismatched author cannot mark that message as reported.
pub(super) fn refresh(conn: &Connection, group: &str, target: &str) -> StorageResult<()> {
    let original = raw(conn, group, target)?;
    conn.execute_cached(
        "DELETE FROM content_reports WHERE group_id_hex=?1 AND message_id_hex=?2",
        params![group, target],
    )
    .storage()?;
    for report in
        app_events_targeting_message_tx(conn, group, MARMOT_APP_EVENT_KIND_REPORT, target)?
    {
        let Some(reference) = parse_report(&report.tags, &report.plaintext) else {
            continue;
        };
        if reference.target != target
            || original
                .as_ref()
                .is_some_and(|e| e.sender != reference.author)
        {
            continue;
        }
        conn.execute_cached(
            "INSERT INTO content_reports(group_id_hex,report_id_hex,message_id_hex,message_author,reporter,reason,reported_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![group, report.message_id_hex, target, reference.author, report.sender,
                reference.reason.as_str(), u64_to_i64(report.recorded_at)?]).storage()?;
    }
    Ok(())
}

pub(super) fn hydrate(
    conn: &Connection,
    messages: &mut [TimelineMessageRecord],
) -> StorageResult<()> {
    // Batch indexed probes, scoped to the exact group, message and author.
    // EXISTS stops at the first report, even when a target has many reports.
    let mut reported = HashSet::new();
    for chunk in messages.chunks(SQLITE_BIND_PARAMETER_CHUNK / 3) {
        let values = vec!["(?, ?, ?)"; chunk.len()].join(",");
        let sql = format!(
            "WITH report_targets(group_id_hex, message_id_hex, message_author) AS (VALUES {values})
             SELECT t.group_id_hex, t.message_id_hex, t.message_author FROM report_targets t
             WHERE EXISTS (SELECT 1 FROM content_reports c
               WHERE c.group_id_hex=t.group_id_hex AND c.message_id_hex=t.message_id_hex
                 AND c.message_author=t.message_author)"
        );
        let mut statement = conn.prepare_cached(&sql).storage()?;
        let rows = statement
            .query_map(
                params_from_iter(chunk.iter().flat_map(|m| {
                    [
                        m.group_id_hex.as_str(),
                        m.message_id_hex.as_str(),
                        m.sender.as_str(),
                    ]
                })),
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .storage()?;
        for row in rows {
            reported.insert(row.storage()?);
        }
    }
    for message in messages {
        message.has_reports = reported.contains(&(
            message.group_id_hex.clone(),
            message.message_id_hex.clone(),
            message.sender.clone(),
        ));
    }
    Ok(())
}

fn dismissal_page(
    conn: &Connection,
    group: &str,
    report: &str,
    after: Option<&str>,
    limit: usize,
) -> StorageResult<ReportDismissalPage> {
    let mut labels = Vec::new();
    // Query in bounded batches before parsing: unrelated NIP-32 labels may
    // reference the same report, and do not consume the returned page limit.
    let mut cursor = after.map(str::to_owned);
    loop {
        let mut statement = conn
            .prepare_cached(
                "SELECT e.message_id_hex,e.sender,e.plaintext,e.recorded_at,e.tags_json
             FROM message_modifier_edges x JOIN app_events e
               ON e.group_id_hex=x.group_id_hex AND e.message_id_hex=x.modifier_message_id_hex
             WHERE x.group_id_hex=?1 AND x.target_message_id_hex=?2 AND x.kind=1985
               AND e.invalidated=0 AND e.moderation_grant=1 AND e.authority_state=2
               AND x.modifier_message_id_hex>COALESCE(?3,'')
             ORDER BY x.modifier_message_id_hex LIMIT 100",
            )
            .storage()?;
        let rows = statement
            .query_map(params![group, report, cursor], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        if rows.is_empty() {
            break;
        }
        for (id, admin, explanation, created_at, tags) in rows {
            cursor = Some(id.clone());
            if let Ok(tags) = serde_json::from_str::<Vec<Vec<String>>>(&tags)
                && parse_dismissal(&tags, &explanation)
                    .is_some_and(|ids| ids.iter().any(|id| id == report))
            {
                labels.push(ReportDismissal {
                    event_id_hex: id,
                    admin,
                    explanation,
                    created_at: created_at as u64,
                });
                if labels.len() > limit {
                    labels.truncate(limit);
                    let next_cursor = labels.last().map(|label| label.event_id_hex.clone());
                    return Ok(ReportDismissalPage {
                        labels,
                        next_cursor,
                    });
                }
            }
        }
    }
    Ok(ReportDismissalPage {
        labels,
        next_cursor: None,
    })
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
                    END
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND authority_state != 2",
                    params![
                        group,
                        id,
                        authority.source_context.as_slice(),
                        authority.moderation_grant,
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

    /// Individual reports in a group, optionally filtered to one app message.
    /// This shared content query deliberately bypasses personal timeline blocks.
    pub fn content_reports(
        &self,
        group: &str,
        message: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<ContentReportPage> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 100);
        // Choose an indexed target range for per-message queries; do not scan
        // every report in the group to find one message's page.
        let sql = format!("SELECT r.report_id_hex,r.message_id_hex,r.message_author,r.reporter,r.reason,e.plaintext,r.reported_at
             FROM content_reports r JOIN app_events e ON e.group_id_hex=r.group_id_hex AND e.message_id_hex=r.report_id_hex
             WHERE r.group_id_hex=?1 AND {}
               AND r.report_id_hex>COALESCE(?3,'') AND e.invalidated=0
             ORDER BY r.report_id_hex LIMIT ?4", if message.is_some() {"r.message_id_hex=?2"} else {"?2 IS NULL"});
        let mut statement = conn.prepare_cached(&sql).storage()?;
        let mut reports = statement
            .query_map(params![group, message, after, (limit + 1) as i64], |r| {
                Ok(ContentReport {
                    report_id_hex: r.get(0)?,
                    message_id_hex: r.get(1)?,
                    message_author: r.get(2)?,
                    reporter: r.get(3)?,
                    reason: ReportReason::parse(&r.get::<_, String>(4)?)
                        .unwrap_or(ReportReason::Other),
                    explanation: r.get(5)?,
                    reported_at: r.get::<_, i64>(6)? as u64,
                    dismissed: false,
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
        for report in &mut reports {
            report.dismissed = !dismissal_page(&conn, group, &report.report_id_hex, None, 1)?
                .labels
                .is_empty();
        }
        Ok(ContentReportPage {
            reports,
            next_cursor,
        })
    }
    pub fn report_dismissals(
        &self,
        group: &str,
        report: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<ReportDismissalPage> {
        let conn = self.lock()?;
        if !raw(&conn, group, report)?.is_some_and(|e| e.kind == 1984 && !e.invalidated) {
            return Ok(ReportDismissalPage {
                labels: Vec::new(),
                next_cursor: None,
            });
        }
        dismissal_page(&conn, group, report, after, limit.clamp(1, 100))
    }
    /// The current projection for a reported message, including removal masking.
    /// Personal blocks do not prevent a member from inspecting reported content.
    pub fn reported_message(
        &self,
        group: &str,
        message: &str,
    ) -> StorageResult<Option<TimelineMessageRecord>> {
        let conn = self.lock()?;
        let reported: bool = conn.query_row_cached("SELECT EXISTS(SELECT 1 FROM content_reports WHERE group_id_hex=?1 AND message_id_hex=?2)",params![group,message],|r|r.get(0)).storage()?;
        if !reported {
            return Ok(None);
        }
        Ok(
            timeline_records_by_ids_tx(&conn, group, BTreeSet::from([message.to_owned()]))?
                .into_iter()
                .next(),
        )
    }
    pub fn report_target_author(&self, group: &str, target: &str) -> StorageResult<Option<String>> {
        let conn = self.lock()?;
        Ok(raw(&conn, group, target)?
            .filter(|e| !e.invalidated)
            .map(|e| e.sender))
    }
    pub fn report_is_reviewable(&self, group: &str, id: &str) -> StorageResult<bool> {
        let conn = self.lock()?;
        Ok(raw(&conn, group, id)?.is_some_and(|e| e.kind == 1984 && !e.invalidated))
    }
}

// Retain only deletion evidence; reports and labels use ordinary message retention.
pub(super) fn retain_expired_target(
    conn: &Connection,
    group: &str,
    target: &str,
) -> StorageResult<()> {
    conn.execute_cached(
        "INSERT OR IGNORE INTO content_expired_targets (group_id_hex, message_id_hex)
         SELECT ?1, ?2 WHERE EXISTS (
            SELECT 1 FROM message_modifier_edges AS edges
            CROSS JOIN content_pruned_controls AS controls
              ON controls.group_id_hex = edges.group_id_hex
             AND controls.message_id_hex = edges.modifier_message_id_hex
            WHERE edges.group_id_hex = ?1 AND edges.target_message_id_hex = ?2
              AND edges.kind IN (5, 4891)
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
                    (5 | 4891, Some("e")) => 2,
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
            || (event.kind == 4891 && parse_removal(&event.tags, &event.plaintext).is_some())
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
    /// Repair only indexed deletion, edit and moderation events in the captured
    /// pre-migration prefix. Ordinary history is neither scanned nor reprojected.
    pub fn backfill_content_reports(
        &self,
        limit: usize,
    ) -> StorageResult<Vec<TimelineProjectionUpdate>> {
        let limit = limit.clamp(1, 100);
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
                   AND kind IN (5,1009,1984,1985,4891)
                 ORDER BY insert_order LIMIT ?3",
            ).storage()?;
            let events = stmt.query_map(
                params![after, through, limit as i64],
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
            let cursor = if events.len() < limit {
                through
            } else {
                events.last().map_or(through, |(_, order)| *order)
            };
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
        MARMOT_APP_EVENT_KIND_REVIEW | MARMOT_APP_EVENT_KIND_REMOVE
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
    fn target() -> StoredAppEvent {
        event(1, 10, 9, vec![], "original")
    }
    fn report(n: u8) -> StoredAppEvent {
        event(
            n,
            11,
            1984,
            vec![
                vec!["e".into(), id(1), "spam".into()],
                vec!["p".into(), id(10)],
            ],
            "quoted explanation",
        )
    }
    fn dismiss(n: u8, reports: &[u8]) -> StoredAppEvent {
        let ns = cgka_traits::reporting::REPORT_REVIEW_NAMESPACE;
        let mut tags = vec![
            vec!["L".into(), ns.into()],
            vec!["l".into(), "dismissed".into(), ns.into()],
        ];
        tags.extend(reports.iter().map(|n| vec!["e".into(), id(*n)]));
        event(n, 20, 1985, tags, "admin explanation")
    }
    fn removal(n: u8, target: u8) -> StoredAppEvent {
        event(
            n,
            20,
            4891,
            vec![vec!["e".into(), id(target)]],
            r#"{"v":1,"action":"remove"}"#,
        )
    }
    fn authority(grant: bool) -> AppMessageAuthority {
        AppMessageAuthority {
            source_context: [42; 32],
            moderation_grant: grant,
        }
    }
    fn record(s: &SqliteAccountStorage, e: &StoredAppEvent) {
        let proof =
            cgka_traits::reporting::requires_source_authority(e.kind).then(|| authority(true));
        s.record_app_event_with_source(e, None, proof).unwrap();
    }
    fn page(s: &SqliteAccountStorage) -> ContentReportPage {
        s.content_reports(&id(99), None, None, 100).unwrap()
    }
    #[test]
    fn deletion_provenance_survives_reload_and_rebuild_and_updates_dependents() {
        use crate::{DeletionSource, SqlCipherKey};
        for admin_is_author in [false, true] {
            for reverse in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("provenance.db");
                let key = SqlCipherKey::new("07".repeat(32)).unwrap();
                let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
                let author = if admin_is_author { 20 } else { 10 };
                record(&s, &event(1, author, 9, vec![], "original"));
                let mut complaint = report(5);
                complaint.tags[1][1] = id(author);
                record(&s, &complaint);
                record(&s, &event(2, 11, 9, vec![vec!["e".into(), id(1)]], "reply"));
                let mut author_delete = event(3, author, 5, vec![vec!["e".into(), id(1)]], "");
                let mut admin_delete = removal(4, 1);
                // Same authenticated timestamp: event id resolves the tie, not arrival order.
                author_delete.recorded_at = 10;
                admin_delete.recorded_at = 10;
                if reverse {
                    record(&s, &admin_delete);
                    record(&s, &author_delete);
                } else {
                    record(&s, &author_delete);
                    assert_eq!(
                        s.timeline_message(&id(99), &id(1))
                            .unwrap()
                            .unwrap()
                            .deletion_source,
                        DeletionSource::Author
                    );
                    let update = s
                        .record_app_event_with_source(&admin_delete, None, Some(authority(true)))
                        .unwrap();
                    assert!(
                        update.messages.iter().any(|m| m.message_id_hex == id(1)
                            && m.deletion_source == DeletionSource::Admin)
                    );
                    assert!(update.messages.iter().any(|m| {
                        m.message_id_hex == id(2)
                            && m.reply_preview
                                .as_ref()
                                .is_some_and(|p| p.deletion_source == DeletionSource::Admin)
                    }));
                }
                drop(s);
                let s = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
                for rebuild in [false, true] {
                    if rebuild {
                        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                    }
                    let row = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
                    assert!(row.deleted);
                    assert!(row.plaintext.is_empty());
                    assert_eq!(row.kind, 9);
                    assert_eq!(row.deletion_source, DeletionSource::Admin);
                    assert_eq!(row.deleted_by_message_id_hex, Some(id(4)));
                    assert_eq!(
                        s.reported_message(&id(99), &id(1))
                            .unwrap()
                            .unwrap()
                            .deletion_source,
                        row.deletion_source
                    );
                    let reply = s
                        .timeline_message(&id(99), &id(2))
                        .unwrap()
                        .unwrap()
                        .reply_preview
                        .unwrap();
                    assert_eq!(reply.deletion_source, row.deletion_source);
                    assert!(reply.plaintext.is_empty());
                }
                s.invalidate_app_event_by_source(&id(4), "LosingBranch")
                    .unwrap();
                assert_eq!(
                    s.timeline_message(&id(99), &id(1))
                        .unwrap()
                        .unwrap()
                        .deletion_source,
                    DeletionSource::Author
                );
                s.invalidate_app_event_by_source(&id(3), "LosingBranch")
                    .unwrap();
                s.invalidate_app_event_by_source(&id(1), "LosingBranch")
                    .unwrap();
                let row = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
                assert!(!row.deleted);
                assert_eq!(row.deletion_source, DeletionSource::Unknown);
                assert_eq!(row.invalidation_status.as_deref(), Some("LosingBranch"));
            }
        }
    }

    #[test]
    fn report_and_label_dependencies_can_arrive_in_any_order() {
        let events = [target(), report(2), dismiss(3, &[2])];
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            for n in order {
                record(&s, &events[n]);
            }
            assert!(page(&s).reports[0].dismissed);
            let messages = s
                .message_timeline(TimelineMessageQuery::default())
                .unwrap()
                .messages;
            assert_eq!(messages.len(), 1);
            assert!(messages[0].has_reports);
            let before = page(&s);
            s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            assert_eq!(page(&s), before);
        }
    }
    #[test]
    fn reports_and_admin_labels_remain_independent_events() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [
            target(),
            report(2),
            dismiss(3, &[2]),
            report(4),
            dismiss(5, &[2]),
        ] {
            record(&s, &e);
        }
        // Re-delivery of an event is idempotent, but a distinct report from the
        // same account is not coalesced with it.
        record(&s, &report(2));
        let reports = page(&s).reports;
        assert_eq!(reports.len(), 2);
        assert!(reports[0].dismissed);
        assert!(!reports[1].dismissed);
        let labels = s.report_dismissals(&id(99), &id(2), None, 10).unwrap();
        assert_eq!(
            labels
                .labels
                .iter()
                .map(|l| l.event_id_hex.clone())
                .collect::<Vec<_>>(),
            vec![id(3), id(5)]
        );
        s.invalidate_app_event_by_source(&id(3), "withdrawn")
            .unwrap();
        assert!(page(&s).reports[0].dismissed);
        s.invalidate_app_event_by_source(&id(5), "withdrawn")
            .unwrap();
        assert!(!page(&s).reports[0].dismissed);
        s.invalidate_app_event_by_source(&id(2), "withdrawn")
            .unwrap();
        s.invalidate_app_event_by_source(&id(4), "withdrawn")
            .unwrap();
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .has_reports
        );
    }
    #[test]
    fn only_same_group_reports_and_source_authorized_labels_take_effect() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        record(&s, &report(2));
        let mut wrong = report(3);
        wrong.tags[1][1] = id(12);
        record(&s, &wrong);
        record(&s, &target());
        assert_eq!(page(&s).reports.len(), 1);
        let mut cross = dismiss(4, &[2]);
        cross.group_id_hex = id(98);
        record(&s, &cross);
        s.record_app_event_with_source(&dismiss(5, &[2]), None, Some(authority(false)))
            .unwrap();
        s.record_app_event_with_source(&dismiss(6, &[2]), None, None)
            .unwrap();
        assert!(!page(&s).reports[0].dismissed);
        assert!(
            s.finalize_app_event_authority(&id(99), &id(6), None)
                .unwrap()
                .is_none()
        );
        assert!(!page(&s).reports[0].dismissed);
        s.finalize_app_event_authority(&id(99), &id(6), Some(authority(true)))
            .unwrap();
        assert!(page(&s).reports[0].dismissed);
        // A later policy verdict cannot overwrite established source evidence.
        s.finalize_app_event_authority(&id(99), &id(6), Some(authority(false)))
            .unwrap();
        assert!(page(&s).reports[0].dismissed);
    }
    #[test]
    fn removal_requires_resolved_source_authority_in_both_projections() {
        // Exercise controls both before and after their target arrives.
        for control_first in [false, true] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            if !control_first {
                record(&s, &target());
            }
            s.record_app_event_with_source(&removal(2, 1), None, Some(authority(false)))
                .unwrap();
            s.record_app_event_with_source(&removal(3, 1), None, None)
                .unwrap();
            if control_first {
                record(&s, &target());
            }
            let assert_projection = |deleted: bool| {
                for rebuild in [false, true] {
                    if rebuild {
                        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                    }
                    let m = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
                    assert_eq!(m.deleted, deleted);
                    assert_eq!(
                        m.deletion_source,
                        if deleted {
                            crate::DeletionSource::Admin
                        } else {
                            crate::DeletionSource::Unknown
                        }
                    );
                    assert_eq!(m.plaintext, if deleted { "" } else { "original" });
                }
            };
            assert_projection(false);
            // Unavailable proof is retryable and has no deletion effect.
            s.finalize_app_event_authority(&id(99), &id(3), None)
                .unwrap();
            assert_projection(false);
            // A resolved denial cannot later be promoted to a grant.
            s.finalize_app_event_authority(&id(99), &id(2), Some(authority(true)))
                .unwrap();
            assert_projection(false);
            // Only the pending control can acquire its source-state verdict.
            s.finalize_app_event_authority(&id(99), &id(3), Some(authority(true)))
                .unwrap();
            assert_projection(true);
            s.finalize_app_event_authority(&id(99), &id(3), Some(authority(false)))
                .unwrap();
            assert_projection(true);
            // Convergence withdrawal, unlike demotion, removes its effect.
            s.invalidate_app_event_by_source(&id(3), "withdrawn")
                .unwrap();
            assert_projection(false);
        }
    }
    #[test]
    fn removal_hides_original_and_late_edits_without_erasing_reports() {
        let events = [
            target(),
            report(2),
            removal(3, 1),
            event(4, 10, 1009, vec![vec!["e".into(), id(1)]], "late edit"),
            dismiss(5, &[2]),
        ];
        for order in [[0, 1, 2, 3, 4], [2, 3, 4, 1, 0], [4, 3, 2, 1, 0]] {
            let s = SqliteAccountStorage::in_memory().unwrap();
            for n in order {
                record(&s, &events[n]);
            }
            for rebuild in [false, true] {
                if rebuild {
                    s.rebuild_message_timeline_for_group(&id(99)).unwrap();
                }
                let m = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
                assert!(m.deleted && m.plaintext.is_empty());
                assert!(m.media.is_none());
                assert_eq!(page(&s).reports[0].explanation, "quoted explanation");
            }
            // Convergence withdrawal is different from a dismissal. Suppression
            // must remain reversible while the underlying events are retained.
            s.invalidate_app_event_by_source(&id(3), "withdrawn")
                .unwrap();
            let m = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert!(!m.deleted);
            assert_eq!(m.plaintext, "late edit");
        }
    }
    #[test]
    fn expiry_of_target_does_not_expire_report_explanations() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        s.record_app_event_with_source(
            &target(),
            Some(AppMessageRetentionDecision {
                retention_seconds: 10,
                expires_at: Some(11),
            }),
            None,
        )
        .unwrap();
        record(&s, &report(2));
        s.secure_prune_expired_app_events(&id(99), 11, &id(10), &|_, _| false)
            .unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        assert_eq!(page(&s).reports[0].explanation, "quoted explanation");
        s.secure_prune_app_events_before(&id(99), 3, &id(10), &|_, _| false)
            .unwrap();
        assert!(page(&s).reports.is_empty());
    }
    #[test]
    fn report_hydration_batches_queries_and_matches_group_message_and_author() {
        use rusqlite::trace::{TraceEvent, TraceEventCodes};
        use std::cell::Cell;
        thread_local! { static QUERIES: Cell<usize> = const { Cell::new(0) }; }
        fn trace(event: TraceEvent<'_>) {
            if let TraceEvent::Stmt(statement, _) = event
                && statement.sql().starts_with("WITH report_targets")
            {
                QUERIES.with(|count| count.set(count.get() + 1));
            }
        }
        let s = SqliteAccountStorage::in_memory().unwrap();
        record(&s, &target());
        record(&s, &report(2));
        record(&s, &report(3));
        let template = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
        let count = 2 * (SQLITE_BIND_PARAMETER_CHUNK / 3) + 1;
        let mut messages = (0..count)
            .map(|n| {
                let mut m = template.clone();
                match n % 4 {
                    1 => m.group_id_hex = id(98),
                    2 => m.message_id_hex = id(4),
                    3 => m.sender = id(12),
                    _ => {}
                }
                m
            })
            .collect::<Vec<_>>();
        let conn = s.lock().unwrap();
        QUERIES.with(|count| count.set(0));
        conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace));
        hydrate(&conn, &mut messages).unwrap();
        assert_eq!(QUERIES.with(Cell::get), 3);
        for (n, m) in messages.iter().enumerate() {
            assert_eq!(m.has_reports, n % 4 == 0);
        }
        hydrate(&conn, &mut []).unwrap();
        assert_eq!(QUERIES.with(Cell::get), 3, "empty pages need no query");
        conn.trace_v2(TraceEventCodes::empty(), None);
    }
    #[test]
    fn indexed_report_and_label_pages_are_bounded() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        record(&s, &target());
        for n in 20..130 {
            record(&s, &report(n));
        }
        let first = s
            .content_reports(&id(99), Some(&id(1)), None, 1000)
            .unwrap();
        assert_eq!(first.reports.len(), 100);
        let second = s
            .content_reports(&id(99), Some(&id(1)), first.next_cursor.as_deref(), 100)
            .unwrap();
        assert_eq!(second.reports.len(), 10);
        assert!(second.next_cursor.is_none());
        for n in 130..240 {
            record(&s, &dismiss(n, &[20]));
        }
        let first = s.report_dismissals(&id(99), &id(20), None, 1000).unwrap();
        assert_eq!(first.labels.len(), 100);
        let second = s
            .report_dismissals(&id(99), &id(20), first.next_cursor.as_deref(), 100)
            .unwrap();
        assert_eq!(second.labels.len(), 10);
        assert!(second.next_cursor.is_none());
    }
    #[test]
    fn projection_failure_rolls_back_raw_event_and_retry_is_safe() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        record(&s, &target());
        s.lock().unwrap().execute_batch("CREATE TRIGGER fail_report BEFORE INSERT ON content_reports BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
        assert!(s.record_app_event(&report(2)).is_err());
        assert!(raw(&s.lock().unwrap(), &id(99), &id(2)).unwrap().is_none());
        assert!(
            !s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .has_reports
        );
        s.lock()
            .unwrap()
            .execute_batch("DROP TRIGGER fail_report")
            .unwrap();
        record(&s, &report(2));
        assert_eq!(page(&s).reports.len(), 1);
    }
    #[test]
    fn bounded_backfill_restores_individual_reports_and_progress() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [
            target(),
            report(2),
            dismiss(3, &[2]),
            event(4, 10, 1009, vec![vec!["e".into(), id(1)]], "edit"),
            event(5, 10, 5, vec![vec!["e".into(), id(1)]], ""),
        ] {
            record(&s, &e);
        }
        s.lock().unwrap().execute_batch("DELETE FROM content_reports; DELETE FROM message_modifier_edges WHERE kind IN (1009,1984,1985,4891); UPDATE message_timeline SET deleted=0,plaintext='stale'; UPDATE content_report_backfill SET after_order=0,through_order=(SELECT MAX(insert_order) FROM app_events)").unwrap();
        for expected in 2..=5 {
            s.backfill_content_reports(1).unwrap();
            let progress: i64 = s
                .lock()
                .unwrap()
                .query_row("SELECT after_order FROM content_report_backfill", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(progress, expected);
        }
        assert!(page(&s).reports[0].dismissed);
        let message = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
        assert!(message.deleted && message.plaintext.is_empty());
        assert!(s.timeline_message(&id(99), &id(4)).unwrap().is_none());
        assert!(s.backfill_content_reports(1).unwrap().is_empty());
    }
    #[test]
    fn blocking_does_not_filter_report_records_or_labels() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), report(2), dismiss(3, &[2])] {
            record(&s, &e);
        }
        s.lock()
            .unwrap()
            .execute("INSERT INTO user_blocks VALUES(?1,0,0)", params![id(11)])
            .unwrap();
        assert!(page(&s).reports[0].dismissed);
        assert_eq!(page(&s).reports[0].reporter, id(11));
        s.lock()
            .unwrap()
            .execute("INSERT INTO user_blocks VALUES(?1,0,0)", params![id(10)])
            .unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        assert_eq!(
            s.reported_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .plaintext,
            "original"
        );
        record(&s, &removal(4, 1));
        let current = s.reported_message(&id(99), &id(1)).unwrap().unwrap();
        assert!(current.deleted && current.plaintext.is_empty());
    }
    #[test]
    fn new_kind_five_is_author_only_but_existing_legacy_tombstones_survive() {
        let authority = Some(AppMessageAuthority {
            source_context: [1; 32],
            moderation_grant: true,
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
        for rebuild in [false, true] {
            if rebuild {
                legacy.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            let row = legacy.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert!(row.deleted);
            assert!(row.plaintext.is_empty());
            assert_eq!(row.deleted_by_message_id_hex, Some(id(2)));
            assert_eq!(row.deletion_source, crate::DeletionSource::Unknown);
        }
    }
    #[test]
    fn deleted_custom_tags_are_masked_on_reads_and_restored_on_withdrawal() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        let tags = vec![vec!["title".into(), "classified title".into()]];
        record(&s, &event(1, 10, 30402, tags.clone(), "listing"));
        record(&s, &event(2, 10, 5, vec![vec!["e".into(), id(1)]], ""));
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            let row = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
            assert!(row.deleted && row.tags.is_empty() && row.plaintext.is_empty());
            let page = s.message_timeline(TimelineMessageQuery::default()).unwrap();
            assert!(
                page.messages
                    .iter()
                    .find(|m| m.message_id_hex == id(1))
                    .unwrap()
                    .tags
                    .is_empty()
            );
        }
        s.invalidate_app_event_by_source(&id(2), "LosingBranch")
            .unwrap();
        let row = s.timeline_message(&id(99), &id(1)).unwrap().unwrap();
        assert!(!row.deleted);
        assert_eq!(row.tags, tags);
    }

    #[test]
    fn admin_deletion_masks_media_reply_search_and_edit_history() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        let mut message = target();
        message.tags.push(vec![
            "imeta".into(),
            "url https://example.com/image.png".into(),
            "m image/png".into(),
        ]);
        record(&s, &message);
        assert!(
            s.timeline_message(&id(99), &id(1))
                .unwrap()
                .unwrap()
                .media
                .is_some()
        );
        record(&s, &event(6, 12, 9, vec![vec!["q".into(), id(1)]], "reply"));
        for e in [
            report(2),
            removal(5, 1),
            event(3, 10, 1009, vec![vec!["e".into(), id(1)]], "edited"),
        ] {
            record(&s, &e);
        }
        for rebuild in [false, true] {
            if rebuild {
                s.rebuild_message_timeline_for_group(&id(99)).unwrap();
            }
            let message = s.reported_message(&id(99), &id(1)).unwrap().unwrap();
            assert!(message.deleted && message.plaintext.is_empty() && message.media.is_none());
            assert!(message.tags.is_empty());
            let preview = s
                .timeline_message(&id(99), &id(6))
                .unwrap()
                .unwrap()
                .reply_preview
                .unwrap();
            assert!(preview.deleted && preview.plaintext.is_empty() && preview.media.is_none());
            assert!(
                s.message_edit_history(&id(99), &id(1), None, 10)
                    .unwrap()
                    .versions
                    .is_empty()
            );
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
    fn expired_deletion_evidence_prevents_late_content_resurrection() {
        let s = SqliteAccountStorage::in_memory().unwrap();
        for e in [target(), removal(2, 1)] {
            record(&s, &e);
        }
        s.secure_prune_app_events_before(&id(99), 3, &id(10), &|_, _| false)
            .unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        record(&s, &target());
        record(
            &s,
            &event(3, 10, 1009, vec![vec!["e".into(), id(1)]], "late edit"),
        );
        record(&s, &report(4));
        s.rebuild_message_timeline_for_group(&id(99)).unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
        assert!(s.reported_message(&id(99), &id(1)).unwrap().is_none());
        assert_eq!(page(&s).reports[0].explanation, "quoted explanation");
        s.invalidate_app_event_by_source(&id(2), "withdrawn")
            .unwrap();
        assert!(s.timeline_message(&id(99), &id(1)).unwrap().is_none());
    }
}
