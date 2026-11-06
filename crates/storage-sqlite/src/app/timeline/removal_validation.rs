//! Original removal shape and conservative, target-specific legacy holds.
//!
//! An edge is a lossy index, not evidence that a complete removal was valid.
//! UNKNOWN is deliberately not upgraded by replay or by normalized retained tags.
use super::*;

pub(super) fn record(conn: &Connection, event: &StoredAppEvent) -> StorageResult<()> {
    if event.kind != MARMOT_APP_EVENT_KIND_REMOVE {
        conn.execute_cached(
            "DELETE FROM content_removal_validation WHERE group_id_hex=?1 AND message_id_hex=?2",
            params![event.group_id_hex, event.message_id_hex],
        )
        .storage()?;
        return Ok(());
    }
    let retained: bool = conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM content_pruned_controls WHERE group_id_hex=?1 AND message_id_hex=?2)",
        params![event.group_id_hex, event.message_id_hex], |r| r.get(0),
    ).storage()?;
    if retained {
        return Ok(());
    }
    let target = cgka_traits::reporting::parse_removal(&event.tags, &event.plaintext);
    // Preserve UNKNOWN, including its upgrade-only holds. Neither redelivery nor
    // history import is an original-payload repair operation.
    conn.execute_cached(
        "INSERT INTO content_removal_validation(group_id_hex,message_id_hex,state,target_message_id_hex)
         VALUES (?1,?2,?3,?4) ON CONFLICT(group_id_hex,message_id_hex) DO UPDATE SET
         state=excluded.state,target_message_id_hex=excluded.target_message_id_hex
         WHERE content_removal_validation.state != 0",
        params![event.group_id_hex, event.message_id_hex, if target.is_some() { 2 } else { 1 }, target],
    ).storage()?;
    Ok(())
}

pub(super) fn targets(
    conn: &Connection,
    group: &str,
    control: Option<&str>,
) -> StorageResult<BTreeMap<String, BTreeSet<String>>> {
    // The single-control form uses the composite key; ordinary incremental
    // updates must not scan all removals in a chat.
    let predicate = if control.is_some() {
        " AND v.message_id_hex=?2"
    } else {
        ""
    };
    let sql = format!(
        "SELECT v.message_id_hex,v.target_message_id_hex FROM content_removal_validation v
         WHERE v.group_id_hex=?1 AND v.state=2{predicate}
         UNION ALL
         SELECT v.message_id_hex,h.target_message_id_hex FROM content_removal_validation v
         JOIN content_removal_legacy_holds h ON h.group_id_hex=v.group_id_hex
          AND h.message_id_hex=v.message_id_hex
         WHERE v.group_id_hex=?1 AND v.state=0{predicate}"
    );
    let mut stmt = conn.prepare_cached(&sql).storage()?;
    let mut result = BTreeMap::<String, BTreeSet<String>>::new();
    let mut rows = if let Some(control) = control {
        stmt.query(params![group, control])
    } else {
        stmt.query(params![group])
    }
    .storage()?;
    while let Some(row) = rows.next().storage()? {
        result
            .entry(row.get(0).storage()?)
            .or_default()
            .insert(row.get(1).storage()?);
    }
    Ok(result)
}

pub(super) fn retained_tags(
    conn: &Connection,
    group: &str,
    control: &str,
) -> StorageResult<Vec<Vec<String>>> {
    Ok(targets(conn, group, Some(control))?
        .remove(control)
        .unwrap_or_default()
        .into_iter()
        .map(|target| vec![EVENT_REF_TAG.to_owned(), target])
        .collect())
}

pub(super) fn targeting(
    conn: &Connection,
    group: &str,
    target: &str,
) -> StorageResult<Vec<RawAppEvent>> {
    let mut stmt = conn.prepare_cached(
        "SELECT message_id_hex FROM content_removal_validation
         WHERE group_id_hex=?1 AND state=2 AND target_message_id_hex=?2
         UNION
         SELECT h.message_id_hex FROM content_removal_legacy_holds h
         JOIN content_removal_validation v ON v.group_id_hex=h.group_id_hex AND v.message_id_hex=h.message_id_hex
         WHERE h.group_id_hex=?1 AND h.target_message_id_hex=?2 AND v.state=0"
    ).storage()?;
    let ids = stmt
        .query_map(params![group, target], |r| r.get::<_, String>(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    ids.into_iter()
        .filter_map(|id| match raw_app_event_tx(conn, group, &id) {
            Ok(Some(event)) if event.kind == MARMOT_APP_EVENT_KIND_REMOVE && !event.invalidated => {
                Some(Ok(event))
            }
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect()
}
