use super::*;
use crate::attachment_acquisition::management::*;

#[test]
fn managed_download_paging_counts_and_filters_are_local_bounded_and_source_bound() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..73 {
        let m = format!("job-{n}");
        seed(&s, &m);
        request(&s, &m);
    }
    let query = AttachmentJobQuery::default();
    let mut cursor = None;
    let mut seen = 0;
    loop {
        let p = s
            .attachment_jobs_page(&query, 17, cursor.as_ref(), 12, true)
            .unwrap();
        assert!(p.entries.len() <= 17);
        seen += p.entries.len();
        cursor = p.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, 73);
    let counts = s.attachment_job_counts(None, 12, true).unwrap();
    assert!(counts.complete);
    assert_eq!(counts.active, 73);
    let q = AttachmentJobQuery {
        view: AttachmentJobView::Ready,
        ..Default::default()
    };
    let empty = s.attachment_jobs_page(&q, 1, None, 12, true).unwrap();
    assert!(empty.entries.is_empty());
    assert!(empty.next_cursor.is_some());
    assert!(
        s.attachment_jobs_page(&query, 1, empty.next_cursor.as_ref(), 12, true)
            .is_err()
    );
    assert!(s.attachment_jobs_page(&query, 51, None, 12, true).is_err());
    let foreign = SqliteAccountStorage::in_memory().unwrap();
    let p = s.attachment_jobs_page(&query, 1, None, 12, true).unwrap();
    assert!(
        foreign
            .attachment_jobs_page(&query, 1, p.next_cursor.as_ref(), 12, true)
            .is_err()
    );
    s.lock()
        .unwrap()
        .execute_batch("UPDATE account_groups SET pending_confirmation=1")
        .unwrap();
    let f = s
        .attachment_management_frame(
            &AttachmentJobQuery {
                group_id_hex: Some(GROUP.into()),
                ..Default::default()
            },
            12,
            true,
        )
        .unwrap();
    assert!(!f.available);
    assert!(f.page.entries.is_empty());
    assert_eq!(f.automatic_recovery_failed, None);
}

#[test]
fn cancellation_freezes_old_intent_and_preserves_promotions_new_work_and_ready_bytes() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..130 {
        let m = format!("job-{n}");
        seed(&s, &m);
        request(&s, &m);
    }
    let old = s.begin_attachment_cancellation(None, true).unwrap();
    let promote = request(&s, "job-0");
    assert!(s.promote_attachment_demand(&promote, 12).unwrap());
    let ready = request(&s, "job-1");
    publish(&s, &ready);
    seed(&s, "new");
    let new = request(&s, "new");
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(other.cancel_attachment_batch(&old, 12).is_err());
    let mut cursor = Some(old.clone());
    let mut requested = 0;
    let mut visited = 0;
    while let Some(c) = cursor {
        let batch = s.cancel_attachment_batch(&c, 12).unwrap();
        assert!(batch.visited <= 64);
        requested += batch.requested;
        visited += batch.visited;
        cursor = batch.next_cursor;
    }
    assert_eq!(requested, 128);
    assert_eq!(visited, 129);
    assert_eq!(read(&s, &ready), BODY);
    for r in [&promote, &new] {
        assert_eq!(
            s.attachment_acquisition_status(r).unwrap().unwrap().state,
            AttachmentAcquisitionState::Queued
        );
    }
    let before = s
        .attachment_jobs_page(&AttachmentJobQuery::default(), 50, None, 12, true)
        .unwrap();
    let token = before
        .entries
        .iter()
        .find(|e| e.source.message_id_hex == "job-129")
        .unwrap()
        .action
        .clone();
    assert!(s.control_managed_attachment(&token, true, 13).unwrap());
    assert!(!s.control_managed_attachment(&token, false, 13).unwrap());
    let replay = s.cancel_attachment_batch(&old, 13).unwrap();
    assert_eq!(replay.requested, 0);
    // Retry is a new intent even when an explicit queued request is retried again.
    let fresh = s
        .attachment_jobs_page(&AttachmentJobQuery::default(), 1, None, 13, true)
        .unwrap()
        .entries[0]
        .action
        .clone();
    let newer_cancel = s.begin_attachment_cancellation(None, false).unwrap();
    assert!(s.control_managed_attachment(&fresh, true, 14).unwrap());
    assert!(!s.control_managed_attachment(&fresh, false, 14).unwrap());
    s.cancel_attachment_batch(&newer_cancel, 14).unwrap();
    let counts = s.attachment_job_counts(None, 14, true).unwrap();
    assert!(counts.active >= 1);
}

#[test]
fn counts_are_explicit_lower_bounds_and_queries_seek_management_indexes() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    // Use one transaction for a large public synthetic fixture, no network or historical plaintext scan.
    s.connection
        .with_transaction(|| {
            for n in 0..1027 {
                let m = format!("job-{n}");
                seed(&s, &m);
                request(&s, &m);
            }
            Ok::<_, StorageError>(())
        })
        .unwrap();
    let counts = s.attachment_job_counts(None, 12, true).unwrap();
    assert!(!counts.complete);
    assert_eq!(counts.active, 1024);
    let c = s.lock().unwrap();
    for (sql, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition INDEXED BY attachment_management_sequence_index WHERE management_sequence>0 AND management_sequence<=99999 ORDER BY management_sequence DESC LIMIT 51",
            "attachment_management_sequence_index",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition INDEXED BY attachment_management_group_sequence WHERE group_id_hex='abababababababababababababababab' AND management_sequence>0 AND management_sequence<=99999 ORDER BY management_sequence DESC LIMIT 51",
            "attachment_management_group_sequence",
        ),
    ] {
        let plan = c
            .prepare(sql)
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" ");
        assert!(plan.contains(index));
        assert!(!plan.contains("TEMP B-TREE"));
    }
    drop(c);
    assert!(
        !format!(
            "{:?}",
            s.begin_attachment_cancellation(None, false).unwrap()
        )
        .contains(GROUP)
    );
}

#[test]
fn management_health_is_independent_of_transfer_phases_and_missing_observations() {
    use cgka_traits::GroupId;
    let s = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..10 {
        let m = format!("phase-{n}");
        seed(&s, &m);
        request(&s, &m);
    }
    for (n, state, phase, extra) in [
        (0, 1, 1, ""),
        (1, 1, 2, ""),
        (2, 1, 3, ""),
        (3, 1, 4, ""),
        (4, 2, 0, ""),
        (5, 4, 0, ""),
        (6, 5, 0, ""),
        (7, 4, 0, ",size_blocked_max=1"),
        (8, 4, 0, ",automatic_history=1,acquisition_attempts=4"),
        (9, 4, 0, ",cancelled=1"),
    ] {
        sql(
            &s,
            &format!(
                "UPDATE attachment_acquisition SET state={state},progress_phase={phase},attempt={},due={} {extra} WHERE message_id_hex='phase-{n}'",
                if state == 1 { "randomblob(16)" } else { "NULL" },
                if state == 1 || state == 2 {
                    "100"
                } else {
                    "NULL"
                }
            ),
        );
    }
    let q = AttachmentJobQuery {
        group_id_hex: Some(GROUP.into()),
        ..Default::default()
    };
    let f = s.attachment_management_frame(&q, 12, true).unwrap();
    assert!(f.available);
    assert_eq!(f.automatic_recovery_failed, Some(false));
    assert_eq!(f.counts.active, 5);
    assert_eq!(f.counts.needs_attention, 2);
    assert_eq!(f.counts.paused, 1);
    assert_eq!(f.counts.policy_blocked, 1);
    assert_eq!(f.counts.cancelled, 1);
    assert!(f.page.entries.iter().all(|e| e.status.total.is_none()));
    let cancelled = f
        .page
        .entries
        .iter()
        .find(|e| e.status.state == AttachmentTransferState::Cancelled)
        .unwrap();
    assert!(!cancelled.origin_known);
    let automatic = s
        .attachment_jobs_page(
            &AttachmentJobQuery {
                origin: AttachmentJobOrigin::Automatic,
                ..Default::default()
            },
            50,
            None,
            12,
            true,
        )
        .unwrap();
    assert!(
        automatic
            .entries
            .iter()
            .all(|e| e.status.state != AttachmentTransferState::Cancelled)
    );

    let global = s
        .attachment_management_frame(&AttachmentJobQuery::default(), 12, true)
        .unwrap();
    assert!(!global.version.same_as(&f.version));
    let filtered = s
        .attachment_management_frame(
            &AttachmentJobQuery {
                view: AttachmentJobView::NeedsAttention,
                ..q.clone()
            },
            12,
            true,
        )
        .unwrap();
    assert!(!filtered.version.same_as(&f.version));

    let g = GroupId::new(hex::decode(GROUP).unwrap());
    use cgka_traits::storage::GroupStorage;
    s.put_group(&crate::storage::test_support::sample_group(g.clone(), 1, 2))
        .unwrap();
    // Durable qualified failure is independent; queued/paused downloads did not create it.
    s.lock()
        .unwrap()
        .execute(
            "INSERT INTO app_group_recovery_failures(group_id) VALUES(?1)",
            [g.as_slice()],
        )
        .unwrap();
    let bad = s.attachment_management_frame(&q, 12, true).unwrap();
    assert_eq!(bad.automatic_recovery_failed, Some(true));
    assert!(!bad.version.same_as(&f.version));
    assert!(s.clear_recovery_failure(&g).unwrap());
    assert_eq!(
        s.attachment_management_frame(&q, 12, true)
            .unwrap()
            .automatic_recovery_failed,
        Some(false)
    );
    s.close().unwrap();
    assert!(s.attachment_management_frame(&q, 12, true).is_err());
}
