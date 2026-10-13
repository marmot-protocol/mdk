fn chat_query() -> AttachmentJobQuery {
    AttachmentJobQuery {
        group_id_hex: GROUP.into(),
        ..Default::default()
    }
}
use super::*;
use crate::attachment_acquisition::management::*;
fn permitted(automatic: bool) -> AttachmentManagementPermission {
    AttachmentManagementPermission {
        automatic,
        categories: [true; 4],
    }
}

#[test]
fn storage_blocked_jobs_need_attention_without_becoming_active_or_scheduled() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "parked");
    let reference = request(&s, "parked");
    let job = s
        .claim_attachment_acquisition(&reference, 12, 100)
        .unwrap()
        .unwrap();
    assert!(s.block_attachment_storage(&job, 8192, 12).unwrap());

    for permission in [permitted(true), permitted(false)] {
        let counts = s.attachment_job_counts(GROUP, 13, permission).unwrap();
        assert!(counts.complete);
        assert_eq!(counts.needs_attention, 1);
        assert_eq!(counts.active, 0);
        assert_eq!(counts.paused, 0);
        assert_eq!(counts.other, 0);
        let page = s
            .attachment_jobs_page(
                &AttachmentJobQuery {
                    view: AttachmentJobView::NeedsAttention,
                    ..chat_query()
                },
                50,
                None,
                13,
                permission,
            )
            .unwrap();
        assert_eq!(page.entries.len(), 1);
        assert!(page.next_cursor.is_none());
        let status = &page.entries[0].status;
        assert_eq!(status.state, AttachmentTransferState::StorageBlocked);
        assert_eq!(status.retry_at, None);
        assert_eq!(status.reference.as_ref(), Some(&reference));
        assert!(
            s.attachment_jobs_page(
                &AttachmentJobQuery {
                    view: AttachmentJobView::Active,
                    ..chat_query()
                },
                50,
                None,
                13,
                permission,
            )
            .unwrap()
            .entries
            .is_empty()
        );
    }
}

#[test]
fn managed_download_paging_counts_and_filters_are_local_bounded_and_source_bound() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    for n in 0..73 {
        let m = format!("job-{n}");
        seed(&s, &m);
        request(&s, &m);
    }
    let query = chat_query();
    let mut cursor = None;
    let mut seen = 0;
    loop {
        let p = s
            .attachment_jobs_page(&query, 17, cursor.as_ref(), 12, permitted(true))
            .unwrap();
        assert!(p.entries.len() <= 17);
        seen += p.entries.len();
        cursor = p.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, 73);
    let counts = s.attachment_job_counts(GROUP, 12, permitted(true)).unwrap();
    assert!(counts.complete);
    assert_eq!(counts.active, 73);
    let q = AttachmentJobQuery {
        view: AttachmentJobView::NeedsAttention,
        ..chat_query()
    };
    let empty = s
        .attachment_jobs_page(&q, 1, None, 12, permitted(true))
        .unwrap();
    assert!(empty.entries.is_empty());
    assert!(empty.next_cursor.is_some());
    assert!(
        s.attachment_jobs_page(&query, 1, empty.next_cursor.as_ref(), 12, permitted(true))
            .is_err()
    );
    assert!(
        s.attachment_jobs_page(&query, 51, None, 12, permitted(true))
            .is_err()
    );
    let foreign = SqliteAccountStorage::in_memory().unwrap();
    let p = s
        .attachment_jobs_page(&query, 1, None, 12, permitted(true))
        .unwrap();
    assert!(
        foreign
            .attachment_jobs_page(&query, 1, p.next_cursor.as_ref(), 12, permitted(true))
            .is_err()
    );
    s.lock()
        .unwrap()
        .execute_batch("UPDATE account_groups SET pending_confirmation=1")
        .unwrap();
    let f = s
        .attachment_management_frame(
            &AttachmentJobQuery {
                group_id_hex: GROUP.into(),
                ..chat_query()
            },
            12,
            permitted(true),
        )
        .unwrap();
    assert!(!f.available);
    assert!(f.page.entries.is_empty());
    assert_eq!(f.automatic_recovery_failed, None);
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
    let start = std::time::Instant::now();
    let frame = s
        .attachment_management_frame(&chat_query(), 12, permitted(true))
        .unwrap();
    eprintln!(
        "management_frame_1027_jobs_us={}",
        start.elapsed().as_micros()
    );
    assert_eq!(frame.page.entries.len(), 50);
    let counts = s.attachment_job_counts(GROUP, 12, permitted(true)).unwrap();
    assert!(!counts.complete);
    assert_eq!(counts.active, 1024);
    // Ready lifetime history must never spend the health/count or attention-page budget.
    sql(&s, "UPDATE attachment_acquisition SET state=3,due=NULL WHERE message_id_hex<>'job-0';
        INSERT INTO retained_attachment_bytes(token,bytes) SELECT token,x'00' FROM attachment_acquisition WHERE state=3;
        UPDATE attachment_acquisition SET state=4,due=NULL WHERE message_id_hex='job-0';");
    let health = s.attachment_job_counts(GROUP, 12, permitted(true)).unwrap();
    assert!(health.complete);
    assert_eq!(health.needs_attention, 1);
    assert_eq!(health.active, 0);
    let attention_query = AttachmentJobQuery {
        view: AttachmentJobView::NeedsAttention,
        ..chat_query()
    };
    let attention_page = s
        .attachment_jobs_page(&attention_query, 1, None, 12, permitted(true))
        .unwrap();
    assert_eq!(attention_page.entries[0].source.message_id_hex, "job-0");
    // Loss of retained bytes rejoins the same derived non-ready index.
    sql(
        &s,
        "DELETE FROM retained_attachment_bytes WHERE token=(SELECT token FROM attachment_acquisition WHERE message_id_hex='job-1');",
    );
    let health = s.attachment_job_counts(GROUP, 12, permitted(true)).unwrap();
    assert!(health.complete);
    assert_eq!(health.needs_attention, 2);
    let c = s.lock().unwrap();
    let plan = c
        .prepare("EXPLAIN QUERY PLAN SELECT token FROM attachment_acquisition INDEXED BY attachment_management_group_work WHERE group_id_hex='abababababababababababababababab' AND management_ready=0 AND rowid>0 AND rowid<=99999 ORDER BY rowid DESC LIMIT 51")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(plan.contains("attachment_management_group_work"));
    assert!(!plan.contains("TEMP B-TREE"));
    drop(c);
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
        group_id_hex: GROUP.into(),
        ..chat_query()
    };
    let f = s
        .attachment_management_frame(&q, 12, permitted(true))
        .unwrap();
    assert!(f.available);
    assert_eq!(f.automatic_recovery_failed, Some(false));
    assert_eq!(f.counts.active, 5);
    assert_eq!(f.counts.needs_attention, 2);
    assert_eq!(f.counts.paused, 1);
    assert_eq!(f.counts.policy_blocked, 1);
    assert_eq!(f.counts.cancelled, 1);
    assert!(f.page.entries.iter().all(|e| e.status.total.is_none()));
    let denied = crate::AttachmentManagementPermission {
        automatic: true,
        categories: [false; 4],
    };
    let paused = s.attachment_management_frame(&q, 12, denied).unwrap();
    assert_eq!(paused.counts.active, 0);
    assert_eq!(paused.counts.paused, 6);
    assert_eq!(paused.counts.needs_attention, 2);
    assert!(!paused.version.same_as(&f.version));
    let active = s
        .attachment_jobs_page(
            &AttachmentJobQuery {
                view: AttachmentJobView::Active,
                ..q.clone()
            },
            50,
            None,
            12,
            denied,
        )
        .unwrap();
    assert!(active.entries.is_empty());

    let cancelled = f
        .page
        .entries
        .iter()
        .find(|e| e.status.state == AttachmentTransferState::Cancelled)
        .unwrap();
    assert_eq!(cancelled.status.state, AttachmentTransferState::Cancelled);
    let automatic = s
        .attachment_jobs_page(
            &AttachmentJobQuery {
                origin: AttachmentJobOrigin::Automatic,
                ..chat_query()
            },
            50,
            None,
            12,
            permitted(true),
        )
        .unwrap();
    assert!(
        automatic
            .entries
            .iter()
            .all(|e| e.status.state != AttachmentTransferState::Cancelled)
    );

    assert!(
        s.attachment_management_frame(&AttachmentJobQuery::default(), 12, permitted(true))
            .is_err()
    );
    let filtered = s
        .attachment_management_frame(
            &AttachmentJobQuery {
                view: AttachmentJobView::NeedsAttention,
                ..q.clone()
            },
            12,
            permitted(true),
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
    let bad = s
        .attachment_management_frame(&q, 12, permitted(true))
        .unwrap();
    assert_eq!(bad.automatic_recovery_failed, Some(true));
    assert!(!bad.version.same_as(&f.version));
    assert!(s.clear_recovery_failure(&g).unwrap());
    assert_eq!(
        s.attachment_management_frame(&q, 12, permitted(true))
            .unwrap()
            .automatic_recovery_failed,
        Some(false)
    );
    s.close().unwrap();
    assert!(
        s.attachment_management_frame(&q, 12, permitted(true))
            .is_err()
    );
}

#[test]
fn management_expiry_replaces_the_frame_once_without_database_writes() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "one");
    request(&s, "one");
    sql(
        &s,
        "UPDATE app_events SET retention_expires_at=13 WHERE message_id_hex='one';",
    );
    let q = chat_query();
    let before = s
        .attachment_management_frame(&q, 12, permitted(true))
        .unwrap();
    assert_eq!(before.page.next_expiry, Some(13));
    assert_eq!(before.page.entries.len(), 1);
    let after = s
        .attachment_management_frame(&q, 13, permitted(true))
        .unwrap();
    assert!(after.page.entries.is_empty());
    assert_eq!(after.page.next_expiry, None);
    assert!(!after.version.same_as(&before.version));
    let later = s
        .attachment_management_frame(&q, 14, permitted(true))
        .unwrap();
    assert!(later.version.same_as(&after.version));
    assert_eq!(later.page.next_expiry, None);
}

#[test]
fn health_references_reuse_existing_account_scoped_controls() {
    let s = SqliteAccountStorage::in_memory().unwrap();
    seed(&s, "one");
    request(&s, "one");
    let reference = s
        .attachment_jobs_page(&chat_query(), 1, None, 12, permitted(true))
        .unwrap()
        .entries[0]
        .status
        .reference
        .clone()
        .unwrap();
    let other = SqliteAccountStorage::in_memory().unwrap();
    assert!(!other.cancel_attachment_acquisition(&reference).unwrap());
    assert!(s.cancel_attachment_acquisition(&reference).unwrap());
    assert!(s.explicitly_retry_attachment(&reference, 13).unwrap());
    assert_eq!(
        s.attachment_job_counts(GROUP, 13, permitted(true))
            .unwrap()
            .active,
        1
    );
}
