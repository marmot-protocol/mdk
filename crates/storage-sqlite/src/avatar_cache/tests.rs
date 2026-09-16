use super::*;

#[test]
fn avatar_cache_available_on_account_open_without_engine() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM avatar_assets", [], |row| row.get(0))
        .expect("account open must provision durable avatar storage without an engine");
    assert_eq!(count, 0);
}
fn image(value: u8, size: usize) -> AvatarImage {
    // Storage receives caller-validated bytes. Decoder/authentication tests are
    // owned by the acquisition layer, not these persistence fixtures.
    AvatarImage::new(vec![value; size], AvatarImageFormat::Png, 16, 16).unwrap()
}
fn bind(store: &SqliteAccountStorage, owner: &str) -> AvatarAssetRef {
    store
        .bind_avatar_source(owner, "selected-source-key")
        .unwrap()
}
fn publish(store: &SqliteAccountStorage, reference: &AvatarAssetRef, image: &AvatarImage) {
    assert_eq!(
        store.publish_avatar(reference, 0, image, None).unwrap(),
        AvatarPublishResult::Published {
            content_revision: 1
        }
    );
}
fn ready(store: &SqliteAccountStorage, reference: &AvatarAssetRef) -> AvatarAssetRead {
    let result = store.read_avatar(reference, 10).unwrap();
    assert_eq!(result.status.availability, AvatarAvailability::Ready);
    result
}

#[test]
fn avatar_bytes_survive_encrypted_reopen_without_engine_or_network() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite3");
    let key = crate::SqlCipherKey::new("avatar-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let reference = bind(&store, "profile-owner");
    let original = image(42, 4096);
    publish(&store, &reference, &original);
    assert_eq!(
        store
            .bind_avatar_source("profile-owner", "selected-source-key")
            .unwrap(),
        reference
    );
    store.close().unwrap();
    let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(
        reopened.avatar_reference("profile-owner").unwrap(),
        Some(reference.clone())
    );
    assert_eq!(ready(&reopened, &reference).image, Some(original));
    reopened.close().unwrap();
    let file = std::fs::read(&path).unwrap();
    assert!(!file.starts_with(b"SQLite format 3"));
    assert!(!file.windows(64).any(|bytes| bytes == [42; 64]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn source_replacement_and_aba_reject_old_reads_publications_and_cleanup() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let old = store.bind_avatar_source("owner", "source-a").unwrap();
    let bytes = image(1, 16);
    publish(&store, &old, &bytes);
    let replacement = store.bind_avatar_source("owner", "source-b").unwrap();
    assert_ne!(old, replacement);
    assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 0);
    assert_eq!(
        store.read_avatar(&old, 1).unwrap().status.availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(
        store
            .read_avatar(&replacement, 1)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Missing
    );
    assert_eq!(
        store.publish_avatar(&old, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    assert!(!store.remove_avatar_source(&old).unwrap());
    let back_to_a = store.bind_avatar_source("owner", "source-a").unwrap();
    assert_ne!(back_to_a, old);
    assert_eq!(
        store.publish_avatar(&old, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    publish(&store, &back_to_a, &bytes);
}

#[test]
fn source_reference_and_content_revision_fence_out_of_order_refresh() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    let first = image(1, 8);
    assert_eq!(
        store
            .publish_avatar(&reference, 0, &first, Some(20))
            .unwrap(),
        AvatarPublishResult::Published {
            content_revision: 1
        }
    );
    assert_eq!(
        store.avatar_status(&reference, 19).unwrap().availability,
        AvatarAvailability::Ready
    );
    let stale = store.read_avatar(&reference, 20).unwrap();
    assert_eq!(stale.status.availability, AvatarAvailability::Stale);
    assert_eq!(stale.image, Some(first.clone()));
    let second = image(2, 8);
    assert_eq!(
        store
            .publish_avatar(&reference, 1, &second, Some(40))
            .unwrap(),
        AvatarPublishResult::Published {
            content_revision: 2
        }
    );
    assert_eq!(
        store
            .publish_avatar(&reference, 1, &first, Some(100))
            .unwrap(),
        AvatarPublishResult::Superseded
    );
    let actual = ready(&store, &reference);
    assert_eq!(actual.status.content_revision, 2);
    assert_eq!(actual.image, Some(second));
    assert_eq!(
        store.avatar_status(&reference, 40).unwrap().availability,
        AvatarAvailability::Stale
    );
}

#[test]
fn account_isolation_reset_and_terminal_close_fence_handles() {
    let a = SqliteAccountStorage::in_memory().unwrap();
    let b = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&a, "owner");
    let bytes = image(7, 16);
    publish(&a, &reference, &bytes);
    let b_ref = bind(&b, "owner");
    // Even a matching token from another account is rejected by its store epoch.
    let forged = AvatarAssetRef {
        token: b_ref.token.clone(),
        ..reference.clone()
    };
    assert_eq!(
        b.read_avatar(&forged, 0).unwrap().status.availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(
        b.publish_avatar(&forged, 0, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    assert!(!b.remove_avatar_source(&forged).unwrap());
    a.lock()
        .unwrap()
        .execute(
            "UPDATE chat_presentation_meta SET store_epoch = randomblob(16) WHERE id = 1",
            [],
        )
        .unwrap();
    assert_eq!(a.avatar_cache_usage().unwrap().entries, 0);
    assert_eq!(
        a.publish_avatar(&reference, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    let new = bind(&a, "owner");
    publish(&a, &new, &bytes);
    let clone = a.clone();
    a.close().unwrap();
    assert!(matches!(
        clone.read_avatar(&new, 0),
        Err(StorageError::Closed(_))
    ));
    assert!(matches!(
        clone.publish_avatar(&new, 1, &bytes, None),
        Err(StorageError::Closed(_))
    ));
    assert!(matches!(
        clone.bind_avatar_source("owner", "source"),
        Err(StorageError::Closed(_))
    ));
}

#[test]
fn lru_eviction_uses_reads_not_status_and_old_completion_cannot_refill() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let limits = Limits {
        entries: 3,
        bytes: 12,
    };
    let first = bind(&store, "first");
    let second = bind(&store, "second");
    let bytes = image(1, 6);
    for reference in [&first, &second] {
        assert_eq!(
            store
                .publish_avatar_with_limits(reference, 0, &bytes, None, limits)
                .unwrap(),
            AvatarPublishResult::Published {
                content_revision: 1
            }
        );
    }
    ready(&store, &first);
    store.avatar_status(&second, 10).unwrap();
    let third = bind(&store, "third");
    assert_eq!(
        store
            .publish_avatar_with_limits(&third, 0, &bytes, None, limits)
            .unwrap(),
        AvatarPublishResult::Published {
            content_revision: 1
        }
    );
    assert_eq!(store.avatar_reference("second").unwrap(), None);
    assert_eq!(
        store.publish_avatar(&second, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    assert_eq!(
        store.avatar_cache_usage().unwrap(),
        AvatarCacheUsage {
            entries: 2,
            byte_count: 12
        }
    );
    ready(&store, &first);
    ready(&store, &third);
    let new = bind(&store, "second");
    assert_ne!(new, second);
}

#[test]
fn missing_mappings_are_bounded_and_eviction_preserves_current_binding() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let limits = Limits {
        entries: 2,
        bytes: 16,
    };
    let old = store
        .bind_avatar_source_with_limits("a", "source", limits)
        .unwrap();
    store
        .bind_avatar_source_with_limits("b", "source", limits)
        .unwrap();
    let current = store
        .bind_avatar_source_with_limits("c", "source", limits)
        .unwrap();
    assert_eq!(
        store.avatar_cache_usage().unwrap(),
        AvatarCacheUsage {
            entries: 2,
            byte_count: 0
        }
    );
    assert_eq!(
        store.avatar_status(&old, 0).unwrap().availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(
        store.avatar_status(&current, 0).unwrap().availability,
        AvatarAvailability::Missing
    );
}

#[test]
fn eviction_failure_rolls_back_publication_and_previously_evicted_entries() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = bind(&store, "a");
    let b = bind(&store, "b");
    let c = bind(&store, "c");
    let old = image(1, 5);
    publish(&store, &a, &old);
    publish(&store, &b, &old);
    publish(&store, &c, &old);
    store
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER avatar_test_fail_delete BEFORE DELETE ON avatar_assets
         WHEN OLD.owner_key = 'b' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    let result = store.publish_avatar_with_limits(
        &c,
        1,
        &image(2, 8),
        None,
        Limits {
            entries: 3,
            bytes: 8,
        },
    );
    assert!(result.is_err());
    assert_eq!(
        store.avatar_cache_usage().unwrap(),
        AvatarCacheUsage {
            entries: 3,
            byte_count: 15
        }
    );
    for reference in [&a, &b, &c] {
        let actual = ready(&store, reference);
        assert_eq!(actual.status.content_revision, 1);
        assert_eq!(actual.image, Some(old.clone()));
    }
}

#[test]
fn avatar_schema_rejects_text_payloads_and_digests() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    let original = image(42, 16);
    publish(&store, &reference, &original);

    for sql in [
        // SQLite length(TEXT) counts characters, which would undercount bytes.
        "UPDATE avatar_assets SET bytes = '🦫🦫'",
        "UPDATE avatar_assets SET digest = '01234567890123456789012345678901'",
    ] {
        let error = store.lock().unwrap().execute(sql, []).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );
        assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 16);
        assert_eq!(ready(&store, &reference).image, Some(original.clone()));
    }
}

#[test]
fn corrupt_bytes_become_a_repairable_miss_and_fence_old_refresh() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    let bytes = image(1, 16);
    publish(&store, &reference, &bytes);
    store
        .lock()
        .unwrap()
        .execute("UPDATE avatar_assets SET bytes = zeroblob(16)", [])
        .unwrap();
    let result = store.read_avatar(&reference, 0).unwrap();
    assert_eq!(result.status.availability, AvatarAvailability::Missing);
    assert_eq!(result.status.content_revision, 2);
    assert!(result.image.is_none());
    assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 0);
    assert_eq!(
        store.publish_avatar(&reference, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    assert_eq!(
        store.publish_avatar(&reference, 2, &bytes, None).unwrap(),
        AvatarPublishResult::Published {
            content_revision: 3
        }
    );
    assert_eq!(ready(&store, &reference).image, Some(bytes));
}

#[test]
fn concurrent_publications_have_one_winner() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (1..=2)
        .map(|value| {
            let store = store.clone();
            let reference = reference.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .publish_avatar(&reference, 0, &image(value, 8), None)
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, AvatarPublishResult::Published { .. }))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| **r == AvatarPublishResult::Superseded)
            .count(),
        1
    );
    assert_eq!(ready(&store, &reference).status.content_revision, 1);
}

#[test]
fn clear_cache_invalidates_all_generations_but_shared_views_share_one_owner() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let first_view = bind(&store, "owner");
    let second_view = bind(&store, "owner");
    assert_eq!(first_view, second_view);
    publish(&store, &first_view, &image(1, 8));
    ready(&store, &second_view);
    store.clear_avatar_cache().unwrap();
    let new = bind(&store, "owner");
    assert_ne!(new, first_view);
    assert!(!store.remove_avatar_source(&second_view).unwrap());
    assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 0);
}

#[test]
fn bounds_and_errors_do_not_expose_source_or_image_material() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let source = "sensitive-url-or-material".repeat(100);
    let error = store
        .bind_avatar_source("owner", &source)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("sensitive"));
    assert!(store.bind_avatar_source("", "source").is_err());
    for (size, width, height) in [
        (0, 1, 1),
        (1, 0, 1),
        (1, 4097, 1),
        (1, 1, 4097),
        (MAX_AVATAR_BYTES + 1, 1, 1),
    ] {
        assert!(AvatarImage::new(vec![42; size], AvatarImageFormat::Png, width, height).is_err());
    }
    let reference = bind(&store, "owner");
    let bytes = image(42, 16);
    let debug = format!("{reference:?} {bytes:?}");
    assert!(!debug.contains("42, 42"));
    assert!(!debug.contains(&hex::encode(&reference.token)));
    assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 0);
    assert!(
        store
            .publish_avatar(&reference, u64::MAX, &bytes, None)
            .is_err()
    );
    assert!(
        store
            .publish_avatar(&reference, 0, &bytes, Some(u64::MAX))
            .is_err()
    );
}

#[test]
fn local_avatar_reads_do_not_scan_other_entries() {
    use crate::query_work_test_support::{QUERY_MEASUREMENT, measure};
    let _measurement = QUERY_MEASUREMENT.lock().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "target");
    publish(&store, &reference, &image(1, 16));
    let (small, small_steps) = measure(&store, || store.read_avatar(&reference, 0).unwrap());
    {
        let conn = store.lock().unwrap();
        conn.execute_batch(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 2047)
             INSERT INTO avatar_assets(owner_key, source_key, token)
             SELECT 'owner-' || x, 'source', randomblob(16) FROM n;
             INSERT INTO avatar_access(token, accessed)
             SELECT token, CAST(substr(owner_key, 7) AS INTEGER) FROM avatar_assets WHERE owner_key != 'target';
             UPDATE avatar_cache_meta SET access_seq = 4096 WHERE id = 1;",
        )
        .unwrap();
    }
    let (large, large_steps) = measure(&store, || store.read_avatar(&reference, 0).unwrap());
    assert_eq!(large, small);
    assert!(
        large_steps <= small_steps + 20,
        "read SQL work grew: {small_steps} -> {large_steps}"
    );
    assert!(large_steps < 500, "unbounded local read: {large_steps}");
    let (state, status_steps) = measure(&store, || store.avatar_status(&reference, 0).unwrap());
    assert_eq!(state.availability, AvatarAvailability::Ready);
    assert!(status_steps < 100, "unbounded status read: {status_steps}");
    let (same, bind_steps) = measure(&store, || bind(&store, "target"));
    assert_eq!(same, reference);
    assert!(
        bind_steps < 500,
        "unchanged binding scanned cache: {bind_steps}"
    );
    let (_, publish_steps) = measure(&store, || {
        assert_eq!(
            store
                .publish_avatar(&reference, 1, &image(2, 16), None)
                .unwrap(),
            AvatarPublishResult::Published {
                content_revision: 2
            }
        );
    });
    assert!(
        publish_steps < 30_000,
        "publication exceeded bounded metadata work: {publish_steps}"
    );
    let new = bind(&store, "new-owner");
    assert_eq!(
        store.avatar_cache_usage().unwrap().entries,
        MAX_AVATAR_CACHE_ENTRIES
    );
    assert_eq!(store.avatar_reference("owner-1").unwrap(), None);
    assert_eq!(
        store.avatar_status(&new, 0).unwrap().availability,
        AvatarAvailability::Missing
    );
}

#[test]
fn failed_source_rebind_and_counter_overflow_preserve_previous_pixels() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    let bytes = image(1, 16);
    publish(&store, &reference, &bytes);
    // Failure after the UPSERT but before commit must not clear the old avatar.
    assert!(
        store
            .bind_avatar_source_with_limits(
                "owner",
                "new",
                Limits {
                    entries: 0,
                    bytes: 16
                }
            )
            .is_err()
    );
    assert_eq!(
        store.avatar_reference("owner").unwrap(),
        Some(reference.clone())
    );
    assert_eq!(ready(&store, &reference).image, Some(bytes.clone()));
    store
        .lock()
        .unwrap()
        .execute("UPDATE avatar_assets SET content_revision = ?1", [i64::MAX])
        .unwrap();
    assert!(
        store
            .publish_avatar(&reference, i64::MAX as u64, &image(2, 16), None)
            .is_err()
    );
    assert_eq!(ready(&store, &reference).image, Some(bytes));
    store
        .lock()
        .unwrap()
        .execute("UPDATE avatar_cache_meta SET access_seq = ?1", [i64::MAX])
        .unwrap();
    assert!(store.bind_avatar_source("owner", "new").is_err());
    assert_eq!(store.avatar_reference("owner").unwrap(), Some(reference));
}

#[test]
fn avatar_recency_counter_widening_does_not_rewrite_blob_pages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("avatar-wal.db");
    let key = crate::SqlCipherKey::new("avatar-wal-test-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let reference = bind(&store, "owner");
    publish(&store, &reference, &image(42, MAX_AVATAR_BYTES));
    {
        let conn = store.lock().unwrap();
        conn.execute("UPDATE avatar_cache_meta SET access_seq = 126", [])
            .unwrap();
        conn.execute("UPDATE avatar_access SET accessed = 126", [])
            .unwrap();
        conn.execute_batch("PRAGMA wal_autocheckpoint = 0; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }
    // SQLite integer encoding widens at 128. LRU bookkeeping must not rewrite
    // the adjacent 10 MiB image when that happens.
    for _ in 0..3 {
        ready(&store, &reference);
    }
    store
        .lock()
        .unwrap()
        .execute("UPDATE avatar_cache_meta SET access_seq = 32766", [])
        .unwrap();
    for _ in 0..3 {
        assert_eq!(bind(&store, "owner"), reference);
    }
    let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
        .unwrap()
        .len();
    eprintln!("10 MiB avatar: three reads and three unchanged binds wrote {wal_bytes} WAL bytes");
    assert!(
        wal_bytes < 256 * 1024,
        "avatar reads rewrote {wal_bytes} WAL bytes"
    );
    store.close().unwrap();
}

#[test]
fn removing_live_avatar_invalidates_shared_views_and_preserves_other_owners() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "removed");
    let another_view = bind(&store, "removed");
    let other = bind(&store, "retained");
    let bytes = image(1, 16);
    publish(&store, &reference, &bytes);
    publish(&store, &other, &bytes);
    assert!(store.remove_avatar_source(&reference).unwrap());
    assert_eq!(
        store.avatar_cache_usage().unwrap(),
        AvatarCacheUsage {
            entries: 1,
            byte_count: 16
        }
    );
    assert_eq!(store.avatar_reference("removed").unwrap(), None);
    assert_eq!(
        store
            .read_avatar(&another_view, 0)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(
        store.publish_avatar(&reference, 1, &bytes, None).unwrap(),
        AvatarPublishResult::Superseded
    );
    assert_eq!(ready(&store, &other).image, Some(bytes));
    assert_ne!(bind(&store, "removed"), reference);
    let recency: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM avatar_access", [], |r| r.get(0))
        .unwrap();
    assert_eq!(recency as u64, store.avatar_cache_usage().unwrap().entries);
}

#[test]
fn avatar_acquisition_intent_exists_without_runtime() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM avatar_acquisition", [], |r| r.get(0))
        .expect("durable avatar work must survive independently of a runtime");
    assert_eq!(count, 0);
}

fn selected_url(key: &str) -> crate::SelectedAvatar {
    crate::SelectedAvatar::RemoteImage {
        url: format!("https://example.com/{key}"),
        cache_key: key.into(),
    }
}

#[test]
fn avatar_acquisition_coalesces_retries_and_retains_stale_bytes() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let selected = selected_url("same");
    let reference = store
        .request_avatar_acquisition("owner", &selected, false)
        .unwrap()
        .unwrap();
    let job = store.claim_avatar_acquisition(100).unwrap().unwrap();
    assert_eq!(
        store
            .request_avatar_acquisition("owner", &selected, true)
            .unwrap(),
        Some(reference.clone())
    );
    assert!(store.claim_avatar_acquisition(100).unwrap().is_none());
    store
        .complete_avatar_acquisition(&job, &image(42, 16), Some(200))
        .unwrap();
    assert!(store.claim_avatar_acquisition(199).unwrap().is_none());
    let refresh = store.claim_avatar_acquisition(200).unwrap().unwrap();
    assert_eq!(
        store
            .read_avatar(&reference, 200)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Stale
    );
    store.fail_avatar_acquisition(&refresh, 200, true).unwrap();
    store
        .request_avatar_acquisition("owner", &selected, true)
        .unwrap();
    assert!(store.claim_avatar_acquisition(259).unwrap().is_none());
    let retry = store.claim_avatar_acquisition(260).unwrap().unwrap();
    assert_eq!(ready(&store, &reference).image, Some(image(42, 16)));
    store
        .complete_avatar_acquisition(&retry, &image(43, 16), Some(300))
        .unwrap();
    assert_eq!(ready(&store, &reference).status.content_revision, 2);
    assert_eq!(ready(&store, &reference).image, Some(image(43, 16)));
}

#[test]
fn avatar_attempts_survive_reopen_and_fence_late_completion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.db");
    let key = crate::SqlCipherKey::new("avatar jobs fixture").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let reference = store
        .request_avatar_acquisition("owner", &selected_url("a"), false)
        .unwrap()
        .unwrap();
    let abandoned = store.claim_avatar_acquisition(0).unwrap().unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store.resume_avatar_acquisition().unwrap();
    let resumed = store.claim_avatar_acquisition(0).unwrap().unwrap();
    assert_eq!(
        store
            .complete_avatar_acquisition(&abandoned, &image(1, 8), None)
            .unwrap(),
        AvatarPublishResult::Superseded
    );
    store
        .complete_avatar_acquisition(&resumed, &image(2, 8), None)
        .unwrap();
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    assert_eq!(ready(&store, &reference).image, Some(image(2, 8)));
    assert!(
        store
            .claim_avatar_acquisition(u32::MAX as u64)
            .unwrap()
            .is_none()
    );
}

#[test]
fn avatar_source_replacement_eviction_and_blocked_failures_do_not_refill() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let a = store
        .request_avatar_acquisition("chat:group", &selected_url("a"), false)
        .unwrap()
        .unwrap();
    let job = store.claim_avatar_acquisition(0).unwrap().unwrap();
    let b = store
        .request_avatar_acquisition("chat:group", &selected_url("b"), false)
        .unwrap()
        .unwrap();
    assert_ne!(a, b);
    assert!(!store.fail_avatar_acquisition(&job, 0, true).unwrap());
    assert_eq!(
        store
            .complete_avatar_acquisition(&job, &image(1, 8), None)
            .unwrap(),
        AvatarPublishResult::Superseded
    );
    let current = store.claim_avatar_acquisition(0).unwrap().unwrap();
    store.fail_avatar_acquisition(&current, 0, false).unwrap();
    assert_eq!(
        store.avatar_acquisition_state(&b).unwrap(),
        Some(AvatarAcquisitionState::Blocked)
    );
    assert!(
        store
            .claim_avatar_acquisition(u32::MAX as u64)
            .unwrap()
            .is_none()
    );
    // Capacity eviction, not source maintenance, drops the remaining work.
    store
        .bind_avatar_source_with_limits(
            "other",
            "source",
            Limits {
                entries: 1,
                bytes: 8,
            },
        )
        .unwrap();
    store
        .maintain_chat_avatar("group", Some(&selected_url("b")), &selected_url("b"))
        .unwrap();
    store.resume_avatar_acquisition().unwrap();
    store.bootstrap_avatar_acquisition().unwrap();
    assert!(store.avatar_reference("chat:group").unwrap().is_none());
    assert!(
        store
            .claim_avatar_acquisition(u32::MAX as u64)
            .unwrap()
            .is_none()
    );
}

#[test]
fn avatar_demand_and_publication_roll_back_with_enclosing_transaction() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let result: StorageResult<()> = store.connection.with_transaction(|| {
        store.request_avatar_acquisition("owner", &selected_url("a"), false)?;
        Err(invalid("injected outer failure"))
    });
    assert!(result.is_err());
    assert!(store.avatar_reference("owner").unwrap().is_none());
    assert!(store.claim_avatar_acquisition(0).unwrap().is_none());
    let reference = store
        .request_avatar_acquisition("owner", &selected_url("a"), false)
        .unwrap()
        .unwrap();
    let job = store.claim_avatar_acquisition(0).unwrap().unwrap();
    store.lock().unwrap().execute_batch("CREATE TRIGGER reject_job_finish BEFORE UPDATE OF state ON avatar_acquisition WHEN NEW.state = 0 BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    assert!(
        store
            .complete_avatar_acquisition(&job, &image(1, 8), None)
            .is_err()
    );
    assert_eq!(
        store.avatar_status(&reference, 0).unwrap().availability,
        AvatarAvailability::Missing
    );
    assert_eq!(
        store.avatar_acquisition_state(&reference).unwrap(),
        Some(AvatarAcquisitionState::Fetching)
    );
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_job_finish;")
        .unwrap();
    store
        .complete_avatar_acquisition(&job, &image(1, 8), None)
        .unwrap();
}

#[test]
fn avatar_visible_priority_and_corruption_repair_are_durable() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .request_avatar_acquisition("background", &selected_url("background"), false)
        .unwrap();
    let visible = store
        .request_avatar_acquisition("visible", &selected_url("visible"), true)
        .unwrap()
        .unwrap();
    let first = store.claim_avatar_acquisition(0).unwrap().unwrap();
    assert_eq!(first.reference, visible);
    store
        .complete_avatar_acquisition(&first, &image(1, 8), None)
        .unwrap();
    let background = store.claim_avatar_acquisition(0).unwrap().unwrap();
    store
        .complete_avatar_acquisition(&background, &image(2, 8), None)
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE avatar_assets SET bytes = zeroblob(8) WHERE token = ?1",
            [&visible.token],
        )
        .unwrap();
    assert_eq!(
        store.read_avatar(&visible, 0).unwrap().status.availability,
        AvatarAvailability::Missing
    );
    assert_eq!(
        store
            .claim_avatar_acquisition(0)
            .unwrap()
            .unwrap()
            .reference,
        visible
    );
}

fn seed_avatar_group(store: &SqliteAccountStorage) {
    store.lock().unwrap().execute_batch("INSERT INTO account_groups(group_id_hex, endpoint, profile_name, updated_at, member_count) VALUES('group', 'fixture', '', 7, 2);
    INSERT INTO chat_list_rows(group_id_hex, activity_sort_at, updated_at) VALUES('group', 19, 7);").unwrap();
}

#[test]
fn avatar_identity_placeholder_updates_are_fenced_and_eviction_stops_maintenance() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&store);
    let absent = crate::SelectedAvatar::Placeholder {
        stable_seed: "seed".into(),
        source: crate::PresentationSource::PeerFallback,
    };
    let v1 = crate::ChatPresentationVersion {
        store_epoch: vec![9; 16],
        revision: 1,
    };
    let v2 = crate::ChatPresentationVersion {
        revision: 2,
        ..v1.clone()
    };
    assert!(
        store
            .request_identity_avatar_acquisition("group", "member", &absent, &v1)
            .unwrap()
            .is_none()
    );
    let identities = store.requested_avatar_identities_after("").unwrap();
    assert_eq!(identities.len(), 1);
    store
        .maintain_identity_avatar_acquisition(&identities[0], &selected_url("new"), &v2)
        .unwrap();
    let reference = store
        .avatar_reference(&identities[0].owner)
        .unwrap()
        .unwrap();
    store
        .maintain_identity_avatar_acquisition(&identities[0], &absent, &v1)
        .unwrap();
    assert_eq!(
        store.avatar_reference(&identities[0].owner).unwrap(),
        Some(reference.clone())
    );
    store
        .maintain_identity_avatar_acquisition(&identities[0], &absent, &v2)
        .unwrap();
    assert!(
        store
            .avatar_reference(&identities[0].owner)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store.requested_avatar_identities_after("").unwrap().len(),
        1
    );
    store
        .maintain_identity_avatar_acquisition(&identities[0], &selected_url("new"), &v2)
        .unwrap();
    store
        .bind_avatar_source_with_limits(
            "other",
            "source",
            Limits {
                entries: 1,
                bytes: 8,
            },
        )
        .unwrap();
    assert!(
        store
            .requested_avatar_identities_after("")
            .unwrap()
            .is_empty()
    );
    store
        .maintain_identity_avatar_acquisition(&identities[0], &selected_url("new"), &v2)
        .unwrap();
    assert!(
        store
            .avatar_reference(&identities[0].owner)
            .unwrap()
            .is_none()
    );
}

#[test]
#[ignore = "host timing evidence; not a device latency gate"]
fn avatar_local_read_timing_by_encoded_size() {
    let dir = tempfile::tempdir().unwrap();
    let key = crate::SqlCipherKey::new("avatar timing fixture").unwrap();
    let store = SqliteAccountStorage::open_encrypted(dir.path().join("account.db"), &key).unwrap();
    for size in [256 * 1024, 1024 * 1024, MAX_AVATAR_BYTES] {
        let reference = store
            .bind_avatar_source("timing", &format!("size-{size}"))
            .unwrap();
        publish(&store, &reference, &image(1, size));
        let mut samples = Vec::new();
        for _ in 0..20 {
            let start = std::time::Instant::now();
            let read = store.read_avatar(&reference, 0).unwrap();
            samples.push(start.elapsed().as_micros());
            assert_eq!(read.image.unwrap().bytes().len(), size);
        }
        samples.sort();
        println!(
            "avatar bytes={size} read_us p50={} p95={}",
            samples[10], samples[19]
        );
    }
}

#[test]
fn avatar_expired_attempt_lease_recovers_failed_completion_storage() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .request_avatar_acquisition("owner", &selected_url("a"), false)
        .unwrap();
    let old = store.claim_avatar_acquisition(0).unwrap().unwrap();
    assert!(store.claim_avatar_acquisition(119).unwrap().is_none());
    let retry = store.claim_avatar_acquisition(120).unwrap().unwrap();
    assert_eq!(
        store
            .complete_avatar_acquisition(&old, &image(1, 8), None)
            .unwrap(),
        AvatarPublishResult::Superseded
    );
    store
        .complete_avatar_acquisition(&retry, &image(2, 8), None)
        .unwrap();
}

#[test]
fn avatar_identity_bytes_are_removed_with_the_local_conversation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&store);
    let version = crate::ChatPresentationVersion {
        store_epoch: vec![9; 16],
        revision: 1,
    };
    let reference = store
        .request_identity_avatar_acquisition("group", "member", &selected_url("a"), &version)
        .unwrap()
        .unwrap();
    let job = store.claim_avatar_acquisition(0).unwrap().unwrap();
    store
        .complete_avatar_acquisition(&job, &image(1, 8), None)
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM chat_list_rows WHERE group_id_hex = 'group'",
            [],
        )
        .unwrap();
    assert!(
        store
            .requested_avatar_identities_after("")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.avatar_status(&reference, 0).unwrap().availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(store.avatar_cache_usage().unwrap().byte_count, 0);
}

#[test]
fn avatar_idle_maintenance_needs_no_write_transaction() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    store
        .lock()
        .unwrap()
        .pragma_update(None, "query_only", true)
        .unwrap();
    assert!(
        !store
            .bootstrap_avatar_acquisition()
            .expect("empty bootstrap is read-only")
    );
    assert!(
        store
            .claim_avatar_acquisition(100)
            .expect("no due demand is read-only")
            .is_none()
    );
}

#[test]
fn avatar_retry_budget_enters_daily_probes_and_recovers() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = store
        .request_avatar_acquisition("owner", &selected_url("a"), false)
        .unwrap()
        .unwrap();
    for n in 0..16 {
        let now = n * 3600;
        let job = store.claim_avatar_acquisition(now).unwrap().unwrap();
        store.fail_avatar_acquisition(&job, now, true).unwrap();
    }
    assert_eq!(
        store.avatar_acquisition_state(&reference).unwrap(),
        Some(AvatarAcquisitionState::RetryScheduled)
    );
    let due = 15 * 3600 + 86400;
    // Restart and repeated visible demand must preserve the full cooldown.
    store.resume_avatar_acquisition().unwrap();
    store
        .request_avatar_acquisition("owner", &selected_url("a"), true)
        .unwrap();
    assert!(store.claim_avatar_acquisition(due - 1).unwrap().is_none());
    let probe = store.claim_avatar_acquisition(due).unwrap().unwrap();
    store.fail_avatar_acquisition(&probe, due, true).unwrap();
    assert!(
        store
            .claim_avatar_acquisition(due + 86400 - 1)
            .unwrap()
            .is_none()
    );
    let recovered = store
        .claim_avatar_acquisition(due + 86400)
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .complete_avatar_acquisition(&recovered, &image(1, 8), Some(due + 86401))
            .unwrap(),
        AvatarPublishResult::Published {
            content_revision: 1
        }
    );
    // Successful acquisition resets the fast retry budget for later refreshes.
    let refresh = store
        .claim_avatar_acquisition(due + 86401)
        .unwrap()
        .unwrap();
    store
        .fail_avatar_acquisition(&refresh, due + 86401, true)
        .unwrap();
    assert!(
        store
            .claim_avatar_acquisition(due + 86460)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .claim_avatar_acquisition(due + 86461)
            .unwrap()
            .is_some()
    );
    store
        .request_avatar_acquisition("owner", &selected_url("new"), false)
        .unwrap();
    assert!(store.claim_avatar_acquisition(0).unwrap().is_some());
}

#[test]
fn avatar_bootstrap_survives_unchanged_presentation_rewrite() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&store);
    let value = crate::StoredChatPresentation {
        presentation: crate::ConversationPresentation {
            title: crate::PresentationText::Literal("Chat".into()),
            avatar: selected_url("a"),
            title_source: crate::PresentationSource::Group,
            avatar_source: crate::PresentationSource::Group,
            peer_id: None,
            resolution: crate::PresentationResolution::Cached,
        },
        profile_version: None,
    };
    let bytes = serde_json::to_vec(&serde_json::json!({"format": 1, "value": value})).unwrap();
    store.lock().unwrap().execute("UPDATE chat_list_rows SET presentation_json = ?1, presentation_applied_source_revision = presentation_source_revision WHERE group_id_hex = 'group'", [bytes]).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO avatar_acquisition_bootstrap(group_id_hex) VALUES('group')",
            [],
        )
        .unwrap();
    // The rename dirties the row but retains its previously selected avatar.
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE account_groups SET profile_name = 'Renamed' WHERE group_id_hex = 'group'",
            [],
        )
        .unwrap();
    let input = store.chat_presentation_input("group").unwrap().unwrap();
    assert_eq!(
        store.store_chat_presentation(&input, &value).unwrap(),
        crate::ChatPresentationWrite::Applied
    );
    assert!(!store.bootstrap_avatar_acquisition().unwrap());
    let job = store
        .claim_avatar_acquisition(0)
        .unwrap()
        .expect("unchanged presentation must not consume upgrade demand");
    assert!(job.descriptor == value.presentation.avatar);
    store
        .complete_avatar_acquisition(&job, &image(1, 8), None)
        .unwrap();
    store.remove_avatar_source(&job.reference).unwrap();
    store
        .maintain_chat_avatar(
            "group",
            Some(&value.presentation.avatar),
            &value.presentation.avatar,
        )
        .unwrap();
    store.bootstrap_avatar_acquisition().unwrap();
    assert!(store.claim_avatar_acquisition(0).unwrap().is_none());
}

#[test]
fn avatar_identity_demand_survives_directory_generation_catchup() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&store);
    let checkpoint = store.chat_presentation_checkpoint().unwrap();
    let mut state = checkpoint.state.clone();
    state.shared_epoch = vec![1; 16];
    store
        .commit_chat_presentation_batch(&checkpoint, &state, &[])
        .unwrap();
    let version = crate::ChatPresentationVersion {
        store_epoch: vec![9; 16],
        revision: 1,
    };
    assert!(
        store
            .request_identity_avatar_acquisition("group", "member", &selected_url("a"), &version)
            .unwrap()
            .is_none()
    );
    let registered = store.requested_avatar_identities_after("").unwrap();
    assert_eq!(registered.len(), 1);
    let checkpoint = store.chat_presentation_checkpoint().unwrap();
    state.shared_epoch = version.store_epoch.clone();
    store
        .commit_chat_presentation_batch(&checkpoint, &state, &[])
        .unwrap();
    store
        .maintain_identity_avatar_acquisition(&registered[0], &selected_url("a"), &version)
        .unwrap();
    assert!(
        store
            .avatar_reference(&registered[0].owner)
            .unwrap()
            .is_some()
    );
}

#[test]
fn avatar_native_reference_and_byte_budget_preserve_source_fencing() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let reference = bind(&store, "owner");
    publish(&store, &reference, &image(7, 16));
    let decoded = AvatarAssetRef::from_opaque(&reference.to_opaque()).unwrap();
    let short = store.read_avatar_bounded(&decoded, 0, 15).unwrap();
    assert!(short.image.is_none());
    assert_eq!(short.status.availability, AvatarAvailability::Ready);
    assert_eq!(
        store.read_avatar_bounded(&decoded, 0, 16).unwrap().image,
        Some(image(7, 16))
    );
    store.bind_avatar_source("owner", "replacement").unwrap();
    assert_eq!(
        store
            .read_avatar_bounded(&decoded, 0, 16)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Invalidated
    );
    assert!(AvatarAssetRef::from_opaque("bad reference").is_err());
}

#[test]
fn avatar_screen_targets_reject_another_account_or_recreated_conversation() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&store);
    let asset = store
        .avatar_target_presentation("group", None, &selected_url("a"), 0)
        .unwrap()
        .unwrap();
    let target = AvatarAssetTarget::from_opaque(&asset.target.to_opaque()).unwrap();
    assert_eq!(
        store.resolve_avatar_target(&target).unwrap().as_deref(),
        Some("group")
    );
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed_avatar_group(&other);
    assert!(other.resolve_avatar_target(&target).unwrap().is_none());
    assert_eq!(
        other
            .request_avatar_target(&target, &selected_url("a"), None, 0)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Invalidated
    );
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM account_groups WHERE group_id_hex = 'group'",
            [],
        )
        .unwrap();
    seed_avatar_group(&store);
    assert!(store.resolve_avatar_target(&target).unwrap().is_none());
    assert_eq!(
        store
            .request_avatar_target(&target, &selected_url("a"), None, 0)
            .unwrap()
            .status
            .availability,
        AvatarAvailability::Invalidated
    );
    assert!(AvatarAssetTarget::from_opaque(&"x".repeat(1201)).is_err());
}

#[test]
fn avatar_target_lookup_uses_the_conversation_incarnation_index() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let conn = store.lock().unwrap();
    let mut query = conn.prepare("EXPLAIN QUERY PLAN SELECT group_id_hex FROM chat_list_rows CROSS JOIN chat_presentation_meta m WHERE presentation_row_epoch = ?1 AND m.id = 1 AND m.store_epoch = ?2").unwrap();
    let plan = query
        .query_map(params![vec![0_u8; 16], vec![0_u8; 16]], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|line| line.contains("chat_avatar_target_lookup"))
    );
    assert!(!plan.iter().any(|line| line.contains("SCAN chat_list_rows")));
}
