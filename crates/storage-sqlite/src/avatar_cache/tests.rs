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
             INSERT INTO avatar_assets(owner_key, source_key, token, accessed)
             SELECT 'owner-' || x, 'source', randomblob(16), x FROM n;
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
