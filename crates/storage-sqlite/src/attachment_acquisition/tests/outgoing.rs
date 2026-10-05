//! Durable outgoing staging and source promotion; real upload/publication is integration-tested.
use super::*;

/// Create an accepted outgoing source without bypassing the storage projection.
fn sent(store: &SqliteAccountStorage, message: &str) {
    seed(store, message);
    let mut event = source(message);
    event.direction = "sent".into();
    store.record_app_event(&event).unwrap();
}

/// Stage the same private bytes and bind their exact source descriptor.
fn bound(store: &SqliteAccountStorage, message: &str) -> Vec<u8> {
    let tokens = store
        .stage_attachment_uploads(GROUP, 3, &[BODY], 11, 10000)
        .unwrap();
    store
        .bind_attachment_uploads(&tokens, &[(selected(message).slot, digest())])
        .unwrap();
    tokens[0].clone()
}

/// Attach an accepted source owner to the staged fixture.
fn staged(store: &SqliteAccountStorage, message: &str) -> Vec<u8> {
    let token = bound(store, message);
    store
        .protect_attachment_uploads(GROUP, message, &source(message).tags)
        .unwrap();
    token
}

/// Count all canonical and upload staging bytes under the shared quota.
fn usage(store: &SqliteAccountStorage) -> u64 {
    store
        .lock()
        .unwrap()
        .query_row(
            "SELECT byte_count FROM attachment_retention_usage WHERE id=1",
            [],
            |r| nonnegative(r, 0),
        )
        .unwrap()
}

/// A late owner-insert failure must not commit an earlier owner's protection.
#[test]
fn outgoing_owner_batch_rolls_back_late_insert_failure() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "owner-batch");
    let first = source("owner-batch").tags[0].clone();
    let mut second = first.clone();
    second.push("filename distinct".into());
    let tokens = store
        .stage_attachment_uploads(GROUP, 3, &[BODY, BODY], 11, 10000)
        .unwrap();
    store
        .bind_attachment_uploads(
            &tokens,
            &[
                (serde_json::to_value(&first).unwrap(), digest()),
                (serde_json::to_value(&second).unwrap(), digest()),
            ],
        )
        .unwrap();
    sql(
        &store,
        &format!(
            "CREATE TRIGGER fail_second_upload_owner BEFORE INSERT ON outgoing_attachment_upload_owners WHEN NEW.token=x'{}' BEGIN SELECT RAISE(ABORT,'generated owner fault'); END",
            hex::encode(&tokens[1])
        ),
    );
    let tags = [first, vec!["other".into()], second];
    assert!(
        store
            .protect_attachment_uploads(GROUP, "owner-batch", &tags)
            .is_err()
    );
    let owner_count = || {
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM outgoing_attachment_upload_owners",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(owner_count(), 0);
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
    sql(&store, "DROP TRIGGER fail_second_upload_owner");
    for _ in 0..2 {
        store
            .protect_attachment_uploads(GROUP, "owner-batch", &tags)
            .unwrap();
        assert_eq!(owner_count(), 2);
        assert_eq!(usage(&store), 2 * BODY.len() as u64);
    }
}

/// Verify a real pending owner prevents TTL cleanup through encrypted reopen.
#[test]
fn outgoing_staging_survives_restart_and_pending_send_outlives_orphan_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("outgoing.sqlite");
    let key = SqlCipherKey::new("outgoing-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES(?1,'',0)",
            [GROUP],
        )
        .unwrap();
    let mut pending = source("pending");
    pending.direction = "sent".into();
    pending.source_message_id_hex = None;
    pending.source_epoch = None;
    store.record_app_event(&pending).unwrap();
    staged(&store, "pending");
    store
        .protect_attachment_uploads(GROUP, "pending", &source("pending").tags)
        .unwrap();
    assert_eq!(
        store
            .prune_attachment_uploads(11 + 8 * 24 * 3600, 64)
            .unwrap(),
        0
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "pending", 20, 10000)
            .unwrap(),
        0
    );
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    sent(&store, "pending");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "pending", 20, 10000)
            .unwrap(),
        1
    );
    let asset = request(&store, "pending");
    assert_eq!(read(&store, &asset), BODY);
    assert_eq!(usage(&store), BODY.len() as u64);
}

/// A complete multi-upload batch converts its existing reservation without double charging.
#[test]
fn outgoing_batch_promotion_respects_exact_capacity_and_repeated_slots() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "two");
    let mut event = source("two");
    event.direction = "sent".into();
    event.tags.push(event.tags[0].clone());
    store.record_app_event(&event).unwrap();
    let token = staged(&store, "two");
    store
        .set_attachment_download_policy(
            &AttachmentDownloadPolicy {
                retained_bytes: 2 * BODY.len() as u64,
                ..policy(false, 1)
            },
            11,
        )
        .unwrap();
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "two", 12, 10000)
            .unwrap(),
        2
    );
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
    for index in [0, 1] {
        let asset = store
            .retained_attachment_asset(GROUP, "two", "source-two", index, 12)
            .unwrap()
            .unwrap();
        assert_eq!(read(&store, &asset.reference), BODY);
    }
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM outgoing_attachment_uploads WHERE token=?1",
            [token],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

/// Optional staging refusal cannot evict existing retained content.
#[test]
fn outgoing_stage_capacity_failure_rolls_back_the_batch_without_eviction() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "existing");
    let asset = request(&store, "existing");
    publish(&store, &asset);
    assert!(
        store
            .stage_attachment_uploads(GROUP, 3, &[BODY, BODY], 20, 2 * BODY.len() as u64)
            .is_err()
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(read(&store, &asset), BODY);
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM outgoing_attachment_uploads",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        0
    );
}

/// Corruption and injected publication faults leave staging recoverable with no ready bytes.
#[test]
fn outgoing_promotion_fault_rolls_back_and_recovers_without_new_demand() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "recover");
    staged(&store, "recover");
    sql(
        &store,
        "CREATE TRIGGER fail_outgoing_publication BEFORE INSERT ON retained_attachment_bytes BEGIN SELECT RAISE(ABORT,'injected publication failure');END;",
    );
    assert!(
        store
            .promote_attachment_uploads(GROUP, "recover", 12, 10000)
            .is_err()
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    assert!(
        store
            .retained_attachment_asset(GROUP, "recover", "source-recover", 0, 12)
            .unwrap()
            .is_none()
    );
    sql(&store, "DROP TRIGGER fail_outgoing_publication;");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "recover", 12, 10000)
            .unwrap(),
        1
    );
    assert_eq!(read(&store, &request(&store, "recover")), BODY);
    sent(&store, "corrupt");
    staged(&store, "corrupt");
    sql(
        &store,
        "UPDATE outgoing_attachment_uploads SET bytes=x'00';",
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "corrupt", 12, 10000)
            .unwrap(),
        0
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(
        transfer(&store, "corrupt", true).state,
        AttachmentTransferState::CompletedUnretained
    );
    assert!(
        store
            .attachment_transfer_candidates(100, 64, true)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.prune_attachment_uploads(13, 64).unwrap(), 1);
}

/// Moving exclusively owned bytes under a lowered quota consumes no extra capacity.
#[test]
fn outgoing_exclusive_move_survives_lowered_quota() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "blocked");
    staged(&store, "blocked");
    store
        .set_attachment_download_policy(
            &AttachmentDownloadPolicy {
                retained_bytes: 1,
                ..policy(true, 1)
            },
            11,
        )
        .unwrap();
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "blocked", 12, 10000)
            .unwrap(),
        1
    );
    assert_eq!(
        transfer(&store, "blocked", true).state,
        AttachmentTransferState::Ready
    );
    assert!(
        store
            .attachment_transfer_candidates(100, 64, true)
            .unwrap()
            .is_empty()
    );
    store
        .set_attachment_download_policy(&policy(false, 10000), 13)
        .unwrap();
    assert_eq!(store.recover_attachment_uploads(14, 64, 10000).unwrap(), 0);
    assert_eq!(read(&store, &request(&store, "blocked")), BODY);
}

/// Promotion fences a racing acquisition rather than permitting late overwrite.
#[test]
fn outgoing_confirmation_fences_active_acquisition_and_preserves_removal() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "race");
    let asset = request(&store, "race");
    let job = store
        .claim_attachment_acquisition(&asset, 11, 100)
        .unwrap()
        .unwrap();
    staged(&store, "race");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "race", 12, 10000)
            .unwrap(),
        1
    );
    assert!(!store.attachment_transfer_is_active(&job, 12).unwrap());
    assert_eq!(
        store
            .complete_attachment_acquisition(&job, BODY, 12, 10000)
            .unwrap(),
        AttachmentPublishResult::Superseded
    );
    store.remove_attachment_reference(&asset).unwrap();
    staged(&store, "race");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "race", 13, 10000)
            .unwrap(),
        0
    );
    assert!(
        store
            .retained_attachment_asset(GROUP, "race", "source-race", 0, 13)
            .unwrap()
            .is_none()
    );
}

/// Expired, invalidated and foreign source metadata cannot adopt uploaded bytes.
#[test]
fn outgoing_promotion_respects_expiry_invalidation_epoch_and_account_isolation() {
    for mutation in [
        "UPDATE app_events SET retention_expires_at=12",
        "UPDATE attachment_history SET visible=0",
        "UPDATE attachment_history SET source_epoch=4",
    ] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        sent(&store, "stale");
        staged(&store, "stale");
        sql(&store, mutation);
        assert_eq!(
            store
                .promote_attachment_uploads(GROUP, "stale", 12, 10000)
                .unwrap(),
            0
        );
    }
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "foreign");
    let tokens = vec![staged(&store, "foreign")];
    assert!(
        SqliteAccountStorage::in_memory()
            .unwrap()
            .bind_attachment_uploads(&tokens, &[(selected("foreign").slot, digest())])
            .is_err()
    );
}

/// Failed unowned uploads expire in bounded pages and group deletion releases reservations.
#[test]
fn outgoing_orphan_cleanup_and_group_deletion_release_quota() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "orphan");
    store
        .stage_attachment_uploads(GROUP, 3, &[BODY, BODY], 11, 10000)
        .unwrap();
    assert_eq!(
        store
            .prune_attachment_uploads(11 + 8 * 24 * 3600, 1)
            .unwrap(),
        1
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    sql(
        &store,
        &format!("DELETE FROM account_groups WHERE group_id_hex='{GROUP}';"),
    );
    assert_eq!(usage(&store), 0);
}

/// Separate pending messages sharing one upload keep staging until both sources confirm.
#[test]
fn shared_upload_survives_first_confirmation_and_configured_quota_is_enforced() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "shared-a");
    sent(&store, "shared-b");
    let token = staged(&store, "shared-a");
    store
        .protect_attachment_uploads(GROUP, "shared-b", &source("shared-b").tags)
        .unwrap();
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "shared-a", 12, BODY.len() as u64)
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "shared-a", 12, 2 * BODY.len() as u64)
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM outgoing_attachment_uploads WHERE token=?1",
                [&token],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "shared-b", 12, 2 * BODY.len() as u64)
            .unwrap(),
        1
    );
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
    assert_eq!(read(&store, &request(&store, "shared-a")), BODY);
    assert_eq!(read(&store, &request(&store, "shared-b")), BODY);
}

/// Observed failed uploads release reservations immediately; admitted ownership wins.
#[test]
fn failed_upload_cleanup_is_immediate_but_never_discards_pending_owner() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "owner");
    let unowned = store
        .stage_attachment_uploads(GROUP, 3, &[BODY, BODY], 11, 10000)
        .unwrap();
    store.abandon_attachment_uploads(&unowned).unwrap();
    assert_eq!(usage(&store), 0);
    let owned = vec![staged(&store, "owner")];
    store.abandon_attachment_uploads(&owned).unwrap();
    assert_eq!(usage(&store), BODY.len() as u64);
}

/// Retired siblings do not retain staging before or after the healthy source is ready.
#[test]
fn shared_upload_releases_retired_owner_reservations() {
    for retire in ["invalidated", "expired", "removed", "cancelled"] {
        for after_first in [false, true] {
            let store = SqliteAccountStorage::in_memory().unwrap();
            sent(&store, "live");
            sent(&store, "retired");
            staged(&store, "live");
            store
                .protect_attachment_uploads(GROUP, "retired", &source("retired").tags)
                .unwrap();
            if after_first {
                assert_eq!(
                    store
                        .promote_attachment_uploads(GROUP, "live", 12, 2 * BODY.len() as u64)
                        .unwrap(),
                    1
                );
            }
            match retire {
                "invalidated" => sql(
                    &store,
                    "UPDATE app_events SET invalidated=1 WHERE message_id_hex='retired'",
                ),
                "expired" => sql(
                    &store,
                    "UPDATE app_events SET retention_expires_at=12 WHERE message_id_hex='retired'",
                ),
                "removed" => {
                    store
                        .remove_attachment_reference(&request(&store, "retired"))
                        .unwrap();
                }
                "cancelled" => {
                    store
                        .cancel_attachment_acquisition(&request(&store, "retired"))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            if after_first {
                assert_eq!(store.prune_attachment_uploads(13, 64).unwrap(), 1);
            } else {
                assert_eq!(
                    store
                        .promote_attachment_uploads(GROUP, "live", 13, BODY.len() as u64)
                        .unwrap(),
                    1
                );
            }
            assert_eq!(usage(&store), BODY.len() as u64);
            assert_eq!(read(&store, &request(&store, "live")), BODY);
        }
    }
}

/// Duplicate slots blocked by quota keep their only local source for later recovery.
#[test]
fn duplicate_outgoing_slots_recover_after_quota_increase() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "duplicate");
    let mut event = source("duplicate");
    event.direction = "sent".into();
    event.tags.push(event.tags[0].clone());
    store.record_app_event(&event).unwrap();
    staged(&store, "duplicate");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "duplicate", 12, BODY.len() as u64)
            .unwrap(),
        0
    );
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(
        store
            .recover_attachment_uploads(13, 64, 2 * BODY.len() as u64)
            .unwrap(),
        2
    );
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
}

/// Full quota defers BLOB integrity reads until a copy can actually be published.
#[test]
fn blocked_recovery_does_not_scan_staged_content() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "blocked-scan");
    staged(&store, "blocked-scan");
    sent(&store, "shared-scan");
    store
        .protect_attachment_uploads(GROUP, "shared-scan", &source("shared-scan").tags)
        .unwrap();
    // A corrupt BLOB would fail verification. Stable full-quota passes must not read it.
    sql(&store, "UPDATE outgoing_attachment_uploads SET bytes=x'00'");
    for now in 12..22 {
        assert_eq!(store.recover_attachment_uploads(now, 64, 1).unwrap(), 0);
    }
    assert_eq!(store.recover_attachment_uploads(22, 64, 10000).unwrap(), 0);
    assert_eq!(usage(&store), 0);
}

/// Recovery rotates past a permanently blocked shared owner to affordable sources.
#[test]
fn outgoing_recovery_page_rotates_past_blocked_owner() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "a-blocked");
    sent(&store, "b-shared");
    sent(&store, "z-affordable");
    staged(&store, "a-blocked");
    store
        .protect_attachment_uploads(GROUP, "b-shared", &source("b-shared").tags)
        .unwrap();
    let mut event = source("z-affordable");
    event.direction = "sent".into();
    event.tags[0].push("filename distinct".into());
    store.record_app_event(&event).unwrap();
    let token = store
        .stage_attachment_uploads(GROUP, 3, &[BODY], 11, 10000)
        .unwrap();
    store
        .bind_attachment_uploads(
            &token,
            &[(serde_json::to_value(&event.tags[0]).unwrap(), digest())],
        )
        .unwrap();
    store
        .protect_attachment_uploads(GROUP, "z-affordable", &event.tags)
        .unwrap();
    let mut recovered = 0;
    for now in 12..18 {
        recovered += store
            .recover_attachment_uploads(now, 1, 2 * BODY.len() as u64)
            .unwrap();
    }
    assert_eq!(
        recovered, 1,
        "bounded token/history cursors must rotate past blocked owners regardless of random token order"
    );
    assert!(
        store
            .retained_attachment_asset(GROUP, "z-affordable", "source-z-affordable", 0, 14)
            .unwrap()
            .is_some()
    );
}

/// A durably rejected pending admission releases its reservation without waiting for TTL.
#[test]
fn rejected_pending_submission_releases_outgoing_staging() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "rejected");
    sql(
        &store,
        "DELETE FROM app_events WHERE message_id_hex='rejected'",
    );
    let mut event = source("rejected");
    event.direction = "sent".into();
    event.source_message_id_hex = None;
    event.source_epoch = None;
    store.record_app_event(&event).unwrap();
    staged(&store, "rejected");
    store
        .insert_local_submission(&crate::local_submissions::LocalSubmission {
            group_id_hex: GROUP.into(),
            client_token: "rejected-token".into(),
            message_id_hex: "rejected".into(),
            request_hash: vec![1; 32],
            payload_hash: vec![2; 32],
            payload: Some(vec![3]),
            request_json: Some("{}".into()),
            state: 0,
            outcome_json: None,
        })
        .unwrap();
    assert_eq!(store.prune_attachment_uploads(12, 64).unwrap(), 0);
    store
        .finish_local_submission(GROUP, "rejected-token", None)
        .unwrap();
    assert_eq!(store.prune_attachment_uploads(13, 64).unwrap(), 1);
    assert_eq!(usage(&store), 0);
}

/// A racing source's own ciphertext reservation is released by atomic outgoing promotion.
#[test]
fn outgoing_promotion_credits_its_own_partial_at_exact_capacity() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "partial-race");
    let asset = request(&store, "partial-race");
    let job = store
        .claim_attachment_acquisition(&asset, 11, 100)
        .unwrap()
        .unwrap();
    assert!(
        store
            .checkpoint_attachment_partial(&job, &partial_identity(100), 0, b"prefix", 11, 10000)
            .unwrap()
    );
    staged(&store, "partial-race");
    assert_eq!(
        store
            .promote_attachment_uploads(GROUP, "partial-race", 12, BODY.len() as u64)
            .unwrap(),
        1
    );
    assert_eq!(partial_usage(&store), 0);
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(read(&store, &asset), BODY);
}

/// Outer rollback discards callbacks; optional promotion faults cannot undo a commit.
#[test]
fn outgoing_retention_waits_for_outer_commit_and_preserves_source_on_fault() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "seed");
    bound(&store, "projection");
    let mut event = source("projection");
    event.direction = "sent".into();
    let rolled_back: StorageResult<()> = store.connection.with_transaction(|| {
        store.record_app_event(&event)?;
        store.retain_attachment_uploads_after_commit(GROUP, "projection", 12, 10000);
        assert_eq!(
            store
                .lock()?
                .query_row(
                    "SELECT count(*) FROM outgoing_attachment_upload_owners",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .storage()?,
            0
        );
        Err(invalid("generated outer rollback"))
    });
    assert!(rolled_back.is_err());
    sql(
        &store,
        "CREATE TRIGGER fail_optional_copy BEFORE INSERT ON retained_attachment_bytes BEGIN SELECT RAISE(ABORT,'generated copy fault'); END;",
    );
    store
        .connection
        .with_transaction(|| {
            store.record_app_event(&event)?;
            store.retain_attachment_uploads_after_commit(GROUP, "projection", 12, 10000);
            assert_eq!(
                store
                    .lock()?
                    .query_row(
                        "SELECT count(*) FROM outgoing_attachment_upload_owners",
                        [],
                        |r| r.get::<_, i64>(0)
                    )
                    .storage()?,
                0
            );
            Ok::<_, StorageError>(())
        })
        .unwrap();
    assert_eq!(
        store
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM app_events WHERE message_id_hex='projection'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert!(
        store
            .retained_attachment_asset(GROUP, "projection", "source-projection", 0, 12)
            .unwrap()
            .is_none()
    );
    sql(&store, "DROP TRIGGER fail_optional_copy");
    assert_eq!(store.recover_attachment_uploads(13, 64, 10000).unwrap(), 1);
    assert_eq!(read(&store, &request(&store, "projection")), BODY);
}

/// Source identity repairs the post-commit/pre-owner gap even after TTL and encrypted reopen.
#[test]
fn ownerless_pending_and_confirmed_uploads_survive_ttl_and_recover() {
    for pending in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new("generated-crash-key").unwrap();
        let path = dir.path().join("account.sqlite");
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        seed(&store, "seed");
        let mut event = source("crash-gap");
        event.direction = "sent".into();
        if pending {
            event.source_message_id_hex = None;
            event.source_epoch = None;
        }
        store.record_app_event(&event).unwrap();
        bound(&store, "crash-gap");
        store.close().unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let now = 11 + 8 * 24 * 3600;
        assert_eq!(store.prune_attachment_uploads(now, 64).unwrap(), 0);
        if pending {
            assert_eq!(store.recover_attachment_uploads(now, 64, 10000).unwrap(), 0);
            sent(&store, "crash-gap");
        }
        assert_eq!(store.recover_attachment_uploads(now, 64, 10000).unwrap(), 1);
        assert_eq!(read(&store, &request(&store, "crash-gap")), BODY);
    }
}

/// A poisoned shared upload releases bytes and settles every live slot before pruning metadata.
#[test]
fn corrupt_shared_upload_is_quarantined_without_reacquisition() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    for message in ["a-poison", "b-poison", "z-valid"] {
        sent(&store, message);
    }
    staged(&store, "a-poison");
    store
        .protect_attachment_uploads(GROUP, "b-poison", &source("b-poison").tags)
        .unwrap();
    sql(&store, "UPDATE outgoing_attachment_uploads SET bytes=x'00'");
    let mut valid = source("z-valid");
    valid.direction = "sent".into();
    valid.tags[0].push("filename distinct".into());
    store.record_app_event(&valid).unwrap();
    let tokens = store
        .stage_attachment_uploads(GROUP, 3, &[BODY], 11, 10000)
        .unwrap();
    store
        .bind_attachment_uploads(
            &tokens,
            &[(serde_json::to_value(&valid.tags[0]).unwrap(), digest())],
        )
        .unwrap();
    assert_eq!(store.recover_attachment_uploads(12, 64, 10000).unwrap(), 1);
    for message in ["a-poison", "b-poison"] {
        assert_eq!(
            transfer(&store, message, true).state,
            AttachmentTransferState::CompletedUnretained
        );
    }
    assert_eq!(usage(&store), BODY.len() as u64);
    assert_eq!(store.prune_attachment_uploads(13, 64).unwrap(), 1);
    assert!(
        store
            .attachment_transfer_candidates(100, 64, true)
            .unwrap()
            .is_empty()
    );
}

/// Accepted pending and confirmed sources survive cleanup when optional owner INSERT fails.
#[test]
fn ownerless_committed_sources_survive_both_abandonment_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ownerless.sqlite");
    let key = SqlCipherKey::new("generated-ownerless-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    seed(&store, "seed");
    for (id, pending) in [("pending-ownerless", true), ("confirmed-ownerless", false)] {
        let mut event = source(id);
        event.direction = "sent".into();
        if pending {
            event.source_message_id_hex = None;
            event.source_epoch = None;
        }
        store.record_app_event(&event).unwrap();
        let token = bound(&store, id);
        sql(
            &store,
            "CREATE TRIGGER fail_owner BEFORE INSERT ON outgoing_attachment_upload_owners BEGIN SELECT RAISE(ABORT,'generated owner fault'); END;",
        );
        assert!(
            store
                .protect_attachment_uploads(GROUP, id, &event.tags)
                .is_err()
        );
        sql(&store, "DROP TRIGGER fail_owner");
        store.abandon_attachment_uploads(&[token]).unwrap();
        store
            .abandon_bound_attachment_uploads(GROUP, &[selected(id).slot])
            .unwrap();
    }
    assert_eq!(usage(&store), 2 * BODY.len() as u64);
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    sent(&store, "pending-ownerless");
    assert_eq!(store.recover_attachment_uploads(20, 64, 10000).unwrap(), 2);
    assert_eq!(read(&store, &request(&store, "pending-ownerless")), BODY);
    assert_eq!(read(&store, &request(&store, "confirmed-ownerless")), BODY);
}

/// Recovery advances through a raw indexed page even when every inspected source is ineligible.
#[test]
fn outgoing_recovery_advances_past_received_history_without_scanning_it_all() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "seed");
    for index in 0..100 {
        store
            .record_app_event(&source(&format!("received-{index:03}")))
            .unwrap();
    }
    sent(&store, "zz-outgoing");
    let token = bound(&store, "zz-outgoing");
    assert_eq!(store.recover_attachment_uploads(20, 4, 10000).unwrap(), 0);
    let first_cursor: String = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT recovery_message_id_hex FROM outgoing_attachment_uploads WHERE token=?1",
            [&token],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !first_cursor.is_empty(),
        "zero-eligible pages still advance"
    );
    assert!(
        first_cursor.as_str() < "received-010",
        "at most four raw identities were inspected"
    );
    let mut recovered = 0;
    for _ in 0..30 {
        recovered += store.recover_attachment_uploads(20, 4, 10000).unwrap();
    }
    assert_eq!(recovered, 1);
    assert_eq!(read(&store, &request(&store, "zz-outgoing")), BODY);
    let plan:String=store.lock().unwrap().query_row("EXPLAIN QUERY PLAN SELECT message_id_hex,attachment_index FROM attachment_history WHERE group_id_hex=?1 AND source_epoch=3 AND slot_json=?2 AND (message_id_hex,attachment_index)>(?3,0) ORDER BY message_id_hex,attachment_index LIMIT 4",params![GROUP,serde_json::to_string(&selected("zz-outgoing").slot).unwrap(),"received-000"],|row|row.get(3)).unwrap();
    assert!(
        plan.contains("idx_attachment_history_outgoing_slot"),
        "descriptor paging must use the ordered seek index: {plan}"
    );
}

/// Interleaved descriptors must not lose owners when a shared page reaches its source limit.
#[test]
fn outgoing_recovery_preserves_interleaved_descriptor_fairness() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store, "seed");
    let mut slots = Vec::new();
    for (name, ids) in [
        ("first", ["a", "b", "c", "z"]),
        ("second", ["d", "e", "f", "y"]),
    ] {
        for id in ids {
            let mut event = source(id);
            event.direction = "sent".into();
            event.tags[0].push(format!("filename {name}"));
            store.record_app_event(&event).unwrap();
            if id == ids[0] {
                slots.push((serde_json::to_value(&event.tags[0]).unwrap(), digest()));
            }
        }
    }
    let tokens = store
        .stage_attachment_uploads(GROUP, 3, &[BODY, BODY], 11, 10000)
        .unwrap();
    store.bind_attachment_uploads(&tokens, &slots).unwrap();
    for now in 12..28 {
        assert_eq!(
            store
                .recover_attachment_uploads(now, 2, 2 * BODY.len() as u64)
                .unwrap(),
            0
        );
    }
    let count: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM attachment_acquisition WHERE state=4 AND body_completed=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 8,
        "every blocked owner must be visited; cursor advancement must not discard unselected candidates"
    );
    for now in 28..44 {
        store.recover_attachment_uploads(now, 2, 10000).unwrap();
    }
    for id in ["a", "b", "c", "d", "e", "f", "y", "z"] {
        let asset = store
            .retained_attachment_asset(GROUP, id, &format!("source-{id}"), 0, 44)
            .unwrap()
            .unwrap();
        assert_eq!(read(&store, &asset.reference), BODY);
    }
}

/// Host-managed automatic demand, queued candidates and final HTTP admission all prefer staged bytes.
#[test]
fn outgoing_staging_blocks_all_network_routes_after_promotion_fault() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    sent(&store, "managed");
    staged(&store, "managed");
    sql(
        &store,
        "CREATE TRIGGER fail_bytes BEFORE INSERT ON retained_attachment_bytes BEGIN SELECT RAISE(ABORT,'generated promotion fault'); END;",
    );
    assert!(
        store
            .promote_attachment_uploads(GROUP, "managed", 12, 10000)
            .is_err()
    );
    let policy = AttachmentDownloadPolicy {
        automatic: true,
        retained_bytes: 10000,
        disk_reserve: 0,
        transfer_limit: 1024,
    };
    let (_, admitted) = store
        .request_automatic_attachment(GROUP, &selected("managed"), digest(), 12, (&policy, true))
        .unwrap();
    assert!(
        !admitted,
        "screen rendering must not reacquire staged outgoing bytes"
    );
    let asset = request(&store, "managed");
    store.promote_attachment_demand(&asset, 12).unwrap();
    assert!(
        store
            .attachment_transfer_candidates(12, 32, true)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .attachment_transfer_candidates(12, 32, false)
            .unwrap()
            .is_empty()
    );
    let job = store
        .claim_attachment_acquisition(&asset, 12, 100)
        .unwrap()
        .unwrap();
    assert!(
        !store.begin_attachment_network_attempt(&job, 12).unwrap(),
        "final race fence must reject HTTP even for an already claimed explicit job"
    );
    sql(&store, "DROP TRIGGER fail_bytes");
    assert_eq!(store.recover_attachment_uploads(13, 64, 10000).unwrap(), 1);
    assert_eq!(read(&store, &asset), BODY);
}
