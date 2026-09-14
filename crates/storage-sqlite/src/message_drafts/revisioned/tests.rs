use super::*;
#[test]
fn legacy_save_delete_recreate_never_reuses_a_draft_revision() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    let group = "11".repeat(16);
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
            [&group],
        )
        .unwrap();
    let empty = store.selected_message_draft(&group).unwrap();
    store
        .save_message_draft(&group, "first", None, &[])
        .unwrap();
    let first = store.selected_message_draft(&group).unwrap();
    store
        .save_message_draft(&group, "second", None, &[])
        .unwrap();
    let second = store.selected_message_draft(&group).unwrap();
    store.delete_message_draft(&group).unwrap();
    let deleted = store.selected_message_draft(&group).unwrap();
    store
        .save_message_draft(&group, "first", None, &[])
        .unwrap();
    let recreated = store.selected_message_draft(&group).unwrap();
    let versions = [
        empty.revision,
        first.revision,
        second.revision,
        deleted.revision,
        recreated.revision,
    ];
    for (i, a) in versions.iter().enumerate() {
        assert!(versions[i + 1..].iter().all(|b| a != b));
    }
}

use cgka_traits::storage::{
    GroupStorage, OutboundIntentStorage, QueuedOutboundIntent, StorageProvider,
};
use cgka_traits::{GroupId, MessageId, SendIntent};
const GROUP: &str = "22222222222222222222222222222222";
fn seed(store: &SqliteAccountStorage) {
    store
        .put_group(&crate::storage::test_support::sample_group(
            GroupId::new(hex::decode(GROUP).unwrap()),
            0,
            0,
        ))
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
            [GROUP],
        )
        .unwrap();
}
fn queued(payload: &[u8]) -> QueuedOutboundIntent {
    let group_id = GroupId::new(hex::decode(GROUP).unwrap());
    QueuedOutboundIntent {
        id: MessageId::new(vec![3; 32]),
        group_id: group_id.clone(),
        intent: SendIntent::AppMessage {
            group_id,
            payload: payload.to_vec(),
            expected_epoch: None,
        },
        created_at_ms: 1,
        reissue_attempts: 0,
    }
}
fn attachment() -> StoredMessageDraftAttachment {
    StoredMessageDraftAttachment {
        id: "one".into(),
        file_name: "voice.m4a".into(),
        media_type: "audio/mp4".into(),
        plaintext: vec![42; 1024 * 1024],
        dim: None,
        thumbhash: Some("hash".into()),
        duration_seconds: Some(3.5),
        waveform_samples: vec![0.2, 0.7],
    }
}
#[test]
fn conditional_mutations_reject_stale_cross_store_and_failed_attachment_edits() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let initial = store.selected_message_draft(GROUP).unwrap();
    let first = store
        .save_message_draft_if_revision(&initial.revision, "first", None, &[])
        .unwrap();
    assert!(matches!(
        store.save_message_draft_if_revision(&initial.revision, "lost edit", None, &[]),
        Err(MessageDraftRevisionError::Conflict)
    ));
    assert!(matches!(
        store.clear_message_draft_if_revision(&initial.revision),
        Err(MessageDraftRevisionError::Conflict)
    ));
    let other = SqliteAccountStorage::in_memory().unwrap();
    seed(&other);
    assert!(matches!(
        other.clear_message_draft_if_revision(&first.revision),
        Err(MessageDraftRevisionError::Conflict)
    ));
    assert!(
        store
            .save_message_draft_if_revision(
                &first.revision,
                "broken",
                None,
                &[attachment(), attachment()]
            )
            .is_err()
    );
    assert_eq!(
        store.selected_message_draft(GROUP).unwrap().revision,
        first.revision
    );
    let empty = store
        .clear_message_draft_if_revision(&first.revision)
        .unwrap();
    assert!(empty.draft.is_none() && empty.revision != first.revision);
    store
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM account_groups WHERE group_id_hex = ?1",
            [GROUP],
        )
        .unwrap();
    seed(&store);
    assert!(store.selected_message_draft(GROUP).unwrap().revision != initial.revision);
}
#[test]
fn selected_metadata_and_keyed_bytes_are_revision_coherent_and_read_only() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let media = attachment();
    store
        .save_message_draft(GROUP, "voice", None, std::slice::from_ref(&media))
        .unwrap();
    let changes = store.lock().unwrap().total_changes();
    store
        .lock()
        .unwrap()
        .execute_batch("PRAGMA query_only=ON")
        .unwrap();
    let selected = store.selected_message_draft(GROUP).unwrap();
    let metadata = &selected.draft.as_ref().unwrap().media_attachments[0];
    assert_eq!(metadata.plaintext_size, media.plaintext.len() as u64);
    assert_eq!(metadata.waveform_samples, media.waveform_samples);
    assert_eq!(metadata.duration_seconds, media.duration_seconds);
    assert_eq!(
        store
            .message_draft_attachment_if_revision(&selected.revision, "one")
            .unwrap(),
        Some(media.plaintext)
    );
    assert!(
        store
            .message_draft_attachment_if_revision(&selected.revision, "missing")
            .unwrap()
            .is_none()
    );
    assert_eq!(store.lock().unwrap().total_changes(), changes);
    store
        .lock()
        .unwrap()
        .execute_batch("PRAGMA query_only=OFF")
        .unwrap();
    store.save_message_draft(GROUP, "new", None, &[]).unwrap();
    assert!(matches!(
        store.message_draft_attachment_if_revision(&selected.revision, "one"),
        Err(MessageDraftRevisionError::Conflict)
    ));
}
#[test]
fn accepted_queue_and_draft_clear_commit_together_and_rollback_without_wakeup() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    store
        .save_message_draft(GROUP, "send", None, &[attachment()])
        .unwrap();
    let selected = store.selected_message_draft(GROUP).unwrap();
    let notifications = Arc::new(AtomicUsize::new(0));
    let counter = notifications.clone();
    store.set_message_draft_commit_observer(Arc::new(move |group| {
        assert_eq!(group, GROUP);
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    store
        .stage_message_draft_submission(&selected.revision, "event", b"payload")
        .unwrap();
    let result: StorageResult<()> = store.with_transaction(|s| {
        s.put_queued_outbound_intent(&queued(b"payload"))?;
        assert!(s.selected_message_draft(GROUP)?.draft.is_none());
        assert_eq!(notifications.load(Ordering::SeqCst), 0);
        Err(StorageError::Backend("rollback".into()))
    });
    assert!(result.is_err());
    assert_eq!(
        store.selected_message_draft(GROUP).unwrap().revision,
        selected.revision
    );
    assert!(
        store
            .list_queued_outbound_intents(&queued(b"payload").group_id)
            .unwrap()
            .is_empty()
    );
    store.lock().unwrap().execute_batch("CREATE TEMP TRIGGER fail_clear BEFORE DELETE ON message_drafts BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    store
        .with_transaction::<_, StorageError, _>(|s| {
            assert!(s.put_queued_outbound_intent(&queued(b"payload")).is_err());
            Ok(())
        })
        .unwrap();
    assert!(
        store
            .list_queued_outbound_intents(&queued(b"payload").group_id)
            .unwrap()
            .is_empty()
    );
    assert!(store.selected_message_draft(GROUP).unwrap().draft.is_some());
    store
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_clear")
        .unwrap();
    store
        .with_transaction::<_, StorageError, _>(|s| {
            s.put_queued_outbound_intent(&queued(b"payload"))?;
            assert_eq!(notifications.load(Ordering::SeqCst), 0);
            Ok(())
        })
        .unwrap();
    assert!(store.selected_message_draft(GROUP).unwrap().draft.is_none());
    assert_eq!(notifications.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .list_queued_outbound_intents(&queued(b"payload").group_id)
            .unwrap()
            .len(),
        1
    );
    // Delivery failure or replay cannot resurrect the composer or notify twice.
    store
        .put_queued_outbound_intent(&queued(b"payload"))
        .unwrap();
    store
        .delete_queued_outbound_intent(&queued(b"payload").id)
        .unwrap();
    assert!(store.selected_message_draft(GROUP).unwrap().draft.is_none());
    assert_eq!(notifications.load(Ordering::SeqCst), 1);
}
#[test]
fn mismatched_acceptance_cancellation_and_late_acceptance_keep_newer_drafts() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    store.save_message_draft(GROUP, "old", None, &[]).unwrap();
    let old = store.selected_message_draft(GROUP).unwrap();
    store
        .stage_message_draft_submission(&old.revision, "event", b"old")
        .unwrap();
    store
        .put_queued_outbound_intent(&queued(b"different"))
        .unwrap();
    assert_eq!(
        store.selected_message_draft(GROUP).unwrap().revision,
        old.revision
    );
    store
        .cancel_message_draft_submission(&old.revision)
        .unwrap();
    store.put_queued_outbound_intent(&queued(b"old")).unwrap();
    assert_eq!(
        store.selected_message_draft(GROUP).unwrap().revision,
        old.revision
    );
    store
        .stage_message_draft_submission(&old.revision, "event", b"old")
        .unwrap();
    let new = store
        .save_message_draft_if_revision(&old.revision, "new", None, &[])
        .unwrap();
    store.put_queued_outbound_intent(&queued(b"old")).unwrap();
    assert_eq!(
        store.selected_message_draft(GROUP).unwrap().revision,
        new.revision
    );
}
#[test]
fn accepted_and_unaccepted_draft_revisions_survive_encrypted_reopen() {
    for accepted in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("draft.sqlite");
        let key = crate::SqlCipherKey::new("ab".repeat(32)).unwrap();
        let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        seed(&store);
        store
            .save_message_draft(GROUP, "retained", None, &[attachment()])
            .unwrap();
        let selected = store.selected_message_draft(GROUP).unwrap();
        store
            .stage_message_draft_submission(&selected.revision, "event", b"payload")
            .unwrap();
        if accepted {
            store
                .put_queued_outbound_intent(&queued(b"payload"))
                .unwrap();
        }
        store.close().unwrap();
        drop(store);
        let reopened = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
        let now = reopened.selected_message_draft(GROUP).unwrap();
        assert_eq!(now.draft.is_none(), accepted);
        assert_eq!(now.revision == selected.revision, !accepted);
        assert_eq!(
            !reopened
                .list_queued_outbound_intents(&queued(b"payload").group_id)
                .unwrap()
                .is_empty(),
            accepted
        );
    }
}

#[test]
fn selected_query_work_ignores_other_drafts_and_attachment_blob_size() {
    use crate::query_work_test_support::measure;
    for count in [200, 20_000] {
        let store = SqliteAccountStorage::in_memory().unwrap();
        seed(&store);
        let mut media = attachment();
        media.plaintext = vec![17; if count == 200 { 1024 } else { 8 * 1024 * 1024 }];
        store
            .save_message_draft(GROUP, "selected", None, &[media])
            .unwrap();
        store.lock().unwrap().execute_batch(&format!("INSERT INTO account_groups(group_id_hex,endpoint,updated_at)
            WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x < {count})
            SELECT printf('other-%08d',x),'',0 FROM n;
            INSERT INTO message_drafts(group_id_hex,content,created_at_ms,updated_at_ms)
                SELECT group_id_hex,'unrelated',0,0 FROM account_groups WHERE group_id_hex != '{GROUP}';")).unwrap();
        let (selected, steps) = measure(&store, || store.selected_message_draft(GROUP).unwrap());
        assert_eq!(selected.draft.unwrap().media_attachments.len(), 1);
        assert!(steps < 500, "{count} unrelated drafts: {steps} VM steps");
    }
}
#[test]
fn revision_exhaustion_fails_without_reusing_tokens_or_changing_draft() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    store
        .save_message_draft(GROUP, "before", None, &[])
        .unwrap();
    let before = store.selected_message_draft(GROUP).unwrap();
    store
        .lock()
        .unwrap()
        .execute(
            "UPDATE message_draft_revision_clock SET revision=?1",
            [i64::MAX],
        )
        .unwrap();
    assert!(
        store
            .save_message_draft_if_revision(&before.revision, "after", None, &[])
            .is_err()
    );
    let after = store.selected_message_draft(GROUP).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(after.draft.unwrap().content, "before");
}

#[test]
fn deferred_wakeups_follow_commit_and_never_leak_from_failed_transactions() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let store = SqliteAccountStorage::in_memory().unwrap();
    let observed = Arc::new(AtomicUsize::new(0));
    let register = |s: &SqliteAccountStorage| {
        let reads = s.clone();
        let observed = observed.clone();
        s.connection.after_commit(move || {
            assert!(reads.lock().unwrap().is_autocommit());
            observed.fetch_add(1, Ordering::SeqCst);
        });
    };
    store
        .with_transaction::<_, StorageError, _>(|s| {
            register(s);
            Ok(())
        })
        .unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: StorageResult<()> = store.with_transaction(|s| {
            register(s);
            panic!("rollback");
        });
    }));
    assert!(panic.is_err());
    store.lock().unwrap().execute_batch("CREATE TABLE wake_parent (id INTEGER PRIMARY KEY);
        CREATE TABLE wake_child (id INTEGER REFERENCES wake_parent(id) DEFERRABLE INITIALLY DEFERRED);").unwrap();
    let failed_commit: StorageResult<()> = store.with_transaction(|s| {
        s.lock()?
            .execute("INSERT INTO wake_child VALUES (1)", [])
            .storage()?;
        register(s);
        Ok(())
    });
    assert!(failed_commit.is_err());
    store
        .with_transaction::<_, StorageError, _>(|_| Ok(()))
        .unwrap();
    assert_eq!(observed.load(Ordering::SeqCst), 1);
}

#[test]
fn selected_draft_debug_redacts_content_identities_and_media_metadata() {
    let store = SqliteAccountStorage::in_memory().unwrap();
    seed(&store);
    let mut media = attachment();
    media.id = "private-attachment-id".into();
    media.file_name = "private-file-name".into();
    store
        .save_message_draft(GROUP, "private-content", Some(&"ab".repeat(32)), &[media])
        .unwrap();
    let selected = store.selected_message_draft(GROUP).unwrap();
    let debug = format!(
        "{selected:?} {:?}",
        selected.draft.as_ref().unwrap().media_attachments
    );
    assert!(debug.contains("revision"));
    assert!(debug.contains("attachment_count"));
    for private in [
        GROUP,
        "private-content",
        &"ab".repeat(32),
        "private-attachment-id",
        "private-file-name",
    ] {
        assert!(!debug.contains(private));
    }
}
