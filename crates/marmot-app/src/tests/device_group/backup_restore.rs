//! Manual backup reader composition. Archive crypto has its own unit owners;
//! these tests own actual membership, HTTP, persistence and worker lifecycle.

use super::super::history_delivery::add_laptop;
use super::*;
use crate::{BackupRestorePhase, BackupRestoreWords, HistoryImportProvenance};
use cgka_traits::storage::GroupStorage as _;
use std::collections::HashMap;

async fn restore(client: &mut AppClient, words: &Words) -> crate::BackupRestoreStatus {
    client
        .begin_backup_restore(BackupRestoreWords::new(words.phrase.clone()))
        .unwrap();
    while let Some(work) = client.prepare_backup_restore().unwrap() {
        client.finish_backup_restore(work.run().await);
    }
    client.backup_restore_status()
}

/// The first relay completes empty while the pointer-holding relay does
/// not finish. Positive views expose real signed publications from that
/// relay's retained prefix; this fixture supplies no restore/import result.
struct PartialPointerView {
    relay: Arc<ScriptedPushRelayClient>,
    visible: bool,
    any_completed: bool,
}

#[async_trait]
impl transport_nostr::DirectoryRelayFetcher for PartialPointerView {
    async fn fetch_directory_events(
        &self,
        request: transport_nostr::DirectoryFetchRequest,
    ) -> Result<Vec<transport_nostr::DirectoryRelayEventRecord>, String> {
        let mut records = self.relay.fetch_directory_events(request).await?;
        if !self.visible
            || !records.iter().any(|record| {
                record
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.0 == "wss://unfinished-pointer.example")
            })
        {
            records.clear();
        }
        Ok(records)
    }

    async fn fetch_directory_events_with_completion(
        &self,
        request: transport_nostr::DirectoryFetchRequest,
    ) -> Result<transport_nostr::DirectoryFetchOutcome, String> {
        let complete_endpoints: Vec<_> = request
            .endpoints
            .iter()
            .filter(|endpoint| self.any_completed && endpoint.0 == "wss://completed-empty.example")
            .cloned()
            .collect();
        let complete =
            !request.endpoints.is_empty() && complete_endpoints.len() == request.endpoints.len();
        let records = self.fetch_directory_events(request).await?;
        Ok(transport_nostr::DirectoryFetchOutcome {
            records,
            complete,
            complete_endpoints,
        })
    }
}

async fn write_backup(client: &mut AppClient) {
    let pass = client
        .prepare_backup_pass()
        .unwrap()
        .expect("a due writer pass");
    client.finish_backup_pass(pass.run().await).await;
}

fn first_message(client: &AppClient, chat: &GroupId) -> String {
    client
        .export_chat_history(chat, None, HISTORY_BUNDLE_MAX_PLAINTEXT)
        .unwrap()
        .unwrap()
        .bundle
        .events[0]
        .event
        .id
        .clone()
}

/// Incomplete discovery never proves absence, including a positive empty
/// pointer that may have been superseded on the unfinished relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_backup_pointer_views_preserve_the_private_catalog_and_report_partial() {
    let blossom = local_blossom();
    let (mut devices, chat, words) = lone_writer(&blossom).await;
    write_backup(&mut devices.phone).await;
    add_laptop(&mut devices, &chat).await;
    assert_eq!(
        restore(&mut devices.laptop, &words).await.phase,
        BackupRestorePhase::Complete
    );
    assert_eq!(
        devices.laptop.backup_history_availability(&chat).unwrap()[0].backups,
        1
    );
    let account = devices.laptop.app.account_home().account("alice").unwrap();
    let directory = devices.laptop.app.directory();
    let mut entry = directory
        .directory_entry_for_account_id(&account.account_id_hex)
        .unwrap()
        .unwrap_or_else(|| directory.empty_directory_record_for_test(&account.account_id_hex));
    entry.relay_lists.nip65.created_at = unix_now_seconds();
    entry.relay_lists.nip65.relays = vec![
        "wss://completed-empty.example".into(),
        "wss://unfinished-pointer.example".into(),
    ];
    entry.relay_lists.refresh();
    directory.save_directory_entry_for_test(&entry).unwrap();
    let complete_plane = devices.laptop.app.relay_plane.clone();
    for (visible, any_completed, expected) in [
        (false, true, BackupRestorePhase::Unavailable),
        (true, true, BackupRestorePhase::Partial),
        (true, false, BackupRestorePhase::Partial),
    ] {
        devices.laptop.app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
            None,
            devices.relay.clone(),
            Arc::new(PartialPointerView {
                relay: devices.relay.clone(),
                visible,
                any_completed,
            }),
            false,
        );
        let status = restore(&mut devices.laptop, &words).await;
        assert_eq!(status.phase, expected);
        assert_eq!(
            devices.laptop.backup_history_availability(&chat).unwrap()[0].backups,
            1,
            "an unfinished view cannot prune the earlier complete catalog"
        );
        assert!(
            devices.laptop.prepare_backup_restore().unwrap().is_none(),
            "terminal partial/unavailable results release the secret-backed job"
        );
    }
    let at = pointer_event(&devices.relay, &words.public)
        .unwrap()
        .created_at
        + 1;
    publish_pointer_at(
        &devices.phone,
        &devices.relay,
        &words.public,
        Vec::new(),
        at,
    )
    .await;
    assert_eq!(
        restore(&mut devices.laptop, &words).await.phase,
        BackupRestorePhase::Partial
    );
    assert_eq!(
        devices.laptop.backup_history_availability(&chat).unwrap()[0].backups,
        1,
        "a valid but incomplete empty pointer is not authoritative absence"
    );
    devices.laptop.app.relay_plane = complete_plane;
    assert_eq!(
        restore(&mut devices.laptop, &words).await.phase,
        BackupRestorePhase::Complete
    );
    assert!(
        devices
            .laptop
            .backup_history_availability(&chat)
            .unwrap()
            .is_empty(),
        "a completed signed empty pointer can prune its own key's catalog"
    );
}

/// A real writer's archive fills only the reader's current chat. Unknown
/// chats stay metadata; preferences and another current recovery key stay
/// untouched. A later real join after reopen gets a words-again hint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backup_restore_imports_only_current_memberships_and_catalog_survives_a_later_join() {
    let blossom = local_blossom();
    let (mut devices, chat, words) = lone_writer(&blossom).await;
    let first = first_message(&devices.phone, &chat);
    let unknown = devices
        .phone
        .create_group("not joined yet", &[])
        .await
        .unwrap();
    let unknown_message = send_text(&mut devices.phone, &unknown, "history for later").await;
    devices
        .phone_app
        .set_chat_pinned("alice", &hex::encode(chat.as_slice()), true)
        .unwrap();
    // A standalone writer may retain small state from an earlier link.
    // Record real local settings through the storage sync owner; the app's
    // live DG broadcaster correctly does nothing without a device group.
    let writer_state = storage(&devices.phone_app);
    writer_state.start_small_state().unwrap();
    let account = devices.phone_app.account_home().account("alice").unwrap();
    writer_state
        .sync_small_state(
            &account.account_id_hex,
            &[],
            &crate::small_state::SmallStateMergeRule,
            &MarmotApp::chat_list_mention_classifier(&account.account_id_hex),
        )
        .unwrap();
    assert!(!writer_state.small_state_items().unwrap().is_empty());
    write_backup(&mut devices.phone).await;
    let entries = pointer(&devices.relay, &words.public);
    assert_eq!(entries.len(), 1);
    let (_, index) = read_backup(&blossom, &entries[0], &words.public);
    let skipped = index
        .chats
        .iter()
        .find(|entry| entry.chat == hex::encode(unknown.as_slice()))
        .unwrap()
        .blobs[0]
        .sha256
        .clone();
    let small = index
        .small_state
        .as_ref()
        .expect("the writer includes small state")
        .sha256
        .clone();
    add_laptop(&mut devices, &chat).await;
    assert!(devices.laptop.runtime.own_leaf_index(&chat).is_ok());
    let current_words = confirm_words(&mut devices.laptop).await;
    assert_ne!(current_words.public, words.public);
    let reader = storage(&devices.laptop_app);
    assert!(
        reader
            .timeline_message(&hex::encode(chat.as_slice()), &first)
            .unwrap()
            .is_none()
    );
    let before_state = reader.small_state_items().unwrap();
    let before_key = reader.kept_recovery_key().unwrap();
    let before_pin = devices.laptop.runtime.epoch_pin(&chat).unwrap();
    let unrelated = devices
        .laptop
        .create_group("not in the archive", &[])
        .await
        .unwrap();
    let published = devices.relay.published_event_ids();
    drop(devices.laptop);
    let plane = MarmotRelayPlane::new(None, devices.relay.clone());
    devices.laptop = devices
        .laptop_app
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    assert!(
        devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&chat)
    );
    assert!(
        devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&unrelated)
    );
    let status = restore(&mut devices.laptop, &words).await;
    assert!(
        !devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&chat)
    );
    assert!(
        devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&unrelated),
        "restore hydrates indexed current candidates, not an account-wide barrier"
    );
    assert_eq!(status.phase, BackupRestorePhase::Complete);
    assert_eq!(status.imported_events, 1);
    let added = reader
        .timeline_message(&hex::encode(chat.as_slice()), &first)
        .unwrap()
        .unwrap();
    assert_eq!(added.plaintext, "before the backup");
    assert_eq!(added.source_message_id_hex, None);
    assert!(matches!(
        reader
            .app_event_import_provenance(&hex::encode(chat.as_slice()), &first)
            .unwrap(),
        Some(HistoryImportProvenance::Backup(_))
    ));
    assert_eq!(reader.small_state_items().unwrap(), before_state);
    assert_eq!(reader.kept_recovery_key().unwrap(), before_key);
    assert_eq!(devices.laptop.runtime.epoch_pin(&chat).unwrap(), before_pin);
    assert_eq!(
        devices.relay.published_event_ids(),
        published,
        "restore publishes nothing"
    );
    assert!(matches!(
        devices
            .laptop_app
            .account_storage("alice")
            .unwrap()
            .get_group(&unknown),
        Err(cgka_traits::storage::StorageError::NotFound)
    ));
    assert!(devices.laptop.state_group_record(&unknown).is_none());
    assert!(
        devices
            .laptop
            .backup_history_availability(&unknown)
            .unwrap()
            .is_empty()
    );
    assert!(!blossom.reads.lock().unwrap().contains(&skipped));
    assert!(!blossom.reads.lock().unwrap().contains(&small));
    assert!(blossom.deleters.lock().unwrap().is_empty());

    // Reopen fresh database connections, not only the AppClient: catalog
    // and provenance survive, while no restore secret/job resumes at open.
    drop(devices.laptop);
    devices.laptop_app.close_storage().unwrap();
    let reopened = device_group_app_at(&devices._dirs[1], devices.relay.clone());
    let plane = MarmotRelayPlane::new(None, devices.relay.clone());
    devices.laptop = reopened
        .local_client_with_relay_plane_and_hydration("alice", &plane, None, true, None)
        .await
        .unwrap();
    devices.laptop_app = reopened;
    assert!(
        devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&chat)
    );
    assert_eq!(
        devices
            .laptop
            .backup_history_availability(&chat)
            .unwrap()
            .len(),
        1,
        "a current cold chat still exposes its persisted private availability hint"
    );
    assert!(
        devices
            .laptop
            .runtime
            .unhydrated_group_ids()
            .contains(&unrelated)
    );
    let reader = storage(&devices.laptop_app);
    assert_eq!(
        devices.laptop.backup_restore_status().phase,
        BackupRestorePhase::Idle
    );
    assert!(devices.laptop.prepare_backup_restore().unwrap().is_none());
    let mut changes = devices.laptop.watch_backup_restore();
    let revision = changes.snapshot().revision;
    add_laptop(&mut devices, &unknown).await;
    devices.laptop.publish_backup_restore_availability();
    assert!(changes.changed().await.unwrap().revision > revision);
    let availability = devices
        .laptop
        .backup_history_availability(&unknown)
        .unwrap();
    assert_eq!(availability.len(), 1);
    assert_eq!(availability[0].recovery_public_key.as_slice(), words.public);
    assert!(
        reader
            .timeline_message(&hex::encode(unknown.as_slice()), &unknown_message)
            .unwrap()
            .is_none()
    );
    let repeated = restore(&mut devices.laptop, &words).await;
    assert_eq!(repeated.phase, BackupRestorePhase::Complete);
    assert_eq!(
        repeated.imported_events, 1,
        "only the later joined chat was missing"
    );
    assert_eq!(
        reader
            .timeline_message(&hex::encode(unknown.as_slice()), &unknown_message)
            .unwrap()
            .unwrap()
            .plaintext,
        "history for later"
    );
}

async fn remove_reader_leaf(devices: &mut Devices, chat: &GroupId) {
    let key = devices.laptop.runtime.own_signature_key();
    let effects = devices
        .phone
        .runtime
        .send(SendIntent::RemoveOwnAccountDevices {
            group_id: chat.clone(),
            leaf_signature_keys: vec![key],
        })
        .await
        .unwrap();
    devices
        .phone
        .observe_drained_session_events(&effects)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            deliver_all(&mut devices.laptop, &devices.relay).await;
            devices.laptop.sync().await.unwrap();
            for group in devices.laptop.take_pending_convergence_groups() {
                devices
                    .laptop
                    .advance_convergence_with_projection_progress_and_yield(
                        &group,
                        None,
                        std::future::pending(),
                    )
                    .await
                    .unwrap();
            }
            if devices.laptop.runtime.group_record(chat).unwrap().removed {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the actual removal becomes canonical on its receiver");
    let record = devices.laptop.runtime.group_record(chat).unwrap();
    assert!(record.removed);
    assert!(
        !record.members.is_empty(),
        "the account still has its other device"
    );
}

/// A selected archive is not permission: a real peer removes this exact
/// device while another account-device remains, both before HTTP admission
/// and while a different blob is held at the server. Neither row is restored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn losing_own_leaf_before_fetch_or_before_apply_prevents_backup_history() {
    let blossom = local_blossom();
    let (mut devices, one, words) = lone_writer(&blossom).await;
    let two = devices
        .phone
        .create_group("second current chat", &[])
        .await
        .unwrap();
    send_text(&mut devices.phone, &two, "old second message").await;
    let messages = HashMap::from([
        (one.clone(), first_message(&devices.phone, &one)),
        (two.clone(), first_message(&devices.phone, &two)),
    ]);
    write_backup(&mut devices.phone).await;
    let entries = pointer(&devices.relay, &words.public);
    let (_, index) = read_backup(&blossom, &entries[0], &words.public);
    let ordered = index
        .blobs()
        .map(|(_, chat, blob)| {
            (
                GroupId::new(hex::decode(&chat.chat).unwrap()),
                blob.sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(ordered.len(), 2);
    add_laptop(&mut devices, &one).await;
    add_laptop(&mut devices, &two).await;
    devices
        .laptop
        .begin_backup_restore(BackupRestoreWords::new(words.phrase.clone()))
        .unwrap();
    // The catalog becomes visible only after a real head has been read and
    // accepted, before the serialized worker admits its next content fetch.
    while devices
        .laptop
        .backup_history_availability(&one)
        .unwrap()
        .is_empty()
    {
        let work = devices.laptop.prepare_backup_restore().unwrap().unwrap();
        devices.laptop.finish_backup_restore(work.run().await);
    }
    assert!(!blossom.reads.lock().unwrap().contains(&ordered[0].1));
    remove_reader_leaf(&mut devices, &ordered[0].0).await;
    let mut hold = blossom.hold_get(&ordered[1].1);
    let work = devices
        .laptop
        .prepare_backup_restore()
        .unwrap()
        .expect("the other current chat still progresses");
    let mut task = tokio::spawn(work.run());
    tokio::time::timeout(Duration::from_secs(30),async {
        tokio::select! {
            _=hold.entered()=>{},
            result=&mut task=> {
                drop(result.unwrap());
                assert!(!blossom.reads.lock().unwrap().contains(&ordered[0].1),"must not fetch a chat after this device lost its leaf");
                panic!("the still-current chat should be waiting at its actual GET");
            }
        }
    }).await.expect("the actual second GET enters its barrier");
    assert!(!blossom.reads.lock().unwrap().contains(&ordered[0].1));
    remove_reader_leaf(&mut devices, &ordered[1].0).await;
    hold.release();
    devices.laptop.finish_backup_restore(task.await.unwrap());
    let status = devices.laptop.backup_restore_status();
    assert_eq!(status.phase, BackupRestorePhase::Partial);
    assert_eq!(
        status.imported_events, 0,
        "a device with no current leaf imports no history"
    );
    assert_eq!(status.skipped_bundles, 2);
    // Finishing the final result releases its secrets immediately; another
    // media credit/prepare call is not needed to complete the operation.
    assert!(devices.laptop.prepare_backup_restore().unwrap().is_none());
    let reader = storage(&devices.laptop_app);
    for (chat, id) in messages {
        assert!(
            reader
                .timeline_message(&hex::encode(chat.as_slice()), &id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reader
                .app_event_import_provenance(&hex::encode(chat.as_slice()), &id)
                .unwrap(),
            None
        );
    }
}

/// Manual restore is worker-owned, not an HTTP future's database lease.
/// Cancelling keeps its committed prefix; shutting down during a later
/// explicit retry releases the root and never resumes secrets on reopen.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_backup_restore_cancels_and_closes_while_a_blob_is_held() {
    let blossom = local_blossom();
    let (mut devices, one, words) = lone_writer(&blossom).await;
    let two = devices
        .phone
        .create_group("second chat", &[])
        .await
        .unwrap();
    send_text(&mut devices.phone, &two, "second history").await;
    write_backup(&mut devices.phone).await;
    let entries = pointer(&devices.relay, &words.public);
    let (_, index) = read_backup(&blossom, &entries[0], &words.public);
    let ordered = index
        .blobs()
        .map(|(_, chat, blob)| {
            (
                GroupId::new(hex::decode(&chat.chat).unwrap()),
                blob.sha256.clone(),
            )
        })
        .collect::<Vec<_>>();
    let ids = HashMap::from([
        (one.clone(), first_message(&devices.phone, &one)),
        (two.clone(), first_message(&devices.phone, &two)),
    ]);
    add_laptop(&mut devices, &one).await;
    add_laptop(&mut devices, &two).await;
    // A known cancellation wins before a prepared content future starts
    // I/O. This observes the actual GET log, not a deadline or task counter.
    let cancelled = devices
        .laptop
        .begin_backup_restore(BackupRestoreWords::new(words.phrase.clone()))
        .unwrap()
        .operation
        .unwrap();
    while devices
        .laptop
        .backup_history_availability(&one)
        .unwrap()
        .is_empty()
    {
        let work = devices.laptop.prepare_backup_restore().unwrap().unwrap();
        devices.laptop.finish_backup_restore(work.run().await);
    }
    let cancelled_work = devices.laptop.prepare_backup_restore().unwrap().unwrap();
    let reads_before_cancelled_work = blossom.reads.lock().unwrap().len();
    assert!(devices.laptop.cancel_backup_restore(cancelled));
    devices
        .laptop
        .finish_backup_restore(cancelled_work.run().await);
    assert_eq!(
        blossom.reads.lock().unwrap().len(),
        reads_before_cancelled_work,
        "a prepared content work starts no GET after its operation was cancelled"
    );
    assert_eq!(
        devices.laptop.backup_restore_status().phase,
        BackupRestorePhase::Cancelled
    );
    let before_worker = storage(&devices.laptop_app);
    for (chat, id) in &ids {
        assert!(
            before_worker
                .timeline_message(&hex::encode(chat.as_slice()), id)
                .unwrap()
                .is_none(),
            "cancelled prepared content imports nothing"
        );
    }
    // Ordinary encrypted-media downloads share the worker's HTTP credits.
    let media_chat = devices
        .laptop
        .create_group("media capacity", &[])
        .await
        .unwrap();
    let uploaded = devices
        .laptop
        .upload_media(
            &media_chat,
            MediaUploadRequest {
                attachments: vec![MediaUploadAttachmentRequest {
                    file_name: "ordinary.txt".into(),
                    media_type: "text/plain".into(),
                    plaintext: b"ordinary transfer".to_vec(),
                    dim: None,
                    thumbhash: None,
                }],
                caption: None,
                send: false,
                blossom_server: Some(blossom.url.clone()),
                message_tags: Vec::new(),
            },
        )
        .await
        .unwrap();
    let media_reference = uploaded.attachments[0].reference.clone();
    let Devices {
        _dirs,
        relay,
        laptop_app,
        laptop,
        ..
    } = devices;
    drop(laptop);
    let root = laptop_app.account_home().root().to_path_buf();
    let reader = storage(&laptop_app);
    let runtime = MarmotAppRuntime::new(laptop_app.clone());
    runtime.reconcile_accounts().await.unwrap();
    let mut watch = runtime.watch_backup_restore("alice").await.unwrap();
    let mut media_holds = Vec::new();
    let mut downloads = Vec::new();
    for _ in 0..3 {
        let mut held = blossom.hold_get(&media_reference.ciphertext_sha256);
        let download_runtime = runtime.clone();
        let group = media_chat.clone();
        let reference = media_reference.clone();
        downloads.push(tokio::spawn(async move {
            download_runtime
                .download_media("alice", &group, reference)
                .await
        }));
        tokio::time::timeout(Duration::from_secs(5), held.entered())
            .await
            .unwrap();
        media_holds.push(held);
    }
    let mut hold = blossom.hold_get(&ordered[1].1);
    let first = runtime
        .begin_backup_restore("alice", BackupRestoreWords::new(words.phrase.clone()))
        .await
        .unwrap()
        .operation
        .unwrap();
    assert_eq!(
        runtime.backup_restore_status("alice").await.unwrap().phase,
        BackupRestorePhase::Discovering,
        "three ordinary transfers reserve the background lane"
    );
    media_holds.remove(0).release();
    assert_eq!(
        downloads.remove(0).await.unwrap().unwrap().plaintext,
        b"ordinary transfer"
    );
    tokio::time::timeout(Duration::from_secs(5), hold.entered())
        .await
        .expect("returning ordinary media capacity resumes restore without a maintenance tick");
    for held in media_holds {
        held.release();
    }
    for download in downloads {
        assert_eq!(
            download.await.unwrap().unwrap().plaintext,
            b"ordinary transfer"
        );
    }
    assert!(
        reader
            .timeline_message(&hex::encode(ordered[0].0.as_slice()), &ids[&ordered[0].0])
            .unwrap()
            .is_some()
    );
    assert!(
        reader
            .timeline_message(&hex::encode(ordered[1].0.as_slice()), &ids[&ordered[1].0])
            .unwrap()
            .is_none()
    );
    assert_eq!(
        runtime
            .backup_restore_status("alice")
            .await
            .unwrap()
            .imported_events,
        1
    );
    assert!(runtime.cancel_backup_restore("alice", first).await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        while watch.changed().await.unwrap().phase != BackupRestorePhase::Cancelled {}
    })
    .await
    .expect("cancellation publishes without waiting for HTTP");
    // Keep the cancelled response held: the next explicit operation must
    // progress without waiting for its predecessor's HTTP response.
    // A stale UI action must not cancel this next explicit words-again job.
    let mut held_retry = blossom.hold_get(&ordered[1].1);
    let second = runtime
        .begin_backup_restore("alice", BackupRestoreWords::new(words.phrase.clone()))
        .await
        .unwrap()
        .operation
        .unwrap();
    assert_ne!(first, second);
    assert!(!runtime.cancel_backup_restore("alice", first).await.unwrap());
    tokio::time::timeout(Duration::from_secs(30), held_retry.entered())
        .await
        .unwrap();
    hold.release();
    assert_eq!(
        runtime
            .backup_restore_status("alice")
            .await
            .unwrap()
            .imported_events,
        0,
        "the committed prefix is not imported twice"
    );
    tokio::time::timeout(Duration::from_secs(10), runtime.shutdown_and_close())
        .await
        .expect("a held HTTP read must not retain the account/root lease")
        .unwrap();
    assert!(laptop_app.storage_is_closed());
    drop(
        crate::MarmotRootRuntimeLease::try_acquire(&root)
            .expect("the root lease is released while HTTP is still held"),
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while watch.changed().await.is_ok() {}
    })
    .await
    .expect("a surviving watch owns neither the worker nor its secrets");
    held_retry.release();
    let reopened = device_group_app_at(&_dirs[1], relay);
    let reopened_storage = storage(&reopened);
    assert!(
        reopened_storage
            .timeline_message(&hex::encode(ordered[0].0.as_slice()), &ids[&ordered[0].0])
            .unwrap()
            .is_some()
    );
    assert!(
        reopened_storage
            .timeline_message(&hex::encode(ordered[1].0.as_slice()), &ids[&ordered[1].0])
            .unwrap()
            .is_none()
    );
    let reopened_runtime = MarmotAppRuntime::new(reopened);
    reopened_runtime.reconcile_accounts().await.unwrap();
    assert_eq!(
        reopened_runtime
            .backup_restore_status("alice")
            .await
            .unwrap()
            .phase,
        BackupRestorePhase::Idle
    );
    reopened_runtime.shutdown_and_close().await.unwrap();
}

/// Every listed archive matters: the writer may have since forgotten a
/// chat that this reader still holds. A missing older blob leaves a partial
/// result with its newer committed prefix; only a manual retry fills it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_partial_backup_restore_keeps_its_prefix_and_retries_older_unique_history_manually() {
    let blossom = local_blossom();
    let (mut devices, older_chat, words) = lone_writer(&blossom).await;
    let older_event = first_message(&devices.phone, &older_chat);
    write_backup(&mut devices.phone).await;
    let original = pointer(&devices.relay, &words.public).remove(0);
    let (head, mut old_index) = read_backup(&blossom, &original, &words.public);
    let older_blob = old_index.chats[0].blobs[0].sha256.clone();
    // Date the complete archive consistently to exercise the writer's daily
    // rule without a clock seam. A fresh id gives the resealed index a fresh
    // derived key; no fixed AEAD key/nonce pair is reused for changed bytes.
    old_index.written_at -= 2 * DAY;
    let key_bytes = zeroize::Zeroizing::new(opened_archive_key(&head, &words));
    let key = ArchiveKey::from_opened(&key_bytes).unwrap();
    let older_id = crate::backup_archive::new_backup_id();
    let old_head = BackupHead::seal(older_id, &key, &words.public, &old_index)
        .unwrap()
        .encode();
    let old_hash = hex::encode(Sha256::digest(&old_head));
    let old_entry = PointerEntry::new(
        &older_id,
        old_index.written_at,
        crate::backup_archive::BlobLocator {
            sha256: old_hash.clone(),
            size: old_head.len() as u64,
            server: blossom.url.clone(),
        },
    );
    blossom.blobs.lock().unwrap().insert(old_hash, old_head);
    publish_pointer(
        &devices.phone,
        &devices.relay,
        &words.public,
        vec![old_entry.clone()],
    )
    .await;
    add_laptop(&mut devices, &older_chat).await;
    assert!(devices.phone.forget_group_local(&older_chat).await.unwrap());
    let newer_chat = devices.phone.create_group("newer chat", &[]).await.unwrap();
    let newer_event = send_text(&mut devices.phone, &newer_chat, "newer available history").await;
    due_now(&devices.phone);
    write_backup(&mut devices.phone).await;
    let listed = pointer(&devices.relay, &words.public);
    assert_eq!(listed.len(), 2);
    let (_, newer_index) = read_backup(&blossom, &listed[0], &words.public);
    assert_eq!(newer_index.chats.len(), 1);
    assert_eq!(
        newer_index.chats[0].chat,
        hex::encode(newer_chat.as_slice())
    );
    assert_eq!(listed[1], old_entry);
    add_laptop(&mut devices, &newer_chat).await;
    let missing = blossom.blobs.lock().unwrap().remove(&older_blob).unwrap();
    let status = restore(&mut devices.laptop, &words).await;
    assert_eq!(status.phase, BackupRestorePhase::Partial);
    assert_eq!(status.failed_archives, 0);
    assert_eq!(status.failed_bundles, 1);
    assert_eq!(status.imported_events, 1);
    let reader = storage(&devices.laptop_app);
    assert_eq!(
        reader
            .timeline_message(&hex::encode(newer_chat.as_slice()), &newer_event)
            .unwrap()
            .unwrap()
            .plaintext,
        "newer available history"
    );
    assert!(
        reader
            .timeline_message(&hex::encode(older_chat.as_slice()), &older_event)
            .unwrap()
            .is_none()
    );
    assert!(blossom.reads.lock().unwrap().contains(&older_blob));
    blossom.blobs.lock().unwrap().insert(older_blob, missing);
    assert!(
        devices.laptop.prepare_backup_restore().unwrap().is_none(),
        "a failed step does not keep words for an automatic retry"
    );
    assert!(
        reader
            .timeline_message(&hex::encode(older_chat.as_slice()), &older_event)
            .unwrap()
            .is_none()
    );
    let retried = restore(&mut devices.laptop, &words).await;
    assert_eq!(retried.phase, BackupRestorePhase::Complete);
    assert_eq!(
        retried.imported_events, 1,
        "the newer committed prefix is not imported twice"
    );
    let row = reader
        .timeline_message(&hex::encode(older_chat.as_slice()), &older_event)
        .unwrap()
        .unwrap();
    assert_eq!(row.plaintext, "before the backup");
    assert!(
        matches!(row.history_import_provenance, Some(HistoryImportProvenance::Backup(source)) if source.backup_id == older_id)
    );
}
