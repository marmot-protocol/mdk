//! File-backed composer draft attachments through the public runtime
//! (mdk#3431): staged once from a host file, kept by id through text saves
//! and a restart, read back in chunks or a handoff, uploaded from MDK's own
//! copy and sent with the draft.
use super::*;
use sha2::{Digest, Sha256};

const RELAY: &str = "wss://relay.example";

fn open_app(dir: &std::path::Path) -> MarmotApp {
    MarmotApp::with_relay_and_config(
        dir,
        RELAY,
        crate::MarmotAppConfig::white_noise().with_allow_loopback_blob_endpoints(true),
    )
    .with_test_relay_client(Arc::new(ScriptedPushRelayClient::default()))
}

async fn group_fixture(app: &MarmotApp) -> GroupId {
    app.client("alice")
        .await
        .unwrap()
        .create_group("file-backed draft", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members")
}

fn file_request(path: &std::path::Path, len: u64) -> crate::MessageDraftAttachmentFileRequest {
    crate::MessageDraftAttachmentFileRequest {
        id: "video".into(),
        source_path: path.to_string_lossy().into_owned(),
        expected_size: Some(len),
        file_name: "clip.mp4".into(),
        // Not canonical: staging stores what the upload will describe.
        media_type: "Video/MP4".into(),
        dim: Some("640x360".into()),
        thumbhash: None,
        duration_seconds: Some(3.5),
        waveform_samples: vec![],
    }
}

/// The staged files the group's draft owns now.
fn draft_files(app: &MarmotApp, group_hex: &str) -> Vec<media_store::FileId> {
    app.account_storage("alice")
        .unwrap()
        .app_storage()
        .message_draft_attachment_files(group_hex)
        .unwrap()
}

/// Whether every one of `files` lost its key row.
fn released(app: &MarmotApp, files: &[media_store::FileId]) -> bool {
    let storage = app.account_storage("alice").unwrap();
    let media = app.account_media_store("alice", &storage).unwrap();
    files
        .iter()
        .all(|file| media.file_state(file).unwrap().is_none())
}

async fn read_all(
    runtime: &MarmotAppRuntime,
    revision: &crate::MessageDraftRevision,
    len: usize,
) -> Vec<u8> {
    let mut copied = Vec::new();
    loop {
        let chunk = runtime
            .read_message_draft_attachment(
                "alice",
                revision.clone(),
                "video".into(),
                copied.len() as u64,
                64 * 1024,
            )
            .await
            .unwrap()
            .expect("the attachment is in the draft");
        if chunk.is_empty() {
            break;
        }
        copied.extend_from_slice(&chunk);
    }
    assert_eq!(copied.len(), len);
    copied
}

/// The acceptance journey: no full-size buffer crosses the runtime boundary
/// after staging, the attachment survives text-only saves and a restart, its
/// digest backs captured-media admission, and `send_message_draft` sends the
/// uploaded references and releases the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_staged_draft_file_survives_saves_and_restart_and_sends_with_the_draft() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = open_app(dir.path());
    let group = group_fixture(&app).await;
    let group_hex = hex::encode(group.as_slice());
    let source_dir = tempfile::tempdir().unwrap();
    let plain = (0..(300 * 1024 + 7))
        .map(|i| (i % 251) as u8)
        .collect::<Vec<_>>();
    let path = source_dir.path().join("pick.mp4");
    std::fs::write(&path, &plain).unwrap();

    let runtime = MarmotAppRuntime::new(app.clone());
    let started = app.selected_message_draft("alice", &group_hex).unwrap();
    let control = Arc::new(crate::MediaFileTransferControl::default());
    let staged = runtime
        .stage_message_draft_attachment_file(
            "alice",
            started.revision.clone(),
            file_request(&path, plain.len() as u64),
            control.clone(),
        )
        .await
        .unwrap();
    assert!(control.processed_bytes() >= plain.len() as u64);
    std::fs::remove_file(&path).unwrap();
    let attachment = &staged.draft.as_ref().unwrap().media_attachments[0];
    assert_eq!(
        (
            attachment.plaintext_size,
            attachment.file_backed,
            attachment.media_type.as_str()
        ),
        (plain.len() as u64, true, "video/mp4")
    );
    assert!(
        matches!(
            app.message_draft_attachment_if_revision("alice", &staged.revision, "video"),
            Err(AppError::InvalidMessageDraft(_))
        ),
        "a file-backed attachment is never hydrated whole"
    );

    let mut revision = staged.revision;
    for caption in ["c", "ca", "caption"] {
        revision = app
            .save_message_draft_inputs_if_revision(
                "alice",
                &revision,
                caption,
                None,
                vec![crate::MessageDraftAttachmentInput::Retained("video".into())],
            )
            .unwrap()
            .revision;
    }
    runtime.shutdown_and_close().await.unwrap();
    drop(app);

    let app = open_app(dir.path());
    let runtime = MarmotAppRuntime::new(app.clone());
    let restored = app.selected_message_draft("alice", &group_hex).unwrap();
    assert_eq!(restored.revision, revision);
    assert_eq!(restored.draft.as_ref().unwrap().content, "caption");
    assert_eq!(read_all(&runtime, &revision, plain.len()).await, plain);
    let handoff = runtime
        .open_message_draft_attachment_handoff(
            "alice",
            revision.clone(),
            "video".into(),
            Arc::new(crate::MediaFileTransferControl::default()),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(&handoff.path).unwrap(), plain);
    runtime
        .release_attachment_handoff(&handoff.lease)
        .await
        .unwrap();

    let (url, puts, server) = crate::client::upload_cleanup_tests::upload_endpoint().await;
    let uploaded = runtime
        .upload_message_draft_attachments(
            "alice",
            revision.clone(),
            vec!["video".into()],
            Some(url),
            Arc::new(crate::MediaFileTransferControl::default()),
        )
        .await
        .unwrap();
    assert_eq!(puts.load(std::sync::atomic::Ordering::SeqCst), 1);
    let references = uploaded
        .attachments
        .into_iter()
        .map(|attachment| attachment.reference)
        .collect::<Vec<_>>();
    assert_eq!(
        references[0].plaintext_sha256,
        hex::encode(Sha256::digest(&plain))
    );
    assert!(
        app.selected_message_draft("alice", &group_hex)
            .unwrap()
            .draft
            .is_some(),
        "uploading keeps the draft and its file"
    );
    let files = draft_files(&app, &group_hex);
    assert_eq!(files.len(), 1);

    // Captured-media admission checks every reference against the draft's
    // plaintext digests, file-backed ones included.
    let mut forged = references.clone();
    forged[0].plaintext_sha256 = hex::encode(Sha256::digest(b"other bytes"));
    assert!(matches!(
        runtime
            .submit_prepared_media_snapshot(
                "alice",
                &group,
                forged,
                Some("caption".into()),
                "forged".into(),
                Some(revision.clone()),
            )
            .await,
        Err(AppError::InvalidMessageDraft(_))
    ));
    runtime
        .send_message_draft("alice", &group, revision, references)
        .await
        .unwrap();
    assert!(
        app.selected_message_draft("alice", &group_hex)
            .unwrap()
            .draft
            .is_none()
    );
    assert!(
        released(&app, &files),
        "sending the draft released its file"
    );
    runtime.shutdown_and_close().await.unwrap();
    server.abort();
}

/// Staging refuses what the draft could never upload before copying it, and
/// a cancelled copy leaves no file, no row and no change to the draft. A
/// save that leaves a staged attachment out keeps it; one that removes it
/// unlinks its file at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staging_refuses_oversize_and_cancelled_copies_and_saves_release_files() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = open_app(dir.path());
    let group = group_fixture(&app).await;
    let group_hex = hex::encode(group.as_slice());
    let runtime = MarmotAppRuntime::new(app.clone());
    let source_dir = tempfile::tempdir().unwrap();
    let media_files = || {
        fn walk(path: &std::path::Path) -> usize {
            std::fs::read_dir(path)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| {
                            if entry.file_type().unwrap().is_dir() {
                                walk(&entry.path())
                            } else {
                                1
                            }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        walk(&app.account_dir("alice").join(media_store::MEDIA_DIRECTORY))
    };
    let initial = app.selected_message_draft("alice", &group_hex).unwrap();

    // Sparse: one byte past the blob limit costs no disk.
    let oversize = source_dir.path().join("oversize.bin");
    let len = crate::MAX_MESSAGE_DRAFT_ATTACHMENT_FILE_BYTES + 1;
    std::fs::File::create(&oversize)
        .unwrap()
        .set_len(len)
        .unwrap();
    let control = Arc::new(crate::MediaFileTransferControl::default());
    assert!(matches!(
        runtime
            .stage_message_draft_attachment_file(
                "alice",
                initial.revision.clone(),
                file_request(&oversize, len),
                control.clone(),
            )
            .await,
        Err(AppError::InvalidEncryptedMedia(_))
    ));
    let mut unsized_request = file_request(&oversize, len);
    unsized_request.expected_size = None;
    assert!(matches!(
        runtime
            .stage_message_draft_attachment_file(
                "alice",
                initial.revision.clone(),
                unsized_request,
                control.clone(),
            )
            .await,
        Err(AppError::InvalidEncryptedMedia(_))
    ));
    let mut unnamed = file_request(&oversize, 1);
    unnamed.file_name = "   ".into();
    std::fs::write(&oversize, b"x").unwrap();
    assert!(
        matches!(
            runtime
                .stage_message_draft_attachment_file(
                    "alice",
                    initial.revision.clone(),
                    unnamed,
                    control.clone(),
                )
                .await,
            Err(AppError::InvalidEncryptedMedia(_))
        ),
        "a name a V1 upload would refuse is refused before copying"
    );
    assert_eq!(control.processed_bytes(), 0, "nothing was copied");

    let large = source_dir.path().join("large.bin");
    let len = 96 * 1024 * 1024u64;
    std::fs::File::create(&large).unwrap().set_len(len).unwrap();
    let control = Arc::new(crate::MediaFileTransferControl::default());
    let staging = tokio::spawn({
        let runtime = runtime.clone();
        let revision = initial.revision.clone();
        let request = file_request(&large, len);
        let control = control.clone();
        async move {
            runtime
                .stage_message_draft_attachment_file("alice", revision, request, control)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        // The copy runs on the blocking pool; yield until it reports bytes.
        while control.processed_bytes() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    control.cancel();
    assert!(staging.await.unwrap().is_err());
    assert!(control.processed_bytes() < len, "cancelled mid-copy");
    let after = app.selected_message_draft("alice", &group_hex).unwrap();
    assert_eq!(
        (after.revision, after.draft),
        (initial.revision.clone(), None),
        "a cancelled stage leaves the draft as it was"
    );
    assert_eq!(media_files(), 0, "a cancelled stage leaves no file");

    let small = source_dir.path().join("small.bin");
    std::fs::write(&small, b"small body").unwrap();
    let staged = runtime
        .stage_message_draft_attachment_file(
            "alice",
            initial.revision.clone(),
            file_request(&small, 10),
            Arc::new(crate::MediaFileTransferControl::default()),
        )
        .await
        .unwrap();
    assert_eq!(media_files(), 1);
    let files = draft_files(&app, &group_hex);
    // A composer that never learned of the file saves without it (mdk#3586).
    let saved = app
        .save_message_draft_inputs_if_revision("alice", &staged.revision, "typed", None, vec![])
        .unwrap();
    assert_eq!(
        draft_files(&app, &group_hex),
        files,
        "the save kept the file"
    );
    assert_eq!(media_files(), 1);
    app.save_message_draft_inputs_if_revision(
        "alice",
        &saved.revision,
        "typed",
        None,
        vec![crate::MessageDraftAttachmentInput::Removed("video".into())],
    )
    .unwrap();
    assert!(released(&app, &files));
    assert_eq!(media_files(), 0, "the save unlinked the released file");
    runtime.shutdown_and_close().await.unwrap();
}
