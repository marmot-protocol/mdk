//! File-backed outgoing uploads on the media store (mdk#2314 step 3): the
//! domain rules of the stage and promotion targets. The crash table lives in
//! the media-store conformance suite.
use media_store::{Category, FileState, MediaStore, PromoteOutcome, StageOutcome};

use super::*;

fn media(
    dir: &tempfile::TempDir,
    store: &SqliteAppStorage,
) -> MediaStore<crate::SqliteMediaCatalog> {
    MediaStore::new(
        dir.path().join(media_store::MEDIA_DIRECTORY),
        crate::SqliteMediaCatalog::new(store.clone()),
    )
}

/// A sent message whose single attachment is uploaded from a staged file,
/// staged and then bound as the 3b send path does.
fn staged_send(
    store: &SqliteAccountStorage,
    media: &MediaStore<crate::SqliteMediaCatalog>,
    message: &str,
) -> (Vec<u8>, media_store::FileId) {
    let app = store.app_storage();
    seed(store, message);
    let mut event = source(message);
    event.direction = "sent".into();
    app.record_app_event(&event).unwrap();
    let token = app
        .reserve_attachment_upload(GROUP, 3, 11)
        .unwrap()
        .unwrap();
    let StageOutcome::Staged { id, digest: sealed } = media
        .stage(
            &app.attachment_upload_stage(&token),
            Category::Retained,
            &mut std::io::Cursor::new(BODY),
            BODY.len() as u64,
            11,
            &|| false,
        )
        .unwrap()
    else {
        panic!("staged");
    };
    assert_eq!(sealed, digest());
    app.bind_attachment_uploads(
        std::slice::from_ref(&token),
        &[(selected(message).slot, digest())],
    )
    .unwrap();
    (token, id)
}

fn count(store: &SqliteAccountStorage, query: &str, id: &media_store::FileId) -> i64 {
    store
        .lock()
        .unwrap()
        .query_row(query, [id.as_bytes().as_slice()], |row| row.get(0))
        .unwrap()
}

/// Promotion makes the staged file ready, references it from the message's
/// slot and consumes the upload; the file stays.
#[test]
fn a_promoted_upload_is_consumed_and_its_file_retained() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (token, id) = staged_send(&store, &media, "sent");
    assert_eq!(app.attachment_upload_file(&token).unwrap(), Some(id));
    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "sent", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Ready));
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM media_file_refs WHERE file_id=?1",
            &id
        ),
        1
    );
    assert_eq!(
        app.attachment_upload_file(&token).unwrap(),
        None,
        "consumed"
    );
    let mut reader = media.open_reader(&id).unwrap().unwrap();
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut body).unwrap();
    assert_eq!(body, BODY);
}

/// A slot the user removed is never filled: promotion attaches nothing and
/// the staged file stays with its upload.
#[test]
fn a_removed_slot_refuses_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (token, id) = staged_send(&store, &media, "removed");
    app.remove_local_attachment(GROUP, "removed", 0).unwrap();
    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "removed", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Superseded
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Staged));
}

/// An expired upload no message owns is pruned, and its staged file goes
/// with it: the key with the row, the file at the next sweep.
#[test]
fn an_expired_upload_releases_its_staged_file() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    seed(&store, "orphan");
    let token = app
        .reserve_attachment_upload(GROUP, 3, 11)
        .unwrap()
        .unwrap();
    let StageOutcome::Staged { id, .. } = media
        .stage(
            &app.attachment_upload_stage(&token),
            Category::Retained,
            &mut std::io::Cursor::new(BODY),
            BODY.len() as u64,
            11,
            &|| false,
        )
        .unwrap()
    else {
        panic!("staged");
    };
    assert_eq!(
        app.prune_attachment_uploads(11 + 8 * 24 * 3600, 64)
            .unwrap(),
        1
    );
    assert_eq!(media.file_state(&id).unwrap(), None);
    while !media.sweep(64).unwrap().complete {}
    assert!(!media.path(&id).exists());
}

/// The legacy promotion path leaves file-backed uploads to the media store.
#[test]
fn legacy_promotion_skips_file_backed_uploads() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let media = media(&dir, &store.app_storage());
    let (_, id) = staged_send(&store, &media, "legacy");
    assert_eq!(
        store
            .app_storage()
            .promote_attachment_uploads(GROUP, "legacy", 12, u64::MAX)
            .unwrap(),
        0
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Staged));
}

/// A store reset deletes every media row, staged ones included, without a
/// foreign-key failure on the uploads that referenced them.
#[test]
fn a_store_reset_clears_staged_files_and_their_upload_references() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let media = media(&dir, &store.app_storage());
    let (token, id) = staged_send(&store, &media, "reset");
    sql(
        &store,
        "UPDATE chat_presentation_meta SET store_epoch=randomblob(16) WHERE id=1",
    );
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert_eq!(
        store.app_storage().attachment_upload_file(&token).unwrap(),
        None
    );
}

/// Releasing a staged upload clears its reference and deletes the staged
/// row, leaving the upload itself for the send path to settle.
#[test]
fn releasing_a_staged_upload_keeps_the_upload_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (token, id) = staged_send(&store, &media, "release");
    assert!(
        media
            .release_staged(&app.attachment_upload_stage(&token), id)
            .unwrap()
    );
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert_eq!(app.attachment_upload_file(&token).unwrap(), None);
    assert!(!media.path(&id).exists());
}

/// Stage `BODY` into a fresh upload bound to `message`'s slot.
fn stage_upload(
    store: &SqliteAppStorage,
    media: &MediaStore<crate::SqliteMediaCatalog>,
    message: &str,
) -> (Vec<u8>, media_store::FileId) {
    let token = store
        .reserve_attachment_upload(GROUP, 3, 11)
        .unwrap()
        .unwrap();
    let StageOutcome::Staged { id, .. } = media
        .stage(
            &store.attachment_upload_stage(&token),
            Category::Retained,
            &mut std::io::Cursor::new(BODY),
            BODY.len() as u64,
            11,
            &|| false,
        )
        .unwrap()
    else {
        panic!("staged");
    };
    store
        .bind_attachment_uploads(
            std::slice::from_ref(&token),
            &[(selected(message).slot, digest())],
        )
        .unwrap();
    (token, id)
}

/// An upload two messages share keeps its promoted file while the second
/// still waits for it, even after the first message's attachment is
/// removed; the second then promotes the same file, and the file goes only
/// once neither a slot nor the upload holds it.
#[test]
fn a_shared_upload_keeps_its_file_for_the_message_still_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (token, id) = staged_send(&store, &media, "first");
    let mut second = source("second");
    second.direction = "sent".into();
    app.record_app_event(&second).unwrap();

    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "first", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    assert_eq!(
        app.attachment_upload_file(&token).unwrap(),
        Some(id),
        "the second message still owns the upload"
    );
    app.remove_local_attachment(GROUP, "first", 0).unwrap();
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Ready));

    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "second", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    assert_eq!(
        app.attachment_upload_file(&token).unwrap(),
        None,
        "consumed"
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Ready));
    app.remove_local_attachment(GROUP, "second", 0).unwrap();
    assert_eq!(
        media.file_state(&id).unwrap(),
        None,
        "no slot or upload holds it"
    );
}

/// When every slot already holds its body, the upload has nothing left to
/// fill: it is consumed and its staged copy released, not kept until expiry.
#[test]
fn an_upload_whose_slots_are_already_filled_is_released() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (first, first_id) = staged_send(&store, &media, "filled");
    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "filled", &first, || 12),
                first_id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    let (token, id) = stage_upload(&app, &media, "filled");
    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "filled", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Released
    );
    assert_eq!(app.attachment_upload_file(&token).unwrap(), None);
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert!(!media.path(&id).exists());
    assert_eq!(media.file_state(&first_id).unwrap(), Some(FileState::Ready));
}

/// The message owning `message`'s upload, as admission records it.
fn protect(store: &SqliteAppStorage, message: &str) {
    let tag: Vec<String> = serde_json::from_value(selected(message).slot).unwrap();
    store
        .protect_attachment_uploads(GROUP, message, &[tag])
        .unwrap();
}

/// The worker's promotion page lists a bound file-backed upload with each
/// sent message carrying its descriptor, in token order, resuming after its
/// cursor.
#[test]
fn owned_file_backed_uploads_are_paged_for_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    seed(&store, "unbound");
    let unbound = app
        .reserve_attachment_upload(GROUP, 3, 11)
        .unwrap()
        .unwrap();
    media
        .stage(
            &app.attachment_upload_stage(&unbound),
            Category::Retained,
            &mut std::io::Cursor::new(BODY),
            BODY.len() as u64,
            11,
            &|| false,
        )
        .unwrap();
    assert!(
        app.attachment_upload_owners(None, 8).unwrap().is_empty(),
        "an upload not yet bound to a descriptor is never promoted"
    );
    // Bound uploads are found through the sent message's descriptor, with or
    // without owner rows.
    let (first, first_file) = staged_send(&store, &media, "first");
    let (second, _) = staged_send(&store, &media, "second");
    // The fixture's sends share one descriptor, so each message carries both
    // uploads: four (upload, message) pairs.
    let all = app.attachment_upload_owners(None, 8).unwrap();
    let key =
        |owner: &crate::AttachmentUploadOwner| (owner.token.clone(), owner.message_id_hex.clone());
    let mut sorted = all.iter().map(key).collect::<Vec<_>>();
    sorted.sort();
    assert_eq!(all.iter().map(key).collect::<Vec<_>>(), sorted);
    assert_eq!(all.len(), 4);
    assert!(all.iter().any(|owner| owner.token == second));
    assert!(
        all.iter()
            .filter(|owner| owner.token == first)
            .all(|owner| owner.file == first_file)
    );
    let mut paged = Vec::new();
    let mut after = None;
    loop {
        let page = app.attachment_upload_owners(after.as_ref(), 1).unwrap();
        let Some(last) = page.last().cloned() else {
            break;
        };
        paged.extend(page);
        after = Some(last);
    }
    assert_eq!(paged, all);
}

/// An upload whose staged file was lost is deleted, with the lost row, so
/// its message downloads its own media; a present file is never dropped.
#[test]
fn an_upload_with_a_lost_file_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let app = store.app_storage();
    let media = media(&dir, &app);
    let (token, id) = staged_send(&store, &media, "lost");
    protect(&app, "lost");
    assert!(!app.drop_lost_attachment_upload(&token, id).unwrap());
    // Promotion runs before any read or sweep notices the missing file: it
    // must mark it lost, not record the slot as retained.
    std::fs::remove_file(media.path(&id)).unwrap();
    assert_eq!(
        media
            .promote(
                &app.attachment_upload_promotion(GROUP, "lost", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Superseded
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Lost));
    let retained: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM attachment_acquisition WHERE state=3 OR body_completed=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, 0, "the slot is not recorded as retained");
    assert!(app.drop_lost_attachment_upload(&token, id).unwrap());
    assert_eq!(app.attachment_upload_file(&token).unwrap(), None);
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert!(
        !app.attachment_source_has_upload(GROUP, "lost", 0).unwrap(),
        "the slot no longer waits for an upload"
    );
}

/// A file-backed upload whose optional owner registration failed survives
/// both abandonment paths while its pending or confirmed message carries it,
/// and the worker's page still finds and promotes it after a reopen.
#[test]
fn ownerless_file_backed_uploads_survive_abandonment_and_promote() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ownerless.sqlite");
    let key = SqlCipherKey::new("generated-ownerless-key").unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let files = media(&dir, &store.app_storage());
    seed(&store, "seed");
    for (id, pending) in [("pending-ownerless", true), ("confirmed-ownerless", false)] {
        let mut event = source(id);
        event.direction = "sent".into();
        if pending {
            event.source_message_id_hex = None;
            event.source_epoch = None;
        }
        store.app_storage().record_app_event(&event).unwrap();
        let token = store
            .app_storage()
            .reserve_attachment_upload(GROUP, 3, 11)
            .unwrap()
            .unwrap();
        assert!(matches!(
            files
                .stage(
                    &store.app_storage().attachment_upload_stage(&token),
                    Category::Retained,
                    &mut std::io::Cursor::new(BODY),
                    BODY.len() as u64,
                    11,
                    &|| false,
                )
                .unwrap(),
            StageOutcome::Staged { .. }
        ));
        store
            .app_storage()
            .bind_attachment_uploads(
                std::slice::from_ref(&token),
                &[(selected(id).slot, digest())],
            )
            .unwrap();
        sql(
            &store,
            "CREATE TRIGGER fail_owner BEFORE INSERT ON outgoing_attachment_upload_owners BEGIN SELECT RAISE(ABORT,'generated owner fault'); END;",
        );
        assert!(
            store
                .app_storage()
                .protect_attachment_uploads(GROUP, id, &event.tags)
                .is_err()
        );
        sql(&store, "DROP TRIGGER fail_owner");
        store
            .app_storage()
            .abandon_attachment_uploads(&[token])
            .unwrap();
        store
            .app_storage()
            .abandon_bound_attachment_uploads(GROUP, &[selected(id).slot])
            .unwrap();
    }
    let staged: i64 = store
        .lock()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM outgoing_attachment_uploads WHERE file_id IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(staged, 2, "both uploads survive abandonment");
    drop(files);
    store.close().unwrap();
    let store = SqliteAccountStorage::open_encrypted(&path, &key).unwrap();
    let app = store.app_storage();
    let files = media(&dir, &app);
    let mut event = source("pending-ownerless");
    event.direction = "sent".into();
    app.record_app_event(&event).unwrap();
    let mut promoted = 0;
    for owner in app.attachment_upload_owners(None, 8).unwrap() {
        let target = app.attachment_upload_promotion(
            &owner.group_id_hex,
            &owner.message_id_hex,
            &owner.token,
            || 20,
        );
        if matches!(
            files.promote(&target, owner.file).unwrap(),
            PromoteOutcome::Ready | PromoteOutcome::Existing(_)
        ) {
            promoted += 1;
        }
    }
    assert!(promoted > 0);
    for id in ["pending-ownerless", "confirmed-ownerless"] {
        let asset = request(&app, id);
        let file: Vec<u8> = store
            .lock()
            .unwrap()
            .query_row(
                "SELECT file_id FROM media_file_refs WHERE token=?1",
                [&asset.token],
                |row| row.get(0),
            )
            .unwrap();
        let mut reader = files
            .open_reader(&media_store::FileId::from_slice(&file).unwrap())
            .unwrap()
            .unwrap();
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut body).unwrap();
        assert_eq!(body, BODY, "{id}");
    }
}
