//! File-backed outgoing uploads on the media store (mdk#2314 step 3): the
//! domain rules of the stage and promotion targets. The crash table lives in
//! the media-store conformance suite.
use media_store::{Category, FileState, MediaStore, PromoteOutcome, StageOutcome};

use super::*;

fn media(
    dir: &tempfile::TempDir,
    store: &SqliteAccountStorage,
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
    seed(store, message);
    let mut event = source(message);
    event.direction = "sent".into();
    store.record_app_event(&event).unwrap();
    let token = store
        .reserve_attachment_upload(GROUP, 3, 11)
        .unwrap()
        .unwrap();
    let StageOutcome::Staged { id, digest: sealed } = media
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
    assert_eq!(sealed, digest());
    store
        .bind_attachment_uploads(
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
    let media = media(&dir, &store);
    let (token, id) = staged_send(&store, &media, "sent");
    assert_eq!(store.attachment_upload_file(&token).unwrap(), Some(id));
    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "sent", &token, || 12),
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
        store.attachment_upload_file(&token).unwrap(),
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
    let media = media(&dir, &store);
    let (token, id) = staged_send(&store, &media, "removed");
    store.remove_local_attachment(GROUP, "removed", 0).unwrap();
    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "removed", &token, || 12),
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
    let media = media(&dir, &store);
    seed(&store, "orphan");
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
    assert_eq!(
        store
            .prune_attachment_uploads(11 + 8 * 24 * 3600, 64)
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
    let media = media(&dir, &store);
    let (_, id) = staged_send(&store, &media, "legacy");
    assert_eq!(
        store
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
    let media = media(&dir, &store);
    let (token, id) = staged_send(&store, &media, "reset");
    sql(
        &store,
        "UPDATE chat_presentation_meta SET store_epoch=randomblob(16) WHERE id=1",
    );
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert_eq!(store.attachment_upload_file(&token).unwrap(), None);
}

/// Releasing a staged upload clears its reference and deletes the staged
/// row, leaving the upload itself for the send path to settle.
#[test]
fn releasing_a_staged_upload_keeps_the_upload_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteAccountStorage::in_memory().unwrap();
    let media = media(&dir, &store);
    let (token, id) = staged_send(&store, &media, "release");
    assert!(
        media
            .release_staged(&store.attachment_upload_stage(&token), id)
            .unwrap()
    );
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert_eq!(store.attachment_upload_file(&token).unwrap(), None);
    assert!(!media.path(&id).exists());
}

/// Stage `BODY` into a fresh upload bound to `message`'s slot.
fn stage_upload(
    store: &SqliteAccountStorage,
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
    let media = media(&dir, &store);
    let (token, id) = staged_send(&store, &media, "first");
    let mut second = source("second");
    second.direction = "sent".into();
    store.record_app_event(&second).unwrap();

    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "first", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    assert_eq!(
        store.attachment_upload_file(&token).unwrap(),
        Some(id),
        "the second message still owns the upload"
    );
    store.remove_local_attachment(GROUP, "first", 0).unwrap();
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Ready));

    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "second", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    assert_eq!(
        store.attachment_upload_file(&token).unwrap(),
        None,
        "consumed"
    );
    assert_eq!(media.file_state(&id).unwrap(), Some(FileState::Ready));
    store.remove_local_attachment(GROUP, "second", 0).unwrap();
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
    let media = media(&dir, &store);
    let (first, first_id) = staged_send(&store, &media, "filled");
    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "filled", &first, || 12),
                first_id
            )
            .unwrap(),
        PromoteOutcome::Ready
    );
    let (token, id) = stage_upload(&store, &media, "filled");
    assert_eq!(
        media
            .promote(
                &store.attachment_upload_promotion(GROUP, "filled", &token, || 12),
                id
            )
            .unwrap(),
        PromoteOutcome::Released
    );
    assert_eq!(store.attachment_upload_file(&token).unwrap(), None);
    assert_eq!(media.file_state(&id).unwrap(), None);
    assert!(!media.path(&id).exists());
    assert_eq!(media.file_state(&first_id).unwrap(), Some(FileState::Ready));
}
