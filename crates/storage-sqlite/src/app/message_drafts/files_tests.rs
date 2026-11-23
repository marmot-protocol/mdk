//! File-backed draft attachments against a real media store: the draft row
//! owns its staged file across text-only saves and the sweep, a save that
//! leaves it out releases it, and refused or unfinished stages leave nothing.
use std::io::Cursor;

use media_store::{Category, FileState, MEDIA_DIRECTORY, MediaStore, StageOutcome};
use sha2::{Digest, Sha256};

use super::*;
use crate::{SqliteAccountStorage, SqliteMediaCatalog, StoredMessageDraftAttachmentInput};

const GROUP: &str = "22222222222222222222222222222222";

struct Fixture {
    _dir: tempfile::TempDir,
    store: SqliteAccountStorage,
    media: MediaStore<SqliteMediaCatalog>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteAccountStorage::in_memory().unwrap();
        store
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
                [GROUP],
            )
            .unwrap();
        let media = MediaStore::new(
            dir.path().join(MEDIA_DIRECTORY),
            SqliteMediaCatalog::new(store.app_storage()),
        );
        Self {
            _dir: dir,
            store,
            media,
        }
    }

    fn app(&self) -> SqliteAppStorage {
        self.store.app_storage()
    }

    fn revision(&self) -> MessageDraftRevision {
        self.app().selected_message_draft(GROUP).unwrap().revision
    }

    /// Starts staging attachment `id` of `len` bytes into the draft
    /// `expected` selects: the owner a copy commits through.
    fn begin(
        &self,
        expected: &MessageDraftRevision,
        id: &str,
        len: usize,
        fits: fn(u64, u64) -> bool,
    ) -> MessageDraftAttachmentStage {
        self.app()
            .message_draft_attachment_stage(expected, meta(id), len as u64, fits)
            .unwrap()
    }

    /// Copies `body` through `target` and commits it.
    fn finish(
        &self,
        target: &MessageDraftAttachmentStage,
        body: &[u8],
    ) -> (StageOutcome, Option<MessageDraftStageRefusal>) {
        let outcome = self
            .media
            .stage(
                target,
                Category::Retained,
                &mut Cursor::new(body),
                body.len() as u64,
                1,
                &|| false,
            )
            .unwrap();
        (outcome, target.refusal())
    }

    /// Stages `body` as attachment `id` of the draft `expected` selects.
    fn stage(
        &self,
        expected: &MessageDraftRevision,
        id: &str,
        body: &[u8],
        fits: fn(u64, u64) -> bool,
    ) -> (StageOutcome, Option<MessageDraftStageRefusal>) {
        self.finish(&self.begin(expected, id, body.len(), fits), body)
    }

    fn media_rows(&self) -> i64 {
        self.store
            .lock()
            .unwrap()
            .query_row("SELECT count(*) FROM media_files", [], |r| r.get(0))
            .unwrap()
    }
}

fn meta(id: &str) -> MessageDraftAttachmentFileMeta {
    MessageDraftAttachmentFileMeta {
        id: id.to_owned(),
        file_name: "clip.mp4".to_owned(),
        media_type: "video/mp4".to_owned(),
        dim: Some("1x1".to_owned()),
        thumbhash: None,
        duration_seconds: Some(2.0),
        waveform_samples: Vec::new(),
    }
}

#[test]
fn saved_draft_stage_release_and_group_cleanup_erase_the_correct_keys() {
    let fixture = Fixture::new();
    let app = fixture.app();
    let target = fixture.begin(&fixture.revision(), "video", 5, any);
    let (
        StageOutcome::Staged {
            id: parked_file, ..
        },
        _,
    ) = fixture.finish(&target, b"first")
    else {
        panic!("parked attachment must stage");
    };
    let parked = app.archive_message_draft(&fixture.revision()).unwrap();
    let (
        StageOutcome::Staged {
            id: active_file, ..
        },
        _,
    ) = fixture.stage(&fixture.revision(), "video", b"second", any)
    else {
        panic!("active attachment must stage");
    };
    let current = fixture.revision();
    assert!(fixture.media.release_staged(&target, parked_file).unwrap());
    assert_eq!(fixture.media.file_state(&parked_file).unwrap(), None);
    assert_eq!(
        fixture.media.file_state(&active_file).unwrap(),
        Some(FileState::Staged)
    );
    assert!(
        app.identified_message_draft(GROUP, parked)
            .unwrap()
            .content
            .media_attachments
            .is_empty()
    );
    assert_eq!(fixture.revision(), current);

    let second = app.archive_message_draft(&current).unwrap();
    let before = fixture.revision();
    let copying = fixture.begin(&before, "late", 4, any);
    app.delete_group_message_drafts(GROUP).unwrap();
    assert!(app.group_message_drafts(GROUP).unwrap().is_empty());
    assert!(matches!(
        app.identified_message_draft(GROUP, second),
        Err(MessageDraftRevisionError::UnknownDraft)
    ));
    assert_eq!(fixture.media.file_state(&active_file).unwrap(), None);
    assert_eq!(
        fixture.finish(&copying, b"late"),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::Conflict)
        )
    );
    assert_eq!(fixture.media_rows(), 0);
}

fn inline(id: &str, bytes: &[u8]) -> StoredMessageDraftAttachmentInput {
    StoredMessageDraftAttachmentInput::Inline(StoredMessageDraftAttachment {
        id: id.to_owned(),
        file_name: "note.txt".to_owned(),
        media_type: "text/plain".to_owned(),
        plaintext: bytes.to_vec(),
        dim: None,
        thumbhash: None,
        duration_seconds: None,
        waveform_samples: Vec::new(),
    })
}

fn any(_: u64, _: u64) -> bool {
    true
}

/// The contract a host relies on after staging: the file-backed attachment
/// is in the draft (size, flag, digest) with no bytes in the database, it
/// survives text-only saves that retain it and a sweep, and a save that
/// leaves it out deletes its key so the store can unlink the file.
#[test]
fn a_staged_file_belongs_to_its_draft_until_a_save_leaves_it_out() {
    let fixture = Fixture::new();
    let app = fixture.app();
    let body = vec![7u8; 200_000];
    let started = fixture.revision();
    // A text save while the file copies must not lose the staged file.
    let copying = fixture.begin(&started, "video", body.len(), any);
    let saved = app
        .save_message_draft_if_revision(&started, "typing", None, &[inline("note", b"hi")])
        .unwrap();
    let (outcome, refusal) = fixture.finish(&copying, &body);
    let StageOutcome::Staged { id: file, digest } = outcome else {
        panic!("stage refused: {refusal:?}");
    };
    assert_eq!(digest, <[u8; 32]>::from(Sha256::digest(&body)));
    let selected = app.selected_message_draft(GROUP).unwrap();
    assert_ne!(
        selected.revision, saved.revision,
        "staging moves the revision"
    );
    let draft = selected.draft.unwrap();
    assert_eq!(draft.content, "typing");
    let attachments = &draft.media_attachments;
    assert_eq!(
        attachments
            .iter()
            .map(|a| (a.id.as_str(), a.plaintext_size, a.file_backed))
            .collect::<Vec<_>>(),
        [("note", 2, false), ("video", body.len() as u64, true)]
    );
    assert_eq!(
        app.message_draft_plaintext_hashes(&selected.revision)
            .unwrap(),
        [
            <[u8; 32]>::from(Sha256::digest(b"hi")),
            <[u8; 32]>::from(Sha256::digest(&body))
        ]
    );
    assert_eq!(
        app.read_message_draft_attachment_if_revision(&selected.revision, "video", 0, 10)
            .unwrap(),
        Some(MessageDraftAttachmentRead::MediaFile(file))
    );
    assert_eq!(
        app.read_message_draft_attachment_if_revision(&selected.revision, "note", 1, 10)
            .unwrap(),
        Some(MessageDraftAttachmentRead::Bytes(b"i".to_vec()))
    );
    assert!(matches!(
        app.message_draft_attachment_if_revision(&selected.revision, "video"),
        Err(MessageDraftRevisionError::Invalid(_))
    ));
    assert!(matches!(
        app.message_draft(GROUP),
        Err(MessageDraftRevisionError::Invalid(_))
    ));

    // Reordered, re-captioned and retained: the file is untouched.
    let kept = app
        .save_message_draft_if_revision(
            &selected.revision,
            "caption",
            None,
            &[
                StoredMessageDraftAttachmentInput::Retained("video".into()),
                StoredMessageDraftAttachmentInput::Retained("note".into()),
            ],
        )
        .unwrap();
    assert_eq!(
        kept.draft
            .unwrap()
            .media_attachments
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        ["video", "note"]
    );
    assert!(fixture.media.sweep(64).unwrap().complete);
    assert_eq!(
        fixture.media.file_state(&file).unwrap(),
        Some(FileState::Staged)
    );
    let mut copy = Vec::new();
    std::io::Read::read_to_end(
        &mut fixture.media.open_staged_reader(&file).unwrap().unwrap(),
        &mut copy,
    )
    .unwrap();
    assert_eq!(copy, body);
    assert_eq!(
        app.message_draft_upload_sources_if_revision(
            &kept.revision,
            &["note".into(), "video".into()]
        )
        .unwrap()
        .into_iter()
        .map(|source| source.body)
        .collect::<Vec<_>>(),
        [
            MessageDraftUploadBody::Inline(b"hi".to_vec()),
            MessageDraftUploadBody::File {
                id: file,
                digest: Sha256::digest(&body).into()
            }
        ]
    );
    assert!(matches!(
        app.save_message_draft_if_revision(
            &kept.revision,
            "",
            None,
            &[StoredMessageDraftAttachmentInput::Retained("gone".into())],
        ),
        Err(MessageDraftRevisionError::Invalid(_))
    ));

    // Left out: the key goes with the row, and the store unlinks the file.
    app.save_message_draft_if_revision(&kept.revision, "caption", None, &[inline("note", b"hi")])
        .unwrap();
    assert_eq!(fixture.media.file_state(&file).unwrap(), None);
    assert!(
        app.message_draft_attachment_files(GROUP)
            .unwrap()
            .is_empty()
    );
    fixture.media.unlink_released(&[file]);
    assert_eq!(fixture.media_rows(), 0);
    assert!(
        fixture.media.sweep(64).unwrap().orphans_unlinked == 0,
        "the released file is already gone"
    );
}

/// A stage the draft cannot take is abandoned with nothing left behind, and
/// says why; a stage still owned when its draft is deleted is released.
#[test]
fn refused_stages_leave_nothing_and_deleting_the_draft_releases_its_files() {
    let fixture = Fixture::new();
    let app = fixture.app();
    let started = fixture.revision();
    let (outcome, _) = fixture.stage(&started, "video", b"first", any);
    assert!(matches!(outcome, StageOutcome::Staged { .. }));
    let current = fixture.revision();
    assert!(matches!(
        app.message_draft_usage_if_revision(&current, "video"),
        Err(MessageDraftRevisionError::Invalid(_))
    ));
    assert_eq!(
        app.message_draft_usage_if_revision(&current, "other")
            .unwrap(),
        (1, 5)
    );
    assert_eq!(
        fixture.stage(&current, "video", b"again", any),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::DuplicateId)
        )
    );
    fn one(count: u64, _: u64) -> bool {
        count <= 1
    }
    assert_eq!(
        fixture.stage(&current, "second", b"again", one),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::Full)
        )
    );
    // The same group in another store: refused before any copy.
    let foreign = {
        let other = SqliteAccountStorage::in_memory().unwrap();
        other
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
                [GROUP],
            )
            .unwrap();
        other
            .app_storage()
            .selected_message_draft(GROUP)
            .unwrap()
            .revision
    };
    assert!(matches!(
        app.message_draft_attachment_stage(&foreign, meta("second"), 5, any),
        Err(MessageDraftRevisionError::Conflict)
    ));
    assert_eq!(fixture.media_rows(), 1, "refused stages left no rows");
    let sweep = fixture.media.sweep(64).unwrap();
    assert_eq!(
        (sweep.orphans_unlinked, sweep.staged_released),
        (0, 0),
        "refused stages left no files, and the owned one is kept"
    );

    app.delete_message_draft(GROUP).unwrap();
    assert_eq!(
        fixture.media_rows(),
        0,
        "deleting the draft deletes the key"
    );
    assert_eq!(fixture.media.sweep(64).unwrap().orphans_unlinked, 1);
    let copying = fixture.begin(&fixture.revision(), "late", 4, any);
    fixture
        .store
        .lock()
        .unwrap()
        .execute("DELETE FROM account_groups", [])
        .unwrap();
    assert_eq!(
        fixture.finish(&copying, b"late"),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::UnknownGroup)
        )
    );
    assert_eq!(fixture.media_rows(), 0);

    let reset = Fixture::new();
    // A store reset while the file copies refuses it at commit.
    let copying = reset.begin(&reset.revision(), "second", 5, any);
    reset
        .store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_presentation_meta SET store_epoch = randomblob(16) WHERE id = 1",
            [],
        )
        .unwrap();
    assert_eq!(
        reset.finish(&copying, b"again"),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::Conflict)
        )
    );
    assert_eq!(reset.media_rows(), 0);
}

/// A draft that ends while its file copies (cleared, deleted or sent) stays
/// ended, even when the composer had no draft row yet or a new draft was
/// started before the copy finished: the copy is refused, not added.
#[test]
fn a_file_staged_into_a_draft_ended_during_the_copy_is_refused() {
    let fixture = Fixture::new();
    let app = fixture.app();
    // The first attachment of an empty composer, cleared while it copies.
    let empty = fixture.revision();
    let copying = fixture.begin(&empty, "video", 9, any);
    app.clear_message_draft_if_revision(&empty).unwrap();
    assert_eq!(
        fixture.finish(&copying, b"late copy"),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::Conflict)
        )
    );
    assert!(app.selected_message_draft(GROUP).unwrap().draft.is_none());

    // A draft cleared, then a new one typed, before the copy finished.
    let typed = app
        .save_message_draft_if_revision(&fixture.revision(), "old", None, &[])
        .unwrap()
        .revision;
    let copying = fixture.begin(&typed, "video", 9, any);
    app.clear_message_draft_if_revision(&typed).unwrap();
    app.save_message_draft_if_revision(&fixture.revision(), "new", None, &[])
        .unwrap();
    assert_eq!(
        fixture.finish(&copying, b"late copy"),
        (
            StageOutcome::Superseded,
            Some(MessageDraftStageRefusal::Conflict)
        )
    );
    let draft = app.selected_message_draft(GROUP).unwrap().draft.unwrap();
    assert_eq!(
        (draft.content.as_str(), draft.media_attachments.len()),
        ("new", 0)
    );

    // The legacy delete ends a composition the same way.
    let current = fixture.revision();
    let copying = fixture.begin(&current, "video", 9, any);
    app.delete_message_draft(GROUP).unwrap();
    assert_eq!(
        fixture.finish(&copying, b"late copy").1,
        Some(MessageDraftStageRefusal::Conflict)
    );
    // The group deleted and recreated (a forget and a later rejoin), with
    // and without an empty clear first: a new composition.
    for clear_first in [false, true] {
        let current = fixture.revision();
        let copying = fixture.begin(&current, "video", 9, any);
        if clear_first {
            app.clear_message_draft_if_revision(&current).unwrap();
        }
        let conn = fixture.store.lock().unwrap();
        conn.execute("DELETE FROM account_groups", []).unwrap();
        conn.execute(
            "INSERT INTO account_groups(group_id_hex,endpoint,updated_at) VALUES (?1,'',0)",
            [GROUP],
        )
        .unwrap();
        drop(conn);
        assert_eq!(
            fixture.finish(&copying, b"late copy").1,
            Some(MessageDraftStageRefusal::Conflict)
        );
        assert!(app.selected_message_draft(GROUP).unwrap().draft.is_none());
    }
    assert_eq!(fixture.media_rows(), 0, "refused copies left no rows");
}

#[test]
fn saved_message_drafts_keep_staged_files_and_refuse_copies_from_previous_compositions() {
    let fixture = Fixture::new();
    let app = fixture.app();
    assert!(matches!(
        fixture.stage(&fixture.revision(), "video", b"saved clip", any),
        (StageOutcome::Staged { .. }, None)
    ));
    let archive_revision = fixture.revision();
    let started_before_archive = fixture.begin(&archive_revision, "late", 9, any);
    let id = app.archive_message_draft(&archive_revision).unwrap();
    let empty = fixture.revision();
    let started_while_empty = fixture.begin(&empty, "empty", 9, any);
    let version = app
        .identified_message_draft(GROUP, id)
        .unwrap()
        .content_revision;
    assert!(matches!(
        app.read_identified_message_draft_attachment(GROUP, id, version, "video", 0, 10)
            .unwrap(),
        Some(MessageDraftAttachmentRead::MediaFile(_))
    ));
    let restored = app.activate_message_draft(&empty, id).unwrap();
    assert!(restored.draft.unwrap().media_attachments[0].file_backed);
    for stage in [&started_before_archive, &started_while_empty] {
        assert_eq!(
            fixture.finish(stage, b"late copy"),
            (
                StageOutcome::Superseded,
                Some(MessageDraftStageRefusal::Conflict)
            )
        );
    }
    assert_eq!(fixture.media_rows(), 1);
    app.archive_message_draft(&fixture.revision()).unwrap();
    app.delete_saved_message_draft(GROUP, id).unwrap();
    assert_eq!(fixture.media_rows(), 0);
}
