//! Catalog conformance suite. A `MediaCatalog` and its `PublishTarget`s pass
//! when every crash point of the publish/delete table converges through the
//! sweep, reuse never adopts a missing file, and deletions release files. Its
//! `CheckpointTarget`s pass when a download checkpoint's file lives exactly
//! as long as its row, never holds unrecorded bytes once an operation or the
//! sweep has run, and a fenced attempt cannot change it.
//!
//! The in-memory catalog runs it in this crate's tests; `storage-sqlite` runs
//! it against the account database (feature `catalog-conformance`). Each
//! scenario panics on failure, like a test.

use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::catalog::{
    CatalogError, Category, CheckpointTarget, ExistingOutcome, FileId, FileState, MediaCatalog,
    PublishTarget, ReadyOutcome,
};
use crate::format::MediaFileWriter;
use crate::store::{MediaStore, PublishOutcome};

/// One fresh catalog with a store root, as an implementation provides it.
pub trait Harness {
    type Catalog: MediaCatalog;
    /// The store directory for this harness's catalog.
    fn root(&self) -> PathBuf;
    /// A handle on the catalog; after `restart`, a handle on the reopened one.
    fn catalog(&self) -> Self::Catalog;
    /// A publication into slot `slot` (a message attachment slot).
    fn target(&self, slot: u32) -> Box<dyn PublishTarget + '_>;
    /// The slot stops accepting publication, like an explicit removal.
    fn supersede(&self, slot: u32);
    /// Removes the slot's reference; returns the ids whose rows (keys) that
    /// deletion committed away.
    fn release(&self, slot: u32) -> Vec<FileId>;
    /// Deletes a row directly: the committed half of a key-first deletion.
    fn delete_row(&self, id: FileId);
    /// A store-generation reset: every row and reference goes.
    fn reset(&self);
    /// Process death and restart: reopen the catalog.
    fn restart(&mut self);
    /// The checkpoint target of `slot`'s current download attempt.
    fn checkpoint(&self, slot: u32) -> Box<dyn CheckpointTarget + '_>;
    /// A newer attempt takes `slot`'s download: targets from older attempts
    /// are fenced.
    fn supersede_checkpoint(&self, slot: u32);
    /// Deletes `slot`'s checkpoint row without touching its file, as
    /// completion, expiry or a terminal failure do in the domain.
    fn end_checkpoint(&self, slot: u32);
}

const NOW: u64 = 1_000;

fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn body(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn store<H: Harness>(harness: &H) -> MediaStore<H::Catalog> {
    MediaStore::new(harness.root(), harness.catalog())
}

fn publish<H: Harness>(
    harness: &H,
    store: &MediaStore<H::Catalog>,
    slot: u32,
    content: &[u8],
) -> PublishOutcome {
    store
        .publish(
            harness.target(slot).as_ref(),
            Category::Retained,
            &mut Cursor::new(content),
            content.len() as u64,
            digest(content),
            NOW,
            &|| false,
        )
        .expect("publish")
}

fn published<H: Harness>(
    harness: &H,
    store: &MediaStore<H::Catalog>,
    slot: u32,
    content: &[u8],
) -> FileId {
    match publish(harness, store, slot, content) {
        PublishOutcome::Published(id) => id,
        other => panic!("expected a new file, got {other:?}"),
    }
}

fn read_all<C: MediaCatalog>(store: &MediaStore<C>, id: &FileId) -> Option<Vec<u8>> {
    let mut reader = store.open_reader(id).expect("open reader")?;
    let mut out = Vec::new();
    reader.read_to_end(&mut out).expect("read");
    Some(out)
}

fn files_on_disk<H: Harness>(harness: &H) -> usize {
    let Ok(shards) = std::fs::read_dir(harness.root()) else {
        return 0;
    };
    shards
        .filter_map(|shard| std::fs::read_dir(shard.ok()?.path()).ok())
        .map(|files| files.count())
        .sum()
}

fn rows<C: MediaCatalog>(catalog: &C) -> usize {
    catalog.page(None, 10_000).expect("page").len()
}

/// Sweeps to completion in small batches and returns the summed counts.
fn sweep_all<C: MediaCatalog>(store: &MediaStore<C>) -> (u64, u64, u64) {
    let (mut pending, mut orphans, mut lost) = (0, 0, 0);
    for _ in 0..10_000 {
        let batch = store.sweep(2).expect("sweep");
        pending += batch.pending_removed;
        orphans += batch.orphans_unlinked;
        lost += batch.lost_marked;
        if batch.complete {
            return (pending, orphans, lost);
        }
    }
    panic!("sweep did not complete");
}

/// A body source that must never be read.
struct Unread;

impl Read for Unread {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("a reused file must not read the body")
    }
}

/// Runs every scenario, each on a fresh harness from `make`.
pub fn run_all<H: Harness>(make: &dyn Fn() -> H) {
    publish_reads_back_and_reuses_identical_content(make());
    crash_before_the_file_drops_the_pending_row(make());
    crash_mid_write_drops_the_row_and_the_partial_file(make());
    crash_before_the_ready_commit_drops_the_complete_file(make());
    crash_after_the_ready_commit_keeps_the_file(make());
    crash_between_key_deletion_and_unlink_unlinks_the_orphan(make());
    missing_ready_files_become_lost(make());
    reuse_skips_a_twin_whose_file_is_gone(make());
    ready_commit_keeps_its_file_when_the_twin_is_gone(make());
    a_failed_presence_check_leaves_the_twin_untouched(make());
    a_torn_twin_is_lost_and_the_new_body_kept(make());
    the_last_reference_releases_the_file(make());
    supersession_during_the_write_keeps_nothing(make());
    reset_during_the_write_keeps_nothing(make());
    the_sweep_leaves_live_publishes_alone(make());
    checkpoints_append_restore_and_clear(make());
    a_new_checkpoint_replaces_the_old_file(make());
    a_fenced_attempt_cannot_change_the_checkpoint(make());
    a_crash_between_append_and_record_is_cut_off(make());
    a_missing_or_short_wire_file_discards_the_checkpoint(make());
    wire_checkpoints_live_exactly_as_long_as_their_rows(make());
    a_checkpoint_reader_reads_the_recorded_bytes_and_outlives_its_row(make());
}

pub fn publish_reads_back_and_reuses_identical_content<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(150_000, 1);
    let id = published(&harness, &store, 0, &content);
    assert_eq!(store.file_state(&id).unwrap(), Some(FileState::Ready));
    assert_eq!(read_all(&store, &id).unwrap(), content);
    let reused = store
        .publish(
            harness.target(1).as_ref(),
            Category::Retained,
            &mut Unread,
            content.len() as u64,
            digest(&content),
            NOW,
            &|| false,
        )
        .unwrap();
    assert_eq!(reused, PublishOutcome::Existing(id));
    assert_eq!(rows(&harness.catalog()), 1);
    assert_eq!(files_on_disk(&harness), 1);
}

pub fn crash_before_the_file_drops_the_pending_row<H: Harness>(mut harness: H) {
    {
        let store = store(&harness);
        let (_, _, in_flight) = store
            .insert_pending(Category::Retained, 5, &digest(b"bytes"), NOW)
            .unwrap();
        std::mem::forget(in_flight);
    }
    harness.restart();
    let store = store(&harness);
    assert_eq!(sweep_all(&store), (1, 0, 0));
    assert_eq!(rows(&harness.catalog()), 0);
    assert_eq!(sweep_all(&store), (0, 0, 0));
}

pub fn crash_mid_write_drops_the_row_and_the_partial_file<H: Harness>(mut harness: H) {
    let content = body(300_000, 2);
    {
        let store = store(&harness);
        let (id, key, in_flight) = store
            .insert_pending(
                Category::Retained,
                content.len() as u64,
                &digest(&content),
                NOW,
            )
            .unwrap();
        let path = store.path(&id);
        fs_private::create_dir_all_private(path.parent().unwrap()).unwrap();
        let file = fs_private::create_new_private(&path).unwrap();
        let mut writer = MediaFileWriter::new(file, &key, id.as_bytes()).unwrap();
        writer.write_all(&content[..150_000]).unwrap();
        drop(writer);
        std::mem::forget(in_flight);
    }
    harness.restart();
    let store = store(&harness);
    assert_eq!(files_on_disk(&harness), 1);
    assert_eq!(sweep_all(&store), (1, 0, 0));
    assert_eq!(rows(&harness.catalog()), 0);
    assert_eq!(files_on_disk(&harness), 0);
}

pub fn crash_before_the_ready_commit_drops_the_complete_file<H: Harness>(mut harness: H) {
    let content = body(70_000, 3);
    let id = {
        let store = store(&harness);
        let (id, key, in_flight) = store
            .insert_pending(
                Category::Retained,
                content.len() as u64,
                &digest(&content),
                NOW,
            )
            .unwrap();
        store
            .write_body(
                &id,
                &key,
                &mut Cursor::new(&content),
                content.len() as u64,
                &digest(&content),
                &|| false,
            )
            .unwrap();
        std::mem::forget(in_flight);
        id
    };
    harness.restart();
    let store = store(&harness);
    // A complete, synced file whose row is still pending is never adopted.
    assert!(store.open_reader(&id).unwrap().is_none());
    assert_eq!(sweep_all(&store), (1, 0, 0));
    assert_eq!(files_on_disk(&harness), 0);
}

pub fn crash_after_the_ready_commit_keeps_the_file<H: Harness>(mut harness: H) {
    let content = body(10_000, 4);
    let id = published(&harness, &store(&harness), 0, &content);
    harness.restart();
    let store = store(&harness);
    assert_eq!(sweep_all(&store), (0, 0, 0));
    assert_eq!(read_all(&store, &id).unwrap(), content);
}

pub fn crash_between_key_deletion_and_unlink_unlinks_the_orphan<H: Harness>(mut harness: H) {
    let id = published(&harness, &store(&harness), 0, b"orphan");
    harness.release(0);
    harness.delete_row(id);
    harness.restart();
    let store = store(&harness);
    assert_eq!(sweep_all(&store), (0, 1, 0));
    assert_eq!(files_on_disk(&harness), 0);
}

pub fn missing_ready_files_become_lost<H: Harness>(harness: H) {
    let store = store(&harness);
    let swept = published(&harness, &store, 0, b"swept");
    let read = published(&harness, &store, 1, b"read");
    std::fs::remove_file(store.path(&swept)).unwrap();
    std::fs::remove_file(store.path(&read)).unwrap();
    assert_eq!(store.read_at(&read, 0, &mut [0; 4]).unwrap(), None);
    assert_eq!(store.file_state(&read).unwrap(), Some(FileState::Lost));
    assert_eq!(sweep_all(&store), (0, 0, 1));
    assert_eq!(store.file_state(&swept).unwrap(), Some(FileState::Lost));
    assert!(store.catalog().ready_file(swept).unwrap().is_none());
}

pub fn reuse_skips_a_twin_whose_file_is_gone<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(3_000, 5);
    let gone = published(&harness, &store, 0, &content);
    std::fs::remove_file(store.path(&gone)).unwrap();
    let fresh = published(&harness, &store, 1, &content);
    assert_ne!(fresh, gone);
    assert_eq!(store.file_state(&gone).unwrap(), Some(FileState::Lost));
    assert_eq!(read_all(&store, &fresh).unwrap(), content);
}

pub fn ready_commit_keeps_its_file_when_the_twin_is_gone<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(4_000, 6);
    let (own, key, _in_flight) = store
        .insert_pending(
            Category::Retained,
            content.len() as u64,
            &digest(&content),
            NOW,
        )
        .unwrap();
    store
        .write_body(
            &own,
            &key,
            &mut Cursor::new(&content),
            content.len() as u64,
            &digest(&content),
            &|| false,
        )
        .unwrap();
    let twin = published(&harness, &store, 0, &content);
    std::fs::remove_file(store.path(&twin)).unwrap();
    let outcome = harness
        .target(1)
        .commit_ready(own, Category::Retained, &digest(&content), &|id, len| {
            store.present(id, len)
        })
        .unwrap();
    assert_eq!(outcome, ReadyOutcome::Ready);
    assert_eq!(store.file_state(&twin).unwrap(), Some(FileState::Lost));
    assert_eq!(read_all(&store, &own).unwrap(), content);
}

/// A presence check that fails (permission, I/O) must never cost the twin its
/// key: both commits return the error and change nothing.
pub fn a_failed_presence_check_leaves_the_twin_untouched<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(2_000, 9);
    let twin = published(&harness, &store, 0, &content);
    let failing = |_: FileId, _: u64| Err(CatalogError::Backend("stat failed".into()));
    assert!(
        harness
            .target(1)
            .commit_existing(Category::Retained, &digest(&content), &failing)
            .is_err()
    );
    let (own, key, _in_flight) = store
        .insert_pending(
            Category::Retained,
            content.len() as u64,
            &digest(&content),
            NOW,
        )
        .unwrap();
    store
        .write_body(
            &own,
            &key,
            &mut Cursor::new(&content),
            content.len() as u64,
            &digest(&content),
            &|| false,
        )
        .unwrap();
    assert!(
        harness
            .target(1)
            .commit_ready(own, Category::Retained, &digest(&content), &failing)
            .is_err()
    );
    assert_eq!(store.file_state(&twin).unwrap(), Some(FileState::Ready));
    assert_eq!(store.file_state(&own).unwrap(), Some(FileState::Pending));
    assert_eq!(read_all(&store, &twin).unwrap(), content);
}

/// A twin whose file is on disk but torn (shorter than its row implies) is
/// not reused: it is marked lost and the body in hand is stored.
pub fn a_torn_twin_is_lost_and_the_new_body_kept<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(100_000, 10);
    let torn = published(&harness, &store, 0, &content);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(store.path(&torn))
        .unwrap();
    file.set_len(1_000).unwrap();
    drop(file);
    assert_eq!(
        harness
            .target(1)
            .commit_existing(Category::Retained, &digest(&content), &|id, len| {
                store.present(id, len)
            })
            .unwrap(),
        ExistingOutcome::None
    );
    assert_eq!(store.file_state(&torn).unwrap(), Some(FileState::Lost));
    let fresh = published(&harness, &store, 1, &content);
    assert_ne!(fresh, torn);
    assert_eq!(read_all(&store, &fresh).unwrap(), content);
}

pub fn the_last_reference_releases_the_file<H: Harness>(harness: H) {
    let store = store(&harness);
    let content = body(1_000, 7);
    let id = published(&harness, &store, 0, &content);
    assert_eq!(
        publish(&harness, &store, 1, &content),
        PublishOutcome::Existing(id)
    );
    assert!(harness.release(0).is_empty());
    assert_eq!(read_all(&store, &id).unwrap(), content);
    let released = harness.release(1);
    assert_eq!(released, vec![id]);
    store.unlink_released(&released);
    assert_eq!(store.file_state(&id).unwrap(), None);
    assert_eq!(files_on_disk(&harness), 0);
}

/// Reads `content` and runs `during` once before the first byte.
struct During<'a> {
    during: Option<Box<dyn FnOnce() + 'a>>,
    content: Cursor<Vec<u8>>,
}

impl Read for During<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if let Some(during) = self.during.take() {
            during();
        }
        let len = out.len().min(1_000);
        self.content.read(&mut out[..len])
    }
}

fn publish_during<H: Harness>(harness: &H, during: Box<dyn FnOnce() + '_>) -> PublishOutcome {
    let store = store(harness);
    let content = body(5_000, 8);
    store
        .publish(
            harness.target(0).as_ref(),
            Category::Retained,
            &mut During {
                during: Some(during),
                content: Cursor::new(content.clone()),
            },
            content.len() as u64,
            digest(&content),
            NOW,
            &|| false,
        )
        .unwrap()
}

pub fn supersession_during_the_write_keeps_nothing<H: Harness>(harness: H) {
    let outcome = publish_during(&harness, Box::new(|| harness.supersede(0)));
    assert_eq!(outcome, PublishOutcome::Superseded);
    assert_eq!(rows(&harness.catalog()), 0);
    assert_eq!(files_on_disk(&harness), 0);
}

pub fn reset_during_the_write_keeps_nothing<H: Harness>(harness: H) {
    let kept = published(&harness, &store(&harness), 1, b"before the reset");
    let outcome = publish_during(&harness, Box::new(|| harness.reset()));
    assert_eq!(outcome, PublishOutcome::Superseded);
    assert_eq!(rows(&harness.catalog()), 0);
    // The reset destroyed the earlier file's key; the sweep removes its file.
    let store = store(&harness);
    assert_eq!(store.file_state(&kept).unwrap(), None);
    assert_eq!(sweep_all(&store), (0, 1, 0));
    assert_eq!(files_on_disk(&harness), 0);
}

pub fn the_sweep_leaves_live_publishes_alone<H: Harness>(harness: H) {
    let store = store(&harness);
    let (id, _, in_flight) = store
        .insert_pending(Category::Retained, 1, &digest(b"x"), NOW)
        .unwrap();
    assert_eq!(sweep_all(&store), (0, 0, 0));
    assert_eq!(store.file_state(&id).unwrap(), Some(FileState::Pending));
    drop(in_flight);
    assert_eq!(sweep_all(&store), (1, 0, 0));
}

/// The wire file and recorded length of `slot`'s checkpoint.
fn checkpoint_wire<H: Harness>(harness: &H, slot: u32) -> Option<(FileId, u64)> {
    harness.checkpoint(slot).current().unwrap()
}

fn restored<C: MediaCatalog>(
    store: &MediaStore<C>,
    target: &dyn CheckpointTarget,
) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    store
        .checkpoint_restore(target, &mut bytes)
        .unwrap()
        .map(|len| {
            assert_eq!(len, bytes.len() as u64);
            bytes
        })
}

fn wire_len<C: MediaCatalog>(store: &MediaStore<C>, id: &FileId) -> Option<u64> {
    std::fs::metadata(store.wire_path(id))
        .ok()
        .map(|metadata| metadata.len())
}

/// Appends grow the checkpoint only at its recorded length; a restore reads
/// back exactly what was recorded; a clear removes the row, then the file.
pub fn checkpoints_append_restore_and_clear<H: Harness>(harness: H) {
    let store = store(&harness);
    let target = harness.checkpoint(0);
    assert!(store.checkpoint_append(target.as_ref(), 0, b"abc").unwrap());
    assert!(store.checkpoint_append(target.as_ref(), 3, b"def").unwrap());
    let (id, received) = checkpoint_wire(&harness, 0).unwrap();
    assert_eq!(received, 6);
    assert!(
        !store.checkpoint_append(target.as_ref(), 4, b"x").unwrap(),
        "an append that does not start at the recorded length is refused"
    );
    assert_eq!(wire_len(&store, &id), Some(6));
    assert_eq!(restored(&store, target.as_ref()).unwrap(), b"abcdef");
    store.checkpoint_clear(target.as_ref()).unwrap();
    assert_eq!(checkpoint_wire(&harness, 0), None);
    assert_eq!(wire_len(&store, &id), None);
    assert_eq!(restored(&store, target.as_ref()), None);
}

/// Starting over at offset zero replaces the checkpoint with a new wire file
/// and unlinks the old one.
pub fn a_new_checkpoint_replaces_the_old_file<H: Harness>(harness: H) {
    let store = store(&harness);
    let target = harness.checkpoint(0);
    assert!(store.checkpoint_append(target.as_ref(), 0, b"old").unwrap());
    let (old, _) = checkpoint_wire(&harness, 0).unwrap();
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"new!")
            .unwrap()
    );
    let (new, received) = checkpoint_wire(&harness, 0).unwrap();
    assert_ne!(old, new);
    assert_eq!(received, 4);
    assert_eq!(wire_len(&store, &old), None);
    assert_eq!(restored(&store, target.as_ref()).unwrap(), b"new!");
}

/// A target from an older attempt can neither grow, restart, read nor clear
/// the checkpoint a newer attempt owns, and leaves its file as it is.
pub fn a_fenced_attempt_cannot_change_the_checkpoint<H: Harness>(harness: H) {
    let store = store(&harness);
    let stale = harness.checkpoint(0);
    assert!(store.checkpoint_append(stale.as_ref(), 0, b"abc").unwrap());
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    harness.supersede_checkpoint(0);
    assert!(!store.checkpoint_append(stale.as_ref(), 3, b"old").unwrap());
    assert!(!store.checkpoint_append(stale.as_ref(), 0, b"old").unwrap());
    assert_eq!(restored(&store, stale.as_ref()), None);
    store.checkpoint_clear(stale.as_ref()).unwrap();
    assert_eq!(wire_len(&store, &id), Some(3));
    let current = harness.checkpoint(0);
    assert_eq!(restored(&store, current.as_ref()).unwrap(), b"abc");
    assert!(
        store
            .checkpoint_append(current.as_ref(), 3, b"new")
            .unwrap()
    );
    assert_eq!(restored(&store, current.as_ref()).unwrap(), b"abcnew");
}

/// A crash after an append synced but before its record leaves bytes the row
/// never recorded. The sweep cuts them off, and so does the next restore.
pub fn a_crash_between_append_and_record_is_cut_off<H: Harness>(harness: H) {
    let store = store(&harness);
    let target = harness.checkpoint(0);
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"recorded")
            .unwrap()
    );
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    let unrecorded_tail = || {
        std::fs::OpenOptions::new()
            .append(true)
            .open(store.wire_path(&id))
            .unwrap()
            .write_all(b"-unrecorded")
            .unwrap();
    };
    unrecorded_tail();
    assert_eq!(sweep_all(&store), (0, 0, 0));
    assert_eq!(wire_len(&store, &id), Some(8), "the sweep cuts the tail");
    unrecorded_tail();
    assert_eq!(restored(&store, target.as_ref()).unwrap(), b"recorded");
    assert_eq!(wire_len(&store, &id), Some(8), "so does a restore");
}

/// A wire file that vanished or is shorter than its row records cannot
/// resume: restoring clears the checkpoint instead of returning bytes.
pub fn a_missing_or_short_wire_file_discards_the_checkpoint<H: Harness>(harness: H) {
    let store = store(&harness);
    let target = harness.checkpoint(0);
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"abcdef")
            .unwrap()
    );
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    std::fs::remove_file(store.wire_path(&id)).unwrap();
    assert_eq!(restored(&store, target.as_ref()), None);
    assert_eq!(checkpoint_wire(&harness, 0), None);

    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"abcdef")
            .unwrap()
    );
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(store.wire_path(&id))
        .unwrap()
        .set_len(2)
        .unwrap();
    assert_eq!(restored(&store, target.as_ref()), None);
    assert_eq!(checkpoint_wire(&harness, 0), None);
    assert_eq!(wire_len(&store, &id), None);
}

/// A wire checkpoint survives the sweep while its row exists and is unlinked
/// once the domain deletes the row; a wire file no row owns is unlinked.
pub fn wire_checkpoints_live_exactly_as_long_as_their_rows<H: Harness>(harness: H) {
    let store = store(&harness);
    let target = harness.checkpoint(0);
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"recorded")
            .unwrap()
    );
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    let stray = FileId([0x7a; 16]);
    let stray_path = store.wire_path(&stray);
    std::fs::create_dir_all(stray_path.parent().unwrap()).unwrap();
    std::fs::write(&stray_path, b"stray").unwrap();

    assert_eq!(sweep_all(&store), (0, 1, 0));
    assert!(!stray_path.exists());
    assert_eq!(wire_len(&store, &id), Some(8));

    harness.end_checkpoint(0);
    assert_eq!(sweep_all(&store), (0, 1, 0));
    assert!(!store.wire_path(&id).exists());
}

/// A checkpoint reader reads exactly the recorded bytes, from the start and
/// again after a rewind. It keeps the file it opened: the sweep leaves it
/// alone and the row's deletion does not cut the read short. A fenced
/// attempt or a missing row gets no reader, a short file is discarded, and
/// reads stop at close.
pub fn a_checkpoint_reader_reads_the_recorded_bytes_and_outlives_its_row<H: Harness>(harness: H) {
    use std::io::Read;
    let store = store(&harness);
    assert!(
        store
            .checkpoint_reader(harness.checkpoint(0).as_ref())
            .unwrap()
            .is_none()
    );
    let target = harness.checkpoint(0);
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"recorded")
            .unwrap()
    );
    let (id, _) = checkpoint_wire(&harness, 0).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(store.wire_path(&id))
        .unwrap()
        .write_all(b"-unrecorded")
        .unwrap();
    let mut reader = store.checkpoint_reader(target.as_ref()).unwrap().unwrap();
    assert_eq!(reader.len(), 8);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"recorded");
    // The domain deletes the row (completion); the open reader still reads.
    harness.end_checkpoint(0);
    assert_eq!(
        sweep_all(&store),
        (0, 0, 0),
        "the sweep leaves an open reader alone"
    );
    reader.rewind().unwrap();
    bytes.clear();
    reader.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"recorded");
    reader.finish().unwrap();
    assert!(
        !store.wire_path(&id).exists(),
        "finishing unlinks a file whose row is gone"
    );

    // While the row remains, finishing keeps the file for its attempt.
    let kept = harness.checkpoint(3);
    assert!(store.checkpoint_append(kept.as_ref(), 0, b"kept").unwrap());
    let (kept_id, _) = checkpoint_wire(&harness, 3).unwrap();
    let reader = store.checkpoint_reader(kept.as_ref()).unwrap().unwrap();
    reader.finish().unwrap();
    assert_eq!(wire_len(&store, &kept_id), Some(4));

    // A fenced attempt gets no reader; a short file is discarded.
    let stale = harness.checkpoint(1);
    assert!(
        store
            .checkpoint_append(stale.as_ref(), 0, b"abcdef")
            .unwrap()
    );
    harness.supersede_checkpoint(1);
    assert!(store.checkpoint_reader(stale.as_ref()).unwrap().is_none());
    let current = harness.checkpoint(1);
    let (id, _) = checkpoint_wire(&harness, 1).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(store.wire_path(&id))
        .unwrap()
        .set_len(2)
        .unwrap();
    assert!(store.checkpoint_reader(current.as_ref()).unwrap().is_none());
    assert_eq!(checkpoint_wire(&harness, 1), None);

    // Reads stop once the store closes.
    let target = harness.checkpoint(2);
    assert!(
        store
            .checkpoint_append(target.as_ref(), 0, b"closing")
            .unwrap()
    );
    let mut reader = store.checkpoint_reader(target.as_ref()).unwrap().unwrap();
    store.close();
    let mut byte = [0; 1];
    assert!(reader.read(&mut byte).is_err());
}
