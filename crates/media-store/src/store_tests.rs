use std::io::{Cursor, Read};
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::*;
use crate::conformance::{self, Harness};
use crate::memory::MemoryCatalog;

const NOW: u64 = 1_000;

struct MemoryHarness {
    dir: tempfile::TempDir,
    catalog: MemoryCatalog,
}

impl MemoryHarness {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            catalog: MemoryCatalog::default(),
        }
    }
}

impl Harness for MemoryHarness {
    type Catalog = MemoryCatalog;

    fn root(&self) -> PathBuf {
        self.dir.path().join(MEDIA_DIRECTORY)
    }

    fn catalog(&self) -> MemoryCatalog {
        self.catalog.clone()
    }

    fn target(&self, slot: u32) -> Box<dyn PublishTarget + '_> {
        Box::new(self.catalog.target(slot))
    }

    fn supersede(&self, slot: u32) {
        self.catalog.supersede(slot);
    }

    fn release(&self, slot: u32) -> Vec<FileId> {
        self.catalog.release(slot)
    }

    fn delete_row(&self, id: FileId) {
        self.catalog.delete_row(id);
    }

    fn reset(&self) {
        self.catalog.reset();
    }

    /// The rows survive; only the process state (in-flight set) is lost,
    /// which a fresh `MediaStore` models.
    fn restart(&mut self) {}
}

#[test]
fn the_in_memory_catalog_passes_the_conformance_suite() {
    conformance::run_all(&MemoryHarness::new);
}

fn digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

fn fixture() -> (MemoryHarness, MediaStore<MemoryCatalog>) {
    let harness = MemoryHarness::new();
    let store = MediaStore::new(harness.root(), harness.catalog());
    (harness, store)
}

fn publish(
    harness: &MemoryHarness,
    store: &MediaStore<MemoryCatalog>,
    slot: u32,
    body: &[u8],
    declared: u64,
    expected: [u8; 32],
    cancelled: &dyn Fn() -> bool,
) -> MediaResult<PublishOutcome> {
    store.publish(
        harness.target(slot).as_ref(),
        Category::Retained,
        &mut Cursor::new(body),
        declared,
        expected,
        NOW,
        cancelled,
    )
}

fn published(harness: &MemoryHarness, store: &MediaStore<MemoryCatalog>, body: &[u8]) -> FileId {
    match publish(
        harness,
        store,
        0,
        body,
        body.len() as u64,
        digest(body),
        &|| false,
    )
    .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("expected a new file, got {other:?}"),
    }
}

fn files(root: &std::path::Path) -> usize {
    std::fs::read_dir(root)
        .map(|shards| {
            shards
                .map(|shard| std::fs::read_dir(shard.unwrap().path()).unwrap().count())
                .sum()
        })
        .unwrap_or(0)
}

#[test]
fn file_names_reveal_nothing_and_bytes_are_encrypted() {
    let (harness, store) = fixture();
    let content: Vec<u8> = (0..70_000_u32).map(|i| (i % 251) as u8).collect();
    let id = published(&harness, &store, &content);
    let path = store.path(&id);
    assert_eq!(
        path.file_name().unwrap().to_str().unwrap(),
        hex::encode(id.as_bytes())
    );
    assert!(
        !std::fs::read(&path)
            .unwrap()
            .windows(32)
            .any(|w| w == &content[..32])
    );
}

#[cfg(unix)]
#[test]
fn media_directories_and_files_are_private_at_creation() {
    use std::os::unix::fs::PermissionsExt;
    let (harness, store) = fixture();
    let id = published(&harness, &store, b"private");
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&harness.root()), 0o700);
    assert_eq!(mode(store.path(&id).parent().unwrap()), 0o700);
    assert_eq!(mode(&store.path(&id)), 0o600);
}

#[test]
fn rejected_bodies_leave_no_row_and_no_file() {
    let (harness, store) = fixture();
    let content = vec![9; 100_000];
    let mut wrong = content.clone();
    wrong[5] ^= 1;
    let len = content.len() as u64;
    assert!(matches!(
        publish(&harness, &store, 0, &wrong, len, digest(&content), &|| {
            false
        }),
        Err(MediaError::InvalidBody(_))
    ));
    assert!(matches!(
        publish(
            &harness,
            &store,
            0,
            &content,
            len - 1,
            digest(&content),
            &|| false
        ),
        Err(MediaError::InvalidBody(_))
    ));
    assert!(matches!(
        publish(
            &harness,
            &store,
            0,
            &content[..10],
            len,
            digest(&content),
            &|| false
        ),
        Err(MediaError::InvalidBody(_))
    ));
    assert!(matches!(
        publish(
            &harness,
            &store,
            0,
            &content,
            len,
            digest(&content),
            &|| true
        ),
        Err(MediaError::Cancelled)
    ));
    assert!(harness.catalog.page(None, 10).unwrap().is_empty());
    assert_eq!(files(&harness.root()), 0);
}

#[test]
fn closing_the_store_or_its_catalog_stops_all_media_io() {
    for close_catalog in [false, true] {
        let (harness, store) = fixture();
        let id = published(&harness, &store, b"kept");
        let mut reader = store.open_reader(&id).unwrap().unwrap();
        let mut window = [0; 4];
        assert_eq!(reader.read_at(0, &mut window).unwrap(), 4);
        if close_catalog {
            harness.catalog.close();
        } else {
            store.close();
        }
        // An open reader stops too, even for the segment it already decrypted.
        assert_eq!(reader.read_at(0, &mut window), Err(MediaError::Closed));
        assert!(reader.read(&mut window).is_err());
        assert_eq!(store.read_at(&id, 0, &mut window), Err(MediaError::Closed));
        assert_eq!(store.sweep(1), Err(MediaError::Closed));
        assert_eq!(
            publish(&harness, &store, 1, b"x", 1, digest(b"x"), &|| false),
            Err(MediaError::Closed)
        );
    }
}

#[test]
fn a_close_during_the_write_is_reclaimed_by_the_next_store() {
    let (harness, store) = fixture();
    struct CloseMidway<'a>(&'a MediaStore<MemoryCatalog>, Cursor<Vec<u8>>);
    impl Read for CloseMidway<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            if self.1.position() > 0 {
                self.0.close();
            }
            let len = out.len().min(1_000);
            self.1.read(&mut out[..len])
        }
    }
    let content = vec![3; 5_000];
    let result = store.publish(
        harness.target(0).as_ref(),
        Category::Retained,
        &mut CloseMidway(&store, Cursor::new(content.clone())),
        content.len() as u64,
        digest(&content),
        NOW,
        &|| false,
    );
    assert_eq!(result, Err(MediaError::Closed));
    // A fresh store (the next process) reclaims the pending row and file.
    let next = MediaStore::new(harness.root(), harness.catalog());
    let report = next.sweep(100).unwrap();
    assert_eq!((report.pending_removed, report.complete), (1, true));
    assert_eq!(files(&harness.root()), 0);
}

#[test]
fn the_sweep_bounds_its_work_inside_a_single_shard() {
    let (harness, store) = fixture();
    let shard = harness.root().join("ab");
    fs_private::create_dir_all_private(&shard).unwrap();
    for n in 0..25_u32 {
        std::fs::write(shard.join(format!("ab{n:030x}")), b"orphan").unwrap();
    }
    std::fs::write(shard.join("foreign.txt"), b"not ours").unwrap();
    let (mut unlinked, mut visited) = (0, 0);
    for _ in 0..10 {
        let batch = store.sweep(10).unwrap();
        assert!(batch.files_checked <= 10, "{batch:?}");
        unlinked += batch.orphans_unlinked;
        visited += batch.files_checked;
        if batch.complete {
            break;
        }
    }
    assert_eq!(unlinked, 25);
    // Each entry, foreign ones included, is listed once per pass: batches
    // resume the open listing instead of re-reading the shard.
    assert_eq!(visited, 26);
    assert_eq!(files(&harness.root()), 1);
}

#[test]
fn the_sweep_ignores_names_it_did_not_create() {
    let (harness, store) = fixture();
    let id = published(&harness, &store, b"kept");
    let shard = store.path(&id).parent().unwrap().to_path_buf();
    std::fs::write(shard.join("notes.txt"), b"foreign").unwrap();
    // A valid id in the wrong shard is not this store's file either.
    let misplaced = if id.as_bytes()[0] == 0 { "01" } else { "00" };
    std::fs::write(shard.join(format!("{misplaced}{}", "0".repeat(30))), b"x").unwrap();
    let mut orphans = 0;
    loop {
        let batch = store.sweep(10).unwrap();
        orphans += batch.orphans_unlinked;
        if batch.complete {
            break;
        }
    }
    assert_eq!(orphans, 0);
    assert_eq!(files(&harness.root()), 3);
}

#[test]
fn a_corrupted_file_fails_verification_instead_of_returning_bytes() {
    let (harness, store) = fixture();
    let id = published(&harness, &store, &vec![5; 1_000]);
    let path = store.path(&id);
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        store.read_at(&id, 0, &mut [0; 10]),
        Err(MediaError::Corruption(_))
    ));
    // A file that fails verification can never be read: its row is lost, so
    // reuse no longer attaches it and the same bytes publish a new file.
    assert_eq!(store.file_state(&id).unwrap(), Some(FileState::Lost));
    let content = vec![5; 1_000];
    let fresh = match publish(
        &harness,
        &store,
        1,
        &content,
        1_000,
        digest(&content),
        &|| false,
    )
    .unwrap()
    {
        PublishOutcome::Published(fresh) => fresh,
        other => panic!("expected a new file, got {other:?}"),
    };
    assert_ne!(fresh, id);

    // A length that does not match the row is corruption too.
    std::fs::write(store.path(&fresh), b"short").unwrap();
    assert!(matches!(
        store.open_reader(&fresh).map(|r| r.is_some()),
        Err(MediaError::Corruption(_))
    ));
    assert_eq!(store.file_state(&fresh).unwrap(), Some(FileState::Lost));
}

#[test]
fn consecutive_reads_reuse_one_cached_reader_and_key() {
    let (harness, store) = fixture();
    let content: Vec<u8> = (0..3_000_000_u32).map(|i| (i % 253) as u8).collect();
    let id = published(&harness, &store, &content);
    let mut out = Vec::new();
    let mut window = vec![0; 1024 * 1024];
    while let Some(read) = store.read_at(&id, out.len() as u64, &mut window).unwrap() {
        if read == 0 {
            break;
        }
        out.extend_from_slice(&window[..read]);
    }
    assert_eq!(out, content);
    assert_eq!(
        harness.catalog.key_lookups(),
        1,
        "one key lookup for the whole file"
    );

    // Releasing the file drops its cached reader and key with it.
    harness.catalog.release(0);
    store.unlink_released(&[id]);
    assert_eq!(store.read_at(&id, 0, &mut window).unwrap(), None);
    // Closing drops the cache and refuses reads.
    let other = published(&harness, &store, &content[..10]);
    assert_eq!(store.read_at(&other, 0, &mut window).unwrap(), Some(10));
    store.close();
    assert_eq!(
        store.read_at(&other, 0, &mut window),
        Err(MediaError::Closed)
    );
}
