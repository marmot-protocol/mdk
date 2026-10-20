use std::io::Cursor;

use media_store::{MEDIA_DIRECTORY, MediaStore, PublishOutcome};
use sha2::{Digest, Sha256};

use super::*;
use crate::app::avatar_cache::{
    AvatarAvailability, AvatarCacheUsage, AvatarImage, AvatarPublishResult,
};
use crate::{SqlCipherKey, SqliteAccountStorage, SqliteMediaCatalog};

const NOW: u64 = 1_000;

struct Fixture {
    _dir: tempfile::TempDir,
    store: SqliteAccountStorage,
    media: MediaStore<SqliteMediaCatalog>,
}

fn body(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SqlCipherKey::new(hex::encode([0x5a; 32])).unwrap();
        let store =
            SqliteAccountStorage::open_encrypted(dir.path().join("session.sqlite"), &key).unwrap();
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

    fn bind(&self, owner: &str) -> AvatarAssetRef {
        self.app()
            .bind_avatar_source(owner, &format!("source-{owner}"))
            .unwrap()
    }

    fn publication(
        &self,
        reference: &AvatarAssetRef,
        revision: u64,
        bytes: &[u8],
        limits: Limits,
    ) -> AvatarPublication {
        let image =
            AvatarFileImage::new(bytes.len() as u64, AvatarImageFormat::Png, 16, 16).unwrap();
        AvatarPublication::with_limits(self.app(), reference.clone(), revision, image, None, limits)
            .unwrap()
    }

    /// Publishes `bytes` for `reference`, unlinking what the commit released.
    fn publish_with(
        &self,
        reference: &AvatarAssetRef,
        revision: u64,
        bytes: &[u8],
        limits: Limits,
    ) -> PublishOutcome {
        let target = self.publication(reference, revision, bytes, limits);
        let outcome = self
            .media
            .publish(
                &target,
                Category::Cache,
                &mut Cursor::new(bytes),
                bytes.len() as u64,
                Sha256::digest(bytes).into(),
                NOW,
                &|| false,
            )
            .unwrap();
        self.media.unlink_released(&target.take_released());
        outcome
    }

    fn publish(&self, reference: &AvatarAssetRef, revision: u64, bytes: &[u8]) -> PublishOutcome {
        self.publish_with(reference, revision, bytes, LIMITS)
    }

    fn read_file(&self, reference: &AvatarAssetRef) -> Option<Vec<u8>> {
        let read = self.app().read_avatar(reference, NOW).unwrap();
        assert!(
            read.image.is_none(),
            "file-backed images are not in the row"
        );
        let file = read.file?;
        let mut out = vec![0; file.byte_len as usize];
        let n = self.media.read_at(&file.id, 0, &mut out).ok()??;
        out.truncate(n);
        Some(out)
    }

    fn count(&self, query: &str) -> i64 {
        self.store
            .lock()
            .unwrap()
            .query_row(query, [], |r| r.get(0))
            .unwrap()
    }

    fn files_on_disk(&self) -> usize {
        fn walk(path: &std::path::Path) -> usize {
            std::fs::read_dir(path)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|entry| {
                            let path = entry.path();
                            if path.is_dir() { walk(&path) } else { 1 }
                        })
                        .sum()
                })
                .unwrap_or(0)
        }
        walk(&self._dir.path().join(MEDIA_DIRECTORY))
    }

    fn sweep(&self) {
        while !self.media.sweep(64).unwrap().complete {}
    }
}

fn file_of(outcome: PublishOutcome) -> FileId {
    match outcome {
        PublishOutcome::Published(id) | PublishOutcome::Existing(id) => id,
        PublishOutcome::Superseded => panic!("superseded"),
    }
}

/// A published image is a cache file: the row holds metadata only, the
/// status and usage report its length, and the read hands out the file.
#[test]
fn a_file_backed_avatar_reads_from_its_cache_file() {
    let f = Fixture::new();
    let owner = f.bind("identity:chat:aa:bb");
    let bytes = body(1, 70_000);
    let target = f.publication(&owner, 0, &bytes, LIMITS);
    let outcome = f
        .media
        .publish(
            &target,
            Category::Cache,
            &mut Cursor::new(&bytes),
            bytes.len() as u64,
            Sha256::digest(&bytes).into(),
            NOW,
            &|| false,
        )
        .unwrap();
    assert!(matches!(outcome, PublishOutcome::Published(_)));
    assert_eq!(target.published_revision(), Some(1));
    assert!(target.take_released().is_empty());
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_assets WHERE bytes IS NULL AND byte_len = 70000"),
        1
    );
    let status = f.app().avatar_status(&owner, NOW).unwrap();
    assert_eq!(status.availability, AvatarAvailability::Ready);
    assert_eq!((status.content_revision, status.byte_count), (1, 70_000));
    assert_eq!(f.read_file(&owner), Some(bytes));
    assert_eq!(
        f.app().avatar_cache_usage().unwrap(),
        AvatarCacheUsage {
            entries: 1,
            byte_count: 70_000
        }
    );
    let usage = f.app().attachment_storage_usage(NOW).unwrap();
    assert_eq!((usage.cache_bytes, usage.media_bytes), (70_000, 0));
}

/// Identical images share one file, counted once. It lives while any owner
/// references it and goes with the last one.
#[test]
fn identical_avatars_share_one_file() {
    let f = Fixture::new();
    let first = f.bind("identity:chat:aa:bb");
    let second = f.bind("identity:chat:cc:bb");
    let bytes = body(2, 5_000);
    let id = file_of(f.publish(&first, 0, &bytes));
    assert_eq!(f.publish(&second, 0, &bytes), PublishOutcome::Existing(id));
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 1);
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 5_000);
    assert_eq!(f.read_file(&second), Some(bytes));

    assert!(f.app().remove_avatar_source(&first).unwrap());
    assert_eq!(
        f.count("SELECT count(*) FROM media_files"),
        1,
        "still shared"
    );
    assert!(f.app().remove_avatar_source(&second).unwrap());
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    assert_eq!(f.files_on_disk(), 1, "the sweep unlinks it");
    f.sweep();
    assert_eq!(f.files_on_disk(), 0);
}

/// Eviction removes the least recently used owner, and the file it released
/// is unlinked as soon as the publication commits.
#[test]
fn eviction_unlinks_released_files_at_once() {
    let f = Fixture::new();
    let limits = Limits {
        entries: 8,
        bytes: 12_000,
    };
    let old = f.bind("identity:chat:aa:01");
    f.publish_with(&old, 0, &body(3, 8_000), limits);
    let new = f.bind("identity:chat:aa:02");
    f.publish_with(&new, 0, &body(4, 8_000), limits);
    assert_eq!(
        f.app().avatar_status(&old, NOW).unwrap().availability,
        AvatarAvailability::Invalidated
    );
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 1);
    assert_eq!(f.files_on_disk(), 1, "freed before the sweep");
    assert_eq!(f.read_file(&new), Some(body(4, 8_000)));
}

/// A shared file frees nothing until its last owner goes, so eviction keeps
/// going until the budget is actually met.
#[test]
fn eviction_counts_a_shared_file_once() {
    let f = Fixture::new();
    let limits = Limits {
        entries: 8,
        bytes: 10_000,
    };
    let shared = body(5, 6_000);
    let a = f.bind("identity:chat:aa:01");
    let b = f.bind("identity:chat:aa:02");
    f.publish_with(&a, 0, &shared, limits);
    f.publish_with(&b, 0, &shared, limits);
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 6_000);
    let c = f.bind("identity:chat:aa:03");
    f.publish_with(&c, 0, &body(6, 6_000), limits);
    for evicted in [&a, &b] {
        assert_eq!(
            f.app().avatar_status(evicted, NOW).unwrap().availability,
            AvatarAvailability::Invalidated
        );
    }
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 6_000);
    assert_eq!(f.files_on_disk(), 1);
}

/// A new image replaces the owner's file; a stale completion is refused and
/// leaves no row or file behind.
#[test]
fn a_new_image_releases_the_old_file_and_stale_completions_lose() {
    let f = Fixture::new();
    let owner = f.bind("chat:aa");
    f.publish(&owner, 0, &body(7, 3_000));
    let second = file_of(f.publish(&owner, 1, &body(8, 4_000)));
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 1);
    assert_eq!(f.files_on_disk(), 1);
    assert_eq!(
        f.publish(&owner, 1, &body(9, 5_000)),
        PublishOutcome::Superseded
    );
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 1);
    assert_eq!(f.files_on_disk(), 1);
    assert_eq!(f.read_file(&owner), Some(body(8, 4_000)));
    let read = f.app().read_avatar(&owner, NOW).unwrap();
    assert_eq!(read.file.unwrap().id, second);
}

/// A database-held image moves to a file on its next publication.
#[test]
fn a_legacy_image_becomes_file_backed() {
    let f = Fixture::new();
    let owner = f.bind("chat:aa");
    let legacy = AvatarImage::new(vec![1; 2_000], AvatarImageFormat::Png, 16, 16).unwrap();
    f.app().publish_avatar(&owner, 0, &legacy, None).unwrap();
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 2_000);
    f.publish(&owner, 1, &body(10, 3_000));
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_assets WHERE bytes IS NULL AND byte_len = 3000"),
        1
    );
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 3_000);
}

/// A database-held publication replaces a file-backed image: the reference
/// goes and, with the last one, the file's key. A stale one changes nothing.
#[test]
fn a_database_held_image_replaces_a_file_backed_one() {
    let f = Fixture::new();
    let owner = f.bind("chat:aa");
    let shared = f.bind("chat:bb");
    let bytes = body(16, 3_000);
    f.publish(&owner, 0, &bytes);
    f.publish(&shared, 0, &bytes);
    let legacy = AvatarImage::new(vec![2; 1_500], AvatarImageFormat::Png, 16, 16).unwrap();
    assert_eq!(
        f.app().publish_avatar(&owner, 0, &legacy, None).unwrap(),
        AvatarPublishResult::Superseded,
        "a stale completion loses"
    );
    assert_eq!(f.read_file(&owner), Some(bytes.clone()));
    assert_eq!(
        f.app().publish_avatar(&owner, 1, &legacy, None).unwrap(),
        AvatarPublishResult::Published {
            content_revision: 2
        }
    );
    assert_eq!(
        f.app().read_avatar(&owner, NOW).unwrap().image,
        Some(legacy.clone())
    );
    assert_eq!(
        f.count("SELECT count(*) FROM media_files"),
        1,
        "still shared"
    );
    f.app().publish_avatar(&shared, 1, &legacy, None).unwrap();
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    assert_eq!(f.count("SELECT count(*) FROM avatar_file_refs"), 0);
    f.sweep();
    assert_eq!(f.files_on_disk(), 0);
    assert_eq!(f.app().avatar_cache_usage().unwrap().byte_count, 3_000);
}

/// A missing or corrupt file is reported once: the file is marked lost, the
/// reporting owner is cleared at once, and every other owner sharing it is
/// cleared on its next read. Clearing schedules a refetch.
#[test]
fn a_bad_file_is_discarded_and_refetched() {
    let f = Fixture::new();
    let first = f.bind("identity:chat:aa:bb");
    let second = f.bind("identity:chat:cc:bb");
    let bytes = body(11, 5_000);
    let id = file_of(f.publish(&first, 0, &bytes));
    f.publish(&second, 0, &bytes);
    f.store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO avatar_acquisition(token, descriptor, state, due)
             SELECT token, x'01', 0, NULL FROM avatar_assets",
            [],
        )
        .unwrap();
    std::fs::remove_file(f.media.path(&id)).unwrap();
    assert_eq!(f.read_file(&first), None, "the store cannot read it");

    let (cleared, released) = f.app().discard_avatar_file(&first, id).unwrap();
    assert!(cleared);
    assert!(released.is_empty(), "the other owner still references it");
    let status = f.app().avatar_status(&first, NOW).unwrap();
    assert_eq!(status.availability, AvatarAvailability::Missing);
    assert_eq!(status.content_revision, 2);

    let read = f.app().read_avatar(&second, NOW).unwrap();
    assert!(read.repaired, "a lost shared file repairs the other owner");
    assert!(read.file.is_none() && read.image.is_none());
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_acquisition WHERE state = 1 AND due = 0"),
        2,
        "both owners refetch"
    );
    assert_eq!(
        f.app().discard_avatar_file(&first, id).unwrap(),
        (false, Vec::new()),
        "a second report changes nothing"
    );
}

/// A report about a file the owner no longer uses changes nothing: the file
/// another owner still reads stays ready with its key.
#[test]
fn a_stale_discard_leaves_a_shared_file_alone() {
    let f = Fixture::new();
    let alice = f.bind("identity:chat:aa:01");
    let bob = f.bind("identity:chat:aa:02");
    let shared = body(17, 2_000);
    let old = file_of(f.publish(&alice, 0, &shared));
    f.publish(&bob, 0, &shared);
    f.publish(&alice, 1, &body(18, 2_500));
    let key = |f: &Fixture| -> Vec<u8> {
        f.store
            .lock()
            .unwrap()
            .query_row(
                "SELECT file_key FROM media_files WHERE id = ?1 AND state = 1",
                [old.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap()
    };
    let before = key(&f);
    assert_eq!(
        f.app().discard_avatar_file(&alice, old).unwrap(),
        (false, Vec::new())
    );
    assert_eq!(key(&f), before);
    assert_eq!(f.read_file(&bob), Some(shared));
}

/// A store reset drops every avatar row and cache file key; the sweep then
/// unlinks the files.
#[test]
fn a_store_reset_drops_cache_files() {
    let f = Fixture::new();
    let owner = f.bind("chat:aa");
    f.publish(&owner, 0, &body(12, 2_000));
    f.store
        .lock()
        .unwrap()
        .execute(
            "UPDATE chat_presentation_meta SET store_epoch = randomblob(16) WHERE id = 1",
            [],
        )
        .unwrap();
    assert_eq!(f.count("SELECT count(*) FROM avatar_assets"), 0);
    assert_eq!(f.count("SELECT count(*) FROM avatar_file_refs"), 0);
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    f.sweep();
    assert_eq!(f.files_on_disk(), 0);
}

/// Clearing the cache or deleting the owning chat's rows releases the files
/// to the sweep.
#[test]
fn clearing_the_cache_releases_its_files() {
    let f = Fixture::new();
    for (owner, seed) in [("chat:aa", 13), ("identity:chat:aa:bb", 14)] {
        let reference = f.bind(owner);
        f.publish(&reference, 0, &body(seed, 1_000));
    }
    assert_eq!(f.files_on_disk(), 2);
    f.app().clear_avatar_cache().unwrap();
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    f.sweep();
    assert_eq!(f.files_on_disk(), 0);
    assert_eq!(
        f.app().attachment_storage_usage(NOW).unwrap().cache_bytes,
        0
    );
}

/// A publication interrupted after its intent row (a crash before the ready
/// commit) leaves a pending cache row and maybe a file; the sweep removes
/// both and the owner is untouched.
#[test]
fn an_interrupted_cache_publication_is_swept() {
    let f = Fixture::new();
    let owner = f.bind("chat:aa");
    let bytes = body(15, 2_000);
    let target = f.publication(&owner, 0, &bytes, LIMITS);
    // A bump between the intent row and the commit plays the crash: the
    // commit finds the fence moved and leaves its row for the store.
    let outcome = f
        .media
        .publish(
            &target,
            Category::Cache,
            &mut Cursor::new(&bytes),
            bytes.len() as u64,
            Sha256::digest(&bytes).into(),
            NOW,
            &|| {
                f.store
                    .lock()
                    .unwrap()
                    .execute(
                        "UPDATE avatar_assets SET content_revision = content_revision + 1",
                        [],
                    )
                    .unwrap();
                false
            },
        )
        .unwrap();
    assert_eq!(outcome, PublishOutcome::Superseded);
    assert_eq!(target.published_revision(), None);
    f.store
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO media_files VALUES(randomblob(16), zeroblob(32), 0, 2, 5, randomblob(32), 1, 1)",
            [],
        )
        .unwrap();
    f.sweep();
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    assert_eq!(f.files_on_disk(), 0);
    assert_eq!(
        f.app().avatar_status(&owner, NOW).unwrap().availability,
        AvatarAvailability::Missing
    );
}
