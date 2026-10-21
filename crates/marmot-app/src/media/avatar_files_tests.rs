use super::*;
use crate::MarmotApp;
use marmot_account::AccountHome;
use storage_sqlite::{AvatarAvailability, AvatarImageFormat, SelectedAvatar, SqliteAccountStorage};

const RESERVE: u64 = 1024;

struct Fixture {
    _dir: tempfile::TempDir,
    app: MarmotApp,
    account: SqliteAccountStorage,
    media: AccountMediaStore,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        AccountHome::open(dir.path())
            .create_account("alice")
            .unwrap();
        let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
        let account = app.account_storage("alice").unwrap();
        let media = app.account_media_store("alice", &account).unwrap();
        Self {
            _dir: dir,
            app,
            account,
            media,
        }
    }

    fn storage(&self) -> SqliteAppStorage {
        self.account.app_storage()
    }

    fn claim(&self, owner: &str) -> (AvatarAssetRef, AvatarAcquisition) {
        let selected = SelectedAvatar::RemoteImage {
            url: format!("https://example.com/{owner}"),
            cache_key: owner.into(),
        };
        let reference = self
            .storage()
            .request_avatar_acquisition(owner, &selected, true)
            .unwrap()
            .unwrap();
        let job = self
            .storage()
            .claim_avatar_acquisition(crate::unix_now_seconds())
            .unwrap()
            .unwrap();
        (reference, job)
    }

    fn count(&self, query: &str) -> i64 {
        raw_connection(&self.app)
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
        walk(
            &self
                .app
                .account_dir("alice")
                .join(media_store::MEDIA_DIRECTORY),
        )
    }

    fn read(&self, reference: &AvatarAssetRef) -> AvatarAssetRead {
        let now = crate::unix_now_seconds();
        let mut read = self.storage().read_avatar(reference, now).unwrap();
        read_file_backed(
            &self.storage(),
            &self.media,
            reference,
            &mut read,
            now,
            storage_sqlite::MAX_AVATAR_BYTES as u64,
        )
        .unwrap();
        read
    }
}

/// A second connection to the account database, for faults and checks.
fn raw_connection(app: &MarmotApp) -> rusqlite::Connection {
    let path = app.account_storage_path("alice");
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let key = app
        .sqlcipher_key("alice", &keys, &path, crate::SqlcipherDatabaseKind::Session)
        .unwrap();
    let connection = rusqlite::Connection::open(path).unwrap();
    storage_sqlite::open_hardened_sqlcipher(
        &connection,
        &key,
        storage_sqlite::SqlCipherHardening::cipher_only(),
    )
    .unwrap();
    connection
}

fn image(seed: u8, len: usize) -> AvatarImage {
    let bytes = (0..len).map(|i| (i as u8).wrapping_mul(7) ^ seed).collect();
    AvatarImage::new(bytes, AvatarImageFormat::Png, 16, 16).unwrap()
}

fn plenty() -> std::io::Result<u64> {
    Ok(u64::MAX / 2)
}

/// A fetched image becomes a cache file in the same commit that settles its
/// attempt, and reads back whole.
#[test]
fn a_fetched_avatar_is_stored_as_a_cache_file() {
    let f = Fixture::new();
    let (reference, job) = f.claim("chat:aa");
    let fetched = image(1, 20_000);
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &plenty,
            &job,
            &fetched,
            Some(9)
        )
        .unwrap(),
        StoredAvatar::Stored
    );
    assert_eq!(
        f.count("SELECT count(*) FROM media_files WHERE category = 2 AND state = 1"),
        1
    );
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_acquisition WHERE state = 0 AND due = 9 AND attempt IS NULL"),
        1,
        "the attempt is settled with its next refresh"
    );
    let read = f.read(&reference);
    assert_eq!(read.image, Some(fetched));
    assert!(!read.repaired);
}

/// A result for an attempt that is no longer current (here a restart reset
/// it) stores nothing.
#[test]
fn a_stale_attempt_stores_nothing() {
    let f = Fixture::new();
    let (reference, job) = f.claim("chat:aa");
    f.storage().resume_avatar_acquisition().unwrap();
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &plenty,
            &job,
            &image(2, 5_000),
            None
        )
        .unwrap(),
        StoredAvatar::Superseded
    );
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    assert_eq!(f.files_on_disk(), 0);
    assert_eq!(
        f.storage()
            .avatar_status(&reference, crate::unix_now_seconds())
            .unwrap()
            .availability,
        AvatarAvailability::Missing
    );
}

/// A disk without room for the file plus the reserve stores nothing; the
/// caller retries the fetch later.
#[test]
fn a_full_disk_stores_no_avatar() {
    let f = Fixture::new();
    let (_, job) = f.claim("chat:aa");
    let fetched = image(3, 5_000);
    let tight = || Ok(RESERVE + DiskPolicy::cache_need(5_000) - 1);
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &tight,
            &job,
            &fetched,
            None
        )
        .unwrap(),
        StoredAvatar::NoRoom
    );
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
    let unknown = || Err(std::io::Error::other("statvfs"));
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &unknown,
            &job,
            &fetched,
            None
        )
        .unwrap(),
        StoredAvatar::NoRoom,
        "unknown free space admits nothing"
    );
}

/// A cache file that went missing is reported on read: the image clears and
/// is fetched again.
#[test]
fn a_missing_cache_file_is_refetched() {
    let f = Fixture::new();
    let (reference, job) = f.claim("chat:aa");
    store_acquired(
        &f.storage(),
        &f.media,
        RESERVE,
        &plenty,
        &job,
        &image(4, 3_000),
        None,
    )
    .unwrap();
    let file = f
        .storage()
        .read_avatar(&reference, crate::unix_now_seconds())
        .unwrap()
        .file
        .unwrap();
    std::fs::remove_file(f.media.path(&file.id)).unwrap();
    let read = f.read(&reference);
    assert!(read.repaired);
    assert!(read.image.is_none());
    assert_eq!(read.status.availability, AvatarAvailability::Missing);
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_acquisition WHERE state = 1 AND due = 0"),
        1,
        "it is fetched again"
    );
    assert_eq!(f.count("SELECT count(*) FROM media_files"), 0);
}

/// Images still in the database move into files without changing what a
/// viewer sees; a corrupt one is cleared for refetch.
#[test]
fn database_avatars_move_into_cache_files() {
    let f = Fixture::new();
    let mut images = Vec::new();
    for (owner, seed) in [("chat:aa", 5), ("chat:bb", 6), ("chat:cc", 7)] {
        let reference = f.storage().bind_avatar_source(owner, "source").unwrap();
        let held = image(seed, 4_000 + seed as usize);
        f.storage()
            .publish_avatar(&reference, 0, &held, None)
            .unwrap();
        images.push((reference, held));
    }
    raw_connection(&f.app)
        .execute(
            "UPDATE avatar_assets SET bytes = zeroblob(10) WHERE owner_key = 'chat:cc'",
            [],
        )
        .unwrap();
    let usage_before = f.storage().avatar_cache_usage().unwrap();
    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &plenty);
    assert_eq!(
        (
            batch.moved,
            batch.dropped_corrupt,
            batch.waiting_for_space,
            batch.deferred
        ),
        (2, 1, false, false)
    );
    assert_eq!(f.storage().database_avatar_bytes().unwrap(), 0);
    assert_eq!(f.files_on_disk(), 2);
    for (reference, held) in &images[..2] {
        let read = f.read(reference);
        assert_eq!(read.image.as_ref(), Some(held));
        assert_eq!(read.status.content_revision, 1, "viewers see no change");
    }
    assert_eq!(
        f.storage().avatar_cache_usage().unwrap().byte_count,
        usage_before.byte_count - 10,
        "only the corrupt image's bytes went"
    );
    assert_eq!(
        migrate_batch(&f.storage(), &f.media, RESERVE, &plenty),
        AvatarMigrationBatch::default(),
        "nothing is left to move"
    );
}

/// On a disk too full for the files, the move waits for space: nothing is
/// deleted, and it continues once there is room.
#[test]
fn a_full_disk_makes_the_move_wait() {
    let f = Fixture::new();
    let mut held = Vec::new();
    for (owner, seed) in [("chat:aa", 8), ("chat:bb", 9)] {
        let reference = f.storage().bind_avatar_source(owner, "source").unwrap();
        f.storage()
            .publish_avatar(&reference, 0, &image(seed, 2_000), None)
            .unwrap();
        held.push(reference);
    }
    let tight = || Ok(RESERVE);
    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &tight);
    assert_eq!((batch.moved, batch.waiting_for_space), (0, true));
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_assets WHERE bytes IS NOT NULL"),
        2,
        "nothing is deleted to make room"
    );
    assert_eq!(f.files_on_disk(), 0);
    assert!(!run_batch(&f.storage(), &f.media, RESERVE, &tight));

    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &plenty);
    assert_eq!((batch.moved, batch.waiting_for_space), (2, false));
    assert_eq!(f.storage().database_avatar_bytes().unwrap(), 0);
}

/// An identical cache file that is corrupt is never trusted with the only
/// good copy: the move verifies it, marks it lost and writes a fresh file
/// from the database bytes.
#[test]
fn a_corrupt_identical_file_is_not_reused_by_the_move() {
    let f = Fixture::new();
    let shared = image(9, 70_000);
    let (_, job) = f.claim("chat:aa");
    store_acquired(
        &f.storage(),
        &f.media,
        RESERVE,
        &plenty,
        &job,
        &shared,
        None,
    )
    .unwrap();
    let held = f.storage().bind_avatar_source("chat:bb", "source").unwrap();
    f.storage().publish_avatar(&held, 0, &shared, None).unwrap();
    // Damage a segment in the middle of the existing file; its header and
    // length still look right.
    let id = f
        .storage()
        .ready_media_file(Category::Cache, &Sha256::digest(shared.bytes()).into())
        .unwrap()
        .unwrap();
    let path = f.media.path(&id);
    let mut bytes = std::fs::read(&path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&path, bytes).unwrap();

    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &plenty);
    assert_eq!((batch.moved, batch.deferred), (1, false));
    assert_eq!(f.read(&held).image, Some(shared));
    assert_ne!(
        f.storage()
            .read_avatar(&held, crate::unix_now_seconds())
            .unwrap()
            .file
            .map(|file| file.id),
        Some(id),
        "the damaged file was not reused"
    );
}

/// A copy of an image already on disk costs no space: on a disk too full for
/// a new file the fetch still attaches it, and the move attaches a
/// database-held copy, then waits at the first image that needs a new file.
#[test]
fn a_full_disk_still_attaches_an_image_already_on_disk() {
    let f = Fixture::new();
    let shared = image(10, 6_000);
    let (_, first) = f.claim("chat:aa");
    store_acquired(
        &f.storage(),
        &f.media,
        RESERVE,
        &plenty,
        &first,
        &shared,
        None,
    )
    .unwrap();
    let held = f.storage().bind_avatar_source("chat:bb", "source").unwrap();
    f.storage().publish_avatar(&held, 0, &shared, None).unwrap();
    let other = f.storage().bind_avatar_source("chat:cc", "source").unwrap();
    // Larger, so the smallest-first move reaches it after the shared copy.
    f.storage()
        .publish_avatar(&other, 0, &image(11, 7_000), None)
        .unwrap();
    let tight = || Ok(RESERVE);

    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &tight);
    assert_eq!((batch.moved, batch.waiting_for_space), (1, true));
    assert_eq!(f.read(&held).image, Some(shared.clone()));
    assert_eq!(f.files_on_disk(), 1);
    assert_eq!(
        f.storage()
            .avatar_status(&other, crate::unix_now_seconds())
            .unwrap()
            .availability,
        AvatarAvailability::Ready,
        "the image that needs a new file waits in the database"
    );

    let (reference, second) = f.claim("chat:dd");
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &tight,
            &second,
            &shared,
            None
        )
        .unwrap(),
        StoredAvatar::Stored
    );
    assert_eq!(f.read(&reference).image, Some(shared));
    assert_eq!(f.files_on_disk(), 1);
}

/// A ready row whose file is gone is not "already on disk": with no room for
/// a new file, neither a fetch nor the move writes one into the reserve.
#[test]
fn a_missing_identical_file_is_charged_as_a_new_one() {
    let f = Fixture::new();
    let shared = image(12, 6_000);
    let (_, first) = f.claim("chat:aa");
    store_acquired(
        &f.storage(),
        &f.media,
        RESERVE,
        &plenty,
        &first,
        &shared,
        None,
    )
    .unwrap();
    let id = f
        .storage()
        .ready_media_file(Category::Cache, &Sha256::digest(shared.bytes()).into())
        .unwrap()
        .unwrap();
    std::fs::remove_file(f.media.path(&id)).unwrap();
    let tight = || Ok(RESERVE);

    let (_, second) = f.claim("chat:bb");
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &tight,
            &second,
            &shared,
            None
        )
        .unwrap(),
        StoredAvatar::NoRoom
    );
    assert_eq!(f.files_on_disk(), 0, "nothing was written into the reserve");

    let held = f.storage().bind_avatar_source("chat:cc", "source").unwrap();
    f.storage().publish_avatar(&held, 0, &shared, None).unwrap();
    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &tight);
    assert_eq!((batch.moved, batch.waiting_for_space), (0, true));
    assert_eq!(f.files_on_disk(), 0);
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_assets WHERE bytes IS NOT NULL"),
        1
    );
}

/// Free space that cannot be measured admits no new file: the move drops
/// nothing and tries again later.
#[test]
fn an_unmeasurable_disk_drops_no_avatars() {
    let f = Fixture::new();
    let held = f.storage().bind_avatar_source("chat:aa", "source").unwrap();
    f.storage()
        .publish_avatar(&held, 0, &image(13, 2_000), None)
        .unwrap();
    let unknown = || Err(std::io::Error::other("statvfs"));
    let batch = migrate_batch(&f.storage(), &f.media, RESERVE, &unknown);
    assert_eq!((batch.moved, batch.waiting_for_space), (0, true));
    assert_eq!(
        f.count("SELECT count(*) FROM avatar_assets WHERE bytes IS NOT NULL"),
        1
    );
    assert_eq!(f.files_on_disk(), 0);
}

/// An owner that moves to another file between the lookup and the read (a
/// newer image landed and its old file was unlinked) is read again from its
/// current file, not returned as an empty "ready" image.
#[test]
fn a_read_follows_an_owner_that_moved_to_another_file() {
    let f = Fixture::new();
    let (reference, first) = f.claim("chat:aa");
    store_acquired(
        &f.storage(),
        &f.media,
        RESERVE,
        &plenty,
        &first,
        &image(14, 3_000),
        Some(0),
    )
    .unwrap();
    let now = crate::unix_now_seconds();
    let mut stale = f.storage().read_avatar(&reference, now).unwrap();
    assert!(stale.file.is_some());
    // A newer image replaces the owner's file and the old one is unlinked.
    let newer = image(15, 4_000);
    let second = f.storage().claim_avatar_acquisition(now).unwrap().unwrap();
    assert_eq!(
        store_acquired(
            &f.storage(),
            &f.media,
            RESERVE,
            &plenty,
            &second,
            &newer,
            None
        )
        .unwrap(),
        StoredAvatar::Stored
    );
    assert_eq!(f.files_on_disk(), 1, "the old file is gone");

    read_file_backed(
        &f.storage(),
        &f.media,
        &reference,
        &mut stale,
        now,
        storage_sqlite::MAX_AVATAR_BYTES as u64,
    )
    .unwrap();
    assert_eq!(stale.image, Some(newer));
    assert!(!stale.repaired);
    assert_eq!(stale.status.content_revision, 2);
}
