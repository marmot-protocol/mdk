//! Avatar and group-image bodies in the media store's cache category
//! (mdk#2314 step 9).
//!
//! Fetched images are published as cache files; identical images share one
//! file. Reads take a file-backed image from the store, and a missing or
//! corrupt file is reported so every owner sharing it fetches it again.
//! Images still held in the account database move into files in small
//! batches on the maintenance tick, smallest first. An identical file
//! already on disk is reused without writing, so only a new file is charged
//! against free space. Cache files are always re-fetchable, so an image the
//! disk cannot take has its owner dropped, as eviction would, and nothing
//! waits on free space. Every function here does file I/O: call them only on the blocking
//! pool.
use std::io::Cursor;

use media_store::{Admission, Category, DiskPolicy, FileId, MediaError, PublishOutcome};
use sha2::{Digest, Sha256};
use storage_sqlite::{
    AvatarAcquisition, AvatarAssetRead, AvatarAssetRef, AvatarFileImage, AvatarImage,
    AvatarPublication, DatabaseAvatarBody, SqliteAppStorage,
};
use zeroize::Zeroizing;

use crate::{AccountMediaStore, AppError};

/// Most database-held images one maintenance batch moves.
pub(crate) const AVATAR_MIGRATION_BATCH: usize = 64;
/// A batch stops starting new images once it has moved this many bytes.
const AVATAR_MIGRATION_BATCH_BYTES: u64 = 16 * 1024 * 1024;
const TRACE_TARGET: &str = "marmot_app::avatar_cache";

/// What happened to a fetched image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StoredAvatar {
    /// Published as a cache file; the attempt is settled.
    Stored,
    /// A newer publication, source change or restart won; the attempt is
    /// settled if it was still current.
    Superseded,
    /// The disk cannot take the file now. The caller retries the fetch later.
    NoRoom,
}

/// Publishes a fetched, validated image for claimed attempt `job` as a
/// cache file, settling the attempt in the same commit. `reserve` stays
/// free on the volume `free` measures.
pub(crate) fn store_acquired(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
    job: &AvatarAcquisition,
    image: &AvatarImage,
    refresh_at: Option<u64>,
) -> Result<StoredAvatar, AppError> {
    let byte_len = image.bytes().len() as u64;
    let digest: [u8; 32] = Sha256::digest(image.bytes()).into();
    let file = AvatarFileImage::new(byte_len, image.format(), image.width(), image.height())?;
    let publication = AvatarPublication::for_acquisition(storage.clone(), job, file, refresh_at)?;
    // An identical image whose file is on disk is attached without writing;
    // only a new file is charged against free space.
    let published = match media.attach_existing(&publication, Category::Cache, &digest) {
        Ok(Some(outcome)) => Ok(outcome),
        Ok(None) if !fits(reserve, free, byte_len) => return Ok(StoredAvatar::NoRoom),
        Ok(None) => media.publish(
            &publication,
            Category::Cache,
            &mut Cursor::new(image.bytes()),
            byte_len,
            digest,
            crate::unix_now_seconds(),
            &|| false,
        ),
        Err(error) => Err(error),
    };
    media.unlink_released(&publication.take_released());
    match published {
        Ok(PublishOutcome::Published(_) | PublishOutcome::Existing(_))
            if publication.published_revision().is_some() =>
        {
            Ok(StoredAvatar::Stored)
        }
        Ok(_) => {
            storage.settle_avatar_acquisition(job, refresh_at)?;
            Ok(StoredAvatar::Superseded)
        }
        Err(MediaError::Capacity) => Ok(StoredAvatar::NoRoom),
        Err(error) => Err(storage_sqlite::media_storage_error(error).into()),
    }
}

/// Fills `read.image` from a file-backed image's cache file. A file that is
/// missing or fails authentication is reported: this owner is cleared at
/// once (`read.repaired`, with its new status) and every owner sharing the
/// file fetches it again. Other store failures are returned unchanged.
pub(crate) fn read_file_backed(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reference: &AvatarAssetRef,
    read: &mut AvatarAssetRead,
    now: u64,
) -> Result<(), AppError> {
    let Some(file) = read.file.take() else {
        return Ok(());
    };
    let image = match read_whole(media, &file.id, file.byte_len) {
        Ok(Some(bytes)) => AvatarImage::new(bytes, file.format, file.width, file.height).ok(),
        Ok(None) => None,
        Err(error) => return Err(storage_sqlite::media_storage_error(error).into()),
    };
    if let Some(image) = image {
        read.image = Some(image);
        return Ok(());
    }
    let (cleared, released) = storage.discard_avatar_file(reference, file.id)?;
    media.unlink_released(&released);
    if cleared {
        read.repaired = true;
        read.status = storage.avatar_status(reference, now)?;
    }
    Ok(())
}

/// The whole plaintext of file `id`, or `None` when it is missing, has the
/// wrong length or fails authentication.
fn read_whole(
    media: &AccountMediaStore,
    id: &FileId,
    byte_len: u64,
) -> Result<Option<Vec<u8>>, MediaError> {
    let mut reader = match media.open_reader(id) {
        Ok(Some(reader)) => reader,
        Ok(None) | Err(MediaError::Corruption(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if reader.plaintext_bytes() != byte_len {
        return Ok(None);
    }
    let mut bytes = Zeroizing::new(vec![0; byte_len as usize]);
    let mut filled = 0;
    while filled < bytes.len() {
        match reader.read_at(filled as u64, &mut bytes[filled..]) {
            Ok(0) | Err(MediaError::Corruption(_)) => return Ok(None),
            Ok(read) => filled += read,
            Err(error) => return Err(error),
        }
    }
    Ok(Some(std::mem::take(&mut *bytes)))
}

fn fits(reserve: u64, free: &dyn Fn() -> std::io::Result<u64>, byte_len: u64) -> bool {
    // Unknown free space admits nothing, as for downloads.
    free().is_ok_and(|available| {
        DiskPolicy {
            reserve_bytes: reserve,
        }
        .admit(available, DiskPolicy::cache_need(byte_len))
            == Admission::Admitted
    })
}

/// The result of one batch of moving database-held images.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AvatarMigrationBatch {
    pub(crate) moved: usize,
    pub(crate) moved_bytes: u64,
    /// Corrupt images cleared for refetch.
    pub(crate) dropped_corrupt: usize,
    /// Owners removed because the disk could not take their files.
    pub(crate) evicted: usize,
    /// The batch stopped before it ran out of database-held images.
    pub(crate) more: bool,
    /// A store or database failure stopped the batch; the next tick retries.
    pub(crate) deferred: bool,
}

/// Moves up to one batch of database-held images into cache files.
pub(crate) fn migrate_batch(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
) -> AvatarMigrationBatch {
    let mut batch = AvatarMigrationBatch::default();
    let Ok(avatars) = storage.database_held_avatars(AVATAR_MIGRATION_BATCH) else {
        batch.deferred = true;
        return batch;
    };
    batch.more = avatars.len() == AVATAR_MIGRATION_BATCH;
    for avatar in &avatars {
        if batch.moved_bytes >= AVATAR_MIGRATION_BATCH_BYTES {
            batch.more = true;
            break;
        }
        let image = match storage.database_avatar_body(avatar) {
            Ok(DatabaseAvatarBody::Image(image)) => image,
            Ok(DatabaseAvatarBody::Changed) => continue,
            Ok(DatabaseAvatarBody::Corrupt) => {
                match storage.drop_corrupt_database_avatar(avatar) {
                    Ok(true) => batch.dropped_corrupt += 1,
                    Ok(false) => {}
                    Err(_) => {
                        batch.deferred = true;
                        return batch;
                    }
                }
                continue;
            }
            Err(_) => {
                batch.deferred = true;
                return batch;
            }
        };
        let byte_len = image.bytes().len() as u64;
        let digest: [u8; 32] = Sha256::digest(image.bytes()).into();
        // The commit drops the database copy, and attaching an identical
        // ready file checks only its presence and length. Read any such file
        // in full first: one that fails is marked lost, so it is not
        // attached and a fresh file is written from these bytes instead.
        let twin_checked = match storage.ready_media_file(Category::Cache, &digest) {
            Ok(Some(twin)) => media.verify(&twin, &digest).is_ok(),
            Ok(None) => true,
            Err(_) => false,
        };
        let Ok(publication) = AvatarPublication::for_migration(storage.clone(), avatar, &image)
        else {
            batch.deferred = true;
            return batch;
        };
        if !twin_checked {
            batch.deferred = true;
            return batch;
        }
        // An identical file on disk is attached without writing; only a new
        // file is charged against free space.
        let published = match media.attach_existing(&publication, Category::Cache, &digest) {
            Ok(Some(outcome)) => Ok(outcome),
            Ok(None) if !fits(reserve, free, byte_len) => {
                if !evict(storage, avatar, &mut batch) {
                    return batch;
                }
                continue;
            }
            Ok(None) => media.publish(
                &publication,
                Category::Cache,
                &mut Cursor::new(image.bytes()),
                byte_len,
                digest,
                crate::unix_now_seconds(),
                &|| false,
            ),
            Err(error) => Err(error),
        };
        media.unlink_released(&publication.take_released());
        match published {
            Ok(_) if publication.published_revision().is_some() => {
                batch.moved += 1;
                batch.moved_bytes = batch.moved_bytes.saturating_add(byte_len);
            }
            // The row changed underneath the move.
            Ok(_) => {}
            Err(MediaError::Capacity) => {
                if !evict(storage, avatar, &mut batch) {
                    return batch;
                }
            }
            Err(_) => {
                batch.deferred = true;
                return batch;
            }
        }
    }
    batch
}

/// The disk cannot take this image's file: drop its owner instead of
/// pausing. Images go smallest first, so the rest of the batch fits only by
/// reusing a file already on disk. `false` (with the batch deferred) on a
/// database failure.
fn evict(
    storage: &SqliteAppStorage,
    avatar: &storage_sqlite::DatabaseAvatar,
    batch: &mut AvatarMigrationBatch,
) -> bool {
    match storage.evict_database_avatar(avatar) {
        Ok(evicted) => {
            batch.evicted += usize::from(evicted);
            true
        }
        Err(_) => {
            batch.deferred = true;
            false
        }
    }
}

/// Runs one batch and logs it. `true` when avatar observers should hear
/// about it: an owner was cleared or removed.
pub(crate) fn run_batch(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    reserve: u64,
    free: &dyn Fn() -> std::io::Result<u64>,
) -> bool {
    let started = std::time::Instant::now();
    let batch = migrate_batch(storage, media, reserve, free);
    let AvatarMigrationBatch {
        moved,
        moved_bytes,
        dropped_corrupt,
        evicted,
        more,
        deferred,
    } = batch;
    if deferred {
        tracing::warn!(target: TRACE_TARGET, method = "migrate_avatar_images",
            moved, dropped_corrupt, evicted, retry_scheduled = true,
            "avatar image migration batch deferred");
    } else if moved + dropped_corrupt + evicted > 0 {
        tracing::info!(target: TRACE_TARGET, method = "migrate_avatar_images",
            moved, moved_bytes, dropped_corrupt, evicted, more,
            duration_ms = started.elapsed().as_millis() as u64,
            "moved one bounded batch of avatar images");
    }
    dropped_corrupt + evicted > 0
}

#[cfg(test)]
#[path = "avatar_files_tests.rs"]
mod tests;
