//! Handoff leases (mdk#2314 step 4): a plaintext copy of a retained
//! attachment that a host lends to an OS surface needing a real file (the
//! package installer, the share sheet, "open with", Quick Look).
//!
//! A copy lives at `<account>/handoff/<lease>/<name>`, created private through
//! `fs-private`. It is deleted only on explicit release, with the account
//! directory, or by the wipe when an account worker takes ownership, which
//! spares the leases this process still holds: a runtime rebuilt after
//! `shutdown_and_close` keeps a file a share sheet is still reading. The copy
//! never needs to survive a crash, so it is written without sync or rename.
//! These are the only plaintext attachment files MDK writes. All work here
//! is blocking.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use media_store::{Admission, DiskPolicy};
use storage_sqlite::{RetainedAttachmentRead, SqliteAccountStorage};
use zeroize::Zeroizing;

use super::file_transfer::{FILE_TRANSFER_BUFFER_BYTES, MediaFileTransferControl};
use crate::{AppError, MarmotApp};

const HANDOFF_DIRECTORY: &str = "handoff";
const MAX_NAME_BYTES: usize = 128;
const FALLBACK_NAME: &str = "attachment";
/// Legacy database bodies are read in steps of this many bytes.
const LEGACY_READ_BYTES: usize = storage_sqlite::MAX_ATTACHMENT_LOCAL_READ_BYTES;

/// A plaintext copy of a retained attachment, lent to the host until it
/// calls [`release`]. Debug output omits every field.
#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentHandoff {
    /// Opaque lease id: 32 lowercase hex characters.
    pub lease: String,
    pub path: PathBuf,
    pub byte_count: u64,
    pub media_type: String,
    pub file_name: String,
}

impl std::fmt::Debug for AttachmentHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentHandoff").finish_non_exhaustive()
    }
}

/// Live leases of this process: lease id to its directory. Process-wide, so
/// a runtime rebuilt in the same process still spares them.
fn leases() -> &'static Mutex<HashMap<String, PathBuf>> {
    static LEASES: OnceLock<Mutex<HashMap<String, PathBuf>>> = OnceLock::new();
    LEASES.get_or_init(Default::default)
}

fn lock_leases() -> std::sync::MutexGuard<'static, HashMap<String, PathBuf>> {
    leases()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The account's handoff directory.
pub(crate) fn handoff_directory(app: &MarmotApp, account: &str) -> PathBuf {
    app.account_dir(account).join(HANDOFF_DIRECTORY)
}

/// A full volume is the storage-full error, as admission reports a known
/// shortfall; any other filesystem failure is I/O (its kind kept, fixed
/// text), never mistaken for invalid media.
fn handoff_error(error: std::io::Error) -> AppError {
    if error.kind() == std::io::ErrorKind::StorageFull {
        return capacity_error();
    }
    AppError::Io(std::io::Error::new(
        error.kind(),
        "attachment handoff copy failed",
    ))
}

fn capacity_error() -> AppError {
    AppError::from(cgka_traits::StorageError::Capacity(
        "not enough free space for the attachment copy".into(),
    ))
}

/// Where a retained attachment is, and what to call its copy.
pub(crate) struct HandoffSource {
    pub(crate) reference: storage_sqlite::AttachmentAssetRef,
    pub(crate) byte_count: u64,
    pub(crate) media_type: String,
    pub(crate) file_name: String,
}

impl HandoffSource {
    /// Looks up a retained slot and its published descriptor. `None` means
    /// the attachment is not held locally. Blocking.
    pub(crate) fn find(
        storage: &SqliteAccountStorage,
        group: &str,
        target: &crate::AttachmentLocalTarget,
        allow_loopback: bool,
    ) -> Result<Option<Self>, AppError> {
        let app_storage = storage.app_storage();
        let Some(asset) = app_storage.retained_attachment_asset(
            group,
            &target.message_id_hex,
            &target.source_message_id_hex,
            target.attachment_index,
            crate::unix_now_seconds(),
        )?
        else {
            return Ok(None);
        };
        let descriptor = app_storage
            .retained_attachment_descriptor(
                group,
                &target.message_id_hex,
                &target.source_message_id_hex,
                target.attachment_index,
                crate::unix_now_seconds(),
            )?
            .and_then(|(slot, epoch)| {
                let tag = serde_json::from_str::<Vec<String>>(&slot).ok()?;
                super::parse_media_attachment(&tag, epoch, allow_loopback).ok()
            });
        let (file_name, media_type) = descriptor.map_or_else(
            || (String::new(), "application/octet-stream".to_owned()),
            |reference| (reference.file_name, reference.media_type),
        );
        Ok(Some(Self {
            reference: asset.reference,
            byte_count: asset.byte_count,
            file_name: handoff_name(&file_name, &media_type),
            media_type,
        }))
    }
}

/// The copy's file name: the attachment's own name reduced to a safe
/// basename (no separators, control characters or edge dots, at most 128
/// bytes), or `attachment`, with an extension from the media type when it
/// has none. Installers and share targets go by the extension.
pub(crate) fn handoff_name(file_name: &str, media_type: &str) -> String {
    let base = file_name.rsplit(['/', '\\']).next().unwrap_or_default();
    let cleaned = base
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_format(*c) && !matches!(c, '/' | '\\' | ':'))
        .collect::<String>();
    let name = cleaned.trim().trim_matches('.').trim();
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() && ext.len() <= 16 => {
            (stem.trim_end_matches('.'), ext.to_owned())
        }
        _ => (name, extension_for(media_type).to_owned()),
    };
    let stem = if stem.is_empty() { FALLBACK_NAME } else { stem };
    // The whole name, extension included, fits the cap.
    let mut cut = stem.len().min(MAX_NAME_BYTES - extension.len() - 1);
    while !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    let stem = if cut == 0 {
        FALLBACK_NAME
    } else {
        &stem[..cut]
    };
    format!("{stem}.{extension}")
}

/// Unicode bidirectional formatting characters, which could make a name
/// display with a different extension than it has (`safe\u{202E}txt.apk`).
fn is_bidi_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

fn extension_for(media_type: &str) -> &'static str {
    match media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "image/jpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/heic" => "heic",
        "video/mp4" => "mp4",
        "video/quicktime" => "mov",
        "video/webm" => "webm",
        "audio/mpeg" => "mp3",
        "audio/mp4" | "audio/x-m4a" => "m4a",
        "audio/ogg" => "ogg",
        "audio/aac" => "aac",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "application/vnd.android.package-archive" => "apk",
        "text/plain" => "txt",
        _ => "bin",
    }
}

/// Deletes a registered lease's directory, then forgets the lease. A
/// deletion that fails keeps the lease registered, so a later release can
/// retry it. An unknown lease is already gone. Blocking.
fn remove_lease(lease: &str) -> std::io::Result<()> {
    let Some(directory) = lock_leases().get(lease).cloned() else {
        return Ok(());
    };
    match std::fs::remove_dir_all(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    lock_leases().remove(lease);
    Ok(())
}

/// Best-effort removal for a copy nobody will release: the lease is
/// forgotten even if deletion fails, so the next wipe reclaims the files.
fn discard_lease(lease: &str) {
    #[cfg(test)]
    tests::record_discard_thread();
    if remove_lease(lease).is_err() {
        lock_leases().remove(lease);
    }
}

/// A finished copy that has not reached the host yet. Dropping it (the
/// opening call was abandoned) discards the copy; [`Self::deliver`] hands it
/// over. A drop can happen on any thread (a host cancelling a finished call
/// drops the stored result where it cancels), so the deletion is sent to
/// the blocking pool of the runtime that made the copy.
pub(crate) struct PendingHandoff {
    handoff: Option<AttachmentHandoff>,
    runtime: Option<tokio::runtime::Handle>,
}

impl std::fmt::Debug for PendingHandoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingHandoff").finish_non_exhaustive()
    }
}

impl PendingHandoff {
    /// Wraps a registered copy made on the current runtime's blocking pool.
    fn new(handoff: AttachmentHandoff) -> Self {
        Self {
            handoff: Some(handoff),
            runtime: tokio::runtime::Handle::try_current().ok(),
        }
    }

    /// The host now holds the lease and must release it.
    pub(crate) fn deliver(mut self) -> AttachmentHandoff {
        self.handoff
            .take()
            .expect("a pending handoff is delivered once")
    }
}

impl Drop for PendingHandoff {
    fn drop(&mut self) {
        let Some(handoff) = self.handoff.take() else {
            return;
        };
        match &self.runtime {
            Some(runtime) => {
                let orphan = Orphan(Some(handoff.lease));
                runtime.spawn_blocking(move || orphan.discard());
            }
            // Made outside a runtime: this thread is already a blocking one.
            None => discard_lease(&handoff.lease),
        }
    }
}

/// A discarded lease on its way to the blocking pool. If the task never
/// runs (the runtime stopped or rejected it), dropping this forgets the
/// lease without file I/O, so the next wipe reclaims the copy instead of
/// sparing an unreachable lease.
struct Orphan(Option<String>);

impl Orphan {
    fn discard(mut self) {
        if let Some(lease) = self.0.take() {
            discard_lease(&lease);
        }
    }
}

impl Drop for Orphan {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lock_leases().remove(&lease);
        }
    }
}

/// Writes a handoff copy of `source` and registers its lease. `None` means
/// the body stopped being available while it was copied. A cancelled,
/// failed or short copy leaves nothing, and so does a finished copy whose
/// [`PendingHandoff`] is dropped undelivered. Blocking.
pub(crate) fn open(
    app: &MarmotApp,
    account: &str,
    storage: &SqliteAccountStorage,
    source: HandoffSource,
    control: &MediaFileTransferControl,
) -> Result<Option<PendingHandoff>, AppError> {
    // Plaintext must not depend on an inherited ACL: `fs-private` modes are
    // no-ops on Windows, which is not a target platform.
    if cfg!(windows) {
        return Err(AppError::InvalidEncryptedMedia(
            "attachment handoff is not supported on this platform".into(),
        ));
    }
    control.check()?;
    let policy = storage.app_storage().attachment_download_policy(
        &crate::runtime::attachment_controls::default_policy(&app.config),
    )?;
    if let Ok(free) = super::attachment_resume::available_space(&app.account_dir(account))
        && let Admission::StorageFull { .. } = (DiskPolicy {
            reserve_bytes: policy.disk_reserve,
        })
        .admit(free, DiskPolicy::handoff_need(source.byte_count))
    {
        return Err(capacity_error());
    }
    let lease = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    // A handle held across account removal must not write into whatever
    // directory now sits at the account's path (a re-import).
    let evicted = || {
        AppError::from(cgka_traits::StorageError::Closed(
            "attachment handoff unavailable: account storage handle was evicted".into(),
        ))
    };
    if !app.account_storage_is_current(account, storage) {
        return Err(evicted());
    }
    let directory = handoff_directory(app, account).join(&lease);
    // Registered before anything exists, so a concurrent wipe spares it.
    lock_leases().insert(lease.clone(), directory.clone());
    let path = directory.join(&source.file_name);
    match write_copy(app, account, storage, &source, &directory, &path, control) {
        // Checked again once the copy exists: a removal during the copy
        // means it came from the evicted store, so it is never handed out.
        Ok(true) if !app.account_storage_is_current(account, storage) => {
            discard_lease(&lease);
            Err(evicted())
        }
        Ok(true) => Ok(Some(PendingHandoff::new(AttachmentHandoff {
            lease,
            path,
            byte_count: source.byte_count,
            media_type: source.media_type,
            file_name: source.file_name,
        }))),
        Ok(false) => {
            discard_lease(&lease);
            Ok(None)
        }
        Err(error) => {
            discard_lease(&lease);
            Err(error)
        }
    }
}

/// Copies the body into a new private file. `false` means it became
/// unavailable part way.
fn write_copy(
    app: &MarmotApp,
    account: &str,
    storage: &SqliteAccountStorage,
    source: &HandoffSource,
    directory: &Path,
    path: &Path,
    control: &MediaFileTransferControl,
) -> Result<bool, AppError> {
    // One level at a time and never the account directory itself: a
    // removed account's directory is not recreated, and a symlinked
    // `handoff` is refused rather than followed out of the account.
    let root = directory
        .parent()
        .ok_or_else(|| AppError::InvalidEncryptedMedia("invalid handoff directory".into()))?;
    create_private_dir_level(root, true).map_err(handoff_error)?;
    create_private_dir_level(directory, false).map_err(handoff_error)?;
    // Unbuffered: chunks are already 64 KiB to 1 MiB, and no plaintext is
    // left behind in a writer buffer.
    let mut file = fs_private::create_new_private(path).map_err(handoff_error)?;
    let now = crate::unix_now_seconds();
    let mut written = 0u64;
    // Nothing past the admitted length is ever written: a longer body is a
    // length mismatch before its extra bytes reach the file.
    let changed =
        || AppError::InvalidEncryptedMedia("attachment length changed during the copy".into());
    loop {
        control.check()?;
        match storage.app_storage().retained_attachment_read(
            &source.reference,
            now,
            written,
            LEGACY_READ_BYTES,
        )? {
            None => return Ok(false),
            Some(RetainedAttachmentRead::Bytes(bytes)) => {
                if bytes.is_empty() {
                    break;
                }
                if written + bytes.len() as u64 > source.byte_count {
                    return Err(changed());
                }
                file.write_all(&bytes).map_err(handoff_error)?;
                written += bytes.len() as u64;
                control.advance(written);
            }
            Some(RetainedAttachmentRead::MediaFile(id)) => {
                let media = app.account_media_store(account, storage)?;
                let Some(mut reader) = media
                    .open_reader(&id)
                    .map_err(storage_sqlite::media_storage_error)?
                else {
                    return Ok(false);
                };
                let mut buffer = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]);
                loop {
                    control.check()?;
                    let read = reader.read(&mut buffer).map_err(handoff_error)?;
                    if read == 0 {
                        break;
                    }
                    if written + read as u64 > source.byte_count {
                        return Err(changed());
                    }
                    file.write_all(&buffer[..read]).map_err(handoff_error)?;
                    written += read as u64;
                    control.advance(written);
                }
                break;
            }
        }
    }
    file.flush().map_err(handoff_error)?;
    if written != source.byte_count {
        return Err(changed());
    }
    control.check()?;
    Ok(true)
}

/// Creates one directory level owner-only, without creating parents and
/// without following a symlink: an existing entry is accepted only when
/// `existing` allows it and it is a real directory.
fn create_private_dir_level(path: &Path, existing: bool) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {}
        Err(error) if existing && error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    if !std::fs::symlink_metadata(path)?.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "handoff directory must be a real directory",
        ));
    }
    Ok(())
}

/// Deletes a lease's copy. An unknown or already released lease is not an
/// error. A copy that cannot be deleted is an I/O error and stays leased, so
/// the host can retry. Blocking.
pub(crate) fn release(lease: &str) -> Result<(), AppError> {
    if lease.len() != 32 || !lease.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::InvalidEncryptedMedia(
            "invalid attachment handoff lease".into(),
        ));
    }
    // An I/O error, unlike a malformed lease, tells the host a retry can
    // succeed. Fixed text: no path or OS detail.
    remove_lease(&lease.to_ascii_lowercase()).map_err(|error| {
        AppError::Io(std::io::Error::new(
            error.kind(),
            "attachment handoff copy could not be deleted",
        ))
    })
}

/// Deletes every handoff copy under `directory` that no live lease of this
/// process holds: what a crash or an earlier process left. Returns how many
/// entries it removed. Best effort. Blocking.
pub(crate) fn wipe_stale(directory: &Path) -> usize {
    // Never traverse a symlink: a handoff directory that is one (or is not
    // a directory) is left alone, and child symlinks are unlinked, not
    // followed.
    if !std::fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        return 0;
    }
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        // Checked per entry: a lease registers before its directory exists,
        // so one opened while this runs is always seen here.
        let name = entry.file_name();
        if lock_leases()
            .values()
            .any(|path| path.file_name() == Some(name.as_os_str()))
        {
            continue;
        }
        let path = entry.path();
        let gone = match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(&path).is_ok(),
            Ok(_) => std::fs::remove_file(&path).is_ok(),
            Err(_) => false,
        };
        if gone {
            removed += 1;
        }
    }
    removed
}

/// Live leases of this process whose copies are under `directory`.
#[cfg(test)]
pub(crate) fn live_leases_under(directory: &Path) -> usize {
    lock_leases()
        .values()
        .filter(|path| path.starts_with(directory))
        .count()
}

#[cfg(test)]
#[path = "handoff/tests.rs"]
mod tests;
