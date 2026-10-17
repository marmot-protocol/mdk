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
//! These are the only plaintext files MDK writes. All work here is blocking.
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

fn handoff_error(_: std::io::Error) -> AppError {
    AppError::InvalidEncryptedMedia("attachment handoff I/O failed".into())
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
        let Some(asset) = storage.retained_attachment_asset(
            group,
            &target.message_id_hex,
            &target.source_message_id_hex,
            target.attachment_index,
            crate::unix_now_seconds(),
        )?
        else {
            return Ok(None);
        };
        let descriptor = storage
            .retained_attachment_descriptor(
                group,
                &target.message_id_hex,
                &target.source_message_id_hex,
                target.attachment_index,
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
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\' | ':'))
        .collect::<String>();
    let mut name = cleaned.trim().trim_matches('.').trim().to_owned();
    if name.len() > MAX_NAME_BYTES {
        // Keep the extension when shortening.
        let extension = name
            .rsplit_once('.')
            .map(|(_, ext)| ext)
            .filter(|ext| !ext.is_empty() && ext.len() <= 16)
            .map(|ext| format!(".{ext}"))
            .unwrap_or_default();
        let mut cut = MAX_NAME_BYTES - extension.len();
        while !name.is_char_boundary(cut) {
            cut -= 1;
        }
        name.truncate(cut);
        name.push_str(&extension);
    }
    if name.is_empty() {
        name = FALLBACK_NAME.to_owned();
    }
    let has_extension = name
        .rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty());
    if !has_extension {
        name.push('.');
        name.push_str(extension_for(media_type));
    }
    name
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

/// Removes a lease's directory if it is still registered. Blocking.
fn remove_lease(lease: &str) {
    let directory = lock_leases().remove(lease);
    if let Some(directory) = directory {
        let _ = std::fs::remove_dir_all(directory);
    }
}

/// Writes a handoff copy of `source` and registers its lease. `None` means
/// the body stopped being available while it was copied. A cancelled,
/// failed or short copy leaves nothing. Blocking.
pub(crate) fn open(
    app: &MarmotApp,
    account: &str,
    storage: &SqliteAccountStorage,
    source: HandoffSource,
    control: &MediaFileTransferControl,
) -> Result<Option<AttachmentHandoff>, AppError> {
    control.check()?;
    let policy = storage.attachment_download_policy(
        &crate::runtime::attachment_controls::default_policy(&app.config),
    )?;
    if let Ok(free) = super::attachment_resume::available_space(&app.account_dir(account))
        && let Admission::StorageFull { .. } = (DiskPolicy {
            reserve_bytes: policy.disk_reserve,
        })
        .admit(free, DiskPolicy::handoff_need(source.byte_count))
    {
        return Err(AppError::from(cgka_traits::StorageError::Capacity(
            "not enough free space for the attachment copy".into(),
        )));
    }
    let lease = {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let directory = handoff_directory(app, account).join(&lease);
    // Registered before anything exists, so a concurrent wipe spares it.
    lock_leases().insert(lease.clone(), directory.clone());
    let path = directory.join(&source.file_name);
    match write_copy(app, account, storage, &source, &directory, &path, control) {
        Ok(true) => Ok(Some(AttachmentHandoff {
            lease,
            path,
            byte_count: source.byte_count,
            media_type: source.media_type,
            file_name: source.file_name,
        })),
        Ok(false) => {
            remove_lease(&lease);
            Ok(None)
        }
        Err(error) => {
            remove_lease(&lease);
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
    fs_private::create_dir_all_private(directory).map_err(handoff_error)?;
    let mut file = std::io::BufWriter::with_capacity(
        FILE_TRANSFER_BUFFER_BYTES,
        fs_private::create_new_private(path).map_err(handoff_error)?,
    );
    let now = crate::unix_now_seconds();
    let mut written = 0u64;
    while written < source.byte_count || source.byte_count == 0 {
        control.check()?;
        match storage.retained_attachment_read(
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
        return Err(AppError::InvalidEncryptedMedia(
            "attachment length changed during the copy".into(),
        ));
    }
    control.check()?;
    Ok(true)
}

/// Deletes a lease's copy. An unknown or already released lease is not an
/// error. Blocking.
pub(crate) fn release(lease: &str) -> Result<(), AppError> {
    if lease.len() != 32 || !lease.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::InvalidEncryptedMedia(
            "invalid attachment handoff lease".into(),
        ));
    }
    remove_lease(&lease.to_ascii_lowercase());
    Ok(())
}

/// Deletes every handoff copy under `directory` that no live lease of this
/// process holds: what a crash or an earlier process left. Returns how many
/// entries it removed. Best effort. Blocking.
pub(crate) fn wipe_stale(directory: &Path) -> usize {
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

#[cfg(test)]
#[path = "handoff/tests.rs"]
mod tests;
