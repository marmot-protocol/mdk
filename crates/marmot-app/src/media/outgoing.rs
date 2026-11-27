//! Outgoing attachments on the account's media store (mdk#2314 step 3).
//!
//! A send reserves an upload row per attachment and stages the body as a
//! media file that row owns, refusing a body the disk cannot hold. The wire
//! ciphertext is never written: one pass over the staged file hashes it
//! (Blossom needs the digest before the PUT), and each server attempt streams
//! a second pass. The uploads are then bound to their published descriptors,
//! and the account worker promotes each into the slots of its sent message
//! once that message is confirmed. Store calls run on the blocking pool.
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use storage_sqlite::SqliteAppStorage;

use media_store::{
    Admission, Category, DiskPolicy, FileId, FileState, MediaCatalog, MediaError, MediaStore,
    PromoteOutcome, StageOutcome, StageTarget,
};
use openssl::symm::{Cipher, Crypter, Mode};
use sha2::{Digest, Sha256};
use storage_sqlite::{AttachmentUploadOwner, SqliteAccountStorage};
use transport_nostr_peeler::MarmotNostrSigner;
use zeroize::Zeroizing;

use super::blossom::{FileUploadBody, FileUploadStream};
use super::file_transfer::{
    FILE_TRANSFER_BUFFER_BYTES, MAX_FILE_MEDIA_CIPHERTEXT_BYTES, MEDIA_AEAD_TAG_BYTES,
    MediaFileTransferControl,
};
use super::{
    BlossomHttpTransport, EncryptedMediaVersion, MediaAttachmentReference, MediaLocator,
    MediaOperationPolicy, MediaUploadAttachmentResult, MediaUploadResult,
};
use crate::{AccountMediaStore, AppError, MarmotApp};

/// One staged body, ready to upload: its store file, plaintext length and
/// digest, and the descriptor fields it is published with.
pub(crate) struct StagedSource {
    pub(crate) file: FileId,
    pub(crate) len: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) file_name: String,
    pub(crate) media_type: String,
    pub(crate) dim: Option<String>,
    pub(crate) thumbhash: Option<String>,
}

/// The descriptor fields of one attachment, validated and canonical.
pub(crate) struct OutgoingDescriptor {
    pub(crate) file_name: String,
    pub(crate) media_type: String,
    pub(crate) dim: Option<String>,
    pub(crate) thumbhash: Option<String>,
}

impl OutgoingDescriptor {
    pub(crate) fn new(
        file_name: String,
        media_type: &str,
        dim: Option<String>,
        thumbhash: Option<String>,
        version: EncryptedMediaVersion,
    ) -> Result<Self, AppError> {
        let file_name = match version {
            EncryptedMediaVersion::V1 => file_name.trim().to_owned(),
            EncryptedMediaVersion::V2 => file_name,
        };
        super::validate_outbound_file_name(&file_name, version)?;
        let media_type = match version {
            EncryptedMediaVersion::V1 => super::crypto::canonical_media_type_v1(media_type)?,
            EncryptedMediaVersion::V2 => super::crypto::canonical_media_type_v2(media_type)?,
        };
        Ok(Self {
            file_name,
            media_type,
            dim,
            thumbhash,
        })
    }

    pub(crate) fn staged(self, file: FileId, len: u64, digest: [u8; 32]) -> StagedSource {
        StagedSource {
            file,
            len,
            digest,
            file_name: self.file_name,
            media_type: self.media_type,
            dim: self.dim,
            thumbhash: self.thumbhash,
        }
    }
}

/// Whether `reference` was prepared for a draft attachment described by
/// `file_name` and `media_type`: equal once the draft's strings get the
/// normalization an upload of the reference's version applies (a V1 upload
/// trims the name; both canonicalize the type). A draft stores what the host
/// gave it, so a literal comparison would refuse a correct upload.
pub(crate) fn describes_draft_attachment(
    file_name: &str,
    media_type: &str,
    reference: &super::MediaAttachmentReference,
) -> bool {
    EncryptedMediaVersion::parse(&reference.version)
        .and_then(|version| {
            OutgoingDescriptor::new(file_name.to_owned(), media_type, None, None, version)
        })
        .is_ok_and(|descriptor| {
            descriptor.file_name == reference.file_name
                && descriptor.media_type == reference.media_type
        })
}

/// The send-side error for a store failure: a full disk or database is the
/// typed storage-full error hosts show; nothing else names the store.
pub(crate) fn staging_error(error: MediaError) -> AppError {
    match error {
        MediaError::Capacity => AppError::from(cgka_traits::StorageError::Capacity(
            "not enough free space to stage the attachment".into(),
        )),
        MediaError::Closed => AppError::from(cgka_traits::StorageError::Closed(
            "media store is closed".into(),
        )),
        MediaError::Cancelled => AppError::InvalidEncryptedMedia("media transfer cancelled".into()),
        MediaError::InvalidBody(_) => {
            AppError::InvalidEncryptedMedia("media source changed during reading".into())
        }
        _ => AppError::InvalidEncryptedMedia("media staging failed".into()),
    }
}

fn source_error(_: std::io::Error) -> AppError {
    AppError::InvalidEncryptedMedia("media source unavailable".into())
}

fn crypto_error(_: openssl::error::ErrorStack) -> AppError {
    AppError::InvalidEncryptedMedia("media encryption failed".into())
}

/// A host file opened for staging. Only a regular file (never a symlink)
/// whose identity did not change between the check and the open is read,
/// and only if it is still exactly as long, and as recently modified, when
/// the body has been read.
pub(crate) struct HostSource {
    file: std::fs::File,
    len: u64,
    modified: Option<std::time::SystemTime>,
    read: u64,
    control: Arc<MediaFileTransferControl>,
}

impl HostSource {
    /// Blocking. `expected_len`, when given, must match the file.
    pub(crate) fn open(
        path: &Path,
        expected_len: Option<u64>,
        control: Arc<MediaFileTransferControl>,
    ) -> Result<Self, AppError> {
        control.check()?;
        let before = std::fs::symlink_metadata(path).map_err(source_error)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(AppError::InvalidEncryptedMedia(
                "media source must be a regular file".into(),
            ));
        }
        let file = std::fs::File::open(path).map_err(source_error)?;
        let opened = file.metadata().map_err(source_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if opened.dev() != before.dev() || opened.ino() != before.ino() {
                return Err(AppError::InvalidEncryptedMedia(
                    "media source changed before reading".into(),
                ));
            }
        }
        if !opened.is_file() || expected_len.is_some_and(|len| len != opened.len()) {
            return Err(AppError::InvalidEncryptedMedia(
                "media source length changed".into(),
            ));
        }
        if opened.len() == 0
            || opened.len() > MAX_FILE_MEDIA_CIPHERTEXT_BYTES - MEDIA_AEAD_TAG_BYTES
        {
            return Err(AppError::InvalidEncryptedMedia(
                "media source exceeds file transfer bound".into(),
            ));
        }
        Ok(Self {
            file,
            len: opened.len(),
            modified: opened.modified().ok(),
            read: 0,
            control,
        })
    }

    pub(crate) fn len(&self) -> u64 {
        self.len
    }

    /// After staging: the source must not have changed while it was read.
    fn unchanged(&self) -> bool {
        self.read == self.len
            && self.file.metadata().is_ok_and(|after| {
                after.len() == self.len && after.modified().ok() == self.modified
            })
    }

    /// A second handle on the source, for checking it is unchanged while the
    /// store still holds this one as the body it reads.
    pub(crate) fn watch(&self) -> Result<HostSourceWatch, AppError> {
        Ok(HostSourceWatch {
            file: self.file.try_clone().map_err(source_error)?,
            len: self.len,
            modified: self.modified,
        })
    }
}

/// See [`HostSource::watch`]. The store reads exactly the source's length,
/// so an unchanged length and modification time mean an unchanged body.
pub(crate) struct HostSourceWatch {
    file: std::fs::File,
    len: u64,
    modified: Option<std::time::SystemTime>,
}

impl HostSourceWatch {
    pub(crate) fn unchanged(&self) -> bool {
        self.file
            .metadata()
            .is_ok_and(|after| after.len() == self.len && after.modified().ok() == self.modified)
    }
}

impl Read for HostSource {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.file.read(out)?;
        self.read = self.read.saturating_add(read as u64);
        self.control.advance(self.read);
        Ok(read)
    }
}

/// Stages `body`, exactly `len` bytes, as `target`'s file. Blocking.
pub(crate) fn stage_body<C: MediaCatalog>(
    media: &MediaStore<C>,
    target: &dyn StageTarget,
    body: &mut dyn Read,
    len: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<(FileId, [u8; 32]), AppError> {
    match media
        .stage(
            target,
            Category::Retained,
            body,
            len,
            crate::unix_now_seconds(),
            cancelled,
        )
        .map_err(staging_error)?
    {
        StageOutcome::Staged { id, digest } => Ok((id, digest)),
        StageOutcome::Superseded => Err(AppError::InvalidEncryptedMedia(
            "outgoing attachment reservation unavailable".into(),
        )),
    }
}

/// Stages a host file as `target`'s file, refusing it if the file changed
/// while it was read. Blocking.
pub(crate) fn stage_host_source<C: MediaCatalog>(
    media: &MediaStore<C>,
    target: &dyn StageTarget,
    mut source: HostSource,
) -> Result<(FileId, [u8; 32]), AppError> {
    let control = source.control.clone();
    let len = source.len;
    let (file, digest) = stage_body(media, target, &mut source, len, &|| control.is_cancelled())?;
    if !source.unchanged() {
        let _ = media.release_staged(target, file);
        return Err(AppError::InvalidEncryptedMedia(
            "media source changed during reading".into(),
        ));
    }
    control.check()?;
    Ok((file, digest))
}

/// Encrypts a plaintext of a known length as it is read: the body, then the
/// tag. Produces the same wire bytes as the in-memory cipher. A body shorter
/// or longer than declared is a read error.
pub(crate) struct EncryptingReader<R> {
    input: R,
    cipher: Crypter,
    remaining: u64,
    finished: bool,
    buffer: Zeroizing<Vec<u8>>,
    encrypted: Vec<u8>,
    start: usize,
    end: usize,
}

impl<R: Read> EncryptingReader<R> {
    pub(crate) fn new(
        input: R,
        len: u64,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Self, AppError> {
        let mut cipher = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, key, Some(nonce))
            .map_err(crypto_error)?;
        cipher.pad(false);
        cipher.aad_update(aad).map_err(crypto_error)?;
        Ok(Self {
            input,
            cipher,
            remaining: len,
            finished: false,
            buffer: Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]),
            encrypted: vec![0; FILE_TRANSFER_BUFFER_BYTES + MEDIA_AEAD_TAG_BYTES as usize * 2],
            start: 0,
            end: 0,
        })
    }
}

impl<R: Read> Read for EncryptingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let failed =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "media encryption failed");
        loop {
            if self.start < self.end {
                let count = out.len().min(self.end - self.start);
                out[..count].copy_from_slice(&self.encrypted[self.start..self.start + count]);
                self.start += count;
                return Ok(count);
            }
            if self.finished || out.is_empty() {
                return Ok(0);
            }
            self.start = 0;
            if self.remaining == 0 {
                // Nothing may follow the declared body.
                let mut trailing = [0u8; 1];
                if self.input.read(&mut trailing)? != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "media body grew",
                    ));
                }
                let written = self
                    .cipher
                    .finalize(&mut self.encrypted)
                    .map_err(|_| failed())?;
                let tag = MEDIA_AEAD_TAG_BYTES as usize;
                self.cipher
                    .get_tag(&mut self.encrypted[written..written + tag])
                    .map_err(|_| failed())?;
                self.end = written + tag;
                self.finished = true;
                continue;
            }
            let take = self.remaining.min(FILE_TRANSFER_BUFFER_BYTES as u64) as usize;
            self.input.read_exact(&mut self.buffer[..take])?;
            self.end = self
                .cipher
                .update(&self.buffer[..take], &mut self.encrypted)
                .map_err(|_| failed())?;
            self.remaining -= take as u64;
        }
    }
}

/// What one staged body is encrypted with.
#[derive(Clone)]
struct WireKey {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    aad: Vec<u8>,
}

fn open_staged<C: MediaCatalog>(
    media: &MediaStore<C>,
    file: &FileId,
) -> Result<media_store::MediaReader<C>, AppError> {
    media
        .open_staged_reader(file)
        .map_err(staging_error)?
        .ok_or_else(|| AppError::InvalidEncryptedMedia("staged media unavailable".into()))
}

/// The first pass: the wire ciphertext's SHA-256, read from the staged file
/// and discarded. Blocking.
fn ciphertext_digest<C: MediaCatalog>(
    media: &MediaStore<C>,
    source: &StagedSource,
    wire: &WireKey,
    control: &MediaFileTransferControl,
) -> Result<[u8; 32], AppError> {
    let reader = open_staged(media, &source.file)?;
    let mut encrypted =
        EncryptingReader::new(reader, source.len, &wire.key, &wire.nonce, &wire.aad)?;
    let mut buffer = vec![0; FILE_TRANSFER_BUFFER_BYTES];
    let mut hash = Sha256::new();
    let mut count = 0u64;
    loop {
        control.check()?;
        let read = encrypted
            .read(&mut buffer)
            .map_err(|_| AppError::InvalidEncryptedMedia("staged media unavailable".into()))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
        count += read as u64;
        control.advance(source.len.saturating_add(count));
    }
    Ok(hash.finalize().into())
}

/// The second pass, once per server attempt: the wire ciphertext streamed
/// from the staged file by a blocking task, through a small bounded channel.
/// A ciphertext that differs from the first pass ends the stream with an
/// error before its last chunk.
fn stream_staged<C: MediaCatalog + 'static>(
    media: MediaStore<C>,
    file: FileId,
    len: u64,
    wire: WireKey,
    digest: [u8; 32],
    tasks: crate::runtime::account_worker::WorkerTaskScope,
) -> FileUploadStream {
    let (sender, receiver) = tokio::sync::mpsc::channel::<std::io::Result<Vec<u8>>>(4);
    tasks.spawn_blocking(move || {
        let result = (|| -> std::io::Result<()> {
            let reader = media
                .open_staged_reader(&file)
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::NotFound, "staged media unavailable")
                })?;
            let mut encrypted =
                EncryptingReader::new(reader, len, &wire.key, &wire.nonce, &wire.aad)
                    .map_err(|_| std::io::Error::other("media encryption failed"))?;
            let mut hash = Sha256::new();
            // The last chunk waits for the digest check, so a changed body
            // never reaches the server complete.
            let mut held: Option<Vec<u8>> = None;
            loop {
                let mut chunk = vec![0; FILE_TRANSFER_BUFFER_BYTES];
                let mut filled = 0;
                while filled < chunk.len() {
                    match encrypted.read(&mut chunk[filled..])? {
                        0 => break,
                        read => filled += read,
                    }
                }
                if filled == 0 {
                    break;
                }
                chunk.truncate(filled);
                hash.update(&chunk);
                if let Some(previous) = held.replace(chunk)
                    && sender.blocking_send(Ok(previous)).is_err()
                {
                    // The upload ended; nobody reads the rest.
                    return Ok(());
                }
            }
            if <[u8; 32]>::from(hash.finalize()) != digest {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "staged media changed",
                ));
            }
            if let Some(last) = held {
                let _ = sender.blocking_send(Ok(last));
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = sender.blocking_send(Err(error));
        }
    });
    Box::pin(futures::stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|item| (item, receiver))
    }))
}

/// Uploads every staged body with ordered server fallback, streaming each
/// wire ciphertext from its staged file in two passes. The descriptors carry
/// the staged digests; nothing is written to disk.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_staged<C: MediaCatalog + 'static>(
    media: &MediaStore<C>,
    sources: Vec<StagedSource>,
    servers: &[String],
    source_epoch: u64,
    media_secret: &[u8],
    signer: &dyn MarmotNostrSigner,
    policy: MediaOperationPolicy<'_>,
    transport: &BlossomHttpTransport,
    control: Arc<MediaFileTransferControl>,
    tasks: &crate::runtime::account_worker::WorkerTaskScope,
) -> Result<MediaUploadResult, AppError> {
    use rand::RngCore;
    let mut attachments = Vec::with_capacity(sources.len());
    for source in sources {
        control.check()?;
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let wire = WireKey {
            key: Zeroizing::new(super::crypto::derive_media_file_key(
                media_secret,
                policy.version,
                &source.digest,
                &source.media_type,
                &source.file_name,
            )?),
            nonce,
            aad: super::crypto::media_aad(
                policy.version,
                &source.digest,
                &source.media_type,
                &source.file_name,
            ),
        };
        let (pass_media, pass_wire, pass_control) = (media.clone(), wire.clone(), control.clone());
        let (source, digest) = tasks
            .spawn_blocking(move || {
                let digest = ciphertext_digest(&pass_media, &source, &pass_wire, &pass_control);
                (source, digest)
            })
            .await
            .map_err(|_| AppError::BlockingTask("media file preparation failed".into()))?;
        let digest = digest?;
        let len = source.len + MEDIA_AEAD_TAG_BYTES;
        let (stream_media, file, plaintext_len, stream_tasks) =
            (media.clone(), source.file, source.len, tasks.clone());
        let body = FileUploadBody {
            len,
            digest,
            open: Box::new(move || {
                Ok(stream_staged(
                    stream_media.clone(),
                    file,
                    plaintext_len,
                    wire.clone(),
                    digest,
                    stream_tasks.clone(),
                ))
            }),
        };
        let mut failures = Vec::new();
        let mut uploaded = None;
        let mut timed_out = false;
        for (index, server) in servers.iter().enumerate() {
            control.check()?;
            match super::blossom::upload_blossom_file(
                server,
                &body,
                signer,
                transport,
                control.clone(),
            )
            .await
            {
                Ok(url) => {
                    uploaded = Some(url);
                    break;
                }
                Err(AppError::ExternalSignerRejected) => {
                    return Err(AppError::ExternalSignerRejected);
                }
                Err(error) => {
                    control.check()?;
                    timed_out |= matches!(error, AppError::MediaUploadTimedOut);
                    failures.push(format!(
                        "server {}: {}",
                        index + 1,
                        super::upload_error_summary(&error)
                    ));
                }
            }
        }
        let url = match uploaded {
            Some(url) => url,
            // Same aggregate as the in-memory path: any pre-publication
            // timeout keeps the batch safely retryable.
            None if timed_out => return Err(AppError::MediaUploadTimedOut),
            None => {
                return Err(AppError::BlobStore(format!(
                    "upload failed for all Blossom servers: {}",
                    failures.join("; ")
                )));
            }
        };
        let reference = MediaAttachmentReference {
            locators: vec![MediaLocator {
                kind: "blossom-v1".into(),
                value: url,
            }],
            ciphertext_sha256: hex::encode(digest),
            plaintext_sha256: hex::encode(source.digest),
            nonce_hex: hex::encode(nonce),
            file_name: source.file_name,
            media_type: source.media_type,
            version: policy.version.as_str().to_owned(),
            source_epoch,
            source_epoch_identity: None,
            dim: source.dim,
            thumbhash: source.thumbhash,
        };
        reference.validate_outbound(
            policy.version,
            policy.allowed_locator_kinds,
            policy.allow_loopback_http,
        )?;
        attachments.push(MediaUploadAttachmentResult {
            reference,
            encrypted_size_bytes: len,
        });
    }
    control.check()?;
    Ok(MediaUploadResult {
        attachments,
        sent: None,
    })
}

/// The uploads of one send until message admission takes them over. Dropping
/// it unfinished (a cancelled job) releases them on the blocking pool under
/// the worker's task scope using the already-open storage/media handles (never
/// reopening storage by label after cache eviction, mdk#3801); error paths
/// call [`Self::release`] to finish that before they return. The upload TTL
/// and the media sweep reclaim anything a release misses.
pub(crate) struct OutgoingUploads {
    handles: Option<(SqliteAccountStorage, AccountMediaStore)>,
    tasks: crate::runtime::account_worker::WorkerTaskScope,
    tokens: Vec<Vec<u8>>,
}

impl OutgoingUploads {
    pub(crate) fn with_handles(
        storage: SqliteAccountStorage,
        media: AccountMediaStore,
        tasks: crate::runtime::account_worker::WorkerTaskScope,
    ) -> Self {
        Self {
            handles: Some((storage, media)),
            tasks,
            tokens: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new(app: MarmotApp, account: String) -> Self {
        let handles = app.account_storage(&account).ok().and_then(|storage| {
            app.account_media_store(&account, &storage)
                .ok()
                .map(|media| (storage, media))
        });
        Self {
            handles,
            tasks: crate::runtime::account_worker::WorkerTaskScope::new(),
            tokens: Vec::new(),
        }
    }

    /// An empty guard for the same account, to move into a blocking task that
    /// reserves uploads. If its result is never awaited, dropping it releases
    /// what it reserved.
    pub(crate) fn handoff(&self) -> Self {
        Self {
            handles: self.handles.clone(),
            tasks: self.tasks.clone(),
            tokens: Vec::new(),
        }
    }

    /// Takes over the uploads `other` reserved.
    pub(crate) fn absorb(&mut self, mut other: Self) {
        self.tokens.append(&mut other.tokens);
    }

    pub(crate) fn tokens_mut(&mut self) -> &mut Vec<Vec<u8>> {
        &mut self.tokens
    }

    pub(crate) fn tokens(&self) -> &[Vec<u8>] {
        &self.tokens
    }

    /// Hands the uploads on, bound, to message admission.
    pub(crate) fn into_tokens(mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tokens)
    }

    /// Releases every upload not owned by an admitted message.
    pub(crate) async fn release(mut self) {
        let tokens = std::mem::take(&mut self.tokens);
        let Some((storage, media)) = self.handles.take() else {
            return;
        };
        release_outgoing_uploads(storage, media, &self.tasks, tokens).await;
    }

    /// Releases every upload synchronously on the current blocking thread and
    /// clears `tokens` so a subsequent `Drop` does not spawn a detached task
    /// after a tracked blocking closure has already released its tracker token
    /// (mdk#3801).
    pub(crate) fn release_blocking(&mut self) {
        if self.tokens.is_empty() {
            return;
        }
        let Some((storage, media)) = self.handles.take() else {
            return;
        };
        let tokens = std::mem::take(&mut self.tokens);
        release_uploads_blocking(&storage, &media, &tokens);
    }
}

impl std::fmt::Debug for OutgoingUploads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutgoingUploads")
            .field("uploads", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

impl Drop for OutgoingUploads {
    fn drop(&mut self) {
        if self.tokens.is_empty() {
            return;
        }
        let Some((storage, media)) = self.handles.take() else {
            return;
        };
        let tokens = std::mem::take(&mut self.tokens);
        if tokio::runtime::Handle::try_current().is_ok() {
            self.tasks
                .spawn_blocking(move || release_uploads_blocking(&storage, &media, &tokens));
        }
    }
}

/// Releases outgoing uploads no admitted message owns: their rows, then
/// their staged files. Failures are logged; the TTL prune and media sweep
/// retry them.
pub(crate) async fn release_outgoing_uploads(
    storage: SqliteAccountStorage,
    media: AccountMediaStore,
    tasks: &crate::runtime::account_worker::WorkerTaskScope,
    tokens: Vec<Vec<u8>>,
) {
    if tokens.is_empty() {
        return;
    }
    let _ = tasks
        .spawn_blocking(move || release_uploads_blocking(&storage, &media, &tokens))
        .await;
}

fn release_uploads_blocking(
    storage: &SqliteAccountStorage,
    media: &AccountMediaStore,
    tokens: &[Vec<u8>],
) {
    let released = (|| -> Result<(), AppError> {
        let files = tokens
            .iter()
            .filter_map(|token| {
                storage
                    .app_storage()
                    .attachment_upload_file(token)
                    .ok()
                    .flatten()
            })
            .collect::<Vec<_>>();
        storage.app_storage().abandon_attachment_uploads(tokens)?;
        media.unlink_released(&files);
        Ok(())
    })();
    if released.is_err() {
        tracing::warn!(target: "marmot_app::media", method = "outgoing_upload_release",
            "outgoing upload release deferred");
    }
}

/// One send's staging context: the account's database and media store, the
/// free-disk rule, and where its uploads are recorded.
pub(crate) struct SendStaging {
    directory: std::path::PathBuf,
    storage: SqliteAccountStorage,
    media: AccountMediaStore,
    disk: DiskPolicy,
    group: String,
    source_epoch: u64,
}

impl SendStaging {
    /// Blocking. Prunes expired uploads first, so the row cap counts live
    /// ones only. Uses already-open storage/media handles so background
    /// staging never reopens storage by label after cache eviction (mdk#3801).
    pub(crate) fn open_with_handles(
        storage: SqliteAccountStorage,
        media: AccountMediaStore,
        directory: std::path::PathBuf,
        fallback_policy: &storage_sqlite::AttachmentDownloadPolicy,
        group: &cgka_traits::GroupId,
        source_epoch: u64,
    ) -> Result<Self, AppError> {
        if storage
            .app_storage()
            .prune_attachment_uploads(crate::unix_now_seconds(), 64)
            .is_err()
        {
            tracing::warn!(target: "marmot_app::media", method = "outgoing_upload_prune",
                "outgoing upload cleanup deferred");
        }
        let disk = send_disk_policy_with_fallback(&storage, fallback_policy)?;
        Ok(Self {
            directory,
            disk,
            storage,
            media,
            group: hex::encode(group.as_slice()),
            source_epoch,
        })
    }

    /// Blocking. Convenience constructor for unit tests.
    #[cfg(test)]
    pub(crate) fn open(
        app: &MarmotApp,
        account: &str,
        group: &cgka_traits::GroupId,
        source_epoch: u64,
    ) -> Result<Self, AppError> {
        let storage = app.account_storage(account)?;
        let media = app.account_media_store(account, &storage)?;
        let fallback_policy = crate::runtime::attachment_controls::default_policy(&app.config);
        Self::open_with_handles(
            storage,
            media,
            app.account_dir(account),
            &fallback_policy,
            group,
            source_epoch,
        )
    }

    pub(crate) fn media(&self) -> &AccountMediaStore {
        &self.media
    }

    fn admit(&self, len: u64) -> Result<(), AppError> {
        admit_send_body_at(&self.directory, self.disk, len)
    }

    /// Admits, reserves and stages one body, recording its upload in
    /// `uploads` as soon as it is reserved. Blocking.
    pub(crate) fn stage(
        &self,
        uploads: &mut Vec<Vec<u8>>,
        len: u64,
        stage: impl FnOnce(&AccountMediaStore, &dyn StageTarget) -> Result<(FileId, [u8; 32]), AppError>,
    ) -> Result<(FileId, [u8; 32]), AppError> {
        self.admit(len)?;
        let token = self
            .storage
            .app_storage()
            .reserve_attachment_upload(&self.group, self.source_epoch, crate::unix_now_seconds())?
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia(
                    "too many attachments are awaiting publication".into(),
                )
            })?;
        uploads.push(token.clone());
        stage(
            &self.media,
            &self.storage.app_storage().attachment_upload_stage(&token),
        )
    }

    /// Binds each upload to its published descriptor. Blocking.
    pub(crate) fn bind(
        &self,
        tokens: &[Vec<u8>],
        result: &MediaUploadResult,
    ) -> Result<(), AppError> {
        let slots = result
            .attachments
            .iter()
            .map(|attachment| {
                Ok((
                    serde_json::to_value(attachment.reference.imeta_tag()).map_err(|_| {
                        AppError::InvalidEncryptedMedia("invalid upload descriptor".into())
                    })?,
                    super::media_hash_from_reference(&attachment.reference)?,
                ))
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        self.storage
            .app_storage()
            .bind_attachment_uploads(tokens, &slots)?;
        Ok(())
    }
}

/// The disk reserve a local copy of an outgoing body must leave. Blocking.
pub(crate) fn send_disk_policy(
    app: &MarmotApp,
    storage: &SqliteAccountStorage,
) -> Result<DiskPolicy, AppError> {
    let fallback = crate::runtime::attachment_controls::default_policy(&app.config);
    send_disk_policy_with_fallback(storage, &fallback)
}

fn send_disk_policy_with_fallback(
    storage: &SqliteAccountStorage,
    fallback: &storage_sqlite::AttachmentDownloadPolicy,
) -> Result<DiskPolicy, AppError> {
    let policy = storage.app_storage().attachment_download_policy(fallback)?;
    Ok(DiskPolicy {
        reserve_bytes: policy.disk_reserve,
    })
}

/// Refuses a `len`-byte body the volume cannot hold beyond `disk`'s reserve.
/// Unknown free space admits it: the write itself then reports a full disk.
pub(crate) fn admit_send_body(
    app: &MarmotApp,
    account: &str,
    disk: DiskPolicy,
    len: u64,
) -> Result<(), AppError> {
    admit_send_body_at(&app.account_dir(account), disk, len)
}

fn admit_send_body_at(
    directory: &std::path::Path,
    disk: DiskPolicy,
    len: u64,
) -> Result<(), AppError> {
    let Ok(free) = super::attachment_resume::available_space(directory) else {
        return Ok(());
    };
    match disk.admit(free, DiskPolicy::send_need(len)) {
        Admission::Admitted => Ok(()),
        Admission::StorageFull { .. } => Err(staging_error(MediaError::Capacity)),
    }
}

/// Stages each draft attachment `request` names as an upload, read from the
/// copy the draft holds (inline bytes or its staged file), within the
/// aggregate wire bound. The draft keeps its own copy until it is sent or
/// cleared. Blocking.
pub(crate) fn stage_draft_sources(
    staging: &SendStaging,
    tokens: &mut Vec<Vec<u8>>,
    request: super::file_transfer::DraftUploadRequest,
    version: EncryptedMediaVersion,
    control: &MediaFileTransferControl,
) -> Result<Vec<StagedSource>, AppError> {
    let sources = staging
        .storage
        .app_storage()
        .message_draft_upload_sources_if_revision(&request.revision, &request.attachment_ids)
        .map_err(|error| crate::drafts::revision_error(error, request.revision.group_id_hex()))?;
    let cancelled = || control.is_cancelled();
    let mut total = 0u64;
    let mut staged = Vec::with_capacity(sources.len());
    for source in sources {
        control.check()?;
        let attachment = source.attachment;
        let descriptor = OutgoingDescriptor::new(
            attachment.file_name,
            &attachment.media_type,
            attachment.dim,
            attachment.thumbhash,
            version,
        )?;
        let len = attachment.plaintext_size;
        total = total
            .checked_add(len.saturating_add(MEDIA_AEAD_TAG_BYTES))
            .filter(|total| *total <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("file attachments exceed transfer bound".into())
            })?;
        let (file, digest) = match source.body {
            storage_sqlite::MessageDraftUploadBody::Inline(bytes) => {
                staging.stage(tokens, len, |media, target| {
                    stage_body(
                        media,
                        target,
                        &mut std::io::Cursor::new(Zeroizing::new(bytes)),
                        len,
                        &cancelled,
                    )
                })?
            }
            storage_sqlite::MessageDraftUploadBody::File { id, digest } => {
                staging.stage(tokens, len, |media, target| {
                    let reader = media
                        .open_staged_reader(&id)
                        .map_err(staging_error)?
                        .ok_or_else(|| {
                            AppError::InvalidMessageDraft(
                                "draft attachment is no longer available".into(),
                            )
                        })?;
                    let mut body = ProgressReader {
                        inner: reader,
                        read: 0,
                        control,
                    };
                    let (file, staged) = stage_body(media, target, &mut body, len, &cancelled)?;
                    // The store authenticates every segment; a different
                    // digest means the draft's file is not what was staged.
                    if staged != digest {
                        let _ = media.release_staged(target, file);
                        return Err(AppError::InvalidMessageDraft(
                            "draft attachment no longer matches its digest".into(),
                        ));
                    }
                    Ok((file, staged))
                })?
            }
        };
        staged.push(descriptor.staged(file, len, digest));
    }
    control.check()?;
    Ok(staged)
}

/// Reports bytes read as preparation progress.
struct ProgressReader<'a, R> {
    inner: R,
    read: u64,
    control: &'a MediaFileTransferControl,
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(out)?;
        self.read = self.read.saturating_add(read as u64);
        self.control.advance(self.read);
        Ok(read)
    }
}

impl std::fmt::Debug for SendStaging {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendStaging").finish_non_exhaustive()
    }
}

/// Uploads promoted per worker pass.
pub(crate) const UPLOAD_PROMOTION_BATCH: usize = 32;

/// One page of file-backed uploads of confirmed sent messages, after `after`,
/// promoted into their slots. An upload whose staged file was lost is dropped
/// so its message downloads its own media instead. Returns the cursor for the
/// next page (`None` once a page comes back short) and whether any slot
/// gained a body. Blocking.
pub(crate) fn promote_uploads(
    storage: &SqliteAppStorage,
    media: &AccountMediaStore,
    after: Option<&AttachmentUploadOwner>,
    limit: usize,
) -> Result<(Option<AttachmentUploadOwner>, bool), AppError> {
    let owners = storage.attachment_upload_owners(after, limit)?;
    let mut promoted = false;
    for owner in &owners {
        let target = storage.attachment_upload_promotion(
            &owner.group_id_hex,
            &owner.message_id_hex,
            &owner.token,
            crate::unix_now_seconds,
        );
        match media.promote(&target, owner.file) {
            Ok(PromoteOutcome::Ready | PromoteOutcome::Existing(_)) => promoted = true,
            Ok(PromoteOutcome::Released) => {}
            Ok(PromoteOutcome::Superseded) => {
                if matches!(media.file_state(&owner.file), Ok(Some(FileState::Lost)))
                    && storage.drop_lost_attachment_upload(&owner.token, owner.file)?
                {
                    media.unlink_released(&[owner.file]);
                    promoted = true;
                }
            }
            Err(MediaError::Closed) => return Err(staging_error(MediaError::Closed)),
            Err(_) => {
                tracing::warn!(target: "marmot_app::media", method = "outgoing_upload_promotion",
                    "outgoing upload promotion deferred");
            }
        }
    }
    let next = (owners.len() == limit)
        .then(|| owners.last().cloned())
        .flatten();
    Ok((next, promoted))
}

#[cfg(test)]
#[path = "outgoing/tests.rs"]
mod tests;
