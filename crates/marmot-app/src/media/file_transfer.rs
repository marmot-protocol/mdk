//! File-backed media preparation. The wire ciphertext remains a single AEAD
//! message; chunking is an implementation detail, not a protocol change.
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use openssl::symm::{Cipher, Crypter, Mode};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use crate::AppError;

pub(crate) const FILE_TRANSFER_BUFFER_BYTES: usize = 64 * 1024;
pub(crate) const MEDIA_AEAD_TAG_BYTES: u64 = 16;
// Leave room below SQLite's default 1,000,000,000-byte row bound. Legacy
// in-memory media keeps its existing, independently checked resource limits.
pub const MAX_FILE_MEDIA_CIPHERTEXT_BYTES: u64 = 900 * 1024 * 1024;

/// Host-local input only. Neither its path nor its bytes enter message tags.
#[derive(Clone)]
pub struct MediaFileUploadAttachmentRequest {
    pub source_path: String,
    pub expected_size: Option<u64>,
    pub file_name: String,
    pub media_type: String,
    pub dim: Option<String>,
    pub thumbhash: Option<String>,
}

#[derive(Clone)]
pub struct MediaFileUploadRequest {
    pub attachments: Vec<MediaFileUploadAttachmentRequest>,
    pub caption: Option<String>,
    pub send: bool,
    pub blossom_server: Option<String>,
    pub message_tags: Vec<Vec<String>>,
}

impl MediaFileUploadRequest {
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        if self.attachments.is_empty() || self.attachments.len() > 64 {
            return Err(AppError::InvalidEncryptedMedia(
                "invalid file attachment count".into(),
            ));
        }
        // Every file contributes a tag even when its source size is unknown.
        // Known batches must fail before expensive snapshot/encryption work.
        let mut declared = self.attachments.len() as u64 * MEDIA_AEAD_TAG_BYTES;
        for attachment in &self.attachments {
            if attachment.source_path.is_empty() {
                return Err(AppError::InvalidEncryptedMedia(
                    "media source unavailable".into(),
                ));
            }
            if let Some(size) = attachment.expected_size {
                declared = declared.checked_add(size).ok_or_else(|| {
                    AppError::InvalidEncryptedMedia("file attachment size overflow".into())
                })?;
                if size == 0 || declared > MAX_FILE_MEDIA_CIPHERTEXT_BYTES {
                    return Err(AppError::InvalidEncryptedMedia(
                        "file attachments exceed transfer bound".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) enum MediaUploadPayload {
    Bytes(super::MediaUploadRequest),
    Files(MediaFileUploadRequest, Arc<MediaFileTransferControl>),
}

impl MediaUploadPayload {
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        match self {
            Self::Bytes(request) => super::validate_media_upload_batch(&request.attachments),
            Self::Files(request, control) => {
                control.check()?;
                request.validate()
            }
        }
    }
    pub(crate) fn server(&self) -> &Option<String> {
        match self {
            Self::Bytes(r) => &r.blossom_server,
            Self::Files(r, _) => &r.blossom_server,
        }
    }
    pub(crate) fn caption(&self) -> &Option<String> {
        match self {
            Self::Bytes(r) => &r.caption,
            Self::Files(r, _) => &r.caption,
        }
    }
    pub(crate) fn tags(&self) -> &[Vec<String>] {
        match self {
            Self::Bytes(r) => &r.message_tags,
            Self::Files(r, _) => &r.message_tags,
        }
    }
    pub(crate) fn send(&self) -> bool {
        match self {
            Self::Bytes(r) => r.send,
            Self::Files(r, _) => r.send,
        }
    }
}

/// One operation's cancellation and monotonic preparation/transfer counters.
#[derive(Default)]
pub struct MediaFileTransferControl {
    cancelled: tokio_util::sync::CancellationToken,
    processed_bytes: AtomicU64,
}

impl MediaFileTransferControl {
    pub fn cancel(&self) {
        self.cancelled.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.is_cancelled()
    }

    pub fn processed_bytes(&self) -> u64 {
        self.processed_bytes.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        self.cancelled.cancelled().await;
    }

    pub(crate) fn check(&self) -> Result<(), AppError> {
        if self.is_cancelled() {
            return Err(AppError::InvalidEncryptedMedia(
                "media transfer cancelled".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn advance(&self, bytes: u64) {
        self.processed_bytes.fetch_max(bytes, Ordering::AcqRel);
    }
}

/// A private temporary file that is deleted on every unfinished/error path.
/// No path, payload, hash or metadata appears in Debug output.
pub(crate) struct PrivateMediaFile {
    file: NamedTempFile,
    pub(crate) len: u64,
    pub(crate) digest: [u8; 32],
}

impl PrivateMediaFile {
    pub(super) fn create(directory: &Path) -> Result<Self, AppError> {
        fs_private::create_dir_all_private(directory).map_err(staging_error)?;
        let file = tempfile::Builder::new()
            .prefix(MEDIA_STAGING_PREFIX)
            .tempfile_in(directory)
            .map_err(staging_error)?;
        // NamedTempFile creates the file owner-only on Unix, before it is
        // reachable; the containing directory is restrictive on every path.
        Ok(Self {
            file,
            len: 0,
            digest: [0; 32],
        })
    }

    pub(crate) fn reader(&self) -> Result<File, AppError> {
        let mut file = self.file.reopen().map_err(staging_error)?;
        file.rewind().map_err(staging_error)?;
        Ok(file)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn path(&self) -> &Path {
        self.file.path()
    }

    pub(super) fn writer(&self) -> Result<File, AppError> {
        self.reader()
    }
}

const MEDIA_STAGING_DIRECTORY: &str = "media-staging";
const MEDIA_STAGING_PREFIX: &str = "media-transfer-";
/// Live operations rewrite or reopen their snapshots well inside this age.
const STALE_MEDIA_STAGING_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
const MEDIA_STAGING_SWEEP_LIMIT: usize = 256;

/// Per-account private staging directory for downloaded ciphertext served
/// without a validator. Removed with the account directory.
pub(crate) fn media_staging_directory(app: &crate::MarmotApp, account: &str) -> PathBuf {
    app.account_dir(account).join(MEDIA_STAGING_DIRECTORY)
}

/// Bounded removal of crash-orphaned snapshots (RAII deletion cannot run after
/// process death). Only regular files with this module's prefix, older than
/// [`STALE_MEDIA_STAGING_AGE`], are removed; symlinks and other names are left.
/// Best effort: errors are skipped and counted only in aggregate by callers.
pub(crate) fn sweep_stale_media_staging(directory: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for entry in entries.take(MEDIA_STAGING_SWEEP_LIMIT).flatten() {
        let is_ours = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(MEDIA_STAGING_PREFIX));
        let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let stale = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= STALE_MEDIA_STAGING_AGE);
        if is_ours && metadata.is_file() && stale && std::fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn staging_error(_: std::io::Error) -> AppError {
    AppError::InvalidEncryptedMedia("media staging I/O failed".into())
}

fn crypto_error(_: openssl::error::ErrorStack) -> AppError {
    AppError::InvalidEncryptedMedia("media authentication failed".into())
}

/// The job's checkpoint reader, as the account's media store opens it.
pub(crate) type WireCiphertext = media_store::CheckpointReader<storage_sqlite::SqliteMediaCatalog>;

/// Where a downloaded ciphertext sits until publication (mdk#2314).
pub(crate) enum CiphertextSource {
    /// The job's `.wire` checkpoint, recorded through its whole length and
    /// held open by the media store's reader.
    Wire(WireCiphertext),
    /// A private staging file, for a body served without a strong validator,
    /// which cannot checkpoint.
    Staged(PrivateMediaFile),
}

/// A complete downloaded ciphertext whose digest matched its reference.
pub(crate) struct DownloadedCiphertext {
    pub(crate) source: CiphertextSource,
    pub(crate) len: u64,
    pub(crate) digest: [u8; 32],
}

impl DownloadedCiphertext {
    /// Staging this ciphertext occupies that the worker's free-space
    /// measurement will not see once it is dropped. A wire checkpoint stays.
    pub(crate) fn staged_bytes(&self) -> u64 {
        match self.source {
            CiphertextSource::Wire(_) => 0,
            CiphertextSource::Staged(_) => self.len,
        }
    }

    /// Reads the ciphertext from its first byte. Blocking.
    pub(crate) fn reader(&mut self) -> Result<Box<dyn Read + '_>, AppError> {
        match &mut self.source {
            CiphertextSource::Wire(reader) => {
                reader
                    .rewind()
                    .map_err(|_| AppError::BlobStore("file checkpoint unavailable".into()))?;
                Ok(Box::new(reader))
            }
            CiphertextSource::Staged(file) => Ok(Box::new(file.reader()?)),
        }
    }

    /// Done with the ciphertext: the store unlinks a wire file whose row is
    /// gone (a published job's), and staging is deleted on drop. Blocking.
    pub(crate) fn finish(self) {
        if let CiphertextSource::Wire(reader) = self.source {
            let _ = reader.finish();
        }
    }
}

/// A downloaded file body, authenticated before its receipt, with what
/// publication needs to decrypt it again as it writes the store file. No
/// plaintext copy is ever written outside the store.
pub(crate) struct DownloadedFileBody {
    pub(crate) ciphertext: DownloadedCiphertext,
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    aad: Vec<u8>,
    pub(crate) plaintext_len: u64,
}

impl DownloadedFileBody {
    pub(crate) fn new(
        ciphertext: DownloadedCiphertext,
        key: [u8; 32],
        nonce: [u8; 12],
        aad: Vec<u8>,
    ) -> Self {
        Self {
            plaintext_len: ciphertext.len.saturating_sub(MEDIA_AEAD_TAG_BYTES),
            ciphertext,
            key: Zeroizing::new(key),
            nonce,
            aad,
        }
    }

    /// The plaintext, decrypted as it is read. Authentication was checked
    /// before the receipt; the tag is checked again at the end, and the store
    /// checks the plaintext digest. Blocking.
    pub(crate) fn plaintext_reader(&mut self) -> Result<DecryptingReader<'_>, AppError> {
        let len = self.ciphertext.len;
        let input = self.ciphertext.reader()?;
        DecryptingReader::new(input, len, &self.key, &self.nonce, &self.aad)
    }
}

/// The body length of a `len`-byte ciphertext: all but its trailing tag.
fn ciphertext_body_len(len: u64) -> Result<u64, AppError> {
    len.checked_sub(MEDIA_AEAD_TAG_BYTES)
        .filter(|_| len <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
        .ok_or_else(|| AppError::InvalidEncryptedMedia("invalid media ciphertext length".into()))
}

fn decryptor(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8]) -> Result<Crypter, AppError> {
    let mut cipher = Crypter::new(Cipher::chacha20_poly1305(), Mode::Decrypt, key, Some(nonce))
        .map_err(crypto_error)?;
    cipher.pad(false);
    cipher.aad_update(aad).map_err(crypto_error)?;
    Ok(cipher)
}

/// Reads the trailing tag after the body and confirms nothing follows it.
fn read_tag(input: &mut dyn Read) -> Result<[u8; 16], AppError> {
    let mut tag = [0u8; 16];
    input.read_exact(&mut tag).map_err(staging_error)?;
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(staging_error)? != 0 {
        return Err(AppError::InvalidEncryptedMedia(
            "media ciphertext grew".into(),
        ));
    }
    Ok(tag)
}

/// Authenticate and hash the complete `len`-byte ciphertext read from
/// `input`, writing the plaintext to `output` (a discard sink when only
/// verifying). Reads once, front to back; never retains a whole array.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decrypt_file_to_writer(
    input: &mut dyn Read,
    len: u64,
    ciphertext_digest: [u8; 32],
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext_hash: [u8; 32],
    control: &MediaFileTransferControl,
    output: &mut dyn Write,
) -> Result<(), AppError> {
    control.check()?;
    let body_len = ciphertext_body_len(len)?;
    let mut cipher = decryptor(key, nonce, aad)?;
    let mut buffer = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]);
    let mut decrypted = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES + 16]);
    let mut ciphertext_hash = Sha256::new();
    let mut hash = Sha256::new();
    let mut remaining = body_len;
    while remaining > 0 {
        control.check()?;
        let take = remaining.min(FILE_TRANSFER_BUFFER_BYTES as u64) as usize;
        input
            .read_exact(&mut buffer[..take])
            .map_err(staging_error)?;
        ciphertext_hash.update(&buffer[..take]);
        let written = cipher
            .update(&buffer[..take], &mut decrypted)
            .map_err(crypto_error)?;
        output
            .write_all(&decrypted[..written])
            .map_err(staging_error)?;
        hash.update(&decrypted[..written]);
        remaining -= take as u64;
        control.advance(body_len - remaining);
    }
    let tag = read_tag(input)?;
    ciphertext_hash.update(tag);
    if <[u8; 32]>::from(ciphertext_hash.finalize()) != ciphertext_digest {
        return Err(AppError::InvalidEncryptedMedia(
            "media ciphertext hash mismatch".into(),
        ));
    }
    cipher.set_tag(&tag).map_err(crypto_error)?;
    let written = cipher.finalize(&mut decrypted).map_err(crypto_error)?;
    output
        .write_all(&decrypted[..written])
        .map_err(staging_error)?;
    hash.update(&decrypted[..written]);
    let digest: [u8; 32] = hash.finalize().into();
    if digest != plaintext_hash {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext hash mismatch".into(),
        ));
    }
    control.check()?;
    Ok(())
}

/// Decrypts a ciphertext as it is read, for publication straight into the
/// media store. A failed tag at the end is a read error, so the store
/// abandons the pending file; its plaintext never left the store's own
/// encryption.
pub(crate) struct DecryptingReader<'a> {
    input: Box<dyn Read + 'a>,
    cipher: Crypter,
    remaining: u64,
    finished: bool,
    buffer: Zeroizing<Vec<u8>>,
    decrypted: Zeroizing<Vec<u8>>,
    start: usize,
    end: usize,
}

impl<'a> DecryptingReader<'a> {
    fn new(
        input: Box<dyn Read + 'a>,
        len: u64,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Self, AppError> {
        Ok(Self {
            input,
            cipher: decryptor(key, nonce, aad)?,
            remaining: ciphertext_body_len(len)?,
            finished: false,
            buffer: Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]),
            decrypted: Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES + 16]),
            start: 0,
            end: 0,
        })
    }
}

impl Read for DecryptingReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let invalid =
            || std::io::Error::new(std::io::ErrorKind::InvalidData, "media decryption failed");
        loop {
            if self.start < self.end {
                let count = out.len().min(self.end - self.start);
                out[..count].copy_from_slice(&self.decrypted[self.start..self.start + count]);
                self.start += count;
                return Ok(count);
            }
            if self.finished || out.is_empty() {
                return Ok(0);
            }
            self.start = 0;
            if self.remaining == 0 {
                let tag = read_tag(self.input.as_mut()).map_err(|_| invalid())?;
                self.cipher.set_tag(&tag).map_err(|_| invalid())?;
                self.end = self
                    .cipher
                    .finalize(&mut self.decrypted)
                    .map_err(|_| invalid())?;
                self.finished = true;
                continue;
            }
            let take = self.remaining.min(FILE_TRANSFER_BUFFER_BYTES as u64) as usize;
            self.input.read_exact(&mut self.buffer[..take])?;
            self.end = self
                .cipher
                .update(&self.buffer[..take], &mut self.decrypted)
                .map_err(|_| invalid())?;
            self.remaining -= take as u64;
        }
    }
}

/// Receive without assembling ciphertext or plaintext arrays, and
/// authenticate the ciphertext without writing plaintext anywhere. The caller
/// retains source/attempt permission and publishes the body into the media
/// store, decrypting it again as it writes.
#[allow(clippy::too_many_arguments)] // Shared media policy, protected sink and operation controls.
pub(crate) async fn download_file(
    reference: super::MediaAttachmentReference,
    media_secret: &[u8],
    endpoints: &[crate::AppBlobEndpoint],
    allowed_kinds: &[String],
    transport: &super::BlossomHttpTransport,
    directory: PathBuf,
    max_bytes: u64,
    control: Arc<MediaFileTransferControl>,
    observation: Arc<super::attachment_resume::AttachmentResume>,
) -> Result<DownloadedFileBody, super::AttachmentDownloadFailure> {
    reference
        .validate(transport.allow_loopback_http)
        .map_err(|error| super::AttachmentDownloadFailure::Stop(AppError::from(error)))?;
    let cipher_hash: [u8; 32] = hex::decode(&reference.ciphertext_sha256)
        .map_err(AppError::from)?
        .try_into()
        .map_err(|_| AppError::InvalidEncryptedMedia("invalid media ciphertext digest".into()))?;
    let plaintext_hash = super::crypto::media_hash_from_reference(&reference)?;
    let nonce = super::crypto::media_nonce_from_reference(&reference)?;
    let version = super::EncryptedMediaVersion::parse(&reference.version)?;
    let media_type = match version {
        super::EncryptedMediaVersion::V1 => {
            super::crypto::canonical_media_type_v1(&reference.media_type)?
        }
        super::EncryptedMediaVersion::V2 => {
            super::crypto::canonical_media_type_v2(&reference.media_type)?
        }
    };
    let key = Zeroizing::new(super::crypto::derive_media_file_key(
        media_secret,
        version,
        &plaintext_hash,
        &media_type,
        &reference.file_name,
    )?);
    let aad = super::crypto::media_aad(version, &plaintext_hash, &media_type, &reference.file_name);
    let mut urls = reference
        .locators
        .iter()
        .filter(|locator| {
            locator.kind == "blossom-v1"
                && super::locator_kind_allowed(&locator.kind, allowed_kinds)
        })
        .map(|locator| locator.value.clone())
        .collect::<Vec<_>>();
    if super::locator_kind_allowed("blossom-v1", allowed_kinds) {
        for endpoint in endpoints
            .iter()
            .filter(|endpoint| endpoint.locator_kind == "blossom-v1")
        {
            let url =
                super::blossom::blossom_blob_url(&endpoint.base_url, &reference.ciphertext_sha256);
            if !urls.contains(&url) {
                urls.push(url);
            }
        }
    }
    if urls.is_empty() {
        return Err(super::AttachmentDownloadFailure::Stop(
            AppError::MediaUnfetchable("no usable file media locator".into()),
        ));
    }
    let mut failures = Vec::new();
    let mut retryable = false;
    let mut size_failure = None;
    let deadline = tokio::time::Instant::now() + transport.transfer_timeout();
    let expected_locator_hash = hex::encode(cipher_hash);
    for (index, url) in urls.iter().enumerate() {
        control.check()?;
        if super::blossom::blossom_content_hash_from_url(url).as_deref()
            != Some(expected_locator_hash.as_str())
        {
            failures.push(format!(
                "locator {}: media locator hash mismatch",
                index + 1
            ));
            continue;
        }
        let candidate_deadline = super::progressing_candidate_deadline(
            tokio::time::Instant::now(),
            deadline,
            index + 1 < urls.len(),
            transport.fallback_reserve(),
        );
        let remaining = candidate_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let candidate_transport = transport.clone().with_file_download_timeout(remaining);
        let encrypted = match super::blossom::fetch_blossom_file_with_transport(
            url,
            &candidate_transport,
            &directory,
            cipher_hash,
            max_bytes,
            control.clone(),
            observation.clone(),
        )
        .await
        {
            Ok(file) => file,
            Err(error) => {
                control.check()?;
                match &error {
                    super::AttachmentDownloadFailure::Retry(_) => retryable = true,
                    super::AttachmentDownloadFailure::SizeLimit(_, size) => {
                        size_failure = Some(*size)
                    }
                    // Disk pressure is not locator-specific; park with the checkpoint.
                    super::AttachmentDownloadFailure::StorageBlocked { .. } => return Err(error),
                    _ => {}
                }
                failures.push(format!(
                    "locator {}: {}",
                    index + 1,
                    super::upload_error_summary(&error.into_error())
                ));
                continue;
            }
        };
        // Authenticate into a discard sink: nothing is written, and the
        // receipt is recorded only for a body that verifies.
        let decryption_control = control.clone();
        let verify_key = key.clone();
        let verify_aad = aad.clone();
        let (encrypted, result) = tokio::task::spawn_blocking(move || {
            let mut encrypted = encrypted;
            let (len, digest) = (encrypted.len, encrypted.digest);
            let result = encrypted.reader().and_then(|mut input| {
                decrypt_file_to_writer(
                    input.as_mut(),
                    len,
                    digest,
                    &verify_key,
                    &nonce,
                    &verify_aad,
                    plaintext_hash,
                    &decryption_control,
                    &mut std::io::sink(),
                )
            });
            (encrypted, result)
        })
        .await
        .map_err(|_| AppError::BlockingTask("file media verification failed".into()))?;
        control.check()?;
        match result {
            Ok(()) => {
                return Ok(DownloadedFileBody::new(encrypted, *key, nonce, aad));
            }
            Err(_) => failures.push(format!(
                "locator {}: file integrity verification failed",
                index + 1
            )),
        }
    }
    let error = AppError::MediaDownloadFailed(format!(
        "file download failed for all locators: {}",
        failures.join("; ")
    ));
    Err(if retryable {
        super::AttachmentDownloadFailure::Retry(error)
    } else if let Some(size) = size_failure {
        super::AttachmentDownloadFailure::SizeLimit(error, size)
    } else {
        super::AttachmentDownloadFailure::Stop(error)
    })
}

#[cfg(test)]
mod tests;
