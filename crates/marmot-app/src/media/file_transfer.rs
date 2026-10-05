//! File-backed media preparation. The wire ciphertext remains a single AEAD
//! message; chunking is an implementation detail, not a protocol change.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
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

/// Per-account private snapshot directory. Removed with the account directory.
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

/// Snapshot one source without trusting provider metadata or retaining a
/// whole-file array. Only the completed private snapshot is used afterwards.
pub(crate) fn snapshot_source(
    source: &Path,
    directory: &Path,
    expected_len: Option<u64>,
    control: &MediaFileTransferControl,
) -> Result<PrivateMediaFile, AppError> {
    control.check()?;
    let before = std::fs::symlink_metadata(source).map_err(staging_error)?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(AppError::InvalidEncryptedMedia(
            "media source must be a regular file".into(),
        ));
    }
    let mut input = File::open(source).map_err(staging_error)?;
    let opened = input.metadata().map_err(staging_error)?;
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
    let max = MAX_FILE_MEDIA_CIPHERTEXT_BYTES - MEDIA_AEAD_TAG_BYTES;
    if opened.len() == 0 || opened.len() > max {
        return Err(AppError::InvalidEncryptedMedia(
            "media source exceeds file transfer bound".into(),
        ));
    }
    let mut output = PrivateMediaFile::create(directory)?;
    let mut buffer = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]);
    let mut hash = Sha256::new();
    loop {
        control.check()?;
        let count = input.read(&mut buffer).map_err(staging_error)?;
        if count == 0 {
            break;
        }
        output.len = output
            .len
            .checked_add(count as u64)
            .filter(|len| *len <= max)
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("media source exceeds file transfer bound".into())
            })?;
        hash.update(&buffer[..count]);
        output
            .file
            .write_all(&buffer[..count])
            .map_err(staging_error)?;
        control.advance(output.len);
    }
    let after = input.metadata().map_err(staging_error)?;
    if output.len != opened.len()
        || after.len() != opened.len()
        || after.modified().ok() != opened.modified().ok()
    {
        return Err(AppError::InvalidEncryptedMedia(
            "media source changed during reading".into(),
        ));
    }
    control.check()?;
    output.file.flush().map_err(staging_error)?;
    output.digest = hash.finalize().into();
    Ok(output)
}

/// Streaming EVP encryption produces the existing RustCrypto wire bytes.
/// Neither the source nor ciphertext is mapped or assembled on the heap.
pub(crate) fn encrypt_file(
    source: &PrivateMediaFile,
    directory: &Path,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    control: &MediaFileTransferControl,
) -> Result<PrivateMediaFile, AppError> {
    control.check()?;
    let encrypted_len = source
        .len
        .checked_add(MEDIA_AEAD_TAG_BYTES)
        .filter(|len| *len <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
        .ok_or_else(|| {
            AppError::InvalidEncryptedMedia("media ciphertext exceeds file transfer bound".into())
        })?;
    let mut input = source.reader()?;
    let mut output = PrivateMediaFile::create(directory)?;
    let mut cipher = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, key, Some(nonce))
        .map_err(crypto_error)?;
    cipher.pad(false);
    cipher.aad_update(aad).map_err(crypto_error)?;
    let mut buffer = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES]);
    let mut encrypted = Zeroizing::new(vec![0; FILE_TRANSFER_BUFFER_BYTES + 16]);
    let mut hash = Sha256::new();
    let mut count = 0u64;
    loop {
        control.check()?;
        let n = input.read(&mut buffer).map_err(staging_error)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|n| *n <= source.len)
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("media snapshot length changed".into())
            })?;
        let written = cipher
            .update(&buffer[..n], &mut encrypted)
            .map_err(crypto_error)?;
        output
            .file
            .write_all(&encrypted[..written])
            .map_err(staging_error)?;
        hash.update(&encrypted[..written]);
        control.advance(source.len.saturating_add(count));
    }
    if count != source.len {
        return Err(AppError::InvalidEncryptedMedia(
            "media snapshot truncated".into(),
        ));
    }
    let written = cipher.finalize(&mut encrypted).map_err(crypto_error)?;
    output
        .file
        .write_all(&encrypted[..written])
        .map_err(staging_error)?;
    hash.update(&encrypted[..written]);
    let mut tag = [0u8; 16];
    cipher.get_tag(&mut tag).map_err(crypto_error)?;
    output.file.write_all(&tag).map_err(staging_error)?;
    hash.update(tag);
    output.file.flush().map_err(staging_error)?;
    control.check()?;
    if output
        .file
        .as_file()
        .metadata()
        .map_err(staging_error)?
        .len()
        != encrypted_len
    {
        return Err(AppError::InvalidEncryptedMedia(
            "media ciphertext length mismatch".into(),
        ));
    }
    output.len = encrypted_len;
    output.digest = hash.finalize().into();
    Ok(output)
}

/// Unauthenticated plaintext stays in an inaccessible private temporary file.
/// Only an authenticated, hash-verified complete result is returned to callers.
pub(crate) fn decrypt_file(
    encrypted: &PrivateMediaFile,
    directory: &Path,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext_hash: [u8; 32],
    control: &MediaFileTransferControl,
) -> Result<PrivateMediaFile, AppError> {
    control.check()?;
    let body_len = encrypted
        .len
        .checked_sub(MEDIA_AEAD_TAG_BYTES)
        .filter(|_| encrypted.len <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
        .ok_or_else(|| AppError::InvalidEncryptedMedia("invalid media ciphertext length".into()))?;
    let mut input = encrypted.reader()?;
    input
        .seek(SeekFrom::Start(body_len))
        .map_err(staging_error)?;
    let mut tag = [0u8; 16];
    input.read_exact(&mut tag).map_err(staging_error)?;
    let mut trailing = [0u8; 1];
    if input.read(&mut trailing).map_err(staging_error)? != 0 {
        return Err(AppError::InvalidEncryptedMedia(
            "media ciphertext grew".into(),
        ));
    }
    input.rewind().map_err(staging_error)?;
    let mut cipher = Crypter::new(Cipher::chacha20_poly1305(), Mode::Decrypt, key, Some(nonce))
        .map_err(crypto_error)?;
    cipher.pad(false);
    cipher.aad_update(aad).map_err(crypto_error)?;
    cipher.set_tag(&tag).map_err(crypto_error)?;
    let mut output = PrivateMediaFile::create(directory)?;
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
            .file
            .write_all(&decrypted[..written])
            .map_err(staging_error)?;
        hash.update(&decrypted[..written]);
        remaining -= take as u64;
        control.advance(body_len - remaining);
    }
    ciphertext_hash.update(tag);
    if <[u8; 32]>::from(ciphertext_hash.finalize()) != encrypted.digest {
        return Err(AppError::InvalidEncryptedMedia(
            "media ciphertext hash mismatch".into(),
        ));
    }
    let written = cipher.finalize(&mut decrypted).map_err(crypto_error)?;
    output
        .file
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
    output.file.flush().map_err(staging_error)?;
    output.len = output
        .file
        .as_file()
        .metadata()
        .map_err(staging_error)?
        .len();
    if output.len != body_len {
        return Err(AppError::InvalidEncryptedMedia(
            "media plaintext length mismatch".into(),
        ));
    }
    output.digest = digest;
    Ok(output)
}

/// Prepare every snapshot and ciphertext (hashing each source before key/AAD
/// derivation), check the aggregate bound, then upload each ciphertext with
/// ordered server fallback. Returns the plaintext snapshots for optional
/// retention; ciphertext files are deleted as each upload finishes.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_files_retaining(
    request: MediaFileUploadRequest,
    source_epoch: u64,
    media_secret: &[u8],
    signer: &dyn transport_nostr_peeler::MarmotNostrSigner,
    policy: super::MediaOperationPolicy<'_>,
    transport: &super::BlossomHttpTransport,
    directory: PathBuf,
    control: Arc<MediaFileTransferControl>,
) -> Result<(super::MediaUploadResult, Vec<PrivateMediaFile>), AppError> {
    request.validate()?;
    let servers = request
        .blossom_server
        .map(|server| vec![server])
        .unwrap_or_else(|| {
            policy
                .default_endpoints
                .iter()
                .map(|endpoint| endpoint.base_url.clone())
                .collect()
        });
    if servers.is_empty() {
        return Err(AppError::InvalidEncryptedMedia(
            "group policy has no usable Blossom endpoint for upload".into(),
        ));
    }
    let mut attachments = Vec::with_capacity(request.attachments.len());
    let mut plaintext = Vec::with_capacity(request.attachments.len());
    struct PreparedUpload {
        source: PrivateMediaFile,
        encrypted: PrivateMediaFile,
        nonce: [u8; 12],
        file_name: String,
        media_type: String,
        dim: Option<String>,
        thumbhash: Option<String>,
    }
    let mut prepared_uploads = Vec::with_capacity(request.attachments.len());
    let mut total = 0u64;
    let sweep_directory = directory.clone();
    if tokio::task::spawn_blocking(move || sweep_stale_media_staging(&sweep_directory))
        .await
        .unwrap_or(0)
        > 0
    {
        tracing::debug!(target: "marmot_app::media", method = "media_staging_sweep",
            "removed stale private media snapshots");
    }
    for attachment in request.attachments {
        control.check()?;
        let file_name = match policy.version {
            super::EncryptedMediaVersion::V1 => attachment.file_name.trim().to_owned(),
            super::EncryptedMediaVersion::V2 => attachment.file_name,
        };
        super::validate_outbound_file_name(&file_name, policy.version)?;
        let media_type = match policy.version {
            super::EncryptedMediaVersion::V1 => {
                super::crypto::canonical_media_type_v1(&attachment.media_type)?
            }
            super::EncryptedMediaVersion::V2 => {
                super::crypto::canonical_media_type_v2(&attachment.media_type)?
            }
        };
        let secret = Zeroizing::new(media_secret.to_vec());
        let version = policy.version;
        let source_path = attachment.source_path;
        let source_size = attachment.expected_size;
        let prepared_name = file_name.clone();
        let prepared_type = media_type.clone();
        let prepared_directory = directory.clone();
        let preparation_control = control.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            use rand::RngCore;
            let source = snapshot_source(
                Path::new(&source_path),
                &prepared_directory,
                source_size,
                &preparation_control,
            )?;
            let key = Zeroizing::new(super::crypto::derive_media_file_key(
                &secret,
                version,
                &source.digest,
                &prepared_type,
                &prepared_name,
            )?);
            let aad =
                super::crypto::media_aad(version, &source.digest, &prepared_type, &prepared_name);
            let mut nonce = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let encrypted = encrypt_file(
                &source,
                &prepared_directory,
                &key,
                &nonce,
                &aad,
                &preparation_control,
            )?;
            Ok::<_, AppError>((source, encrypted, nonce))
        })
        .await
        .map_err(|_| AppError::BlockingTask("media file preparation failed".into()))??;
        let (source, encrypted, nonce) = prepared;
        total = total
            .checked_add(encrypted.len)
            .filter(|total| *total <= MAX_FILE_MEDIA_CIPHERTEXT_BYTES)
            .ok_or_else(|| {
                AppError::InvalidEncryptedMedia("file attachments exceed transfer bound".into())
            })?;
        prepared_uploads.push(PreparedUpload {
            source,
            encrypted,
            nonce,
            file_name,
            media_type,
            dim: attachment.dim,
            thumbhash: attachment.thumbhash,
        });
    }
    // Validate every source and the aggregate bound before the first PUT.
    for prepared in prepared_uploads {
        let PreparedUpload {
            source,
            encrypted,
            nonce,
            file_name,
            media_type,
            dim,
            thumbhash,
        } = prepared;
        let mut failures = Vec::new();
        let mut uploaded = None;
        let mut timed_out = false;
        // Each candidate reopens the identical private ciphertext at offset 0.
        for (index, server) in servers.iter().enumerate() {
            control.check()?;
            match super::blossom::upload_blossom_file(
                server,
                &encrypted,
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
        let reference = super::MediaAttachmentReference {
            locators: vec![super::MediaLocator {
                kind: "blossom-v1".into(),
                value: url,
            }],
            ciphertext_sha256: hex::encode(encrypted.digest),
            plaintext_sha256: hex::encode(source.digest),
            nonce_hex: hex::encode(nonce),
            file_name,
            media_type,
            version: policy.version.as_str().to_owned(),
            source_epoch,
            dim,
            thumbhash,
        };
        reference.validate_outbound(
            policy.version,
            policy.allowed_locator_kinds,
            policy.allow_loopback_http,
        )?;
        attachments.push(super::MediaUploadAttachmentResult {
            reference,
            encrypted_size_bytes: encrypted.len,
        });
        plaintext.push(source);
    }
    control.check()?;
    Ok((
        super::MediaUploadResult {
            attachments,
            sent: None,
        },
        plaintext,
    ))
}

/// Receive without assembling ciphertext or plaintext arrays. The caller
/// retains source/attempt permission and publishes through bounded storage.
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
) -> Result<PrivateMediaFile, super::AttachmentDownloadFailure> {
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
        let decryption_directory = directory.clone();
        let decryption_control = control.clone();
        let key = key.clone();
        let aad = aad.clone();
        let result = tokio::task::spawn_blocking(move || {
            decrypt_file(
                &encrypted,
                &decryption_directory,
                &key,
                &nonce,
                &aad,
                plaintext_hash,
                &decryption_control,
            )
        })
        .await
        .map_err(|_| AppError::BlockingTask("file media verification failed".into()))?;
        control.check()?;
        match result {
            Ok(file) => return Ok(file),
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
