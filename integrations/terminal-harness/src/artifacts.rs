use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_control::{
    MAX_MEDIA_UPLOAD_ATTACHMENT_BYTES, MAX_MEDIA_UPLOAD_ATTACHMENTS, MAX_MEDIA_UPLOAD_BATCH_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{HarnessError, Result};

pub(crate) const MAX_ARTIFACTS_PER_RESULT: usize = MAX_MEDIA_UPLOAD_ATTACHMENTS;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = MAX_MEDIA_UPLOAD_ATTACHMENT_BYTES;
pub(crate) const MAX_ARTIFACT_BATCH_BYTES: u64 = MAX_MEDIA_UPLOAD_BATCH_BYTES;
const MAX_ARTIFACT_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_ARTIFACT_OUTBOX_BYTES: u64 = 1024 * 1024;
pub(crate) const DEFAULT_ARTIFACT_GRANT_TTL_SECONDS: u64 = 3600;
pub(crate) const MAX_ARTIFACT_GRANT_TTL_SECONDS: u64 = 86_400;

fn default_artifact_grant_ttl_seconds() -> u64 {
    DEFAULT_ARTIFACT_GRANT_TTL_SECONDS
}

/// Operator-authorized policy for exporting backend-created artifacts.
#[derive(Clone)]
pub struct ArtifactExportConfig {
    enabled: bool,
    grants: Vec<ArtifactExportGrant>,
    max_count: usize,
    staging_root: PathBuf,
    outbox_path: PathBuf,
}

impl ArtifactExportConfig {
    pub(crate) fn new(
        enabled: bool,
        grants: Vec<ArtifactExportGrant>,
        staging_root: PathBuf,
        outbox_path: PathBuf,
    ) -> Self {
        Self {
            enabled,
            grants,
            max_count: MAX_ARTIFACTS_PER_RESULT,
            staging_root,
            outbox_path,
        }
    }

    pub(crate) fn with_max_count(mut self, max_count: usize) -> Self {
        self.max_count = max_count;
        self
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn grants(&self) -> &[ArtifactExportGrant] {
        &self.grants
    }

    /// Maximum number of artifacts accepted from one backend result.
    pub fn max_count(&self) -> usize {
        self.max_count
    }

    pub(crate) fn staging_root(&self) -> &Path {
        &self.staging_root
    }

    pub(crate) fn outbox_path(&self) -> &Path {
        &self.outbox_path
    }

    pub(crate) fn authorize(
        &self,
        group_ref: &str,
        message_ref: &str,
    ) -> Result<Option<ArtifactAuthorization>> {
        if !self.enabled {
            return Ok(None);
        }
        let Some(grant) = self
            .grants
            .iter()
            .find(|grant| grant.group_id_hex.eq_ignore_ascii_case(group_ref))
        else {
            return Ok(None);
        };
        if !(1..=MAX_ARTIFACT_GRANT_TTL_SECONDS).contains(&grant.ttl_seconds) {
            return Err(HarnessError::ArtifactAuthorizationInvalid);
        }
        let metadata = std::fs::symlink_metadata(&grant.export_root)
            .map_err(|_| HarnessError::ArtifactAuthorizationInvalid)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HarnessError::ArtifactAuthorizationInvalid);
        }
        let root = std::fs::canonicalize(&grant.export_root)
            .map_err(|_| HarnessError::ArtifactAuthorizationInvalid)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HarnessError::ArtifactAuthorizationInvalid)?
            .as_secs();
        let expires_at_unix_secs = now
            .checked_add(grant.ttl_seconds)
            .ok_or(HarnessError::ArtifactAuthorizationInvalid)?;
        let mut nonce = [0_u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(group_ref.as_bytes());
        hasher.update(message_ref.as_bytes());
        let id = hex::encode(hasher.finalize());
        Ok(Some(ArtifactAuthorization {
            id,
            group_ref: group_ref.to_owned(),
            message_ref: message_ref.to_owned(),
            root,
            expires_at_unix_secs,
        }))
    }
}

impl Default for ArtifactExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            grants: Vec::new(),
            max_count: MAX_ARTIFACTS_PER_RESULT,
            staging_root: PathBuf::new(),
            outbox_path: PathBuf::new(),
        }
    }
}

impl fmt::Debug for ArtifactExportConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactExportConfig")
            .field("enabled", &self.enabled)
            .field("grant_count", &self.grants.len())
            .field("max_count", &self.max_count)
            .finish_non_exhaustive()
    }
}

/// One operator-approved destination scope for one exact Marmot group.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactExportGrant {
    pub group_id_hex: String,
    pub export_root: PathBuf,
    #[serde(default = "default_artifact_grant_ttl_seconds")]
    pub ttl_seconds: u64,
}

impl fmt::Debug for ArtifactExportGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactExportGrant")
            .field("ttl_seconds", &self.ttl_seconds)
            .finish_non_exhaustive()
    }
}

/// Connector-minted, single-turn artifact capability.
#[derive(Clone)]
pub(crate) struct ArtifactAuthorization {
    id: String,
    group_ref: String,
    message_ref: String,
    root: PathBuf,
    expires_at_unix_secs: u64,
}

impl ArtifactAuthorization {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

/// Backend-owned manifest path for one completion.
#[derive(Clone)]
pub struct ArtifactOutputRequest {
    manifest_path: PathBuf,
    authorization_id: String,
    export_root: PathBuf,
}

impl ArtifactOutputRequest {
    pub fn new(manifest_path: PathBuf, authorization_id: String, export_root: PathBuf) -> Self {
        Self {
            manifest_path,
            authorization_id,
            export_root,
        }
    }

    pub(crate) fn from_authorization(
        manifest_path: PathBuf,
        authorization: &ArtifactAuthorization,
    ) -> Self {
        Self::new(
            manifest_path,
            authorization.id().to_owned(),
            authorization.root.clone(),
        )
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn authorization_id(&self) -> &str {
        &self.authorization_id
    }

    pub fn export_root(&self) -> &Path {
        &self.export_root
    }
}

impl fmt::Debug for ArtifactOutputRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactOutputRequest")
            .finish_non_exhaustive()
    }
}

/// One explicitly declared backend output file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactOutput {
    pub authorization_id: String,
    pub path: PathBuf,
    pub media_type: String,
    pub file_name: String,
}

impl fmt::Debug for ArtifactOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactOutput")
            .field("authorization_present", &!self.authorization_id.is_empty())
            .field("media_type_present", &!self.media_type.is_empty())
            .field("file_name_present", &!self.file_name.is_empty())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArtifactOutputManifest {
    #[serde(default)]
    pub(crate) artifacts: Vec<ArtifactOutput>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StagedArtifact {
    pub(crate) path: PathBuf,
    pub(crate) media_type: String,
    pub(crate) file_name: String,
    pub(crate) plaintext_sha256: String,
    pub(crate) size_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct PendingArtifactBatch {
    pub(crate) idempotency_key: String,
    pub(crate) account_ref: String,
    pub(crate) group_ref: String,
    pub(crate) reply_to_message_ref: String,
    pub(crate) caption: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) remaining_text: Vec<String>,
    pub(crate) artifacts: Vec<StagedArtifact>,
}

impl fmt::Debug for StagedArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedArtifact")
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PendingArtifactBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingArtifactBatch")
            .field("artifact_count", &self.artifacts.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedOutbox {
    mac: String,
    #[serde(default)]
    batches: Vec<PendingArtifactBatch>,
}

pub(crate) struct ArtifactOutbox {
    path: PathBuf,
    key: [u8; 32],
    batches: Vec<PendingArtifactBatch>,
}

impl ArtifactOutbox {
    pub(crate) fn disabled(path: PathBuf) -> Self {
        Self {
            path,
            key: [0_u8; 32],
            batches: Vec::new(),
        }
    }

    pub(crate) fn load(path: PathBuf) -> Result<Self> {
        let key = load_or_create_outbox_key(&path)?;
        let batches = match read_regular_file_limited(&path, MAX_ARTIFACT_OUTBOX_BYTES) {
            Ok(bytes) if !bytes.is_empty() => {
                let persisted: PersistedOutbox = serde_json::from_slice(&bytes)?;
                verify_outbox_mac(&key, &persisted)?;
                persisted.batches
            }
            Ok(_) => Vec::new(),
            Err(HarnessError::Io {
                kind: std::io::ErrorKind::NotFound,
            }) => Vec::new(),
            Err(error) => return Err(error),
        };
        Ok(Self { path, key, batches })
    }

    pub(crate) fn pending(&self) -> Vec<PendingArtifactBatch> {
        self.batches.clone()
    }

    pub(crate) fn record(&mut self, batch: PendingArtifactBatch) -> Result<()> {
        if let Some(existing) = self
            .batches
            .iter()
            .find(|existing| existing.idempotency_key == batch.idempotency_key)
        {
            if batch_matches(existing, &batch) {
                return Ok(());
            }
            return Err(HarnessError::ArtifactIdempotencyConflict);
        }
        let mut next = self.batches.clone();
        next.push(batch);
        self.persist_batches(&next)?;
        self.batches = next;
        Ok(())
    }

    pub(crate) fn complete(&mut self, key: &str) -> Result<Vec<PathBuf>> {
        let mut removed_paths = Vec::new();
        let next = self
            .batches
            .iter()
            .filter_map(|batch| {
                if batch.idempotency_key == key {
                    removed_paths
                        .extend(batch.artifacts.iter().map(|artifact| artifact.path.clone()));
                    None
                } else {
                    Some(batch.clone())
                }
            })
            .collect::<Vec<_>>();
        self.persist_batches(&next)?;
        self.batches = next;
        Ok(removed_paths)
    }

    fn persist_batches(&self, batches: &[PendingArtifactBatch]) -> Result<()> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| HarnessError::Config("artifact outbox path has no parent".to_owned()))?;
        fs_private::create_dir_all_private(parent)?;
        let persisted = PersistedOutbox {
            mac: outbox_mac(&self.key, batches)?,
            batches: batches.to_vec(),
        };
        let bytes = serde_json::to_vec(&persisted)?;
        let temp = self.path.with_extension("tmp");
        fs_private::write_private(&temp, &bytes)?;
        std::fs::rename(&temp, &self.path)?;
        // `write_private` fsyncs the temp file before this atomic rename. A parent-directory
        // fsync is best effort: once rename succeeds, callers must treat the new file as
        // authoritative rather than deleting staged bytes on a post-rename sync error.
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    }
}

pub(crate) fn prepare_manifest_path(outbox_path: &Path, message_ref: &str) -> Result<PathBuf> {
    let dir = outbox_path.with_extension("manifests");
    fs_private::create_dir_all_private(&dir)?;
    let name = format!(
        "{}.json",
        hex::encode(Sha256::digest(message_ref.as_bytes()))
    );
    let path = dir.join(name);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = serde_json::to_vec(&ArtifactOutputManifest {
        artifacts: Vec::new(),
    })?;
    let mut file = fs_private::create_new_private(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(path)
}

pub fn read_artifact_output_manifest(path: &Path) -> Result<Vec<ArtifactOutput>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_MANIFEST_BYTES {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_ARTIFACT_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARTIFACT_MANIFEST_BYTES {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    let manifest: ArtifactOutputManifest = serde_json::from_slice(&bytes)?;
    Ok(manifest.artifacts)
}

pub(crate) struct ArtifactDeliveryContext<'a> {
    pub(crate) reply_prefix: &'a str,
    pub(crate) account_ref: &'a str,
    pub(crate) group_ref: &'a str,
    pub(crate) message_ref: &'a str,
    pub(crate) caption: Option<String>,
    pub(crate) remaining_text: Vec<String>,
}

pub(crate) fn stage_artifacts(
    config: &ArtifactExportConfig,
    destination: ArtifactDeliveryContext<'_>,
    authorization: &ArtifactAuthorization,
    outputs: &[ArtifactOutput],
) -> Result<PendingArtifactBatch> {
    if !config.enabled() {
        return Err(HarnessError::ArtifactExportsDisabled);
    }
    if outputs.is_empty() || outputs.len() > config.max_count() {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    let ArtifactDeliveryContext {
        reply_prefix,
        account_ref,
        group_ref,
        message_ref,
        caption,
        remaining_text,
    } = destination;
    fs_private::create_dir_all_private(config.staging_root())?;
    let staging_metadata = std::fs::symlink_metadata(config.staging_root())?;
    if staging_metadata.file_type().is_symlink() || !staging_metadata.is_dir() {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    let staging_root = std::fs::canonicalize(config.staging_root())?;
    let mut artifacts = Vec::with_capacity(outputs.len());
    let mut created_paths = Vec::with_capacity(outputs.len());
    let mut batch_bytes = 0_u64;
    let message_digest = hex::encode(Sha256::digest(message_ref.as_bytes()));
    let result = (|| {
        for (index, output) in outputs.iter().enumerate() {
            validate_metadata(output)?;
            validate_authorization(authorization, group_ref, message_ref, output)?;
            let mut source = open_authorized_source(&output.path, authorization.root())?;
            let size_bytes = source.metadata()?.len();
            if size_bytes == 0 || size_bytes > MAX_ARTIFACT_BYTES {
                return Err(HarnessError::ArtifactLimitsExceeded);
            }
            batch_bytes = batch_bytes
                .checked_add(size_bytes)
                .ok_or(HarnessError::ArtifactLimitsExceeded)?;
            if batch_bytes > MAX_ARTIFACT_BATCH_BYTES {
                return Err(HarnessError::ArtifactLimitsExceeded);
            }
            let staged_name = format!(
                "{}-{}-{}",
                &message_digest[..16],
                index + 1,
                output.file_name
            );
            let staged_path = config.staging_root().join(staged_name);
            let mut destination = fs_private::create_new_private(&staged_path)?;
            created_paths.push(staged_path.clone());
            if !opened_file_path(&destination, &staged_path)?.starts_with(&staging_root) {
                return Err(HarnessError::ArtifactUnsafeSource);
            }
            let digest = copy_exact_with_digest(&mut source, &mut destination, size_bytes)?;
            destination.sync_all()?;
            artifacts.push(StagedArtifact {
                path: staged_path,
                media_type: output.media_type.clone(),
                file_name: output.file_name.clone(),
                plaintext_sha256: digest,
                size_bytes,
            });
        }
        Ok(())
    })();
    if let Err(error) = result {
        for path in &created_paths {
            let _ = std::fs::remove_file(path);
        }
        return Err(error);
    }

    let idempotency_key = artifact_idempotency_key(
        reply_prefix,
        account_ref,
        group_ref,
        message_ref,
        caption.as_deref(),
        &artifacts,
    )?;
    Ok(PendingArtifactBatch {
        idempotency_key,
        account_ref: account_ref.to_owned(),
        group_ref: group_ref.to_owned(),
        reply_to_message_ref: message_ref.to_owned(),
        caption,
        remaining_text,
        artifacts,
    })
}

fn load_or_create_outbox_key(outbox_path: &Path) -> Result<[u8; 32]> {
    let parent = outbox_path
        .parent()
        .ok_or_else(|| HarnessError::Config("artifact outbox path has no parent".to_owned()))?;
    fs_private::create_dir_all_private(parent)?;
    let key_path = outbox_path.with_extension("key");
    match read_regular_file_limited(&key_path, 32) {
        Ok(bytes) if bytes.len() == 32 => return Ok(bytes.try_into().unwrap()),
        Ok(_) => {
            let outbox_has_state =
                match read_regular_file_limited(outbox_path, MAX_ARTIFACT_OUTBOX_BYTES) {
                    Ok(bytes) => !bytes.is_empty(),
                    Err(HarnessError::Io {
                        kind: std::io::ErrorKind::NotFound,
                    }) => false,
                    Err(_) => true,
                };
            if outbox_has_state {
                return Err(HarnessError::ArtifactUnsafeSource);
            }
            std::fs::remove_file(&key_path)?;
        }
        Err(HarnessError::Io {
            kind: std::io::ErrorKind::NotFound,
        }) => {}
        Err(error) => return Err(error),
    }

    let mut random = File::open("/dev/urandom")?;
    let mut key = [0_u8; 32];
    random.read_exact(&mut key)?;
    let temp = key_path.with_extension(format!("key.{}.tmp", hex::encode(&key[..8])));
    let mut key_file = fs_private::create_new_private(&temp)?;
    key_file.write_all(&key)?;
    key_file.sync_all()?;
    match std::fs::hard_link(&temp, &key_path) {
        Ok(()) => {
            std::fs::remove_file(&temp)?;
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&temp);
            let bytes = read_regular_file_limited(&key_path, 32)?;
            bytes
                .try_into()
                .map_err(|_| HarnessError::ArtifactUnsafeSource)
        }
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            Err(error.into())
        }
    }
}

fn outbox_mac(key: &[u8; 32], batches: &[PendingArtifactBatch]) -> Result<String> {
    let bytes = serde_json::to_vec(batches)?;
    Ok(hex::encode(hmac_sha256(key, &bytes)))
}

fn verify_outbox_mac(key: &[u8; 32], persisted: &PersistedOutbox) -> Result<()> {
    let expected = outbox_mac(key, &persisted.batches)?;
    let actual = persisted.mac.as_bytes();
    let expected = expected.as_bytes();
    if actual.len() != expected.len() {
        return Err(HarnessError::ArtifactIdempotencyConflict);
    }
    let different = actual
        .iter()
        .zip(expected)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    if different != 0 {
        return Err(HarnessError::ArtifactIdempotencyConflict);
    }
    Ok(())
}

fn hmac_sha256(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut inner_key = [0x36_u8; 64];
    let mut outer_key = [0x5c_u8; 64];
    for (index, value) in key.iter().enumerate() {
        inner_key[index] ^= value;
        outer_key[index] ^= value;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(bytes);
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner.finalize());
    outer.finalize().into()
}

pub(crate) fn artifact_idempotency_key(
    reply_prefix: &str,
    account_ref: &str,
    group_ref: &str,
    message_ref: &str,
    caption: Option<&str>,
    artifacts: &[StagedArtifact],
) -> Result<String> {
    let values = artifacts
        .iter()
        .map(|artifact| {
            serde_json::json!([
                artifact.media_type,
                artifact.file_name,
                artifact.plaintext_sha256,
                artifact.size_bytes,
            ])
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!([
        1,
        reply_prefix,
        account_ref,
        group_ref,
        message_ref,
        caption,
        values,
    ]))?;
    Ok(format!(
        "{reply_prefix}:artifact-v1:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}

fn canonical_private_staging_root(path: &Path) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    Ok(std::fs::canonicalize(path)?)
}

fn validate_staged_artifact(root: &Path, artifact: &StagedArtifact) -> Result<u64> {
    validate_file_metadata(&artifact.media_type, &artifact.file_name)?;
    if !artifact.path.is_absolute() {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    validate_opened_staged_artifact(root, artifact)
}

fn validate_opened_staged_artifact(root: &Path, artifact: &StagedArtifact) -> Result<u64> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&artifact.path)
        .map_err(|_| HarnessError::ArtifactUnsafeSource)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_ARTIFACT_BYTES
        || metadata.len() != artifact.size_bytes
    {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    validate_private_single_link(&metadata)?;
    let opened =
        opened_file_path(&file, &artifact.path).map_err(|_| HarnessError::ArtifactUnsafeSource)?;
    let declared =
        std::fs::canonicalize(&artifact.path).map_err(|_| HarnessError::ArtifactUnsafeSource)?;
    if opened != declared || !opened.starts_with(root) {
        return Err(HarnessError::ArtifactOutsideAllowedRoots);
    }
    let digest = digest_exact(&mut file, metadata.len())?;
    if digest != artifact.plaintext_sha256 {
        return Err(HarnessError::ArtifactIdempotencyConflict);
    }
    Ok(metadata.len())
}

fn validate_private_single_link(metadata: &std::fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
        {
            return Err(HarnessError::ArtifactUnsafeSource);
        }
    }
    Ok(())
}

fn digest_exact(file: &mut File, expected: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while copied <= expected {
        let remaining = expected.saturating_add(1).saturating_sub(copied);
        let limit = remaining.min(buffer.len() as u64) as usize;
        if limit == 0 {
            break;
        }
        let read = file.read(&mut buffer[..limit])?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        copied += read as u64;
    }
    if copied != expected {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_staged_batch_inner(
    config: &ArtifactExportConfig,
    reply_prefix: &str,
    batch: &PendingArtifactBatch,
) -> Result<()> {
    if batch.artifacts.is_empty() || batch.artifacts.len() > MAX_ARTIFACTS_PER_RESULT {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    let root = canonical_private_staging_root(config.staging_root())?;
    let mut total = 0_u64;
    for artifact in &batch.artifacts {
        total = total
            .checked_add(validate_staged_artifact(&root, artifact)?)
            .ok_or(HarnessError::ArtifactLimitsExceeded)?;
    }
    if total > MAX_ARTIFACT_BATCH_BYTES {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    let expected = artifact_idempotency_key(
        reply_prefix,
        &batch.account_ref,
        &batch.group_ref,
        &batch.reply_to_message_ref,
        batch.caption.as_deref(),
        &batch.artifacts,
    )?;
    if expected != batch.idempotency_key {
        return Err(HarnessError::ArtifactIdempotencyConflict);
    }
    Ok(())
}

pub(crate) fn remove_staged_files(config: &ArtifactExportConfig, paths: Vec<PathBuf>) {
    let Ok(root) = canonical_private_staging_root(config.staging_root()) else {
        return;
    };
    for path in paths {
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let Ok(canonical) = std::fs::canonicalize(&path) else {
            continue;
        };
        if canonical.starts_with(&root) {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub(crate) fn validate_staged_batch(
    config: &ArtifactExportConfig,
    reply_prefix: &str,
    batch: &PendingArtifactBatch,
) -> Result<()> {
    validate_staged_batch_inner(config, reply_prefix, batch)
}

fn read_regular_file_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    validate_private_single_link(&metadata)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    Ok(bytes)
}

fn batch_matches(left: &PendingArtifactBatch, right: &PendingArtifactBatch) -> bool {
    left.account_ref == right.account_ref
        && left.group_ref == right.group_ref
        && left.reply_to_message_ref == right.reply_to_message_ref
        && left.caption == right.caption
        && left.remaining_text == right.remaining_text
        && left.artifacts.len() == right.artifacts.len()
        && left
            .artifacts
            .iter()
            .zip(&right.artifacts)
            .all(|(left, right)| {
                left.plaintext_sha256 == right.plaintext_sha256
                    && left.file_name == right.file_name
                    && left.media_type == right.media_type
            })
}

fn validate_metadata(output: &ArtifactOutput) -> Result<()> {
    if output.authorization_id.is_empty()
        || output.path.is_absolute()
        || output.path.as_os_str().is_empty()
        || output.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(HarnessError::ArtifactInvalidMetadata);
    }
    validate_file_metadata(&output.media_type, &output.file_name)
}

fn validate_file_metadata(media_type: &str, file_name: &str) -> Result<()> {
    if file_name.is_empty()
        || Path::new(file_name)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(file_name)
        || file_name.chars().any(char::is_control)
        || !media_type.contains('/')
        || media_type.chars().any(char::is_control)
    {
        return Err(HarnessError::ArtifactInvalidMetadata);
    }
    Ok(())
}

fn validate_authorization(
    authorization: &ArtifactAuthorization,
    group_ref: &str,
    message_ref: &str,
    output: &ArtifactOutput,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| HarnessError::ArtifactAuthorizationInvalid)?
        .as_secs();
    if output.authorization_id != authorization.id
        || group_ref != authorization.group_ref
        || message_ref != authorization.message_ref
        || now > authorization.expires_at_unix_secs
    {
        return Err(HarnessError::ArtifactAuthorizationInvalid);
    }
    Ok(())
}

fn open_authorized_source(relative_path: &Path, root: &Path) -> Result<File> {
    let path = root.join(relative_path);
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(HarnessError::ArtifactUnsafeSource);
    }
    let opened_path = opened_file_path(&file, &path)?;
    if !opened_path.starts_with(root) {
        return Err(HarnessError::ArtifactOutsideAllowedRoots);
    }
    Ok(file)
}

fn opened_file_path(file: &File, _fallback: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        Ok(std::fs::canonicalize(format!(
            "/proc/self/fd/{}",
            file.as_raw_fd()
        ))?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(std::fs::canonicalize(_fallback)?)
    }
}

fn copy_exact_with_digest(
    source: &mut File,
    destination: &mut File,
    expected: u64,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while copied <= expected {
        let remaining = expected.saturating_add(1).saturating_sub(copied);
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| HarnessError::ArtifactLimitsExceeded)?;
        if limit == 0 {
            break;
        }
        let read = source.read(&mut buffer[..limit])?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
        copied = copied
            .checked_add(read as u64)
            .ok_or(HarnessError::ArtifactLimitsExceeded)?;
    }
    if copied != expected {
        return Err(HarnessError::ArtifactLimitsExceeded);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn config(root: &Path, staging: &Path, outbox: &Path) -> ArtifactExportConfig {
        ArtifactExportConfig::new(
            true,
            vec![ArtifactExportGrant {
                group_id_hex: "group".to_owned(),
                export_root: root.to_path_buf(),
                ttl_seconds: 300,
            }],
            staging.to_path_buf(),
            outbox.to_path_buf(),
        )
    }

    fn stage_artifacts(
        config: &ArtifactExportConfig,
        reply_prefix: &str,
        account_ref: &str,
        group_ref: &str,
        message_ref: &str,
        outputs: &[ArtifactOutput],
    ) -> Result<PendingArtifactBatch> {
        let root = &config.grants[0].export_root;
        let authorization = ArtifactAuthorization {
            id: "auth".to_owned(),
            group_ref: group_ref.to_owned(),
            message_ref: message_ref.to_owned(),
            root: std::fs::canonicalize(root).unwrap(),
            expires_at_unix_secs: u64::MAX,
        };
        let outputs = outputs
            .iter()
            .cloned()
            .map(|mut output| {
                if let Ok(relative) = output.path.strip_prefix(root) {
                    output.path = relative.to_path_buf();
                }
                output
            })
            .collect::<Vec<_>>();
        super::stage_artifacts(
            config,
            ArtifactDeliveryContext {
                reply_prefix,
                account_ref,
                group_ref,
                message_ref,
                caption: None,
                remaining_text: Vec::new(),
            },
            &authorization,
            &outputs,
        )
    }

    #[test]
    fn operator_artifact_count_limit_is_enforced_before_staging() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        let mut cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        cfg.max_count = 1;
        let output = ArtifactOutput {
            authorization_id: "auth".to_owned(),
            path: PathBuf::from("report.pdf"),
            media_type: "application/pdf".to_owned(),
            file_name: "report.pdf".to_owned(),
        };

        assert!(matches!(
            stage_artifacts(
                &cfg,
                "wn-test",
                "account",
                "group",
                "message",
                &[output.clone(), output],
            ),
            Err(HarnessError::ArtifactLimitsExceeded)
        ));
        assert!(!staging.exists());
    }

    #[test]
    fn stages_only_regular_files_beneath_allowed_roots_with_private_mode() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        let source = root.join("report.pdf");
        std::fs::write(&source, b"report").unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        let batch = stage_artifacts(
            &cfg,
            "wn-test",
            "account",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source,
                media_type: "application/pdf".to_owned(),
                file_name: "report.pdf".to_owned(),
            }],
        )
        .unwrap();
        assert_eq!(batch.artifacts.len(), 1);
        assert_eq!(std::fs::read(&batch.artifacts[0].path).unwrap(), b"report");
        assert_eq!(
            std::fs::metadata(&batch.artifacts[0].path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn declaration_rejects_unknown_metadata_and_backend_invented_authorization() {
        let unknown = serde_json::from_str::<ArtifactOutputManifest>(
            r#"{"artifacts":[{"authorization_id":"auth","path":"report.pdf","media_type":"application/pdf","file_name":"report.pdf","caption":"secret"}]}"#,
        );
        assert!(unknown.is_err());

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("report.pdf"), b"report").unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        let error = stage_artifacts(
            &cfg,
            "wn-test",
            "account",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "backend-invented".to_owned(),
                path: PathBuf::from("report.pdf"),
                media_type: "application/pdf".to_owned(),
                file_name: "report.pdf".to_owned(),
            }],
        )
        .unwrap_err();
        assert!(matches!(error, HarnessError::ArtifactAuthorizationInvalid));
    }

    #[test]
    fn rejects_outside_root_symlink_and_unsafe_metadata_without_path_leaks() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        let outside = temp.path().join("secret.txt");
        std::fs::write(&outside, b"secret").unwrap();
        let link = root.join("link.txt");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        for output in [
            ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: outside,
                media_type: "text/plain".to_owned(),
                file_name: "secret.txt".to_owned(),
            },
            ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: link,
                media_type: "text/plain".to_owned(),
                file_name: "link.txt".to_owned(),
            },
            ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: root.join("missing"),
                media_type: "invalid".to_owned(),
                file_name: "../escape".to_owned(),
            },
        ] {
            let error = stage_artifacts(&cfg, "wn-test", "account", "group", "message", &[output])
                .unwrap_err();
            assert!(
                !error
                    .to_string()
                    .contains(temp.path().to_string_lossy().as_ref())
            );
        }
    }

    #[test]
    fn outbox_recovers_an_interrupted_empty_key_before_any_intent_exists() {
        let temp = tempfile::tempdir().unwrap();
        let outbox_path = temp.path().join("state/outbox.json");
        std::fs::create_dir_all(outbox_path.parent().unwrap()).unwrap();
        fs_private::write_private(&outbox_path.with_extension("key"), b"").unwrap();

        let outbox = ArtifactOutbox::load(outbox_path.clone()).unwrap();
        assert!(outbox.pending().is_empty());
        assert_eq!(
            std::fs::read(outbox_path.with_extension("key"))
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn manifest_path_is_scoped_to_the_private_outbox_state() {
        let temp = tempfile::tempdir().unwrap();
        let outbox_path = temp.path().join("state/outbox.json");
        let manifest = prepare_manifest_path(&outbox_path, "message").unwrap();
        assert!(manifest.starts_with(outbox_path.with_extension("manifests")));
        assert!(manifest.is_file());
    }

    #[test]
    fn outbox_persists_and_completes_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        let outbox_path = temp.path().join("state/outbox.json");
        std::fs::create_dir(&root).unwrap();
        let source = root.join("result.bin");
        std::fs::write(&source, b"result").unwrap();
        let cfg = config(&root, &staging, &outbox_path);
        let batch = stage_artifacts(
            &cfg,
            "wn-test",
            "account",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source,
                media_type: "application/octet-stream".to_owned(),
                file_name: "result.bin".to_owned(),
            }],
        )
        .unwrap();
        let mut outbox = ArtifactOutbox::load(outbox_path.clone()).unwrap();
        outbox.record(batch.clone()).unwrap();
        outbox.record(batch.clone()).unwrap();
        assert_eq!(
            ArtifactOutbox::load(outbox_path.clone())
                .unwrap()
                .pending()
                .len(),
            1
        );
        let mut forged = std::fs::read(&outbox_path).unwrap();
        let position = forged
            .windows(b"account".len())
            .position(|window| window == b"account")
            .unwrap();
        forged[position..position + b"account".len()].copy_from_slice(b"attackr");
        fs_private::write_private(&outbox_path, &forged).unwrap();
        assert!(ArtifactOutbox::load(outbox_path.clone()).is_err());
        outbox.persist_batches(&outbox.batches.clone()).unwrap();
        let removed = outbox.complete(&batch.idempotency_key).unwrap();
        assert_eq!(removed.len(), 1);
        assert!(
            ArtifactOutbox::load(outbox_path)
                .unwrap()
                .pending()
                .is_empty()
        );
    }

    #[test]
    fn rejects_precreated_staging_symlink_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        fs_private::create_dir_all_private(&staging).unwrap();
        let source = root.join("report.pdf");
        std::fs::write(&source, b"report").unwrap();
        let victim = temp.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let message_digest = hex::encode(Sha256::digest(b"message"));
        let staged = staging.join(format!("{}-1-report.pdf", &message_digest[..16]));
        std::os::unix::fs::symlink(&victim, staged).unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        assert!(
            stage_artifacts(
                &cfg,
                "wn-test",
                "account",
                "group",
                "message",
                &[ArtifactOutput {
                    authorization_id: "auth".to_owned(),
                    path: source,
                    media_type: "application/pdf".to_owned(),
                    file_name: "report.pdf".to_owned(),
                }],
            )
            .is_err()
        );
        assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
    }

    #[test]
    fn manifest_reader_rejects_symlink_fifo_and_oversize_input() {
        let temp = tempfile::tempdir().unwrap();
        let regular = temp.path().join("manifest.json");
        std::fs::write(
            &regular,
            vec![b'x'; MAX_ARTIFACT_MANIFEST_BYTES as usize + 1],
        )
        .unwrap();
        assert!(matches!(
            read_artifact_output_manifest(&regular),
            Err(HarnessError::ArtifactUnsafeSource)
        ));
        let link = temp.path().join("manifest-link");
        std::os::unix::fs::symlink(&regular, &link).unwrap();
        assert!(read_artifact_output_manifest(&link).is_err());
        let fifo = temp.path().join("manifest-fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            read_artifact_output_manifest(&fifo),
            Err(HarnessError::ArtifactUnsafeSource)
        ));
    }

    #[test]
    fn exact_copy_rejects_growth_and_outbox_mutations_roll_back_on_persist_error() {
        let temp = tempfile::tempdir().unwrap();
        let source_path = temp.path().join("source");
        let destination_path = temp.path().join("destination");
        std::fs::write(&source_path, b"four").unwrap();
        let mut source = File::open(source_path).unwrap();
        let mut destination = fs_private::create_new_private(&destination_path).unwrap();
        assert!(matches!(
            copy_exact_with_digest(&mut source, &mut destination, 3),
            Err(HarnessError::ArtifactLimitsExceeded)
        ));

        let missing_parent = temp.path().join("missing/outbox.json");
        std::fs::write(temp.path().join("missing"), b"not-a-directory").unwrap();
        let mut outbox = ArtifactOutbox::load(temp.path().join("record-outbox.json")).unwrap();
        outbox.path = missing_parent;
        let batch = PendingArtifactBatch {
            idempotency_key: "key".to_owned(),
            account_ref: "account".to_owned(),
            group_ref: "group".to_owned(),
            reply_to_message_ref: "message".to_owned(),
            caption: None,
            remaining_text: Vec::new(),
            artifacts: Vec::new(),
        };
        assert!(outbox.record(batch.clone()).is_err());
        assert!(outbox.pending().is_empty());

        let mut durable = ArtifactOutbox::load(temp.path().join("state/outbox.json")).unwrap();
        durable.record(batch).unwrap();
        durable.path = temp.path().join("blocked/outbox.json");
        std::fs::write(temp.path().join("blocked"), b"not-a-directory").unwrap();
        assert!(durable.complete("key").is_err());
        assert_eq!(durable.pending().len(), 1);
    }

    #[test]
    fn batch_limits_and_destination_binding_are_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        std::fs::create_dir(&root).unwrap();
        let empty = root.join("empty");
        std::fs::write(&empty, b"").unwrap();
        let cfg = config(
            &root,
            &temp.path().join("staging-empty"),
            &temp.path().join("outbox-empty.json"),
        );
        assert!(
            stage_artifacts(
                &cfg,
                "wn-test",
                "account",
                "group",
                "message",
                &[ArtifactOutput {
                    authorization_id: "auth".to_owned(),
                    path: empty,
                    media_type: "application/octet-stream".to_owned(),
                    file_name: "empty".to_owned(),
                }],
            )
            .is_err()
        );
        let source = root.join("value");
        std::fs::write(&source, b"value").unwrap();
        let too_many = (0..=MAX_ARTIFACTS_PER_RESULT)
            .map(|index| ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source.clone(),
                media_type: "application/octet-stream".to_owned(),
                file_name: format!("value-{index}"),
            })
            .collect::<Vec<_>>();
        assert!(
            stage_artifacts(&cfg, "wn-test", "account", "group", "message", &too_many).is_err()
        );

        let first = stage_artifacts(
            &config(
                &root,
                &temp.path().join("staging-a"),
                &temp.path().join("a.json"),
            ),
            "wn-test",
            "account-a",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source.clone(),
                media_type: "application/octet-stream".to_owned(),
                file_name: "value".to_owned(),
            }],
        )
        .unwrap();
        let second = stage_artifacts(
            &config(
                &root,
                &temp.path().join("staging-b"),
                &temp.path().join("b.json"),
            ),
            "wn-test",
            "account-b",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source,
                media_type: "application/octet-stream".to_owned(),
                file_name: "value".to_owned(),
            }],
        )
        .unwrap();
        assert_ne!(first.idempotency_key, second.idempotency_key);
    }

    #[test]
    fn replay_revalidates_staging_root_hash_and_single_link() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        let source = root.join("value");
        std::fs::write(&source, b"value").unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        let mut batch = stage_artifacts(
            &cfg,
            "wn-test",
            "account",
            "group",
            "message",
            &[ArtifactOutput {
                authorization_id: "auth".to_owned(),
                path: source,
                media_type: "application/octet-stream".to_owned(),
                file_name: "value".to_owned(),
            }],
        )
        .unwrap();
        assert!(validate_staged_batch(&cfg, "wn-test", &batch).is_ok());
        std::fs::write(&batch.artifacts[0].path, b"other").unwrap();
        assert!(validate_staged_batch(&cfg, "wn-test", &batch).is_err());
        std::fs::write(&batch.artifacts[0].path, b"value").unwrap();
        let second_link = staging.join("second-link");
        std::fs::hard_link(&batch.artifacts[0].path, second_link).unwrap();
        assert!(validate_staged_batch(&cfg, "wn-test", &batch).is_err());
        batch.artifacts[0].path = temp.path().join("outside");
        std::fs::write(&batch.artifacts[0].path, b"value").unwrap();
        batch.idempotency_key = artifact_idempotency_key(
            "wn-test",
            "account",
            "group",
            "message",
            batch.caption.as_deref(),
            &batch.artifacts,
        )
        .unwrap();
        assert!(validate_staged_batch(&cfg, "wn-test", &batch).is_err());
    }

    #[test]
    fn authorization_is_bound_to_group_turn_root_and_ttl() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let staging = temp.path().join("staging");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("report.pdf"), b"report").unwrap();
        let cfg = config(&root, &staging, &temp.path().join("outbox.json"));
        assert!(cfg.authorize("other-group", "message").unwrap().is_none());
        let authorization = cfg.authorize("group", "message").unwrap().unwrap();
        let output = ArtifactOutput {
            authorization_id: authorization.id().to_owned(),
            path: PathBuf::from("report.pdf"),
            media_type: "application/pdf".to_owned(),
            file_name: "report.pdf".to_owned(),
        };
        assert!(
            super::stage_artifacts(
                &cfg,
                ArtifactDeliveryContext {
                    reply_prefix: "wn-test",
                    account_ref: "account",
                    group_ref: "group",
                    message_ref: "message",
                    caption: Some("Report attached".to_owned()),
                    remaining_text: Vec::new(),
                },
                &authorization,
                std::slice::from_ref(&output),
            )
            .is_ok()
        );

        let mut wrong_turn = authorization.clone();
        wrong_turn.message_ref = "other-message".to_owned();
        assert!(matches!(
            super::stage_artifacts(
                &cfg,
                ArtifactDeliveryContext {
                    reply_prefix: "wn-test",
                    account_ref: "account",
                    group_ref: "group",
                    message_ref: "message",
                    caption: None,
                    remaining_text: Vec::new(),
                },
                &wrong_turn,
                std::slice::from_ref(&output),
            ),
            Err(HarnessError::ArtifactAuthorizationInvalid)
        ));

        let mut expired = authorization;
        expired.expires_at_unix_secs = 0;
        assert!(matches!(
            super::stage_artifacts(
                &cfg,
                ArtifactDeliveryContext {
                    reply_prefix: "wn-test",
                    account_ref: "account",
                    group_ref: "group",
                    message_ref: "message",
                    caption: None,
                    remaining_text: Vec::new(),
                },
                &expired,
                &[output],
            ),
            Err(HarnessError::ArtifactAuthorizationInvalid)
        ));
    }
}
