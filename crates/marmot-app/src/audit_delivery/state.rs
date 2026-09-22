use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::recovery::{
    FaultPoint, Faults, JournalDirectories, atomic_replace, create_journal_directories,
    open_or_recover_empty_journal_directories, open_segment_read, open_segment_sync, read_bounded,
    validate_single_component,
};

const FORMAT_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const STATE_FILE: &str = "state.json";
const SEGMENTS_DIR: &str = "segments";
const MAX_SEGMENTS: usize = 256;
const MAX_RECORDS_PER_RANGE: usize = 8;
pub(super) const MAX_RANGE_BYTES: usize = 1024 * 1024;
const BOUNDARY_DIGEST_BYTES: u64 = 64 * 1024;
const ACKNOWLEDGED_DIGEST_DOMAIN: &[u8] = b"marmot-audit-delivery-acknowledged-v1";
pub(super) const MAX_METADATA_BYTES: usize = 1024 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JournalId(String);

impl JournalId {
    /// Generate an opaque, collision-resistant local journal identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(random_id())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuditDeliveryError> {
        let value = value.into();
        validate_single_component(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JournalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JournalId([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SegmentId(String);

impl SegmentId {
    #[must_use]
    pub fn generate() -> Self {
        Self(random_id())
    }

    pub fn parse(value: impl Into<String>) -> Result<Self, AuditDeliveryError> {
        let value = value.into();
        validate_single_component(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SegmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SegmentId([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DestinationProfile(String);

impl DestinationProfile {
    pub fn new(value: impl Into<String>) -> Result<Self, AuditDeliveryError> {
        let value = value.into();
        let profile = Self(value);
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), AuditDeliveryError> {
        if self.0.is_empty() || self.0.len() > 256 || self.0.chars().any(char::is_control) {
            Err(AuditDeliveryError::InvalidDestinationProfile)
        } else {
            Ok(())
        }
    }
}

impl fmt::Debug for DestinationProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DestinationProfile([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    Active,
    Sealed,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttemptToken {
    journal_id: JournalId,
    destination_profile: DestinationProfile,
    attempt_id: String,
    prepared_revision: u64,
    owner_epoch: [u8; 16],
}

impl fmt::Debug for AttemptToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttemptToken([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PreparedRange {
    bodies: Vec<Vec<u8>>,
    digest: [u8; 32],
    start_offset: u64,
    end_offset: u64,
    token: AttemptToken,
}

impl PreparedRange {
    #[must_use]
    pub fn bodies(&self) -> &[Vec<u8>] {
        &self.bodies
    }

    #[must_use]
    pub fn ordered_body_digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub fn start_offset(&self) -> u64 {
        self.start_offset
    }

    #[must_use]
    pub fn end_offset(&self) -> u64 {
        self.end_offset
    }

    #[must_use]
    pub fn token(&self) -> &AttemptToken {
        &self.token
    }
}

impl fmt::Debug for PreparedRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRange")
            .field("record_count", &self.bodies.len())
            .field("start_offset", &self.start_offset)
            .field("end_offset", &self.end_offset)
            .field("digest", &"[redacted]")
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuditDeliveryError {
    #[error("unsafe audit-delivery identifier")]
    UnsafeIdentifier,
    #[error("unsafe audit-delivery path")]
    UnsafePath,
    #[error("invalid destination profile")]
    InvalidDestinationProfile,
    #[error("journal generation already exists")]
    GenerationCollision,
    #[error("unsupported audit-delivery metadata version")]
    UnknownVersion,
    #[error("audit-delivery metadata is missing or incomplete")]
    IncompleteState,
    #[error("audit-delivery metadata is corrupt")]
    CorruptState,
    #[error("audit-delivery metadata exceeds its bound")]
    MetadataTooLarge,
    #[error("audit-delivery segment bound exceeded")]
    SegmentLimit,
    #[error("audit-delivery segment is already registered")]
    DuplicateSegment,
    #[error("audit-delivery segment ordering is invalid")]
    InvalidSegmentOrder,
    #[error("audit-delivery segment is missing")]
    MissingSegment,
    #[error("audit-delivery range exceeds its bound")]
    RangeTooLarge,
    #[error("audit-delivery range is not valid UTF-8 JSONL framing")]
    InvalidJsonl,
    #[error("audit-delivery store already has a prepared range")]
    PreparationPending,
    #[error("audit-delivery attempt token is stale")]
    StaleToken,
    #[error("audit-delivery owner is closed")]
    Closed,
    #[error("audit-delivery owner requires reopen recovery")]
    RecoveryRequired,
    #[error("audit-delivery metadata publication has uncertain durability")]
    UncertainPublication {
        #[source]
        source: std::io::Error,
    },
    #[error("could not allocate a private staging file")]
    TemporaryNameExhausted,
    #[error("audit-delivery filesystem operation failed: {operation}")]
    Filesystem {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    journal_id: JournalId,
    segments: Vec<SegmentEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentEntry {
    segment_id: SegmentId,
    relative_name: String,
    status: SegmentStatus,
    registered_length: u64,
    registered_digest: String,
    file_identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedPrefix {
    segment_id: SegmentId,
    file_identity: FileIdentity,
    registered_length: u64,
    registered_digest: String,
}

impl VerifiedPrefix {
    fn matches(&self, entry: &SegmentEntry) -> bool {
        self.segment_id == entry.segment_id
            && self.file_identity == entry.file_identity
            && self.registered_length == entry.registered_length
            && self.registered_digest == entry.registered_digest
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableState {
    version: u32,
    journal_id: JournalId,
    destination_profile: DestinationProfile,
    revision: u64,
    cursors: Vec<SegmentCursor>,
    prepared: Option<PreparedState>,
    health: HealthState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentCursor {
    segment_id: SegmentId,
    acknowledged_end: u64,
    boundary_digest: String,
    acknowledged_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedState {
    attempt_id: String,
    segment_id: SegmentId,
    start_offset: u64,
    end_offset: u64,
    ordered_body_digest: String,
    prepared_revision: u64,
}

// Reserved by the v1 handoff for later durable gap counters. PR1 writes only
// `Clean`: after an uncertain directory sync it must fence in memory and reopen
// the observable old/new document instead of attempting a second publication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthState {
    status: HealthStatus,
    recovery_events: u32,
    corruption_events: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HealthStatus {
    Clean,
    RecoveryRequired,
    Corrupt,
}

/// Single-owner metadata store for one private JSONL journal generation.
///
/// The payload segment files must already exist. Registering one records its
/// initial length and digest but never creates, appends, truncates, or deletes
/// payload data.
pub struct AuditDeliveryStore {
    root: PathBuf,
    directories: JournalDirectories,
    manifest: Manifest,
    state: DurableState,
    owner_epoch: [u8; 16],
    closed: bool,
    recovery_required: bool,
    faults: Faults,
    verified_prefix: Mutex<Option<VerifiedPrefix>>,
    #[cfg(test)]
    registered_prefix_validations: AtomicUsize,
}

impl fmt::Debug for AuditDeliveryStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditDeliveryStore")
            .field("journal_id", &self.manifest.journal_id)
            .field("segment_count", &self.manifest.segments.len())
            .field("revision", &self.state.revision)
            .field("closed", &self.closed)
            .field("recovery_required", &self.recovery_required)
            .finish()
    }
}

impl AuditDeliveryStore {
    /// Create a new empty generation below
    /// `<account>/audit-delivery/v1/<journal-id>`.
    pub fn create(
        account_root: impl AsRef<Path>,
        journal_id: JournalId,
        destination_profile: DestinationProfile,
    ) -> Result<Self, AuditDeliveryError> {
        Self::create_with_faults(
            account_root.as_ref(),
            journal_id,
            destination_profile,
            Faults::default(),
        )
    }

    fn create_with_faults(
        account_root: &Path,
        journal_id: JournalId,
        destination_profile: DestinationProfile,
        faults: Faults,
    ) -> Result<Self, AuditDeliveryError> {
        validate_single_component(journal_id.as_str())?;
        destination_profile.validate()?;
        let root = account_root
            .join("audit-delivery")
            .join("v1")
            .join(journal_id.as_str());
        let directories = create_journal_directories(&root)?;
        let manifest = Manifest {
            version: FORMAT_VERSION,
            journal_id: journal_id.clone(),
            segments: Vec::new(),
        };
        let state = initial_state(journal_id, destination_profile);
        let mut store = Self {
            root,
            directories,
            manifest,
            state,
            owner_epoch: random_epoch(),
            closed: false,
            recovery_required: false,
            faults,
            verified_prefix: Mutex::new(None),
            #[cfg(test)]
            registered_prefix_validations: AtomicUsize::new(0),
        };
        store.publish_manifest()?;
        store.publish_state()?;
        Ok(store)
    }

    /// Reopen and fully validate an existing generation. A strictly safe
    /// create/registration publication gap is completed conservatively with a
    /// zero cursor; missing, inconsistent, unknown-version, or ambiguous state
    /// otherwise fails closed and is never reset.
    pub fn open(
        account_root: impl AsRef<Path>,
        journal_id: JournalId,
        destination_profile: DestinationProfile,
    ) -> Result<Self, AuditDeliveryError> {
        validate_single_component(journal_id.as_str())?;
        let root = account_root
            .as_ref()
            .join("audit-delivery")
            .join("v1")
            .join(journal_id.as_str());
        destination_profile.validate()?;
        let directories = open_or_recover_empty_journal_directories(&root)?;
        let manifest: Manifest = match decode_metadata(&directories.root, MANIFEST_FILE) {
            Ok(manifest) => manifest,
            Err(AuditDeliveryError::IncompleteState) => {
                match decode_metadata::<DurableState>(&directories.root, STATE_FILE) {
                    Err(AuditDeliveryError::IncompleteState) => {}
                    Err(error) => return Err(error),
                    Ok(_) => return Err(AuditDeliveryError::IncompleteState),
                }
                let segments_empty = directories.segments.is_empty().map_err(|source| {
                    AuditDeliveryError::Filesystem {
                        operation: "inspect incomplete generation segments",
                        source,
                    }
                })?;
                if !segments_empty {
                    return Err(AuditDeliveryError::IncompleteState);
                }

                let manifest = Manifest {
                    version: FORMAT_VERSION,
                    journal_id: journal_id.clone(),
                    segments: Vec::new(),
                };
                let mut state = initial_state(journal_id.clone(), destination_profile.clone());
                state.health.recovery_events = 1;
                let mut store = Self {
                    root,
                    directories,
                    manifest,
                    state,
                    owner_epoch: random_epoch(),
                    closed: false,
                    recovery_required: false,
                    faults: Faults::default(),
                    verified_prefix: Mutex::new(None),
                    #[cfg(test)]
                    registered_prefix_validations: AtomicUsize::new(0),
                };
                store.publish_manifest()?;
                store.publish_state()?;
                store.validate_all()?;
                return Ok(store);
            }
            Err(error) => return Err(error),
        };
        if manifest.version != FORMAT_VERSION {
            return Err(AuditDeliveryError::UnknownVersion);
        }
        if manifest.journal_id != journal_id {
            return Err(AuditDeliveryError::CorruptState);
        }
        let (state, recover_missing_initial_state) =
            match decode_metadata(&directories.root, STATE_FILE) {
                Ok(state) => (state, false),
                Err(AuditDeliveryError::IncompleteState) if manifest.segments.is_empty() => {
                    let mut state = initial_state(journal_id.clone(), destination_profile.clone());
                    state.health.recovery_events = 1;
                    (state, true)
                }
                Err(error) => return Err(error),
            };
        if state.version != FORMAT_VERSION {
            return Err(AuditDeliveryError::UnknownVersion);
        }
        if state.journal_id != journal_id || state.destination_profile != destination_profile {
            return Err(AuditDeliveryError::CorruptState);
        }
        let mut store = Self {
            root,
            directories,
            manifest,
            state,
            owner_epoch: random_epoch(),
            closed: false,
            recovery_required: false,
            faults: Faults::default(),
            verified_prefix: Mutex::new(None),
            #[cfg(test)]
            registered_prefix_validations: AtomicUsize::new(0),
        };
        if recover_missing_initial_state {
            store.publish_state()?;
        }
        store.recover_registration_gap()?;
        store.validate_all()?;
        Ok(store)
    }

    /// Return the deterministic path where a future recorder or a synthetic
    /// test fixture may create this segment. This method performs no I/O.
    pub fn segment_path(&self, segment_id: &SegmentId) -> Result<PathBuf, AuditDeliveryError> {
        validate_single_component(segment_id.as_str())?;
        Ok(self
            .root
            .join(SEGMENTS_DIR)
            .join(format!("{}.jsonl", segment_id.as_str())))
    }

    /// Register an already-created private payload segment.
    ///
    /// The manifest is published before its zero acknowledgement cursor. A
    /// crash between those documents recovers that cursor at zero rather than
    /// guessing that any bytes were acknowledged.
    pub fn register_segment(
        &mut self,
        segment_id: SegmentId,
        status: SegmentStatus,
    ) -> Result<(), AuditDeliveryError> {
        self.ensure_open()?;
        if self.state.prepared.is_some() {
            return Err(AuditDeliveryError::PreparationPending);
        }
        if self.manifest.segments.len() >= MAX_SEGMENTS {
            return Err(AuditDeliveryError::SegmentLimit);
        }
        if self
            .manifest
            .segments
            .iter()
            .any(|entry| entry.segment_id == segment_id)
        {
            return Err(AuditDeliveryError::DuplicateSegment);
        }
        if self
            .manifest
            .segments
            .iter()
            .any(|entry| entry.status == SegmentStatus::Active)
        {
            return Err(AuditDeliveryError::InvalidSegmentOrder);
        }
        let file_name = segment_file_name(&segment_id);
        let file = open_segment_sync(&self.directories.segments, OsStr::new(&file_name))?;
        let (length, digest) = file_length_and_digest(&file)?;
        validate_payload_framing(&file, length, status == SegmentStatus::Sealed)?;
        sync_payload(&file, &mut self.faults)?;
        let relative_name = format!("{SEGMENTS_DIR}/{}.jsonl", segment_id.as_str());
        let mut manifest = self.manifest.clone();
        manifest.segments.push(SegmentEntry {
            segment_id: segment_id.clone(),
            relative_name,
            status,
            registered_length: length,
            registered_digest: hex::encode(digest),
            file_identity: file_identity(&file)?,
        });
        self.publish_manifest_value(&manifest)?;
        self.manifest = manifest;
        self.invalidate_verified_prefix();

        let mut state = self.state.clone();
        state.revision = next_revision(state.revision)?;
        state.cursors.push(SegmentCursor {
            segment_id,
            acknowledged_end: 0,
            boundary_digest: hex::encode(Sha256::digest([])),
            acknowledged_digest: hex::encode(initial_acknowledged_digest()),
        });
        if let Err(error) = self.publish_state_value(&state) {
            self.recovery_required = true;
            return Err(error);
        }
        self.state = state;
        Ok(())
    }

    /// Seal the current active segment after its writer has stopped appending.
    ///
    /// This only publishes the final payload identity in the manifest. Recorder
    /// rotation and lifecycle ownership remain outside this inactive foundation.
    pub fn seal_active_segment(
        &mut self,
        segment_id: &SegmentId,
    ) -> Result<(), AuditDeliveryError> {
        self.ensure_open()?;
        if self.state.prepared.is_some() {
            return Err(AuditDeliveryError::PreparationPending);
        }
        let entry = self.segment(segment_id)?;
        if entry.status != SegmentStatus::Active
            || self.manifest.segments.last().map(|entry| &entry.segment_id) != Some(segment_id)
        {
            return Err(AuditDeliveryError::InvalidSegmentOrder);
        }
        let file_name = segment_file_name(segment_id);
        let file = open_segment_sync(&self.directories.segments, OsStr::new(&file_name))?;
        validate_registered_shape(&file, entry)?;
        validate_registered_digest(&file, entry)?;
        let (length, digest) = file_length_and_digest(&file)?;
        let cursor = self.cursor(segment_id)?;
        validate_acknowledged_boundary(&file, cursor)?;
        validate_acknowledged_digest(&file, cursor)?;
        validate_payload_framing(&file, length, true)?;
        sync_payload(&file, &mut self.faults)?;

        let mut manifest = self.manifest.clone();
        let entry = manifest
            .segments
            .last_mut()
            .ok_or(AuditDeliveryError::MissingSegment)?;
        entry.status = SegmentStatus::Sealed;
        entry.registered_length = length;
        entry.registered_digest = hex::encode(digest);
        self.publish_manifest_value(&manifest)?;
        self.manifest = manifest;
        self.invalidate_verified_prefix();
        Ok(())
    }

    /// Prepare the next bounded complete-line range, or return `None` when no
    /// complete new line is available. An existing unresolved range must be
    /// recovered with [`Self::recover_prepared`] first.
    pub fn prepare_next(&mut self) -> Result<Option<PreparedRange>, AuditDeliveryError> {
        self.ensure_open()?;
        if self.state.prepared.is_some() {
            return Err(AuditDeliveryError::PreparationPending);
        }
        for entry in &self.manifest.segments {
            let cursor = self.cursor(&entry.segment_id)?;
            if entry.status == SegmentStatus::Sealed
                && cursor.acknowledged_end == entry.registered_length
            {
                continue;
            }
            let file_name = segment_file_name(&entry.segment_id);
            let mut file = open_segment_sync(&self.directories.segments, OsStr::new(&file_name))?;
            self.validate_live_segment(&file, entry)?;
            validate_acknowledged_boundary(&file, cursor)?;
            let (bodies, end_offset) =
                read_complete_range(&mut file, cursor.acknowledged_end, None)?;
            if bodies.is_empty() {
                let length = file
                    .metadata()
                    .map_err(|source| AuditDeliveryError::Filesystem {
                        operation: "inspect empty payload range",
                        source,
                    })?
                    .len();
                if length == cursor.acknowledged_end {
                    continue;
                }
                return match entry.status {
                    SegmentStatus::Active => Ok(None),
                    SegmentStatus::Sealed => Err(AuditDeliveryError::InvalidJsonl),
                };
            }
            let digest = ordered_body_digest(&bodies);
            let revision = next_revision(self.state.revision)?;
            let prepared = PreparedState {
                attempt_id: random_id(),
                segment_id: entry.segment_id.clone(),
                start_offset: cursor.acknowledged_end,
                end_offset,
                ordered_body_digest: hex::encode(digest),
                prepared_revision: revision,
            };

            let current_len = file
                .metadata()
                .map_err(|source| AuditDeliveryError::Filesystem {
                    operation: "inspect payload before sync",
                    source,
                })?
                .len();
            if current_len < end_offset {
                return Err(AuditDeliveryError::CorruptState);
            }
            sync_payload(&file, &mut self.faults)?;

            let mut state = self.state.clone();
            state.revision = revision;
            state.prepared = Some(prepared.clone());
            self.publish_state_value(&state)?;
            self.state = state;
            return Ok(Some(self.range_from_parts(prepared, bodies, digest)));
        }
        Ok(None)
    }

    /// Re-read and verify the unchanged bytes for the unresolved attempt.
    pub fn recover_prepared(&self) -> Result<Option<PreparedRange>, AuditDeliveryError> {
        self.ensure_open()?;
        let Some(prepared) = self.state.prepared.clone() else {
            return Ok(None);
        };
        validate_single_component(&prepared.attempt_id)?;
        self.validate_prepared_cursor(&prepared)?;
        let entry = self.segment(&prepared.segment_id)?;
        let file_name = segment_file_name(&entry.segment_id);
        let mut file = open_segment_read(&self.directories.segments, OsStr::new(&file_name))?;
        self.validate_live_segment(&file, entry)?;
        let (bodies, end_offset) =
            read_complete_range(&mut file, prepared.start_offset, Some(prepared.end_offset))?;
        if end_offset != prepared.end_offset
            || hex::encode(ordered_body_digest(&bodies)) != prepared.ordered_body_digest
        {
            return Err(AuditDeliveryError::CorruptState);
        }
        let digest = ordered_body_digest(&bodies);
        Ok(Some(self.range_from_parts(prepared, bodies, digest)))
    }

    /// Advance exactly the range proven by `token` and atomically clear it.
    pub fn acknowledge(&mut self, token: &AttemptToken) -> Result<(), AuditDeliveryError> {
        self.ensure_open()?;
        let prepared = self
            .state
            .prepared
            .clone()
            .ok_or(AuditDeliveryError::StaleToken)?;
        self.validate_prepared_cursor(&prepared)?;
        if token.owner_epoch != self.owner_epoch
            || token.journal_id != self.state.journal_id
            || token.destination_profile != self.state.destination_profile
            || token.attempt_id != prepared.attempt_id
            || token.prepared_revision != prepared.prepared_revision
            || self.state.revision != prepared.prepared_revision
        {
            return Err(AuditDeliveryError::StaleToken);
        }
        // Re-verify the complete in-flight bytes immediately before advancing.
        let recovered = self
            .recover_prepared()?
            .ok_or(AuditDeliveryError::CorruptState)?;
        let entry = self.segment(&prepared.segment_id)?;
        let file_name = segment_file_name(&entry.segment_id);
        let file = open_segment_read(&self.directories.segments, OsStr::new(&file_name))?;
        validate_registered_shape(&file, entry)?;
        let current_cursor = self.cursor(&prepared.segment_id)?;
        validate_acknowledged_boundary(&file, current_cursor)?;
        validate_acknowledged_digest(&file, current_cursor)?;
        let previous_digest = decode_digest(&current_cursor.acknowledged_digest)?;
        let (acknowledged_digest, acknowledged_end) =
            extend_acknowledged_digest(previous_digest, prepared.start_offset, recovered.bodies())?;
        if acknowledged_end != prepared.end_offset {
            return Err(AuditDeliveryError::CorruptState);
        }
        let boundary_digest = digest_boundary(&file, prepared.end_offset)?;
        let mut state = self.state.clone();
        state.revision = next_revision(state.revision)?;
        let cursor = state
            .cursors
            .iter_mut()
            .find(|cursor| cursor.segment_id == prepared.segment_id)
            .ok_or(AuditDeliveryError::IncompleteState)?;
        cursor.acknowledged_end = prepared.end_offset;
        cursor.boundary_digest = hex::encode(boundary_digest);
        cursor.acknowledged_digest = hex::encode(acknowledged_digest);
        state.prepared = None;
        self.publish_state_value(&state)?;
        self.state = state;
        Ok(())
    }

    /// Fence this owner. An unresolved range remains on disk for a newly
    /// opened owner, while this handle and every token it issued become inert.
    pub fn close(&mut self) {
        self.closed = true;
        self.owner_epoch = random_epoch();
    }

    fn range_from_parts(
        &self,
        prepared: PreparedState,
        bodies: Vec<Vec<u8>>,
        digest: [u8; 32],
    ) -> PreparedRange {
        PreparedRange {
            bodies,
            digest,
            start_offset: prepared.start_offset,
            end_offset: prepared.end_offset,
            token: AttemptToken {
                journal_id: self.state.journal_id.clone(),
                destination_profile: self.state.destination_profile.clone(),
                attempt_id: prepared.attempt_id,
                prepared_revision: prepared.prepared_revision,
                owner_epoch: self.owner_epoch,
            },
        }
    }

    fn validate_all(&self) -> Result<(), AuditDeliveryError> {
        if self.manifest.segments.len() > MAX_SEGMENTS {
            return Err(AuditDeliveryError::SegmentLimit);
        }
        if self.manifest.segments.len() != self.state.cursors.len() {
            return Err(AuditDeliveryError::IncompleteState);
        }
        let mut ids = std::collections::HashSet::with_capacity(self.manifest.segments.len());
        for (index, entry) in self.manifest.segments.iter().enumerate() {
            validate_single_component(entry.segment_id.as_str())?;
            if entry.relative_name != format!("{SEGMENTS_DIR}/{}.jsonl", entry.segment_id.as_str())
                || !ids.insert(entry.segment_id.as_str())
            {
                return Err(AuditDeliveryError::CorruptState);
            }
            if entry.status == SegmentStatus::Active && index + 1 != self.manifest.segments.len() {
                return Err(AuditDeliveryError::InvalidSegmentOrder);
            }
            let cursor = self.cursor(&entry.segment_id)?;
            let file_name = segment_file_name(&entry.segment_id);
            let file = open_segment_read(&self.directories.segments, OsStr::new(&file_name))?;
            self.validate_live_segment(&file, entry)?;
            validate_acknowledged_boundary(&file, cursor)?;
            validate_acknowledged_digest(&file, cursor)?;
        }
        match self.state.health.status {
            HealthStatus::Clean => {}
            HealthStatus::RecoveryRequired => return Err(AuditDeliveryError::RecoveryRequired),
            HealthStatus::Corrupt => return Err(AuditDeliveryError::CorruptState),
        }
        if self.state.prepared.is_some() {
            self.recover_prepared()?;
        }
        Ok(())
    }

    fn validate_live_segment(
        &self,
        file: &File,
        entry: &SegmentEntry,
    ) -> Result<(), AuditDeliveryError> {
        validate_registered_shape(file, entry)?;
        if self
            .verified_prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|verified| verified.matches(entry))
        {
            return Ok(());
        }

        #[cfg(test)]
        self.registered_prefix_validations
            .fetch_add(1, Ordering::Relaxed);
        validate_registered_digest(file, entry)?;
        *self
            .verified_prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(VerifiedPrefix {
            segment_id: entry.segment_id.clone(),
            file_identity: entry.file_identity.clone(),
            registered_length: entry.registered_length,
            registered_digest: entry.registered_digest.clone(),
        });
        Ok(())
    }

    fn invalidate_verified_prefix(&self) {
        *self
            .verified_prefix
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    #[cfg(test)]
    pub(super) fn registered_prefix_validation_count(&self) -> usize {
        self.registered_prefix_validations.load(Ordering::Relaxed)
    }

    fn recover_registration_gap(&mut self) -> Result<(), AuditDeliveryError> {
        if self.manifest.segments.len() == self.state.cursors.len() {
            return Ok(());
        }
        if self.manifest.segments.len() != self.state.cursors.len().saturating_add(1)
            || self.state.prepared.is_some()
        {
            return Err(AuditDeliveryError::IncompleteState);
        }

        let segment_id = self
            .manifest
            .segments
            .last()
            .ok_or(AuditDeliveryError::IncompleteState)?
            .segment_id
            .clone();
        let mut recovered = self.state.clone();
        recovered.revision = next_revision(recovered.revision)?;
        recovered.health.recovery_events = recovered
            .health
            .recovery_events
            .checked_add(1)
            .ok_or(AuditDeliveryError::CorruptState)?;
        recovered.cursors.push(SegmentCursor {
            segment_id,
            acknowledged_end: 0,
            boundary_digest: hex::encode(Sha256::digest([])),
            acknowledged_digest: hex::encode(initial_acknowledged_digest()),
        });

        let previous = std::mem::replace(&mut self.state, recovered.clone());
        let validation = self.validate_all();
        self.state = previous;
        validation?;
        self.publish_state_value(&recovered)?;
        self.state = recovered;
        Ok(())
    }

    fn validate_prepared_cursor(&self, prepared: &PreparedState) -> Result<(), AuditDeliveryError> {
        let cursor = self.cursor(&prepared.segment_id)?;
        if prepared.start_offset != cursor.acknowledged_end
            || prepared.end_offset <= prepared.start_offset
            || prepared.end_offset - prepared.start_offset > MAX_RANGE_BYTES as u64
            || prepared.prepared_revision != self.state.revision
        {
            return Err(AuditDeliveryError::CorruptState);
        }
        Ok(())
    }

    fn segment(&self, id: &SegmentId) -> Result<&SegmentEntry, AuditDeliveryError> {
        self.manifest
            .segments
            .iter()
            .find(|entry| entry.segment_id == *id)
            .ok_or(AuditDeliveryError::MissingSegment)
    }

    fn cursor(&self, id: &SegmentId) -> Result<&SegmentCursor, AuditDeliveryError> {
        self.state
            .cursors
            .iter()
            .find(|cursor| cursor.segment_id == *id)
            .ok_or(AuditDeliveryError::IncompleteState)
    }

    fn ensure_open(&self) -> Result<(), AuditDeliveryError> {
        if self.closed {
            Err(AuditDeliveryError::Closed)
        } else if self.recovery_required {
            Err(AuditDeliveryError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn publish_manifest(&mut self) -> Result<(), AuditDeliveryError> {
        let manifest = self.manifest.clone();
        self.publish_manifest_value(&manifest)
    }

    fn publish_manifest_value(&mut self, manifest: &Manifest) -> Result<(), AuditDeliveryError> {
        self.publish_metadata(MANIFEST_FILE, manifest)
    }

    fn publish_state(&mut self) -> Result<(), AuditDeliveryError> {
        let state = self.state.clone();
        self.publish_state_value(&state)
    }

    fn publish_state_value(&mut self, state: &DurableState) -> Result<(), AuditDeliveryError> {
        self.publish_metadata(STATE_FILE, state)
    }

    fn publish_metadata(
        &mut self,
        file_name: &str,
        value: &impl Serialize,
    ) -> Result<(), AuditDeliveryError> {
        let bytes = encode_metadata(value)?;
        let result = atomic_replace(
            &self.directories.root,
            OsStr::new(file_name),
            &bytes,
            &mut self.faults,
        );
        if matches!(result, Err(AuditDeliveryError::UncertainPublication { .. })) {
            self.recovery_required = true;
        }
        result
    }

    #[cfg(test)]
    pub(super) fn fail_next(&mut self, point: FaultPoint) {
        self.faults.fail_next(point);
    }

    #[cfg(test)]
    pub(super) fn fail_after(&mut self, point: FaultPoint, matching_calls_to_skip: u8) {
        self.faults.fail_after(point, matching_calls_to_skip);
    }

    #[cfg(test)]
    pub(super) fn create_failing(
        account_root: &Path,
        journal_id: JournalId,
        destination_profile: DestinationProfile,
        point: FaultPoint,
    ) -> Result<Self, AuditDeliveryError> {
        let mut faults = Faults::default();
        faults.fail_next(point);
        Self::create_with_faults(account_root, journal_id, destination_profile, faults)
    }
}

fn initial_state(journal_id: JournalId, destination_profile: DestinationProfile) -> DurableState {
    DurableState {
        version: FORMAT_VERSION,
        journal_id,
        destination_profile,
        revision: 0,
        cursors: Vec::new(),
        prepared: None,
        health: HealthState {
            status: HealthStatus::Clean,
            recovery_events: 0,
            corruption_events: 0,
        },
    }
}

fn encode_metadata(value: &impl Serialize) -> Result<Vec<u8>, AuditDeliveryError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| AuditDeliveryError::CorruptState)?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(AuditDeliveryError::MetadataTooLarge);
    }
    Ok(bytes)
}

fn decode_metadata<T: for<'de> Deserialize<'de>>(
    root: &fs_private::PreparedDirectory,
    file_name: &str,
) -> Result<T, AuditDeliveryError> {
    let bytes = match read_bounded(root, OsStr::new(file_name)) {
        Ok(bytes) => bytes,
        Err(AuditDeliveryError::Filesystem { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Err(AuditDeliveryError::IncompleteState);
        }
        Err(error) => return Err(error),
    };
    serde_json::from_slice(&bytes).map_err(|_| AuditDeliveryError::CorruptState)
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_epoch() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn next_revision(revision: u64) -> Result<u64, AuditDeliveryError> {
    revision
        .checked_add(1)
        .ok_or(AuditDeliveryError::CorruptState)
}

fn file_length_and_digest(file: &File) -> Result<(u64, [u8; 32]), AuditDeliveryError> {
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect payload segment",
            source,
        })?
        .len();
    Ok((length, digest_range(file, 0, length)?))
}

fn sync_payload(file: &File, faults: &mut Faults) -> Result<(), AuditDeliveryError> {
    faults.check(FaultPoint::PayloadSync)?;
    file.sync_all()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "sync payload prefix",
            source,
        })
}

fn validate_payload_framing(
    file: &File,
    length: u64,
    require_final_newline: bool,
) -> Result<(), AuditDeliveryError> {
    let mut file = file
        .try_clone()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "clone payload framing handle",
            source,
        })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "seek payload framing range",
            source,
        })?;

    let mut remaining = length;
    let mut buffer = [0u8; 16 * 1024];
    let mut body = Vec::new();
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AuditDeliveryError::RangeTooLarge)?;
        file.read_exact(&mut buffer[..amount]).map_err(|source| {
            AuditDeliveryError::Filesystem {
                operation: "read payload framing range",
                source,
            }
        })?;
        let mut body_start = 0usize;
        for (index, byte) in buffer[..amount].iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let body_length = body
                .len()
                .checked_add(index - body_start)
                .ok_or(AuditDeliveryError::RangeTooLarge)?;
            if body_length
                .checked_add(1)
                .ok_or(AuditDeliveryError::RangeTooLarge)?
                > MAX_RANGE_BYTES
            {
                return Err(AuditDeliveryError::RangeTooLarge);
            }
            body.extend_from_slice(&buffer[body_start..index]);
            std::str::from_utf8(&body).map_err(|_| AuditDeliveryError::InvalidJsonl)?;
            body.clear();
            body_start = index + 1;
        }
        if body_start < amount {
            let body_length = body
                .len()
                .checked_add(amount - body_start)
                .ok_or(AuditDeliveryError::RangeTooLarge)?;
            if body_length >= MAX_RANGE_BYTES {
                return Err(AuditDeliveryError::RangeTooLarge);
            }
            body.extend_from_slice(&buffer[body_start..amount]);
        }
        remaining -= amount as u64;
    }

    if !body.is_empty() {
        std::str::from_utf8(&body).map_err(|_| AuditDeliveryError::InvalidJsonl)?;
    }
    if require_final_newline && !body.is_empty() {
        return Err(AuditDeliveryError::InvalidJsonl);
    }
    Ok(())
}

fn validate_registered_shape(file: &File, entry: &SegmentEntry) -> Result<(), AuditDeliveryError> {
    validate_file_identity(file, &entry.file_identity)?;
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect payload identity",
            source,
        })?
        .len();
    if length < entry.registered_length
        || (entry.status == SegmentStatus::Sealed && length != entry.registered_length)
    {
        return Err(AuditDeliveryError::CorruptState);
    }
    Ok(())
}

fn validate_registered_digest(file: &File, entry: &SegmentEntry) -> Result<(), AuditDeliveryError> {
    if hex::encode(digest_range(file, 0, entry.registered_length)?) != entry.registered_digest {
        return Err(AuditDeliveryError::CorruptState);
    }
    Ok(())
}

fn file_identity(file: &File) -> Result<FileIdentity, AuditDeliveryError> {
    let metadata = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect payload file identity",
            source,
        })?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_file_identity(file: &File, expected: &FileIdentity) -> Result<(), AuditDeliveryError> {
    if file_identity(file)? != *expected {
        return Err(AuditDeliveryError::CorruptState);
    }
    Ok(())
}

fn segment_file_name(segment_id: &SegmentId) -> String {
    format!("{}.jsonl", segment_id.as_str())
}

fn validate_acknowledged_boundary(
    file: &File,
    cursor: &SegmentCursor,
) -> Result<(), AuditDeliveryError> {
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect acknowledged payload prefix",
            source,
        })?
        .len();
    if cursor.acknowledged_end > length {
        return Err(AuditDeliveryError::CorruptState);
    }
    if hex::encode(digest_boundary(file, cursor.acknowledged_end)?) != cursor.boundary_digest {
        return Err(AuditDeliveryError::CorruptState);
    }
    Ok(())
}

fn initial_acknowledged_digest() -> [u8; 32] {
    Sha256::digest(ACKNOWLEDGED_DIGEST_DOMAIN).into()
}

fn decode_digest(value: &str) -> Result<[u8; 32], AuditDeliveryError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AuditDeliveryError::CorruptState)
}

fn extend_acknowledged_digest(
    mut digest: [u8; 32],
    mut start: u64,
    bodies: &[Vec<u8>],
) -> Result<([u8; 32], u64), AuditDeliveryError> {
    for body in bodies {
        let body_length =
            u64::try_from(body.len()).map_err(|_| AuditDeliveryError::CorruptState)?;
        let end = start
            .checked_add(body_length)
            .and_then(|end| end.checked_add(1))
            .ok_or(AuditDeliveryError::CorruptState)?;
        let mut hasher = Sha256::new();
        hasher.update(ACKNOWLEDGED_DIGEST_DOMAIN);
        hasher.update(digest);
        hasher.update(start.to_be_bytes());
        hasher.update(end.to_be_bytes());
        hasher.update(body_length.to_be_bytes());
        hasher.update(body);
        digest = hasher.finalize().into();
        start = end;
    }
    Ok((digest, start))
}

fn validate_acknowledged_digest(
    file: &File,
    cursor: &SegmentCursor,
) -> Result<(), AuditDeliveryError> {
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect acknowledged payload commitment",
            source,
        })?
        .len();
    if cursor.acknowledged_end > length {
        return Err(AuditDeliveryError::CorruptState);
    }

    let mut file = file
        .try_clone()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "clone acknowledged payload commitment handle",
            source,
        })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "seek acknowledged payload commitment",
            source,
        })?;

    let mut digest = initial_acknowledged_digest();
    let mut remaining = cursor.acknowledged_end;
    let mut offset = 0_u64;
    let mut record_start = 0_u64;
    let mut body = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AuditDeliveryError::CorruptState)?;
        file.read_exact(&mut buffer[..amount]).map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                AuditDeliveryError::CorruptState
            } else {
                AuditDeliveryError::Filesystem {
                    operation: "read acknowledged payload commitment",
                    source,
                }
            }
        })?;
        for byte in &buffer[..amount] {
            offset = offset
                .checked_add(1)
                .ok_or(AuditDeliveryError::CorruptState)?;
            if *byte == b'\n' {
                std::str::from_utf8(&body).map_err(|_| AuditDeliveryError::CorruptState)?;
                let (next_digest, end) =
                    extend_acknowledged_digest(digest, record_start, std::slice::from_ref(&body))?;
                if end != offset {
                    return Err(AuditDeliveryError::CorruptState);
                }
                digest = next_digest;
                record_start = offset;
                body.clear();
            } else {
                if body.len() + 1 >= MAX_RANGE_BYTES {
                    return Err(AuditDeliveryError::CorruptState);
                }
                body.push(*byte);
            }
        }
        remaining -= amount as u64;
    }

    if !body.is_empty()
        || record_start != cursor.acknowledged_end
        || digest != decode_digest(&cursor.acknowledged_digest)?
    {
        return Err(AuditDeliveryError::CorruptState);
    }
    Ok(())
}

fn digest_boundary(file: &File, end: u64) -> Result<[u8; 32], AuditDeliveryError> {
    let start = end.saturating_sub(BOUNDARY_DIGEST_BYTES);
    digest_range(file, start, end - start)
}

fn digest_range(file: &File, start: u64, length: u64) -> Result<[u8; 32], AuditDeliveryError> {
    let mut file = file
        .try_clone()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "clone payload digest handle",
            source,
        })?;
    file.seek(SeekFrom::Start(start))
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "seek payload digest range",
            source,
        })?;
    let mut remaining = length;
    let mut buffer = [0u8; 16 * 1024];
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AuditDeliveryError::CorruptState)?;
        file.read_exact(&mut buffer[..amount]).map_err(|source| {
            AuditDeliveryError::Filesystem {
                operation: "read payload digest range",
                source,
            }
        })?;
        hasher.update(&buffer[..amount]);
        remaining -= amount as u64;
    }
    Ok(hasher.finalize().into())
}

fn read_complete_range(
    file: &mut File,
    start: u64,
    exact_end: Option<u64>,
) -> Result<(Vec<Vec<u8>>, u64), AuditDeliveryError> {
    let length = file
        .metadata()
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "inspect payload range",
            source,
        })?
        .len();
    if start > length {
        return Err(AuditDeliveryError::CorruptState);
    }
    let limit_end =
        exact_end.unwrap_or_else(|| length.min(start.saturating_add(MAX_RANGE_BYTES as u64)));
    if limit_end > length {
        return Err(if exact_end.is_some() {
            AuditDeliveryError::CorruptState
        } else {
            AuditDeliveryError::RangeTooLarge
        });
    }
    if start > limit_end || limit_end - start > MAX_RANGE_BYTES as u64 {
        return Err(AuditDeliveryError::RangeTooLarge);
    }
    file.seek(SeekFrom::Start(start))
        .map_err(|source| AuditDeliveryError::Filesystem {
            operation: "seek payload range",
            source,
        })?;
    let mut bodies = Vec::new();
    let mut body = Vec::new();
    let mut remaining = limit_end - start;
    let mut consumed = 0_u64;
    let mut complete_end = start;
    let mut buffer = [0_u8; 16 * 1024];
    while remaining > 0 {
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| AuditDeliveryError::RangeTooLarge)?;
        file.read_exact(&mut buffer[..amount]).map_err(|source| {
            if source.kind() == std::io::ErrorKind::UnexpectedEof {
                AuditDeliveryError::CorruptState
            } else {
                AuditDeliveryError::Filesystem {
                    operation: "read payload range",
                    source,
                }
            }
        })?;
        for byte in &buffer[..amount] {
            consumed = consumed
                .checked_add(1)
                .ok_or(AuditDeliveryError::RangeTooLarge)?;
            if *byte == b'\n' {
                std::str::from_utf8(&body).map_err(|_| AuditDeliveryError::InvalidJsonl)?;
                bodies.push(std::mem::take(&mut body));
                complete_end = start + consumed;
                if bodies.len() == MAX_RECORDS_PER_RANGE {
                    if exact_end.is_some() && complete_end != limit_end {
                        return Err(AuditDeliveryError::CorruptState);
                    }
                    return Ok((bodies, complete_end));
                }
            } else {
                if body.len() + 1 >= MAX_RANGE_BYTES {
                    return Err(AuditDeliveryError::RangeTooLarge);
                }
                body.push(*byte);
            }
        }
        remaining -= amount as u64;
    }

    if let Some(expected_end) = exact_end {
        if complete_end != expected_end || !body.is_empty() || bodies.is_empty() {
            return Err(AuditDeliveryError::CorruptState);
        }
    } else if bodies.is_empty() && length.saturating_sub(start) >= MAX_RANGE_BYTES as u64 {
        return Err(AuditDeliveryError::RangeTooLarge);
    }
    Ok((bodies, complete_end))
}

fn ordered_body_digest(bodies: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for body in bodies {
        hasher.update((body.len() as u64).to_be_bytes());
        hasher.update(body);
    }
    hasher.finalize().into()
}
