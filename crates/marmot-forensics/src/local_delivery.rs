//! Small, opt-in local audit delivery boundary. No network or runtime activation.
//! The caller owns the account root lease and supplies a receiver with an explicit
//! complete-acceptance result. One attempt contains original, complete JSONL lines.

use crate::audit::{AUDIT_LOG_SCHEMA_VERSION, AuditEvent};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_BATCH_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 96;
// The recorder session id follows the schema, sequence, and wall clock fields.
// Include the full id even when two fresh heads share the same millisecond.
const FINGERPRINT_BYTES: usize = 192;
const MAX_STATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryBatch {
    pub destination: String,
    pub generation: u64,
    pub segment: String,
    pub start: u64,
    pub end: u64,
    pub bodies: Vec<Vec<u8>>,
}

pub enum ReceiverResult {
    Complete,
    Retryable,
    Permanent,
    Partial,
}

pub trait AuditReceiver {
    fn send(&mut self, batch: &DeliveryBatch) -> ReceiverResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStep {
    Idle,
    WaitingForWriter,
    Accepted,
    Retryable,
    Blocked,
    Gap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapReason {
    TornTail,
    InvalidRecord,
    OversizedLine,
    ChangedPreparedRange,
    MissingSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryGap {
    pub generation: u64,
    pub segment: String,
    pub start: u64,
    pub end: Option<u64>,
    pub reason: GapReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prepared {
    start: u64,
    end: u64,
    digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Journal {
    generation: u64,
    segment: String,
    device: u64,
    inode: u64,
    fingerprint: String,
    fingerprint_len: u8,
    observed_len: u64,
    acknowledged: u64,
    prepared: Option<Prepared>,
    blocked: Option<String>,
    missing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    version: u8,
    destination: String,
    next_generation: u64,
    journals: Vec<Journal>,
    gaps: Vec<DeliveryGap>,
}

/// A single-account, single-destination delivery cursor over one recorder path.
/// Calls must be serialized under the account root lease. The source is never
/// deleted by this type; retention and explicit gap repair belong to the host.
pub struct LocalAuditDelivery {
    active: PathBuf,
    state_path: PathBuf,
    state: State,
    fenced: bool,
}

impl LocalAuditDelivery {
    pub fn open(
        active: impl AsRef<Path>,
        state_dir: impl AsRef<Path>,
        destination: &str,
    ) -> io::Result<Self> {
        if destination.is_empty() || destination.len() > 256 {
            return Err(invalid("invalid destination identity"));
        }
        let active = active.as_ref().to_path_buf();
        let name = active
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("invalid recorder path"))?;
        if !name.starts_with("audit-") || !name.ends_with(".jsonl") {
            return Err(invalid("unexpected recorder file name"));
        }
        fs_private::prepare_directory_path(
            state_dir.as_ref(),
            0o700,
            fs_private::ExistingDirectoryMode::Enforce,
        )?;
        let state_path = state_dir.as_ref().join("local-delivery.json");
        // Rename is the state commit point. A leftover staging file came from
        // an interrupted pre-commit write and can be discarded on restart.
        match fs::remove_file(state_path.with_extension("json.tmp")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let state = if state_path.exists() {
            let bytes = read_private_file(&state_path)?;
            let state: State =
                serde_json::from_slice(&bytes).map_err(|_| invalid("corrupt delivery cursor"))?;
            if state.version != 1 || state.destination != destination || state.next_generation == 0
            {
                return Err(invalid("incompatible delivery cursor"));
            }
            validate_state(&state, name)?;
            state
        } else {
            State {
                version: 1,
                destination: destination.into(),
                next_generation: 1,
                journals: Vec::new(),
                gaps: Vec::new(),
            }
        };
        let mut delivery = Self {
            active,
            state_path,
            state,
            fenced: false,
        };
        delivery.discover()?;
        Ok(delivery)
    }

    pub fn gaps(&self) -> &[DeliveryGap] {
        &self.state.gaps
    }

    pub fn blocked(&self) -> Vec<(u64, &str)> {
        self.state
            .journals
            .iter()
            .filter_map(|j| j.blocked.as_deref().map(|reason| (j.generation, reason)))
            .collect()
    }

    pub fn run_once(&mut self, receiver: &mut impl AuditReceiver) -> io::Result<DeliveryStep> {
        self.run_once_with_after_discover(receiver, || {})
    }

    fn run_once_with_after_discover(
        &mut self,
        receiver: &mut impl AuditReceiver,
        after_discover: impl FnOnce(),
    ) -> io::Result<DeliveryStep> {
        if self.fenced {
            return Err(invalid("uncertain local state publication"));
        }
        let old_gap_count = self.state.gaps.len();
        self.discover()?;
        after_discover();
        if self.state.gaps.len() > old_gap_count {
            return Ok(DeliveryStep::Gap);
        }
        let mut source_moved = false;
        for index in 0..self.state.journals.len() {
            if self.state.journals[index].missing || self.state.journals[index].blocked.is_some() {
                continue;
            }
            let (mut file, len) = match self.open_journal(index) {
                Ok(source) => source,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    source_moved = true;
                    continue;
                }
                Err(error) => return Err(error),
            };
            self.state.journals[index].observed_len =
                self.state.journals[index].observed_len.max(len);
            if let Some(prepared) = self.state.journals[index].prepared.clone() {
                if len < prepared.end {
                    self.state.journals[index].observed_len =
                        self.state.journals[index].observed_len.max(prepared.end);
                    file.sync_all()?;
                    self.record_gap(
                        index,
                        prepared.start,
                        prepared.end,
                        GapReason::ChangedPreparedRange,
                    )?;
                    self.state.journals[index].blocked =
                        Some("source truncated after prepared attempt".into());
                    self.publish()?;
                    return Ok(DeliveryStep::Gap);
                }
                let bytes = read_range(&mut file, prepared.start, prepared.end)?;
                if digest(&bytes) != prepared.digest {
                    file.sync_all()?;
                    self.record_gap(
                        index,
                        prepared.start,
                        prepared.end,
                        GapReason::ChangedPreparedRange,
                    )?;
                    return Ok(DeliveryStep::Gap);
                }
                let bodies = checked_bodies(&bytes)?;
                return self.send(index, prepared, bodies, receiver);
            }
            let start = self.state.journals[index].acknowledged;
            if start >= len {
                continue;
            }
            file.seek(SeekFrom::Start(start))?;
            let mut position = start;
            let mut bodies = Vec::new();
            let mut bytes = Vec::new();
            while position < len && bodies.len() < MAX_RECORDS {
                let line_start = position;
                let (line, end, complete, oversized) = read_line(&mut file, position, len)?;
                position = end;
                if !complete {
                    if !bodies.is_empty() {
                        break;
                    }
                    if self.is_active(index) {
                        return Ok(DeliveryStep::WaitingForWriter);
                    }
                    file.sync_all()?;
                    self.record_gap(index, line_start, end, GapReason::TornTail)?;
                    return Ok(DeliveryStep::Gap);
                }
                if oversized {
                    if !bodies.is_empty() {
                        break;
                    }
                    file.sync_all()?;
                    self.record_gap(index, line_start, end, GapReason::OversizedLine)?;
                    return Ok(DeliveryStep::Gap);
                }
                if !valid_event(&line) {
                    if !bodies.is_empty() {
                        break;
                    }
                    file.sync_all()?;
                    self.record_gap(index, line_start, end, GapReason::InvalidRecord)?;
                    return Ok(DeliveryStep::Gap);
                }
                if bytes.len() + line.len() > MAX_BATCH_BYTES {
                    break;
                }
                bytes.extend_from_slice(&line);
                bodies.push(line);
            }
            if bodies.is_empty() {
                continue;
            }
            let end = start + bytes.len() as u64;
            // The recorder flushes but does not fsync. A local prepared claim
            // must establish that boundary before publication and send.
            file.sync_all()?;
            let prepared = Prepared {
                start,
                end,
                digest: digest(&bytes),
            };
            self.state.journals[index].prepared = Some(prepared.clone());
            self.publish()?;
            return self.send(index, prepared, bodies, receiver);
        }
        if source_moved {
            Ok(DeliveryStep::Retryable)
        } else if self.state.journals.iter().any(|j| j.blocked.is_some()) {
            Ok(DeliveryStep::Blocked)
        } else {
            Ok(DeliveryStep::Idle)
        }
    }

    fn send(
        &mut self,
        index: usize,
        prepared: Prepared,
        bodies: Vec<Vec<u8>>,
        receiver: &mut impl AuditReceiver,
    ) -> io::Result<DeliveryStep> {
        let journal = &self.state.journals[index];
        let batch = DeliveryBatch {
            destination: self.state.destination.clone(),
            generation: journal.generation,
            segment: journal.segment.clone(),
            start: prepared.start,
            end: prepared.end,
            bodies,
        };
        match receiver.send(&batch) {
            ReceiverResult::Complete => {
                self.state.journals[index].acknowledged = prepared.end;
                self.state.journals[index].prepared = None;
                self.publish()?;
                Ok(DeliveryStep::Accepted)
            }
            ReceiverResult::Retryable => Ok(DeliveryStep::Retryable),
            ReceiverResult::Permanent => {
                self.state.journals[index].blocked = Some("permanent receiver rejection".into());
                self.publish()?;
                Ok(DeliveryStep::Blocked)
            }
            ReceiverResult::Partial => {
                self.state.journals[index].blocked = Some("partial receiver acceptance".into());
                self.publish()?;
                Ok(DeliveryStep::Blocked)
            }
        }
    }

    fn record_gap(
        &mut self,
        index: usize,
        start: u64,
        end: u64,
        reason: GapReason,
    ) -> io::Result<()> {
        let j = &self.state.journals[index];
        append_gap(
            &mut self.state.gaps,
            DeliveryGap {
                generation: j.generation,
                segment: j.segment.clone(),
                start,
                end: Some(end),
                reason,
            },
        );
        self.state.journals[index].acknowledged = end;
        self.state.journals[index].prepared = None;
        self.publish()
    }

    fn is_active(&self, index: usize) -> bool {
        if self.active.file_name().and_then(|n| n.to_str())
            == Some(self.state.journals[index].segment.as_str())
        {
            return true;
        }
        // A failed roll restore can leave the recorder appending to the last
        // segment while the active path is absent. Wait for an explicit new
        // active file before treating that segment's tail as sealed.
        !self.active.exists()
            && self
                .state
                .journals
                .iter()
                .filter(|j| !j.missing)
                .max_by_key(|j| j.generation)
                .is_some_and(|j| j.generation == self.state.journals[index].generation)
    }

    fn open_journal(&self, index: usize) -> io::Result<(File, u64)> {
        let j = &self.state.journals[index];
        let path = self
            .active
            .parent()
            .unwrap_or(Path::new("."))
            .join(&j.segment);
        let mut file = match open_source(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            result => result?,
        };
        let meta = file.metadata()?;
        let (device, inode) = file_identity(&meta);
        let len = meta.len();
        if device != j.device || inode != j.inode {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        if len < j.fingerprint_len as u64 {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let fingerprint = match fingerprint(&mut file, j.fingerprint_len as usize) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            }
            result => result?,
        };
        if len < j.acknowledged || (!j.fingerprint.is_empty() && fingerprint != j.fingerprint) {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        Ok((file, len))
    }

    fn discover(&mut self) -> io::Result<()> {
        self.discover_with_after_active_open(|| {})
    }

    fn discover_with_after_active_open(
        &mut self,
        after_active_open: impl FnOnce(),
    ) -> io::Result<()> {
        // Hold the active inode before scanning segments. If the recorder rolls
        // between these operations, the held inode or its new segment name is
        // still observed, so a normal rename cannot create a missing gap.
        let active_file = match open_source(&self.active) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        after_active_open();
        let paths = source_paths(&self.active)?;
        let mut sources = Vec::new();
        let mut source_identities = std::collections::HashSet::new();
        for path in paths.into_iter().filter(|path| path != &self.active) {
            let file = open_source(&path)?;
            if source_identities.insert(file_identity(&file.metadata()?)) {
                sources.push((path, file));
            }
        }
        if let Some(file) = active_file
            && source_identities.insert(file_identity(&file.metadata()?))
        {
            sources.push((self.active.clone(), file));
        }
        let mut seen = vec![false; self.state.journals.len()];
        let mut changed = false;
        for (path, mut file) in sources {
            let meta = file.metadata()?;
            let (device, inode) = file_identity(&meta);
            let len = meta.len();
            let fp_len = (len as usize).min(FINGERPRINT_BYTES) as u8;
            let fp = fingerprint(&mut file, fp_len as usize)?;
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("invalid source name"))?
                .to_owned();
            if len == 0
                && !self
                    .state
                    .journals
                    .iter()
                    .any(|j| j.device == device && j.inode == inode && !j.missing)
            {
                // Empty new files carry no stable prefix or deliverable line.
                // Assign their generation after the first completed write.
                continue;
            }
            if let Some(index) = self
                .state
                .journals
                .iter()
                .position(|j| j.device == device && j.inode == inode && !j.missing)
            {
                let journal = &mut self.state.journals[index];
                let was_blocked = journal.blocked.is_some();
                let existing_fp = fingerprint(
                    &mut file,
                    (journal.fingerprint_len as u64).min(len) as usize,
                )?;
                let changed_head =
                    !journal.fingerprint.is_empty() && journal.fingerprint != existing_fp;
                let lost_unprepared_tail = journal.prepared.is_none()
                    && journal.blocked.is_none()
                    && len < journal.observed_len;
                if changed_head || lost_unprepared_tail {
                    // The recorder never rewrites or truncates a file in place.
                    // A reused inode or a shortened observed file is a new
                    // generation; keep the old unaccepted extent visible.
                    let was_active = self.active.file_name().and_then(|n| n.to_str())
                        == Some(journal.segment.as_str());
                    retire_missing(&mut self.state, index, was_active);
                    seen[index] = true;
                    register_journal(&mut self.state, name, device, inode, fp, fp_len, len)?;
                    seen.push(true);
                    changed = true;
                    continue;
                } else {
                    let observed_len = journal
                        .observed_len
                        .max(len)
                        .max(journal.acknowledged)
                        .max(journal.prepared.as_ref().map_or(0, |p| p.end));
                    changed |= journal.fingerprint != fp
                        || journal.segment != name
                        || journal.observed_len != observed_len;
                    journal.fingerprint = fp;
                    journal.fingerprint_len = fp_len;
                    journal.segment = name;
                    if len < journal.acknowledged {
                        journal.blocked = Some("source truncated below cursor".into());
                    }
                    journal.observed_len = observed_len;
                }
                seen[index] = true;
                changed |= !was_blocked && journal.blocked.is_some();
            } else {
                register_journal(&mut self.state, name, device, inode, fp, fp_len, len)?;
                seen.push(true);
                changed = true;
            }
        }
        for (index, present) in seen.into_iter().enumerate() {
            if !present && !self.state.journals[index].missing {
                let was_active = self.active.file_name().and_then(|n| n.to_str())
                    == Some(self.state.journals[index].segment.as_str());
                retire_missing(&mut self.state, index, was_active);
                changed = true;
            }
        }
        if changed {
            self.publish()?;
        }
        Ok(())
    }

    fn publish(&mut self) -> io::Result<()> {
        if self.fenced {
            return Err(invalid("uncertain local state publication"));
        }
        let result = self.publish_inner();
        if result.is_err() {
            self.fenced = true;
        }
        result
    }

    fn publish_inner(&self) -> io::Result<()> {
        let temp = self.state_path.with_extension("json.tmp");
        let bytes = serde_json::to_vec(&self.state).map_err(io::Error::other)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            return Err(invalid("delivery cursor exceeds size limit"));
        }
        let mut file = fs_private::create_new_private(&temp)?;
        if let Err(error) = (|| {
            file.write_all(&bytes)?;
            file.sync_all()
        })() {
            let _ = fs::remove_file(&temp);
            return Err(error);
        }
        drop(file);
        fs::rename(&temp, &self.state_path)?;
        File::open(self.state_path.parent().unwrap_or(Path::new(".")))?.sync_all()
    }
}

fn append_gap(gaps: &mut Vec<DeliveryGap>, gap: DeliveryGap) {
    if let Some(previous) = gaps.last_mut()
        && previous.generation == gap.generation
        && previous.segment == gap.segment
        && previous.reason == gap.reason
        && previous.end == Some(gap.start)
    {
        previous.end = gap.end;
    } else {
        gaps.push(gap);
    }
}

fn retire_missing(state: &mut State, index: usize, was_active: bool) {
    let journal = &mut state.journals[index];
    if journal.prepared.is_some() || journal.acknowledged < journal.observed_len || was_active {
        append_gap(
            &mut state.gaps,
            DeliveryGap {
                generation: journal.generation,
                segment: journal.segment.clone(),
                start: journal
                    .prepared
                    .as_ref()
                    .map_or(journal.acknowledged, |p| p.start),
                end: None,
                reason: GapReason::MissingSource,
            },
        );
    }
    journal.prepared = None;
    journal.missing = true;
}

fn register_journal(
    state: &mut State,
    segment: String,
    device: u64,
    inode: u64,
    fingerprint: String,
    fingerprint_len: u8,
    observed_len: u64,
) -> io::Result<()> {
    let generation = state.next_generation;
    state.next_generation = generation
        .checked_add(1)
        .ok_or_else(|| invalid("generation exhausted"))?;
    state.journals.push(Journal {
        generation,
        segment,
        device,
        inode,
        fingerprint,
        fingerprint_len,
        observed_len,
        acknowledged: 0,
        prepared: None,
        blocked: None,
        missing: false,
    });
    Ok(())
}

fn validate_state(state: &State, active_name: &str) -> io::Result<()> {
    let mut generations = std::collections::HashSet::new();
    let mut identities = std::collections::HashSet::new();
    let stem = active_name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid recorder name"))?;
    for j in &state.journals {
        let expected_prefix = format!("{stem}-seg");
        let segment_index = j
            .segment
            .strip_prefix(&expected_prefix)
            .and_then(|s| s.strip_suffix(".jsonl"));
        let valid_name = j.segment == active_name
            || segment_index.is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()));
        if !generations.insert(j.generation)
            || (!j.missing && !identities.insert((j.device, j.inode)))
            || j.generation >= state.next_generation
            || !valid_name
            || j.fingerprint_len as usize > FINGERPRINT_BYTES
            || (j.fingerprint_len == 0) != j.fingerprint.is_empty()
            || (!j.fingerprint.is_empty() && !valid_digest(&j.fingerprint))
            || j.acknowledged > j.observed_len
            || j.prepared.as_ref().is_some_and(|p| {
                p.start != j.acknowledged
                    || p.end <= p.start
                    || p.end > j.observed_len
                    || p.end - p.start > MAX_BATCH_BYTES as u64
                    || !valid_digest(&p.digest)
            })
        {
            return Err(invalid("corrupt delivery cursor"));
        }
    }
    for gap in &state.gaps {
        if !generations.contains(&gap.generation) || gap.end.is_some_and(|end| end <= gap.start) {
            return Err(invalid("corrupt delivery gaps"));
        }
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn source_paths(active: &Path) -> io::Result<Vec<PathBuf>> {
    let parent = active.parent().unwrap_or(Path::new("."));
    let name = active
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid source path"))?;
    let stem = name
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid source path"))?;
    let prefix = format!("{stem}-seg");
    let mut segments = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if filename.starts_with(&prefix) && filename.ends_with(".jsonl") {
            let middle = &filename[prefix.len()..filename.len() - 6];
            if middle.len() == 6 && middle.bytes().all(|b| b.is_ascii_digit()) {
                segments.push(entry.path());
            }
        }
    }
    segments.sort();
    if active.exists() {
        segments.push(active.to_owned());
    }
    Ok(segments)
}

fn open_source(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("source is not a regular file"));
    }
    Ok(file)
}

fn read_private_file(path: &Path) -> io::Result<Vec<u8>> {
    let file = open_source(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(invalid("delivery cursor exceeds size limit"));
    }
    Ok(bytes)
}

fn file_identity(meta: &fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

fn fingerprint(file: &mut File, len: usize) -> io::Result<String> {
    if len == 0 {
        return Ok(String::new());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0; len];
    file.read_exact(&mut bytes)?;
    Ok(digest(&bytes))
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_range(file: &mut File, start: u64, end: u64) -> io::Result<Vec<u8>> {
    if end <= start || end - start > MAX_BATCH_BYTES as u64 {
        return Err(invalid("invalid prepared range"));
    }
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (end - start) as usize];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_line(file: &mut File, start: u64, limit: u64) -> io::Result<(Vec<u8>, u64, bool, bool)> {
    let mut bytes = Vec::new();
    let mut position = start;
    let mut oversized = false;
    let mut buffer = [0u8; 4096];
    while position < limit {
        let remaining = ((limit - position) as usize).min(buffer.len());
        let count = file.read(&mut buffer[..remaining])?;
        if count == 0 {
            break;
        }
        if let Some(index) = buffer[..count].iter().position(|b| *b == b'\n') {
            let used = index + 1;
            if !oversized && bytes.len() + used <= MAX_LINE_BYTES {
                bytes.extend_from_slice(&buffer[..used]);
            } else {
                oversized = true;
            }
            position += used as u64;
            file.seek(SeekFrom::Start(position))?;
            return Ok((bytes, position, true, oversized));
        }
        if !oversized && bytes.len() + count <= MAX_LINE_BYTES {
            bytes.extend_from_slice(&buffer[..count]);
        } else {
            oversized = true;
        }
        position += count as u64;
    }
    Ok((bytes, position, false, oversized))
}

fn valid_event(line: &[u8]) -> bool {
    std::str::from_utf8(line)
        .ok()
        .and_then(|text| serde_json::from_str::<AuditEvent>(text).ok())
        .is_some_and(|event| event.schema_version == AUDIT_LOG_SCHEMA_VERSION)
}

fn checked_bodies(bytes: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut bodies = Vec::new();
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if !line.ends_with(b"\n") || !valid_event(line) {
            return Err(invalid("prepared range contains invalid record"));
        }
        bodies.push(line.to_vec());
    }
    if bodies.is_empty() || bodies.len() > MAX_RECORDS {
        return Err(invalid("invalid prepared record count"));
    }
    Ok(bodies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{
        AuditEventKind, AuditRecord, ForensicRecorder, JsonlRecorder, default_jsonl_path,
    };
    use tempfile::TempDir;

    #[derive(Default)]
    struct FakeReceiver {
        next: Option<ReceiverResult>,
        batches: Vec<DeliveryBatch>,
    }

    impl AuditReceiver for FakeReceiver {
        fn send(&mut self, batch: &DeliveryBatch) -> ReceiverResult {
            self.batches.push(batch.clone());
            self.next.take().unwrap_or(ReceiverResult::Complete)
        }
    }

    fn record(recorder: &JsonlRecorder, label: &str) {
        recorder.record(AuditRecord::new(
            None,
            AuditEventKind::SendEntry {
                intent_kind: label.into(),
            },
        ));
    }

    fn setup() -> (TempDir, PathBuf, PathBuf, JsonlRecorder) {
        let dir = TempDir::new().unwrap();
        let active = default_jsonl_path(dir.path(), "engine-abc");
        let state_dir = dir.path().join("delivery");
        let recorder = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
        (dir, active, state_dir, recorder)
    }

    fn drain(worker: &mut LocalAuditDelivery, sink: &mut FakeReceiver) {
        for _ in 0..2000 {
            match worker.run_once(sink).unwrap() {
                DeliveryStep::Idle => return,
                DeliveryStep::Accepted | DeliveryStep::Gap => {}
                other => panic!("unexpected delivery step: {other:?}"),
            }
        }
        panic!("delivery did not drain");
    }

    #[test]
    fn real_recorder_append_retry_restart_and_ack_preserve_original_lines() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let original = fs::read(&active).unwrap();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        let first = sink.batches[0].clone();
        assert_eq!(first.bodies.concat(), original);
        drop(worker);

        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[1].bodies, first.bodies);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Idle);
        record(&recorder, "two");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[2].start, first.end);
        assert_eq!(
            sink.batches[2].bodies.concat(),
            fs::read(&active).unwrap()[first.end as usize..]
        );
        assert!(LocalAuditDelivery::open(&active, &state_dir, "receiver-B").is_err());
    }

    #[test]
    fn same_inode_changed_prepared_range_is_a_visible_gap_then_later_rows_continue() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        let prepared_end = sink.batches[0].end;
        // Rewrite a byte beyond the 192-byte head fingerprint, preserving inode
        // and length. The range digest must catch the change before any send.
        let mut file = OpenOptions::new().write(true).open(&active).unwrap();
        file.seek(SeekFrom::Start(250)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        drop(worker);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(sink.batches.len(), 1);
        assert_eq!(worker.gaps()[0].reason, GapReason::ChangedPreparedRange);
        assert_eq!(worker.gaps()[0].end, Some(prepared_end));
        record(&recorder, "later");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[1].start, prepared_end);
    }

    #[test]
    fn changed_head_retires_prepared_generation_with_visible_missing_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        let mut file = OpenOptions::new().write(true).open(&active).unwrap();
        file.seek(SeekFrom::Start(1)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(sink.batches.len(), 1);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].start, 0);
        assert_eq!(worker.gaps()[0].end, None);
        assert!(worker.state.journals[0].missing);
        assert!(worker.state.journals[0].prepared.is_none());
        assert_eq!(worker.state.journals.len(), 2);
        assert_ne!(
            worker.state.journals[0].generation,
            worker.state.journals[1].generation
        );
        drop(worker);
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert!(worker.blocked().is_empty());
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert!(worker.state.journals[0].missing);
    }

    #[test]
    fn reused_inode_number_after_clear_retires_old_unaccepted_bytes() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "old_unaccepted");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let old_generation = worker.state.journals[0].generation;
        // Inode reuse is filesystem-dependent. Force the observed identity to
        // match the replacement after a real recorder clear to model reuse.
        recorder.rotate().unwrap();
        record(&recorder, "new_generation");
        let identity = file_identity(&fs::metadata(&active).unwrap());
        worker.state.journals[0].device = identity.0;
        worker.state.journals[0].inode = identity.1;
        let mut sink = FakeReceiver::default();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].start, 0);
        assert_eq!(worker.gaps()[0].end, None);
        assert!(worker.state.journals[0].missing);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_ne!(sink.batches[0].generation, old_generation);
        assert_eq!(sink.batches[0].bodies.concat(), fs::read(&active).unwrap());
    }

    #[test]
    fn torn_active_tail_waits_and_bad_line_skips_only_its_extent() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let prior_end = fs::metadata(&active).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&active).unwrap();
        file.write_all(b"{broken").unwrap();
        assert_eq!(
            worker.run_once(&mut sink).unwrap(),
            DeliveryStep::WaitingForWriter
        );
        assert!(worker.gaps().is_empty());
        file.write_all(b"}\n").unwrap();
        file.sync_all().unwrap();
        record(&recorder, "after_bad_line");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].start, prior_end);
        assert_eq!(worker.gaps()[0].end, Some(prior_end + 9));
        assert_eq!(worker.gaps()[0].reason, GapReason::InvalidRecord);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches.last().unwrap().start, prior_end + 9);
    }

    #[test]
    fn adjacent_invalid_lines_coalesce_into_one_gap() {
        let (_dir, active, state_dir, _recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let start = fs::metadata(&active).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&active).unwrap();
        file.write_all(b"bad-one\nbad-two\n").unwrap();
        file.sync_all().unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps().len(), 1);
        assert_eq!(worker.gaps()[0].start, start);
        assert_eq!(worker.gaps()[0].end, Some(start + 16));
        assert_eq!(worker.gaps()[0].reason, GapReason::InvalidRecord);
    }

    #[test]
    fn ordinary_rows_use_more_than_eight_records_per_bounded_batch() {
        let (_dir, active, state_dir, recorder) = setup();
        for index in 0..120 {
            record(&recorder, &format!("row-{index}"));
        }
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        let first = &sink.batches[0];
        assert!(first.bodies.len() > 8);
        assert!(first.bodies.len() <= MAX_RECORDS);
        assert!(first.bodies.concat().len() <= MAX_BATCH_BYTES);
    }

    #[test]
    fn real_size_rotation_keeps_old_inode_and_drains_both_files() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        for index in 0..7000 {
            record(&recorder, &format!("row-{index:05}"));
            if fs::read_dir(active.parent().unwrap())
                .unwrap()
                .any(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains("-seg")
                })
            {
                break;
            }
        }
        let segment = source_paths(&active)
            .unwrap()
            .into_iter()
            .find(|p| p != &active)
            .expect("real recorder rotated");
        record(&recorder, "after_roll");
        drain(&mut worker, &mut sink);
        let sent: Vec<u8> = sink
            .batches
            .iter()
            .flat_map(|b| b.bodies.concat())
            .collect();
        let mut expected = fs::read(&segment).unwrap();
        expected.extend_from_slice(&fs::read(&active).unwrap());
        assert_eq!(sent, expected);
        assert!(worker.gaps().is_empty());
        assert_eq!(worker.state.journals.len(), 2);
        assert_eq!(
            worker.state.journals[0].segment,
            segment.file_name().unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn partial_rejection_blocks_one_journal_and_corrupt_state_fails_closed() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Partial),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Blocked);
        assert_eq!(worker.blocked(), vec![(1, "partial receiver acceptance")]);
        assert_eq!(worker.state.journals[0].acknowledged, 0);
        drop(worker);
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.blocked(), vec![(1, "partial receiver acceptance")]);
        drop(worker);
        fs::write(state_dir.join("local-delivery.json"), b"broken").unwrap();
        assert!(LocalAuditDelivery::open(&active, &state_dir, "receiver-A").is_err());
    }

    #[test]
    fn blocked_journal_does_not_stop_a_new_recorder_generation() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "first");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Permanent),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Blocked);
        recorder.rotate().unwrap();
        record(&recorder, "second");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches.len(), 2);
        assert_ne!(sink.batches[0].generation, sink.batches[1].generation);
        assert_eq!(worker.blocked()[0].1, "permanent receiver rejection");
    }

    #[test]
    #[cfg(unix)]
    fn cursor_and_staging_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, active, state_dir, _recorder) = setup();
        let _worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(
            fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(state_dir.join("local-delivery.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn oversized_line_is_skipped_and_later_record_is_delivered() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let start = fs::metadata(&active).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&active).unwrap();
        file.write_all(&vec![b'x'; MAX_LINE_BYTES + 1]).unwrap();
        file.write_all(b"\n").unwrap();
        record(&recorder, "after_large_line");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::OversizedLine);
        assert_eq!(worker.gaps()[0].start, start);
        assert_eq!(
            worker.gaps()[0].end,
            Some(start + MAX_LINE_BYTES as u64 + 2)
        );
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
    }

    #[test]
    fn destructive_clear_reports_unknown_missing_source_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "unaccepted");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        recorder.rotate().unwrap();
        let mut sink = FakeReceiver::default();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].end, None);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
    }

    #[test]
    fn stale_state_staging_file_is_discarded_on_open() {
        let (_dir, active, state_dir, _recorder) = setup();
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drop(worker);
        fs::write(state_dir.join("local-delivery.json.tmp"), b"uncertain").unwrap();
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert!(worker.gaps().is_empty());
        assert!(!state_dir.join("local-delivery.json.tmp").exists());
    }

    #[test]
    fn rotation_between_active_open_and_segment_scan_preserves_generation() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let old_generation = worker.state.journals[0].generation;
        let acknowledged = worker.state.journals[0].acknowledged;
        worker
            .discover_with_after_active_open(|| {
                for index in 0..7000 {
                    record(&recorder, &format!("roll-{index:05}"));
                    if !source_paths(&active).unwrap().iter().all(|p| p == &active) {
                        break;
                    }
                }
            })
            .unwrap();
        assert!(worker.gaps().is_empty());
        assert_eq!(worker.state.journals[0].generation, old_generation);
        assert_eq!(worker.state.journals[0].acknowledged, acknowledged);
        assert!(!worker.state.journals[0].missing);
        assert!(worker.state.journals[0].segment.contains("-seg"));
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches.last().unwrap().start, acknowledged);
    }

    #[test]
    fn append_between_discover_and_open_persists_valid_observed_length() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        sink.next = Some(ReceiverResult::Retryable);
        assert_eq!(
            worker
                .run_once_with_after_discover(&mut sink, || record(&recorder, "late"))
                .unwrap(),
            DeliveryStep::Retryable
        );
        let prepared_end = worker.state.journals[0].prepared.as_ref().unwrap().end;
        assert_eq!(worker.state.journals[0].observed_len, prepared_end);
        drop(worker);
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(
            worker.state.journals[0].prepared.as_ref().unwrap().end,
            prepared_end
        );
    }

    #[test]
    fn rotation_between_discover_and_open_is_retryable_then_reconciled() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "before_roll");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        let stem = active.file_stem().unwrap().to_str().unwrap();
        let segment = active.with_file_name(format!("{stem}-seg000001.jsonl"));
        assert_eq!(
            worker
                .run_once_with_after_discover(&mut sink, || {
                    drop(recorder);
                    fs::rename(&active, &segment).unwrap();
                    let next = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
                    record(&next, "after_roll");
                })
                .unwrap(),
            DeliveryStep::Retryable
        );
        assert!(sink.batches.is_empty());
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[0].bodies.concat(), fs::read(&segment).unwrap());
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[1].bodies.concat(), fs::read(&active).unwrap());
        assert!(worker.gaps().is_empty());
    }

    #[test]
    fn numbered_segment_change_after_discovery_does_not_stop_active_delivery() {
        for replace in [false, true] {
            let (_dir, active, state_dir, recorder) = setup();
            record(&recorder, "old_segment");
            let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
            let old_generation = worker.state.journals[0].generation;
            drop(recorder);
            let stem = active.file_stem().unwrap().to_str().unwrap();
            let segment = active.with_file_name(format!("{stem}-seg000001.jsonl"));
            fs::rename(&active, &segment).unwrap();
            let next = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
            record(&next, "live_active");
            let mut sink = FakeReceiver::default();
            assert_eq!(
                worker
                    .run_once_with_after_discover(&mut sink, || {
                        if replace {
                            let replacement = segment.with_extension("replacement");
                            fs::copy(&segment, &replacement).unwrap();
                            fs::rename(&replacement, &segment).unwrap();
                        } else {
                            fs::remove_file(&segment).unwrap();
                        }
                    })
                    .unwrap(),
                DeliveryStep::Accepted
            );
            assert_eq!(sink.batches[0].bodies.concat(), fs::read(&active).unwrap());
            assert_ne!(sink.batches[0].generation, old_generation);
            assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
            assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
            assert_eq!(worker.gaps()[0].start, 0);
            assert_eq!(worker.gaps()[0].end, None);
        }
    }

    #[test]
    fn missing_prepared_source_records_unknown_gap_and_unblocks_later_generation() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        recorder.rotate().unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].start, 0);
        assert_eq!(worker.gaps()[0].end, None);
        assert!(worker.state.journals[0].prepared.is_none());
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
    }

    #[test]
    fn destructive_clear_after_unseen_append_reports_unknown_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let acknowledged = worker.state.journals[0].acknowledged;
        record(&recorder, "unseen");
        recorder.rotate().unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].start, acknowledged);
        assert_eq!(worker.gaps()[0].end, None);
    }

    #[test]
    fn shrink_inside_prepared_range_keeps_cursor_readable_until_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        let prepared_end = worker.state.journals[0].prepared.as_ref().unwrap().end;
        let file = OpenOptions::new().write(true).open(&active).unwrap();
        file.set_len(prepared_end - 1).unwrap();
        worker.discover().unwrap();
        drop(worker);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::ChangedPreparedRange);
    }

    #[test]
    fn shrink_of_observed_unprepared_tail_records_gap_before_replay() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "accepted");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let old_generation = worker.state.journals[0].generation;
        let acknowledged = worker.state.journals[0].acknowledged;
        assert!(acknowledged > FINGERPRINT_BYTES as u64);

        record(&recorder, "observed_but_unprepared");
        worker.discover().unwrap();
        assert!(worker.state.journals[0].observed_len > acknowledged);
        assert!(worker.state.journals[0].prepared.is_none());
        OpenOptions::new()
            .write(true)
            .open(&active)
            .unwrap()
            .set_len(acknowledged)
            .unwrap();

        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].generation, old_generation);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].start, acknowledged);
        assert_eq!(worker.gaps()[0].end, None);
        assert!(worker.state.journals[0].missing);
        assert!(worker.state.journals[0].observed_len > acknowledged);
        drop(worker);

        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.gaps()[0].start, acknowledged);
        assert!(worker.state.journals[0].observed_len > acknowledged);
        record(&recorder, "after_shrink");
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_ne!(sink.batches.last().unwrap().generation, old_generation);
    }

    #[test]
    fn oversized_cursor_returns_explicit_size_error() {
        let (_dir, active, state_dir, _recorder) = setup();
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drop(worker);
        fs::write(
            state_dir.join("local-delivery.json"),
            vec![b'x'; MAX_STATE_BYTES as usize + 1],
        )
        .unwrap();
        let error = LocalAuditDelivery::open(&active, &state_dir, "receiver-A")
            .err()
            .unwrap();
        assert!(error.to_string().contains("size limit"));
    }
}
