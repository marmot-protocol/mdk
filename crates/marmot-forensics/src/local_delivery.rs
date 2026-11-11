//! Small, opt-in local audit delivery boundary. No network or runtime activation.
//! Prepare and finish run under the account root lease. The owned batch can be
//! sent after releasing that lease. One attempt contains original, complete JSONL lines.

use crate::audit::{AUDIT_LOG_SCHEMA_VERSION, AuditEvent};
use crate::v5::Record as V5Record;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

mod retention;
pub use retention::expire_closed_source;

const MAX_BATCH_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 96;
// The recorder session id follows the schema, sequence, and wall clock fields.
// Include the full id even when two fresh heads share the same millisecond.
const FINGERPRINT_BYTES: usize = 192;
const MAX_STATE_BYTES: u64 = 1024 * 1024;
// Older gaps are counted, not kept, so loss evidence cannot grow the cursor
// without bound.
const MAX_GAPS: usize = 256;
// Version 2 stores idle sealed sources as compact `SealedEntry` rows.
const STATE_VERSION: u8 = 2;
// Hex characters of the head fingerprint a compact entry keeps: enough to
// catch a replaced file, small enough for thousands of retained segments.
const COMPACT_FINGERPRINT_HEX: usize = 16;
// The block reason version 1 recorded for a permanent receiver rejection.
const LEGACY_REJECTION_BLOCK: &str = "permanent receiver rejection";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryBatch {
    pub token: DeliveryToken,
    pub segment: String,
    pub bodies: Vec<Vec<u8>>,
}

/// Identifies the persisted attempt without holding a source or cursor handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryToken {
    destination: String,
    generation: u64,
    start: u64,
    end: u64,
    digest: String,
}

impl DeliveryToken {
    pub fn destination(&self) -> &str {
        &self.destination
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn end(&self) -> u64 {
        self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Preparation {
    Batch(DeliveryBatch),
    Step(DeliveryStep),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverResult {
    Complete,
    Retryable,
    Permanent,
    Partial,
}

#[cfg(test)]
trait TestAuditReceiver {
    fn send(&mut self, batch: &DeliveryBatch) -> ReceiverResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStep {
    Idle,
    WaitingForWriter,
    Accepted,
    Retryable,
    Stale,
    Blocked,
    Gap,
    /// The receiver rejected a multi-record batch. The next preparation
    /// re-sends a smaller prefix until the rejected record is isolated.
    Split,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapReason {
    TornTail,
    InvalidRecord,
    OversizedLine,
    ChangedPreparedRange,
    MissingSource,
    /// The receiver rejected this exact range as invalid input.
    ReceiverRejected,
    /// Retention deleted the source before this range was delivered.
    ExpiredUndelivered,
    /// The cursor reached its size limit; this sealed segment's undelivered
    /// extent is no longer tracked.
    CursorOverflow,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeliveryGap {
    pub generation: u64,
    pub segment: String,
    pub start: u64,
    pub end: Option<u64>,
    pub reason: GapReason,
}

/// Undelivered local work, as reported by [`LocalAuditDelivery::backlog`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeliveryBacklog {
    /// Unacknowledged bytes across present source files.
    pub undelivered_bytes: u64,
    /// Present source files with unacknowledged bytes.
    pub undelivered_segments: u64,
    /// Recorded delivery gaps.
    pub gaps: u64,
    /// Recorder wall time of the oldest undelivered record, when readable.
    pub oldest_undelivered_wall_time_ms: Option<u64>,
}

/// Local delivery failures a host can act on differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDeliveryFailure {
    /// The persisted cursor state exceeds its size limit.
    StateOverLimit,
    /// The process or system ran out of file descriptors.
    TooManyOpenFiles,
    /// Any other local I/O failure.
    Io,
}

const STATE_SIZE_LIMIT_MESSAGE: &str = "delivery cursor exceeds size limit";

/// Classify an error returned by [`LocalAuditDelivery`].
pub fn classify_local_failure(error: &io::Error) -> LocalDeliveryFailure {
    if error.kind() == io::ErrorKind::InvalidData
        && error
            .get_ref()
            .is_some_and(|inner| inner.to_string() == STATE_SIZE_LIMIT_MESSAGE)
    {
        return LocalDeliveryFailure::StateOverLimit;
    }
    #[cfg(unix)]
    let too_many_open_files = matches!(
        error.raw_os_error(),
        Some(libc::EMFILE) | Some(libc::ENFILE)
    );
    // ERROR_TOO_MANY_OPEN_FILES
    #[cfg(windows)]
    let too_many_open_files = error.raw_os_error() == Some(4);
    #[cfg(not(any(unix, windows)))]
    let too_many_open_files = false;
    if too_many_open_files {
        LocalDeliveryFailure::TooManyOpenFiles
    } else {
        LocalDeliveryFailure::Io
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Prepared {
    start: u64,
    end: u64,
    digest: String,
    /// Record count; 0 in a range prepared before counts were persisted.
    #[serde(default)]
    records: u16,
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
    /// Record limit while isolating a record the receiver rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    split_records: Option<u16>,
    /// End of the last rejected range. The rejected record lies before it,
    /// so the limit ends once acknowledgement passes this offset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    split_until: Option<u64>,
    /// Source change time in nanoseconds when last opened; 0 unknown. See
    /// `change_time_ns`.
    #[serde(default, skip_serializing_if = "is_zero")]
    change_time: u64,
}

/// A sealed source with no work in flight: never read (`delivered` false) or
/// fully acknowledged. Stored as `[generation, segment index, device, inode,
/// length, delivered, change time, fingerprint prefix]` so retained history
/// costs well under a hundred bytes per file.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SealedEntry(u64, u32, u64, u64, u64, bool, u64, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    version: u8,
    destination: String,
    /// Active recorder file name; compact entries derive segment names from it.
    /// Empty only in a version 1 file, which stored every name in full.
    #[serde(default)]
    source: String,
    next_generation: u64,
    journals: Vec<Journal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    sealed: Vec<SealedEntry>,
    gaps: Vec<DeliveryGap>,
    #[serde(default, skip_serializing_if = "is_zero")]
    dropped_gaps: u64,
    /// After a cursor overflow, untracked sealed segments at or below this
    /// index are not adopted again. Cleared once none of them remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    overflow_floor: Option<u32>,
    /// Newest change time (ns) among the shed segments. A file at or below
    /// the floor index but changed later is a new incarnation.
    #[serde(default, skip_serializing_if = "is_zero")]
    overflow_floor_change_time: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// A single-account, single-destination delivery cursor over one recorder path.
/// Preparation and completion must be serialized under the account root lease.
/// No lease or source handle is retained in a returned batch. The source is never
/// deleted by this type; retention and explicit gap repair belong to the host.
pub struct LocalAuditDelivery {
    active: PathBuf,
    state_path: PathBuf,
    state: State,
    fenced: bool,
    state_limit: u64,
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
        #[cfg(unix)]
        fs_private::prepare_directory_path(
            state_dir.as_ref(),
            0o700,
            fs_private::ExistingDirectoryMode::Enforce,
        )?;
        #[cfg(not(unix))]
        fs_private::create_dir_all_private(state_dir.as_ref())?;
        let state_path = state_dir.as_ref().join("local-delivery.json");
        // Rename is the state commit point. A leftover staging file came from
        // an interrupted pre-commit write and can be discarded on restart.
        match fs::remove_file(state_path.with_extension("json.tmp")) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let state = if state_path.exists() {
            load_state(&state_path, destination, name)?
        } else {
            State {
                version: STATE_VERSION,
                destination: destination.into(),
                source: name.into(),
                next_generation: 1,
                journals: Vec::new(),
                sealed: Vec::new(),
                gaps: Vec::new(),
                dropped_gaps: 0,
                overflow_floor: None,
                overflow_floor_change_time: 0,
            }
        };
        let mut delivery = Self {
            active,
            state_path,
            state,
            fenced: false,
            state_limit: MAX_STATE_BYTES,
        };
        delivery.discover()?;
        if !delivery.state_path.exists() {
            delivery.publish()?;
        }
        Ok(delivery)
    }

    /// Filesystem identity of the exact prepared generation; no path re-read
    /// that could accidentally identify a freshly rotated active file instead.
    pub fn prepared_source_identity(&self, token: &DeliveryToken) -> Option<(u64, u64)> {
        (token.destination == self.state.destination)
            .then(|| {
                self.state
                    .journals
                    .iter()
                    .find(|journal| !journal.missing && journal.generation == token.generation)
                    .map(|journal| (journal.device, journal.inode))
            })
            .flatten()
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

    /// Undelivered work this cursor still owns, for host status. Read-only:
    /// it counts the unacknowledged extents of present journals and reads at
    /// most the first undelivered line of the oldest one. Journals are kept in
    /// generation order, so the first present journal with an extent is oldest.
    pub fn backlog(&self) -> DeliveryBacklog {
        let mut backlog = DeliveryBacklog {
            gaps: self.state.gaps.len() as u64,
            ..DeliveryBacklog::default()
        };
        let mut oldest = None;
        for (index, journal) in self.state.journals.iter().enumerate() {
            if journal.missing || journal.acknowledged >= journal.observed_len {
                continue;
            }
            backlog.undelivered_bytes += journal.observed_len - journal.acknowledged;
            backlog.undelivered_segments += 1;
            oldest.get_or_insert(index);
        }
        backlog.oldest_undelivered_wall_time_ms =
            oldest.and_then(|index| self.first_undelivered_wall_time_ms(index));
        backlog
    }

    /// The `wall_time_ms` of the journal's first unacknowledged line, or
    /// `None` when the source moved or that line is not yet a complete record.
    fn first_undelivered_wall_time_ms(&self, index: usize) -> Option<u64> {
        // v5 encodes the wall time as a decimal string, v4 as a number.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum WallTimeMs {
            Number(u64),
            Text(String),
        }
        #[derive(Deserialize)]
        struct WallTime {
            wall_time_ms: WallTimeMs,
        }
        let (mut file, len) = self.open_journal(index).ok()?.ok()?;
        let start = self.state.journals[index].acknowledged;
        file.seek(SeekFrom::Start(start)).ok()?;
        let (line, _, complete, oversized) = read_line(&mut file, start, len).ok()?;
        if !complete || oversized {
            return None;
        }
        match serde_json::from_slice::<WallTime>(&line).ok()?.wall_time_ms {
            WallTimeMs::Number(ms) => Some(ms),
            WallTimeMs::Text(ms) => ms.parse().ok(),
        }
    }

    pub fn prepare_once(&mut self) -> io::Result<Preparation> {
        self.prepare_once_with_after_discover(|| {})
    }

    fn prepare_once_with_after_discover(
        &mut self,
        after_discover: impl FnOnce(),
    ) -> io::Result<Preparation> {
        let mut after_discover = Some(after_discover);
        self.prepare_inner(
            &mut || {
                if let Some(hook) = after_discover.take() {
                    hook();
                }
            },
            true,
        )
    }

    fn prepare_inner(
        &mut self,
        after_discover: &mut dyn FnMut(),
        recheck_heads: bool,
    ) -> io::Result<Preparation> {
        if self.fenced {
            return Err(invalid("uncertain local state publication"));
        }
        self.refresh()?;
        let old_gap_count = self.state.gaps.len();
        self.discover()?;
        after_discover();
        if self.state.gaps.len() > old_gap_count {
            return Ok(Preparation::Step(DeliveryStep::Gap));
        }
        let mut source_moved = false;
        for index in 0..self.state.journals.len() {
            let journal = &self.state.journals[index];
            if journal.missing
                || journal.blocked.is_some()
                // Discovery keeps a sealed journal's length current; one with
                // nothing left needs no open.
                || (journal.prepared.is_none()
                    && journal.acknowledged >= journal.observed_len
                    && !self.is_active(index))
            {
                continue;
            }
            let (mut file, len) = match self.open_journal(index)? {
                Ok(source) => source,
                Err(Unopened::Moved) => {
                    source_moved = true;
                    continue;
                }
                Err(Unopened::HeadChanged) => {
                    // Metadata matched, so discovery skipped this file, but
                    // its bytes changed (a rewrite within one change-time
                    // tick). Persist that discovery must read it before any
                    // later journal can end this pass, then rediscover once.
                    self.state.journals[index].change_time = 0;
                    self.publish()?;
                    if recheck_heads {
                        return self.prepare_inner(&mut || {}, false);
                    }
                    source_moved = true;
                    continue;
                }
            };
            self.state.journals[index].observed_len =
                self.state.journals[index].observed_len.max(len);
            if let Some(prepared) = self.state.journals[index].prepared.clone() {
                if len < prepared.end {
                    self.state.journals[index].observed_len =
                        self.state.journals[index].observed_len.max(prepared.end);
                    sync_source(&file)?;
                    self.record_gap(
                        index,
                        prepared.start,
                        prepared.end,
                        GapReason::ChangedPreparedRange,
                    )?;
                    self.state.journals[index].blocked =
                        Some("source truncated after prepared attempt".into());
                    self.publish()?;
                    return Ok(Preparation::Step(DeliveryStep::Gap));
                }
                let bytes = read_range(&mut file, prepared.start, prepared.end)?;
                if digest(&bytes) != prepared.digest {
                    sync_source(&file)?;
                    self.record_gap(
                        index,
                        prepared.start,
                        prepared.end,
                        GapReason::ChangedPreparedRange,
                    )?;
                    return Ok(Preparation::Step(DeliveryStep::Gap));
                }
                let bodies = checked_bodies(&bytes)?;
                return Ok(Preparation::Batch(self.batch(index, &prepared, bodies)));
            }
            let start = self.state.journals[index].acknowledged;
            if start >= len {
                continue;
            }
            file.seek(SeekFrom::Start(start))?;
            let mut position = start;
            let mut bodies = Vec::new();
            let mut bytes = Vec::new();
            let max_records = self.state.journals[index]
                .split_records
                .map_or(MAX_RECORDS, |limit| {
                    usize::from(limit).clamp(1, MAX_RECORDS)
                });
            while position < len && bodies.len() < max_records {
                let line_start = position;
                let (line, end, complete, oversized) = read_line(&mut file, position, len)?;
                position = end;
                if !complete {
                    if !bodies.is_empty() {
                        break;
                    }
                    if self.is_active(index) {
                        return Ok(Preparation::Step(DeliveryStep::WaitingForWriter));
                    }
                    sync_source(&file)?;
                    self.record_gap(index, line_start, end, GapReason::TornTail)?;
                    return Ok(Preparation::Step(DeliveryStep::Gap));
                }
                if oversized {
                    if !bodies.is_empty() {
                        break;
                    }
                    sync_source(&file)?;
                    self.record_gap(index, line_start, end, GapReason::OversizedLine)?;
                    return Ok(Preparation::Step(DeliveryStep::Gap));
                }
                if !valid_event(&line) {
                    if !bodies.is_empty() {
                        break;
                    }
                    sync_source(&file)?;
                    self.record_gap(index, line_start, end, GapReason::InvalidRecord)?;
                    return Ok(Preparation::Step(DeliveryStep::Gap));
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
            sync_source(&file)?;
            let prepared = Prepared {
                start,
                end,
                digest: digest(&bytes),
                records: bodies.len() as u16,
            };
            self.state.journals[index].prepared = Some(prepared.clone());
            self.publish()?;
            return Ok(Preparation::Batch(self.batch(index, &prepared, bodies)));
        }
        if source_moved {
            Ok(Preparation::Step(DeliveryStep::Retryable))
        } else if self.state.journals.iter().any(|j| j.blocked.is_some()) {
            Ok(Preparation::Step(DeliveryStep::Blocked))
        } else {
            Ok(Preparation::Step(DeliveryStep::Idle))
        }
    }

    fn batch(&self, index: usize, prepared: &Prepared, bodies: Vec<Vec<u8>>) -> DeliveryBatch {
        let journal = &self.state.journals[index];
        DeliveryBatch {
            token: DeliveryToken {
                destination: self.state.destination.clone(),
                generation: journal.generation,
                start: prepared.start,
                end: prepared.end,
                digest: prepared.digest.clone(),
            },
            segment: journal.segment.clone(),
            bodies,
        }
    }

    /// Apply an explicit response to this persisted attempt. If the response
    /// is lost, do not call finish; preparation will replay the same range.
    pub fn finish(
        &mut self,
        token: &DeliveryToken,
        result: ReceiverResult,
    ) -> io::Result<DeliveryStep> {
        if self.fenced {
            return Err(invalid("uncertain local state publication"));
        }
        self.refresh()?;
        let index = self.state.journals.iter().position(|j| {
            j.generation == token.generation
                && !j.missing
                && j.blocked.is_none()
                && j.prepared.as_ref().is_some_and(|prepared| {
                    prepared.start == token.start
                        && prepared.end == token.end
                        && prepared.digest == token.digest
                })
        });
        let Some(index) = index.filter(|_| token.destination == self.state.destination) else {
            return Ok(DeliveryStep::Stale);
        };
        match result {
            ReceiverResult::Complete => {
                let journal = &mut self.state.journals[index];
                journal.acknowledged = token.end;
                journal.prepared = None;
                if journal.split_until.is_some_and(|until| token.end >= until) {
                    journal.split_records = None;
                    journal.split_until = None;
                }
                self.publish()?;
                Ok(DeliveryStep::Accepted)
            }
            ReceiverResult::Retryable => Ok(DeliveryStep::Retryable),
            ReceiverResult::Permanent => {
                // The receiver refuses a whole batch for one bad record.
                // Halve the batch until that record is alone, then skip only
                // its range and keep later records flowing.
                let journal = &mut self.state.journals[index];
                let records = journal.prepared.as_ref().map_or(0, |p| p.records);
                if records == 1 {
                    journal.split_records = None;
                    journal.split_until = None;
                    self.record_gap(index, token.start, token.end, GapReason::ReceiverRejected)?;
                    return Ok(DeliveryStep::Gap);
                }
                let current = if records == 0 {
                    MAX_RECORDS as u16
                } else {
                    records
                };
                journal.split_records = Some((current / 2).max(1));
                journal.split_until = Some(token.end);
                journal.prepared = None;
                self.publish()?;
                Ok(DeliveryStep::Split)
            }
            ReceiverResult::Partial => {
                self.state.journals[index].blocked = Some("partial receiver acceptance".into());
                self.publish()?;
                Ok(DeliveryStep::Blocked)
            }
        }
    }

    #[cfg(test)]
    fn run_once(&mut self, receiver: &mut impl TestAuditReceiver) -> io::Result<DeliveryStep> {
        self.run_once_with_after_discover(receiver, || {})
    }

    #[cfg(test)]
    fn run_once_with_after_discover(
        &mut self,
        receiver: &mut impl TestAuditReceiver,
        after_discover: impl FnOnce(),
    ) -> io::Result<DeliveryStep> {
        match self.prepare_once_with_after_discover(after_discover)? {
            Preparation::Batch(batch) => self.finish(&batch.token, receiver.send(&batch)),
            Preparation::Step(step) => Ok(step),
        }
    }

    fn record_gap(
        &mut self,
        index: usize,
        start: u64,
        end: u64,
        reason: GapReason,
    ) -> io::Result<()> {
        let gap = DeliveryGap {
            generation: self.state.journals[index].generation,
            segment: self.state.journals[index].segment.clone(),
            start,
            end: Some(end),
            reason,
        };
        append_gap(&mut self.state, gap);
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

    fn open_journal(&self, index: usize) -> io::Result<Result<(File, u64), Unopened>> {
        let j = &self.state.journals[index];
        let path = self
            .active
            .parent()
            .unwrap_or(Path::new("."))
            .join(&j.segment);
        let mut file = match open_source(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Err(Unopened::Moved));
            }
            result => result?,
        };
        let (device, inode) = file_identity(&file)?;
        let len = file.metadata()?.len();
        if device != j.device || inode != j.inode || len < j.fingerprint_len as u64 {
            return Ok(Err(Unopened::Moved));
        }
        let fingerprint = match fingerprint(&mut file, j.fingerprint_len as usize) {
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(Err(Unopened::Moved));
            }
            result => result?,
        };
        if !fingerprint_matches(&j.fingerprint, &fingerprint) {
            return Ok(Err(Unopened::HeadChanged));
        }
        if len < j.acknowledged {
            return Ok(Err(Unopened::Moved));
        }
        Ok(Ok((file, len)))
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
        let stem = self
            .state
            .source
            .strip_suffix(".jsonl")
            .ok_or_else(|| invalid("invalid recorder name"))?
            .to_owned();
        let mut scan = Scan {
            by_identity: self
                .state
                .journals
                .iter()
                .enumerate()
                .filter(|(_, j)| !j.missing)
                .map(|(index, j)| ((j.device, j.inode), index))
                .collect(),
            seen: vec![false; self.state.journals.len()],
            changed: false,
        };
        // Sources are opened one at a time, and an idle sealed source not at
        // all: an account can retain thousands of segments.
        let mut identities = std::collections::HashSet::new();
        let mut lowest_index = None::<u32>;
        for path in source_paths(&self.active)? {
            if path == self.active {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| invalid("invalid source name"))?
                .to_owned();
            let index = sealed_index(&stem, &name);
            if let Some(index) = index {
                lowest_index = Some(lowest_index.map_or(index, |lowest| lowest.min(index)));
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                // Gone since the listing: absent, as if never listed.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if let Some(identity) = metadata_identity(&metadata) {
                if identities.contains(&identity) {
                    continue;
                }
                let change_time = change_time_ns(&metadata);
                match scan.by_identity.get(&identity) {
                    Some(&known) if self.idle_sealed(known, &stem, &name, &metadata) => {
                        identities.insert(identity);
                        scan.seen[known] = true;
                        continue;
                    }
                    None if self.below_overflow_floor(index, change_time) => {
                        identities.insert(identity);
                        continue;
                    }
                    _ => {}
                }
            }
            let file = match open_source(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if identities.insert(file_identity(&file)?) {
                self.observe(&mut scan, name, index, file)?;
            }
        }
        if let Some(file) = active_file
            && identities.insert(file_identity(&file)?)
        {
            let name = self.state.source.clone();
            self.observe(&mut scan, name, None, file)?;
        }
        let Scan {
            seen, mut changed, ..
        } = scan;
        for (index, present) in seen.into_iter().enumerate() {
            if !present && !self.state.journals[index].missing {
                let was_active = self.active.file_name().and_then(|n| n.to_str())
                    == Some(self.state.journals[index].segment.as_str());
                retire_missing(&mut self.state, index, was_active);
                changed = true;
            }
        }
        // Expiry of an acknowledged sealed file is not missing evidence.
        // Keep a retired journal only while a recorded gap still names it.
        // Otherwise normal daily expiry accumulates a permanent journal for
        // every file this device has ever uploaded.
        let gap_generations: std::collections::HashSet<_> =
            self.state.gaps.iter().map(|gap| gap.generation).collect();
        let before = self.state.journals.len();
        self.state
            .journals
            .retain(|journal| !journal.missing || gap_generations.contains(&journal.generation));
        changed |= before != self.state.journals.len();
        if let Some(floor) = self.state.overflow_floor
            && lowest_index.is_none_or(|lowest| lowest > floor)
        {
            // No segment it covered remains, so a reused index is new data.
            self.state.overflow_floor = None;
            self.state.overflow_floor_change_time = 0;
            changed = true;
        }
        changed |= self.shed_until_fits()?;
        if changed {
            self.publish()?;
        }
        Ok(())
    }

    /// True when a known sealed source has nothing in flight and is unchanged
    /// by name, length and modification time, so this pass need not open it.
    /// Any difference sends it through `observe`, which checks its head.
    fn idle_sealed(&self, index: usize, stem: &str, name: &str, metadata: &fs::Metadata) -> bool {
        let journal = &self.state.journals[index];
        journal.segment == name
            && journal.observed_len == metadata.len()
            && journal.change_time != 0
            && journal.change_time == change_time_ns(metadata)
            && compact_index(stem, &self.state.source, journal).is_some()
    }

    fn below_overflow_floor(&self, index: Option<u32>, change_time: u64) -> bool {
        self.state
            .overflow_floor
            .zip(index)
            .is_some_and(|(floor, index)| {
                index <= floor && change_time <= self.state.overflow_floor_change_time
            })
    }

    /// Reconcile one opened source with its journal, or adopt it.
    fn observe(
        &mut self,
        scan: &mut Scan,
        name: String,
        index: Option<u32>,
        mut file: File,
    ) -> io::Result<()> {
        let (device, inode) = file_identity(&file)?;
        let metadata = file.metadata()?;
        let len = metadata.len();
        let change_time = change_time_ns(&metadata);
        let fp_len = (len as usize).min(FINGERPRINT_BYTES) as u8;
        let fp = fingerprint(&mut file, fp_len as usize)?;
        let Some(&known) = scan.by_identity.get(&(device, inode)) else {
            // Empty new files carry no stable prefix or deliverable line.
            // Assign their generation after the first completed write.
            if len == 0 || self.below_overflow_floor(index, change_time) {
                return Ok(());
            }
            return self.adopt(scan, name, device, inode, fp, fp_len, len, change_time);
        };
        let journal = &mut self.state.journals[known];
        let was_blocked = journal.blocked.is_some();
        let existing_fp = fingerprint(
            &mut file,
            (journal.fingerprint_len as u64).min(len) as usize,
        )?;
        let changed_head = !fingerprint_matches(&journal.fingerprint, &existing_fp);
        let lost_unprepared_tail =
            journal.prepared.is_none() && journal.blocked.is_none() && len < journal.observed_len;
        if changed_head || lost_unprepared_tail {
            // The recorder never rewrites or truncates a file in place.
            // A reused inode or a shortened observed file is a new
            // generation; keep the old unaccepted extent visible.
            let was_active =
                self.active.file_name().and_then(|n| n.to_str()) == Some(journal.segment.as_str());
            retire_missing(&mut self.state, known, was_active);
            scan.seen[known] = true;
            scan.by_identity.remove(&(device, inode));
            return self.adopt(scan, name, device, inode, fp, fp_len, len, change_time);
        }
        let observed_len = journal
            .observed_len
            .max(len)
            .max(journal.acknowledged)
            .max(journal.prepared.as_ref().map_or(0, |p| p.end));
        scan.changed |= journal.fingerprint != fp
            || journal.segment != name
            || journal.observed_len != observed_len
            || journal.change_time != change_time;
        journal.fingerprint = fp;
        journal.change_time = change_time;
        journal.fingerprint_len = fp_len;
        journal.segment = name;
        if len < journal.acknowledged {
            journal.blocked = Some("source truncated below cursor".into());
        }
        journal.observed_len = observed_len;
        scan.seen[known] = true;
        scan.changed |= !was_blocked && journal.blocked.is_some();
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt(
        &mut self,
        scan: &mut Scan,
        name: String,
        device: u64,
        inode: u64,
        fingerprint: String,
        fingerprint_len: u8,
        len: u64,
        change_time: u64,
    ) -> io::Result<()> {
        register_journal(
            &mut self.state,
            name,
            device,
            inode,
            fingerprint,
            fingerprint_len,
            len,
        )?;
        let index = self.state.journals.len() - 1;
        self.state.journals[index].change_time = change_time;
        scan.by_identity.insert((device, inode), index);
        scan.seen.push(true);
        scan.changed = true;
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

    /// A full cursor must not stop delivery. Give up the oldest sealed
    /// segments, record that loss as one gap, and keep the newer data. Runs
    /// only at the end of discovery, when no caller holds a journal index,
    /// and leaves headroom for the pass's own gaps and prepared range.
    fn shed_until_fits(&mut self) -> io::Result<bool> {
        let target = self.state_limit - self.state_limit / 8;
        let mut shed_any = false;
        loop {
            if encode_state(&self.state)?.len() as u64 <= target {
                return Ok(shed_any);
            }
            shed_any = true;
            let stem = self
                .state
                .source
                .strip_suffix(".jsonl")
                .ok_or_else(|| invalid("invalid recorder name"))?
                .to_owned();
            let writer = (!self.active.exists())
                .then(|| {
                    self.state
                        .journals
                        .iter()
                        .filter(|j| !j.missing)
                        .max_by_key(|j| j.generation)
                        .map(|j| j.generation)
                })
                .flatten();
            let mut candidates: Vec<u32> = self
                .state
                .journals
                .iter()
                .filter(|j| !j.missing && j.prepared.is_none() && Some(j.generation) != writer)
                .filter_map(|j| sealed_index(&stem, &j.segment))
                .collect();
            if candidates.is_empty() {
                return Err(invalid("delivery cursor exceeds size limit"));
            }
            candidates.sort_unstable();
            let floor = candidates[(candidates.len() / 8).max(1) - 1];
            let mut lost = Vec::new();
            let mut newest = self.state.overflow_floor_change_time;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| {
                    elapsed.as_nanos().try_into().unwrap_or(u64::MAX)
                });
            self.state.journals.retain(|j| {
                let shed = !j.missing
                    && j.prepared.is_none()
                    && Some(j.generation) != writer
                    && sealed_index(&stem, &j.segment).is_some_and(|index| index <= floor);
                if shed {
                    newest = newest.max(if j.change_time == 0 {
                        now
                    } else {
                        j.change_time
                    });
                }
                if shed && j.acknowledged < j.observed_len {
                    lost.push(DeliveryGap {
                        generation: j.generation,
                        segment: j.segment.clone(),
                        start: j.prepared.as_ref().map_or(j.acknowledged, |p| p.start),
                        end: None,
                        reason: GapReason::CursorOverflow,
                    });
                }
                !shed
            });
            // One gap per abandoned extent; the gap cap bounds their count.
            for gap in lost {
                append_gap(&mut self.state, gap);
            }
            self.state.overflow_floor = Some(self.state.overflow_floor.unwrap_or(0).max(floor));
            self.state.overflow_floor_change_time = newest;
        }
    }

    fn refresh(&mut self) -> io::Result<()> {
        let name = self
            .active
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("invalid recorder path"))?;
        self.state = load_state(&self.state_path, &self.state.destination, name)?;
        Ok(())
    }

    fn publish_inner(&self) -> io::Result<()> {
        let temp = self.state_path.with_extension("json.tmp");
        let bytes = encode_state(&self.state)?;
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
        commit_rename(&temp, &self.state_path)
    }
}

/// Why a journal's source could not be read this pass.
enum Unopened {
    /// Renamed, replaced or shortened; the next discovery reconciles it.
    Moved,
    /// Same identity and metadata, different head bytes.
    HeadChanged,
}

/// One discovery pass's view of the journals it has matched.
struct Scan {
    by_identity: std::collections::HashMap<(u64, u64), usize>,
    seen: Vec<bool>,
    changed: bool,
}

/// Filesystem identity from metadata, without opening the file. Windows
/// metadata does not expose it, so every source is opened there.
#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    metadata
        .file_type()
        .is_file()
        .then(|| (metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn metadata_identity(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

fn append_gap(state: &mut State, gap: DeliveryGap) {
    let gaps = &mut state.gaps;
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
    let excess = gaps.len().saturating_sub(MAX_GAPS);
    if excess > 0 {
        gaps.drain(..excess);
        state.dropped_gaps = state.dropped_gaps.saturating_add(excess as u64);
    }
}

fn retire_missing(state: &mut State, index: usize, was_active: bool) {
    let journal = &state.journals[index];
    if journal.prepared.is_some() || journal.acknowledged < journal.observed_len || was_active {
        let gap = DeliveryGap {
            generation: journal.generation,
            segment: journal.segment.clone(),
            start: journal
                .prepared
                .as_ref()
                .map_or(journal.acknowledged, |p| p.start),
            end: None,
            reason: GapReason::MissingSource,
        };
        append_gap(state, gap);
    }
    let journal = &mut state.journals[index];
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
        split_records: None,
        split_until: None,
        change_time: 0,
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
        let valid_name = j.segment == active_name || sealed_index(stem, &j.segment).is_some();
        if !generations.insert(j.generation)
            || (!j.missing && !identities.insert((j.device, j.inode)))
            || j.generation >= state.next_generation
            || !valid_name
            || j.fingerprint_len as usize > FINGERPRINT_BYTES
            || (j.fingerprint_len == 0) != j.fingerprint.is_empty()
            || (!j.fingerprint.is_empty()
                && !(valid_digest(&j.fingerprint)
                    || (j.fingerprint.len() == COMPACT_FINGERPRINT_HEX
                        && j.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()))))
            || j.acknowledged > j.observed_len
            || j.prepared.as_ref().is_some_and(|p| {
                p.start != j.acknowledged
                    || p.end <= p.start
                    || p.end > j.observed_len
                    || p.end - p.start > MAX_BATCH_BYTES as u64
                    || usize::from(p.records) > MAX_RECORDS
                    || !valid_digest(&p.digest)
            })
            || j.split_records
                .is_some_and(|limit| limit == 0 || usize::from(limit) > MAX_RECORDS)
            || j.split_records.is_some() != j.split_until.is_some()
        {
            return Err(invalid("corrupt delivery cursor"));
        }
    }
    // A gap may outlive its journal: overflow shedding drops the journal and
    // keeps only the loss record.
    for gap in &state.gaps {
        if gap.generation >= state.next_generation || gap.end.is_some_and(|end| end <= gap.start) {
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
    let mut segments = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if sealed_index(stem, filename).is_some() {
            segments.push(entry.path());
        }
    }
    // Numeric order: the recorder keeps counting past seg999999.
    segments.sort_by_key(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| sealed_index(stem, name))
    });
    if active.exists() {
        segments.push(active.to_owned());
    }
    Ok(segments)
}

/// Read an inode identity without following a symlink. The caller must keep
/// the source excluded from writers through the subsequent expiry operation.
pub fn source_identity(path: &Path) -> io::Result<(u64, u64)> {
    file_identity(&open_source(path)?)
}

fn open_source(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        // Open a symlink itself (like O_NOFOLLOW); the is_file check rejects it.
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
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

fn load_state(path: &Path, destination: &str, active_name: &str) -> io::Result<State> {
    let state = decode_state(&read_private_file(path)?, active_name)?;
    if state.destination != destination || state.source != active_name {
        return Err(invalid("incompatible delivery cursor"));
    }
    check_header(&state)?;
    validate_state(&state, active_name)?;
    Ok(state)
}

fn check_header(state: &State) -> io::Result<()> {
    if state.version != STATE_VERSION
        || state.destination.is_empty()
        || state.destination.len() > 256
        || state.next_generation == 0
    {
        return Err(invalid("incompatible delivery cursor"));
    }
    Ok(())
}

/// Parse either cursor version into the in-memory form, where every source,
/// including a compact sealed one, is a `Journal` ordered by generation.
/// `fallback_source` names a version 1 cursor's source, which it did not store.
fn decode_state(bytes: &[u8], fallback_source: &str) -> io::Result<State> {
    let mut state: State =
        serde_json::from_slice(bytes).map_err(|_| invalid("corrupt delivery cursor"))?;
    match state.version {
        1 if state.source.is_empty() && state.sealed.is_empty() => {
            state.source = fallback_source.to_owned();
        }
        STATE_VERSION if !state.source.is_empty() => {}
        _ => return Err(invalid("incompatible delivery cursor")),
    }
    state.version = STATE_VERSION;
    // Version 1 blocked a journal for good on a receiver rejection. Resume
    // it from its prepared range; a new rejection now splits the batch.
    for journal in &mut state.journals {
        if journal.blocked.as_deref() == Some(LEGACY_REJECTION_BLOCK) {
            journal.blocked = None;
        }
    }
    let stem = state
        .source
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("corrupt delivery cursor"))?
        .to_owned();
    for SealedEntry(generation, index, device, inode, len, delivered, change_time, prefix) in
        std::mem::take(&mut state.sealed)
    {
        if len == 0 || prefix.len() != COMPACT_FINGERPRINT_HEX {
            return Err(invalid("corrupt delivery cursor"));
        }
        state.journals.push(Journal {
            generation,
            segment: segment_name(&stem, index),
            device,
            inode,
            fingerprint: prefix,
            fingerprint_len: len.min(FINGERPRINT_BYTES as u64) as u8,
            observed_len: len,
            acknowledged: if delivered { len } else { 0 },
            prepared: None,
            blocked: None,
            missing: false,
            split_records: None,
            split_until: None,
            change_time,
        });
    }
    state.journals.sort_by_key(|journal| journal.generation);
    // A version 1 cursor kept every gap; cap it before anything is published.
    let excess = state.gaps.len().saturating_sub(MAX_GAPS);
    if excess > 0 {
        state.gaps.drain(..excess);
        state.dropped_gaps = state.dropped_gaps.saturating_add(excess as u64);
    }
    Ok(state)
}

/// The on-disk form: idle sealed sources leave the journal list for one
/// compact row each, so retained history costs tens of bytes per file.
fn encode_state(state: &State) -> io::Result<Vec<u8>> {
    let stem = state
        .source
        .strip_suffix(".jsonl")
        .ok_or_else(|| invalid("invalid recorder name"))?;
    let mut encoded = State {
        journals: Vec::new(),
        sealed: Vec::new(),
        ..state.clone()
    };
    for journal in &state.journals {
        match compact_index(stem, &state.source, journal) {
            Some(index) => encoded.sealed.push(SealedEntry(
                journal.generation,
                index,
                journal.device,
                journal.inode,
                journal.observed_len,
                journal.acknowledged == journal.observed_len,
                journal.change_time,
                journal.fingerprint[..COMPACT_FINGERPRINT_HEX].to_owned(),
            )),
            None => encoded.journals.push(journal.clone()),
        }
    }
    serde_json::to_vec(&encoded).map_err(io::Error::other)
}

/// A sealed source with nothing in flight: unread, or fully acknowledged.
/// Its segment name must round-trip through the index alone.
fn compact_index(stem: &str, active_name: &str, journal: &Journal) -> Option<u32> {
    if journal.missing
        || journal.prepared.is_some()
        || journal.blocked.is_some()
        || journal.split_records.is_some()
        || journal.observed_len == 0
        || journal.fingerprint.len() < COMPACT_FINGERPRINT_HEX
        || journal.fingerprint_len as u64 != journal.observed_len.min(FINGERPRINT_BYTES as u64)
        || journal.segment == active_name
        || (journal.acknowledged != 0 && journal.acknowledged != journal.observed_len)
    {
        return None;
    }
    sealed_index(stem, &journal.segment)
        .filter(|index| segment_name(stem, *index) == journal.segment)
}

/// Index of a recorder segment name. The recorder pads to six digits and
/// keeps counting past 999999.
fn sealed_index(stem: &str, name: &str) -> Option<u32> {
    let digits = name
        .strip_prefix(stem)?
        .strip_prefix("-seg")?
        .strip_suffix(".jsonl")?;
    if digits.len() < 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// A compact entry keeps only a prefix of its head fingerprint. An empty
/// stored fingerprint is a version 1 journal that never recorded one.
fn fingerprint_matches(stored: &str, computed: &str) -> bool {
    stored.is_empty() || computed.starts_with(stored)
}

/// Inode change time on Unix: every write or metadata change moves it, and
/// unlike the modification time, `touch`, `cp -p` or `rsync -t` cannot set it
/// back. Elsewhere the modification time is the best available signal.
#[cfg(unix)]
fn change_time_ns(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    u64::try_from(metadata.ctime())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|ns| ns.checked_add(u64::try_from(metadata.ctime_nsec()).ok()?))
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn change_time_ns(metadata: &fs::Metadata) -> u64 {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |elapsed| {
            elapsed.as_nanos().try_into().unwrap_or(u64::MAX)
        })
}

fn segment_name(stem: &str, index: u32) -> String {
    format!("{stem}-seg{index:06}.jsonl")
}

/// Flush a source's bytes before publishing a range that depends on them.
#[cfg(unix)]
fn sync_source(file: &File) -> io::Result<()> {
    file.sync_all()
}

/// FlushFileBuffers needs write access, which the read-only source handle
/// lacks. Reopen the same file object (not the path, so a concurrent rotation
/// cannot swap it) with write access for the flush only.
#[cfg(windows)]
fn sync_source(file: &File) -> io::Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    const INVALID_HANDLE_VALUE: isize = -1;
    unsafe extern "system" {
        fn ReOpenFile(
            file: *mut std::ffi::c_void,
            access: u32,
            share: u32,
            flags: u32,
        ) -> *mut std::ffi::c_void;
    }
    // SAFETY: the source handle is valid for the call; ReOpenFile returns a
    // new owned handle, which `File` closes on drop.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle().cast(),
            GENERIC_WRITE,
            FILE_SHARE_ALL,
            0,
        )
    };
    if handle as isize == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    unsafe { File::from_raw_handle(handle.cast()) }.sync_all()
}

#[cfg(unix)]
fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata()?;
    Ok((meta.dev(), meta.ino()))
}

/// Volume serial and 64-bit file index, the Windows analogue of dev/inode.
/// NTFS file indexes are unique per volume; ReFS may need the 128-bit
/// FILE_ID_INFO instead, which the journal's u64 inode field cannot hold.
#[cfg(windows)]
fn file_identity(file: &File) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        attributes: u32,
        times: [u32; 6],
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = ByHandleFileInformation::default();
    // SAFETY: the handle is owned by `file` and outlives the call; `info`
    // matches BY_HANDLE_FILE_INFORMATION's layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let index = (u64::from(info.index_high) << 32) | u64::from(info.index_low);
    Ok((u64::from(info.volume_serial), index))
}

/// Replace `target` with the fully synced `temp`; this is the cursor's
/// commit point, so the rename itself must be durable before returning.
#[cfg(unix)]
fn commit_rename(temp: &Path, target: &Path) -> io::Result<()> {
    fs::rename(temp, target)?;
    File::open(target.parent().unwrap_or(Path::new(".")))?.sync_all()
}

/// Windows cannot fsync a directory; MOVEFILE_WRITE_THROUGH returns only
/// after the rename is flushed to disk.
#[cfg(windows)]
fn commit_rename(temp: &Path, target: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    unsafe extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let wide = |path: &Path| -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let (from, to) = (wide(temp), wide(target));
    // SAFETY: both buffers are NUL-terminated UTF-16 paths that outlive the call.
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
    let Some(body) = line.strip_suffix(b"\n") else {
        return false;
    };
    if V5Record::from_json(body).is_ok() {
        return true;
    }
    std::str::from_utf8(body)
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

    impl TestAuditReceiver for FakeReceiver {
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

    fn prepared_batch(worker: &mut LocalAuditDelivery) -> DeliveryBatch {
        match worker.prepare_once().unwrap() {
            Preparation::Batch(batch) => batch,
            Preparation::Step(step) => panic!("expected a batch, got {step:?}"),
        }
    }

    #[test]
    fn prepare_survives_restart_and_missing_ack_replays_identical_bodies() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let original = fs::read(&active).unwrap();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let first = prepared_batch(&mut worker);
        assert_eq!(first.bodies.concat(), original);
        drop(worker);

        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let replay = prepared_batch(&mut worker);
        assert_eq!(replay.token, first.token);
        assert_eq!(replay.bodies, first.bodies);
        assert_eq!(worker.state.journals[0].acknowledged, 0);

        let mut receiver = FakeReceiver::default();
        assert!(matches!(receiver.send(&first), ReceiverResult::Complete));
        // The acknowledgement is lost. A duplicate-safe receiver may see the
        // same original rows again before the cursor can move.
        let duplicate = prepared_batch(&mut worker);
        assert_eq!(duplicate.token, first.token);
        assert_eq!(duplicate.bodies, first.bodies);
        assert!(matches!(
            receiver.send(&duplicate),
            ReceiverResult::Complete
        ));
        assert_eq!(
            worker
                .finish(&duplicate.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
        assert_eq!(receiver.batches[0].bodies, receiver.batches[1].bodies);
        assert_eq!(worker.state.journals[0].acknowledged, first.token.end());
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Idle)
        );
        record(&recorder, "two");
        let next = prepared_batch(&mut worker);
        assert_eq!(next.token.generation(), first.token.generation());
        assert_eq!(
            worker
                .finish(&first.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Stale
        );
        assert_eq!(worker.state.journals[0].acknowledged, first.token.end());
        assert_eq!(
            worker
                .finish(&next.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
    }

    #[test]
    fn completion_uses_owned_originals_after_source_changes() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let batch = prepared_batch(&mut worker);
        let originals = batch.bodies.clone();
        let mut file = OpenOptions::new().write(true).open(&active).unwrap();
        file.seek(SeekFrom::Start(250)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        let mut receiver = FakeReceiver::default();
        assert!(matches!(receiver.send(&batch), ReceiverResult::Complete));
        assert_eq!(receiver.batches[0].bodies, originals);
        assert_eq!(
            worker
                .finish(&batch.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
        assert_eq!(worker.state.journals[0].acknowledged, batch.token.end());
    }

    #[test]
    fn stale_generation_and_destination_completions_cannot_advance_cursor() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let old = prepared_batch(&mut worker);
        recorder.rotate().unwrap();
        record(&recorder, "new");
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Gap)
        );
        let current = prepared_batch(&mut worker);
        assert_ne!(old.token.generation(), current.token.generation());
        assert_eq!(
            worker.finish(&old.token, ReceiverResult::Complete).unwrap(),
            DeliveryStep::Stale
        );
        assert_eq!(worker.state.journals[1].acknowledged, 0);

        let other_state = state_dir.with_file_name("other-delivery");
        let mut other = LocalAuditDelivery::open(&active, &other_state, "receiver-B").unwrap();
        let other_batch = prepared_batch(&mut other);
        assert_eq!(
            other
                .finish(&current.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Stale
        );
        assert_eq!(other.state.journals[0].acknowledged, 0);
        assert_eq!(
            other
                .finish(&other_batch.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
        assert_eq!(
            worker
                .finish(&current.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
    }

    #[test]
    fn late_completion_refreshes_generation_changed_by_another_owner() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "first");
        let mut first_owner = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let old = prepared_batch(&mut first_owner);
        let mut next_owner = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        recorder.rotate().unwrap();
        record(&recorder, "second");
        assert_eq!(
            next_owner.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Gap)
        );
        let current = prepared_batch(&mut next_owner);
        assert_eq!(
            first_owner
                .finish(&old.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Stale
        );
        assert_eq!(first_owner.state.journals[1].acknowledged, 0);
        assert_eq!(
            next_owner
                .finish(&current.token, ReceiverResult::Complete)
                .unwrap(),
            DeliveryStep::Accepted
        );
    }

    #[test]
    fn prepared_batch_is_owned_after_worker_and_source_are_gone() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let batch = prepared_batch(&mut worker);
        drop(worker);
        drop(recorder);
        fs::remove_file(&active).unwrap();
        let originals = batch.bodies.clone();
        let sent = std::thread::spawn(move || {
            let mut receiver = FakeReceiver::default();
            assert!(matches!(receiver.send(&batch), ReceiverResult::Complete));
            receiver.batches.remove(0).bodies
        })
        .join()
        .unwrap();
        assert_eq!(sent, originals);
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
        assert_eq!(sink.batches[2].token.start(), first.token.end());
        assert_eq!(
            sink.batches[2].bodies.concat(),
            fs::read(&active).unwrap()[first.token.end() as usize..]
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
        let prepared_end = sink.batches[0].token.end();
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
        assert_eq!(sink.batches[1].token.start(), prepared_end);
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
        let identity = file_identity(&File::open(&active).unwrap()).unwrap();
        worker.state.journals[0].device = identity.0;
        worker.state.journals[0].inode = identity.1;
        worker.publish().unwrap();
        let mut sink = FakeReceiver::default();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Gap);
        assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
        assert_eq!(worker.gaps()[0].start, 0);
        assert_eq!(worker.gaps()[0].end, None);
        assert!(worker.state.journals[0].missing);
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_ne!(sink.batches[0].token.generation(), old_generation);
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
        assert_eq!(sink.batches.last().unwrap().token.start(), prior_end + 9);
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

    /// Rejects every batch that contains a record labelled `bad`, as the
    /// receiver rejects a whole batch for one invalid record.
    #[derive(Default)]
    struct RejectingReceiver {
        accepted: Vec<Vec<u8>>,
        sends: usize,
    }

    impl TestAuditReceiver for RejectingReceiver {
        fn send(&mut self, batch: &DeliveryBatch) -> ReceiverResult {
            self.sends += 1;
            if batch
                .bodies
                .iter()
                .any(|body| body.windows(5).any(|w| w == b"\"bad\""))
            {
                return ReceiverResult::Permanent;
            }
            self.accepted.extend(batch.bodies.iter().cloned());
            ReceiverResult::Complete
        }
    }

    /// Seal `count` one-record segments beside `active`, numbered from
    /// `first`, as the recorder leaves them after rolls.
    fn seal_segments(
        recorder: &JsonlRecorder,
        active: &Path,
        first: u32,
        count: u32,
    ) -> Vec<PathBuf> {
        record(recorder, "sealed");
        let bytes = fs::read(active).unwrap();
        let line = bytes
            .split_inclusive(|b| *b == b'\n')
            .next_back()
            .unwrap()
            .to_vec();
        let stem = active
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_suffix(".jsonl")
            .unwrap()
            .to_owned();
        (first..first + count)
            .map(|index| {
                let path = active.with_file_name(segment_name(&stem, index));
                fs::write(&path, &line).unwrap();
                path
            })
            .collect()
    }

    fn acknowledge_all(worker: &mut LocalAuditDelivery) {
        for journal in &mut worker.state.journals {
            journal.acknowledged = journal.observed_len;
        }
        worker.publish().unwrap();
    }

    fn state_len(state_dir: &Path) -> u64 {
        fs::metadata(state_dir.join("local-delivery.json"))
            .unwrap()
            .len()
    }

    #[test]
    fn thousands_of_retained_delivered_segments_keep_the_cursor_compact() {
        let (_dir, active, state_dir, recorder) = setup();
        seal_segments(&recorder, &active, 1, 5000);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        acknowledge_all(&mut worker);
        // Version 1 kept ~320 bytes per retained file and wedged at ~3,250.
        assert!(
            state_len(&state_dir) < 5000 * 128,
            "{}",
            state_len(&state_dir)
        );
        record(&recorder, "after-history");
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        assert_eq!(sink.batches.len(), 1);
        assert!(
            sink.batches[0]
                .bodies
                .iter()
                .any(|body| body.windows(13).any(|w| w == b"after-history"))
        );
        assert!(worker.gaps().is_empty());
        assert!(state_len(&state_dir) < 5000 * 128);
    }

    #[test]
    fn segment_indexes_past_six_digits_are_delivered() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        seal_segments(&recorder, &active, 999_999, 2);
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let segments: Vec<_> = sink.batches.iter().map(|b| b.segment.clone()).collect();
        // Delivered in recorder order: generations follow the numeric index.
        let position = |suffix: &str| segments.iter().position(|s| s.ends_with(suffix)).unwrap();
        assert!(position("-seg999999.jsonl") < position("-seg1000000.jsonl"));
    }

    #[test]
    fn version_one_cursor_near_the_size_cap_upgrades_and_resumes() {
        let (_dir, active, state_dir, recorder) = setup();
        seal_segments(&recorder, &active, 1, 3400);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        // The stalled device: most segments delivered, a backlog behind them.
        let backlog = worker.state.journals.len() - 10;
        for journal in &mut worker.state.journals[..backlog] {
            journal.acknowledged = journal.observed_len;
        }
        let mut legacy = serde_json::to_value(&worker.state).unwrap();
        legacy["version"] = 1.into();
        legacy.as_object_mut().unwrap().remove("source");
        for journal in legacy["journals"].as_array_mut().unwrap() {
            journal.as_object_mut().unwrap().remove("change_time");
        }
        let legacy = serde_json::to_vec(&legacy).unwrap();
        assert!(legacy.len() as u64 > MAX_STATE_BYTES * 7 / 8);
        drop(worker);
        fs::write(state_dir.join("local-delivery.json"), legacy).unwrap();
        record(&recorder, "after-upgrade");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        // Nine backlog segments, then the active file with its new record.
        assert_eq!(sink.batches.len(), 10);
        assert!(worker.gaps().is_empty());
        // Windows file ids make each compact row larger than on Unix.
        assert!(state_len(&state_dir) < MAX_STATE_BYTES / 2);
        let reopened = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(reopened.state.version, STATE_VERSION);
    }

    #[test]
    fn full_cursor_sheds_oldest_segments_and_keeps_delivering() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        worker.state_limit = 64 * 1024;
        let old = seal_segments(&recorder, &active, 1, 2000);
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        assert!(state_len(&state_dir) <= 64 * 1024);
        let floor = worker.state.overflow_floor.unwrap();
        let overflow: Vec<_> = worker
            .gaps()
            .iter()
            .filter(|gap| gap.reason == GapReason::CursorOverflow)
            .collect();
        assert!(!overflow.is_empty());
        let stem = worker.state.source.strip_suffix(".jsonl").unwrap();
        for batch in &sink.batches {
            assert!(sealed_index(stem, &batch.segment).is_none_or(|index| index > floor));
        }
        // Every untracked segment above the floor was still delivered once.
        let delivered = sink.batches.len();
        drain(&mut worker, &mut sink);
        assert_eq!(sink.batches.len(), delivered);
        assert!(!worker.fenced);
        // A restarted recorder can reuse a shed index before discovery sees
        // the old file gone. That new incarnation is delivered.
        let reused = old[0].clone();
        fs::remove_file(&reused).unwrap();
        let fresh = recorded_line(&recorder, &active, "reused-index");
        fs::write(&reused, &fresh).unwrap();
        File::options()
            .write(true)
            .open(&reused)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(10))
            .unwrap();
        let reused_name = reused.file_name().unwrap().to_str().unwrap().to_owned();
        let before = sink.batches.len();
        drain(&mut worker, &mut sink);
        let reused_batches: Vec<_> = sink.batches[before..]
            .iter()
            .filter(|batch| batch.segment == reused_name)
            .collect();
        assert_eq!(reused_batches.len(), 1);
        assert_eq!(reused_batches[0].bodies.concat(), fresh);
        // Once nothing at or below the floor remains, it no longer applies.
        for path in &old[..floor as usize] {
            fs::remove_file(path).unwrap();
        }
        drain(&mut worker, &mut sink);
        assert_eq!(worker.state.overflow_floor, None);
    }

    #[test]
    fn retained_gaps_are_bounded_and_counted() {
        let (_dir, active, state_dir, _recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let segment = worker.state.source.clone();
        for index in 0..(MAX_GAPS as u64 + 10) {
            append_gap(
                &mut worker.state,
                DeliveryGap {
                    generation: 0,
                    segment: segment.clone(),
                    start: index * 2,
                    end: Some(index * 2 + 1),
                    reason: GapReason::InvalidRecord,
                },
            );
        }
        assert_eq!(worker.gaps().len(), MAX_GAPS);
        assert_eq!(worker.state.dropped_gaps, 10);
        assert_eq!(worker.gaps()[0].start, 20);
    }

    /// Runs only in the child process that `low_open_file_limit_*` spawns,
    /// so lowering the limit cannot affect other tests in this process.
    #[cfg(unix)]
    #[test]
    fn low_open_file_limit_child() {
        if std::env::var_os("MDK_LOCAL_DELIVERY_LOW_NOFILE").is_none() {
            return;
        }
        let limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: libc::RLIM_INFINITY,
        };
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: both pointers reference valid rlimit values for the call.
        unsafe {
            assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut current), 0);
            let limit = libc::rlimit {
                rlim_max: current.rlim_max,
                ..limit
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
        }
        let (_dir, active, state_dir, recorder) = setup();
        seal_segments(&recorder, &active, 1, 300);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        assert_eq!(sink.batches.len(), 301);
    }

    #[cfg(unix)]
    #[test]
    fn low_open_file_limit_still_delivers_hundreds_of_segments() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_delivery::tests::low_open_file_limit_child",
                "--nocapture",
            ])
            .env("MDK_LOCAL_DELIVERY_LOW_NOFILE", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The last line `recorder` wrote for `label`.
    fn recorded_line(recorder: &JsonlRecorder, active: &Path, label: &str) -> Vec<u8> {
        record(recorder, label);
        fs::read(active)
            .unwrap()
            .split_inclusive(|b| *b == b'\n')
            .next_back()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn compact_entry_whose_inode_is_reused_starts_a_new_generation() {
        let (_dir, active, state_dir, recorder) = setup();
        let old = seal_segments(&recorder, &active, 1, 1).remove(0);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        // Retention deletes the delivered segment and a new one reuses its
        // inode number, longer than the old one and with a different head.
        fs::remove_file(&old).unwrap();
        let mut fresh = recorded_line(&recorder, &active, "fresh-head");
        fresh.extend(recorded_line(&recorder, &active, "fresh-tail"));
        let replacement = active.with_file_name(segment_name(
            worker.state.source.strip_suffix(".jsonl").unwrap(),
            2,
        ));
        fs::write(&replacement, &fresh).unwrap();
        let identity = file_identity(&File::open(&replacement).unwrap()).unwrap();
        let journal = worker
            .state
            .journals
            .iter_mut()
            .find(|j| j.segment.ends_with("-seg000001.jsonl"))
            .unwrap();
        (journal.device, journal.inode) = identity;
        worker.publish().unwrap();
        drop(worker);
        // Reopen so the old journal is the compact on-disk form.
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let delivered: Vec<u8> = sink
            .batches
            .iter()
            .filter(|b| b.segment.ends_with("-seg000002.jsonl"))
            .flat_map(|b| b.bodies.concat())
            .collect();
        assert_eq!(delivered, fresh);
    }

    #[test]
    fn rewrite_that_restores_mtime_is_reread_instead_of_retried_forever() {
        let (_dir, active, state_dir, recorder) = setup();
        let sealed = seal_segments(&recorder, &active, 1, 1).remove(0);
        drop(LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap());
        // As `cp -p` or `rsync -t` would: same name, inode, length and mtime.
        let original = fs::metadata(&sealed).unwrap().modified().unwrap();
        let mut bytes = fs::read(&sealed).unwrap();
        bytes[1] = b'X';
        let file = OpenOptions::new().write(true).open(&sealed).unwrap();
        (&file).write_all(&bytes).unwrap();
        file.set_modified(original).unwrap();
        drop(file);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        assert_ne!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        drain(&mut worker, &mut sink);
        let gaps: Vec<_> = worker
            .gaps()
            .iter()
            .filter(|gap| gap.segment.ends_with("-seg000001.jsonl"))
            .map(|gap| gap.reason.clone())
            .collect();
        assert!(gaps.contains(&GapReason::MissingSource));
        assert!(gaps.contains(&GapReason::InvalidRecord));
    }

    #[test]
    fn delivered_segment_rewritten_with_restored_mtime_is_delivered_again() {
        let (_dir, active, state_dir, recorder) = setup();
        let sealed = seal_segments(&recorder, &active, 1, 1).remove(0);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        drop(worker);
        // Let the change-time clock tick past the original write.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let original = fs::metadata(&sealed).unwrap().modified().unwrap();
        let mut bytes = fs::read(&sealed).unwrap();
        bytes[1] = b'X';
        let file = OpenOptions::new().write(true).open(&sealed).unwrap();
        (&file).write_all(&bytes).unwrap();
        file.set_modified(original).unwrap();
        drop(file);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        // The rewrite is a new generation, read from its first byte.
        assert!(worker.gaps().iter().any(|gap| {
            gap.reason == GapReason::InvalidRecord
                && gap.segment.ends_with("-seg000001.jsonl")
                && gap.start == 0
        }));
    }

    #[test]
    fn head_change_hidden_from_metadata_is_retired_despite_a_torn_active_tail() {
        let (_dir, active, state_dir, recorder) = setup();
        let sealed = seal_segments(&recorder, &active, 1, 1).remove(0);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        drop(recorder);
        // Make the sealed segment unread again, then rewrite it so that even
        // its change time matches (a coarse-clock filesystem in one tick).
        let mut bytes = fs::read(&sealed).unwrap();
        bytes[1] = b'X';
        fs::write(&sealed, &bytes).unwrap();
        let metadata = fs::metadata(&sealed).unwrap();
        let journal = worker
            .state
            .journals
            .iter_mut()
            .find(|j| j.segment.ends_with("-seg000001.jsonl"))
            .unwrap();
        journal.acknowledged = 0;
        journal.change_time = change_time_ns(&metadata);
        worker.publish().unwrap();
        // The active file ends in a torn line the reader must wait on.
        let mut tail = OpenOptions::new().append(true).open(&active).unwrap();
        tail.write_all(b"{\"partial").unwrap();
        drop(tail);
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Gap)
        );
        assert!(worker.gaps().iter().any(|gap| {
            gap.reason == GapReason::MissingSource && gap.segment.ends_with("-seg000001.jsonl")
        }));
    }

    #[test]
    fn expiry_never_blesses_a_journal_without_a_stored_head() {
        let (_dir, active, state_dir, recorder) = setup();
        let sealed = seal_segments(&recorder, &active, 1, 1).remove(0);
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let index = worker
            .state
            .journals
            .iter()
            .position(|j| j.segment.ends_with("-seg000001.jsonl"))
            .unwrap();
        let observed = worker.state.journals[index].observed_len;
        worker.state.journals[index].fingerprint.clear();
        worker.state.journals[index].fingerprint_len = 0;
        worker.publish().unwrap();
        drop(worker);
        // Different, longer bytes under the same inode.
        let mut replacement = OpenOptions::new().append(true).open(&sealed).unwrap();
        replacement.write_all(b"{\"unrelated\":true}\n").unwrap();
        drop(replacement);
        assert!(retention::expire_closed_source(&sealed, &state_dir).unwrap());
        let state = load_state(
            &state_dir.join("local-delivery.json"),
            "receiver-A",
            active.file_name().unwrap().to_str().unwrap(),
        )
        .unwrap();
        // The cursor still holds the old extent; discovery reports the loss.
        let journal = state
            .journals
            .iter()
            .find(|j| j.segment.ends_with("-seg000001.jsonl"))
            .unwrap();
        assert_eq!(journal.observed_len, observed);
    }

    #[test]
    fn version_one_rejection_block_resumes_its_prepared_range() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Retryable),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Retryable);
        // What version 1 left after a 4xx: the journal blocked, its range kept.
        worker.state.journals[0].blocked = Some(LEGACY_REJECTION_BLOCK.into());
        let mut legacy = serde_json::to_value(&worker.state).unwrap();
        legacy["version"] = 1.into();
        legacy.as_object_mut().unwrap().remove("source");
        drop(worker);
        fs::write(
            state_dir.join("local-delivery.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert!(worker.blocked().is_empty());
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(sink.batches[1].token.start(), 0);
        assert_eq!(sink.batches[1].bodies, sink.batches[0].bodies);
    }

    #[test]
    fn version_one_cursor_with_many_gaps_is_capped_on_upgrade() {
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "one");
        let worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut legacy = serde_json::to_value(&worker.state).unwrap();
        legacy["version"] = 1.into();
        legacy.as_object_mut().unwrap().remove("source");
        legacy["gaps"] = (0..9000u64)
            .map(|index| {
                serde_json::json!({
                    "generation": 1,
                    "segment": worker.state.source,
                    "start": index * 2,
                    "end": index * 2 + 1,
                    "reason": "InvalidRecord",
                })
            })
            .collect();
        drop(worker);
        fs::write(
            state_dir.join("local-delivery.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(worker.gaps().len(), MAX_GAPS);
        assert_eq!(worker.state.dropped_gaps, 9000 - MAX_GAPS as u64);
        record(&recorder, "two");
        drain(&mut worker, &mut FakeReceiver::default());
        assert!(state_len(&state_dir) < 64 * 1024);
    }

    #[test]
    fn split_limit_ends_once_the_rejected_range_is_acknowledged() {
        let (_dir, active, state_dir, recorder) = setup();
        for index in 0..150 {
            record(&recorder, &format!("row-{index}"));
        }
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        // One rejection that a smaller retry no longer reproduces.
        let mut sink = FakeReceiver {
            next: Some(ReceiverResult::Permanent),
            ..Default::default()
        };
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Split);
        let rejected_end = sink.batches[0].token.end();
        while worker.state.journals[0].acknowledged < rejected_end {
            assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        }
        assert!(worker.state.journals[0].split_records.is_none());
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        // Back to full batches: more than the halved limit of 48.
        assert!(sink.batches.last().unwrap().bodies.len() > MAX_RECORDS / 2);
        assert!(worker.gaps().is_empty());
    }

    #[test]
    fn rejected_batch_is_split_until_only_the_bad_record_is_skipped() {
        let (_dir, active, state_dir, recorder) = setup();
        for index in 0..40 {
            record(&recorder, &format!("good-{index}"));
        }
        record(&recorder, "bad");
        for index in 40..60 {
            record(&recorder, &format!("good-{index}"));
        }
        let lines: Vec<Vec<u8>> = fs::read(&active)
            .unwrap()
            .split_inclusive(|b| *b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        let bad = lines
            .iter()
            .position(|line| line.windows(5).any(|w| w == b"\"bad\""))
            .unwrap();
        let bad_start: u64 = lines[..bad].iter().map(|l| l.len() as u64).sum();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = RejectingReceiver::default();
        let mut splits = 0;
        loop {
            match worker.run_once(&mut sink).unwrap() {
                DeliveryStep::Idle => break,
                DeliveryStep::Split => splits += 1,
                DeliveryStep::Accepted | DeliveryStep::Gap => {}
                other => panic!("unexpected delivery step: {other:?}"),
            }
            assert!(sink.sends < 64, "bisection did not converge");
        }
        let mut expected = lines.clone();
        expected.remove(bad);
        assert_eq!(sink.accepted, expected);
        assert!(splits > 0 && splits <= 7);
        assert_eq!(
            worker.gaps(),
            &[DeliveryGap {
                generation: 1,
                segment: worker.state.source.clone(),
                start: bad_start,
                end: Some(bad_start + lines[bad].len() as u64),
                reason: GapReason::ReceiverRejected,
            }]
        );
        assert!(worker.blocked().is_empty());
        assert!(worker.state.journals[0].split_records.is_none());
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
        assert_eq!(sink.batches.last().unwrap().token.start(), acknowledged);
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
            assert_ne!(sink.batches[0].token.generation(), old_generation);
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
        assert_ne!(
            sink.batches.last().unwrap().token.generation(),
            old_generation
        );
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
        assert_eq!(
            classify_local_failure(&error),
            LocalDeliveryFailure::StateOverLimit
        );
    }

    #[test]
    fn local_failures_distinguish_descriptor_exhaustion_from_other_io() {
        #[cfg(unix)]
        for errno in [libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                classify_local_failure(&io::Error::from_raw_os_error(errno)),
                LocalDeliveryFailure::TooManyOpenFiles
            );
        }
        for error in [
            io::Error::from(io::ErrorKind::PermissionDenied),
            invalid("corrupt delivery cursor"),
        ] {
            assert_eq!(classify_local_failure(&error), LocalDeliveryFailure::Io);
        }
    }

    #[test]
    fn backlog_reports_undelivered_extent_oldest_record_time_and_gaps() {
        fn first_wall_time(path: &Path) -> u64 {
            let bytes = fs::read(path).unwrap();
            let line = bytes.split(|byte| *byte == b'\n').next().unwrap();
            serde_json::from_slice::<serde_json::Value>(line).unwrap()["wall_time_ms"]
                .as_u64()
                .unwrap()
        }
        let (_dir, active, state_dir, recorder) = setup();
        record(&recorder, "sealed");
        let stem = active.file_stem().unwrap().to_str().unwrap().to_owned();
        let sealed = active.with_file_name(format!("{stem}-seg000001.jsonl"));
        drop(recorder);
        fs::rename(&active, &sealed).unwrap();
        let recorder = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
        record(&recorder, "active");
        let sealed_len = fs::metadata(&sealed).unwrap().len();
        let active_len = fs::metadata(&active).unwrap().len();

        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        assert_eq!(
            worker.backlog(),
            DeliveryBacklog {
                undelivered_bytes: sealed_len + active_len,
                undelivered_segments: 2,
                gaps: 0,
                oldest_undelivered_wall_time_ms: Some(first_wall_time(&sealed)),
            }
        );
        let mut sink = FakeReceiver::default();
        assert_eq!(worker.run_once(&mut sink).unwrap(), DeliveryStep::Accepted);
        assert_eq!(
            worker.backlog(),
            DeliveryBacklog {
                undelivered_bytes: active_len,
                undelivered_segments: 1,
                gaps: 0,
                oldest_undelivered_wall_time_ms: Some(first_wall_time(&active)),
            }
        );
        drain(&mut worker, &mut sink);
        assert_eq!(worker.backlog(), DeliveryBacklog::default());

        // An undelivered source that disappears is a gap, not backlog.
        record(&recorder, "lost");
        prepared_batch(&mut worker);
        drop(recorder);
        let lost = active.with_file_name(format!("{stem}-seg000002.jsonl"));
        fs::rename(&active, &lost).unwrap();
        let _recorder = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
        fs::remove_file(&lost).unwrap();
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Gap)
        );
        // The reopened recorder's first rows are the only backlog left.
        assert_eq!(
            worker.backlog(),
            DeliveryBacklog {
                undelivered_bytes: fs::metadata(&active).unwrap().len(),
                undelivered_segments: 1,
                gaps: 1,
                oldest_undelivered_wall_time_ms: Some(first_wall_time(&active)),
            }
        );
    }
    #[test]
    fn acknowledged_daily_file_expiry_keeps_cursor_bounded_without_replays_or_false_gaps() {
        let (dir, active, state_dir, mut recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        for index in 0..1000 {
            let sealed = dir
                .path()
                .join(format!("audit-engine-abc-v4-seg{index:06}.jsonl"));
            // The recorder is not used while the test simulates its atomic
            // daily rename. Reopen restores the actual writer for each turn.
            drop(recorder);
            fs::rename(&active, &sealed).unwrap();
            let next = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
            drain(&mut worker, &mut sink);
            let batches_before = sink.batches.len();
            fs::remove_file(&sealed).unwrap();
            drain(&mut worker, &mut sink);
            assert_eq!(sink.batches.len(), batches_before);
            assert!(worker.gaps().is_empty());
            assert_eq!(worker.state.journals.len(), 1);
            assert!(
                fs::metadata(state_dir.join("local-delivery.json"))
                    .unwrap()
                    .len()
                    < 4096
            );
            // Keep one recorder binding across iterations without leaving an
            // old descriptor alive during the next rename.
            recorder = next;
        }
    }
    #[test]
    fn retention_retires_fully_acknowledged_active_file_without_false_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        drop(recorder);
        assert!(
            crate::NoopRecorder
                .expire_file_before(&active, u64::MAX, &mut |p| retention::expire_closed_source(
                    p, &state_dir
                ))
                .unwrap()
        );
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Idle)
        );
        assert!(worker.gaps().is_empty());
        assert!(worker.state.journals.is_empty());
    }

    #[test]
    fn retention_preserves_unobserved_and_prepared_unsent_tail_evidence() {
        for prepare_tail in [false, true] {
            let (_dir, active, state_dir, recorder) = setup();
            let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
            drain(&mut worker, &mut FakeReceiver::default());
            let acknowledged = worker.state.journals[0].acknowledged;
            record(&recorder, "not-yet-uploaded");
            let final_len = fs::metadata(&active).unwrap().len();
            if prepare_tail {
                let _ = prepared_batch(&mut worker);
            }
            drop(recorder);
            assert!(
                crate::NoopRecorder
                    .expire_file_before(
                        &active,
                        u64::MAX,
                        &mut |p| retention::expire_closed_source(p, &state_dir)
                    )
                    .unwrap()
            );
            assert_eq!(
                worker.prepare_once().unwrap(),
                Preparation::Step(DeliveryStep::Gap)
            );
            assert_eq!(worker.gaps()[0].reason, GapReason::MissingSource);
            assert_eq!(worker.gaps()[0].start, acknowledged);
            assert_eq!(worker.state.journals[0].observed_len, final_len);
        }
    }

    #[test]
    fn retention_reconciles_a_roll_the_cursor_has_not_observed() {
        let (dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        drop(recorder);
        let sealed = dir.path().join("audit-engine-abc-v4-seg000003.jsonl");
        fs::rename(&active, &sealed).unwrap();
        let _new = JsonlRecorder::open(&active, "engine-abc".into()).unwrap();
        assert!(
            crate::NoopRecorder
                .expire_file_before(&sealed, u64::MAX, &mut |p| retention::expire_closed_source(
                    p, &state_dir
                ))
                .unwrap()
        );
        let before = sink.batches.len();
        drain(&mut worker, &mut sink);
        assert!(worker.gaps().is_empty());
        assert_eq!(sink.batches.len(), before + 1); // Only the new active session.
    }

    #[test]
    fn retention_compensates_cursor_and_rename_when_publication_or_unlink_fails() {
        for fail_publication in [false, true] {
            let (dir, active, state_dir, recorder) = setup();
            let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
            drain(&mut worker, &mut FakeReceiver::default());
            drop(recorder);
            let bytes = fs::read(&active).unwrap();
            let state_before = fs::read(state_dir.join("local-delivery.json")).unwrap();
            let result = retention::expire_with(
                &active,
                &state_dir,
                |_| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                |delivery| {
                    delivery.publish()?;
                    if fail_publication {
                        Err(io::Error::other("injected post-commit failure"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(fs::read(&active).unwrap(), bytes);
            assert_eq!(
                fs::read(state_dir.join("local-delivery.json")).unwrap(),
                state_before
            );
            assert_eq!(source_paths(&active).unwrap().len(), 1);
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
            assert!(
                crate::NoopRecorder
                    .expire_file_before(
                        &active,
                        u64::MAX,
                        &mut |p| retention::expire_closed_source(p, &state_dir)
                    )
                    .unwrap()
            );
            assert_eq!(
                worker.prepare_once().unwrap(),
                Preparation::Step(DeliveryStep::Idle)
            );
            assert!(worker.gaps().is_empty());
        }
    }

    #[test]
    fn retention_crash_after_cursor_publication_retries_sealed_inode_without_false_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        drop(recorder);
        let bytes = fs::read(&active).unwrap();
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = retention::expire_with(
                &active,
                &state_dir,
                |_| panic!("simulated process stop before unlink"),
                |delivery| delivery.publish(),
            );
        }));
        assert!(interrupted.is_err());
        assert!(!active.exists());
        let sealed = source_paths(&active).unwrap().pop().unwrap();
        assert_eq!(fs::read(&sealed).unwrap(), bytes);
        assert!(
            crate::NoopRecorder
                .expire_file_before(&sealed, u64::MAX, &mut |p| retention::expire_closed_source(
                    p, &state_dir
                ))
                .unwrap()
        );
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Idle)
        );
        assert!(worker.gaps().is_empty());
    }

    #[test]
    fn retention_failed_compensation_preserves_the_sealed_source_for_retry() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        drain(&mut worker, &mut FakeReceiver::default());
        drop(recorder);
        let bytes = fs::read(&active).unwrap();
        let result = retention::expire_with(
            &active,
            &state_dir,
            |_| panic!("unlink must not run"),
            |delivery| {
                delivery.publish()?;
                fs::create_dir(delivery.state_path.with_extension("json.tmp"))?;
                Err(io::Error::other("injected publication uncertainty"))
            },
        );
        assert!(result.is_err());
        assert!(!active.exists());
        let sealed = source_paths(&active).unwrap().pop().unwrap();
        assert_eq!(fs::read(&sealed).unwrap(), bytes);
        fs::remove_dir(state_dir.join("local-delivery.json.tmp")).unwrap();
        assert!(
            crate::NoopRecorder
                .expire_file_before(&sealed, u64::MAX, &mut |p| retention::expire_closed_source(
                    p, &state_dir
                ))
                .unwrap()
        );
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Idle)
        );
        assert!(worker.gaps().is_empty());
    }
    #[test]
    fn retention_expires_idle_live_data_and_keeps_recording_without_false_gap() {
        let (_dir, active, state_dir, recorder) = setup();
        let mut worker = LocalAuditDelivery::open(&active, &state_dir, "receiver-A").unwrap();
        let mut sink = FakeReceiver::default();
        drain(&mut worker, &mut sink);
        let before = fs::read(&active).unwrap();
        let health = recorder.health_snapshot();
        assert!(
            recorder
                .expire_file_before(&active, u64::MAX, &mut |closed| {
                    assert_eq!(fs::read(closed).unwrap(), before);
                    assert!(fs::read(&active).unwrap().is_empty());
                    retention::expire_closed_source(closed, &state_dir)
                })
                .unwrap()
        );
        assert_eq!(recorder.health_snapshot(), health);
        assert_eq!(
            worker.prepare_once().unwrap(),
            Preparation::Step(DeliveryStep::Idle)
        );
        assert!(worker.gaps().is_empty());
        let count = sink.batches.len();
        record(&recorder, "after-expiry");
        drain(&mut worker, &mut sink);
        assert_eq!(sink.batches.len(), count + 1);
        assert!(worker.gaps().is_empty());
    }
}
