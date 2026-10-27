//! Incident-only local capture. Never sent to tracing, telemetry or audit upload.
//!
//! JSONL v1: process nonce, sequence, monotonic elapsed_ms, closed kind, ephemeral
//! owner/operation (zero means unknown), and eight numeric values. Fixed meanings:
//! selected: [0 (head sequence unavailable), admission_correlation_unknown]; admission_duplicate: [original_operation];
//! engine_entry: [recorder_token, send_entry_ordinal, recorder_call_ordinal];
//! recorder_open: [recorder_token, entries_before_capture_registration]; worker_state: [pending, commands, flags,
//! retry_remaining_ms, convergence_remaining_ms, convergence_count, worker_generation]; flags bits:
//! due=0, owed=1, avatar=2, presentation=3, attachment=4, stopping=5, overdue=6.
//! branch_begin/end: [branch, duration_ms]; branch codes: command=1, convergence=2,
//! receive=3, avatar=4, presentation=5, attachment=6, maintenance=7, media=8,
//! replay_admission=9, generic_loop=10, comparison=11, welcome_completion=12,
//! select_wait_or_poll=13, local_submission_service=14. worker_start: [worker_generation]. command: [kind], where
//! catch_up=1, repair=2, direct_send=3, convergence_retry=4, drain=5,
//! connectivity=6, read=7, media=8, other=9. Other end/completion events: [success]. Unknown depth is
//! intentionally omitted: recording never adds a database read to the worker.
//! branch_counts contains cumulative counts for branches 1 through 8. Branch
//! timings/state/command samples are capped at 4Hz per owner/category; counts
//! cover every attempted branch unless capture loss is reported. No absence
//! inference is valid between samples. Engine entry ordinals count callbacks,
//! not durable audit rows; recorder_call_ordinal is NOT the v5 sequence. Cross-audit
//! joins require a complete recorder session and zero recorder capture loss.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use marmot_forensics::{
    AuditEventKind, AuditRecord, AuditRecorderHealthSnapshot, ForensicRecorder,
};
use rand::RngCore;
use serde::Serialize;

const SEGMENT_BYTES: usize = 256 * 1024;
const SEGMENTS: usize = 4;
const CAPACITY: usize = 1024;
const OWNER_LIMIT: usize = 64;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    AdmissionBegin,
    WorkerAcquired,
    GateWait,
    GateAcquired,
    AdmissionCommitted,
    AdmissionFailed,
    AdmissionDuplicate,
    SelectionAttempt,
    GateBusy,
    StorageError,
    QueueError,
    QueueEmpty,
    Selected,
    ExecutionBegin,
    ExecutionEnd,
    Completion,
    PreEngineSyncBegin,
    PreEngineSyncEnd,
    RuntimeSendBegin,
    RuntimeSendEnd,
    EngineEntry,
    EngineOutcome,
    WorkerStart,
    Command,
    WorkerState,
    BranchCounts,
    BranchBegin,
    BranchEnd,
    RecorderOpen,
}

#[derive(Serialize)]
struct Row {
    schema: u8,
    process: String,
    seq: u64,
    elapsed_ms: u64,
    kind: Kind,
    owner: u64,
    operation: u64,
    values: [u64; 8],
}

#[derive(Default)]
struct Counts {
    dropped: AtomicU64,
    write_failures: AtomicU64,
    running: AtomicBool,
    external_loss: Arc<AtomicU64>,
    live: Mutex<Live>,
    started_unix_ms: u64,
    start: Option<Instant>,
}
// Fixed numeric snapshots contain no private lookup keys. Producers only try_lock.
#[derive(Default, Clone)]
struct Live {
    sequence: u64,
    elapsed_ms: u64,
    owners: HashMap<u64, [u64; 16]>,
    operations: HashMap<u64, [u64; 20]>,
}
impl Live {
    fn observe(
        &mut self,
        kind: Kind,
        owner: u64,
        operation: u64,
        v: [u64; 8],
        elapsed: u64,
    ) -> bool {
        self.sequence = self.sequence.saturating_add(1);
        self.elapsed_ms = elapsed;
        if owner != 0 {
            if self.owners.len() >= OWNER_LIMIT && !self.owners.contains_key(&owner) {
                return false;
            }
            let o = self.owners.entry(owner).or_default();
            o[0] = owner;
            o[6] = elapsed;
            match kind {
                Kind::WorkerStart => o[1] = v[0],
                Kind::WorkerState => {
                    o[1] = v[6];
                    o[7..15].copy_from_slice(&v);
                }
                Kind::Command => o[5] = v[0],
                _ => {}
            }
        }
        if operation == 0 {
            return true;
        }
        if !self.operations.contains_key(&operation) && self.operations.len() >= 256 {
            let terminal = self
                .operations
                .iter()
                .filter(|(_, o)| o[2] >> 63 != 0)
                .min_by_key(|(_, o)| o[3])
                .map(|(id, _)| *id);
            if let Some(id) = terminal {
                self.operations.remove(&id);
            } else {
                return false;
            }
        }
        let o = self.operations.entry(operation).or_default();
        o[0] = operation;
        if owner != 0 {
            o[1] = owner;
        }
        o[3] = elapsed;
        let milestone = match kind {
            Kind::AdmissionBegin => Some(4),
            Kind::WorkerAcquired => Some(5),
            Kind::GateWait => Some(6),
            Kind::GateAcquired => Some(7),
            Kind::AdmissionCommitted => Some(8),
            Kind::Selected => Some(9),
            Kind::ExecutionBegin => Some(10),
            Kind::PreEngineSyncBegin => Some(11),
            Kind::PreEngineSyncEnd => Some(12),
            Kind::RuntimeSendBegin => Some(13),
            Kind::RuntimeSendEnd => Some(14),
            Kind::EngineEntry => Some(15),
            Kind::ExecutionEnd => Some(16),
            Kind::Completion => Some(17),
            _ => None,
        };
        if let Some(index) = milestone {
            let bit = 1 << (index - 4);
            if o[2] & bit == 0 {
                o[index] = elapsed;
                o[2] |= bit;
            }
        }
        if matches!(kind, Kind::AdmissionFailed | Kind::AdmissionDuplicate)
            || (matches!(kind, Kind::Completion) && v[0] == 1)
        {
            o[2] |= 1 << 63;
        }
        if matches!(kind, Kind::EngineEntry) && o[18] == 0 {
            o[18] = v[0];
            o[19] = v[1];
        }
        true
    }
}
struct Session {
    process: String,
    start: Instant,
    tx: mpsc::SyncSender<Row>,
    counts: Arc<Counts>,
    writer: Option<std::thread::JoinHandle<()>>,
}
#[derive(Default)]
struct State {
    session: Option<Session>,
    // Private keys deliberately have no Serialize/Debug implementation.
    owners: HashMap<String, u64>,
    operations: HashMap<(u64, String), u64>,
    sampled: HashMap<(u64, u8), Instant>,
    branch_counts: HashMap<u64, [u64; 8]>,
}

/// One root-owned capture; disabled instances do no I/O and spawn no threads.
pub(crate) struct Trace {
    directory: PathBuf,
    next: AtomicU64,
    sequence: AtomicU64,
    state: Mutex<State>,
    control: Mutex<()>,
    configured: AtomicBool,
    lost_lock: Arc<AtomicU64>,
}
impl Trace {
    pub(crate) fn new(root: &Path) -> Self {
        Self {
            directory: root.join("local-send-trace"),
            next: AtomicU64::new(1),
            sequence: AtomicU64::new(1),
            state: Mutex::default(),
            control: Mutex::default(),
            lost_lock: Arc::new(AtomicU64::new(0)),
            configured: AtomicBool::new(false),
        }
    }
    pub(crate) fn token(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
    /// Called only at consent/open/close boundaries, never in worker selection.
    pub(crate) fn enable(&self, enabled: bool) {
        let _control = self.control.lock().unwrap_or_else(|e| e.into_inner());
        self.configured.store(true, Ordering::Release);
        self.set_enabled(enabled);
    }
    fn initialize(&self) {
        let _control = self.control.lock().unwrap_or_else(|e| e.into_inner());
        if !self.configured.swap(true, Ordering::AcqRel) {
            self.set_enabled(true);
        }
    }
    fn set_enabled(&self, enabled: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if enabled && state.session.is_some() {
            return;
        }
        let previous = state.session.take();
        state.owners.clear();
        state.operations.clear();
        state.sampled.clear();
        state.branch_counts.clear();
        drop(state);
        if let Some(mut previous) = previous {
            previous.counts.running.store(false, Ordering::Release);
            drop(previous.tx);
            if let Some(writer) = previous.writer.take() {
                let _ = writer.join();
            }
        }
        if !enabled {
            return;
        }
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let process = hex::encode(nonce);
        let (tx, rx) = mpsc::sync_channel(CAPACITY);
        self.lost_lock.store(0, Ordering::Relaxed);
        let start = Instant::now();
        let started_unix_ms = millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        );
        let counts = Arc::new(Counts {
            external_loss: self.lost_lock.clone(),
            started_unix_ms,
            start: Some(start),
            ..Default::default()
        });
        counts.running.store(true, Ordering::Release);
        let directory = self.directory.clone();
        let writer_counts = counts.clone();
        let writer_process = process.clone();
        let writer = std::thread::Builder::new()
            .name("send-trace".into())
            .spawn(move || {
                if write_loop(&directory, &writer_process, &writer_counts, rx).is_err() {
                    writer_counts.write_failures.fetch_add(1, Ordering::Relaxed);
                    writer_counts.running.store(false, Ordering::Release);
                }
            });
        if let Ok(writer) = writer {
            self.state.lock().unwrap_or_else(|e| e.into_inner()).session = Some(Session {
                process,
                start,
                tx,
                counts,
                writer: Some(writer),
            });
        }
    }
    pub(crate) fn owner(&self, private_key: &str) -> u64 {
        let Ok(mut s) = self.state.try_lock() else {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        if s.session.is_none() {
            return 0;
        }
        if let Some(id) = s.owners.get(private_key) {
            return *id;
        }
        if s.owners.len() >= OWNER_LIMIT {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        let id = self.token();
        s.owners.insert(private_key.to_owned(), id);
        id
    }
    /// Register/retrieve an opaque token. Never evict a live correlation into a false join.
    pub(crate) fn operation(&self, owner: u64, private_key: &str, proposed: u64) -> u64 {
        if owner == 0 {
            return 0;
        }
        let Ok(mut s) = self.state.try_lock() else {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return 0;
        };
        if s.session.is_none() {
            return 0;
        }
        let key = (owner, private_key.to_owned());
        if let Some(id) = s.operations.get(&key) {
            return *id;
        }
        if proposed == 0 {
            return 0;
        }
        if s.operations.len() >= CAPACITY {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return 0;
        }
        s.operations.insert(key, proposed);
        proposed
    }
    pub(crate) fn emit(&self, kind: Kind, owner: u64, operation: u64, values: [u64; 8]) {
        let Ok(s) = self.state.try_lock() else {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(session) = &s.session else {
            return;
        };
        if !session.counts.running.load(Ordering::Acquire) {
            return;
        }
        let row = Row {
            schema: 1,
            process: session.process.clone(),
            seq: self.sequence.fetch_add(1, Ordering::Relaxed),
            elapsed_ms: millis(session.start.elapsed()),
            kind,
            owner,
            operation,
            values,
        };
        Self::observe_live(session, kind, owner, operation, values, row.elapsed_ms);
        if session.tx.try_send(row).is_err() {
            session.counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn observe_live(
        session: &Session,
        kind: Kind,
        owner: u64,
        operation: u64,
        values: [u64; 8],
        elapsed: u64,
    ) {
        let updated = session
            .counts
            .live
            .try_lock()
            .ok()
            .is_some_and(|mut live| live.observe(kind, owner, operation, values, elapsed));
        if !updated {
            session.counts.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn live_only(&self, kind: Kind, owner: u64, values: [u64; 8]) {
        if let Ok(s) = self.state.try_lock() {
            if let Some(session) = &s.session {
                Self::observe_live(
                    session,
                    kind,
                    owner,
                    0,
                    values,
                    millis(session.start.elapsed()),
                );
            }
        } else {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn phase(
        &self,
        owner: u64,
        phase: u64,
        token: u64,
        restore: Option<[u64; 3]>,
    ) -> Option<[u64; 3]> {
        if owner == 0 {
            return None;
        }
        let Ok(s) = self.state.try_lock() else {
            self.lost_lock.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let session = s.session.as_ref()?;
        let Ok(mut live) = session.counts.live.try_lock() else {
            session.counts.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if restore.is_some() && !live.owners.contains_key(&owner) {
            return None;
        }
        let elapsed = millis(session.start.elapsed());
        if !live.observe(Kind::BranchBegin, owner, 0, [0; 8], elapsed) {
            session.counts.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let o = live.owners.get_mut(&owner)?;
        let previous = [o[2], o[3], o[4]];
        if let Some(restore) = restore {
            if o[4] == token {
                o[2..5].copy_from_slice(&restore);
            }
        } else {
            if phase == 1 {
                o[5] = 0;
            }
            o[2] = phase;
            o[3] = elapsed;
            o[4] = token;
            o[15] = o[15].saturating_add(1);
        }
        Some(previous)
    }
    fn sample(&self, owner: u64, category: u8) -> bool {
        let Ok(mut s) = self.state.try_lock() else {
            return false;
        };
        if s.session.is_none() || owner == 0 {
            return false;
        }
        let now = Instant::now();
        let last = s
            .sampled
            .entry((owner, category))
            .or_insert(now - Duration::from_secs(1));
        if now.duration_since(*last) < Duration::from_millis(250) {
            return false;
        }
        *last = now;
        true
    }
    pub(crate) fn worker_state(&self, owner: u64, values: [u64; 8]) {
        self.live_only(Kind::WorkerState, owner, values);
        if self.sample(owner, 0) {
            self.emit(Kind::WorkerState, owner, 0, values);
            let counts = self
                .state
                .try_lock()
                .ok()
                .and_then(|s| s.branch_counts.get(&owner).copied());
            if let Some(counts) = counts {
                self.emit(Kind::BranchCounts, owner, 0, counts);
            }
        }
    }
    pub(crate) fn branch(self: &Arc<Self>, owner: u64, branch: u64) -> Branch {
        if owner != 0 {
            if let Ok(mut state) = self.state.try_lock() {
                if state.session.is_some() && (1..=8).contains(&branch) {
                    let counts = state.branch_counts.entry(owner).or_default();
                    counts[branch as usize - 1] = counts[branch as usize - 1].saturating_add(1);
                }
            } else {
                self.lost_lock.fetch_add(1, Ordering::Relaxed);
            }
        }
        let phase_token = self.token();
        let previous = self.phase(owner, branch, phase_token, None);
        let recorded = self.sample(owner, branch as u8);
        if recorded {
            self.emit(Kind::BranchBegin, owner, 0, values(branch));
        }
        Branch {
            trace: self.clone(),
            owner,
            branch,
            start: Instant::now(),
            recorded,
            phase_token,
            previous,
        }
    }
    pub(crate) fn command(&self, owner: u64, kind: u64) {
        self.live_only(Kind::Command, owner, values(kind));
        if self.sample(owner, 16 + kind as u8) {
            self.emit(Kind::Command, owner, 0, values(kind));
        }
    }
    pub(crate) fn decorate(
        self: &Arc<Self>,
        owner_key: &str,
        inner: Box<dyn ForensicRecorder>,
    ) -> Box<dyn ForensicRecorder> {
        self.initialize();
        let owner = self.owner(owner_key);
        let recorder = self.token();
        self.emit(Kind::RecorderOpen, owner, 0, values(recorder));
        Box::new(Recorder {
            trace: self.clone(),
            owner_key: owner_key.to_owned(),
            last_owner: AtomicU64::new(owner),
            recorder,
            entries: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            inner,
        })
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        self.enable(false);
    }
}

pub(crate) struct Branch {
    trace: Arc<Trace>,
    owner: u64,
    branch: u64,
    start: Instant,
    recorded: bool,
    phase_token: u64,
    previous: Option<[u64; 3]>,
}
impl Drop for Branch {
    fn drop(&mut self) {
        if let Some(previous) = self.previous {
            self.trace
                .phase(self.owner, self.branch, self.phase_token, Some(previous));
        }
        if self.recorded {
            let mut v = values(self.branch);
            v[1] = millis(self.start.elapsed());
            self.trace.emit(Kind::BranchEnd, self.owner, 0, v);
        }
    }
}
pub(crate) fn values(first: u64) -> [u64; 8] {
    [first, 0, 0, 0, 0, 0, 0, 0]
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

struct Recorder {
    trace: Arc<Trace>,
    owner_key: String,
    last_owner: AtomicU64,
    recorder: u64,
    entries: AtomicU64,
    calls: AtomicU64,
    inner: Box<dyn ForensicRecorder>,
}
impl ForensicRecorder for Recorder {
    fn record(&self, record: AuditRecord) {
        let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = matches!(record.kind, AuditEventKind::SendEntry { .. });
        let outcome = matches!(
            record.kind,
            AuditEventKind::SendOutcome { .. } | AuditEventKind::SendError { .. }
        );
        if entry || outcome {
            let owner = self.trace.owner(&self.owner_key);
            if owner != 0 && self.last_owner.swap(owner, Ordering::Relaxed) != owner {
                self.trace.emit(
                    Kind::RecorderOpen,
                    owner,
                    0,
                    [
                        self.recorder,
                        self.entries.load(Ordering::Relaxed),
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                    ],
                );
            }
            let op = record
                .context
                .as_ref()
                .and_then(|c| c.operation_id.as_deref())
                .map(|key| self.trace.operation(owner, key, 0))
                .unwrap_or(0);
            let ordinal = if entry {
                self.entries.fetch_add(1, Ordering::Relaxed) + 1
            } else {
                self.entries.load(Ordering::Relaxed)
            };
            self.trace.emit(
                if entry {
                    Kind::EngineEntry
                } else {
                    Kind::EngineOutcome
                },
                owner,
                op,
                [self.recorder, ordinal, call, 0, 0, 0, 0, 0],
            );
        }
        self.inner.record(record);
    }
    fn record_v5_event(
        &self,
        group: Option<marmot_forensics::v5::GroupRef>,
        event: marmot_forensics::v5::Event,
    ) {
        self.inner.record_v5_event(group, event);
    }
    fn finish_v5_recording(&self, reason: marmot_forensics::v5::RecordingStopReason) {
        self.inner.finish_v5_recording(reason);
    }
    fn records_v5(&self) -> bool {
        self.inner.records_v5()
    }
    fn is_enabled(&self) -> bool {
        self.inner.is_enabled()
    }
    fn health_snapshot(&self) -> AuditRecorderHealthSnapshot {
        self.inner.health_snapshot()
    }
    fn audit_log_path(&self) -> Option<PathBuf> {
        self.inner.audit_log_path()
    }
    fn rotate(&self) -> io::Result<()> {
        self.inner.rotate()
    }
}

fn safe_replace(path: &Path) -> io::Result<File> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonregular diagnostic artifact",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs_private::create_new_private(path)
}
#[derive(Serialize)]
struct Manifest<'a> {
    schema: u8,
    process: &'a str,
    started_unix_ms: u64,
    dropped: u64,
    write_failures: u64,
    rotations: u64,
    active_segment: usize,
    recording: bool,
    last_written_seq: u64,
    first_written_seq: u64,
    clear_count: u64,
    sample_period_ms: u64,
    live_snapshot_seq: u64,
    live_snapshot_elapsed_ms: u64,
    owners: Vec<[u64; 16]>,
    operations: Vec<[u64; 20]>,
}
fn write_loop(
    directory: &Path,
    process: &str,
    counts: &Counts,
    rx: mpsc::Receiver<Row>,
) -> io::Result<()> {
    if let Ok(m) = fs::symlink_metadata(directory)
        && !m.file_type().is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-directory diagnostic artifact",
        ));
    }
    fs_private::create_dir_all_private(directory)?;
    // Fresh capture invalidates old bounded files, rather than mixing nonce generations.
    for n in 0..SEGMENTS {
        let path = directory.join(format!("segment-{n}.jsonl"));
        if path.exists() {
            drop(safe_replace(&path)?);
        }
    }
    let mut segment = 0;
    let mut rotations = 0;
    let mut size = 0;
    let mut last = 0;
    let mut first = 0;
    let mut clear_count = 0;
    let mut file = safe_replace(&directory.join("segment-0.jsonl"))?;
    let mut last_manifest = Instant::now() - Duration::from_secs(1);
    loop {
        let row = if counts.running.load(Ordering::Acquire) {
            rx.recv_timeout(Duration::from_millis(250)).ok()
        } else {
            None
        };
        // Android's explicit clear removes only this allowlisted sidecar. Never
        // keep writing an unlinked inode or replay pre-clear queued records.
        let current_path = directory.join(format!("segment-{segment}.jsonl"));
        if replaced(&file, &current_path)? {
            clear_count += 1;
            *counts.live.lock().unwrap_or_else(|e| e.into_inner()) = Live::default();
            if row.is_some() {
                counts.dropped.fetch_add(1, Ordering::Relaxed);
            }
            while rx.try_recv().is_ok() {
                counts.dropped.fetch_add(1, Ordering::Relaxed);
            }
            file = safe_replace(&current_path)?;
            size = 0;
            last_manifest = Instant::now() - Duration::from_secs(1);
            continue;
        }
        if let Some(row) = row {
            if !counts.running.load(Ordering::Acquire) {
                counts.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut bytes = serde_json::to_vec(&row)?;
            bytes.push(b'\n');
            if bytes.len() > 512 {
                counts.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if size + bytes.len() > SEGMENT_BYTES {
                file.flush()?;
                segment = (segment + 1) % SEGMENTS;
                rotations += 1;
                file = safe_replace(&directory.join(format!("segment-{segment}.jsonl")))?;
                size = 0;
            }
            file.write_all(&bytes)?;
            size += bytes.len();
            last = row.seq;
            if first == 0 {
                first = row.seq;
            }
        }
        let recording = counts.running.load(Ordering::Acquire);
        if !recording {
            while rx.try_recv().is_ok() {
                counts.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if !recording || last_manifest.elapsed() >= Duration::from_millis(250) {
            file.flush()?;
            let live = counts
                .live
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            let manifest = Manifest {
                schema: 1,
                process,
                started_unix_ms: counts.started_unix_ms,
                dropped: counts
                    .dropped
                    .load(Ordering::Relaxed)
                    .saturating_add(counts.external_loss.load(Ordering::Relaxed)),
                write_failures: counts.write_failures.load(Ordering::Relaxed),
                rotations,
                active_segment: segment,
                recording,
                last_written_seq: last,
                first_written_seq: first,
                clear_count,
                sample_period_ms: 250,
                live_snapshot_seq: live.sequence,
                live_snapshot_elapsed_ms: counts
                    .start
                    .map(|start| millis(start.elapsed()))
                    .unwrap_or(live.elapsed_ms),
                owners: live.owners.into_values().collect(),
                operations: live.operations.into_values().collect(),
            };
            let bytes = serde_json::to_vec(&manifest)?;
            if bytes.len() > SEGMENT_BYTES {
                return Err(io::Error::other("diagnostic snapshot exceeds bound"));
            }
            let temporary = directory.join("manifest.tmp");
            let mut output = safe_replace(&temporary)?;
            output.write_all(&bytes)?;
            output.flush()?;
            drop(output);
            fs::rename(temporary, directory.join("manifest.json"))?;
            last_manifest = Instant::now();
        }
        if !recording {
            break;
        }
    }
    Ok(())
}

fn replaced(file: &File, path: &Path) -> io::Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nonregular diagnostic artifact",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        Ok(opened.ino() != metadata.ino() || opened.dev() != metadata.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = (file, metadata);
        Ok(false)
    }
}

#[cfg(test)]
mod tests;
