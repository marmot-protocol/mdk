//! One recorder handle for every owner of an account-device's audit log.

use std::path::PathBuf;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};

use super::{AuditRecord, AuditRecorderHealthSnapshot, ForensicRecorder, NoopRecorder};

/// A cloneable [`ForensicRecorder`] that delegates to one swappable inner
/// recorder.
///
/// The engine, the account runtime and the app each hold a clone, so their
/// rows share one writer, one recording session and one sequence. Two separate
/// recorders on the same file would split that sequence.
///
/// The file's lifetime is explicit rather than tied to whichever clone is
/// dropped last. [`swap`](Self::swap) installs a new recorder for every clone
/// and drops the old one before it returns, and [`finish`](Self::finish) ends
/// the log the same way, so a clone that outlives shutdown writes nothing.
#[derive(Clone)]
pub struct SharedRecorder {
    inner: Arc<RwLock<Box<dyn ForensicRecorder>>>,
}

/// A registry reference that never extends a recorder's file lifetime.
#[derive(Clone)]
pub struct WeakRecorder(Weak<RwLock<Box<dyn ForensicRecorder>>>);

impl WeakRecorder {
    pub fn upgrade(&self) -> Option<SharedRecorder> {
        self.0.upgrade().map(|inner| SharedRecorder { inner })
    }
}

impl SharedRecorder {
    pub fn downgrade(&self) -> WeakRecorder {
        WeakRecorder(Arc::downgrade(&self.inner))
    }
    pub fn new(recorder: Box<dyn ForensicRecorder>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(recorder)),
        }
    }

    /// A handle that records nothing until a recorder is swapped in.
    pub fn disabled() -> Self {
        Self::new(Box::new(NoopRecorder))
    }

    /// Install `recorder` for every clone of this handle. The previous
    /// recorder is dropped before this returns, which flushes and closes any
    /// file it held.
    pub fn swap(&self, recorder: Box<dyn ForensicRecorder>) {
        let previous = std::mem::replace(&mut *self.write(), recorder);
        drop(previous);
    }

    /// End the audit log: write the clean-stop row, then swap in a
    /// [`NoopRecorder`], which closes the file. No row from any clone can land
    /// between the two, and every clone records nothing afterwards until a
    /// later [`swap`](Self::swap).
    pub fn finish(&self, reason: crate::v5::RecordingStopReason) {
        let previous = {
            let mut current = self.write();
            current.finish_v5_recording(reason);
            std::mem::replace(&mut *current, Box::new(NoopRecorder))
        };
        drop(previous);
    }

    // Poisoning means a recorder panicked while holding the lock. The boxed
    // recorder is still a whole value, and the audit log must never crash its
    // callers' hot paths, so recover and continue, as `JsonlRecorder` does.
    fn read(&self) -> RwLockReadGuard<'_, Box<dyn ForensicRecorder>> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, Box<dyn ForensicRecorder>> {
        self.inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for SharedRecorder {
    fn default() -> Self {
        Self::disabled()
    }
}

impl std::fmt::Debug for SharedRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedRecorder")
            .field("enabled", &self.is_enabled())
            .finish_non_exhaustive()
    }
}

impl ForensicRecorder for SharedRecorder {
    fn record(&self, record: AuditRecord) {
        self.read().record(record);
    }

    fn record_v5_event(&self, group_ref: Option<crate::v5::GroupRef>, event: crate::v5::Event) {
        self.read().record_v5_event(group_ref, event);
    }

    fn finish_v5_recording(&self, reason: crate::v5::RecordingStopReason) {
        self.read().finish_v5_recording(reason);
    }

    fn records_v5(&self) -> bool {
        self.read().records_v5()
    }

    fn is_enabled(&self) -> bool {
        self.read().is_enabled()
    }

    fn health_snapshot(&self) -> AuditRecorderHealthSnapshot {
        self.read().health_snapshot()
    }

    fn audit_log_path(&self) -> Option<PathBuf> {
        self.read().audit_log_path()
    }

    fn rotate(&self) -> std::io::Result<()> {
        self.read().rotate()
    }

    fn expire_file_before(&self, path: &std::path::Path, cutoff_ms: u64) -> std::io::Result<bool> {
        self.read().expire_file_before(path, cutoff_ms)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::{AuditEvent, AuditEventKind, JsonlRecorder};

    struct DropFlag {
        dropped: Arc<AtomicBool>,
        recorded: Arc<AtomicUsize>,
    }

    impl ForensicRecorder for DropFlag {
        fn record(&self, _record: AuditRecord) {
            self.recorded.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn health_row() -> AuditRecord {
        AuditRecord::new(
            None,
            AuditEventKind::RecorderHealth {
                serialization_failures: 0,
                write_failures: 0,
                flush_failures: 0,
            },
        )
    }

    fn producer() -> crate::v5::Producer {
        crate::v5::Producer {
            mdk_revision: None,
            build_profile: crate::v5::BuildProfile::Debug,
            platform: crate::v5::Platform::Other,
            host_build: None,
        }
    }

    fn rows(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn a_swap_closes_the_old_recorder_before_it_returns() {
        let dropped = Arc::new(AtomicBool::new(false));
        let recorded = Arc::new(AtomicUsize::new(0));
        let shared = SharedRecorder::new(Box::new(DropFlag {
            dropped: dropped.clone(),
            recorded: recorded.clone(),
        }));
        let clone = shared.clone();
        clone.record(health_row());
        assert_eq!(recorded.load(Ordering::SeqCst), 1);

        shared.swap(Box::new(NoopRecorder));
        assert!(
            dropped.load(Ordering::SeqCst),
            "a swap must close the old recorder before it returns, while clones still live"
        );
        clone.record(health_row());
        assert_eq!(recorded.load(Ordering::SeqCst), 1);
    }

    /// The engine holds its clone as a `Box<dyn ForensicRecorder>` and skips
    /// audit-only work when `is_enabled` is false, so the handle must not fall
    /// back to the trait's enabled default.
    #[test]
    fn a_disabled_handle_reads_as_disabled_through_the_engines_view() {
        let shared = SharedRecorder::disabled();
        let engine_view: Box<dyn ForensicRecorder> = Box::new(shared.clone());
        assert!(!engine_view.is_enabled());

        let recorded = Arc::new(AtomicUsize::new(0));
        shared.swap(Box::new(DropFlag {
            dropped: Arc::new(AtomicBool::new(false)),
            recorded: recorded.clone(),
        }));
        assert!(engine_view.is_enabled(), "a swap reaches every clone");
        engine_view.record(health_row());
        assert_eq!(recorded.load(Ordering::SeqCst), 1);

        shared.swap(Box::new(NoopRecorder));
        assert!(!engine_view.is_enabled());
    }

    #[test]
    fn clones_record_into_one_session_and_one_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-shared.jsonl");
        let shared = SharedRecorder::new(Box::new(
            JsonlRecorder::open(&path, "shared".into()).unwrap(),
        ));
        let engine = shared.clone();
        let app = shared.clone();
        for _ in 0..3 {
            engine.record(health_row());
            app.record(health_row());
        }
        drop((engine, app, shared));

        let events: Vec<AuditEvent> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let seqs: Vec<u64> = events.iter().map(|event| event.seq).collect();
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]), "{seqs:?}");
        let sessions: std::collections::BTreeSet<_> = events
            .iter()
            .map(|event| event.recorder_session_id.clone())
            .collect();
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn finish_writes_the_stop_row_last_and_silences_surviving_clones() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-shared-v5.jsonl");
        let shared = SharedRecorder::new(Box::new(
            JsonlRecorder::open_v5_with_account_ref(
                &path,
                "0123456789abcdef0123456789abcdef".into(),
                None,
                producer(),
            )
            .unwrap(),
        ));
        let surviving = shared.clone();
        surviving.record(health_row());

        shared.finish(crate::v5::RecordingStopReason::CleanRuntimeShutdown);
        assert!(
            !surviving.is_enabled(),
            "finish leaves every clone disabled"
        );
        assert_eq!(surviving.audit_log_path(), None, "finish closes the file");
        let finished = std::fs::read_to_string(&path).unwrap();

        surviving.record(health_row());
        surviving.record_v5_event(
            None,
            crate::v5::Event::RecordingSessionStopped(crate::v5::RecordingSessionStopped {
                reason: crate::v5::RecordingStopReason::CleanRuntimeShutdown,
            }),
        );
        drop(surviving);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            finished,
            "a clone that outlives finish writes nothing"
        );
        let rows = rows(&path);
        assert_eq!(
            rows.last().unwrap()["event"]["type"],
            "recording_session_stopped"
        );
    }
}
