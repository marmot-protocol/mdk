//! Opt-in, process-local native progress; this recorder never reads databases or keys.
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Fixed native boundaries. No identifiers, paths, arguments or error text are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStartupStage {
    AttachmentTaskQueued,
    AccountResolution,
    AccountStorageCache,
    StorageAdmission,
    DatabaseOpenLock,
    SigningKeys,
    ExternalDatabaseSecret,
    KeyDerivation,
    SaltRead,
    RecoveryProbe,
    RecoveryRekey,
    EncryptedStoreOpen,
    CipherConfiguration,
    CipherKeyApplication,
    OperationalPragmas,
    MigrationInspection,
    MigrationApply,
    AttachmentLocalRead,
    AttachmentFutureWait,
    ProductAnalyticsAdmission,
}
/// Scope outcomes distinguish active work from completed or unwound observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStartupOutcome {
    Active,
    Success,
    Failure,
    Abandoned,
}
/// One bounded, anonymous operation; token is process-local and not an account reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStartupObservation {
    pub token: u64,
    pub stage: NativeStartupStage,
    pub elapsed_ms: u64,
    pub stage_elapsed_ms: u64,
    pub migration_version: Option<u32>,
    pub migrations_completed: u32,
    pub outcome: NativeStartupOutcome,
}
/// Independent memory snapshot, available while native storage work is blocked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeStartupSnapshot {
    pub enabled: bool,
    pub active: Vec<NativeStartupObservation>,
    pub events: Vec<NativeStartupObservation>,
    pub dropped_events: u64,
    pub dropped_scopes: u64,
}
#[derive(Clone, Default)]
pub(crate) struct NativeStartupDiagnostics(Arc<Mutex<State>>);
#[derive(Default)]
struct State {
    enabled: bool,
    generation: u64,
    next_token: u64,
    active: Vec<Active>,
    events: VecDeque<NativeStartupObservation>,
    dropped_events: u64,
    dropped_scopes: u64,
}
struct Active {
    observation: NativeStartupObservation,
    started: Instant,
    stage_started: Instant,
    history: bool,
    pending_initial: Option<NativeStartupObservation>,
}
const MAX_ACTIVE: usize = 16;
const MAX_EVENTS: usize = 96;

impl NativeStartupDiagnostics {
    /// Reset or revoke only this diagnostic memory; no durable or upload consent is changed.
    pub(crate) fn set_enabled(&self, enabled: bool) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.enabled == enabled {
            return;
        }
        state.enabled = enabled;
        state.generation = state.generation.wrapping_add(1);
        state.active.clear();
        state.events.clear();
        state.dropped_events = 0;
        state.dropped_scopes = 0;
    }
    /// Start a scope before scheduling or potentially blocking native work.
    pub(crate) fn observe(&self, stage: NativeStartupStage) -> NativeStartupProbe {
        self.start_scope(stage, true)
    }
    /// Keep cache/admission waits visible in active memory without filling history on successful hits.
    pub(crate) fn observe_pending_open(&self, stage: NativeStartupStage) -> NativeStartupProbe {
        self.start_scope(stage, false)
    }
    /// Reserve bounded active state; pending opens retain their first phase until a miss or failure.
    fn start_scope(&self, stage: NativeStartupStage, history: bool) -> NativeStartupProbe {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.enabled {
            return NativeStartupProbe::default();
        }
        if state.active.len() == MAX_ACTIVE {
            state.dropped_scopes = state.dropped_scopes.saturating_add(1);
            return NativeStartupProbe::default();
        }
        state.next_token = state.next_token.wrapping_add(1);
        let token = state.next_token;
        let observation = NativeStartupObservation {
            token,
            stage,
            elapsed_ms: 0,
            stage_elapsed_ms: 0,
            migration_version: None,
            migrations_completed: 0,
            outcome: NativeStartupOutcome::Active,
        };
        let now = Instant::now();
        state.active.push(Active {
            observation: observation.clone(),
            started: now,
            stage_started: now,
            history,
            pending_initial: (!history).then(|| observation.clone()),
        });
        if history {
            state.event(observation);
        }
        NativeStartupProbe {
            owner: Some(self.clone()),
            token,
            generation: state.generation,
        }
    }
    /// Clone bounded memory under its own short lock, never under an account/storage lock.
    pub(crate) fn snapshot(&self) -> NativeStartupSnapshot {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        NativeStartupSnapshot {
            enabled: state.enabled,
            active: state.active.iter().map(Active::snapshot).collect(),
            events: state.events.iter().cloned().collect(),
            dropped_events: state.dropped_events,
            dropped_scopes: state.dropped_scopes,
        }
    }
}
impl State {
    /// Evict the oldest historical observation and count omissions at the fixed history limit.
    fn event(&mut self, observation: NativeStartupObservation) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
            self.dropped_events = self.dropped_events.saturating_add(1);
        }
        self.events.push_back(observation);
    }
}
impl Active {
    /// Refresh monotonic durations without changing the stored phase or operation identity.
    fn snapshot(&self) -> NativeStartupObservation {
        let mut value = self.observation.clone();
        value.elapsed_ms = self
            .started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        value.stage_elapsed_ms = self
            .stage_started
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        value
    }
}
/// Owned scopes remain observable across Rust task movement and retire on every unwind.
#[derive(Default)]
pub(crate) struct NativeStartupProbe {
    owner: Option<NativeStartupDiagnostics>,
    token: u64,
    generation: u64,
}
impl NativeStartupProbe {
    /// Commit a cache miss to history, including its initial admission and current cache-wait timing.
    pub(crate) fn record_history(&self) {
        let Some(owner) = &self.owner else {
            return;
        };
        let mut state = owner.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.enabled || state.generation != self.generation {
            return;
        }
        let Some(active) = state
            .active
            .iter_mut()
            .find(|a| a.observation.token == self.token && !a.history)
        else {
            return;
        };
        active.history = true;
        let initial = active.pending_initial.take();
        let observation = active.snapshot();
        if let Some(initial) = initial {
            state.event(initial);
        }
        state.event(observation);
    }

    /// Move to a non-migration phase, clearing the previous migration number and restarting its timer.
    pub(crate) fn phase(&self, stage: NativeStartupStage) {
        self.progress(stage, None, false);
    }
    /// Publish fixed progress only while this scope belongs to the enabled capture generation.
    /// `completed` counts a successful migration; failed migrations retain their version at retirement.
    pub(crate) fn progress(
        &self,
        stage: NativeStartupStage,
        version: Option<u32>,
        completed: bool,
    ) {
        let Some(owner) = &self.owner else {
            return;
        };
        let mut state = owner.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.enabled || state.generation != self.generation {
            return;
        }
        let Some(active) = state
            .active
            .iter_mut()
            .find(|a| a.observation.token == self.token)
        else {
            return;
        };
        active.observation.stage = stage;
        active.stage_started = Instant::now();
        active.observation.migration_version = version;
        if completed {
            active.observation.migrations_completed =
                active.observation.migrations_completed.saturating_add(1);
        }
        let observation = active.history.then(|| active.snapshot());
        if let Some(observation) = observation {
            state.event(observation);
        }
    }
    /// Consume the probe with an explicit result so its later drop cannot report abandonment.
    pub(crate) fn finish(mut self, success: bool) {
        self.retire(if success {
            NativeStartupOutcome::Success
        } else {
            NativeStartupOutcome::Failure
        });
    }
    /// Remove the active scope once; a revoked generation can never append to a newer capture.
    /// Successful cache hits stay silent; failures and unwinds still retain their terminal phase.
    fn retire(&mut self, outcome: NativeStartupOutcome) {
        let Some(owner) = self.owner.take() else {
            return;
        };
        let mut state = owner.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.generation != self.generation {
            return;
        }
        if let Some(index) = state
            .active
            .iter()
            .position(|a| a.observation.token == self.token)
        {
            let mut active = state.active.remove(index);
            if active.history || outcome != NativeStartupOutcome::Success {
                if let Some(initial) = active.pending_initial.take() {
                    state.event(initial);
                }
                let mut observation = active.snapshot();
                observation.outcome = outcome;
                state.event(observation);
            }
        }
    }
}
impl Drop for NativeStartupProbe {
    /// Retire cancellation or unwinding as abandoned without retaining the underlying error.
    fn drop(&mut self) {
        self.retire(NativeStartupOutcome::Abandoned);
    }
}

impl crate::MarmotApp {
    /// Enable/revoke native startup observations independently of upload consent. Disabled by default.
    pub fn set_startup_diagnostics_enabled(&self, enabled: bool) {
        self.startup_diagnostics.set_enabled(enabled);
    }
    /// Return bounded anonymous progress without opening storage or loading account secrets.
    pub fn startup_diagnostics_snapshot(&self) -> NativeStartupSnapshot {
        self.startup_diagnostics.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_and_revoked_scopes_cannot_leak_into_a_new_capture() {
        let recorder = NativeStartupDiagnostics::default();
        let disabled = recorder.observe(NativeStartupStage::SigningKeys);
        recorder.set_enabled(true);
        disabled.phase(NativeStartupStage::AttachmentLocalRead);
        let old = recorder.observe(NativeStartupStage::SigningKeys);
        let old_pending = recorder.observe_pending_open(NativeStartupStage::SigningKeys);
        recorder.set_enabled(false);
        recorder.set_enabled(true);
        old.phase(NativeStartupStage::RecoveryProbe);
        old.finish(true);
        old_pending.record_history();
        old_pending.finish(false);
        assert!(recorder.snapshot().events.is_empty());
    }
    #[test]
    fn held_work_can_be_snapshotted_without_releasing_its_resource() {
        let recorder = NativeStartupDiagnostics::default();
        recorder.set_enabled(true);
        let resource = Arc::new(std::sync::Mutex::new(()));
        let held = resource.lock().unwrap();
        let ready = Arc::new(std::sync::Barrier::new(2));
        let worker = {
            let recorder = recorder.clone();
            let resource = resource.clone();
            let ready = ready.clone();
            std::thread::spawn(move || {
                let probe = recorder.observe(NativeStartupStage::DatabaseOpenLock);
                ready.wait();
                let _lock = resource.lock().unwrap();
                probe.finish(true);
            })
        };
        ready.wait();
        assert_eq!(
            recorder.snapshot().active[0].stage,
            NativeStartupStage::DatabaseOpenLock
        );
        drop(held);
        worker.join().unwrap();
        assert!(recorder.snapshot().active.is_empty());
        assert_eq!(
            recorder.snapshot().events.last().unwrap().outcome,
            NativeStartupOutcome::Success
        );
    }
    #[test]
    fn app_snapshot_remains_available_while_account_cache_is_locked() {
        let root = tempfile::tempdir().unwrap();
        let app = crate::MarmotApp::with_relays(root.path(), Vec::new());
        app.set_startup_diagnostics_enabled(true);
        let held = app.account_storages.lock().unwrap();
        let worker = {
            let app = app.clone();
            std::thread::spawn(move || app.account_storage("synthetic-private-label").is_err())
        };
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let snapshot = app.startup_diagnostics_snapshot();
            if snapshot
                .active
                .iter()
                .any(|entry| entry.stage == NativeStartupStage::AccountStorageCache)
            {
                assert_eq!(
                    snapshot.active[0].stage,
                    NativeStartupStage::AccountStorageCache
                );
                assert!(!format!("{snapshot:?}").contains("synthetic-private-label"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "scope was not observable before account cache access"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        drop(held);
        assert!(worker.join().unwrap());
        let snapshot = app.startup_diagnostics_snapshot();
        assert!(snapshot.active.is_empty());
        assert_eq!(
            snapshot.events.last().unwrap().outcome,
            NativeStartupOutcome::Failure
        );
    }

    /// Normal reads of an already-open store must not evict the first-open migration evidence.
    #[test]
    fn cached_account_reads_preserve_first_open_history() {
        let root = tempfile::tempdir().unwrap();
        let app = crate::MarmotApp::with_relays(root.path(), Vec::new());
        app.account_storages.lock().unwrap().insert(
            "synthetic-private-label".to_owned(),
            storage_sqlite::SqliteAccountStorage::in_memory().unwrap(),
        );
        app.set_startup_diagnostics_enabled(true);
        let first_open = app
            .startup_diagnostics
            .observe(NativeStartupStage::MigrationApply);
        first_open.progress(NativeStartupStage::MigrationApply, Some(104), true);
        first_open.finish(true);
        let before = app.startup_diagnostics_snapshot();
        for _ in 0..128 {
            app.account_storage("synthetic-private-label").unwrap();
        }
        let after = app.startup_diagnostics_snapshot();
        assert_eq!(after.events, before.events);
        assert_eq!(after.dropped_events, 0);
        assert!(after.active.is_empty());
    }

    /// Deferred cache observations become history on a miss, failure or unwind while remaining revocable.
    #[test]
    fn pending_open_scopes_preserve_misses_and_terminal_failures() {
        let recorder = NativeStartupDiagnostics::default();
        recorder.set_enabled(true);
        let miss = recorder.observe_pending_open(NativeStartupStage::ProductAnalyticsAdmission);
        miss.phase(NativeStartupStage::AccountStorageCache);
        let pending = recorder.snapshot();
        assert!(pending.events.is_empty());
        assert_eq!(
            pending.active[0].stage,
            NativeStartupStage::AccountStorageCache
        );
        miss.record_history();
        miss.progress(NativeStartupStage::MigrationApply, Some(105), true);
        miss.finish(true);
        let completed = recorder.snapshot();
        assert_eq!(
            completed.events[0].stage,
            NativeStartupStage::ProductAnalyticsAdmission
        );
        assert_eq!(
            completed.events[1].stage,
            NativeStartupStage::AccountStorageCache
        );
        assert_eq!(
            completed.events.last().unwrap().migration_version,
            Some(105)
        );

        recorder
            .observe_pending_open(NativeStartupStage::AccountStorageCache)
            .finish(false);
        assert_eq!(
            recorder.snapshot().events.last().unwrap().outcome,
            NativeStartupOutcome::Failure
        );
        drop(recorder.observe_pending_open(NativeStartupStage::AccountStorageCache));
        let abandoned = recorder.snapshot();
        assert!(abandoned.active.is_empty());
        assert_eq!(
            abandoned.events.last().unwrap().outcome,
            NativeStartupOutcome::Abandoned
        );
    }

    #[test]
    fn history_and_active_scopes_are_bounded_and_report_truncation() {
        let recorder = NativeStartupDiagnostics::default();
        recorder.set_enabled(true);
        let scopes: Vec<_> = (0..100)
            .map(|_| recorder.observe(NativeStartupStage::StorageAdmission))
            .collect();
        assert_eq!(recorder.snapshot().active.len(), MAX_ACTIVE);
        assert_eq!(recorder.snapshot().dropped_scopes, 84);
        drop(scopes);
        for _ in 0..100 {
            recorder
                .observe(NativeStartupStage::AttachmentLocalRead)
                .finish(false);
        }
        let report = recorder.snapshot();
        assert_eq!(report.events.len(), MAX_EVENTS);
        assert!(report.dropped_events > 0);
    }
}
