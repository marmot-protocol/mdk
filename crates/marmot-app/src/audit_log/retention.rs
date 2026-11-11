//! Local forensic retention: a host-configured maximum age and per-account
//! size budget, independent of recording consent and upload.

use crate::runtime::RuntimeLifecycle;
use crate::{AppError, MarmotApp};
use marmot_forensics::ForensicRecorder;
use marmot_forensics::local_delivery::{DeliveryCursorView, SourceDelivery};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage_sqlite::StoredAuditLogRetention;
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

/// The receiver accepts records up to 30 days old, so files are never kept
/// longer.
pub const AUDIT_LOG_MAX_AGE_DAYS: u32 = 30;
pub const AUDIT_LOG_DEFAULT_MAX_BYTES_PER_ACCOUNT: u64 = 256 * 1024 * 1024;
/// A smaller budget would evict the few segments a delivery pass is reading.
pub const AUDIT_LOG_MIN_MAX_BYTES_PER_ACCOUNT: u64 = 16 * 1024 * 1024;
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const AUDIT_RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Recording activity and delivery passes request budget checks; a replay
/// storm seals several segments a minute. Run at most one per this spacing.
const AUDIT_BUDGET_CHECK_SPACING: Duration = Duration::from_secs(30);
const DELIVERY_STATE_DIR: &str = "audit-otlp-delivery-v5";

/// Host-configured local audit retention, persisted in shared storage.
///
/// A file older than `max_age_days` is deleted whether or not it was
/// delivered; deleting undelivered data records an `ExpiredUndelivered` gap in
/// the account's v5 delivery cursor. Above `max_bytes_per_account`, the oldest
/// sealed segments are deleted only when no delivery cursor still owes them.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogRetention {
    pub max_age_days: u32,
    pub max_bytes_per_account: u64,
}

impl Default for AuditLogRetention {
    fn default() -> Self {
        Self {
            max_age_days: AUDIT_LOG_MAX_AGE_DAYS,
            max_bytes_per_account: AUDIT_LOG_DEFAULT_MAX_BYTES_PER_ACCOUNT,
        }
    }
}

impl AuditLogRetention {
    /// Clamp to what retention enforces and storage holds: 1 to 30 days, and
    /// a budget from [`AUDIT_LOG_MIN_MAX_BYTES_PER_ACCOUNT`] to `i64::MAX`.
    pub fn normalized(self) -> Self {
        Self {
            max_age_days: self.max_age_days.clamp(1, AUDIT_LOG_MAX_AGE_DAYS),
            max_bytes_per_account: self
                .max_bytes_per_account
                .clamp(AUDIT_LOG_MIN_MAX_BYTES_PER_ACCOUNT, i64::MAX as u64),
        }
    }

    fn cutoff_ms(self, now: SystemTime) -> u64 {
        cutoff_ms(now, DAY * self.max_age_days)
    }
}

impl MarmotApp {
    pub fn audit_log_retention(&self) -> Result<AuditLogRetention, AppError> {
        Ok(self
            .shared_storage()?
            .audit_log_retention()?
            .map(|stored| AuditLogRetention {
                max_age_days: stored.max_age_days,
                max_bytes_per_account: stored.max_bytes_per_account,
            })
            .unwrap_or_default()
            .normalized())
    }

    /// Persist the retention policy, clamped as [`AuditLogRetention::normalized`]
    /// describes, and return what is stored. Runtime sweeps apply it.
    pub fn set_audit_log_retention(
        &self,
        retention: AuditLogRetention,
    ) -> Result<AuditLogRetention, AppError> {
        let retention = retention.normalized();
        self.shared_storage()?
            .set_audit_log_retention(StoredAuditLogRetention {
                max_age_days: retention.max_age_days,
                max_bytes_per_account: retention.max_bytes_per_account,
            })?;
        Ok(retention)
    }

    /// The policy a sweep enforces. An unreadable policy keeps files for the
    /// longest allowed age and skips the size budget.
    fn retention_policy(&self) -> Option<AuditLogRetention> {
        self.audit_log_retention().ok()
    }
}

fn cutoff_ms(now: SystemTime, max_age: Duration) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(max_age)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Exclusive-root startup only. This reads metadata and delivery cursors,
/// never audit payloads, and reads the policy only once some file could be
/// affected.
pub(crate) fn cleanup_expired_audit_logs(app: &MarmotApp) {
    let now = SystemTime::now();
    let mut cached = None;
    let mut policy = || *cached.get_or_insert_with(|| app.retention_policy());
    let mut failed = 0;
    scan_root(
        &app.root,
        cutoff_ms(now, DAY),
        || false,
        |path| {
            let cutoff = policy().unwrap_or_default().cutoff_ms(now);
            failed += usize::from(
                marmot_forensics::NoopRecorder
                    .expire_file_before(&path, cutoff, &mut |closed| Retire::Expire.source(closed))
                    .is_err(),
            );
            true
        },
    );
    scan_budgets(
        &app.root,
        || policy().map(|policy| policy.max_bytes_per_account),
        || false,
        |path| {
            failed += usize::from(
                marmot_forensics::NoopRecorder
                    .expire_file_before(&path, u64::MAX, &mut |closed| Retire::Evict.source(closed))
                    .is_err(),
            );
            true
        },
    );
    report_failures(failed);
}

/// One installation-wide worker, independent of signed-in account workers.
/// Its scans have a size-one path queue and read metadata and delivery
/// cursors only. File mutations acquire storage admission for one file, never
/// across the directory walk.
#[derive(Clone)]
pub(crate) struct AuditRetentionWorker(Arc<WorkerOwner>);
struct WorkerOwner {
    app: MarmotApp,
    task: Mutex<Option<JoinHandle<()>>>,
    wake: Arc<Notify>,
    sweep_requested: Arc<AtomicBool>,
}
impl Drop for WorkerOwner {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            task.abort();
        }
    }
}
impl AuditRetentionWorker {
    pub(crate) fn new(app: MarmotApp) -> Self {
        Self(Arc::new(WorkerOwner {
            app,
            task: Mutex::new(None),
            wake: Arc::new(Notify::new()),
            sweep_requested: Arc::new(AtomicBool::new(false)),
        }))
    }
    pub(crate) fn start(&self, lifecycle: RuntimeLifecycle) {
        self.start_with_intervals(
            lifecycle,
            AUDIT_RETENTION_SWEEP_INTERVAL,
            AUDIT_BUDGET_CHECK_SPACING,
        );
    }

    /// Check size budgets soon: new segments were sealed, or a delivery pass
    /// made some evictable. Requests coalesce.
    pub(crate) fn request_budget_check(&self) {
        self.0.wake.notify_one();
    }

    /// Run a full age and budget sweep soon, after a policy change.
    pub(crate) fn request_sweep(&self) {
        self.0.sweep_requested.store(true, Ordering::Release);
        self.0.wake.notify_one();
    }

    fn start_with_intervals(
        &self,
        lifecycle: RuntimeLifecycle,
        period: Duration,
        spacing: Duration,
    ) {
        let mut task = self.0.task.lock().unwrap_or_else(|p| p.into_inner());
        if task.as_ref().is_some_and(|t| !t.is_finished()) || lifecycle.is_stopping() {
            return;
        }
        let app = self.0.app.clone();
        let wake = self.0.wake.clone();
        let sweep_requested = self.0.sweep_requested.clone();
        *task = Some(tokio::spawn(async move {
            let mut stopping = lifecycle.subscribe_shutdown();
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // Exclusive open just swept; don't scan twice at launch.
            loop {
                let ticked = tokio::select! { biased;
                    _ = stopping.changed() => break,
                    _ = tick.tick() => true,
                    _ = wake.notified() => false,
                };
                let sweep = sweep_requested.swap(false, Ordering::AcqRel) || ticked;
                if lifecycle.is_stopping() || app.storage_closed.load(Ordering::Acquire) {
                    break;
                }
                let policy = crate::blocking_app_task({
                    let app = app.clone();
                    move || Ok(app.retention_policy())
                })
                .await
                .ok()
                .flatten();
                if sweep {
                    let root = app.root.clone();
                    let cutoff = policy.unwrap_or_default().cutoff_ms(SystemTime::now());
                    let scan =
                        move |stopped: &dyn Fn() -> bool,
                              candidate: &mut dyn FnMut(PathBuf) -> bool| {
                            scan_root(&root, cutoff, stopped, candidate)
                        };
                    let retire = Retire::Expire;
                    if !retire_scanned(&app, &lifecycle, &mut stopping, retire, cutoff, scan).await
                    {
                        return;
                    }
                }
                if let Some(policy) = policy {
                    let root = app.root.clone();
                    let scan =
                        move |stopped: &dyn Fn() -> bool,
                              candidate: &mut dyn FnMut(PathBuf) -> bool| {
                            scan_budgets(
                                &root,
                                || Some(policy.max_bytes_per_account),
                                stopped,
                                candidate,
                            )
                        };
                    let retire = Retire::Evict;
                    if !retire_scanned(&app, &lifecycle, &mut stopping, retire, u64::MAX, scan)
                        .await
                    {
                        return;
                    }
                }
                tokio::select! { biased;
                    _ = stopping.changed() => break,
                    _ = tokio::time::sleep(spacing) => {}
                }
            }
        }));
    }
    pub(crate) async fn shutdown(&self) {
        let task = self.0.task.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Retire each candidate one metadata scan yields, one file at a time.
/// Returns false when the worker must stop.
async fn retire_scanned(
    app: &MarmotApp,
    lifecycle: &RuntimeLifecycle,
    stopping: &mut watch::Receiver<bool>,
    retire: Retire,
    cutoff: u64,
    scan: impl FnOnce(&dyn Fn() -> bool, &mut dyn FnMut(PathBuf) -> bool) + Send + 'static,
) -> bool {
    let (sender, mut candidates) = mpsc::channel(1);
    let scanner_lifecycle = lifecycle.clone();
    // The scanner holds no app, recorder, database or storage guard.
    let scanner = tokio::task::spawn_blocking(move || {
        scan(&|| scanner_lifecycle.is_stopping(), &mut |path| {
            sender.blocking_send(path).is_ok()
        });
    });
    loop {
        let path = tokio::select! { biased;
            _ = stopping.changed() => return false,
            path = candidates.recv() => match path { Some(path) => path, None => break },
        };
        if lifecycle.is_stopping() || app.storage_closed.load(Ordering::Acquire) {
            return false;
        }
        let candidate_app = app.clone();
        let candidate_lifecycle = lifecycle.clone();
        // This is only a metadata check, a cursor update and one unlink.
        // Shutdown can never wait for payload copying or a directory walk.
        let result = crate::blocking_app_task(move || {
            if candidate_lifecycle.is_stopping() {
                return Ok(false);
            }
            candidate_app.retire_audit_file(&path, retire, cutoff)
        })
        .await;
        report_failures(usize::from(result.is_err()));
    }
    if scanner.await.is_err() {
        report_failures(1);
    }
    true
}

/// How retention removes one file.
#[derive(Clone, Copy, Debug)]
enum Retire {
    /// Past the maximum age: remove it, recording undelivered data as a gap.
    Expire,
    /// Over the size budget: remove it only if no cursor still owes it.
    Evict,
}

impl Retire {
    fn source(self, path: &Path) -> io::Result<bool> {
        if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.contains("-v5"))
        {
            let state = path
                .parent()
                .expect("account directory")
                .join(DELIVERY_STATE_DIR);
            return match self {
                Retire::Expire => {
                    marmot_forensics::local_delivery::expire_closed_source(path, &state)
                }
                Retire::Evict => {
                    marmot_forensics::local_delivery::evict_delivered_source(path, &state)
                }
            };
        }
        // v4 files have no delivery cursor.
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
}

impl MarmotApp {
    /// Age expiry under the stored policy, as a runtime sweep applies it.
    #[cfg(test)]
    pub(crate) fn expire_audit_file(&self, path: &Path) -> Result<bool, AppError> {
        let cutoff = self
            .retention_policy()
            .unwrap_or_default()
            .cutoff_ms(SystemTime::now());
        self.retire_audit_file(path, Retire::Expire, cutoff)
    }

    /// Retire one file last modified before `cutoff` (milliseconds since the
    /// epoch; `u64::MAX` for any age).
    fn retire_audit_file(
        &self,
        path: &Path,
        retire: Retire,
        cutoff: u64,
    ) -> Result<bool, AppError> {
        let _storage = self.begin_storage_open("audit retention")?;
        let Some(account) = path.parent() else {
            return Ok(false);
        };
        let Some(container) = account.parent() else {
            return Ok(false);
        };
        if !fs::symlink_metadata(container)?.is_dir()
            || !fs::symlink_metadata(account)?.is_dir()
            || !is_expired(path, cutoff)?
        {
            return Ok(false);
        }
        // AccountHome may use /var while recorders use /private/var. Reject
        // links at the mutable levels first, then normalize both sides of
        // the writer-path comparison so expiry cannot orphan a live inode.
        let root = fs::canonicalize(&self.root)?;
        let container = fs::canonicalize(container)?;
        let accounts = root.join("accounts");
        if container != accounts && container != root.join(".wipe-tombstones") {
            return Ok(false);
        }
        let path = fs::canonicalize(path)?;
        let label = account.file_name().and_then(|s| s.to_str());
        let slot = if container == accounts {
            label.map(|label| self.audit_recorder_slot(label))
        } else {
            None
        };
        // An opener holding this slot may still need storage admission.
        // Never wait on it while holding a lifecycle reader: a queued close
        // would otherwise block that opener's next read and deadlock all three.
        let registration = match slot.as_ref().map(|slot| slot.try_lock()) {
            Some(Ok(guard)) => Some(guard),
            Some(Err(std::sync::TryLockError::Poisoned(error))) => Some(error.into_inner()),
            Some(Err(std::sync::TryLockError::WouldBlock)) => return Ok(false),
            None => None,
        };
        let recorder = registration
            .as_ref()
            .and_then(|registration| registration.as_ref())
            .and_then(|weak| weak.upgrade());
        let directory = path.parent().expect("validated account directory");
        let mut expire = |closed: &Path| {
            let source = marmot_forensics::local_delivery::source_identity(closed)?;
            self.audit_export_lifecycle
                .mutate_source(directory, source, || retire.source(closed))
        };
        Ok(match recorder {
            Some(recorder) => recorder.expire_file_before(&path, cutoff, &mut expire)?,
            None => {
                marmot_forensics::NoopRecorder.expire_file_before(&path, cutoff, &mut expire)?
            }
        })
    }
}

/// Each account's oldest sealed segments, beyond its size budget, that no
/// delivery cursor still owes. Reads metadata and cursors, never payloads,
/// and reads the budget only for an account above the smallest allowed one.
fn scan_budgets(
    root: &Path,
    mut budget: impl FnMut() -> Option<u64>,
    stopped: impl Fn() -> bool,
    mut candidate: impl FnMut(PathBuf) -> bool,
) {
    let container = root.join("accounts");
    let entries = match fs::symlink_metadata(&container) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return,
        Ok(m) if m.is_dir() => fs::read_dir(&container),
        _ => Err(io::Error::other("unexpected audit container")),
    };
    let Ok(entries) = entries else {
        report_failures(1);
        return;
    };
    let mut failed = 0;
    for entry in entries {
        if stopped() {
            break;
        }
        let result = (|| {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                return Ok(true);
            }
            for path in over_budget(&entry.path(), &mut budget)? {
                if stopped() || !candidate(path) {
                    return Ok(false);
                }
            }
            Ok::<_, io::Error>(true)
        })();
        match result {
            Ok(false) => break,
            Err(_) => failed += 1,
            _ => {}
        }
    }
    report_failures(failed);
}

fn over_budget(
    account: &Path,
    budget: &mut impl FnMut() -> Option<u64>,
) -> io::Result<Vec<PathBuf>> {
    let mut total = 0u64;
    let mut segments = Vec::new();
    for entry in fs::read_dir(account)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| is_retained_audit_file(name)) else {
            continue;
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            other => other?,
        };
        if !metadata.is_file() {
            continue;
        }
        total = total.saturating_add(metadata.len());
        // Active files are live or tiny; only sealed segments are evicted.
        if name.contains("-seg") {
            segments.push((metadata.modified()?, entry.path(), metadata.len()));
        }
    }
    if total <= AUDIT_LOG_MIN_MAX_BYTES_PER_ACCOUNT {
        return Ok(Vec::new());
    }
    let Some(limit) = budget().filter(|limit| total > *limit) else {
        return Ok(Vec::new());
    };
    let cursor = DeliveryCursorView::load(&account.join(DELIVERY_STATE_DIR))?;
    segments.sort();
    let mut evict = Vec::new();
    for (_, path, len) in segments {
        if total <= limit {
            break;
        }
        match cursor.source_delivery(&path) {
            Ok(SourceDelivery::Delivered | SourceDelivery::Untracked) => {
                total -= len;
                evict.push(path);
            }
            Ok(SourceDelivery::Undelivered) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(evict)
}

fn scan_root(
    root: &Path,
    cutoff: u64,
    stopped: impl Fn() -> bool,
    mut candidate: impl FnMut(PathBuf) -> bool,
) {
    let mut failed = 0;
    for name in ["accounts", ".wipe-tombstones"] {
        if stopped() {
            break;
        }
        let container = root.join(name);
        match fs::symlink_metadata(&container) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Ok(m) if m.is_dir() => {}
            _ => {
                failed += 1;
                continue;
            }
        }
        let entries = match fs::read_dir(&container) {
            Ok(e) => e,
            Err(_) => {
                failed += 1;
                continue;
            }
        };
        for entry in entries {
            if stopped() {
                break;
            }
            let result = (|| {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    let mut accepting = true;
                    scan_expired(&entry.path(), cutoff, &stopped, |path| {
                        accepting = candidate(path);
                        accepting
                    })?;
                    if !accepting {
                        return Ok(false);
                    }
                }
                Ok::<_, io::Error>(true)
            })();
            match result {
                Ok(false) => return,
                Err(_) => failed += 1,
                _ => {}
            }
        }
    }
    report_failures(failed);
}

fn scan_expired(
    account: &Path,
    cutoff: u64,
    stopped: impl Fn() -> bool,
    mut candidate: impl FnMut(PathBuf) -> bool,
) -> io::Result<()> {
    if !fs::symlink_metadata(account)?.is_dir() {
        return Err(io::Error::other("unexpected audit directory"));
    }
    let mut failed = 0;
    for entry in fs::read_dir(account)? {
        if stopped() {
            break;
        }
        let result = (|| {
            let path = entry?.path();
            if is_expired(&path, cutoff)? && !candidate(path) {
                return Ok(false);
            }
            Ok::<_, io::Error>(true)
        })();
        match result {
            Ok(false) => break,
            Err(_) => failed += 1,
            _ => {}
        }
    }
    report_failures(failed);
    Ok(())
}

fn is_expired(path: &Path, cutoff: u64) -> io::Result<bool> {
    if !path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_retained_audit_file)
    {
        return Ok(false);
    }
    let metadata = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        other => other?,
    };
    Ok(metadata.is_file()
        && metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            < u128::from(cutoff))
}

fn report_failures(failed: usize) {
    if failed > 0 {
        tracing::warn!(target: "marmot_app::audit_log", method = "expire_audit_logs",
        failed, "audit retention incomplete; will retry on next sweep or open");
    }
}

fn is_retained_audit_file(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("audit-")
        .and_then(|s| s.strip_suffix(".jsonl"))
    else {
        return false;
    };
    let stem = if let Some((base, index)) = stem.rsplit_once("-seg") {
        if index.len() < 6
            || !index.bytes().all(|b| b.is_ascii_digit())
            || index.parse::<u32>().is_err()
        {
            return false;
        }
        base
    } else {
        stem
    };
    let Some(id) = stem
        .strip_suffix("-v4")
        .or_else(|| stem.strip_suffix("-v5"))
    else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn age(path: &Path, time: SystemTime) {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(time))
            .unwrap();
    }
    #[test]
    fn audit_retention_cleans_dormant_accounts_and_wipe_remnants_on_exclusive_open() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let account = home.account_dir("alice");
        let old = format!("audit-{}-v4-seg000001.jsonl", "a".repeat(32));
        let recent = format!("audit-{}-v5.jsonl", "b".repeat(32));
        fs::write(account.join(&old), b"old unreadable payload").unwrap();
        age(&account.join(&old), UNIX_EPOCH);
        fs::write(account.join(&recent), b"recent").unwrap();
        fs::write(account.join("audit-key-reveal.jsonl"), b"security").unwrap();
        age(&account.join("audit-key-reveal.jsonl"), UNIX_EPOCH);
        let tombstone = root.path().join(".wipe-tombstones/remnant");
        fs::create_dir_all(&tombstone).unwrap();
        fs::write(tombstone.join(&old), b"old").unwrap();
        age(&tombstone.join(&old), UNIX_EPOCH);
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            root.path(),
            Vec::new(),
            home,
            crate::MarmotAppConfig::white_noise(),
        )
        .unwrap();
        assert!(!app.audit_log_settings().unwrap().enabled);
        assert!(!account.join(&old).exists());
        assert!(!tombstone.join(&old).exists());
        assert_eq!(fs::read(account.join(recent)).unwrap(), b"recent");
        assert!(account.join("audit-key-reveal.jsonl").exists());
    }
    #[test]
    fn audit_retention_keeps_boundary_and_fences_only_expired_candidates() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let path = app
            .account_dir("alice")
            .join(format!("audit-{}-v4.jsonl", "a".repeat(32)));
        fs::write(&path, b"old").unwrap();
        age(&path, UNIX_EPOCH + Duration::from_millis(100));
        assert!(!is_expired(&path, 100).unwrap());
        assert!(is_expired(&path, 101).unwrap());
        age(&path, SystemTime::now());
        let attempt = app
            .audit_export_lifecycle
            .reserve(
                &account.account_id_hex,
                "test",
                &fs::canonicalize(app.account_dir("alice")).unwrap(),
            )
            .unwrap();

        app.audit_export_lifecycle.prepared_source(
            &attempt,
            marmot_forensics::local_delivery::source_identity(&path).unwrap(),
        );
        assert!(!app.expire_audit_file(&path).unwrap());
        assert!(app.audit_export_lifecycle.admit(&attempt, || ()).is_some());
        age(&path, UNIX_EPOCH);
        assert!(app.expire_audit_file(&path).unwrap());
        assert!(app.audit_export_lifecycle.admit(&attempt, || ()).is_none());
        app.close_storage().unwrap();
        assert!(app.expire_audit_file(&path).is_err());
    }
    #[test]
    fn audit_retention_policy_is_clamped_persisted_and_sets_the_age_cutoff() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        assert_eq!(
            app.audit_log_retention().unwrap(),
            AuditLogRetention {
                max_age_days: 30,
                max_bytes_per_account: 256 << 20,
            }
        );
        let clamped = |max_age_days, max_bytes_per_account| {
            app.set_audit_log_retention(AuditLogRetention {
                max_age_days,
                max_bytes_per_account,
            })
            .unwrap()
        };
        assert_eq!(
            clamped(0, 1),
            AuditLogRetention {
                max_age_days: 1,
                max_bytes_per_account: 16 << 20
            }
        );
        let largest = clamped(45, u64::MAX);
        assert_eq!(
            (largest.max_age_days, largest.max_bytes_per_account),
            (30, i64::MAX as u64)
        );
        assert_eq!(app.audit_log_retention().unwrap(), largest);
        let stored = clamped(2, 1 << 40);
        let reopened = MarmotApp::with_relays_and_account_home(
            root.path(),
            Vec::new(),
            marmot_account::AccountHome::open(root.path()),
        );
        assert_eq!(reopened.audit_log_retention().unwrap(), stored);

        let file = |name: &str, days_old: u64| {
            let path = app
                .account_dir("alice")
                .join(format!("audit-{}-v4.jsonl", name.repeat(32)));
            fs::write(&path, b"row").unwrap();
            age(&path, SystemTime::now() - DAY * days_old as u32);
            path
        };
        let (expired, kept) = (file("a", 3), file("b", 1));
        assert!(app.expire_audit_file(&expired).unwrap());
        assert!(!app.expire_audit_file(&kept).unwrap());
        assert!(!expired.exists() && kept.exists());
    }

    /// Deliver every record the account's v5 cursor can see.
    fn deliver_all(active: &Path) {
        use marmot_forensics::local_delivery::{LocalAuditDelivery, Preparation, ReceiverResult};
        let state = active.with_file_name(DELIVERY_STATE_DIR);
        let mut delivery = LocalAuditDelivery::open(active, state, "receiver").unwrap();
        while let Preparation::Batch(batch) = delivery.prepare_once().unwrap() {
            delivery
                .finish(&batch.token, ReceiverResult::Complete)
                .unwrap();
        }
    }

    #[test]
    fn audit_size_budget_evicts_delivered_and_untracked_oldest_first_and_keeps_owed_data() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        home.create_account("bob").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let recorder = app.build_audit_recorder("alice", true);
        recorder.record(marmot_forensics::AuditRecord::new(
            None,
            marmot_forensics::AuditEventKind::SendEntry {
                intent_kind: "delivered".into(),
            },
        ));
        let active = recorder.audit_log_path().unwrap();
        drop(recorder);
        let stem = active
            .to_str()
            .unwrap()
            .strip_suffix(".jsonl")
            .unwrap()
            .to_owned();
        let mut minute = 0;
        let mut file = |path: PathBuf, bytes: Option<&[u8]>| {
            match bytes {
                Some(bytes) => fs::write(&path, bytes).unwrap(),
                // Sparse: counted at its length without using the disk.
                None => fs::File::create(&path).unwrap().set_len(6 << 20).unwrap(),
            }
            minute += 1;
            age(&path, UNIX_EPOCH + Duration::from_secs(60 * minute));
            path
        };
        let rows = fs::read(&active).unwrap();
        let delivered: Vec<_> = (1..=2)
            .map(|index| {
                file(
                    PathBuf::from(format!("{stem}-seg{index:06}.jsonl")),
                    Some(&rows),
                )
            })
            .collect();
        deliver_all(&active);
        let owed = file(
            PathBuf::from(format!("{stem}-seg000003.jsonl")),
            Some(&rows),
        );
        let alice = app.account_dir("alice");
        let bob = app.account_dir("bob");
        let v4: Vec<_> = (1..=3)
            .map(|index| {
                file(
                    alice.join(format!("audit-{}-v4-seg{index:06}.jsonl", "b".repeat(32))),
                    None,
                )
            })
            .collect();
        // Bob never configured v5 delivery: nothing will upload his files.
        let untracked: Vec<_> = (1..=3)
            .map(|index| {
                file(
                    bob.join(format!("audit-{}-v5-seg{index:06}.jsonl", "c".repeat(32))),
                    None,
                )
            })
            .collect();

        scan_budgets(
            root.path(),
            || Some(16 << 20),
            || false,
            |path| {
                assert!(
                    app.retire_audit_file(&path, Retire::Evict, u64::MAX)
                        .unwrap()
                );
                true
            },
        );
        let present = |paths: &[&PathBuf]| paths.iter().map(|p| p.exists()).collect::<Vec<_>>();
        // Alice sheds both delivered segments, skips the one her cursor still
        // owes, and stops once the oldest v4 segment brings her under 16 MiB.
        assert_eq!(
            present(&[&delivered[0], &delivered[1], &owed, &v4[0], &v4[1], &v4[2]]),
            [false, false, true, false, true, true]
        );
        assert_eq!(
            present(&[&untracked[0], &untracked[1], &untracked[2]]),
            [false, true, true]
        );
        assert!(active.exists());
    }

    #[cfg(unix)]
    #[test]
    fn audit_retention_never_follows_links_or_removes_custom_names() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let name = format!("audit-{}-v5.jsonl", "a".repeat(32));
        let target = external.path().join(&name);
        fs::write(&target, b"keep").unwrap();
        age(&target, UNIX_EPOCH);
        fs::create_dir_all(root.path().join("accounts/real")).unwrap();
        std::os::unix::fs::symlink(external.path(), root.path().join("accounts/linked")).unwrap();
        std::os::unix::fs::symlink(&target, root.path().join("accounts/real").join(&name)).unwrap();
        let custom = root.path().join("accounts/real/audit-custom.jsonl");
        fs::write(&custom, b"keep").unwrap();
        age(&custom, UNIX_EPOCH);
        let home = marmot_account::AccountHome::open(root.path());
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        cleanup_expired_audit_logs(&app);
        assert!(target.exists());
        assert!(custom.exists());
    }
    #[test]
    fn audit_retention_protects_live_files_without_keeping_recorders_alive() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let slot = app.audit_recorder_slot("alice");
        let recorder = marmot_forensics::SharedRecorder::new(
            app.open_audit_recorder("alice", &app.member_id("alice").unwrap())
                .unwrap(),
        );
        *slot.lock().unwrap() = Some(recorder.downgrade());
        let active = recorder.audit_log_path().unwrap();
        age(&active, UNIX_EPOCH);
        assert!(app.expire_audit_file(&active).unwrap());
        assert_eq!(fs::metadata(&active).unwrap().len(), 0);
        age(&active, UNIX_EPOCH);
        let listed = app.account_dir("alice").join(active.file_name().unwrap());
        assert!(!app.expire_audit_file(&listed).unwrap());
        let old = app
            .account_dir("alice")
            .join(format!("audit-{}-v4-seg000001.jsonl", "b".repeat(32)));
        fs::write(&old, b"expired").unwrap();
        age(&old, UNIX_EPOCH);
        assert!(app.expire_audit_file(&old).unwrap());
        drop(recorder);
        assert!(slot.lock().unwrap().as_ref().unwrap().upgrade().is_none());
        assert!(app.expire_audit_file(&active).unwrap());
    }

    #[cfg(feature = "test-policy-overrides")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_retention_background_sweeps_new_dormant_and_failed_wipe_directories_and_stops() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let lifecycle = crate::runtime::RuntimeSharedServices::default().lifecycle();
        let worker = AuditRetentionWorker::new(app.clone());
        worker.start_with_intervals(
            lifecycle.clone(),
            Duration::from_millis(10),
            Duration::from_millis(10),
        );
        let mut files = Vec::new();
        for container in ["accounts", ".wipe-tombstones"] {
            let account = root.path().join(container).join("late-dormant");
            fs::create_dir_all(&account).unwrap();
            let path = account.join(format!("audit-{}-v5.jsonl", "a".repeat(32)));
            fs::write(&path, b"old").unwrap();
            age(&path, UNIX_EPOCH);
            files.push(path);
        }
        tokio::time::timeout(Duration::from_secs(3), async {
            while files.iter().any(|p| p.exists()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        lifecycle.begin_shutdown();
        worker.shutdown().await;
        app.close_storage().unwrap();
        fs::write(&files[0], b"old").unwrap();
        age(&files[0], UNIX_EPOCH);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(files[0].exists());
    }

    #[cfg(feature = "test-policy-overrides")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_size_budget_runs_on_request_between_hourly_sweeps() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        app.set_audit_log_retention(AuditLogRetention {
            max_age_days: 30,
            max_bytes_per_account: 16 << 20,
        })
        .unwrap();
        let segments: Vec<_> = (1..=3)
            .map(|index| {
                let path = app
                    .account_dir("alice")
                    .join(format!("audit-{}-v5-seg{index:06}.jsonl", "a".repeat(32)));
                fs::File::create(&path).unwrap().set_len(6 << 20).unwrap();
                age(&path, UNIX_EPOCH + Duration::from_secs(index));
                path
            })
            .collect();
        let lifecycle = crate::runtime::RuntimeSharedServices::default().lifecycle();
        let worker = AuditRetentionWorker::new(app.clone());
        worker.start_with_intervals(
            lifecycle.clone(),
            Duration::from_secs(3600),
            Duration::from_millis(10),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(segments[0].exists());
        worker.request_budget_check();
        tokio::time::timeout(Duration::from_secs(3), async {
            while segments[0].exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(segments[1].exists() && segments[2].exists());
        lifecycle.begin_shutdown();
        worker.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn audit_retention_scanner_cancels_when_its_bounded_queue_closes() {
        let root = tempfile::tempdir().unwrap();
        let account = root.path().join("accounts/alice");
        fs::create_dir_all(&account).unwrap();
        for index in 0..100 {
            let path = account.join(format!("audit-{}-v5-seg{index:06}.jsonl", "a".repeat(32)));
            fs::write(&path, b"old").unwrap();
            age(&path, UNIX_EPOCH);
        }
        let (sender, mut receiver) = mpsc::channel(1);
        let scan_root_path = root.path().to_owned();
        let scanner = tokio::task::spawn_blocking(move || {
            scan_root(
                &scan_root_path,
                u64::MAX,
                || false,
                |path| sender.blocking_send(path).is_ok(),
            )
        });
        receiver.recv().await.unwrap();
        drop(receiver);
        tokio::time::timeout(Duration::from_secs(3), scanner)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fs::read_dir(account).unwrap().count(), 100); // Scanner never deletes.
    }
    #[test]
    fn audit_retention_defers_a_candidate_while_its_account_is_opening() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let path = app
            .account_dir("alice")
            .join(format!("audit-{}-v5-seg000001.jsonl", "a".repeat(32)));
        fs::write(&path, b"old").unwrap();
        age(&path, UNIX_EPOCH);
        let slot = app.audit_recorder_slot("alice");
        let opening = slot.lock().unwrap();
        assert!(!app.expire_audit_file(&path).unwrap());
        assert!(path.exists());
        drop(opening);
        assert!(app.expire_audit_file(&path).unwrap());
    }
    #[test]
    fn audit_retention_does_not_cancel_other_sources_or_accounts() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        let alice = home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let alice_dir = fs::canonicalize(app.account_dir("alice")).unwrap();
        let bob_dir = fs::canonicalize(app.account_dir("bob")).unwrap();
        let alice_attempt = app
            .audit_export_lifecycle
            .reserve(&alice.account_id_hex, "receiver", &alice_dir)
            .unwrap();
        let bob_attempt = app
            .audit_export_lifecycle
            .reserve(&bob.account_id_hex, "receiver", &bob_dir)
            .unwrap();
        let file = |directory: &Path, id: &str| {
            let path = directory.join(format!("audit-{id}-v5-seg000001.jsonl"));
            fs::write(&path, b"source").unwrap();
            path
        };
        let on_wire = file(&alice_dir, &"a".repeat(32));
        let bob_wire = file(&bob_dir, &"b".repeat(32));
        app.audit_export_lifecycle.prepared_source(
            &alice_attempt,
            marmot_forensics::local_delivery::source_identity(&on_wire).unwrap(),
        );
        app.audit_export_lifecycle.prepared_source(
            &bob_attempt,
            marmot_forensics::local_delivery::source_identity(&bob_wire).unwrap(),
        );
        let other_alice = file(&alice_dir, &"c".repeat(32));
        age(&other_alice, UNIX_EPOCH);
        assert!(app.expire_audit_file(&other_alice).unwrap());
        let tomb = root.path().join(".wipe-tombstones/old");
        fs::create_dir_all(&tomb).unwrap();
        let remnant = file(&tomb, &"d".repeat(32));
        age(&remnant, UNIX_EPOCH);
        assert!(app.expire_audit_file(&remnant).unwrap());
        assert!(
            app.audit_export_lifecycle
                .admit(&alice_attempt, || ())
                .is_some()
        );
        assert!(
            app.audit_export_lifecycle
                .admit(&bob_attempt, || ())
                .is_some()
        );
        age(&on_wire, UNIX_EPOCH);
        assert!(app.expire_audit_file(&on_wire).unwrap());
        assert!(
            app.audit_export_lifecycle
                .admit(&alice_attempt, || ())
                .is_none()
        );
        assert!(
            app.audit_export_lifecycle
                .admit(&bob_attempt, || ())
                .is_some()
        );
    }
}
