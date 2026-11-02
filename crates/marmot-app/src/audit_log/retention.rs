//! Whole-file forensic expiry, independent of recording consent and upload.

use crate::runtime::RuntimeLifecycle;
use crate::{AppError, MarmotApp};
use marmot_forensics::ForensicRecorder;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const AUDIT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const AUDIT_RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

fn cutoff_ms(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(AUDIT_RETENTION)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Exclusive-root startup only. This reads metadata, never audit payloads.
pub(crate) fn cleanup_expired_audit_logs(root: &Path) {
    let cutoff = cutoff_ms(SystemTime::now());
    let mut failed = 0;
    scan_root(
        root,
        cutoff,
        || false,
        |path| {
            failed += usize::from(
                marmot_forensics::NoopRecorder
                    .expire_file_before(&path, cutoff, &mut expire_source_file)
                    .is_err(),
            );
            true
        },
    );
    report_failures(failed);
}

/// One installation-wide worker, independent of signed-in account workers.
/// Its scan has a size-one path queue and reads metadata only. File mutations
/// acquire storage admission for one file, never across the directory walk.
#[derive(Clone)]
pub(crate) struct AuditRetentionWorker(Arc<WorkerOwner>);
struct WorkerOwner {
    app: MarmotApp,
    task: Mutex<Option<JoinHandle<()>>>,
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
        }))
    }
    pub(crate) fn start(&self, lifecycle: RuntimeLifecycle) {
        self.start_with_interval(lifecycle, AUDIT_RETENTION_SWEEP_INTERVAL);
    }

    fn start_with_interval(&self, lifecycle: RuntimeLifecycle, period: Duration) {
        let mut task = self.0.task.lock().unwrap_or_else(|p| p.into_inner());
        if task.as_ref().is_some_and(|t| !t.is_finished()) || lifecycle.is_stopping() {
            return;
        }
        let app = self.0.app.clone();
        *task = Some(tokio::spawn(async move {
            let mut stopping = lifecycle.subscribe_shutdown();
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // Exclusive open just swept; don't scan twice at launch.
            loop {
                tokio::select! { biased;
                    _ = stopping.changed() => break,
                    _ = tick.tick() => {}
                }
                if lifecycle.is_stopping()
                    || app
                        .storage_closed
                        .load(std::sync::atomic::Ordering::Acquire)
                {
                    break;
                }
                let (sender, mut candidates) = mpsc::channel(1);
                let root = app.root.clone();
                let scanner_lifecycle = lifecycle.clone();
                // The scanner holds no app, recorder, database or storage guard.
                let scanner = tokio::task::spawn_blocking(move || {
                    scan_root(
                        &root,
                        cutoff_ms(SystemTime::now()),
                        || scanner_lifecycle.is_stopping(),
                        |path| sender.blocking_send(path).is_ok(),
                    );
                });
                loop {
                    let path = tokio::select! { biased;
                        _ = stopping.changed() => return,
                        path = candidates.recv() => match path { Some(path) => path, None => break },
                    };
                    if lifecycle.is_stopping()
                        || app
                            .storage_closed
                            .load(std::sync::atomic::Ordering::Acquire)
                    {
                        return;
                    }
                    let candidate_app = app.clone();
                    let candidate_lifecycle = lifecycle.clone();
                    // This is only a metadata check and one unlink. Shutdown
                    // can never wait for payload copying or a directory walk.
                    let result = crate::blocking_app_task(move || {
                        if candidate_lifecycle.is_stopping() {
                            return Ok(false);
                        }
                        candidate_app.expire_audit_file(&path)
                    })
                    .await;
                    report_failures(usize::from(result.is_err()));
                }
                if scanner.await.is_err() {
                    report_failures(1);
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

impl MarmotApp {
    pub(crate) fn expire_audit_file(&self, path: &Path) -> Result<bool, AppError> {
        let _storage = self.begin_storage_open("audit retention")?;
        let Some(account) = path.parent() else {
            return Ok(false);
        };
        let Some(container) = account.parent() else {
            return Ok(false);
        };
        if !fs::symlink_metadata(container)?.is_dir()
            || !fs::symlink_metadata(account)?.is_dir()
            || !is_expired(path, cutoff_ms(SystemTime::now()))?
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
        let cutoff = cutoff_ms(SystemTime::now());
        let mut expire = |closed: &Path| {
            let source = marmot_forensics::local_delivery::source_identity(closed)?;
            self.audit_export_lifecycle
                .mutate_source(directory, source, || expire_source_file(closed))
        };
        Ok(match recorder {
            Some(recorder) => recorder.expire_file_before(&path, cutoff, &mut expire)?,
            None => {
                marmot_forensics::NoopRecorder.expire_file_before(&path, cutoff, &mut expire)?
            }
        })
    }
}

fn expire_source_file(path: &Path) -> io::Result<bool> {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains("-v5"))
    {
        let state = path
            .parent()
            .expect("account directory")
            .join("audit-otlp-delivery-v5");
        marmot_forensics::local_delivery::expire_closed_source(path, &state)
    } else {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
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
        cleanup_expired_audit_logs(root.path());
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
        worker.start_with_interval(lifecycle.clone(), Duration::from_millis(10));
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
