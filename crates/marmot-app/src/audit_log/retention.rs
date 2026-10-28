//! Fixed local diagnostic history; independent of recording consent and upload.

use std::fs;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use marmot_forensics::ForensicRecorder;

use crate::{AppError, MarmotApp};

const AUDIT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub(crate) const AUDIT_RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

fn cutoff_ms(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .saturating_sub(AUDIT_RETENTION)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Exclusive-root startup only: there are no live writers or export attempts.
/// Include dormant accounts and failed-wipe remnants even with consent off.
pub(crate) fn cleanup_expired_audit_logs(root: &Path) {
    let cutoff = cutoff_ms(SystemTime::now());
    let mut failed = 0;
    for container in ["accounts", ".wipe-tombstones"] {
        let path = root.join(container);
        let result = (|| {
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Ok(metadata) if metadata.is_dir() => {}
                _ => return Err(io::Error::other("unexpected audit container")),
            }
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir()
                    && prune_account(&entry.path(), cutoff, None).is_err()
                {
                    failed += 1;
                }
            }
            Ok::<_, io::Error>(())
        })();
        failed += usize::from(result.is_err());
    }
    report_failures(failed);
}

impl MarmotApp {
    pub(crate) fn prune_account_audit_logs(
        &self,
        label: &str,
        recorder: &marmot_forensics::SharedRecorder,
    ) -> Result<(), AppError> {
        let _storage = self.begin_storage_open("audit retention")?;
        let account = self.account_home().account(label)?;
        let _mutation = self
            .audit_export_lifecycle
            .mutate_account(&account.account_id_hex);
        let cutoff = cutoff_ms(SystemTime::now());
        recorder.prune_before(cutoff)?;
        let active = recorder.audit_log_path();
        // The recorder owns its entire segment family, including the actual
        // writer path after failed rename compensation; never unlink those
        // files from the generic closed-file pass.
        prune_account(&self.account_dir(label), cutoff, active.as_deref())?;
        Ok(())
    }
}

fn prune_account(account: &Path, cutoff: u64, live: Option<&Path>) -> io::Result<()> {
    let mut failed = 0;
    for entry in fs::read_dir(account)? {
        let result = (|| {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Ok(());
            };
            if name
                .strip_suffix("-retention")
                .is_some_and(is_retained_audit_file)
                && entry.file_type()?.is_file()
            {
                // Remove an interrupted atomic replacement even if its source
                // was subsequently deleted through the host's file UI.
                fs::remove_file(entry.path())?;
                return Ok(());
            }
            if !is_retained_audit_file(name) || !entry.file_type()?.is_file() {
                return Ok(());
            }
            if let Some(stem) = live.and_then(|p| p.file_stem()).and_then(|s| s.to_str())
                && (name == format!("{stem}.jsonl") || name.starts_with(&format!("{stem}-seg")))
            {
                return Ok(());
            }
            marmot_forensics::audit::prune_jsonl_file_before(&entry.path(), cutoff)?;
            Ok::<_, io::Error>(())
        })();
        failed += usize::from(result.is_err());
    }
    if failed > 0 {
        report_failures(failed);
        return Err(io::Error::other("audit retention incomplete"));
    }
    Ok(())
}

fn report_failures(failed: usize) {
    if failed > 0 {
        tracing::warn!(target: "marmot_app::audit_log", method = "prune_audit_logs",
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

    #[test]
    fn audit_retention_runs_on_exclusive_open_with_recording_disabled() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        let name = format!("audit-{}-v4.jsonl", "a".repeat(32));
        let path = home.account_dir("alice").join(name);
        let recent = format!(
            "{{\"wall_time_ms\":{}}}\n",
            cutoff_ms(SystemTime::now()) + 60_000
        );
        fs::write(&path, format!("{{\"wall_time_ms\":1}}\n{recent}")).unwrap();
        let app = MarmotApp::try_with_relays_and_account_home_and_config(
            root.path(),
            Vec::new(),
            home,
            crate::MarmotAppConfig::white_noise(),
        )
        .unwrap();
        assert!(!app.audit_log_settings().unwrap().enabled);
        assert_eq!(fs::read_to_string(path).unwrap(), recent);
    }

    #[test]
    fn audit_retention_fences_delivery_and_preserves_live_recording() {
        let root = tempfile::tempdir().unwrap();
        let home = marmot_account::AccountHome::open(root.path());
        let account = home.create_account("alice").unwrap();
        let app = MarmotApp::with_relays_and_account_home(root.path(), Vec::new(), home);
        let path = app
            .account_dir("alice")
            .join(format!("audit-{}-v5.jsonl", "a".repeat(32)));
        fs::write(&path, b"{\"wall_time_ms\":1}\n").unwrap();
        let audit = marmot_forensics::SharedRecorder::new(Box::new(
            marmot_forensics::JsonlRecorder::open_v5_with_account_ref(
                &path,
                "a".repeat(32),
                None,
                super::super::audit_v5_producer(),
            )
            .unwrap(),
        ));
        let before = fs::read(&path).unwrap();
        let attempt = app
            .audit_export_lifecycle
            .reserve(&account.account_id_hex, "test")
            .unwrap();
        app.prune_account_audit_logs("alice", &audit).unwrap();
        assert!(app.audit_export_lifecycle.admit(&attempt, || ()).is_none());
        assert_eq!(
            fs::read(&path).unwrap(),
            before[b"{\"wall_time_ms\":1}\n".len()..]
        );
        audit.record(marmot_forensics::AuditRecord::new(
            None,
            marmot_forensics::AuditEventKind::RecorderHealth {
                serialization_failures: 0,
                write_failures: 0,
                flush_failures: 0,
            },
        ));
        assert!(
            fs::metadata(path).unwrap().len()
                > (before.len() - b"{\"wall_time_ms\":1}\n".len()) as u64
        );
        app.close_storage().unwrap();
        assert!(app.prune_account_audit_logs("alice", &audit).is_err());
    }

    #[test]
    fn audit_retention_cleans_dormant_accounts_and_wipe_remnants_without_following_links() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let name = format!("audit-{}-v5.jsonl", "a".repeat(32));
        fs::write(external.path().join(&name), b"{\"wall_time_ms\":1}\n").unwrap();
        for container in ["accounts", ".wipe-tombstones"] {
            let account = root.path().join(container).join("dormant");
            fs::create_dir_all(&account).unwrap();
            fs::write(account.join(&name), b"{\"wall_time_ms\":1}\n").unwrap();
            fs::write(
                account.join(format!("{name}-retention")),
                b"interrupted copy",
            )
            .unwrap();
            let v4_segment = format!("audit-{}-v4-seg000001.jsonl", "b".repeat(32));
            fs::write(account.join(v4_segment), b"{\"wall_time_ms\":1}\n").unwrap();
            fs::write(
                account.join("audit-key-reveal.jsonl"),
                b"{\"wall_time_ms\":1}\n",
            )
            .unwrap();
            fs::write(
                account.join("audit-custom.jsonl"),
                b"{\"wall_time_ms\":1}\n",
            )
            .unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink(external.path(), root.path().join(container).join("linked"))
                .unwrap();
        }
        cleanup_expired_audit_logs(root.path());
        for container in ["accounts", ".wipe-tombstones"] {
            let account = root.path().join(container).join("dormant");
            assert!(!account.join(&name).exists());
            assert!(!account.join(format!("{name}-retention")).exists());
            assert!(
                !account
                    .join(format!("audit-{}-v4-seg000001.jsonl", "b".repeat(32)))
                    .exists()
            );
            assert!(account.join("audit-key-reveal.jsonl").exists());
            assert!(account.join("audit-custom.jsonl").exists());
        }
        assert!(external.path().join(name).exists());
        assert_eq!(cutoff_ms(UNIX_EPOCH + AUDIT_RETENTION), 0);
    }
}
