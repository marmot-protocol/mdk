//! Retire the app's v1-v3 forensic files after acquiring exclusive root ownership.

use std::fs;
use std::io;
use std::path::Path;

#[derive(Default)]
struct CleanupCounts {
    deleted: usize,
    failed: usize,
}

/// Only call while holding the root lease, before exposing the new app to callers.
/// Scan every account directory, including signed-out or unreadable accounts,
/// independently of audit consent. Failed deletions are retried on the next open.
pub(crate) fn cleanup_legacy_audit_logs(root: &Path) {
    let mut counts = CleanupCounts::default();
    if clean_accounts(&root.join("accounts"), &mut counts).is_err() {
        counts.failed += 1;
    }
    if counts.failed > 0 {
        tracing::warn!(
            target: "marmot_app::audit_log",
            method = "cleanup_legacy_audit_logs",
            deleted = counts.deleted,
            failed = counts.failed,
            "legacy forensic audit cleanup incomplete; will retry on next app open"
        );
    } else if counts.deleted > 0 {
        tracing::info!(
            target: "marmot_app::audit_log",
            method = "cleanup_legacy_audit_logs",
            deleted = counts.deleted,
            "removed legacy forensic audit files"
        );
    }
}

fn clean_accounts(accounts: &Path, counts: &mut CleanupCounts) -> io::Result<()> {
    // The constructor already verified and exclusively leased the root. Do not
    // follow links in the accounts container or either level beneath it.
    match fs::symlink_metadata(accounts) {
        Ok(metadata) if !metadata.is_dir() => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    for entry in fs::read_dir(accounts)? {
        let result = (|| {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                clean_account(&entry.path(), counts)?;
            }
            Ok::<_, io::Error>(())
        })();
        if result.is_err() {
            counts.failed += 1;
        }
    }
    Ok(())
}

fn clean_account(account: &Path, counts: &mut CleanupCounts) -> io::Result<()> {
    for entry in fs::read_dir(account)? {
        let result = (|| {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_str().is_some_and(is_legacy_audit_file_name)
                || !entry.file_type()?.is_file()
            {
                return Ok(());
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => counts.deleted += 1,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            Ok::<_, io::Error>(())
        })();
        if result.is_err() {
            counts.failed += 1;
        }
    }
    Ok(())
}

/// The app's reserved filename convention, not the broad upload/listing glob.
/// This also removes empty, corrupt, or truncated legacy logs without reading
/// their sensitive contents. Custom-named logs and non-legacy versions stay put.
fn is_legacy_audit_file_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix("audit-")
        .and_then(|name| name.strip_suffix(".jsonl"))
    else {
        return false;
    };
    let stem = if let Some((base, index)) = stem.rsplit_once("-seg") {
        // Recorder indices are u32, padded to at least six decimal digits.
        if index.len() < 6
            || !index.bytes().all(|byte| byte.is_ascii_digit())
            || index.parse::<u32>().is_err()
        {
            return false;
        }
        base
    } else {
        stem
    };
    let engine_id = stem
        .strip_suffix("-v1")
        .or_else(|| stem.strip_suffix("-v2"))
        .or_else(|| stem.strip_suffix("-v3"))
        .unwrap_or(stem);
    engine_id.len() == super::AUDIT_ID_BYTES * 2
        && engine_id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{AppError, MarmotApp, MarmotAppConfig, MarmotRootRuntimeLease};
    use marmot_account::AccountHome;
    use std::os::unix::fs::{PermissionsExt, symlink};

    const ENGINE: &str = "0123456789abcdef0123456789abcdef";

    fn open_app(root: &Path) -> Result<MarmotApp, AppError> {
        MarmotApp::try_with_relays_and_account_home_and_config(
            root,
            Vec::new(),
            AccountHome::open(root),
            MarmotAppConfig::default(),
        )
    }

    #[test]
    fn legacy_audit_cleanup_deletes_only_reserved_old_names_at_startup() {
        let root = tempfile::tempdir().unwrap();
        let account = root.path().join("accounts/alice");
        // No valid account record is required to retire the old plaintext files.
        fs::create_dir_all(&account).unwrap();
        let mut old_files = Vec::new();
        for version in ["", "-v1", "-v2", "-v3"] {
            for segment in ["", "-seg000001", "-seg1000000", "-seg4294967295"] {
                let name = format!("audit-{ENGINE}{version}{segment}.jsonl");
                fs::write(account.join(&name), b"PRIVATE_OLD_CONTENT\n{truncated").unwrap();
                old_files.push(name);
            }
        }
        let mut preserved = vec![
            "audit-key-reveal.jsonl".to_owned(),
            "audit-upload-checkpoint.json".to_owned(),
            "audit-device-id".to_owned(),
            "session.db".to_owned(),
            "audit-custom-v3.jsonl".to_owned(),
            format!("audit-{ENGINE}-v3.jsonl.tmp"),
            format!("audit-{ENGINE}-v3-seg1.jsonl"),
            format!("audit-{ENGINE}-v3-seg4294967296.jsonl"),
            format!("audit-{ENGINE}-v3-seg000001-seg000002.jsonl"),
        ];
        for version in ["v4", "v5", "v30"] {
            preserved.push(format!("audit-{ENGINE}-{version}.jsonl"));
            preserved.push(format!("audit-{ENGINE}-{version}-seg000001.jsonl"));
        }
        for other_id in ["g".repeat(32), "a".repeat(31), "a".repeat(33)] {
            preserved.push(format!("audit-{other_id}-v3.jsonl"));
        }
        for name in &preserved {
            fs::write(account.join(name), b"KEEP_EXACT_BYTES").unwrap();
        }
        let nested = account.join("nested");
        fs::create_dir(&nested).unwrap();
        let nested_old = nested.join(&old_files[0]);
        fs::write(&nested_old, b"NOT_AN_ACCOUNT_AUDIT").unwrap();
        let fake_file = account.join(format!("audit-{}-v3.jsonl", "ab".repeat(16)));
        fs::create_dir(&fake_file).unwrap();

        let app = open_app(root.path()).unwrap();
        assert!(!app.audit_log_settings().unwrap().enabled);
        for name in old_files {
            assert!(!account.join(name).exists());
        }
        for name in &preserved {
            assert_eq!(fs::read(account.join(name)).unwrap(), b"KEEP_EXACT_BYTES");
        }
        assert!(fake_file.is_dir());
        assert_eq!(fs::read(&nested_old).unwrap(), b"NOT_AN_ACCOUNT_AUDIT");
        drop(app);
        drop(open_app(root.path()).unwrap()); // Idempotent, including with audit disabled.
        for name in preserved {
            assert_eq!(fs::read(account.join(name)).unwrap(), b"KEEP_EXACT_BYTES");
        }
    }

    #[test]
    fn legacy_audit_cleanup_waits_for_exclusive_root_ownership() {
        let root = tempfile::tempdir().unwrap();
        let account = root.path().join("accounts/alice");
        fs::create_dir_all(&account).unwrap();
        let file = account.join(format!("audit-{ENGINE}-v3.jsonl"));
        fs::write(&file, b"OLD_ACTIVE_RECORDER").unwrap();
        let owner = MarmotRootRuntimeLease::try_acquire(root.path()).unwrap();
        assert!(matches!(open_app(root.path()), Err(AppError::RuntimeBusy)));
        assert_eq!(fs::read(&file).unwrap(), b"OLD_ACTIVE_RECORDER");
        drop(owner);
        let app = open_app(root.path()).unwrap();
        assert!(!file.exists());
        // A new v4 recorder remains live and untouched by a rejected second open.
        app.account_home().create_account("bob").unwrap();
        let recorder = app.build_audit_recorder("bob", true);
        let path = recorder.audit_log_path().unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(open_app(root.path()), Err(AppError::RuntimeBusy)));
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn legacy_audit_cleanup_does_not_follow_links_at_any_scan_level() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let name = format!("audit-{ENGINE}-v3.jsonl");
        let target = external.path().join(&name);
        fs::write(&target, b"EXTERNAL_BYTES").unwrap();
        let external_account = external.path().join("victim");
        fs::create_dir(&external_account).unwrap();
        let nested_target = external_account.join(&name);
        fs::write(&nested_target, b"EXTERNAL_ACCOUNT_BYTES").unwrap();
        let accounts = root.path().join("accounts");
        symlink(external.path(), &accounts).unwrap();
        drop(open_app(root.path()).unwrap());
        assert_eq!(fs::read(&target).unwrap(), b"EXTERNAL_BYTES");
        assert_eq!(fs::read(&nested_target).unwrap(), b"EXTERNAL_ACCOUNT_BYTES");
        fs::remove_file(&accounts).unwrap();
        fs::create_dir(&accounts).unwrap();
        symlink(external.path(), accounts.join("linked-account")).unwrap();
        let real_account = accounts.join("real-account");
        fs::create_dir(&real_account).unwrap();
        symlink(&target, real_account.join(&name)).unwrap();
        drop(open_app(root.path()).unwrap());
        assert_eq!(fs::read(target).unwrap(), b"EXTERNAL_BYTES");
        assert!(
            fs::symlink_metadata(real_account.join(name))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn legacy_audit_cleanup_failure_does_not_block_open_and_retries_later() {
        let root = tempfile::tempdir().unwrap();
        let blocked = root.path().join("accounts/blocked");
        let healthy = root.path().join("accounts/healthy");
        fs::create_dir_all(&blocked).unwrap();
        fs::create_dir_all(&healthy).unwrap();
        let name = format!("audit-{ENGINE}-v2.jsonl");
        fs::write(blocked.join(&name), b"OLD").unwrap();
        fs::write(healthy.join(&name), b"OLD").unwrap();
        // Probe whether this test process bypasses directory permissions (root).
        let probe = blocked.join("permission-probe");
        fs::write(&probe, b"").unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o500)).unwrap();
        if fs::remove_file(&probe).is_ok() {
            fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
            eprintln!("permission failure scenario requires an unprivileged test process");
            return;
        }
        let result = open_app(root.path());
        // Restore permissions before assertions so temp cleanup works on failure.
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700)).unwrap();
        let app = result.unwrap();
        assert!(blocked.join(&name).exists());
        assert!(!healthy.join(&name).exists());
        drop(app);
        drop(open_app(root.path()).unwrap());
        assert!(!blocked.join(name).exists());
    }
}
