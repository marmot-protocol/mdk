//! Retire the app's v1-v3 forensic files after acquiring exclusive root ownership.

use std::fs;
use std::io;
use std::path::Path;

// These describe the on-disk history, independently of future account layout
// or audit ID changes. Never redirect cleanup outside the exclusively leased root.
const LEGACY_CONTAINERS: [&str; 2] = ["accounts", ".wipe-tombstones"];
const LEGACY_ENGINE_ID_HEX_LEN: usize = 32;

#[derive(Default)]
struct CleanupCounts {
    deleted: usize,
    failed: usize,
}

/// Only call while holding the root lease, before exposing the new app to callers.
/// Scan account directories and failed-wipe remnants, including unreadable accounts,
/// independently of audit consent. Failed deletions are retried on the next open.
pub(crate) fn cleanup_legacy_audit_logs(root: &Path) {
    let mut counts = CleanupCounts::default();
    for container in LEGACY_CONTAINERS {
        if clean_container(&root.join(container), &mut counts).is_err() {
            counts.failed += 1;
        }
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

fn clean_container(container: &Path, counts: &mut CleanupCounts) -> io::Result<()> {
    // The constructor already verified and exclusively leased the root. Do not
    // follow links in a container or either level beneath it. An unexpected
    // container is observable as a cleanup failure; only absence is a quiet no-op.
    match fs::symlink_metadata(container) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "legacy audit container is not a real directory",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    for entry in fs::read_dir(container)? {
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
/// their sensitive contents. Names outside the reserved forms stay put; a
/// custom file that collides with a reserved legacy name is still deleted.
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
    engine_id.len() == LEGACY_ENGINE_ID_HEX_LEN
        && engine_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod classifier_tests {
    use super::*;

    #[test]
    fn legacy_audit_cleanup_matches_the_frozen_filename_convention() {
        let engine = "0123456789abcdef0123456789abcdef";
        for version in ["", "-v1", "-v2", "-v3"] {
            for segment in ["", "-seg000001", "-seg1000000", "-seg4294967295"] {
                let name = format!("audit-{engine}{version}{segment}.jsonl");
                assert!(is_legacy_audit_file_name(&name), "{name}");
            }
        }
        for suffix in [
            "-v4",
            "-v5",
            "-v10",
            "-v30",
            "-v1-v1",
            "-v3-seg",
            "-v3-seg1",
            "-v3-seg00000a",
            "-v3-seg4294967296",
            "-v3-seg000001-seg000002",
            "-v4-seg000001",
        ] {
            let name = format!("audit-{engine}{suffix}.jsonl");
            assert!(!is_legacy_audit_file_name(&name), "{name}");
        }
        for other_id in [
            engine.to_uppercase(),
            "g".repeat(32),
            "a".repeat(31),
            "a".repeat(33),
            "é".repeat(16),
        ] {
            let name = format!("audit-{other_id}-v3.jsonl");
            assert!(!is_legacy_audit_file_name(&name), "{name}");
        }
        for name in [
            "audit-key-reveal.jsonl".to_owned(),
            "audit-custom-v3.jsonl".to_owned(),
            format!("audit-{engine}-v3.jsonl.tmp"),
            format!("other-{engine}-v3.jsonl"),
        ] {
            assert!(!is_legacy_audit_file_name(&name), "{name}");
        }
    }
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
        let home = AccountHome::open(root.path());
        home.create_account("alice").unwrap();
        // Use AccountHome's actual layout so drift cannot leave the test green.
        let account = home.account_dir("alice");
        let old_files = ["", "-v2", "-v3", "-v3-seg000001"]
            .map(|suffix| format!("audit-{ENGINE}{suffix}.jsonl"));
        for name in &old_files {
            fs::write(account.join(name), b"PRIVATE_OLD_CONTENT\n{truncated").unwrap();
        }
        let preserved = [
            "audit-key-reveal.jsonl".to_owned(),
            "audit-upload-checkpoint.json".to_owned(),
            "audit-device-id".to_owned(),
            "session.db".to_owned(),
            "audit-custom-v3.jsonl".to_owned(),
            format!("audit-{ENGINE}-v3.jsonl.tmp"),
            format!("audit-{ENGINE}-v4.jsonl"),
            format!("audit-{ENGINE}-v4-seg000001.jsonl"),
            format!("audit-{ENGINE}-v5.jsonl"),
        ];
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
        let account = AccountHome::open(root.path()).account_dir("alice");
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
        for container in LEGACY_CONTAINERS {
            let root = tempfile::tempdir().unwrap();
            let external = tempfile::tempdir().unwrap();
            let name = format!("audit-{ENGINE}-v3.jsonl");
            let target = external.path().join(&name);
            fs::write(&target, b"EXTERNAL_BYTES").unwrap();
            let external_account = external.path().join("victim");
            fs::create_dir(&external_account).unwrap();
            let nested_target = external_account.join(&name);
            fs::write(&nested_target, b"EXTERNAL_ACCOUNT_BYTES").unwrap();
            let accounts = root.path().join(container);
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
    }

    #[test]
    fn legacy_audit_cleanup_never_scans_an_unleased_account_home() {
        let root = tempfile::tempdir().unwrap();
        let external = tempfile::tempdir().unwrap();
        let home = AccountHome::open(external.path());
        let account = home.account_dir("alice");
        fs::create_dir_all(&account).unwrap();
        let file = account.join(format!("audit-{ENGINE}-v3.jsonl"));
        fs::write(&file, b"OUTSIDE_LEASED_ROOT").unwrap();
        // A mismatched embedding must never redirect deletion to the unleased
        // AccountHome, whether the constructor accepts or rejects that config.
        let _app = MarmotApp::try_with_relays_and_account_home_and_config(
            root.path(),
            Vec::new(),
            home,
            MarmotAppConfig::default(),
        );
        assert_eq!(fs::read(file).unwrap(), b"OUTSIDE_LEASED_ROOT");
    }

    #[test]
    fn legacy_audit_cleanup_reports_invalid_containers_and_continues() {
        let root = tempfile::tempdir().unwrap();
        let accounts = root.path().join("accounts");
        fs::write(&accounts, b"UNEXPECTED_CONTAINER_FILE").unwrap();
        let mut counts = CleanupCounts::default();
        assert!(clean_container(&accounts, &mut counts).is_err());
        let remnant = root.path().join(".wipe-tombstones/orphan");
        fs::create_dir_all(&remnant).unwrap();
        let old = remnant.join(format!("audit-{ENGINE}-v3.jsonl"));
        fs::write(&old, b"OLD").unwrap();
        drop(open_app(root.path()).unwrap());
        assert!(!old.exists());
        assert_eq!(fs::read(&accounts).unwrap(), b"UNEXPECTED_CONTAINER_FILE");
        fs::remove_file(&accounts).unwrap();
        symlink(&remnant, &accounts).unwrap();
        assert!(clean_container(&accounts, &mut counts).is_err());
    }

    #[test]
    fn legacy_audit_cleanup_removes_logs_left_by_a_failed_account_wipe() {
        use marmot_account::{
            AccountHomeResult, AccountSecretStore, AccountSummary, LocalFileSecretStore,
        };

        struct FailSecretRemoval(LocalFileSecretStore);
        impl AccountSecretStore for FailSecretRemoval {
            fn has_secret_for_label(&self, label: &str) -> AccountHomeResult<bool> {
                self.0.has_secret_for_label(label)
            }
            fn write_secret(
                &self,
                account: &AccountSummary,
                keys: &nostr::Keys,
            ) -> AccountHomeResult<()> {
                self.0.write_secret(account, keys)
            }
            fn load_secret(&self, account: &AccountSummary) -> AccountHomeResult<nostr::Keys> {
                self.0.load_secret(account)
            }
            fn remove_secret(&self, _account: &AccountSummary) -> AccountHomeResult<()> {
                Err(io::Error::from(io::ErrorKind::PermissionDenied).into())
            }
        }

        let root = tempfile::tempdir().unwrap();
        let home = AccountHome::open_with_secret_store(
            root.path(),
            std::sync::Arc::new(FailSecretRemoval(LocalFileSecretStore::new(root.path()))),
        );
        home.create_account("alice").unwrap();
        let account = home.account_dir("alice");
        let old = format!("audit-{ENGINE}-v2.jsonl");
        let v4 = format!("audit-{ENGINE}-v4.jsonl");
        for name in [&old, &v4, "audit-key-reveal.jsonl"] {
            fs::write(account.join(name), b"PRESERVED_UNTIL_CLEANUP").unwrap();
        }
        // Exercise the real rename-to-tombstone path. A credential-store error
        // after the rename leaves the removed account's files outside accounts/.
        assert!(home.remove_account("alice").is_err());
        let remnant = fs::read_dir(root.path().join(".wipe-tombstones"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        assert!(!account.exists());
        assert!(remnant.join(&old).exists());
        drop(open_app(root.path()).unwrap());
        assert!(!remnant.join(old).exists());
        for name in [&v4, "audit-key-reveal.jsonl"] {
            assert_eq!(
                fs::read(remnant.join(name)).unwrap(),
                b"PRESERVED_UNTIL_CLEANUP"
            );
        }
    }

    #[test]
    fn legacy_audit_cleanup_failure_does_not_block_open_and_retries_later() {
        let root = tempfile::tempdir().unwrap();
        let home = AccountHome::open(root.path());
        let blocked = home.account_dir("blocked");
        let healthy = home.account_dir("healthy");
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
