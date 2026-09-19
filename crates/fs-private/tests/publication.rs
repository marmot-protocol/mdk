#![cfg(unix)]

// Run process-spawning publication tests in their own test binary so a child
// cannot temporarily inherit another unit test's advisory lock before exec.
use fs_private::rename_noreplace_with_lock;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn publication_lock_path(destination: &Path) -> PathBuf {
    let mut name = destination.file_name().unwrap().to_os_string();
    name.push(".publish.lock");
    destination.with_file_name(name)
}

#[test]
fn publication_preserves_existing_entries_and_private_modes() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("salt");
    let stage = dir.path().join("staging");
    fs_private::write_private(&stage, b"winner").unwrap();
    rename_noreplace_with_lock(&stage, &target).unwrap();
    assert!(!stage.exists());
    let lock = publication_lock_path(&target);
    let inode = fs::metadata(&lock).unwrap().ino();
    for path in [&target, &lock] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs_private::write_private(&stage, b"loser").unwrap();
    assert_eq!(
        rename_noreplace_with_lock(&stage, &target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&target).unwrap(), b"winner");
    assert_eq!(fs::read(&stage).unwrap(), b"loser");
    assert_eq!(fs::metadata(&lock).unwrap().ino(), inode);

    let dangling = dir.path().join("dangling");
    symlink(dir.path().join("absent"), &dangling).unwrap();
    assert_eq!(
        rename_noreplace_with_lock(&stage, &dangling)
            .unwrap_err()
            .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert!(
        fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn publication_rejects_symlink_lock_and_releases_lock_after_error() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("salt");
    let stage = dir.path().join("staging");
    let lock = publication_lock_path(&target);
    let unrelated = dir.path().join("unrelated");
    fs_private::write_private(&unrelated, b"untouched").unwrap();
    symlink(&unrelated, &lock).unwrap();
    fs_private::write_private(&stage, b"salt").unwrap();
    assert!(rename_noreplace_with_lock(&stage, &target).is_err());
    assert_eq!(fs::read(&unrelated).unwrap(), b"untouched");
    assert!(!target.exists());
    fs::remove_file(&lock).unwrap(); // No live publisher: remove the test symlink only.
    assert!(rename_noreplace_with_lock(&dir.path().join("missing"), &target).is_err());
    rename_noreplace_with_lock(&stage, &target).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"salt");
}

// Invoked in fresh processes so the race cannot accidentally be protected
// by an in-process Rust mutex. The parent holds the publication lock until
// every child has staged and synced different complete candidate bytes.
#[test]
fn publication_child_process() {
    let Some(root) = std::env::var_os("FS_PRIVATE_PUBLICATION_CHILD_ROOT") else {
        return;
    };
    let root = Path::new(&root);
    let id: u8 = std::env::var("FS_PRIVATE_PUBLICATION_CHILD_ID")
        .unwrap()
        .parse()
        .unwrap();
    let target = root.join("salt");
    let stage = root.join(format!("staging-{id}"));
    fs_private::write_private(&stage, &vec![id; 65_536]).unwrap();
    if std::env::var_os("FS_PRIVATE_PUBLICATION_CRASH").is_some() {
        let lock = publication_lock_path(&target);
        let _lease = fs_private::try_acquire_private_exclusive_file_lease(&lock).unwrap();
        // An interrupted publisher must neither install partial contents
        // nor leave a stale lock that requires deletion to recover.
        unsafe { libc::_exit(0) }
    }
    fs::write(root.join(format!("ready-{id}")), b"ready").unwrap();
    let result = rename_noreplace_with_lock(&stage, &target);
    let won = match result {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => panic!("publication failed: {error}"),
    };
    let bytes = fs::read(&target).unwrap();
    assert_eq!(bytes.len(), 65_536);
    assert!(bytes.iter().all(|byte| *byte == bytes[0]));
    if won {
        assert_eq!(bytes[0], id);
    }
    fs::write(
        root.join(format!("result-{id}")),
        if won { "won" } else { "lost" },
    )
    .unwrap();
}

fn child(root: &Path, id: u8) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "publication_child_process", "--nocapture"])
        .env("FS_PRIVATE_PUBLICATION_CHILD_ROOT", root)
        .env("FS_PRIVATE_PUBLICATION_CHILD_ID", id.to_string())
        .stdout(Stdio::null());
    command
}

#[test]
fn publication_serializes_processes_and_recovers_after_abrupt_exit() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        child(dir.path(), 9)
            .env("FS_PRIVATE_PUBLICATION_CRASH", "1")
            .status()
            .unwrap()
            .success()
    );
    let target = dir.path().join("salt");
    assert!(!target.exists());
    let lock = publication_lock_path(&target);
    let lease = fs_private::try_acquire_private_exclusive_file_lease(&lock).unwrap();
    let mut children: Vec<_> = (1..=4)
        .map(|id| child(dir.path(), id).spawn().unwrap())
        .collect();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !(1..=4).all(|id| dir.path().join(format!("ready-{id}")).exists()) {
        assert!(
            Instant::now() < deadline,
            "children failed to reach publication"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!target.exists(), "publication must wait for the file lock");
    assert!(
        children
            .iter_mut()
            .all(|child| child.try_wait().unwrap().is_none())
    );
    drop(lease);
    for mut child in children {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("publication child did not finish");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(
        (1..=4)
            .filter(|id| fs::read(dir.path().join(format!("result-{id}"))).unwrap() == b"won")
            .count(),
        1
    );
    assert_eq!(
        fs::read(dir.path().join("staging-9")).unwrap(),
        vec![9; 65_536]
    );
    assert_ne!(
        fs::read(&target).unwrap()[0],
        9,
        "never adopt an interrupted staging file"
    );
    drop(fs_private::try_acquire_private_exclusive_file_lease(&lock).unwrap());
}
