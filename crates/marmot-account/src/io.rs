//! Filesystem JSON read/write helpers and account-label validation.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bound on re-reads of a secret file that keeps being replaced mid-read.
const SECRET_READ_ATTEMPTS: usize = 8;

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_secret_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = read_linked_secret(path.as_ref(), || {})?;
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

/// Read key material that a concurrent [`FileMode::Secret`] replacement or
/// [`remove_file_then_scrub`] may race.
///
/// Both zero the old inode after unlinking it, so a reader that opened it
/// first can read zeros. A read counts only if its inode was still linked once
/// the read finished, which puts it before that scrub. A removal whose unlink
/// fails zeroes the linked file in place; that read fails to parse instead of
/// yielding a key. `after_open` lets tests replace the file inside that window.
fn read_linked_secret(path: &Path, mut after_open: impl FnMut()) -> io::Result<Zeroizing<Vec<u8>>> {
    for _ in 0..SECRET_READ_ATTEMPTS {
        let mut file = File::open(path)?;
        after_open();
        let mut bytes = Zeroizing::new(Vec::new());
        file.read_to_end(&mut bytes)?;
        if still_linked(&file)? {
            return Ok(bytes);
        }
    }
    Err(io::Error::other(
        "secret file was replaced during every read",
    ))
}

#[cfg(unix)]
fn still_linked(file: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    Ok(file.metadata()?.nlink() > 0)
}

/// Without a portable link count, other platforms accept every read.
#[cfg(not(unix))]
fn still_linked(_file: &File) -> io::Result<bool> {
    Ok(true)
}

pub(crate) fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> AccountHomeResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_file_atomically(path.as_ref(), &bytes, FileMode::Public)
}

pub(crate) fn write_private_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_file_atomically(path.as_ref(), &bytes, FileMode::Private)
}

pub(crate) fn write_private_bytes(path: impl AsRef<Path>, bytes: &[u8]) -> AccountHomeResult<()> {
    write_file_atomically(path.as_ref(), bytes, FileMode::Private)
}

/// Key material only: read it back with [`read_secret_json`].
pub(crate) fn write_secret_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    write_file_atomically(path.as_ref(), bytes.as_slice(), FileMode::Secret)
}

/// Every mode publishes by renaming a synced temp file over the target, so on
/// Unix a reader sees the complete previous file or the complete new one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMode {
    Public,
    /// Owner-only. The replaced inode is left intact for readers that still
    /// hold it open.
    Private,
    /// Owner-only key material. Failed temp files and the replaced inode are
    /// zeroed, so readers must reject reads of an unlinked inode.
    Secret,
}

fn write_file_atomically(path: &Path, bytes: &[u8], mode: FileMode) -> AccountHomeResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    fs_private::create_dir_all_private(parent)?;

    let (mut file, temp_path) = create_temp_file(parent, path, mode)?;
    let result = (|| -> AccountHomeResult<()> {
        file.write_all(bytes)?;

        #[cfg(unix)]
        if mode != FileMode::Public {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }

        file.sync_all()?;
        drop(file);

        let mut replaced_secret_file = if mode == FileMode::Secret {
            match open_file_for_zero_overwrite(path) {
                Ok(file) => Some(file),
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            }
        } else {
            None
        };
        replace_file(&temp_path, path)?;
        // The handle still refers to the replaced inode after the atomic rename,
        // so scrub it without creating a window where the live secret path is
        // zeroed if replacement fails. Best-effort, matching secret deletion.
        if let Some(file) = &mut replaced_secret_file {
            let _ = overwrite_open_file_with_zeros(file);
        }
        sync_directory(parent)?;
        Ok(())
    })();

    if result.is_err() {
        if mode == FileMode::Secret {
            let _ = overwrite_file_with_zeros(&temp_path);
        }
        let _ = fs::remove_file(&temp_path);
    }

    result
}

/// Unlink `path`, then zero the removed inode through a handle opened first.
///
/// Readers therefore see the complete file or no file, never a zeroed one
/// that is still linked. If the unlink fails, the file is zeroed in place
/// anyway: a failed removal still destroys the key material and surfaces the
/// error. The scrub is best-effort, and symlinks and hard-linked files are
/// unlinked unscrubbed.
pub(crate) fn remove_file_then_scrub(path: &Path) -> io::Result<()> {
    let mut removed_file = match open_file_for_zero_overwrite(path) {
        Ok(file) => Some(file),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => None,
    };
    let removed = fs::remove_file(path);
    if let Some(file) = &mut removed_file {
        let _ = overwrite_open_file_with_zeros(file);
    }
    match removed {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
        _ => Ok(()),
    }
}

/// Best-effort in-place zero overwrite used before unlinking files that may
/// contain plaintext key material and that no reader opens, such as a failed
/// write's temp file. Live paths go through [`remove_file_then_scrub`].
pub(crate) fn overwrite_file_with_zeros(path: &Path) -> io::Result<()> {
    let mut file = open_file_for_zero_overwrite(path)?;
    overwrite_open_file_with_zeros(&mut file)
}

fn open_file_for_zero_overwrite(path: &Path) -> io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret scrub target must be a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret scrub target must have exactly one hard link",
            ));
        }
    }
    Ok(file)
}

fn overwrite_open_file_with_zeros(file: &mut File) -> io::Result<()> {
    let len = file.metadata()?.len();
    if len > 0 {
        let zeros = vec![0u8; len as usize];
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&zeros)?;
        file.sync_all()?;
    }
    Ok(())
}

fn create_temp_file(
    parent: &Path,
    path: &Path,
    mode: FileMode,
) -> AccountHomeResult<(File, PathBuf)> {
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target must name a file",
        )
    })?;

    for _ in 0..32 {
        let attempt = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(file_name);
        temp_name.push(format!(".tmp.{}.{}", std::process::id(), attempt));
        let temp_path = parent.join(temp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        if mode != FileMode::Public {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&temp_path) {
            Ok(file) => return Ok((file, temp_path)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique atomic write temp file",
    )
    .into())
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temp_path, path)
}

#[cfg(not(windows))]
fn replace_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) fn validate_account_label(label: &str) -> AccountHomeResult<()> {
    let mut components = Path::new(label).components();
    let is_single_normal_component =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();

    if !is_single_normal_component
        || label.contains('/')
        || label.contains('\\')
        || label.contains(':')
        || label.chars().any(char::is_control)
    {
        return Err(AccountHomeError::InvalidAccountLabel(label.to_owned()));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn secret_write_creates_account_directory_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let account_dir = root.path().join("accounts").join("alice");
        let secret_path = account_dir.join("secret.json");

        write_secret_json(&secret_path, &serde_json::json!({ "secret": "test" })).unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&account_dir), 0o700);
        assert_eq!(mode(&secret_path), 0o600);
    }

    #[test]
    fn failed_secret_atomic_write_scrubs_temp_before_unlink() {
        let source = include_str!("io.rs");
        let cleanup = source
            .split("if result.is_err()")
            .nth(1)
            .unwrap()
            .split("result\n}")
            .next()
            .unwrap();

        assert!(
            cleanup.find("overwrite_file_with_zeros").unwrap()
                < cleanup.find("remove_file").unwrap()
        );
    }

    #[test]
    fn replacing_secret_scrubs_the_replaced_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(&secret_path, &serde_json::json!({ "secret": "old-key" })).unwrap();
        let mut old_inode = File::open(&secret_path).unwrap();

        write_secret_json(&secret_path, &serde_json::json!({ "secret": "new-key" })).unwrap();

        let mut replaced_bytes = Vec::new();
        old_inode.read_to_end(&mut replaced_bytes).unwrap();
        assert!(replaced_bytes.iter().all(|byte| *byte == 0));
        assert!(
            fs::read_to_string(&secret_path)
                .unwrap()
                .contains("new-key")
        );
    }

    /// A reader that opened a private file just before its replacement still
    /// reads the whole previous version, so it never parses zeros.
    #[test]
    fn private_replacement_leaves_open_readers_the_previous_file() {
        let root = tempfile::tempdir().unwrap();
        let json_path = root.path().join("account").join("journal.json");
        let bytes_path = root.path().join("account").join("checkpoint.json");
        write_private_json(&json_path, &serde_json::json!({ "phase": "old" })).unwrap();
        write_private_bytes(&bytes_path, br#"{"revision":1}"#).unwrap();
        let mut json_reader = File::open(&json_path).unwrap();
        let mut bytes_reader = File::open(&bytes_path).unwrap();

        write_private_json(&json_path, &serde_json::json!({ "phase": "new" })).unwrap();
        write_private_bytes(&bytes_path, br#"{"revision":2}"#).unwrap();

        let mut previous = Vec::new();
        json_reader.read_to_end(&mut previous).unwrap();
        let previous: serde_json::Value = serde_json::from_slice(&previous).unwrap();
        assert_eq!(previous["phase"], "old");
        let mut previous = Vec::new();
        bytes_reader.read_to_end(&mut previous).unwrap();
        assert_eq!(previous, br#"{"revision":1}"#);
        assert_eq!(
            read_json::<serde_json::Value>(&json_path).unwrap()["phase"],
            "new"
        );
        assert_eq!(fs::read(&bytes_path).unwrap(), br#"{"revision":2}"#);
        for path in [&json_path, &bytes_path] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn secret_read_retries_past_a_replacement_that_scrubbed_its_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(&secret_path, &serde_json::json!({ "secret": "old-key" })).unwrap();
        let mut opens = 0;

        let bytes = read_linked_secret(&secret_path, || {
            opens += 1;
            if opens == 1 {
                let mut old_inode = File::open(&secret_path).unwrap();
                write_secret_json(&secret_path, &serde_json::json!({ "secret": "new-key" }))
                    .unwrap();
                let mut scrubbed = Vec::new();
                old_inode.read_to_end(&mut scrubbed).unwrap();
                assert!(scrubbed.iter().all(|byte| *byte == 0));
            }
        })
        .unwrap();

        assert_eq!(opens, 2);
        let secret: serde_json::Value = serde_json::from_slice(bytes.as_slice()).unwrap();
        assert_eq!(secret["secret"], "new-key");
    }

    #[test]
    fn secret_read_reports_a_removal_instead_of_its_scrubbed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(&secret_path, &serde_json::json!({ "secret": "old-key" })).unwrap();

        let err = read_linked_secret(&secret_path, || {
            remove_file_then_scrub(&secret_path).unwrap();
        })
        .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn secret_read_gives_up_rather_than_return_a_scrubbed_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(&secret_path, &serde_json::json!({ "secret": 0 })).unwrap();
        let mut replacements = 0;

        let err = read_linked_secret(&secret_path, || {
            replacements += 1;
            write_secret_json(&secret_path, &serde_json::json!({ "secret": replacements }))
                .unwrap();
        })
        .unwrap_err();

        assert_eq!(replacements, SECRET_READ_ATTEMPTS);
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn removing_a_secret_unlinks_before_scrubbing() {
        let source = include_str!("io.rs");
        let removal = source
            .split("fn remove_file_then_scrub")
            .nth(1)
            .unwrap()
            .split("\n}\n")
            .next()
            .unwrap();

        assert!(
            removal.find("fs::remove_file").unwrap()
                < removal.find("overwrite_open_file_with_zeros").unwrap()
        );
    }

    #[test]
    fn removing_a_secret_scrubs_the_removed_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(&secret_path, &serde_json::json!({ "secret": "old-key" })).unwrap();
        let mut reader = File::open(&secret_path).unwrap();

        remove_file_then_scrub(&secret_path).unwrap();

        assert!(!secret_path.exists());
        assert_eq!(reader.metadata().unwrap().nlink(), 0);
        let mut scrubbed = Vec::new();
        reader.read_to_end(&mut scrubbed).unwrap();
        assert!(!scrubbed.is_empty());
        assert!(scrubbed.iter().all(|byte| *byte == 0));
    }
}
