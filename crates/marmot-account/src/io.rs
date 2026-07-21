//! Filesystem JSON read/write helpers and account-label validation.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{AccountHomeError, AccountHomeResult};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_secret_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = Zeroizing::new(fs::read(path)?);
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

pub(crate) fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> AccountHomeResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_file_atomically(path.as_ref(), &bytes, FileMode::Public)
}

pub(crate) fn write_secret_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    write_file_atomically(path.as_ref(), bytes.as_slice(), FileMode::Private)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMode {
    Public,
    Private,
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
        if mode == FileMode::Private {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }

        file.sync_all()?;
        drop(file);

        replace_file(&temp_path, path)?;
        sync_directory(parent)?;
        Ok(())
    })();

    if result.is_err() {
        if mode == FileMode::Private {
            let _ = overwrite_file_with_zeros(&temp_path);
        }
        let _ = fs::remove_file(&temp_path);
    }

    result
}

/// Best-effort in-place zero overwrite used before unlinking files that may
/// contain plaintext key material.
pub(crate) fn overwrite_file_with_zeros(path: &Path) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
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
    let len = metadata.len();
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
        if mode == FileMode::Private {
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
    use std::os::unix::fs::PermissionsExt;

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
    fn failed_private_atomic_write_scrubs_temp_before_unlink() {
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
}
