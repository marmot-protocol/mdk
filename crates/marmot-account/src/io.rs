//! Filesystem JSON read/write helpers and account-label validation.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
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
    fs::create_dir_all(parent)?;

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
        let _ = fs::remove_file(&temp_path);
    }

    result
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
    {
        return Err(AccountHomeError::InvalidAccountLabel(label.to_owned()));
    }
    Ok(())
}
