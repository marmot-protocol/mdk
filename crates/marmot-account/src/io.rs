//! Filesystem JSON read/write helpers and account-label validation.

use std::fs;
use std::io::Write;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{AccountHomeError, AccountHomeResult};

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn write_json<T: Serialize>(path: impl AsRef<Path>, value: &T) -> AccountHomeResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

pub(crate) fn write_secret_json<T: Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    write_private_file(path, &bytes)?;
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> AccountHomeResult<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    let mut permissions = file.metadata()?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> AccountHomeResult<()> {
    fs::write(path, bytes)?;
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
