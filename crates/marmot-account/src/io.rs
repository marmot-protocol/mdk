//! Filesystem JSON read/write helpers and account-label validation.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AccountHomeError, AccountHomeResult};

pub(crate) mod record_directory;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bound on re-reads of a secret file that keeps being replaced mid-read.
const SECRET_READ_ATTEMPTS: usize = 8;
const MAX_SECRET_FILE_BYTES: u64 = 16 * 1024;

pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Read an owner-only record that builds before mdk#2569 wrote at the process
/// umask, tightening it to 0600 first. A record that cannot be tightened
/// fails the read.
pub(crate) fn read_private_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = read_tightened_private_file(path.as_ref(), || {})?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Open `path` once without following symlinks, then tighten and read that
/// handle, so a replacement after the open can neither skip the tightening
/// nor redirect the read. An owner-only file is left alone, which keeps
/// steady-state reads free of inode metadata writes. `after_open` lets tests
/// replace the file inside that window.
fn read_tightened_private_file(path: &Path, after_open: impl FnOnce()) -> io::Result<Vec<u8>> {
    read_private_file_bounded(path, u64::MAX, PrivateRead::Tighten, after_open)
}

pub(crate) fn read_private_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> AccountHomeResult<T> {
    let bytes = read_private_file_bounded(path, max_bytes, PrivateRead::Tighten, || {})?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub(crate) fn read_immutable_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    read_immutable_json_bounded(path.as_ref(), u64::MAX)
}

pub(crate) fn read_immutable_json_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> AccountHomeResult<T> {
    let bytes = read_private_file_bounded(path, max_bytes, PrivateRead::Immutable, || {})?;
    Ok(serde_json::from_slice(&bytes)?)
}

enum PrivateRead {
    Tighten,
    Immutable,
}

fn read_private_file_bounded(
    path: &Path,
    max_bytes: u64,
    mode: PrivateRead,
    after_open: impl FnOnce(),
) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    after_open();
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private record must be a regular file",
        ));
    }
    match mode {
        PrivateRead::Tighten => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    file.set_permissions(fs::Permissions::from_mode(0o600))?;
                }
            }
        }
        PrivateRead::Immutable => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private record needs a permission upgrade under writer admission",
                    ));
                }
            }
        }
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private record exceeds size limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn read_secret_json<T: for<'de> Deserialize<'de>>(
    path: impl AsRef<Path>,
) -> AccountHomeResult<T> {
    let bytes = read_linked_secret(path.as_ref(), || {})?;
    Ok(serde_json::from_slice(bytes.as_slice())?)
}

pub(crate) fn read_secret_text(path: &Path) -> AccountHomeResult<Zeroizing<String>> {
    read_secret_text_with(|| open_secret_file(path))
}

pub(crate) fn read_secret_text_with(
    open: impl FnMut() -> io::Result<File>,
) -> AccountHomeResult<Zeroizing<String>> {
    let mut bytes = read_linked_secret_with(open, || {})?;
    let bytes = std::mem::take(&mut *bytes);
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|error| {
            error.into_bytes().zeroize();
            io::Error::new(io::ErrorKind::InvalidData, "credential record is not UTF-8").into()
        })
}

fn open_secret_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn read_linked_secret(path: &Path, after_open: impl FnMut()) -> io::Result<Zeroizing<Vec<u8>>> {
    read_linked_secret_with(|| open_secret_file(path), after_open)
}

/// Read key material that a concurrent [`FileMode::Secret`] replacement or
/// [`remove_file_then_scrub`] may race.
///
/// Both zero the old inode after unlinking it, so a reader that opened it
/// first can read zeros. A read counts only if its inode was still linked once
/// the read finished, which puts it before that scrub. A removal whose unlink
/// fails zeroes the linked file in place; that read fails to parse instead of
/// yielding a key. `after_open` lets tests replace the file inside that window.
fn read_linked_secret_with(
    mut open: impl FnMut() -> io::Result<File>,
    mut after_open: impl FnMut(),
) -> io::Result<Zeroizing<Vec<u8>>> {
    for _ in 0..SECRET_READ_ATTEMPTS {
        let mut file = open()?;
        after_open();
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "credential record must be a regular file",
            ));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_SECRET_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "credential record exceeds size limit",
            ));
        }
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

pub(crate) fn write_private_json<T: Serialize>(
    owned_root: &Path,
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_file_atomically(owned_root, path.as_ref(), &bytes, FileMode::Private)
}

pub(crate) fn write_private_bytes(
    owned_root: &Path,
    path: impl AsRef<Path>,
    bytes: &[u8],
) -> AccountHomeResult<()> {
    write_file_atomically(owned_root, path.as_ref(), bytes, FileMode::Private)
}

#[cfg(test)]
pub(crate) fn write_secret_bytes(
    owned_root: &Path,
    path: &Path,
    bytes: &[u8],
) -> AccountHomeResult<()> {
    write_file_atomically(owned_root, path, bytes, FileMode::Secret)
}

/// Create or tighten directories in the owned tree. On Unix, sync every
/// owned directory on retry. Sync above the root only when bootstrapping it.
pub(crate) fn create_durable_private_dir(owned_root: &Path, path: &Path) -> io::Result<()> {
    open_durable_private_dir(owned_root, path).map(drop)
}

pub(crate) fn open_durable_private_dir(owned_root: &Path, path: &Path) -> io::Result<File> {
    let relative = path.strip_prefix(owned_root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory is outside the owned root",
        )
    })?;
    if !relative
        .components()
        .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid private directory path",
        ));
    }
    #[cfg(unix)]
    {
        unix_directory::create(owned_root, relative, |directory, _| {
            record_directory::sync(directory)
        })
    }
    #[cfg(not(unix))]
    {
        let mut directory = match owned_root.canonicalize() {
            Ok(root) => record_directory::open_root(&root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Windows absolute applies Win32 normalization to ordinary paths
                // but leaves verbatim names alone; NtCreateFile receives a leaf.
                open_or_create_root(&std::path::absolute(owned_root)?)?
            }
            Err(error) => return Err(error),
        };
        for part in relative {
            directory = record_directory::create_dir(&directory, part)?;
        }
        Ok(directory)
    }
}

#[cfg(not(unix))]
fn open_or_create_root(path: &Path) -> io::Result<File> {
    match path.canonicalize() {
        Ok(root) => record_directory::open_root(&root),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(error)?;
            let parent = open_or_create_root(containing_dir(path))?;
            record_directory::create_dir(&parent, name)
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
pub(crate) fn tighten_private_directory(directory: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if directory.metadata()?.permissions().mode() & 0o7777 != 0o700 {
        directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
mod unix_directory {
    use super::*;
    use std::borrow::Cow;
    use std::ffi::{CStr, CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    pub(super) fn create(
        root: &Path,
        relative: &Path,
        mut sync: impl FnMut(&File, &Path) -> io::Result<()>,
    ) -> io::Result<File> {
        let (directory, mut path) = bootstrap(root, &mut sync)?;
        tighten_private_directory(&directory)?;
        sync_tree(directory, &mut path, relative.iter(), &mut sync)
    }

    // A configured root may be an alias. Do not walk above an existing
    // authorized root; iOS can grant access to the root but not its parent.
    fn bootstrap(
        path: &Path,
        sync: &mut impl FnMut(&File, &Path) -> io::Result<()>,
    ) -> io::Result<(File, PathBuf)> {
        match path.canonicalize() {
            Ok(path) => {
                let directory = record_directory::open_root(&path)?;
                Ok((directory, path))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = path.file_name().ok_or(error)?;
                let (parent, mut parent_path) = bootstrap(containing_dir(path), sync)?;
                let mut buffer = [0; 256];
                let name_c = component_name(name, &mut buffer)?;
                let created = mkdir_at(&parent, &name_c)?;
                let result = (|| -> io::Result<File> {
                    let directory = open_directory_at(&parent, &name_c)?;
                    if created {
                        tighten_private_directory(&directory)?;
                    }
                    sync(&parent, &parent_path)?;
                    Ok(directory)
                })();
                if result.is_err() && created {
                    // No child is published until this edge is synced. Remove
                    // the empty unsynced child so a retry cannot skip the barrier.
                    // SAFETY: The parent handle and component remain live.
                    unsafe {
                        libc::unlinkat(parent.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR);
                    }
                }
                let directory = result?;
                parent_path.push(name);
                Ok((directory, parent_path))
            }
            Err(error) => Err(error),
        }
    }

    fn sync_tree(
        directory: File,
        path: &mut PathBuf,
        mut remaining: std::path::Iter<'_>,
        sync: &mut impl FnMut(&File, &Path) -> io::Result<()>,
    ) -> io::Result<File> {
        let leaf = if let Some(component) = remaining.next() {
            let mut buffer = [0; 256];
            let name = component_name(component, &mut buffer)?;
            let child = create_child(&directory, &name)?;
            path.push(component);
            let leaf = sync_tree(child, path, remaining, sync)?;
            path.pop();
            leaf
        } else {
            sync(&directory, path)?;
            return Ok(directory);
        };
        // A previous attempt can have failed before syncing an existing edge.
        sync(&directory, path)?;
        Ok(leaf)
    }

    pub(super) fn create_child(parent: &File, name: &CStr) -> io::Result<File> {
        let child = match open_directory_at(parent, name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mkdir_at(parent, name)?;
                open_directory_at(parent, name)?
            }
            result => result?,
        };
        tighten_private_directory(&child)?;
        Ok(child)
    }

    pub(super) fn component_name<'a>(
        name: &OsStr,
        buffer: &'a mut [u8],
    ) -> io::Result<Cow<'a, CStr>> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || name == ".." || bytes.contains(&b'/') || bytes.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid record component",
            ));
        }
        if let Some(buffer) = buffer.get_mut(..=bytes.len()) {
            buffer[..bytes.len()].copy_from_slice(bytes);
            buffer[bytes.len()] = 0;
            // SAFETY: The name has no NUL and the buffer ends with one.
            Ok(Cow::Borrowed(unsafe {
                CStr::from_bytes_with_nul_unchecked(buffer)
            }))
        } else {
            // SAFETY: The name has no NUL. CString adds the terminator.
            Ok(Cow::Owned(unsafe {
                CString::from_vec_unchecked(bytes.to_vec())
            }))
        }
    }

    pub(super) fn mkdir_at(parent: &File, name: &CStr) -> io::Result<bool> {
        // SAFETY: The parent handle and component remain live for the call.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::AlreadyExists {
            Ok(false)
        } else {
            Err(error)
        }
    }

    pub(super) fn open_at(parent: &File, name: &CStr, flags: libc::c_int) -> io::Result<File> {
        // O_NONBLOCK keeps a FIFO from blocking the type check.
        // SAFETY: The parent handle and component remain live for the call.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                0o600_i32,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn open_directory_at(parent: &File, name: &CStr) -> io::Result<File> {
        // Do not combine O_DIRECTORY with O_NOFOLLOW: retain the symlink error.
        let file = open_at(parent, name, libc::O_RDONLY)?;
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "private directory target is not a directory",
            ));
        }
        Ok(file)
    }
}

fn containing_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Key material only: read it back with [`read_secret_json`].
#[cfg(test)]
pub(crate) fn write_secret_json<T: Serialize>(
    owned_root: &Path,
    path: impl AsRef<Path>,
    value: &T,
) -> AccountHomeResult<()> {
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    write_file_atomically(
        owned_root,
        path.as_ref(),
        bytes.as_slice(),
        FileMode::Secret,
    )
}

/// Private records publish by replacing the live name with a synced owner-only
/// temp file. Secret replacement also detaches the previous file for scrubbing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileMode {
    /// Owner-only. The replaced inode is left intact for readers that still
    /// hold it open.
    Private,
    /// Owner-only key material. Failed temp files and the replaced inode are
    /// zeroed, so readers must reject reads of an unlinked inode.
    Secret,
}

fn write_file_atomically(
    owned_root: &Path,
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
) -> AccountHomeResult<()> {
    let name = record_name(path)?;
    let parent = open_durable_private_dir(owned_root, containing_dir(path))?;
    write_record(&parent, name, bytes, mode)
}

pub(crate) fn write_private_record(
    parent: &File,
    name: &OsStr,
    bytes: &[u8],
) -> AccountHomeResult<()> {
    write_record(parent, name, bytes, FileMode::Private)
}

pub(crate) fn write_secret_record(
    parent: &File,
    name: &OsStr,
    bytes: &[u8],
) -> AccountHomeResult<()> {
    write_record(parent, name, bytes, FileMode::Secret)
}

fn write_record(
    parent: &File,
    name: &OsStr,
    bytes: &[u8],
    mode: FileMode,
) -> AccountHomeResult<()> {
    let (file, stage_name) = create_temp_file(parent, name)?;
    write_staged_file(parent, file, &stage_name, name, bytes, mode)
}

fn write_staged_file(
    parent: &File,
    mut file: File,
    stage_name: &OsStr,
    name: &OsStr,
    bytes: &[u8],
    mode: FileMode,
) -> AccountHomeResult<()> {
    let published = (|| -> io::Result<()> {
        file.write_all(bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        file.sync_all()?;
        match mode {
            FileMode::Private => record_directory::replace(parent, &file, stage_name, name),
            FileMode::Secret => record_directory::replace_secret(parent, &file, stage_name, name),
        }
    })();

    if let Err(error) = published {
        if mode == FileMode::Secret {
            let _ = overwrite_open_file_with_zeros(&mut file);
        }
        let _ = record_directory::discard_stage(parent, &file, stage_name);
        return Err(error.into());
    }
    // A failed durability barrier leaves the published record intact for retry.
    Ok(record_directory::sync(parent)?)
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

#[cfg(test)]
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
    check_scrubbable(&file)?;
    Ok(file)
}

fn check_scrubbable(file: &File) -> io::Result<()> {
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
    Ok(())
}

fn overwrite_open_file_with_zeros(file: &mut File) -> io::Result<()> {
    let mut remaining = file.metadata()?.len();
    if remaining > 0 {
        let zeros = [0; 4096];
        file.seek(SeekFrom::Start(0))?;
        while remaining > 0 {
            let count = remaining.min(zeros.len() as u64) as usize;
            file.write_all(&zeros[..count])?;
            remaining -= count as u64;
        }
        file.sync_all()?;
    }
    Ok(())
}

fn record_name(path: &Path) -> io::Result<&OsStr> {
    path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic write target must name a file",
        )
    })
}

fn temporary_name(name: &OsStr, purpose: &str) -> OsString {
    let attempt = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".{purpose}.{}.{attempt}", std::process::id()));
    temporary
}

fn create_temp_file(parent: &File, name: &OsStr) -> io::Result<(File, OsString)> {
    for _ in 0..32 {
        let temporary = temporary_name(name, "tmp");
        match record_directory::create_stage(parent, &temporary) {
            Ok(file) => return Ok((file, temporary)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique atomic write temp file",
    ))
}

/// Publish an already-synced file, replacing the old entry in the same directory.
pub(crate) fn replace_file_for_commit(from: &Path, to: &Path) -> io::Result<()> {
    let parent = containing_dir(to);
    if containing_dir(from) != parent {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private replacement requires the same directory",
        ));
    }
    let directory = record_directory::open_root(&parent.canonicalize()?)?;
    record_directory::replace_existing_stage(&directory, record_name(from)?, record_name(to)?)?;
    record_directory::sync(&directory)
}

#[cfg(windows)]
pub(crate) fn rename_for_commit(from: &Path, to: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let from = windows_move_path(from)?;
    let to = windows_move_path(to)?;
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_move_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "rename path has no filename")
    })?;
    let mut absolute = containing_dir(path).canonicalize()?;
    absolute.push(name);
    let mut wide: Vec<_> = absolute.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "rename path contains NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

#[cfg(not(windows))]
pub(crate) fn rename_for_commit(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(unix)]
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    record_directory::sync(&File::open(path)?)
}

#[cfg(not(unix))]
pub(crate) fn sync_directory(_path: &Path) -> io::Result<()> {
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
    fn fifo_reads_do_not_block() {
        use std::os::unix::ffi::OsStrExt;
        use std::process::Command;

        const FIFO_PROBE: &str = "MDK_ACCOUNT_FIFO_PROBE";
        if let Some(path) = std::env::var_os(FIFO_PROBE) {
            // Kill only the probe if a reader blocks opening the FIFO.
            unsafe { libc::alarm(5) };
            let path = Path::new(&path);
            for result in [
                read_private_json_bounded::<serde_json::Value>(path, 128).map(|_| ()),
                read_secret_text(path).map(|_| ()),
            ] {
                assert!(matches!(result,
                    Err(AccountHomeError::Io(error)) if error.kind() == io::ErrorKind::InvalidInput));
            }
            unsafe { libc::alarm(0) };
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("record");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "io::tests::fifo_reads_do_not_block",
                "--nocapture",
            ])
            .env(FIFO_PROBE, &fifo)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "FIFO reader child failed: {}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("running 1 test"),
            "FIFO probe did not run: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn secret_write_creates_account_directory_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let account_dir = root.path().join("accounts").join("alice");
        let secret_path = account_dir.join("secret.json");

        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "test" }),
        )
        .unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&account_dir), 0o700);
        assert_eq!(mode(&secret_path), 0o600);
    }

    #[test]
    fn nested_root_bootstrap_retries_the_failed_parent_barrier() {
        let scratch = tempfile::tempdir().unwrap();
        let host = scratch.path().canonicalize().unwrap();
        fs::set_permissions(&host, fs::Permissions::from_mode(0o755)).unwrap();
        let first = host.join("first");
        let second = first.join("second");
        let root = second.join("root");

        let error = unix_directory::create(&root, Path::new(""), |file, directory| {
            if directory == host {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            record_directory::sync(file)
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(!first.exists());

        let mut synced = Vec::new();
        unix_directory::create(&root, Path::new(""), |file, directory| {
            record_directory::sync(file)?;
            synced.push(directory.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert!(root.is_dir());
        assert_eq!(
            synced,
            [&host, &first, &second, &root].map(|dir| dir.to_path_buf())
        );
        assert_eq!(
            fs::metadata(host).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn directory_sync_retry_covers_the_existing_owned_tree() {
        let scratch = tempfile::tempdir().unwrap();
        let host_path = scratch.path().canonicalize().unwrap();
        let external_parent = host_path.join("external");
        let root = external_parent.join("owned");
        let parent = root.join("collection");
        let path = parent.join("leaf");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&external_parent, fs::Permissions::from_mode(0o111)).unwrap();
        let relative = Path::new("collection/leaf");

        let error = unix_directory::create(&root, relative, |file, directory| {
            if directory == root {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            record_directory::sync(file)
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(path.is_dir());

        let mut synced = Vec::new();
        unix_directory::create(&root, relative, |file, directory| {
            record_directory::sync(file)?;
            synced.push(directory.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(synced, [&path, &parent, &root].map(|dir| dir.to_path_buf()));
        let mode = |directory: &Path| fs::metadata(directory).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&external_parent), 0o111);
        fs::set_permissions(&external_parent, fs::Permissions::from_mode(0o700)).unwrap();
        for directory in [&root, &parent, &path] {
            assert_eq!(mode(directory), 0o700);
        }
    }

    #[test]
    fn failed_secret_atomic_write_scrubs_temp_before_unlink() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("records");
        let moved = root.path().join("moved");
        let name = OsStr::new("secret");
        fs::create_dir_all(directory.join(name)).unwrap();
        let parent = open_durable_private_dir(root.path(), &directory).unwrap();
        let (staged, stage_name) = create_temp_file(&parent, name).unwrap();
        let mut reader = File::open(directory.join(&stage_name)).unwrap();
        fs::rename(&directory, &moved).unwrap();
        fs::create_dir(&directory).unwrap();
        let replacement_stage = directory.join(&stage_name);
        fs::write(&replacement_stage, b"replacement stage").unwrap();
        const BYTES: &[u8] = b"unpublished secret";

        let error = write_staged_file(&parent, staged, &stage_name, name, BYTES, FileMode::Secret)
            .unwrap_err();
        assert!(
            matches!(error, AccountHomeError::Io(error) if error.raw_os_error() == Some(libc::EISDIR))
        );
        assert!(moved.join(name).is_dir());
        assert!(!moved.join(stage_name).exists());
        assert!(!directory.join(name).exists());
        assert_eq!(fs::read(replacement_stage).unwrap(), b"replacement stage");
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, [0; BYTES.len()]);
    }

    #[test]
    fn replacing_secret_scrubs_the_replaced_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "old-key" }),
        )
        .unwrap();
        let mut old_inode = File::open(&secret_path).unwrap();

        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "new-key" }),
        )
        .unwrap();

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
        write_private_json(
            root.path(),
            &json_path,
            &serde_json::json!({ "phase": "old" }),
        )
        .unwrap();
        write_private_bytes(root.path(), &bytes_path, br#"{"revision":1}"#).unwrap();
        let mut json_reader = File::open(&json_path).unwrap();
        let mut bytes_reader = File::open(&bytes_path).unwrap();

        write_private_json(
            root.path(),
            &json_path,
            &serde_json::json!({ "phase": "new" }),
        )
        .unwrap();
        write_private_bytes(root.path(), &bytes_path, br#"{"revision":2}"#).unwrap();

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

    /// A symlink swapped in after the no-follow open is neither followed nor
    /// tightened; the inode the open reached is.
    #[test]
    fn private_record_read_tightens_and_reads_the_inode_it_opened() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("account").join("account.json");
        let opened = root.path().join("opened.json");
        let elsewhere = root.path().join("elsewhere.json");
        write_private_json(
            root.path(),
            &path,
            &serde_json::json!({ "label": "opened" }),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::hard_link(&path, &opened).unwrap();
        fs::write(&elsewhere, br#"{"label":"elsewhere"}"#).unwrap();
        fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o644)).unwrap();

        let bytes = read_tightened_private_file(&path, || {
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        })
        .unwrap();

        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record["label"], "opened");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&opened), 0o600);
        assert_eq!(mode(&elsewhere), 0o644);
    }

    #[test]
    fn private_record_read_rejects_a_directory_without_tightening_it() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("account.json");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

        let error = read_private_json::<serde_json::Value>(&path).unwrap_err();

        assert!(
            matches!(error, AccountHomeError::Io(error) if error.kind() == io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn secret_read_retries_past_a_replacement_that_scrubbed_its_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "old-key" }),
        )
        .unwrap();
        let mut opens = 0;

        let bytes = read_linked_secret(&secret_path, || {
            opens += 1;
            if opens == 1 {
                let mut old_inode = File::open(&secret_path).unwrap();
                write_secret_json(
                    root.path(),
                    &secret_path,
                    &serde_json::json!({ "secret": "new-key" }),
                )
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
        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "old-key" }),
        )
        .unwrap();

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
        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": 0 }),
        )
        .unwrap();
        let mut replacements = 0;

        let err = read_linked_secret(&secret_path, || {
            replacements += 1;
            write_secret_json(
                root.path(),
                &secret_path,
                &serde_json::json!({ "secret": replacements }),
            )
            .unwrap();
        })
        .unwrap_err();

        assert_eq!(replacements, SECRET_READ_ATTEMPTS);
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn removing_a_secret_scrubs_the_removed_inode() {
        let root = tempfile::tempdir().unwrap();
        let secret_path = root.path().join("account").join("secret.json");
        write_secret_json(
            root.path(),
            &secret_path,
            &serde_json::json!({ "secret": "old-key" }),
        )
        .unwrap();
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};

    #[test]
    fn creating_private_roots_preserves_win32_and_verbatim_names() {
        let directory = tempfile::tempdir().unwrap();
        let ordinary = directory.path().join("ordinary-root. ");
        assert!(
            !matches!(ordinary.components().next(), Some(Component::Prefix(prefix)) if prefix.kind().is_verbatim())
        );
        write_private_bytes(&ordinary, ordinary.join("record"), b"ordinary").unwrap();
        assert_eq!(
            fs::read(directory.path().join("ordinary-root/record")).unwrap(),
            b"ordinary"
        );

        let verbatim = directory
            .path()
            .canonicalize()
            .unwrap()
            .join("verbatim-root. ");
        write_private_bytes(&verbatim, verbatim.join("record"), b"verbatim").unwrap();
        assert_eq!(fs::read(verbatim.join("record")).unwrap(), b"verbatim");
        assert!(!directory.path().join("verbatim-root").exists());
    }

    #[test]
    fn private_replacement_leaves_open_reader_the_previous_file() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a".repeat(144)).join("資料".repeat(72));
        let path = dir.join("journal.json");
        write_private_bytes(root.path(), &path, b"old revision").unwrap();
        let mut reader = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();

        write_private_bytes(root.path(), &path, b"new revision").unwrap();

        let mut previous = Vec::new();
        reader.read_to_end(&mut previous).unwrap();
        assert_eq!(previous, b"old revision");
        assert_eq!(fs::read(&path).unwrap(), b"new revision");
    }

    #[test]
    fn secret_replace_scrubs_old_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("secret.json");
        let old = serde_json::json!({ "secret": "old-key" });
        let new = serde_json::json!({ "secret": "new-key" });
        write_secret_json(root.path(), &path, &old).unwrap();
        let mut reader = File::open(&path).unwrap();
        let old_len = reader.metadata().unwrap().len() as usize;

        write_secret_json(root.path(), &path, &new).unwrap();

        assert_eq!(read_secret_json::<serde_json::Value>(&path).unwrap(), new);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, vec![0; old_len]);
    }

    #[test]
    fn failed_replace_restores_target() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("secret.json");
        let stage = root.path().join("staged.tmp");
        fs::write(&path, b"old-key").unwrap();
        fs::write(&stage, b"new-key").unwrap();
        let reader = File::open(&path).unwrap();
        let parent = record_directory::open_root(root.path()).unwrap();
        // A stage without DELETE access fails the install after the old name moved aside.
        let restricted_stage = File::open(&stage).unwrap();

        let error = record_directory::replace_secret(
            &parent,
            &restricted_stage,
            record_name(&stage).unwrap(),
            record_name(&path).unwrap(),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&path).unwrap(), b"old-key");
        assert_eq!(fs::read(&stage).unwrap(), b"new-key");
        drop(reader);
    }
}

#[cfg(all(test, any(unix, windows)))]
#[test]
fn replacing_a_checkpoint_moves_the_synced_active_record_over_existing_evidence() {
    let root = tempfile::tempdir().unwrap();
    let active = root.path().join("onboarding.json");
    let cancelled = root.path().join("onboarding-cancelled.json");
    write_private_bytes(root.path(), &active, b"new evidence").unwrap();
    write_private_bytes(root.path(), &cancelled, b"previous evidence").unwrap();
    let mut reader = File::open(&cancelled).unwrap();

    replace_file_for_commit(&active, &cancelled).unwrap();

    assert_eq!(fs::read(&cancelled).unwrap(), b"new evidence");
    assert_eq!(
        fs::read(&active).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    let mut previous = Vec::new();
    reader.read_to_end(&mut previous).unwrap();
    assert_eq!(previous, b"previous evidence");
}
