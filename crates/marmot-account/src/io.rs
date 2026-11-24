//! Filesystem JSON read/write helpers and account-label validation.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AccountHomeError, AccountHomeResult};

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
        unix_directory::create(owned_root, relative, |directory, _| directory.sync_all())
    }
    #[cfg(not(unix))]
    {
        let mut directory = match owned_root.canonicalize() {
            Ok(root) => root,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(containing_dir(owned_root))?;
                owned_root.to_path_buf()
            }
            Err(error) => return Err(error),
        };
        create_private_directory(&directory)?;
        for part in relative {
            directory.push(part);
            create_private_directory(&directory)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
mod unix_directory {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    pub(super) fn create(
        root: &Path,
        relative: &Path,
        mut sync: impl FnMut(&File, &Path) -> io::Result<()>,
    ) -> io::Result<()> {
        let (directory, mut path) = bootstrap(root, &mut sync)?;
        tighten(&directory)?;
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
                let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW;
                #[cfg(target_vendor = "apple")]
                let flags = flags | libc::O_NOFOLLOW_ANY;
                let directory = OpenOptions::new()
                    .read(true)
                    .custom_flags(flags)
                    .open(&path)?;
                Ok((directory, path))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = path.file_name().ok_or(error)?;
                let (parent, mut parent_path) = bootstrap(containing_dir(path), sync)?;
                let name_c = component_name(name)?;
                let created = mkdir_at(&parent, &name_c)?;
                let result = (|| -> io::Result<File> {
                    let directory = open_at(&parent, &name_c)?;
                    if created {
                        tighten(&directory)?;
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
    ) -> io::Result<()> {
        if let Some(component) = remaining.next() {
            let name = component_name(component)?;
            let child = match open_at(&directory, &name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    mkdir_at(&directory, &name)?;
                    open_at(&directory, &name)?
                }
                result => result?,
            };
            tighten(&child)?;
            path.push(component);
            sync_tree(child, path, remaining, sync)?;
            path.pop();
        }
        // Sync even if all entries were already present. A previous attempt
        // can have failed after creating the tree but before syncing it.
        sync(&directory, path)
    }

    fn component_name(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory name contains NUL",
            )
        })
    }

    fn mkdir_at(parent: &File, name: &CString) -> io::Result<bool> {
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

    fn open_at(parent: &File, name: &CString) -> io::Result<File> {
        // O_NOFOLLOW without O_DIRECTORY preserves ELOOP (EMLINK on FreeBSD)
        // for a symlink. O_NONBLOCK keeps a FIFO from blocking the type check.
        // SAFETY: The parent handle and component remain live for the call.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a new, owned descriptor.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "private directory target is not a directory",
            ));
        }
        Ok(file)
    }

    fn tighten(directory: &File) -> io::Result<()> {
        if directory.metadata()?.permissions().mode() & 0o7777 != 0o700 {
            directory.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory target must not be a reparse point",
            ));
        }
    }
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "private directory target is not a directory",
        ));
    }
    Ok(())
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
    let parent = containing_dir(path);
    create_durable_private_dir(owned_root, parent)?;

    let (file, temp_path) = create_temp_file(parent, path, mode)?;
    write_staged_file(file, &temp_path, path, bytes, mode)
}

fn write_staged_file(
    mut file: File,
    temp_path: &Path,
    path: &Path,
    bytes: &[u8],
    mode: FileMode,
) -> AccountHomeResult<()> {
    let result = (|| -> AccountHomeResult<()> {
        file.write_all(bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = file.metadata()?.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)?;
        }

        file.sync_all()?;
        if mode == FileMode::Private {
            #[cfg(windows)]
            replace_open_file_for_commit(&file, path)?;
            #[cfg(not(windows))]
            {
                drop(file);
                replace_file_for_commit(temp_path, path)?;
            }
            return Ok(());
        }

        drop(file);
        let mut replaced_secret_file = match open_file_for_zero_overwrite(path) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => return Err(err.into()),
        };
        replace_secret_file(temp_path, path)?;
        // The handle still refers to the replaced file after publication,
        // so scrub it without creating a window where the live secret path is
        // zeroed if replacement fails. Best-effort, matching secret deletion.
        if let Some(file) = &mut replaced_secret_file {
            let _ = overwrite_open_file_with_zeros(file);
        }
        sync_directory(containing_dir(path))?;
        Ok(())
    })();

    if result.is_err() {
        if mode == FileMode::Secret {
            let _ = overwrite_file_with_zeros(temp_path);
        }
        let _ = fs::remove_file(temp_path);
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
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(windows)]
        if mode == FileMode::Private {
            use windows_sys::Win32::Foundation::GENERIC_WRITE;
            windows_rename_options(&mut options, GENERIC_WRITE);
        }
        #[cfg(not(windows))]
        let _ = mode;

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

/// Replace a Windows secret file while retaining its open scrub handle.
/// Deleting it and renaming onto its name only works with
/// POSIX delete semantics (NTFS on Windows 10 1903 and later); elsewhere the
/// name stays delete-pending and the rename is denied. Moving the old file
/// aside keeps open handles attached to the old file. A failed install attempts
/// to restore the old name. Unlike Unix replacement, readers can observe a
/// missing live path between the two renames.
#[cfg(windows)]
fn replace_secret_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    let mut aside = OsString::from(".");
    aside.push(path.file_name().unwrap_or_default());
    aside.push(format!(
        ".old.{}.{}",
        std::process::id(),
        TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let aside = path.with_file_name(aside);
    match rename_for_commit(path, &aside) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return rename_for_commit(temp_path, path);
        }
        Err(err) => return Err(err),
    }
    if let Err(err) = rename_for_commit(temp_path, path) {
        let _ = rename_for_commit(&aside, path);
        return Err(err);
    }
    // The new file is live; the caller scrubs the old bytes through its open
    // handle, and the name goes once that handle closes. Best-effort, like
    // the rest of secret deletion: failing here must not fail the write.
    let _ = fs::remove_file(&aside);
    Ok(())
}

#[cfg(not(windows))]
fn replace_secret_file(temp_path: &Path, path: &Path) -> io::Result<()> {
    fs::rename(temp_path, path)
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
    #[cfg(unix)]
    {
        fs::rename(from, to)?;
        sync_directory(parent)
    }
    #[cfg(windows)]
    {
        let mut options = OpenOptions::new();
        windows_rename_options(&mut options, 0);
        let file = options.open(from)?;
        replace_open_file_for_commit(&file, to)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable private replacement requires Unix or Windows",
        ))
    }
}

#[cfg(windows)]
fn windows_rename_options(options: &mut OpenOptions, access: u32) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES,
    };

    options
        .access_mode(access | DELETE | FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_WRITE_THROUGH | FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(windows)]
fn replace_open_file_for_commit(file: &File, to: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_RENAME_INFO, FileRenameInfoEx,
        GetVolumeInformationByHandleW, SetFileInformationByHandle,
    };

    // winbase.h and winnt.h constants outside our windows-sys feature set.
    const FILE_RENAME_FLAG_REPLACE_IF_EXISTS: u32 = 1;
    const FILE_RENAME_FLAG_POSIX_SEMANTICS: u32 = 2;
    const FILE_SUPPORTS_POSIX_UNLINK_RENAME: u32 = 0x400;

    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private replacement source must be a regular file",
        ));
    }

    // CreateFileW documents rename metadata write-through for NTFS. Do not
    // publish where we cannot rely on that or fall back to a two-step rename.
    let handle = file.as_raw_handle();
    let mut filesystem = [0u16; 32];
    let mut flags = 0;
    // SAFETY: The file handle and writable output buffers remain live for the call.
    if unsafe {
        GetVolumeInformationByHandleW(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if !filesystem.starts_with(&[b'N' as u16, b'T' as u16, b'F' as u16, b'S' as u16, 0])
        || flags & FILE_SUPPORTS_POSIX_UNLINK_RENAME == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "durable private replacement requires NTFS with POSIX rename support",
        ));
    }

    let name = windows_move_path(to)?;
    let name_bytes = (name.len() - 1) * size_of::<u16>();
    let size = size_of::<FILE_RENAME_INFO>() + name_bytes;
    let size_u32 = u32::try_from(size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "private replacement path is too long",
        )
    })?;
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: usize provides the header's pointer alignment. The zeroed
    // buffer contains the header and space for the wide name and terminator.
    unsafe {
        (*info).Anonymous.Flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*info).FileNameLength = name_bytes as u32;
        let filename = buffer
            .as_mut_ptr()
            .cast::<u8>()
            .add(std::mem::offset_of!(FILE_RENAME_INFO, FileName))
            .cast();
        ptr::copy_nonoverlapping(name.as_ptr(), filename, name.len());
        if SetFileInformationByHandle(handle, FileRenameInfoEx, info.cast(), size_u32) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
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
    File::open(path)?.sync_all()
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
            file.sync_all()
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(!first.exists());

        let mut synced = Vec::new();
        unix_directory::create(&root, Path::new(""), |file, directory| {
            file.sync_all()?;
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
            file.sync_all()
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(path.is_dir());

        let mut synced = Vec::new();
        unix_directory::create(&root, relative, |file, directory| {
            file.sync_all()?;
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
        let destination = root.path().join("secret");
        fs::create_dir(&destination).unwrap();
        let (staged, path) = create_temp_file(root.path(), &destination, FileMode::Secret).unwrap();
        let mut reader = File::open(&path).unwrap();
        const BYTES: &[u8] = b"unpublished secret";

        let error =
            write_staged_file(staged, &path, &destination, BYTES, FileMode::Secret).unwrap_err();
        assert!(
            matches!(error, AccountHomeError::Io(error) if error.raw_os_error() == Some(libc::EISDIR))
        );
        assert!(destination.is_dir());
        assert!(!path.exists());
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
        fs::write(&path, b"old-key").unwrap();
        let reader = File::open(&path).unwrap();

        let error = replace_secret_file(&root.path().join("missing.tmp"), &path).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(&path).unwrap(), b"old-key");
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
