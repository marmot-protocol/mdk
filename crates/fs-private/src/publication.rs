//! Atomic publication for sandboxes that forbid hard links (notably Android).

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// Rename a complete staging file into place without replacing a destination
/// created by another cooperating publisher. Uses only `flock` and ordinary
/// rename, including on Android API 26; no hard link or `renameat2` is needed.
///
/// Every writer of `destination` MUST use this helper. An exclusive advisory
/// lock on a stable sibling `<destination>.publish.lock` protects the existence
/// check and rename across threads and processes. The lock file is private and
/// must never be unlinked/replaced while publishers can run, including after a
/// failed publication. Closing the descriptor (also on process exit) releases
/// the lock. This call waits for competing publishers, so run it on a thread
/// where blocking filesystem I/O is allowed.
///
/// The caller must own the parent directory and a unique, private staging file
/// in that same directory, and sync its contents before calling. Readers see
/// either no destination or the complete file. Existing entries, including
/// dangling symlinks, return `AlreadyExists`. The caller owns staging cleanup on
/// error and must sync the parent directory after success for crash durability.
pub fn rename_noreplace_with_lock(source: &Path, destination: &Path) -> io::Result<()> {
    if source == destination || source.parent() != destination.parent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "publication requires distinct paths in the same directory",
        ));
    }
    let lock_path = publication_lock_path(destination)?;
    if source == lock_path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "staging file must not be the publication lock",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    crate::set_private_file_mode(&mut options);
    let file = options
        .open(&lock_path)
        .map_err(|error| crate::io_context("open publication lock", &lock_path, error))?;
    let _lease = crate::finish_private_exclusive_file_lease(file, &lock_path, libc::LOCK_EX)?;

    // `exists()` follows symlinks and hides errors; neither behavior is safe
    // for a check that authorizes replacement of key material.
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => fs::rename(source, destination)
            .map_err(|error| crate::io_context("publish staging file", destination, error)),
        Err(error) => Err(crate::io_context(
            "inspect publication destination",
            destination,
            error,
        )),
    }
}

fn publication_lock_path(destination: &Path) -> io::Result<PathBuf> {
    let mut name = destination
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing publication filename"))?
        .to_os_string();
    name.push(".publish.lock");
    Ok(destination.with_file_name(name))
}
