//! TTL sweep of decrypted inbound media temp dirs under `$TMPDIR/marmot-media/`.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::{AgentConnector, MEDIA_TEMP_MAX_AGE, MEDIA_TEMP_SWEEP_INTERVAL};

/// Mode for the `marmot-media` root and per-blob subdirs: owner-only so other
/// local users cannot `readdir` the tree and learn ciphertext hashes (used
/// verbatim as dir names) or sender-controlled media filenames.
pub(crate) const MEDIA_TEMP_DIR_MODE: u32 = 0o700;

impl AgentConnector {
    pub(crate) fn spawn_media_temp_sweeper(&self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(MEDIA_TEMP_SWEEP_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match sweep_stale_media_downloads(MEDIA_TEMP_MAX_AGE).await {
                    Ok(swept) if swept > 0 => {
                        tracing::warn!(
                            target: "agent_connector",
                            method = "spawn_media_temp_sweeper",
                            swept,
                            "removed stale inbound media download directories"
                        );
                    }
                    Ok(_) => {}
                    Err(_) => {
                        tracing::debug!(
                            target: "agent_connector",
                            method = "spawn_media_temp_sweeper",
                            "media temp sweep failed"
                        );
                    }
                }
            }
        });
    }
}

pub(crate) fn media_download_root() -> PathBuf {
    std::env::temp_dir().join("marmot-media")
}

/// Create the per-blob download dir under the `marmot-media` root and harden
/// both the root and the per-blob subdir to 0700 (owner-only).
///
/// On a default `TMPDIR=/tmp` a bare `create_dir_all` yields `0777 & ~umask`
/// (typically 0755), leaving the tree world-traversable. The per-blob subdir
/// is named after the ciphertext SHA-256 and holds a sender-controlled media
/// filename, so a readable parent leaks ciphertext/message metadata to other
/// local users. Mirror the connector's other private paths
/// (`socket::prepare_socket_dir`, `stream_session::persist_to_disk`,
/// `AllowlistStore::write_record`), which all chmod their parent dir to 0700.
///
/// Ordering matters: the secret-named child must never be materialized inside a
/// world-traversable or attacker-controlled root. We therefore secure the
/// `marmot-media` root *first* (atomic 0700 create, plus symlink/ownership
/// rejection and a mode re-verification on a pre-existing root) and only then
/// create the per-blob child. This closes the local-observer race and the
/// pre-created-writable-root leak: another user can never `readdir` the root
/// and learn the ciphertext hash before the directory is private.
///
/// Returns the per-blob dir path.
pub(crate) async fn create_media_download_dir(subdir: &str) -> Result<PathBuf, std::io::Error> {
    create_media_download_dir_in(&media_download_root(), subdir).await
}

/// Root-relative core of [`create_media_download_dir`], split out so tests can
/// drive an isolated root without mutating the process-global `$TMPDIR`.
pub(crate) async fn create_media_download_dir_in(
    root: &Path,
    subdir: &str,
) -> Result<PathBuf, std::io::Error> {
    // Step 1: secure the root before deriving any secret-named child on disk.
    // If the root cannot be made owner-only private, we abort *before* creating
    // the `<ciphertext_sha256>` child, so the hash is never leaked.
    secure_media_root(root).await?;

    // Step 2: the root is now a verified, owner-only (0700) real directory, so
    // it is safe to create the secret-named child inside it. Create atomically
    // at 0700 so it is never world-traversable even momentarily, then
    // re-harden to stay robust if the child already existed at a looser mode.
    let dir = root.join(subdir);
    create_dir_atomic_0700(&dir).await?;
    // `create_dir_atomic_0700` returns `Ok` when the child already exists, so a
    // pre-planted `<ciphertext_sha256>` symlink (possible if a legacy/loose
    // root let an attacker write before we hardened it) would otherwise be
    // followed by `harden_media_dir` and the subsequent 0600 plaintext write,
    // landing key material in an attacker-controlled tree. Reject a symlink or
    // non-directory child before either operation follows it out of our tree.
    let child_type = tokio::fs::symlink_metadata(&dir).await?.file_type();
    ensure_real_dir(
        child_type,
        "marmot-media per-blob dir exists but is not a directory; refusing to use it",
    )?;
    harden_media_dir(&dir).await?;
    Ok(dir)
}

/// Reject a pre-existing path that is a symlink or non-directory. A symlink
/// here would let `set_permissions`/file writes follow it out of our private
/// tree, so callers validate before hardening or writing through the path.
fn ensure_real_dir(file_type: std::fs::FileType, message: &str) -> Result<(), std::io::Error> {
    if file_type.is_symlink() || !file_type.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            message,
        ));
    }
    Ok(())
}

/// Ensure the `marmot-media` root exists as an owner-only (0700) real
/// directory, creating it atomically at 0700 when absent and rejecting an
/// untrusted pre-existing root (symlink or non-directory) before any
/// secret-named child is placed inside it.
async fn secure_media_root(root: &Path) -> Result<(), std::io::Error> {
    // `symlink_metadata` does not follow symlinks: a local user who pre-creates
    // `/tmp/marmot-media` as a symlink (or a plain file) must not be able to
    // redirect our private tree or have us treat their dir as ours.
    match tokio::fs::symlink_metadata(root).await {
        Ok(meta) => {
            ensure_real_dir(
                meta.file_type(),
                "marmot-media root exists but is not a directory; refusing to use it",
            )?;
            // Pre-existing real directory: re-harden to 0700. If we cannot
            // (e.g. an attacker owns it: `set_permissions` fails with EPERM),
            // bail here, before the secret-named child is ever created.
            harden_media_dir(root).await?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Create the root atomically at 0700 so it never transiently exists
            // at the umask-masked default mode (typically 0755) while empty.
            create_dir_atomic_0700(root).await?;
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

/// Create a single directory atomically with mode 0700, succeeding when it
/// already exists. `DirBuilder` applies the requested mode at creation time
/// (subject to umask) so the directory is never observable at a looser mode
/// in the window before a follow-up `chmod`.
async fn create_dir_atomic_0700(dir: &Path) -> Result<(), std::io::Error> {
    match tokio::fs::DirBuilder::new()
        .mode(MEDIA_TEMP_DIR_MODE)
        .create(dir)
        .await
    {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(err),
    }
}

async fn harden_media_dir(dir: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(MEDIA_TEMP_DIR_MODE)).await
}

pub(crate) async fn sweep_stale_media_downloads(max_age: Duration) -> Result<u64, std::io::Error> {
    let cutoff = SystemTime::now()
        .checked_sub(max_age)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    sweep_media_dirs_modified_before(&media_download_root(), cutoff).await
}

pub(crate) async fn sweep_media_dirs_modified_before(
    root: &std::path::Path,
    cutoff: SystemTime,
) -> Result<u64, std::io::Error> {
    if !root.is_dir() {
        return Ok(0);
    }
    let mut swept = 0u64;
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(_) => return Ok(0),
    };
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(_) => continue,
        };
        let is_dir = match entry.file_type().await {
            Ok(file_type) => file_type.is_dir(),
            Err(_) => continue,
        };
        if !is_dir {
            continue;
        }
        let modified = match entry.metadata().await {
            Ok(metadata) => metadata.modified().unwrap_or(SystemTime::now()),
            Err(_) => continue,
        };
        if modified < cutoff && tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
            swept += 1;
        }
    }
    Ok(swept)
}
