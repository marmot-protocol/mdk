//! Connector-enforced confinement for outbound plaintext media paths.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::ConnectorError;

#[derive(Clone, Default)]
pub(crate) struct MediaAllowedRoots {
    roots: Arc<[MediaAllowedRoot]>,
}

struct MediaAllowedRoot {
    configured_path: PathBuf,
    canonical_path: PathBuf,
    directory: Arc<File>,
}

impl MediaAllowedRoots {
    pub(crate) fn prepare(configured_roots: &[PathBuf]) -> Result<Self, ConnectorError> {
        let mut roots = Vec::with_capacity(configured_roots.len());
        for configured_root in configured_roots {
            let configured_path = absolute_lexical_path(configured_root)?;
            let canonical_path = std::fs::canonicalize(&configured_path)?;
            if roots
                .iter()
                .any(|root: &MediaAllowedRoot| root.canonical_path == canonical_path)
            {
                continue;
            }
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
            let directory = options.open(&canonical_path)?;
            if !directory.metadata()?.file_type().is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "media allowed root must be a directory",
                )
                .into());
            }
            roots.push(MediaAllowedRoot {
                configured_path,
                canonical_path,
                directory: Arc::new(directory),
            });
        }
        Ok(Self {
            roots: roots.into(),
        })
    }

    pub(crate) async fn read_regular_file(&self, path: PathBuf) -> Result<Vec<u8>, ConnectorError> {
        let roots = self.clone();
        tokio::task::spawn_blocking(move || roots.read_regular_file_blocking(&path))
            .await
            .map_err(|_| ConnectorError::MediaPathDenied("media file read task failed"))?
    }

    fn read_regular_file_blocking(&self, path: &Path) -> Result<Vec<u8>, ConnectorError> {
        if self.roots.is_empty() || !path.is_absolute() {
            return Err(ConnectorError::MediaPathDenied(
                "media path is outside configured roots",
            ));
        }
        let path = lexical_normalize(path);
        for root in self.roots.iter() {
            let relative = path
                .strip_prefix(&root.configured_path)
                .or_else(|_| path.strip_prefix(&root.canonical_path));
            let Ok(relative) = relative else {
                continue;
            };
            if relative.as_os_str().is_empty() {
                continue;
            }
            let Ok(mut file) = open_regular_beneath(&root.directory, relative) else {
                continue;
            };
            let mut plaintext = Vec::new();
            file.read_to_end(&mut plaintext)
                .map_err(|_| ConnectorError::MediaPathDenied("media file could not be read"))?;
            return Ok(plaintext);
        }
        Err(ConnectorError::MediaPathDenied(
            "media path is outside configured roots",
        ))
    }
}

fn absolute_lexical_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(lexical_normalize(path))
    } else {
        Ok(lexical_normalize(&std::env::current_dir()?.join(path)))
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

/// Open each path component relative to an already-open approved root. Every
/// component rejects symlinks; the leaf is opened nonblocking before its file
/// type is checked so a FIFO cannot pin a connector worker.
fn open_regular_beneath(root: &File, relative: &Path) -> io::Result<File> {
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "media path contains a disallowed component",
            )),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "media path must name a file beneath the allowed root",
        ));
    }

    let mut current: Option<OwnedFd> = None;
    for (index, component) in components.iter().enumerate() {
        let parent_fd = current
            .as_ref()
            .map_or_else(|| root.as_raw_fd(), AsRawFd::as_raw_fd);
        let is_leaf = index + 1 == components.len();
        let flags = if is_leaf {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY
        };
        current = Some(openat(parent_fd, component.as_bytes(), flags)?);
    }

    let file = File::from(current.expect("nonempty media path must yield a file descriptor"));
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "media path must identify a regular file",
        ));
    }
    Ok(file)
}

fn openat(parent: RawFd, name: &[u8], flags: libc::c_int) -> io::Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "media path contains NUL"))?;
    // SAFETY: `parent` is a live directory descriptor, `name` is NUL-terminated,
    // and the returned descriptor is immediately owned on success.
    let descriptor = unsafe { libc::openat(parent, name.as_ptr(), flags) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a fresh descriptor that has not been wrapped.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::MediaAllowedRoots;
    use crate::ConnectorError;

    #[tokio::test]
    async fn empty_roots_deny_every_media_path() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let roots = MediaAllowedRoots::prepare(&[]).unwrap();
        assert!(matches!(
            roots.read_regular_file(file.path().to_owned()).await,
            Err(ConnectorError::MediaPathDenied(_))
        ));
    }

    #[tokio::test]
    async fn allowed_root_reads_regular_file() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("staged.bin");
        std::fs::write(&file, b"allowed").unwrap();
        let roots = MediaAllowedRoots::prepare(&[root.path().to_owned()]).unwrap();
        assert_eq!(roots.read_regular_file(file).await.unwrap(), b"allowed");
    }

    #[tokio::test]
    async fn allowed_root_rejects_outside_file_and_directory() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let roots = MediaAllowedRoots::prepare(&[root.path().to_owned()]).unwrap();
        for path in [outside.path(), root.path()] {
            assert!(matches!(
                roots.read_regular_file(path.to_owned()).await,
                Err(ConnectorError::MediaPathDenied(_))
            ));
        }
    }

    #[tokio::test]
    async fn allowed_root_rejects_leaf_and_ancestor_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let real_dir = root.path().join("real");
        std::fs::create_dir(&real_dir).unwrap();
        let real_file = real_dir.join("secret.bin");
        std::fs::write(&real_file, b"secret").unwrap();
        let leaf_link = root.path().join("leaf-link");
        symlink(&real_file, &leaf_link).unwrap();
        let dir_link = root.path().join("dir-link");
        symlink(&real_dir, &dir_link).unwrap();
        let roots = MediaAllowedRoots::prepare(&[root.path().to_owned()]).unwrap();

        for path in [leaf_link, dir_link.join("secret.bin")] {
            assert!(matches!(
                roots.read_regular_file(path).await,
                Err(ConnectorError::MediaPathDenied(_))
            ));
        }
    }
}
