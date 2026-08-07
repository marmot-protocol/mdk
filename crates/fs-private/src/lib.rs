//! Restrictive-by-construction creation of local files, directories, and Unix
//! sockets.
//!
//! Every helper creates the artifact already at its target mode (`O_CREAT` +
//! mode, or a staging directory for sockets) so there is no window where it is
//! reachable at the process umask's default permissions. Post-create
//! tightening is only used belt-and-braces for artifacts that already existed.
//!
//! Mode application is Unix-only; on other platforms the helpers still create
//! the artifacts and the mode calls are no-ops.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Owner-only mode for files holding private data.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Owner-only mode for directories holding private artifacts.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// Highest meaningful permission value (`suid|sgid|sticky` + `rwxrwxrwx`).
const MAX_MODE: u32 = 0o7777;

/// An exclusive advisory lease held for as long as its private file descriptor
/// remains open.
///
/// The kernel releases the lease when this value is dropped or the process
/// exits, including abrupt termination. Callers must keep the lock file at a
/// stable path for its full lifetime: unlinking or replacing the file would
/// allow a second process to lock a different inode under the same pathname.
#[cfg(unix)]
#[derive(Debug)]
pub struct PrivateExclusiveFileLease {
    _file: std::fs::File,
}

/// Try to acquire an exclusive, nonblocking advisory lease on `path`.
///
/// The lock file is created at 0600 without following a final symlink and an
/// existing file is tightened to 0600 before locking. Returns
/// [`io::ErrorKind::WouldBlock`] when another process or separately opened
/// descriptor owns the lease. The function never waits for that owner.
///
/// This Unix-only helper uses `flock(LOCK_EX | LOCK_NB)`, which is available to
/// Apple App Group containers as well as the workspace's other Unix targets.
#[cfg(unix)]
pub fn try_acquire_private_exclusive_file_lease(
    path: &Path,
) -> io::Result<PrivateExclusiveFileLease> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    set_private_file_mode(&mut options);
    let file = options
        .open(path)
        .map_err(|error| io_context("open private lease file", path, error))?;
    finish_private_exclusive_file_lease(file, path)
}

#[cfg(unix)]
fn finish_private_exclusive_file_lease(
    file: std::fs::File,
    path: &Path,
) -> io::Result<PrivateExclusiveFileLease> {
    use std::os::fd::AsRawFd;

    let metadata = file
        .metadata()
        .map_err(|error| io_context("read private lease file metadata", path, error))?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "validate private lease file at {}: target must be a regular file",
                path.display()
            ),
        ));
    }
    set_handle_private(&file)
        .map_err(|error| io_context("set private lease file mode", path, error))?;

    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(PrivateExclusiveFileLease { _file: file });
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io_context("acquire nonblocking private lease", path, error));
    }
}

/// How [`prepare_directory_path`] handles a leaf directory that already
/// exists.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingDirectoryMode {
    /// Leave an externally managed directory's mode unchanged.
    Preserve,
    /// Apply the configured mode through the opened directory descriptor.
    Enforce,
}

/// An opened directory returned by [`prepare_directory_path`]. Keeping this
/// value alive keeps the verified leaf open while a caller creates an artifact
/// beneath it.
#[cfg(unix)]
#[derive(Debug)]
pub struct PreparedDirectory {
    directory: std::fs::File,
    path: PathBuf,
    mode: u32,
    uid: libc::uid_t,
    created: bool,
}

#[cfg(unix)]
impl PreparedDirectory {
    #[must_use]
    pub fn mode(&self) -> u32 {
        self.mode
    }

    #[must_use]
    pub fn uid(&self) -> libc::uid_t {
        self.uid
    }

    #[must_use]
    pub fn was_created(&self) -> bool {
        self.created
    }

    /// Try to acquire a private lease file directly beneath this verified
    /// directory without resolving the directory pathname again.
    pub fn try_acquire_private_exclusive_file_lease(
        &self,
        name: &std::ffi::OsStr,
    ) -> io::Result<PrivateExclusiveFileLease> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;

        let mut name_components = Path::new(name).components();
        let single_normal = matches!(
            (name_components.next(), name_components.next()),
            (Some(std::path::Component::Normal(_)), None)
        );
        if !single_normal {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private lease name must be one non-empty path component",
            ));
        }
        let name_c = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private lease name contains a NUL byte",
            )
        })?;
        let path = self.path.join(name);
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                libc::c_uint::try_from(PRIVATE_FILE_MODE).expect("0600 fits c_uint"),
            )
        };
        if descriptor < 0 {
            return Err(io_context(
                "open private lease file relative to prepared directory",
                &path,
                io::Error::last_os_error(),
            ));
        }
        let file = unsafe { std::fs::File::from_raw_fd(descriptor) };
        finish_private_exclusive_file_lease(file, &path)
    }
}

/// Open or create `path` while refusing symlinks.
///
/// Missing components are created at `mode` (subject only to a temporarily
/// more-restrictive umask) and immediately brought to the requested mode via
/// `fchmod`. Existing ancestors are never chmodded. The leaf follows `policy`,
/// allowing owned directories to be enforced while externally managed socket
/// parents are preserved and validated by the caller. Apple platforms open the
/// complete authorized path (or deepest complete existing ancestor) with
/// `O_NOFOLLOW_ANY`, then operate descriptor-relative below that anchor. This
/// avoids independently opening sandbox-managed ancestors such as `/private`
/// and `/private/var` on physical iOS. Android anchors below the ancestors its
/// app sandbox refuses to open, including `/`. Other Unix platforms retain the
/// component-by-component descriptor walk from `/` or `.`.
#[cfg(unix)]
pub fn prepare_directory_path(
    path: &Path,
    mode: u32,
    policy: ExistingDirectoryMode,
) -> io::Result<PreparedDirectory> {
    use std::ffi::{CString, OsString};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    if mode > MAX_MODE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory mode is out of range",
        ));
    }
    let platform_mode = libc::mode_t::try_from(mode).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory mode is unsupported on this platform",
        )
    })?;

    // Platforms spell parts of a private root through symlinks they own
    // themselves: macOS `/var -> private/var`, and `/data/user/0 -> /data/data`
    // inside an Android app's mount namespace. Rewrite only such verified
    // platform aliases out of the prefix; every caller-controlled component
    // below them is still opened with `O_NOFOLLOW`. Without this normalization,
    // neither ordinary temp-backed homes nor an Android app's own data
    // directory could use the descriptor walk.
    // iOS App Group APIs return the canonical `/private/...` spelling. Avoid
    // even probing its first sandbox-managed ancestor independently; the
    // complete-path open below is the authorization boundary.
    #[cfg(target_os = "ios")]
    let normalized_path: Option<PathBuf> = None;
    #[cfg(not(target_os = "ios"))]
    let normalized_path = resolve_platform_directory_aliases(path, TRUSTED_PATH_IDS, inspect_path)?;
    let path = normalized_path.as_deref().unwrap_or(path);

    #[cfg(not(target_vendor = "apple"))]
    let mut components = Vec::<OsString>::new();
    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(_component) => {
                has_normal_component = true;
                #[cfg(not(target_vendor = "apple"))]
                components.push(_component.to_owned());
            }
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path must not contain parent traversal",
                ));
            }
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported directory path prefix",
                ));
            }
        }
    }
    if !has_normal_component && policy == ExistingDirectoryMode::Enforce {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to change the current or root directory mode",
        ));
    }

    #[cfg(target_vendor = "apple")]
    let (mut current, components, mut current_path) = open_apple_authorized_ancestor(path)?;
    // An Android app domain is denied opening `/` and the private root's
    // system-owned parents, so the walk has to anchor deeper.
    #[cfg(target_os = "android")]
    let (mut current, mut current_path): (OwnedFd, PathBuf) = {
        let start = if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut options = OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let (depth, directory, anchor) =
            open_walk_anchor(start, &components, |prefix| options.open(prefix)).map_err(
                |error| io_context("locate openable directory-walk anchor", path, error),
            )?;
        components.drain(..depth);
        (directory.into(), anchor)
    };
    #[cfg(not(any(target_vendor = "apple", target_os = "android")))]
    let (mut current, mut current_path): (OwnedFd, PathBuf) = {
        let start = if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut options = OpenOptions::new();
        use std::os::unix::fs::OpenOptionsExt;
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options
            .open(start)
            .map(Into::into)
            .map_err(|error| io_context("open directory-walk anchor", start, error))?;
        (directory, start.to_owned())
    };
    let mut leaf_created = false;

    for (index, component) in components.iter().enumerate() {
        let component_path = current_path.join(component);
        let component = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory component contains a NUL byte",
            )
        })?;
        let mut created = false;
        let next = match open_directory_at(current.as_raw_fd(), &component) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let result = unsafe {
                    libc::mkdirat(current.as_raw_fd(), component.as_ptr(), platform_mode)
                };
                if result == 0 {
                    created = true;
                } else {
                    let mkdir_error = io::Error::last_os_error();
                    if mkdir_error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(io_context(
                            "create directory component",
                            &component_path,
                            mkdir_error,
                        ));
                    }
                }
                open_directory_at(current.as_raw_fd(), &component).map_err(|error| {
                    io_context(
                        "open newly created directory component",
                        &component_path,
                        error,
                    )
                })?
            }
            Err(error) => {
                return Err(io_context(
                    "open directory component",
                    &component_path,
                    error,
                ));
            }
        };
        if created {
            fchmod_directory(next.as_raw_fd(), platform_mode).map_err(|error| {
                io_context("set created directory mode", &component_path, error)
            })?;
        }
        if index + 1 == components.len() {
            leaf_created = created;
        }
        current = next;
        current_path = component_path;
    }

    if policy == ExistingDirectoryMode::Enforce && !leaf_created {
        fchmod_directory(current.as_raw_fd(), platform_mode)
            .map_err(|error| io_context("set existing directory mode", path, error))?;
    }

    let directory = std::fs::File::from(current);
    let metadata = directory
        .metadata()
        .map_err(|error| io_context("read prepared directory metadata", path, error))?;
    let prepared = PreparedDirectory {
        mode: metadata.mode() & MAX_MODE,
        uid: metadata.uid(),
        created: leaf_created,
        directory,
        path: path.to_owned(),
    };

    #[cfg(target_vendor = "apple")]
    fn open_apple_authorized_ancestor(
        path: &Path,
    ) -> io::Result<(OwnedFd, Vec<OsString>, PathBuf)> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut candidate = path.to_owned();
        let mut missing = Vec::new();
        loop {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW_ANY | libc::O_CLOEXEC);
            match options.open(&candidate) {
                Ok(directory) => {
                    missing.reverse();
                    return Ok((directory.into(), missing, candidate));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let Some(name) = candidate.file_name() else {
                        return Err(io_context(
                            "open authorized directory anchor",
                            &candidate,
                            error,
                        ));
                    };
                    missing.push(name.to_owned());
                    if !candidate.pop() {
                        return Err(io_context(
                            "locate authorized directory anchor",
                            path,
                            error,
                        ));
                    }
                    if candidate.as_os_str().is_empty() {
                        candidate.push(".");
                    }
                }
                Err(error) => {
                    return Err(io_context(
                        "open complete authorized directory path",
                        &candidate,
                        error,
                    ));
                }
            }
        }
    }

    fn open_directory_at(parent: libc::c_int, component: &CString) -> io::Result<OwnedFd> {
        let descriptor = unsafe {
            libc::openat(
                parent,
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn fchmod_directory(descriptor: libc::c_int, mode: libc::mode_t) -> io::Result<()> {
        if unsafe { libc::fchmod(descriptor, mode) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    Ok(prepared)
}

/// Pick the descriptor-walk anchor among the prefixes of `root` joined with
/// `components`: the shallowest prefix `open` accepts below the deepest one it
/// denies, as its component depth, opened value, and path.
///
/// Probing continues past denied prefixes and stops at the first missing one.
/// Every other rejection fails the lookup instead of descending: `O_NOFOLLOW`
/// only guards a path's final component, so skipping a symlinked prefix would
/// let the next, deeper probe resolve through that symlink and anchor outside
/// the intended tree.
#[cfg(all(unix, any(target_os = "android", test)))]
fn open_walk_anchor<T>(
    root: &Path,
    components: &[std::ffi::OsString],
    mut open: impl FnMut(&Path) -> io::Result<T>,
) -> io::Result<(usize, T, PathBuf)> {
    let mut prefix = root.to_owned();
    let mut anchor: Option<(usize, T, PathBuf)> = None;
    for depth in 0..=components.len() {
        if depth > 0 {
            prefix.push(&components[depth - 1]);
        }
        match open(&prefix) {
            Ok(opened) if anchor.is_none() => {
                anchor = Some((depth, opened, prefix.clone()));
            }
            Ok(_) => {}
            // A denied ancestor is the only obstacle this anchor exists for,
            // so keep descending but drop the candidates above it.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => anchor = None,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            // A symlinked prefix reports ELOOP or ENOTDIR depending on the
            // platform, and a non-directory prefix is unusable either way.
            Err(error) => {
                return Err(io_context(
                    "open directory-walk anchor candidate",
                    &prefix,
                    error,
                ));
            }
        }
    }
    anchor.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "every candidate prefix was denied",
        )
    })
}

/// Ids whose writes a private artifact path already trusts because they outrank
/// the process: the superuser everywhere, plus the Android platform uid, which
/// owns `/data` and builds each app's mount namespace.
#[cfg(all(unix, not(target_os = "ios")))]
const TRUSTED_PATH_IDS: &[u32] = if cfg!(target_os = "android") {
    &[0, 1000]
} else {
    &[0]
};

/// What alias verification needs to know about one path component.
#[cfg(all(unix, not(target_os = "ios")))]
#[derive(Clone, Debug)]
struct PathFacts {
    kind: PathKind,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(all(unix, not(target_os = "ios")))]
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathKind {
    Directory,
    /// The link target exactly as stored, which may be relative.
    Symlink(PathBuf),
    Other,
}

/// Read one path component's facts without following a final symlink.
#[cfg(all(unix, not(target_os = "ios")))]
fn inspect_path(path: &Path) -> io::Result<PathFacts> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path)?;
    let kind = if metadata.file_type().is_symlink() {
        PathKind::Symlink(std::fs::read_link(path)?)
    } else if metadata.is_dir() {
        PathKind::Directory
    } else {
        PathKind::Other
    };
    Ok(PathFacts {
        kind,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    })
}

/// Whether only `trusted` ids can modify what `facts` describes: a trusted
/// owner, no world write, and group write only for a trusted group.
#[cfg(all(unix, not(target_os = "ios")))]
fn only_trusted_ids_can_modify(facts: &PathFacts, trusted: &[u32]) -> bool {
    trusted.contains(&facts.uid)
        && facts.mode & 0o002 == 0
        && (facts.mode & 0o020 == 0 || trusted.contains(&facts.gid))
}

#[cfg(all(unix, not(target_os = "ios")))]
fn untrusted_alias(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "refusing untrusted directory alias at {}: {reason}",
            path.display()
        ),
    )
}

/// The normal components of an absolute path, or `None` if it is relative or
/// spells any component as `.` or `..`.
#[cfg(all(unix, not(target_os = "ios")))]
fn absolute_normal_components(path: &Path) -> Option<Vec<&std::ffi::OsStr>> {
    use std::path::Component;

    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    components
        .map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect()
}

/// Verify that `/` through `directory` are real directories only `trusted` ids
/// can modify, so no less-privileged id could have planted or could swap any of
/// them.
#[cfg(all(unix, not(target_os = "ios")))]
fn verify_trusted_directory_chain(
    directory: &Path,
    trusted: &[u32],
    inspect: &mut impl FnMut(&Path) -> io::Result<PathFacts>,
) -> io::Result<()> {
    let Some(components) = absolute_normal_components(directory) else {
        return Err(untrusted_alias(
            directory,
            "target is not a plain absolute path",
        ));
    };
    let mut current = PathBuf::from("/");
    for component in std::iter::once(None).chain(components.into_iter().map(Some)) {
        if let Some(component) = component {
            current.push(component);
        }
        let facts = inspect(&current)
            .map_err(|error| io_context("inspect trusted path component", &current, error))?;
        if facts.kind != PathKind::Directory {
            return Err(untrusted_alias(&current, "component is not a directory"));
        }
        if !only_trusted_ids_can_modify(&facts, trusted) {
            return Err(untrusted_alias(&current, "component is not trusted-owned"));
        }
    }
    Ok(())
}

/// Resolve a symlink target against the link's own directory, keeping the
/// result a plain absolute path.
#[cfg(all(unix, not(target_os = "ios")))]
fn resolve_link_target(link: &Path, target: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    let mut resolved = if target.is_absolute() {
        PathBuf::from("/")
    } else {
        link.parent().unwrap_or(Path::new("/")).to_owned()
    };
    for component in target.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => resolved.push(name),
            // No platform alias needs `.` or `..`, and either would need its own
            // verification pass.
            _ => return Err(untrusted_alias(link, "target is not a plain path")),
        }
    }
    Ok(resolved)
}

/// Rewrite trusted platform directory aliases out of `path`'s prefix.
///
/// Platforms hand callers canonical paths whose prefix crosses a symlink the
/// platform itself owns: macOS spells `/var -> private/var`, and inside an
/// Android app's mount namespace `/data/user/0` is a root-owned symlink to
/// `/data/data`. A strict `O_NOFOLLOW` walk cannot open either component, so
/// replace it with its target — but only after verifying that nothing less
/// privileged than `trusted` could have planted it or could swap it: the
/// symlink is trusted-owned, and every directory above it and above its target
/// is trusted-owned, not world-writable, and group-writable only for a trusted
/// group. An alias that fails verification is rejected, never skipped, so the
/// resolved path still reaches the walk with no symlink in it. The leaf is left
/// alone: it is the artifact itself, and only `O_NOFOLLOW` decides it.
#[cfg(all(unix, not(target_os = "ios")))]
fn resolve_platform_directory_aliases(
    path: &Path,
    trusted: &[u32],
    mut inspect: impl FnMut(&Path) -> io::Result<PathFacts>,
) -> io::Result<Option<PathBuf>> {
    // A relative path, or one still spelling `.`/`..`, is the caller's own
    // validation to reject.
    let Some(components) = absolute_normal_components(path) else {
        return Ok(None);
    };
    let Some((leaf, prefix)) = components.split_last() else {
        return Ok(None);
    };

    let mut resolved = PathBuf::from("/");
    let mut rewritten = false;
    let mut index = 0;
    while index < prefix.len() {
        resolved.push(prefix[index]);
        index += 1;
        let facts = match inspect(&resolved) {
            Ok(facts) => facts,
            // Nothing below the first missing component exists to be an alias;
            // the walk creates it and opens it with `O_NOFOLLOW`.
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(io_context(
                    "inspect directory path component",
                    &resolved,
                    error,
                ));
            }
        };
        let PathKind::Symlink(target) = facts.kind else {
            continue;
        };
        if !trusted.contains(&facts.uid) {
            return Err(untrusted_alias(&resolved, "symlink is not trusted-owned"));
        }
        let parent = resolved.parent().unwrap_or(Path::new("/")).to_owned();
        verify_trusted_directory_chain(&parent, trusted, &mut inspect)?;
        let target = resolve_link_target(&resolved, &target)?;
        verify_trusted_directory_chain(&target, trusted, &mut inspect)?;
        resolved = target;
        rewritten = true;
    }
    if !rewritten {
        return Ok(None);
    }
    for remaining in &prefix[index..] {
        resolved.push(remaining);
    }
    resolved.push(leaf);
    Ok(Some(resolved))
}

fn io_context(operation: &str, path: &Path, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} at {}: {error}", path.display()),
    )
}

/// Configure `options` to create files owner-only (0600). No-op off Unix.
pub fn set_private_file_mode(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(PRIVATE_FILE_MODE);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        let _ = options;
    }
}

/// Create `path` and any missing ancestors as 0700 directories; tighten the
/// leaf to 0700 if it already existed.
pub fn create_dir_all_private(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(PRIVATE_DIR_MODE);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let directory = options.open(path)?;
        if !directory.metadata()?.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "private directory target must be a directory",
            ));
        }
        set_directory_handle_private(&directory)?;
    }
    Ok(())
}

/// Write `bytes` to `path`, creating the file 0600; tightens a pre-existing
/// file to 0600 before writing.
pub fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    set_private_file_mode(&mut options);
    let mut file = options.open(path)?;
    set_handle_private(&file)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Open `path` for appending, creating it 0600; tightens a pre-existing file
/// to 0600.
pub fn open_private_append(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    set_private_file_mode(&mut options);
    let file = options.open(path)?;
    set_handle_private(&file)?;
    Ok(file)
}

/// Create `path` 0600, failing with `AlreadyExists` if it exists.
pub fn create_new_private(path: &Path) -> io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    set_private_file_mode(&mut options);
    options.open(path)
}

/// Ensure a file exists at `path` with mode 0600: created atomically at 0600
/// if missing, tightened to 0600 if pre-existing. Contents are untouched.
pub fn ensure_private_file(path: &Path) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    set_private_file_mode(&mut options);
    let file = options.open(path)?;
    set_handle_private(&file)
}

/// Tighten an existing file at `path` to 0600; `Ok(())` when it does not
/// exist (for optional sidecars such as `-wal`/`-shm`).
pub fn tighten_existing_private_file(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        match options.open(path) {
            Ok(file) => set_handle_private(&file),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Make a SQLite database owner-only before SQLite can create it at the
/// process umask: pre-create the main file 0600 (SQLite then copies its mode
/// onto the `-wal`/`-shm`/journal sidecars it creates) and tighten any
/// sidecars left behind by earlier permissive builds — SQLite does not
/// rewrite pre-existing sidecar modes when the main file's mode changes.
pub fn ensure_private_db_files(path: &Path) -> io::Result<()> {
    ensure_private_file(path)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        tighten_existing_private_file(Path::new(&sidecar))?;
    }
    Ok(())
}

fn set_handle_private(file: &std::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(())
    }
}

fn set_directory_handle_private(directory: &std::fs::File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        directory.set_permissions(std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}

/// The workspace's one octal permission-mode parser.
///
/// Accepts an optional `0o` prefix followed by octal digits, parsed
/// whole-string in radix 8 (so `0600`, `00600`, `600`, and `0o600` all yield
/// `0o600`, and `0` yields mode 0 — rejecting useless-but-valid modes is the
/// caller's policy). Values above `0o7777`, empty input, and non-octal digits
/// are errors.
pub fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix("0o").unwrap_or(trimmed);
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() && byte < b'8')
    {
        return Err(format!(
            "expected octal digits (e.g. 0600), got {trimmed:?}"
        ));
    }
    let mode = u32::from_str_radix(digits, 8)
        .map_err(|_| format!("octal mode out of range, got {trimmed:?}"))?;
    if mode > MAX_MODE {
        return Err(format!("octal mode out of range, got {trimmed:?}"));
    }
    Ok(mode)
}

/// Device/inode identity of a bound Unix socket path entry.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnixSocketInode {
    dev: u64,
    ino: u64,
}

/// Read the device/inode identity of an existing Unix socket path.
#[cfg(unix)]
fn unix_socket_inode(path: &Path) -> io::Result<UnixSocketInode> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a Unix socket",
        ));
    }
    Ok(UnixSocketInode {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// Fail when `path` is missing, is not a Unix socket, or no longer names
/// `expected` (for example after an external unlink or replacement).
#[cfg(unix)]
pub fn verify_unix_socket_inode(path: &Path, expected: UnixSocketInode) -> io::Result<()> {
    const LINK_LOST: &str = "unix socket path no longer names the bound listener";

    let actual = unix_socket_inode(path)?;
    if actual != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, LINK_LOST));
    }
    Ok(())
}

/// Unix listener bound through [`bind_unix_listener_private_tracked`],
/// retaining the final-path link identity callers must keep stable while
/// serving.
#[cfg(unix)]
#[derive(Debug)]
pub struct BoundUnixListener {
    listener: std::os::unix::net::UnixListener,
    link_identity: UnixSocketInode,
}

#[cfg(unix)]
impl BoundUnixListener {
    pub fn link_identity(&self) -> UnixSocketInode {
        self.link_identity
    }

    pub fn into_listener(self) -> std::os::unix::net::UnixListener {
        self.listener
    }
}

/// The staging directory `bind_unix_listener_private` binds through for
/// `final_path`. Exposed so callers and tests can assert staging cleanup
/// without re-deriving the (otherwise private) naming scheme.
#[cfg(unix)]
pub fn socket_staging_dir(final_path: &Path) -> std::path::PathBuf {
    let parent = match final_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = final_path.file_name().unwrap_or_default();
    // Keyed by pid for crash recovery and by target name so concurrent binds
    // of different sockets in the same parent never share staging state.
    parent.join(format!(
        ".sock.{}.{}",
        std::process::id(),
        name.to_string_lossy()
    ))
}

/// Bind a Unix listener so the socket is never reachable at default
/// permissions: bind inside a fresh 0700 staging directory next to
/// `final_path`, chmod the socket to `mode`, then hard-link it into place
/// (failing with `AddrInUse` if `final_path` already exists, matching plain
/// `bind` semantics so callers keep their stale-socket recovery).
///
/// The staging directory name stays short (`.sock.<pid>.<name>`) to respect
/// `sun_path` length limits.
#[cfg(unix)]
pub fn bind_unix_listener_private(
    final_path: &Path,
    mode: u32,
) -> io::Result<std::os::unix::net::UnixListener> {
    bind_unix_listener_private_tracked(final_path, mode).map(BoundUnixListener::into_listener)
}

/// Bind as [`bind_unix_listener_private`] does, retaining the final-path link
/// identity so long-lived services can detect an unlink or replacement.
#[cfg(unix)]
pub fn bind_unix_listener_private_tracked(
    final_path: &Path,
    mode: u32,
) -> io::Result<BoundUnixListener> {
    use std::os::unix::fs::DirBuilderExt;
    use std::os::unix::fs::PermissionsExt;

    let name = final_path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "socket path has no file name")
    })?;
    let staging_dir = socket_staging_dir(final_path);
    // A leftover staging dir can only be ours (pid-suffixed, 0700) from a
    // crashed previous run; clear it so the atomic 0700 create succeeds.
    if staging_dir.symlink_metadata().is_ok() {
        std::fs::remove_dir_all(&staging_dir)?;
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(PRIVATE_DIR_MODE);
    builder.create(&staging_dir)?;

    let staged_socket = staging_dir.join(name);
    let outcome: io::Result<_> = (|| {
        let listener = std::os::unix::net::UnixListener::bind(&staged_socket)?;
        std::fs::set_permissions(&staged_socket, std::fs::Permissions::from_mode(mode))?;
        let link_identity = unix_socket_inode(&staged_socket)?;
        // link(2) fails if the target exists, unlike rename: preserves bind's
        // AddrInUse contract instead of silently replacing a live socket. Keep
        // every fallible validation before this atomic publication: POSIX has
        // no atomic compare-and-unlink operation that could safely compensate
        // a later error without risking removal of a concurrent replacement.
        std::fs::hard_link(&staged_socket, final_path).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{} already exists", final_path.display()),
                )
            } else {
                err
            }
        })?;
        Ok((listener, link_identity))
    })();
    let _ = std::fs::remove_file(&staged_socket);
    let _ = std::fs::remove_dir(&staging_dir);
    let (listener, link_identity) = outcome?;
    Ok(BoundUnixListener {
        listener,
        link_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_octal_mode_accepts_0600_00600_600_and_0o600() {
        for input in ["0600", "00600", "600", "0o600", " 0600 "] {
            assert_eq!(parse_octal_mode(input), Ok(0o600), "input {input:?}");
        }
        assert_eq!(parse_octal_mode("0700"), Ok(0o700));
        assert_eq!(parse_octal_mode("7777"), Ok(0o7777));
    }

    #[test]
    fn parse_octal_mode_parses_bare_zero_to_mode_zero() {
        assert_eq!(parse_octal_mode("0"), Ok(0));
        assert_eq!(parse_octal_mode("00"), Ok(0));
    }

    #[test]
    fn parse_octal_mode_rejects_empty_non_octal_and_overlong() {
        for input in ["", "8", "abc", "077777", "0o", "6 00", "-600", "0x600"] {
            assert!(parse_octal_mode(input).is_err(), "input {input:?}");
        }
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn write_private_creates_file_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        write_private(&path, b"secret").unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"secret");
    }

    #[test]
    fn open_private_append_creates_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        drop(open_private_append(&path).unwrap());
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn private_exclusive_file_lease_is_nonblocking_and_drop_releases_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.lock");
        let first = try_acquire_private_exclusive_file_lease(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);

        let blocked = try_acquire_private_exclusive_file_lease(&path).unwrap_err();
        assert_eq!(blocked.kind(), io::ErrorKind::WouldBlock);

        drop(first);
        drop(try_acquire_private_exclusive_file_lease(&path).unwrap());
    }

    #[test]
    fn private_exclusive_file_lease_child_process() {
        let Some(path) = std::env::var_os("FS_PRIVATE_LEASE_CHILD_PATH") else {
            return;
        };
        let expect_blocked = std::env::var_os("FS_PRIVATE_LEASE_EXPECT_BLOCKED").is_some();
        let result = try_acquire_private_exclusive_file_lease(Path::new(&path));
        if std::env::var_os("FS_PRIVATE_LEASE_EXIT_WITHOUT_DROP").is_some() {
            let _lease = result.expect("child should acquire lease before abrupt exit");
            // Simulate process termination without running Rust destructors.
            // The kernel must still close the descriptor and release the lock.
            unsafe { libc::_exit(0) }
        }
        if expect_blocked {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        } else {
            drop(result.expect("child should acquire released lease"));
        }
    }

    #[test]
    fn private_exclusive_file_lease_coordinates_processes() {
        use std::process::Command;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.lock");
        let first = try_acquire_private_exclusive_file_lease(&path).unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let run_child = |expect_blocked: bool| {
            let mut command = Command::new(&current_exe);
            command
                .arg("--exact")
                .arg("unix_tests::private_exclusive_file_lease_child_process")
                .arg("--nocapture")
                .env("FS_PRIVATE_LEASE_CHILD_PATH", &path);
            if expect_blocked {
                command.env("FS_PRIVATE_LEASE_EXPECT_BLOCKED", "1");
            }
            let status = command.status().expect("run lease child test process");
            assert!(status.success(), "lease child process failed");
        };

        run_child(true);
        drop(first);
        run_child(false);

        let status = Command::new(&current_exe)
            .arg("--exact")
            .arg("unix_tests::private_exclusive_file_lease_child_process")
            .arg("--nocapture")
            .env("FS_PRIVATE_LEASE_CHILD_PATH", &path)
            .env("FS_PRIVATE_LEASE_EXIT_WITHOUT_DROP", "1")
            .status()
            .expect("run abrupt-exit lease child test process");
        assert!(status.success(), "abrupt-exit lease child process failed");
        drop(try_acquire_private_exclusive_file_lease(&path).unwrap());
    }

    #[test]
    fn create_new_private_creates_owner_only_and_rejects_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id");
        drop(create_new_private(&path).unwrap());
        assert_eq!(mode_of(&path), 0o600);
        let err = create_new_private(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn ensure_private_file_tightens_existing_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        std::fs::write(&path, b"data").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        ensure_private_file(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"data", "contents untouched");
        let missing = dir.path().join("fresh.sqlite");
        ensure_private_file(&missing).unwrap();
        assert_eq!(mode_of(&missing), 0o600);
    }

    #[test]
    fn tighten_existing_private_file_ignores_missing_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite-wal");
        tighten_existing_private_file(&path).unwrap();
        std::fs::write(&path, b"wal").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        tighten_existing_private_file(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn private_file_helpers_do_not_follow_final_symlinks() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("artifact");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(write_private(&link, b"replacement").is_err());
        assert!(open_private_append(&link).is_err());
        assert!(ensure_private_file(&link).is_err());
        assert!(tighten_existing_private_file(&link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(mode_of(&target), 0o644);
    }

    #[test]
    fn ensure_private_db_files_tightens_main_db_and_stale_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cache.sqlite");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.path().join(format!("cache.sqlite{suffix}"));
            std::fs::write(&path, b"x").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        ensure_private_db_files(&db).unwrap();
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = dir.path().join(format!("cache.sqlite{suffix}"));
            assert_eq!(mode_of(&path), 0o600, "suffix {suffix:?}");
        }
        // Missing sidecars are fine.
        let fresh = dir.path().join("fresh.sqlite");
        ensure_private_db_files(&fresh).unwrap();
        assert_eq!(mode_of(&fresh), 0o600);
    }

    #[test]
    fn create_dir_all_private_sets_0700() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b");
        create_dir_all_private(&path).unwrap();
        assert_eq!(mode_of(&path), 0o700);
        assert_eq!(mode_of(&dir.path().join("a")), 0o700);
    }

    #[test]
    fn create_dir_all_private_does_not_follow_final_symlink() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("private");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(create_dir_all_private(&link).is_err());
        assert_eq!(mode_of(&target), 0o755);
    }

    #[test]
    fn prepare_directory_path_preserves_or_enforces_existing_leaf_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared");
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750)).unwrap();

        let preserved = prepare_directory_path(&path, 0o700, ExistingDirectoryMode::Preserve)
            .expect("preserve existing directory");
        assert!(!preserved.was_created());
        assert_eq!(preserved.mode() & 0o777, 0o750);
        drop(preserved);

        let enforced = prepare_directory_path(&path, 0o700, ExistingDirectoryMode::Enforce)
            .expect("enforce owned directory mode");
        assert_eq!(enforced.mode() & 0o777, 0o700);
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn prepare_directory_path_creates_each_component_at_requested_mode() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("first");
        let leaf = parent.join("second");
        let prepared = prepare_directory_path(&leaf, 0o770, ExistingDirectoryMode::Preserve)
            .expect("create descriptor-relative directory path");
        assert!(prepared.was_created());
        assert_eq!(prepared.mode() & 0o777, 0o770);
        assert_eq!(mode_of(&parent), 0o770);
        assert_eq!(mode_of(&leaf), 0o770);
    }

    #[test]
    fn prepare_directory_path_rejects_symlinks_in_any_component() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(
            prepare_directory_path(&link.join("child"), 0o700, ExistingDirectoryMode::Enforce)
                .is_err()
        );
        assert!(!target.join("child").exists());
        assert_eq!(mode_of(&target), 0o755);
        assert!(prepare_directory_path(&link, 0o700, ExistingDirectoryMode::Enforce).is_err());
        assert_eq!(mode_of(&target), 0o755);
    }

    fn walk_anchor(root: &Path, components: &[&str]) -> io::Result<(usize, PathBuf)> {
        walk_anchor_probing(root, components).0
    }

    /// The anchor lookup plus every prefix it probed, in order.
    fn walk_anchor_probing(
        root: &Path,
        components: &[&str],
    ) -> (io::Result<(usize, PathBuf)>, Vec<PathBuf>) {
        use std::os::unix::fs::OpenOptionsExt;

        let owned: Vec<std::ffi::OsString> =
            components.iter().map(std::ffi::OsString::from).collect();
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut probed = Vec::new();
        let anchor = open_walk_anchor(root, &owned, |prefix| {
            probed.push(prefix.to_owned());
            options.open(prefix)
        })
        .map(|(depth, _directory, path)| (depth, path));
        (anchor, probed)
    }

    fn effectively_root() -> bool {
        (unsafe { libc::geteuid() }) == 0
    }

    #[test]
    fn open_walk_anchor_descends_past_a_traverse_only_ancestor() {
        if effectively_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("blocked");
        let inner = blocked.join("inner");
        std::fs::create_dir_all(inner.join("leaf")).unwrap();
        // Traversal without read, as Android grants on `/data`.
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o111)).unwrap();

        let anchor = walk_anchor(dir.path(), &["blocked", "inner", "leaf"]);

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            anchor.expect("anchor below the traverse-only ancestor"),
            (2, inner)
        );
    }

    #[test]
    fn open_walk_anchor_discards_candidates_above_a_blocked_ancestor() {
        if effectively_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("readable").join("blocked");
        let inner = blocked.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o111)).unwrap();

        let anchor = walk_anchor(dir.path(), &["readable", "blocked", "inner"]);

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            anchor.expect("anchor below the blocked ancestor"),
            (3, inner)
        );
    }

    #[test]
    fn open_walk_anchor_keeps_the_root_when_no_ancestor_is_blocked() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("first").join("second")).unwrap();
        assert_eq!(
            walk_anchor(dir.path(), &["first", "second"]).expect("anchor at the root"),
            (0, dir.path().to_owned())
        );
    }

    #[test]
    fn open_walk_anchor_stops_at_the_first_missing_component() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            walk_anchor(dir.path(), &["missing", "deeper"]).expect("anchor at the root"),
            (0, dir.path().to_owned())
        );
    }

    #[test]
    fn open_walk_anchor_reports_no_anchor_when_nothing_opens() {
        let components: Vec<std::ffi::OsString> =
            ["a", "b"].iter().map(std::ffi::OsString::from).collect();
        let error = open_walk_anchor(Path::new("/"), &components, |_| {
            Err::<(), _>(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .map(|(depth, _directory, path)| (depth, path))
        .expect_err("no openable prefix");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn open_walk_anchor_rejects_a_symlinked_prefix_component() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(outside.join("leaf")).unwrap();
        let inside = dir.path().join("inside");
        std::fs::create_dir(&inside).unwrap();
        symlink(&outside, inside.join("link")).unwrap();

        let (anchor, probed) = walk_anchor_probing(dir.path(), &["inside", "link", "leaf"]);

        let error = anchor.expect_err("symlinked prefix component");
        assert_ne!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_ne!(error.kind(), io::ErrorKind::NotFound);
        // Probing must stop at the symlink: the next prefix would have resolved
        // through it and anchored under `outside`.
        assert_eq!(
            probed,
            vec![dir.path().to_owned(), inside.clone(), inside.join("link")]
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    }

    #[test]
    fn open_walk_anchor_rejects_a_symlink_below_a_denied_ancestor() {
        use std::os::unix::fs::symlink;

        if effectively_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(outside.join("leaf")).unwrap();
        let blocked = dir.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        symlink(&outside, blocked.join("link")).unwrap();
        // Traversal without read, as Android grants on `/data`.
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o111)).unwrap();

        let (anchor, probed) = walk_anchor_probing(dir.path(), &["blocked", "link", "leaf"]);

        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let error = anchor.expect_err("symlink below a denied ancestor");
        // The denial is forgiven, the symlink below it is not.
        assert_ne!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            probed,
            vec![dir.path().to_owned(), blocked.clone(), blocked.join("link")]
        );
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 1);
    }

    /// Trusted ids for the Android app-namespace shape: superuser plus the
    /// platform uid that owns `/data`.
    const PLATFORM_TRUSTED_IDS: &[u32] = &[0, 1000];
    const ALIASED_PATH: &str = "/data/user/0/pkg/files/Marmot";
    const CANONICAL_PATH: &str = "/data/data/pkg/files/Marmot";

    fn directory_facts(uid: u32, gid: u32, mode: u32) -> PathFacts {
        PathFacts {
            kind: PathKind::Directory,
            uid,
            gid,
            mode,
        }
    }

    fn symlink_facts(target: &str, uid: u32) -> PathFacts {
        PathFacts {
            kind: PathKind::Symlink(PathBuf::from(target)),
            uid,
            gid: uid,
            mode: 0o777,
        }
    }

    /// The Android app mount namespace: `/data/user/0` is a root-owned symlink
    /// to `/data/data`, both on root-owned tmpfs, below a platform-owned
    /// `/data`. Host tests cannot create root-owned fixtures, so alias
    /// verification reads facts supplied by the caller.
    fn android_namespace() -> Vec<(&'static str, PathFacts)> {
        vec![
            ("/", directory_facts(0, 0, 0o755)),
            ("/data", directory_facts(1000, 1000, 0o771)),
            ("/data/user", directory_facts(0, 0, 0o751)),
            ("/data/user/0", symlink_facts("/data/data", 0)),
            ("/data/data", directory_facts(0, 0, 0o751)),
            ("/data/data/pkg", directory_facts(10491, 10491, 0o700)),
            ("/data/data/pkg/files", directory_facts(10491, 10491, 0o771)),
        ]
    }

    fn replacing(
        tree: Vec<(&'static str, PathFacts)>,
        path: &str,
        facts: PathFacts,
    ) -> Vec<(&'static str, PathFacts)> {
        tree.into_iter()
            .map(|(candidate, existing)| {
                if candidate == path {
                    (candidate, facts.clone())
                } else {
                    (candidate, existing)
                }
            })
            .collect()
    }

    fn without(tree: Vec<(&'static str, PathFacts)>, path: &str) -> Vec<(&'static str, PathFacts)> {
        tree.into_iter()
            .filter(|(candidate, _)| *candidate != path)
            .collect()
    }

    fn inspector(
        tree: Vec<(&'static str, PathFacts)>,
    ) -> impl FnMut(&Path) -> io::Result<PathFacts> {
        move |path| {
            tree.iter()
                .find(|(candidate, _)| Path::new(candidate) == path)
                .map(|(_, facts)| facts.clone())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn resolve_aliases(
        path: &str,
        tree: Vec<(&'static str, PathFacts)>,
    ) -> io::Result<Option<PathBuf>> {
        resolve_platform_directory_aliases(Path::new(path), PLATFORM_TRUSTED_IDS, inspector(tree))
    }

    #[test]
    fn trusted_path_ids_admit_the_platform_uid_only_where_it_is_one() {
        // Uid 1000 owns `/data` on Android but is an ordinary human user on a
        // desktop, where trusting it would be a hole.
        assert!(TRUSTED_PATH_IDS.contains(&0));
        assert_eq!(
            TRUSTED_PATH_IDS.contains(&1000),
            cfg!(target_os = "android")
        );
    }

    #[test]
    fn resolve_platform_directory_aliases_rewrites_a_trusted_platform_alias() {
        assert_eq!(
            resolve_aliases(ALIASED_PATH, android_namespace()).expect("trusted alias resolves"),
            Some(PathBuf::from(CANONICAL_PATH))
        );
    }

    #[test]
    fn resolve_platform_directory_aliases_rejects_an_untrusted_alias_owner() {
        let tree = replacing(
            android_namespace(),
            "/data/user/0",
            symlink_facts("/data/data", 10491),
        );
        let error = resolve_aliases(ALIASED_PATH, tree).expect_err("app-owned alias");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_rejects_an_untrusted_group_writable_ancestor() {
        let tree = replacing(
            android_namespace(),
            "/data",
            directory_facts(0, 2000, 0o775),
        );
        let error = resolve_aliases(ALIASED_PATH, tree).expect_err("group-writable ancestor");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_rejects_a_world_writable_ancestor() {
        let tree = replacing(android_namespace(), "/data", directory_facts(0, 0, 0o777));
        let error = resolve_aliases(ALIASED_PATH, tree).expect_err("world-writable ancestor");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_rejects_an_untrusted_alias_target() {
        let tree = replacing(
            android_namespace(),
            "/data/data",
            directory_facts(10491, 10491, 0o700),
        );
        let error = resolve_aliases(ALIASED_PATH, tree).expect_err("app-owned alias target");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_trusts_only_the_ids_it_is_given() {
        // The Android shape needs the platform uid that owns `/data`; the
        // superuser alone must not be enough to accept it.
        let error = resolve_platform_directory_aliases(
            Path::new(ALIASED_PATH),
            &[0],
            inspector(android_namespace()),
        )
        .expect_err("platform-owned ancestor outside the trusted ids");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_leaves_an_alias_free_path_alone() {
        assert_eq!(
            resolve_aliases(CANONICAL_PATH, android_namespace()).expect("no alias to resolve"),
            None
        );
    }

    #[test]
    fn resolve_platform_directory_aliases_leaves_a_leaf_alias_to_the_walk() {
        // The leaf is the artifact itself: only `O_NOFOLLOW` decides it.
        assert_eq!(
            resolve_aliases("/data/user/0", android_namespace()).expect("leaf left alone"),
            None
        );
    }

    #[test]
    fn resolve_platform_directory_aliases_keeps_components_below_a_missing_one() {
        let tree = without(android_namespace(), "/data/data/pkg");
        assert_eq!(
            resolve_aliases(ALIASED_PATH, tree).expect("alias above a missing component"),
            Some(PathBuf::from(CANONICAL_PATH))
        );
    }

    #[test]
    fn resolve_platform_directory_aliases_rejects_a_real_untrusted_symlinked_prefix() {
        use std::os::unix::fs::symlink;

        if effectively_root() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // Canonical spelling throughout, so only ownership can reject the link.
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        symlink(&target, base.join("link")).unwrap();

        let error = resolve_platform_directory_aliases(
            &base.join("link").join("leaf"),
            TRUSTED_PATH_IDS,
            inspect_path,
        )
        .expect_err("test-user-owned symlinked prefix");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn resolve_platform_directory_aliases_resolves_a_real_platform_alias() {
        // macOS ships the one trusted-alias shape whose root ownership a host
        // test cannot fabricate: `/var -> private/var`.
        let Ok(metadata) = std::fs::symlink_metadata("/var") else {
            return;
        };
        if !metadata.file_type().is_symlink() {
            return;
        }
        assert_eq!(
            resolve_platform_directory_aliases(
                Path::new("/var/folders/leaf"),
                TRUSTED_PATH_IDS,
                inspect_path,
            )
            .expect("root-owned platform alias resolves"),
            Some(PathBuf::from("/private/var/folders/leaf"))
        );
    }

    #[test]
    fn prepared_directory_lease_is_private_nonblocking_and_descriptor_relative() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("marmot");
        let prepared = prepare_directory_path(&root, 0o700, ExistingDirectoryMode::Enforce)
            .expect("prepare fresh root");
        let name = std::ffi::OsStr::new(".runtime.lock");

        let first = prepared
            .try_acquire_private_exclusive_file_lease(name)
            .expect("acquire initial lease");
        assert_eq!(mode_of(&root), 0o700);
        assert_eq!(mode_of(&root.join(name)), 0o600);

        let blocked = prepared
            .try_acquire_private_exclusive_file_lease(name)
            .expect_err("second owner must not block");
        assert_eq!(blocked.kind(), io::ErrorKind::WouldBlock);

        drop(first);
        drop(
            prepared
                .try_acquire_private_exclusive_file_lease(name)
                .expect("released lease can be reacquired"),
        );
    }

    #[test]
    fn prepared_directory_lease_rejects_invalid_names_and_symlink_targets() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let prepared = prepare_directory_path(
            dir.path(),
            PRIVATE_DIR_MODE,
            ExistingDirectoryMode::Preserve,
        )
        .expect("prepare root");

        for name in ["", ".", "..", "child/lock", "/etc/passwd", "../escape"] {
            let error = prepared
                .try_acquire_private_exclusive_file_lease(std::ffi::OsStr::new(name))
                .expect_err("invalid lease name must be rejected");
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidInput,
                "name {name:?} must be rejected by name validation"
            );
        }

        let target = dir.path().join("target");
        let link = dir.path().join("lease-link");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&target, &link).unwrap();

        assert!(
            prepared
                .try_acquire_private_exclusive_file_lease(std::ffi::OsStr::new("lease-link"))
                .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(mode_of(&target), 0o644);
    }

    #[test]
    fn verify_unix_socket_inode_fails_when_final_path_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let bound = bind_unix_listener_private_tracked(&socket, 0o600).unwrap();
        let identity = bound.link_identity();
        std::fs::remove_file(&socket).unwrap();
        let err = verify_unix_socket_inode(&socket, identity).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn verify_unix_socket_inode_fails_when_path_names_a_different_socket() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.sock");
        let second = dir.path().join("second.sock");
        let first_bound = bind_unix_listener_private_tracked(&first, 0o600).unwrap();
        let first_identity = first_bound.link_identity();
        drop(first_bound);
        drop(bind_unix_listener_private(&second, 0o600).unwrap());
        std::fs::rename(&second, &first).unwrap();
        let err = verify_unix_socket_inode(&first, first_identity).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn bind_unix_listener_private_yields_0600_socket_and_no_staging_leftover() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let listener = bind_unix_listener_private(&socket, 0o600).unwrap();
        assert_eq!(mode_of(&socket), 0o600);
        assert!(
            !socket_staging_dir(&socket).exists(),
            "staging dir should be cleaned up"
        );
        // The listener must still accept connections at the final path.
        let client = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        let (_server, _addr) = listener.accept().unwrap();
        drop(client);
    }

    #[test]
    fn bind_unix_listener_private_errors_addr_in_use_when_target_exists() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        std::fs::write(&socket, b"").unwrap();
        let err = bind_unix_listener_private(&socket, 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn bind_unix_listener_private_recovers_from_stale_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("test.sock");
        let staging = socket_staging_dir(&socket);
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("leftover"), b"x").unwrap();
        drop(bind_unix_listener_private(&socket, 0o600).unwrap());
        assert_eq!(mode_of(&socket), 0o600);
        assert!(!staging.exists());
    }

    #[test]
    fn concurrent_binds_in_same_parent_use_distinct_staging_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.sock");
        let second = dir.path().join("second.sock");
        assert_ne!(socket_staging_dir(&first), socket_staging_dir(&second));
        let first_listener = bind_unix_listener_private(&first, 0o600).unwrap();
        let second_listener = bind_unix_listener_private(&second, 0o600).unwrap();
        assert_eq!(mode_of(&first), 0o600);
        assert_eq!(mode_of(&second), 0o600);
        drop((first_listener, second_listener));
    }
}
