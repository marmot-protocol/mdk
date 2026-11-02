//! Unix-socket path resolution, binding, stale-socket recovery, and permission hardening.

use std::io::ErrorKind;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::error::ConnectorError;
use crate::{AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE};

pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join("dev").join("wn-agent.sock")
}

pub fn bind_connector_socket(socket: &Path) -> Result<UnixListener, ConnectorError> {
    bind_connector_socket_with_mode(socket, AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE)
}

pub fn bind_connector_socket_with_mode(
    socket: &Path,
    socket_dir_mode: u32,
    socket_mode: u32,
) -> Result<UnixListener, ConnectorError> {
    bind_connector_socket_with_owned_home(socket, socket_dir_mode, socket_mode, None)
        .map(|(listener, _link_identity)| listener)
}

pub(crate) fn bind_connector_socket_with_owned_home(
    socket: &Path,
    socket_dir_mode: u32,
    socket_mode: u32,
    owned_home: Option<&Path>,
) -> Result<(UnixListener, fs_private::UnixSocketInode), ConnectorError> {
    fs_private::validate_private_unix_socket_path(socket)
        .map_err(|_| ConnectorError::SocketPathTooLong)?;
    let _parent_guard = socket
        .parent()
        .map(|parent| prepare_socket_dir(parent, socket_dir_mode, owned_home))
        .transpose()?;
    let (listener, link_identity) = match bind_private(socket, socket_mode) {
        Ok(bound) => bound,
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            remove_stale_socket(socket, &error)?;
            bind_private(socket, socket_mode)?
        }
        Err(error) => return Err(error.into()),
    };
    Ok((listener, link_identity))
}

/// Bind through a 0700 staging dir so the socket never exists at
/// umask-default permissions, even when `socket_dir_mode` is group-accessible.
fn bind_private(
    socket: &Path,
    socket_mode: u32,
) -> std::io::Result<(UnixListener, fs_private::UnixSocketInode)> {
    let bound = fs_private::bind_unix_listener_private_tracked(socket, socket_mode)?;
    let link_identity = bound.link_identity();
    let listener = bound.into_listener();
    listener.set_nonblocking(true)?;
    Ok((UnixListener::from_std(listener)?, link_identity))
}

pub(crate) fn verify_control_socket_link(
    socket: &Path,
    link_identity: fs_private::UnixSocketInode,
) -> Result<(), ConnectorError> {
    fs_private::verify_unix_socket_inode(socket, link_identity).map_err(ConnectorError::from)
}

/// A socket-setup refusal the connector writes itself: fixed text with no path
/// or identifier, so startup can print it ([`socket_rejection`]).
#[derive(Debug)]
struct SocketRejection(&'static str);

impl std::fmt::Display for SocketRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for SocketRejection {}

fn socket_rejection_error(kind: ErrorKind, message: &'static str) -> std::io::Error {
    std::io::Error::new(kind, SocketRejection(message))
}

/// The connector's own fixed socket-setup message carried by `error`, if any.
/// Errors from the OS or `fs_private` return `None`: their text may name a path.
pub(crate) fn socket_rejection(error: &std::io::Error) -> Option<&'static str> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<SocketRejection>())
        .map(|rejection| rejection.0)
}

/// What occupies a control socket path. The bind path and `wn-agent doctor`
/// share these rules; neither changes the path while probing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketPathState {
    Missing,
    NotSocket,
    /// A listener accepted a connection.
    Live,
    /// A socket file that no listener answers.
    Stale,
}

/// What is at `socket` short of connecting. `None` is a socket file, which
/// only a connect attempt can tell live from stale.
pub(crate) fn socket_path_occupant(socket: &Path) -> std::io::Result<Option<SocketPathState>> {
    match std::fs::metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(None),
        Ok(_) => Ok(Some(SocketPathState::NotSocket)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Some(SocketPathState::Missing)),
        Err(error) => Err(error),
    }
}

/// Whether a failed connect to a socket file means no listener owns it.
pub(crate) fn is_stale_socket_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused | ErrorKind::NotFound
    )
}

fn probe_socket_path(socket: &Path) -> std::io::Result<SocketPathState> {
    if let Some(state) = socket_path_occupant(socket)? {
        return Ok(state);
    }
    match StdUnixStream::connect(socket) {
        Ok(_) => Ok(SocketPathState::Live),
        Err(error) if is_stale_socket_error(&error) => Ok(SocketPathState::Stale),
        Err(error) => Err(error),
    }
}

fn remove_stale_socket(socket: &Path, bind_error: &std::io::Error) -> std::io::Result<()> {
    match probe_socket_path(socket)? {
        SocketPathState::Missing => Ok(()),
        SocketPathState::NotSocket => Err(socket_rejection_error(
            bind_error.kind(),
            "the control socket path exists and is not a Unix socket; \
             move that file or choose another --socket",
        )),
        SocketPathState::Live => Err(socket_rejection_error(
            bind_error.kind(),
            "the control socket is already in use; stop the other wn-agent or choose another --socket",
        )),
        SocketPathState::Stale => match std::fs::remove_file(socket) {
            Ok(()) => Ok(()),
            Err(remove_error) if remove_error.kind() == ErrorKind::NotFound => Ok(()),
            Err(remove_error) => Err(remove_error),
        },
    }
}

/// A socket-directory rule `prepare_socket_dir` enforces once the directory
/// is prepared. `wn-agent doctor` evaluates the same rules without preparing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketDirViolation {
    WorldAccessible,
    UnexpectedGroupWritable,
    ForeignOwner,
}

impl SocketDirViolation {
    fn message(self) -> &'static str {
        match self {
            Self::WorldAccessible => {
                "the control socket directory must not be world-accessible; \
                 chmod it to 0700, or omit --socket to use <home>/dev"
            }
            Self::UnexpectedGroupWritable => {
                "the control socket directory is group-writable but --socket-dir-mode is not; \
                 chmod it to 0700 or 0750, or pass --socket-dir-mode 0770 with --auth-token-file"
            }
            Self::ForeignOwner => {
                "the control socket directory must be owned by the service user or root"
            }
        }
    }
}

pub(crate) fn socket_dir_violation(
    actual_mode: u32,
    requested_mode: u32,
    owner_uid: libc::uid_t,
    effective_uid: libc::uid_t,
) -> Option<SocketDirViolation> {
    if actual_mode & 0o007 != 0 {
        return Some(SocketDirViolation::WorldAccessible);
    }
    if actual_mode & 0o020 != 0 && requested_mode & 0o020 == 0 {
        return Some(SocketDirViolation::UnexpectedGroupWritable);
    }
    if owner_uid != effective_uid && owner_uid != 0 {
        return Some(SocketDirViolation::ForeignOwner);
    }
    None
}

/// Whether the connector owns `parent` and so enforces its mode rather than
/// preserving an externally managed one.
pub(crate) fn socket_dir_is_connector_owned(parent: &Path, owned_home: Option<&Path>) -> bool {
    owned_home.is_some_and(|home| parent == home.join("dev"))
}

fn prepare_socket_dir(
    parent: &Path,
    mode: u32,
    owned_home: Option<&Path>,
) -> std::io::Result<fs_private::PreparedDirectory> {
    let policy = if socket_dir_is_connector_owned(parent, owned_home) {
        fs_private::ExistingDirectoryMode::Enforce
    } else {
        fs_private::ExistingDirectoryMode::Preserve
    };
    let prepared = fs_private::prepare_directory_path(parent, mode, policy)?;
    if let Some(violation) = socket_dir_violation(
        prepared.mode(),
        mode,
        prepared.uid(),
        current_effective_uid(),
    ) {
        return Err(socket_rejection_error(
            ErrorKind::PermissionDenied,
            violation.message(),
        ));
    }
    Ok(prepared)
}

pub(crate) fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}
