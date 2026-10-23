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

fn remove_stale_socket(socket: &Path, bind_error: &std::io::Error) -> std::io::Result<()> {
    let metadata = match std::fs::metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(socket_rejection_error(
            bind_error.kind(),
            "the control socket path exists and is not a Unix socket; \
             move that file or choose another --socket",
        ));
    }
    match StdUnixStream::connect(socket) {
        Ok(_) => Err(socket_rejection_error(
            bind_error.kind(),
            "the control socket is already in use; stop the other wn-agent or choose another --socket",
        )),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::NotFound
            ) =>
        {
            match std::fs::remove_file(socket) {
                Ok(()) => Ok(()),
                Err(remove_error) if remove_error.kind() == ErrorKind::NotFound => Ok(()),
                Err(remove_error) => Err(remove_error),
            }
        }
        Err(error) => Err(error),
    }
}

fn prepare_socket_dir(
    parent: &Path,
    mode: u32,
    owned_home: Option<&Path>,
) -> std::io::Result<fs_private::PreparedDirectory> {
    let is_connector_owned = owned_home.is_some_and(|home| parent == home.join("dev"));
    let policy = if is_connector_owned {
        fs_private::ExistingDirectoryMode::Enforce
    } else {
        fs_private::ExistingDirectoryMode::Preserve
    };
    let prepared = fs_private::prepare_directory_path(parent, mode, policy)?;
    let actual_mode = prepared.mode();
    if actual_mode & 0o007 != 0 {
        return Err(socket_rejection_error(
            ErrorKind::PermissionDenied,
            "the control socket directory must not be world-accessible; \
             chmod it to 0700, or omit --socket to use <home>/dev",
        ));
    }
    if actual_mode & 0o020 != 0 && mode & 0o020 == 0 {
        return Err(socket_rejection_error(
            ErrorKind::PermissionDenied,
            "the control socket directory is group-writable but --socket-dir-mode is not; \
             chmod it to 0700 or 0750, or pass --socket-dir-mode 0770 with --auth-token-file",
        ));
    }
    let effective_uid = current_effective_uid();
    if prepared.uid() != effective_uid && prepared.uid() != 0 {
        return Err(socket_rejection_error(
            ErrorKind::PermissionDenied,
            "the control socket directory must be owned by the service user or root",
        ));
    }
    Ok(prepared)
}

pub(crate) fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}
