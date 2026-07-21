//! Unix-socket path resolution, binding, stale-socket recovery, and permission hardening.

use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
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
}

pub(crate) fn bind_connector_socket_with_owned_home(
    socket: &Path,
    socket_dir_mode: u32,
    socket_mode: u32,
    owned_home: Option<&Path>,
) -> Result<UnixListener, ConnectorError> {
    if let Some(parent) = socket.parent() {
        prepare_socket_dir(parent, socket_dir_mode, owned_home)?;
    }
    let listener = match bind_private(socket, socket_mode) {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            remove_stale_socket(socket, &error)?;
            bind_private(socket, socket_mode)?
        }
        Err(error) => return Err(error.into()),
    };
    Ok(listener)
}

/// Bind through a 0700 staging dir so the socket never exists at
/// umask-default permissions, even when `socket_dir_mode` is group-accessible.
fn bind_private(socket: &Path, socket_mode: u32) -> std::io::Result<UnixListener> {
    let listener = fs_private::bind_unix_listener_private(socket, socket_mode)?;
    listener.set_nonblocking(true)?;
    UnixListener::from_std(listener)
}

fn remove_stale_socket(socket: &Path, bind_error: &std::io::Error) -> std::io::Result<()> {
    let metadata = match std::fs::metadata(socket) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            bind_error.kind(),
            "agent connector socket path exists and is not a Unix socket",
        ));
    }
    match StdUnixStream::connect(socket) {
        Ok(_) => Err(std::io::Error::new(
            bind_error.kind(),
            "agent connector socket is already in use",
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

fn prepare_socket_dir(parent: &Path, mode: u32, owned_home: Option<&Path>) -> std::io::Result<()> {
    let existed = parent.try_exists()?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(mode).create(parent)?;
    let is_connector_owned = owned_home.is_some_and(|home| parent == home.join("dev"));
    if !existed || is_connector_owned {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

pub(crate) fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}
