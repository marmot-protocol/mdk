//! Unix-socket path resolution, binding, stale-socket recovery, and permission hardening.

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

use crate::error::ConnectorError;
use crate::{AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE};

pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join("dev").join("dm-agent.sock")
}

pub fn bind_connector_socket(socket: &Path) -> Result<UnixListener, ConnectorError> {
    bind_connector_socket_with_mode(socket, AGENT_SOCKET_DIR_MODE, AGENT_SOCKET_MODE)
}

pub fn bind_connector_socket_with_mode(
    socket: &Path,
    socket_dir_mode: u32,
    socket_mode: u32,
) -> Result<UnixListener, ConnectorError> {
    if let Some(parent) = socket.parent() {
        prepare_socket_dir(parent, socket_dir_mode)?;
    }
    let listener = match UnixListener::bind(socket) {
        Ok(listener) => listener,
        Err(error) if error.kind() == ErrorKind::AddrInUse => {
            remove_stale_socket(socket, &error)?;
            UnixListener::bind(socket)?
        }
        Err(error) => return Err(error.into()),
    };
    harden_socket_permissions(socket, socket_mode)?;
    Ok(listener)
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

fn prepare_socket_dir(parent: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode))
}

fn harden_socket_permissions(socket: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode))
}

pub(crate) fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}
