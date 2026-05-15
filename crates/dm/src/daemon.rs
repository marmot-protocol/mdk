use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::{Cli, CliOutput, DaemonCommand, SecretStoreKind, resolve_home};

#[derive(Debug, thiserror::Error)]
pub enum DaemonClientError {
    #[error("daemon not running at {socket}: {source}")]
    Connect {
        socket: PathBuf,
        source: std::io::Error,
    },
    #[error("daemon request failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon protocol failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon closed the connection without responding")]
    EmptyResponse,
}

#[derive(Parser, Debug)]
#[command(name = "dmd", about = "Darkmatter daemon")]
struct DaemonArgs {
    #[arg(long, value_name = "PATH")]
    home: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
    #[arg(long, value_name = "URL")]
    relay: Option<String>,
    #[arg(long, value_enum, value_name = "STORE")]
    secret_store: Option<SecretStoreKind>,
    #[arg(long, value_name = "SERVICE")]
    keychain_service: Option<String>,
}

#[derive(Clone, Debug)]
struct DaemonDefaults {
    home: PathBuf,
    relay: Option<String>,
    secret_store: Option<SecretStoreKind>,
    keychain_service: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DaemonRequest {
    Ping,
    Shutdown,
    Execute { cli: Box<Cli> },
}

pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join("dev").join("dmd.sock")
}

pub async fn run_server_from<I, T>(args: I) -> CliOutput
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let argv = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let args = match DaemonArgs::try_parse_from(argv) {
        Ok(args) => args,
        Err(err) => {
            return CliOutput {
                code: err.exit_code(),
                stdout: String::new(),
                stderr: err.to_string(),
            };
        }
    };

    server_output("dmd", run_server(args).await)
}

fn server_output(
    label: &str,
    result: Result<(), Box<dyn std::error::Error + Send + Sync>>,
) -> CliOutput {
    match result {
        Ok(()) => CliOutput {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
        Err(err) => CliOutput {
            code: 1,
            stdout: String::new(),
            stderr: format!("{label}: {err}\n"),
        },
    }
}

pub(crate) async fn run_daemon_command(cli: Cli, command: DaemonCommand) -> CliOutput {
    match command {
        DaemonCommand::Start => {
            let home = resolve_home(cli.home.clone());
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("DM_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            start_daemon(&cli, &home, &socket).await
        }
        DaemonCommand::Stop => {
            let home = resolve_home(cli.home.clone());
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("DM_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            stop_daemon(cli.json, &socket).await
        }
        DaemonCommand::Status => {
            let home = resolve_home(cli.home.clone());
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("DM_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            status_daemon(cli.json, &socket).await
        }
    }
}

pub(crate) async fn send_execute(socket: &Path, cli: Cli) -> Result<CliOutput, DaemonClientError> {
    send_request(socket, &DaemonRequest::Execute { cli: Box::new(cli) }).await
}

async fn run_server(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = resolve_home(args.home);
    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(&home));
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_stale_socket(&socket).await?;

    let listener = UnixListener::bind(&socket)?;
    let defaults = DaemonDefaults {
        home,
        relay: args.relay,
        secret_store: args.secret_store,
        keychain_service: args.keychain_service,
    };

    loop {
        let (mut stream, _) = listener.accept().await?;
        let should_shutdown = handle_connection(&mut stream, &defaults).await?;
        if should_shutdown {
            break;
        }
    }

    let _ = std::fs::remove_file(&socket);
    Ok(())
}

async fn handle_connection(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let request: DaemonRequest = serde_json::from_slice(&bytes)?;
    let (shutdown, output) = match request {
        DaemonRequest::Ping => (
            false,
            CliOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        ),
        DaemonRequest::Shutdown => (
            true,
            CliOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        ),
        DaemonRequest::Execute { mut cli } => {
            apply_defaults(&mut cli, defaults);
            (false, crate::run_cli_local(*cli).await)
        }
    };

    let mut response = serde_json::to_vec(&output)?;
    response.push(b'\n');
    stream.write_all(&response).await?;
    stream.shutdown().await?;
    Ok(shutdown)
}

fn apply_defaults(cli: &mut Cli, defaults: &DaemonDefaults) {
    if cli.home.is_none() {
        cli.home = Some(defaults.home.clone());
    }
    if cli.relay.is_none() {
        cli.relay = defaults.relay.clone();
    }
    if cli.secret_store.is_none() {
        cli.secret_store = defaults.secret_store;
    }
    if cli.keychain_service.is_none() {
        cli.keychain_service = defaults.keychain_service.clone();
    }
    cli.socket = None;
}

async fn start_daemon(cli: &Cli, home: &Path, socket: &Path) -> CliOutput {
    if send_request(socket, &DaemonRequest::Ping).await.is_ok() {
        return daemon_output(
            cli.json,
            "daemon already running",
            serde_json::json!({"running": true, "socket": socket}),
            0,
        );
    }

    let executable = match daemon_executable() {
        Ok(path) => path,
        Err(err) => {
            return daemon_error(cli.json, "daemon_start_failed", err.to_string());
        }
    };

    let mut command = Command::new(executable);
    command.arg("--home").arg(home);
    command.arg("--socket").arg(socket);
    if let Some(relay) = &cli.relay {
        command.arg("--relay").arg(relay);
    }
    if let Some(secret_store) = cli.secret_store {
        command.arg("--secret-store").arg(secret_store.as_str());
    }
    if let Some(keychain_service) = &cli.keychain_service {
        command.arg("--keychain-service").arg(keychain_service);
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());

    if let Err(err) = command.spawn() {
        return daemon_error(cli.json, "daemon_start_failed", err.to_string());
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if send_request(socket, &DaemonRequest::Ping).await.is_ok() {
            return daemon_output(
                cli.json,
                "daemon started",
                serde_json::json!({"running": true, "socket": socket}),
                0,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    daemon_error(
        cli.json,
        "daemon_start_failed",
        format!("daemon did not become ready at {}", socket.display()),
    )
}

async fn stop_daemon(json: bool, socket: &Path) -> CliOutput {
    match send_request(socket, &DaemonRequest::Shutdown).await {
        Ok(_) => daemon_output(
            json,
            "daemon stopped",
            serde_json::json!({"running": false, "socket": socket}),
            0,
        ),
        Err(err) => daemon_error(json, "daemon_unavailable", err.to_string()),
    }
}

async fn status_daemon(json: bool, socket: &Path) -> CliOutput {
    let running = send_request(socket, &DaemonRequest::Ping).await.is_ok();
    let plain = if running {
        format!("daemon running\nsocket: {}", socket.display())
    } else {
        "daemon not running".to_owned()
    };
    daemon_output(
        json,
        &plain,
        serde_json::json!({"running": running, "socket": socket}),
        0,
    )
}

fn daemon_output(json: bool, plain: &str, result: serde_json::Value, code: i32) -> CliOutput {
    if json {
        return CliOutput {
            code,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&serde_json::json!({
                    "ok": code == 0,
                    "result": result,
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        };
    }
    CliOutput {
        code,
        stdout: format!("{plain}\n"),
        stderr: String::new(),
    }
}

fn daemon_error(json: bool, code: &str, message: String) -> CliOutput {
    if json {
        return CliOutput {
            code: 1,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": code,
                        "message": message,
                    }
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        };
    }
    CliOutput {
        code: 1,
        stdout: String::new(),
        stderr: format!("error: {message}\n"),
    }
}

async fn send_request(
    socket: &Path,
    request: &DaemonRequest,
) -> Result<CliOutput, DaemonClientError> {
    let mut stream =
        UnixStream::connect(socket)
            .await
            .map_err(|source| DaemonClientError::Connect {
                socket: socket.to_owned(),
                source,
            })?;
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    if response.is_empty() {
        return Err(DaemonClientError::EmptyResponse);
    }
    Ok(serde_json::from_slice(&response)?)
}

async fn remove_stale_socket(
    socket: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !socket.exists() {
        return Ok(());
    }

    match send_request(socket, &DaemonRequest::Ping).await {
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AddrInUse,
            format!("daemon already running at {}", socket.display()),
        )
        .into()),
        Err(DaemonClientError::Connect { source, .. })
            if matches!(
                source.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::NotFound
            ) =>
        {
            match std::fs::remove_file(socket) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err.into()),
            }
        }
        Err(DaemonClientError::Connect { source, .. }) => Err(source.into()),
        Err(err) => Err(std::io::Error::new(
            ErrorKind::AddrInUse,
            format!(
                "socket already exists at {} but did not respond as dmd: {err}",
                socket.display()
            ),
        )
        .into()),
    }
}

fn daemon_executable() -> Result<PathBuf, String> {
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        let sibling = parent.join("dmd");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let candidate = dir.join("dmd");
                candidate.is_file().then_some(candidate)
            })
        })
        .ok_or_else(|| "dmd not found; ensure it is built and on PATH".to_owned())
}
