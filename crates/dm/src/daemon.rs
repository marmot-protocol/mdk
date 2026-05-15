use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::MissedTickBehavior;

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
    #[arg(long, value_name = "MILLIS", default_value_t = default_sync_interval_ms())]
    sync_interval_ms: u64,
}

#[derive(Clone, Debug)]
struct DaemonDefaults {
    home: PathBuf,
    socket: PathBuf,
    pid_path: PathBuf,
    log_path: PathBuf,
    relay: Option<String>,
    secret_store: Option<SecretStoreKind>,
    keychain_service: Option<String>,
    sync_interval: Duration,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaemonSyncReport {
    pub started_at: u64,
    pub finished_at: u64,
    pub accounts: usize,
    pub events: usize,
    pub joined_groups: usize,
    pub messages: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub socket: PathBuf,
    pub pid: Option<u32>,
    pub pid_file: Option<PathBuf>,
    pub stale_pid: Option<u32>,
    pub started_at: Option<u64>,
    pub home: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub sync_interval_ms: Option<u64>,
    pub last_sync: Option<DaemonSyncReport>,
}

#[derive(Debug)]
struct DaemonState {
    pid: u32,
    started_at: u64,
    last_sync: Option<DaemonSyncReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DaemonRequest {
    Ping,
    Status,
    Shutdown,
    SyncNow { account: Option<String> },
    Execute { cli: Box<Cli> },
}

pub fn default_socket_path(home: &Path) -> PathBuf {
    home.join("dev").join("dmd.sock")
}

pub fn default_pid_path(home: &Path) -> PathBuf {
    home.join("dev").join("dmd.pid")
}

pub fn default_log_path(home: &Path) -> PathBuf {
    home.join("dev").join("dmd.log")
}

fn default_sync_interval_ms() -> u64 {
    2_000
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
        DaemonCommand::Start { sync_interval_ms } => {
            let home = resolve_home(cli.home.clone());
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("DM_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            start_daemon(&cli, &home, &socket, sync_interval_ms).await
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
    DaemonClient::new(socket).execute(cli).await
}

#[derive(Clone, Debug)]
pub struct DaemonClient {
    socket: PathBuf,
}

impl DaemonClient {
    pub fn new(socket: impl AsRef<Path>) -> Self {
        Self {
            socket: socket.as_ref().to_path_buf(),
        }
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub async fn status(&self) -> Result<DaemonStatus, DaemonClientError> {
        let output = send_request(&self.socket, &DaemonRequest::Status).await?;
        if output.code != 0 {
            return Err(DaemonClientError::EmptyResponse);
        }
        serde_json::from_str(output.stdout.trim()).map_err(DaemonClientError::Json)
    }

    pub async fn shutdown(&self) -> Result<CliOutput, DaemonClientError> {
        send_request(&self.socket, &DaemonRequest::Shutdown).await
    }

    pub async fn sync_now(
        &self,
        account: Option<String>,
    ) -> Result<DaemonSyncReport, DaemonClientError> {
        let output = send_request(&self.socket, &DaemonRequest::SyncNow { account }).await?;
        if output.code != 0 {
            return Err(DaemonClientError::EmptyResponse);
        }
        serde_json::from_str(output.stdout.trim()).map_err(DaemonClientError::Json)
    }

    pub(crate) async fn execute(&self, cli: Cli) -> Result<CliOutput, DaemonClientError> {
        send_request(&self.socket, &DaemonRequest::Execute { cli: Box::new(cli) }).await
    }
}

async fn run_server(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = resolve_home(args.home);
    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(&home));
    let pid_path = default_pid_path(&home);
    let log_path = default_log_path(&home);
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_stale_socket(&socket).await?;
    remove_stale_pid(&pid_path).await?;

    let listener = UnixListener::bind(&socket)?;
    write_pid_file(&pid_path)?;
    let defaults = DaemonDefaults {
        home,
        socket: socket.clone(),
        pid_path: pid_path.clone(),
        log_path,
        relay: args.relay,
        secret_store: args.secret_store,
        keychain_service: args.keychain_service,
        sync_interval: Duration::from_millis(args.sync_interval_ms.max(1)),
    };
    let state = Arc::new(Mutex::new(DaemonState {
        pid: std::process::id(),
        started_at: unix_now(),
        last_sync: None,
    }));
    let mut sync_interval = tokio::time::interval(defaults.sync_interval);
    sync_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let shutdown_result = loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, _) = accepted?;
                let should_shutdown = handle_connection(&mut stream, &defaults, state.clone()).await?;
                if should_shutdown {
                    break Ok(());
                }
            }
            _ = sync_interval.tick() => {
                let report = sync_accounts(&defaults, None).await;
                if let Ok(mut state) = state.lock() {
                    state.last_sync = Some(report);
                }
            }
        }
    };

    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pid_path);
    shutdown_result
}

async fn handle_connection(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
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
        DaemonRequest::Status => {
            let status = server_status(defaults, &state);
            (
                false,
                CliOutput {
                    code: 0,
                    stdout: serde_json::to_string(&status)?,
                    stderr: String::new(),
                },
            )
        }
        DaemonRequest::Shutdown => (
            true,
            CliOutput {
                code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        ),
        DaemonRequest::SyncNow { account } => {
            let report = sync_accounts(defaults, account).await;
            if let Ok(mut state) = state.lock() {
                state.last_sync = Some(report.clone());
            }
            (
                false,
                CliOutput {
                    code: if report.errors.is_empty() { 0 } else { 1 },
                    stdout: serde_json::to_string(&report)?,
                    stderr: String::new(),
                },
            )
        }
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

async fn start_daemon(
    cli: &Cli,
    home: &Path,
    socket: &Path,
    sync_interval_ms: Option<u64>,
) -> CliOutput {
    if let Ok(status) = DaemonClient::new(socket).status().await {
        return daemon_output(
            cli.json,
            "daemon already running",
            daemon_status_json(status),
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
    if let Some(sync_interval_ms) = sync_interval_ms {
        command
            .arg("--sync-interval-ms")
            .arg(sync_interval_ms.to_string());
    }
    if let Some(relay) = &cli.relay {
        command.arg("--relay").arg(relay);
    }
    if let Some(secret_store) = cli.secret_store {
        command.arg("--secret-store").arg(secret_store.as_str());
    }
    if let Some(keychain_service) = &cli.keychain_service {
        command.arg("--keychain-service").arg(keychain_service);
    }
    let log_path = default_log_path(home);
    let log = match open_daemon_log(&log_path) {
        Ok(log) => log,
        Err(err) => return daemon_error(cli.json, "daemon_start_failed", err.to_string()),
    };
    let stderr = match log.try_clone() {
        Ok(stderr) => stderr,
        Err(err) => return daemon_error(cli.json, "daemon_start_failed", err.to_string()),
    };
    command.stdout(Stdio::from(log)).stderr(Stdio::from(stderr));

    if let Err(err) = command.spawn() {
        return daemon_error(cli.json, "daemon_start_failed", err.to_string());
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(status) = DaemonClient::new(socket).status().await {
            return daemon_output(cli.json, "daemon started", daemon_status_json(status), 0);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    daemon_error(
        cli.json,
        "daemon_start_failed",
        format!(
            "daemon did not become ready at {}; log: {}{}",
            socket.display(),
            log_path.display(),
            daemon_log_hint(&log_path)
        ),
    )
}

async fn stop_daemon(json: bool, socket: &Path) -> CliOutput {
    match DaemonClient::new(socket).shutdown().await {
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
    let status = DaemonClient::new(socket)
        .status()
        .await
        .ok()
        .unwrap_or_else(|| {
            let home = socket
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf);
            let stale_pid = home
                .as_deref()
                .and_then(|home| read_pid_file(&default_pid_path(home)).ok().flatten());
            DaemonStatus {
                running: false,
                socket: socket.to_path_buf(),
                pid: None,
                pid_file: home.as_deref().map(default_pid_path),
                stale_pid,
                started_at: None,
                log: home.as_deref().map(default_log_path),
                home,
                sync_interval_ms: None,
                last_sync: None,
            }
        });
    let plain = if status.running {
        format!("daemon running\nsocket: {}", socket.display())
    } else {
        "daemon not running".to_owned()
    };
    daemon_output(json, &plain, daemon_status_json(status), 0)
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

fn daemon_status_json(status: DaemonStatus) -> serde_json::Value {
    serde_json::json!({
        "running": status.running,
        "socket": status.socket,
        "pid": status.pid,
        "pid_file": status.pid_file,
        "stale_pid": status.stale_pid,
        "started_at": status.started_at,
        "home": status.home,
        "log": status.log,
        "sync_interval_ms": status.sync_interval_ms,
        "last_sync": status.last_sync,
    })
}

fn server_status(defaults: &DaemonDefaults, state: &Arc<Mutex<DaemonState>>) -> DaemonStatus {
    let state = state.lock().ok();
    DaemonStatus {
        running: true,
        socket: defaults.socket.clone(),
        pid: state.as_ref().map(|state| state.pid),
        pid_file: Some(defaults.pid_path.clone()),
        stale_pid: None,
        started_at: state.as_ref().map(|state| state.started_at),
        home: Some(defaults.home.clone()),
        log: Some(defaults.log_path.clone()),
        sync_interval_ms: Some(defaults.sync_interval.as_millis() as u64),
        last_sync: state.as_ref().and_then(|state| state.last_sync.clone()),
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

async fn sync_accounts(defaults: &DaemonDefaults, account: Option<String>) -> DaemonSyncReport {
    let started_at = unix_now();
    let mut report = DaemonSyncReport {
        started_at,
        finished_at: started_at,
        accounts: 0,
        events: 0,
        joined_groups: 0,
        messages: 0,
        errors: Vec::new(),
    };

    let sync_result = async {
        let secret_store = crate::resolve_secret_store(defaults.secret_store)?;
        let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
        let account_home =
            crate::open_account_home(&defaults.home, secret_store, &keychain_service)?;
        let app = crate::app_for(
            defaults.home.clone(),
            defaults.relay.clone(),
            account_home.clone(),
        );
        let accounts = match account {
            Some(account) => vec![crate::resolve_account(&account_home, Some(account))?],
            None => account_home.accounts()?,
        };
        for account in accounts.into_iter().filter(|account| account.local_signing) {
            report.accounts += 1;
            match crate::sync_command(&app, account.clone()).await {
                Ok(output) => {
                    report.events += output
                        .json
                        .get("events")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0) as usize;
                    report.joined_groups += output
                        .json
                        .get("joined_groups")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len);
                    report.messages += output
                        .json
                        .get("messages")
                        .and_then(serde_json::Value::as_array)
                        .map_or(0, Vec::len);
                }
                Err(err) => {
                    report.errors.push(err.to_string());
                }
            }
        }
        Ok::<(), crate::DmError>(())
    }
    .await;

    if let Err(err) = sync_result {
        report.errors.push(err.to_string());
    }
    report.finished_at = unix_now();
    report
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

fn write_pid_file(pid_path: &Path) -> std::io::Result<()> {
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(pid_path, format!("{}\n", std::process::id()))
}

fn read_pid_file(pid_path: &Path) -> std::io::Result<Option<u32>> {
    match std::fs::read_to_string(pid_path) {
        Ok(contents) => Ok(contents.trim().parse::<u32>().ok()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

async fn remove_stale_pid(pid_path: &Path) -> std::io::Result<()> {
    if read_pid_file(pid_path)?.is_some() {
        match std::fs::remove_file(pid_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    } else {
        Ok(())
    }
}

fn open_daemon_log(log_path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    writeln!(log, "dmd start requested at {}", unix_now())?;
    Ok(log)
}

fn daemon_log_hint(log_path: &Path) -> String {
    match std::fs::read_to_string(log_path) {
        Ok(contents) if !contents.trim().is_empty() => {
            let tail = contents
                .lines()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ");
            format!("; recent log: {tail}")
        }
        _ => String::new(),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
