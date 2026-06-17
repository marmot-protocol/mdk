//! Daemon lifecycle: start/stop/status, pid/log/socket files, and process setup.

use super::*;

#[derive(Parser, Debug)]
#[command(
    name = "dmd",
    about = "Darkmatter background runtime daemon for live subscriptions and stream previews"
)]
pub(crate) struct DaemonArgs {
    #[arg(long, value_name = "PATH", help = "Use this Darkmatter data directory")]
    pub(crate) home: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Alias for --home")]
    pub(crate) data_dir: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write daemon logs in this directory"
    )]
    pub(crate) logs_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Listen on this Unix socket")]
    pub(crate) socket: Option<PathBuf>,
    #[arg(long, value_name = "URL", hide = true)]
    pub(crate) relay: Option<String>,
    #[arg(
        long,
        value_name = "URLS",
        value_delimiter = ',',
        help = "Comma-separated discovery relays for profiles, relay lists, and KeyPackages"
    )]
    pub(crate) discovery_relays: Vec<String>,
    #[arg(
        long,
        value_name = "URLS",
        value_delimiter = ',',
        help = "Comma-separated default account relays used when creating identities"
    )]
    pub(crate) default_account_relays: Vec<String>,
    #[arg(
        long,
        value_enum,
        value_name = "STORE",
        help = "Store account secrets in the OS keychain or local files"
    )]
    pub(crate) secret_store: Option<SecretStoreKind>,
    #[arg(
        long,
        value_name = "SERVICE",
        help = "Use this OS keychain service name for local secret storage"
    )]
    pub(crate) keychain_service: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct DaemonDefaults {
    pub(crate) home: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) pid_path: PathBuf,
    pub(crate) log_path: PathBuf,
    pub(crate) relay: Option<String>,
    pub(crate) discovery_relays: Vec<String>,
    pub(crate) default_account_relays: Vec<String>,
    pub(crate) secret_store: Option<SecretStoreKind>,
    pub(crate) keychain_service: Option<String>,
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

pub(crate) async fn run_daemon_command(cli: Cli, command: DaemonCommand) -> CliOutput {
    match command {
        DaemonCommand::Start {
            data_dir,
            discovery_relays,
            default_account_relays,
            logs_dir,
        } => {
            let home = resolve_home(cli.home.clone().or(data_dir));
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("DM_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            start_daemon(
                &cli,
                &home,
                &socket,
                discovery_relays,
                default_account_relays,
                logs_dir,
            )
            .await
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

pub(crate) fn prepare_socket_dir(parent: &Path, home: &Path) -> std::io::Result<()> {
    let existed = parent.try_exists()?;
    std::fs::create_dir_all(parent)?;
    if !existed || is_daemon_owned_socket_dir(parent, home) {
        std::fs::set_permissions(
            parent,
            std::fs::Permissions::from_mode(DAEMON_SOCKET_DIR_MODE),
        )?;
    }
    Ok(())
}

pub(crate) fn is_daemon_owned_socket_dir(parent: &Path, home: &Path) -> bool {
    let dev_dir = home.join("dev");
    parent == dev_dir || parent.starts_with(dev_dir)
}

pub(crate) fn harden_socket_permissions(socket: &Path) -> std::io::Result<()> {
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(DAEMON_SOCKET_MODE))
}

pub(crate) fn authorize_daemon_peer(stream: &UnixStream) -> std::io::Result<()> {
    let peer_uid = stream.peer_cred()?.uid();
    let server_uid = current_effective_uid();
    if daemon_peer_uid_authorized(peer_uid, server_uid) {
        return Ok(());
    }
    Err(std::io::Error::new(
        ErrorKind::PermissionDenied,
        "daemon peer UID does not match server UID",
    ))
}

pub(crate) fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

pub(crate) fn daemon_peer_uid_authorized(peer_uid: libc::uid_t, server_uid: libc::uid_t) -> bool {
    peer_uid == server_uid
}

pub(crate) fn blocked_daemon_execute_output(cli: &Cli) -> Option<CliOutput> {
    let (command, reason) = blocked_daemon_execute_command(&cli.command)?;
    let message = format!("{command} cannot be run through dmd: {reason}");
    if cli.json {
        return Some(CliOutput {
            code: 1,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&serde_json::json!({
                    "ok": false,
                    "error": {
                        "code": "daemon_forbidden",
                        "message": message,
                        "command": command,
                        "reason": reason,
                    },
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        });
    }
    Some(CliOutput {
        code: 1,
        stdout: String::new(),
        stderr: format!("error: {message}\n"),
    })
}

pub(crate) fn blocked_daemon_execute_command(
    command: &crate::Command,
) -> Option<(&'static str, &'static str)> {
    match command {
        crate::Command::Reset { .. } => Some((
            "reset",
            "it deletes the daemon home; run dm reset directly after stopping the daemon",
        )),
        crate::Command::Logout { .. } => Some((
            "logout",
            "it removes a local account; run dm logout directly without --socket",
        )),
        crate::Command::Stream { command } => crate::client_hosted_stream_command(command),
        _ => None,
    }
}

pub(crate) async fn start_daemon(
    cli: &Cli,
    home: &Path,
    socket: &Path,
    mut discovery_relays: Vec<String>,
    mut default_account_relays: Vec<String>,
    logs_dir: Option<PathBuf>,
) -> CliOutput {
    if let Ok(status) = DaemonClient::new(socket).status().await {
        return daemon_output(
            cli.json,
            "daemon already running",
            daemon_status_json(status),
            0,
        );
    }
    discovery_relays = match normalize_relay_list(discovery_relays) {
        Ok(relays) => relays,
        Err(err) => return daemon_error(cli.json, relay_error_code(&err), err.to_string()),
    };
    default_account_relays = match normalize_relay_list(default_account_relays) {
        Ok(relays) => relays,
        Err(err) => return daemon_error(cli.json, relay_error_code(&err), err.to_string()),
    };
    let hidden_relay = match crate::resolve_relay(cli.relay.clone()) {
        Ok(relay) => relay,
        Err(err) => return daemon_error(cli.json, relay_error_code(&err), err.to_string()),
    };
    if discovery_relays.is_empty()
        && default_account_relays.is_empty()
        && let Some(relay) = hidden_relay.clone()
    {
        discovery_relays.push(relay.clone());
        default_account_relays.push(relay);
    }
    if discovery_relays.is_empty() && !default_account_relays.is_empty() {
        discovery_relays = default_account_relays.clone();
    }
    if default_account_relays.is_empty() && !discovery_relays.is_empty() {
        default_account_relays = discovery_relays.clone();
    }
    if discovery_relays.is_empty() && default_account_relays.is_empty() {
        return daemon_error(
            cli.json,
            "missing_relay_url",
            crate::DmError::MissingRelay.to_string(),
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
    if !discovery_relays.is_empty() {
        command
            .arg("--discovery-relays")
            .arg(discovery_relays.join(","));
    }
    if !default_account_relays.is_empty() {
        command
            .arg("--default-account-relays")
            .arg(default_account_relays.join(","));
    }
    if let Some(secret_store) = cli.secret_store {
        command.arg("--secret-store").arg(secret_store.as_str());
    }
    if let Some(keychain_service) = &cli.keychain_service {
        command.arg("--keychain-service").arg(keychain_service);
    }
    if let Some(logs_dir) = &logs_dir {
        command.arg("--logs-dir").arg(logs_dir);
    }
    detach_daemon_command(&mut command);
    // Mirror dmd's run_server log-path derivation so the captured stdout/stderr
    // and the readiness hint point at the requested directory, not the default.
    let log_path = match &logs_dir {
        Some(dir) => {
            if let Err(err) = std::fs::create_dir_all(dir) {
                return daemon_error(cli.json, "daemon_start_failed", err.to_string());
            }
            dir.join("dmd.log")
        }
        None => default_log_path(home),
    };
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

pub(crate) async fn stop_daemon(json: bool, socket: &Path) -> CliOutput {
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

pub(crate) async fn status_daemon(json: bool, socket: &Path) -> CliOutput {
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
                last_runtime_activity: None,
                relay_health: None,
                stream_watches: Vec::new(),
            }
        });
    let plain = if status.running {
        format!("daemon running\nsocket: {}", socket.display())
    } else {
        "daemon not running".to_owned()
    };
    daemon_output(json, &plain, daemon_status_json(status), 0)
}

pub(crate) fn daemon_output(
    json: bool,
    plain: &str,
    result: serde_json::Value,
    code: i32,
) -> CliOutput {
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

pub(crate) fn daemon_status_json(status: DaemonStatus) -> serde_json::Value {
    serde_json::json!({
        "running": status.running,
        "socket": status.socket,
        "pid": status.pid,
        "pid_file": status.pid_file,
        "stale_pid": status.stale_pid,
        "started_at": status.started_at,
        "home": status.home,
        "log": status.log,
        "last_runtime_activity": status.last_runtime_activity,
        "relay_health": status.relay_health,
        "stream_watches": status.stream_watches,
    })
}

pub(crate) async fn server_status(
    defaults: &DaemonDefaults,
    state: &Arc<Mutex<DaemonState>>,
    runtime: Option<&marmot_app::MarmotAppRuntime>,
    stream_workers: &StreamWatchWorkers,
) -> DaemonStatus {
    stream_workers.reap_finished();
    let (pid, started_at, last_runtime_activity) = state
        .lock()
        .ok()
        .map(|state| {
            (
                Some(state.pid),
                Some(state.started_at),
                state.last_runtime_activity.clone(),
            )
        })
        .unwrap_or((None, None, None));
    let relay_health = if let Some(runtime) = runtime {
        let shared = runtime.shared_services();
        Some(shared.relay_plane().relay_health().await)
    } else {
        None
    };
    let stream_watches = runtime
        .map(|runtime| runtime.shared_services().agent_streams().reports())
        .unwrap_or_default();
    DaemonStatus {
        running: true,
        socket: defaults.socket.clone(),
        pid,
        pid_file: Some(defaults.pid_path.clone()),
        stale_pid: None,
        started_at,
        home: Some(defaults.home.clone()),
        log: Some(defaults.log_path.clone()),
        last_runtime_activity,
        relay_health,
        stream_watches,
    }
}

pub(crate) fn daemon_error(json: bool, code: &str, message: String) -> CliOutput {
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

pub(crate) fn normalize_relay_list(relays: Vec<String>) -> Result<Vec<String>, crate::DmError> {
    relays
        .into_iter()
        .map(crate::validate_relay_url)
        .collect::<Result<Vec<_>, _>>()
}

pub(crate) fn write_pid_file(pid_path: &Path) -> std::io::Result<()> {
    write_private_file(pid_path, format!("{}\n", std::process::id()))
}

pub(crate) fn read_pid_file(pid_path: &Path) -> std::io::Result<Option<u32>> {
    match std::fs::read_to_string(pid_path) {
        Ok(contents) => Ok(contents.trim().parse::<u32>().ok()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) async fn remove_stale_pid(pid_path: &Path) -> std::io::Result<()> {
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

pub(crate) fn open_daemon_log(log_path: &Path) -> std::io::Result<std::fs::File> {
    let mut log = open_private_append_file(log_path)?;
    writeln!(log, "dmd start requested at {}", unix_now())?;
    Ok(log)
}

pub(crate) fn daemon_log_hint(log_path: &Path) -> String {
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

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

pub(crate) async fn remove_stale_socket(
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

pub(crate) fn relay_error_code(err: &crate::DmError) -> &'static str {
    match err {
        crate::DmError::EmptyRelayUrl => "empty_relay_url",
        crate::DmError::InvalidRelayUrl(_) => "invalid_relay_url",
        _ => "relay_url_error",
    }
}

#[cfg(unix)]
pub(crate) fn detach_daemon_command(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
pub(crate) fn detach_daemon_command(_command: &mut Command) {}

pub(crate) fn daemon_executable() -> Result<PathBuf, String> {
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
