//! Daemon lifecycle: start/stop/status, pid/log/socket files, and process setup.

use super::*;

#[derive(Parser, Debug)]
#[command(
    name = "wnd",
    about = "White Noise background runtime daemon for live subscriptions and stream previews"
)]
pub(crate) struct DaemonArgs {
    #[arg(
        long,
        value_name = "PATH",
        help = "Use this White Noise data directory"
    )]
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
    home.join("dev").join("wnd.sock")
}

pub fn default_pid_path(home: &Path) -> PathBuf {
    home.join("dev").join("wnd.pid")
}

pub fn default_log_path(home: &Path) -> PathBuf {
    home.join("dev").join("wnd.log")
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
                .or_else(|| std::env::var_os("WN_SOCKET").map(PathBuf::from))
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
                .or_else(|| std::env::var_os("WN_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            stop_daemon(cli.json, &socket).await
        }
        DaemonCommand::Status => {
            let home = resolve_home(cli.home.clone());
            let socket = cli
                .socket
                .clone()
                .or_else(|| std::env::var_os("WN_SOCKET").map(PathBuf::from))
                .unwrap_or_else(|| default_socket_path(&home));
            status_daemon(cli.json, &socket).await
        }
    }
}

pub(crate) fn prepare_socket_dir(
    parent: &Path,
    home: &Path,
) -> std::io::Result<fs_private::PreparedDirectory> {
    let policy = if is_daemon_owned_socket_dir(parent, home) {
        fs_private::ExistingDirectoryMode::Enforce
    } else {
        fs_private::ExistingDirectoryMode::Preserve
    };
    let prepared = fs_private::prepare_directory_path(parent, DAEMON_SOCKET_DIR_MODE, policy)?;
    if prepared.mode() & 0o007 != 0 || prepared.mode() & 0o020 != 0 {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "daemon socket directory has unsafe on-disk permissions",
        ));
    }
    let effective_uid = current_effective_uid();
    if prepared.uid() != effective_uid && prepared.uid() != 0 {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "daemon socket directory must be owned by the service user or root",
        ));
    }
    Ok(prepared)
}

pub(crate) fn is_daemon_owned_socket_dir(parent: &Path, home: &Path) -> bool {
    let dev_dir = home.join("dev");
    parent == dev_dir || parent.starts_with(dev_dir)
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
    let message = format!("{command} cannot be run through wnd: {reason}");
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
            "it deletes the daemon home; run wn reset directly after stopping the daemon",
        )),
        crate::Command::Logout { .. } => Some((
            "logout",
            "it removes a local account; run wn logout directly without --socket",
        )),
        crate::Command::Stream { command } => crate::client_hosted_stream_command(command),
        _ => None,
    }
}

/// How long `wn daemon start` waits for the `wnd` it spawned to answer while
/// that daemon is still running. A warm start answers in well under a second,
/// but the first launch of a freshly linked binary on a loaded macOS machine
/// waited up to 8.5 s before reaching `main` (mdk#2696), and the daemon answers
/// only after its app runtime starts, which waits up to 45 s for each account
/// to open (`APP_RUNTIME_ACCOUNT_READY_WAIT` in `marmot-app`). The cap covers
/// both, so it stops only a daemon that has outlived its own startup budget. A
/// daemon that exits fails the start at once.
pub(crate) const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(60);

const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Explicit test builds only: `WN_DEV_DAEMON_START_TIMEOUT_MS` replaces
/// [`DAEMON_START_TIMEOUT`] so CLI tests can reach the cap without waiting for
/// it. Like `WN_DEV_SETTLEMENT_QUIESCENCE_MS`, it is an error in normal
/// binaries.
pub(crate) fn resolve_daemon_start_timeout(
    value: Option<&str>,
    dev_overrides_enabled: bool,
) -> Result<Duration, String> {
    match value {
        None => Ok(DAEMON_START_TIMEOUT),
        Some(_) if !dev_overrides_enabled => Err(
            "WN_DEV_DAEMON_START_TIMEOUT_MS requires a test-policy-overrides build; unset it in normal binaries"
                .to_owned(),
        ),
        Some(value) => Ok(value
            .trim()
            .parse()
            .map(Duration::from_millis)
            .unwrap_or(DAEMON_START_TIMEOUT)),
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
    let start_timeout = match resolve_daemon_start_timeout(
        std::env::var("WN_DEV_DAEMON_START_TIMEOUT_MS")
            .ok()
            .as_deref(),
        cfg!(feature = "test-policy-overrides"),
    ) {
        Ok(timeout) => timeout,
        Err(message) => {
            return daemon_error(
                cli.json,
                "dev_daemon_start_timeout_override_in_release",
                message,
            );
        }
    };
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
            crate::WnError::MissingRelay.to_string(),
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
    // Mirror wnd's run_server log-path derivation so the captured stdout/stderr
    // and the readiness hint point at the requested directory, not the default.
    let log_path = match &logs_dir {
        Some(dir) => {
            if let Err(err) = std::fs::create_dir_all(dir) {
                return daemon_error(cli.json, "daemon_start_failed", err.to_string());
            }
            dir.join("wnd.log")
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

    // Ctrl-C stops the daemon this command starts: it runs in its own process
    // group, so the terminal's SIGINT does not reach it. Register before the
    // spawn so no SIGINT can end this process with the daemon left starting.
    let sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt());
    let interrupted = async move {
        let received = match sigint {
            Ok(mut sigint) => sigint.recv().await.is_some(),
            Err(_) => false,
        };
        if !received {
            std::future::pending::<()>().await;
        }
    };
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return daemon_error(cli.json, "daemon_start_failed", err.to_string()),
    };

    match wait_for_spawned_daemon(socket, &mut child, start_timeout, interrupted).await {
        SpawnedDaemon::Ready(status) => {
            daemon_output(cli.json, "daemon started", daemon_status_json(status), 0)
        }
        SpawnedDaemon::AlreadyRunning(status) => daemon_output(
            cli.json,
            "daemon already running",
            daemon_status_json(status),
            0,
        ),
        SpawnedDaemon::Exited(exit) => daemon_error(
            cli.json,
            "daemon_start_failed",
            format!(
                "wnd exited before it became ready ({exit}); log: {}{}",
                log_path.display(),
                daemon_log_hint(&log_path)
            ),
        ),
        SpawnedDaemon::Stopped => daemon_error(
            cli.json,
            "daemon_start_timeout",
            format!(
                "daemon did not become ready at {} within {start_timeout:?}, so it was stopped; log: {}{}",
                socket.display(),
                log_path.display(),
                daemon_log_hint(&log_path)
            ),
        ),
        SpawnedDaemon::Interrupted => daemon_error(
            cli.json,
            "daemon_start_interrupted",
            format!(
                "interrupted before the daemon at {} became ready, so it was stopped; log: {}",
                socket.display(),
                log_path.display()
            ),
        ),
    }
}

/// How the `wnd` that `start_daemon` spawned turned out.
#[derive(Debug)]
pub(crate) enum SpawnedDaemon {
    /// It answered on the socket and has opened its accounts.
    Ready(DaemonStatus),
    /// Another daemon answers on the socket: two starts raced for it and the
    /// other one won. The spawned `wnd` has exited or been stopped.
    AlreadyRunning(DaemonStatus),
    /// It exited before it answered.
    Exited(std::process::ExitStatus),
    /// It was still running but not ready when the timeout passed, so it was
    /// killed and reaped.
    Stopped,
    /// The wait was interrupted, so it was killed and reaped.
    Interrupted,
}

/// Wait for the `wnd` that `start_daemon` spawned to answer on `socket` with
/// its accounts open. It fails as soon as the daemon exits, and stops the
/// daemon once `timeout` passes or `interrupt` completes, so a failed start
/// never leaves a daemon running.
pub(crate) async fn wait_for_spawned_daemon(
    socket: &Path,
    child: &mut std::process::Child,
    timeout: Duration,
    interrupt: impl std::future::Future<Output = ()>,
) -> SpawnedDaemon {
    let deadline = Instant::now() + timeout;
    let client = DaemonClient::new(socket);
    tokio::pin!(interrupt);
    // At most one status probe is in flight, checked alongside the child, the
    // deadline and the interrupt: a daemon from before status answered during
    // startup holds the probe until it has opened its accounts.
    let mut probe = Box::pin(client.status());
    loop {
        tokio::select! {
            status = &mut probe => {
                match status {
                    Ok(status) if status.pid == Some(child.id()) && !status.starting => {
                        return SpawnedDaemon::Ready(status);
                    }
                    Ok(status) if status.pid == Some(child.id()) => {}
                    Ok(status) => {
                        // Another daemon holds the socket. Stop ours, which
                        // could otherwise take the socket over once that one
                        // stops.
                        let _ = child.kill();
                        let _ = child.wait();
                        return SpawnedDaemon::AlreadyRunning(status);
                    }
                    Err(_) => {}
                }
                tokio::time::sleep(DAEMON_POLL_INTERVAL).await;
                probe = Box::pin(client.status());
            }
            () = tokio::time::sleep(DAEMON_POLL_INTERVAL) => {}
            () = &mut interrupt => {
                let _ = child.kill();
                let _ = child.wait();
                return SpawnedDaemon::Interrupted;
            }
        }
        if let Ok(Some(exit)) = child.try_wait() {
            return match tokio::time::timeout(DAEMON_POLL_INTERVAL * 10, client.status()).await {
                Ok(Ok(status)) => SpawnedDaemon::AlreadyRunning(status),
                _ => SpawnedDaemon::Exited(exit),
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return SpawnedDaemon::Stopped;
        }
    }
}

/// How long `wn daemon stop` waits for the daemon to exit after it accepts the
/// request. The daemon answers before it shuts down its app runtime, which
/// gives its account workers 5 s and its relay connections 2 s, side by side;
/// a daemon on a live relay exited within 0.2 s of answering on a heavily
/// loaded machine (mdk#2696).
pub(crate) const DAEMON_STOP_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn stop_daemon(json: bool, socket: &Path) -> CliOutput {
    stop_daemon_within(json, socket, DAEMON_STOP_TIMEOUT).await
}

/// Ask the daemon on `socket` to stop, and report it stopped only once its
/// process has exited.
pub(crate) async fn stop_daemon_within(json: bool, socket: &Path, timeout: Duration) -> CliOutput {
    // The daemon answers before it shuts down, with the pid to wait for.
    let pid = match DaemonClient::new(socket).shutdown().await {
        Ok(output) => serde_json::from_str::<DaemonShutdownAck>(output.stdout.trim())
            .ok()
            .map(|ack| ack.pid),
        Err(err @ DaemonClientError::ServerBusy) => {
            return daemon_error(json, DAEMON_SERVER_BUSY_CODE, err.to_string());
        }
        Err(err) => return daemon_error(json, "daemon_unavailable", err.to_string()),
    };
    let exited = match pid {
        Some(pid) => wait_for_process_exit(pid, timeout).await,
        // A daemon built before its answer carried a pid removes its socket
        // as the last step of its shutdown.
        None => wait_for_socket_removal(socket, timeout).await,
    };
    if !exited {
        let daemon = pid.map_or_else(|| "daemon".to_owned(), |pid| format!("daemon {pid}"));
        return daemon_error(
            json,
            "daemon_stop_timeout",
            format!(
                "{daemon} at {} accepted the stop request but is still running after {timeout:?}",
                socket.display()
            ),
        );
    }
    daemon_output(
        json,
        "daemon stopped",
        serde_json::json!({"running": false, "socket": socket}),
        0,
    )
}

/// Whether process `pid` exits within `timeout`.
async fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while process_running(pid) {
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(DAEMON_POLL_INTERVAL).await;
    }
    true
}

/// Whether the socket file is removed within `timeout`. It is watched rather
/// than connected to: a daemon shutting down no longer accepts, so probe
/// connections would fill its backlog and fail as if it had closed.
async fn wait_for_socket_removal(socket: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::symlink_metadata(socket) {
            Err(err) if err.kind() == ErrorKind::NotFound => return true,
            _ if Instant::now() >= deadline => return false,
            _ => tokio::time::sleep(DAEMON_POLL_INTERVAL).await,
        }
    }
}

/// Whether process `pid` is still running. A process that has exited but that
/// its parent has not reaped yet (a zombie) is not: a parent can wait for
/// `wn daemon stop` before reaping, and some container init processes never
/// reap.
#[cfg(target_os = "macos")]
fn process_running(pid: u32) -> bool {
    let Ok(pid) = libc::c_int::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: `proc_bsdinfo` holds only integers and byte arrays, so all
    // zeroes is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut info).cast(),
            size as libc::c_int,
        )
    };
    usize::try_from(written).is_ok_and(|written| written == size) && info.pbi_status != libc::SZOMB
}

#[cfg(target_os = "linux")]
fn process_running(pid: u32) -> bool {
    // The state follows the command name, which is in parentheses and may
    // itself contain spaces or parentheses.
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next())
            .is_some_and(|state| !matches!(state, 'Z' | 'X'))
    })
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn process_running(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: kill with signal 0 sends nothing and touches no memory.
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

pub(crate) async fn status_daemon(json: bool, socket: &Path) -> CliOutput {
    let status = match DaemonClient::new(socket).status().await {
        Ok(status) => status,
        Err(err @ DaemonClientError::ServerBusy) => {
            return daemon_error(json, DAEMON_SERVER_BUSY_CODE, err.to_string());
        }
        Err(_) => {
            let home = socket
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf);
            let stale_pid = home
                .as_deref()
                .and_then(|home| read_pid_file(&default_pid_path(home)).ok().flatten());
            DaemonStatus {
                running: false,
                starting: false,
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
        }
    };
    let plain = if status.running && status.starting {
        format!("daemon starting\nsocket: {}", socket.display())
    } else if status.running {
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
        "starting": status.starting,
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
    let (pid, started_at, starting, last_runtime_activity) = state
        .lock()
        .ok()
        .map(|state| {
            (
                Some(state.pid),
                Some(state.started_at),
                state.starting,
                state.last_runtime_activity.clone(),
            )
        })
        .unwrap_or((None, None, false, None));
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
        starting,
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
        stderr: format!("error: {}\n", crate::terminal_safe_text(&message)),
    }
}

pub(crate) fn normalize_relay_list(relays: Vec<String>) -> Result<Vec<String>, crate::WnError> {
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
    writeln!(log, "wnd start requested at {}", unix_now())?;
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
                "socket already exists at {} but did not respond as wnd: {err}",
                socket.display()
            ),
        )
        .into()),
    }
}

pub(crate) fn relay_error_code(err: &crate::WnError) -> &'static str {
    match err {
        crate::WnError::EmptyRelayUrl => "empty_relay_url",
        crate::WnError::InvalidRelayUrl(_) => "invalid_relay_url",
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
        let sibling = parent.join("wnd");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }

    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths).find_map(|dir| {
                let candidate = dir.join("wnd");
                candidate.is_file().then_some(candidate)
            })
        })
        .ok_or_else(|| "wnd not found; ensure it is built and on PATH".to_owned())
}
