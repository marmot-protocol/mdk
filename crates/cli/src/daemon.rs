use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::{fs::PermissionsExt, process::CommandExt};

use agent_stream_compose::{StreamComposeCommand, StreamComposeReport, run_stream_compose_session};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use transport_quic_broker::OpenBrokerTextPublisher;

use cgka_traits::GroupId;
use cgka_traits::app_event::{
    MARMOT_APP_EVENT_KIND_CHAT, MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_REACTION,
};

use crate::{
    Cli, CliOutput, DaemonCommand, SecretStoreKind, create_private_dir_all,
    open_private_append_file, resolve_home, write_private_file,
};

const DAEMON_EVENT_REPLAY_LIMIT: usize = 256;
const MAX_DAEMON_REQUEST_BYTES: usize = 1024 * 1024;
const DAEMON_SOCKET_DIR_MODE: u32 = 0o700;
const DAEMON_SOCKET_MODE: u32 = 0o600;

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
#[command(
    name = "dmd",
    about = "Darkmatter background runtime daemon for live subscriptions and stream previews"
)]
struct DaemonArgs {
    #[arg(long, value_name = "PATH", help = "Use this Darkmatter data directory")]
    home: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Alias for --home")]
    data_dir: Option<PathBuf>,
    #[arg(
        long,
        value_name = "PATH",
        help = "Write daemon logs in this directory"
    )]
    logs_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH", help = "Listen on this Unix socket")]
    socket: Option<PathBuf>,
    #[arg(long, value_name = "URL", hide = true)]
    relay: Option<String>,
    #[arg(
        long,
        value_name = "URLS",
        value_delimiter = ',',
        help = "Comma-separated discovery relays for profiles, relay lists, and KeyPackages"
    )]
    discovery_relays: Vec<String>,
    #[arg(
        long,
        value_name = "URLS",
        value_delimiter = ',',
        help = "Comma-separated default account relays used when creating identities"
    )]
    default_account_relays: Vec<String>,
    #[arg(
        long,
        value_enum,
        value_name = "STORE",
        help = "Store account secrets in the OS keychain or local files"
    )]
    secret_store: Option<SecretStoreKind>,
    #[arg(
        long,
        value_name = "SERVICE",
        help = "Use this OS keychain service name for local secret storage"
    )]
    keychain_service: Option<String>,
}

#[derive(Clone, Debug)]
struct DaemonDefaults {
    home: PathBuf,
    socket: PathBuf,
    pid_path: PathBuf,
    log_path: PathBuf,
    relay: Option<String>,
    discovery_relays: Vec<String>,
    default_account_relays: Vec<String>,
    secret_store: Option<SecretStoreKind>,
    keychain_service: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaemonRuntimeActivityReport {
    pub started_at: u64,
    pub finished_at: u64,
    pub accounts: usize,
    pub events: usize,
    pub joined_groups: usize,
    pub messages: usize,
    pub directory_accounts: usize,
    pub directory_follows: usize,
    pub directory_profiles: usize,
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
    pub last_runtime_activity: Option<DaemonRuntimeActivityReport>,
    pub relay_health: Option<marmot_app::RelayPlaneHealth>,
    pub stream_watches: Vec<DaemonStreamWatchReport>,
}

pub type DaemonStreamWatchReport = marmot_app::AgentStreamWatchReport;

pub type DaemonOutgoingStreamReport = StreamComposeReport;

#[derive(Debug)]
struct DaemonState {
    pid: u32,
    started_at: u64,
    last_runtime_activity: Option<DaemonRuntimeActivityReport>,
}

#[derive(Default)]
struct AppRuntimeHost {
    runtime: Option<marmot_app::MarmotAppRuntime>,
    bridge: Option<JoinHandle<()>>,
    stream_watch: StreamWatchWorkers,
}

impl AppRuntimeHost {
    async fn abort_all(&mut self) {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown().await;
        }
        if let Some(handle) = self.bridge.take() {
            handle.abort();
        }
        self.stream_watch.abort_all();
        self.runtime = None;
    }
}

#[derive(Clone, Default)]
struct StreamWatchWorkers {
    handles: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

impl StreamWatchWorkers {
    fn replace(&self, watch_id: String, handle: JoinHandle<()>) {
        match self.handles.lock() {
            Ok(mut handles) => {
                Self::reap_finished_locked(&mut handles);
                if let Some(previous) = handles.insert(watch_id, handle) {
                    previous.abort();
                }
            }
            Err(_) => handle.abort(),
        }
    }

    fn reap_finished(&self) {
        if let Ok(mut handles) = self.handles.lock() {
            Self::reap_finished_locked(&mut handles);
        }
    }

    fn reap_finished_locked(handles: &mut HashMap<String, JoinHandle<()>>) {
        handles.retain(|_, handle| !handle.is_finished());
    }

    fn abort_all(&self) {
        if let Ok(mut handles) = self.handles.lock() {
            for (_, handle) in handles.drain() {
                handle.abort();
            }
        }
    }
}

#[derive(Default)]
struct StreamComposeWorkers {
    sessions: HashMap<String, StreamComposeSession>,
}

impl StreamComposeWorkers {
    fn insert(&mut self, key: String, session: StreamComposeSession) {
        if let Some(previous) = self.sessions.insert(key, session) {
            // Graceful cancel over the dedicated signal: let the replaced
            // session emit its live Abort and self-terminate. The cancel signal
            // is its own bounded channel that can't be starved by queued
            // commands, so only force-abort if that channel is already gone.
            if previous.cancel_tx.try_send(()).is_err() {
                previous.handle.abort();
            }
        }
    }

    fn remove(&mut self, key: &str) -> Option<StreamComposeSession> {
        self.sessions.remove(key)
    }

    fn get(&self, key: &str) -> Option<&StreamComposeSession> {
        self.sessions.get(key)
    }

    fn abort_all(&mut self) {
        for (_, session) in self.sessions.drain() {
            // Graceful cancel so each session flushes its live Abort before the
            // task ends; force-abort only as a fallback when the dedicated
            // cancel channel is gone.
            if session.cancel_tx.try_send(()).is_err() {
                session.handle.abort();
            }
        }
    }
}

#[derive(Default)]
struct DaemonWorkers {
    runtime: AppRuntimeHost,
    stream_compose: StreamComposeWorkers,
}

impl DaemonWorkers {
    async fn abort_all(&mut self) {
        self.runtime.abort_all().await;
        self.stream_compose.abort_all();
    }
}

struct StreamComposeSession {
    tx: mpsc::Sender<StreamComposeCommand>,
    cancel_tx: mpsc::Sender<()>,
    handle: JoinHandle<()>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DaemonRequest {
    Ping,
    Status,
    Shutdown,
    StreamWatch { cli: Box<Cli> },
    MessagesSubscribe { cli: Box<Cli> },
    ChatsSubscribe { cli: Box<Cli> },
    GroupStateSubscribe { cli: Box<Cli> },
    Execute { cli: Box<Cli> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStreamResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DaemonStreamError>,
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub stream_end: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonStreamError {
    pub message: String,
}

impl DaemonStreamResponse {
    fn ok(result: serde_json::Value) -> Self {
        Self {
            result: Some(result),
            error: None,
            stream_end: false,
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(DaemonStreamError {
                message: message.into(),
            }),
            stream_end: false,
        }
    }
}

#[derive(Clone)]
struct DaemonEventHub {
    messages: broadcast::Sender<DaemonStreamResponse>,
    recent_messages: Arc<Mutex<VecDeque<DaemonStreamResponse>>>,
}

impl DaemonEventHub {
    fn new() -> Self {
        let (messages, _) = broadcast::channel(1024);
        Self {
            messages,
            recent_messages: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    fn subscribe_messages(&self) -> broadcast::Receiver<DaemonStreamResponse> {
        self.messages.subscribe()
    }

    fn publish_message(&self, response: DaemonStreamResponse) {
        if let Ok(mut recent) = self.recent_messages.lock() {
            recent.push_back(response.clone());
            while recent.len() > DAEMON_EVENT_REPLAY_LIMIT {
                recent.pop_front();
            }
        }
        let _ = self.messages.send(response);
    }

    fn recent_messages(&self) -> Vec<DaemonStreamResponse> {
        self.recent_messages
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
    }
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
        DaemonCommand::Start {
            discovery_relays,
            default_account_relays,
        } => {
            let home = resolve_home(cli.home.clone());
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

pub(crate) async fn send_execute(socket: &Path, cli: Cli) -> Result<CliOutput, DaemonClientError> {
    DaemonClient::new(socket).execute(cli).await
}

pub(crate) async fn send_stream_watch(
    socket: &Path,
    cli: Cli,
) -> Result<CliOutput, DaemonClientError> {
    DaemonClient::new(socket).stream_watch(cli).await
}

pub(crate) async fn send_messages_subscribe(
    socket: &Path,
    cli: Cli,
) -> Result<CliOutput, DaemonClientError> {
    DaemonClient::new(socket).messages_subscribe(cli).await
}

pub(crate) async fn send_chats_subscribe(
    socket: &Path,
    cli: Cli,
) -> Result<CliOutput, DaemonClientError> {
    DaemonClient::new(socket).chats_subscribe(cli).await
}

pub(crate) async fn send_group_state_subscribe(
    socket: &Path,
    cli: Cli,
) -> Result<CliOutput, DaemonClientError> {
    DaemonClient::new(socket).group_state_subscribe(cli).await
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

    pub(crate) async fn execute(&self, cli: Cli) -> Result<CliOutput, DaemonClientError> {
        send_request(&self.socket, &DaemonRequest::Execute { cli: Box::new(cli) }).await
    }

    pub(crate) async fn stream_watch(&self, cli: Cli) -> Result<CliOutput, DaemonClientError> {
        send_request(
            &self.socket,
            &DaemonRequest::StreamWatch { cli: Box::new(cli) },
        )
        .await
    }

    pub(crate) async fn messages_subscribe(
        &self,
        cli: Cli,
    ) -> Result<CliOutput, DaemonClientError> {
        let json = cli.json;
        stream_request(
            &self.socket,
            &DaemonRequest::MessagesSubscribe { cli: Box::new(cli) },
            json,
        )
        .await
    }

    pub(crate) async fn chats_subscribe(&self, cli: Cli) -> Result<CliOutput, DaemonClientError> {
        let json = cli.json;
        stream_request(
            &self.socket,
            &DaemonRequest::ChatsSubscribe { cli: Box::new(cli) },
            json,
        )
        .await
    }

    pub(crate) async fn group_state_subscribe(
        &self,
        cli: Cli,
    ) -> Result<CliOutput, DaemonClientError> {
        let json = cli.json;
        stream_request(
            &self.socket,
            &DaemonRequest::GroupStateSubscribe { cli: Box::new(cli) },
            json,
        )
        .await
    }
}

async fn run_server(args: DaemonArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let home = resolve_home(args.home.or(args.data_dir));
    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| default_socket_path(&home));
    let pid_path = default_pid_path(&home);
    let log_path = args
        .logs_dir
        .clone()
        .map(|logs_dir| logs_dir.join("dmd.log"))
        .unwrap_or_else(|| default_log_path(&home));
    if let Some(parent) = socket.parent() {
        prepare_socket_dir(parent, &home)?;
    }
    if let Some(parent) = pid_path.parent() {
        create_private_dir_all(parent)?;
    }
    remove_stale_socket(&socket).await?;
    remove_stale_pid(&pid_path).await?;

    let listener = UnixListener::bind(&socket)?;
    harden_socket_permissions(&socket)?;
    write_pid_file(&pid_path)?;
    let hidden_relay = crate::resolve_relay(args.relay)?;
    let mut discovery_relays = normalize_relay_list(args.discovery_relays)?;
    let mut default_account_relays = normalize_relay_list(args.default_account_relays)?;
    if discovery_relays.is_empty() {
        if let Some(relay) = hidden_relay.clone() {
            discovery_relays.push(relay);
        } else if !default_account_relays.is_empty() {
            discovery_relays = default_account_relays.clone();
        }
    }
    if default_account_relays.is_empty() {
        if !discovery_relays.is_empty() {
            default_account_relays = discovery_relays.clone();
        } else if let Some(relay) = hidden_relay.clone() {
            default_account_relays.push(relay);
        }
    }
    let relay = hidden_relay
        .or_else(|| discovery_relays.first().cloned())
        .or_else(|| default_account_relays.first().cloned())
        .ok_or(crate::DmError::MissingRelay)?;
    let defaults = DaemonDefaults {
        home,
        socket: socket.clone(),
        pid_path: pid_path.clone(),
        log_path,
        relay: Some(relay),
        discovery_relays,
        default_account_relays,
        secret_store: args.secret_store,
        keychain_service: args.keychain_service,
    };
    let state = Arc::new(Mutex::new(DaemonState {
        pid: std::process::id(),
        started_at: unix_now(),
        last_runtime_activity: None,
    }));
    let events = DaemonEventHub::new();
    let mut workers = DaemonWorkers::default();
    reconcile_app_runtime(
        &defaults,
        state.clone(),
        events.clone(),
        &mut workers.runtime,
    )
    .await;
    let shutdown_result = loop {
        let (mut stream, _) = listener.accept().await?;
        if let Err(err) = authorize_daemon_peer(&stream) {
            write_daemon_output(
                &mut stream,
                &CliOutput {
                    code: 1,
                    stdout: String::new(),
                    stderr: format!("error: {err}\n"),
                },
            )
            .await;
            continue;
        }
        let request = read_daemon_request(&mut stream).await?;
        match request {
            DaemonRequest::MessagesSubscribe { mut cli } => {
                apply_defaults(&mut cli, &defaults);
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers.runtime,
                )
                .await;
                let defaults = defaults.clone();
                let state = state.clone();
                let events = events.clone();
                let runtime = workers.runtime.runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_messages_subscription(
                        &mut stream,
                        &defaults,
                        state,
                        events,
                        runtime,
                        *cli,
                    )
                    .await;
                });
            }
            DaemonRequest::ChatsSubscribe { mut cli } => {
                apply_defaults(&mut cli, &defaults);
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers.runtime,
                )
                .await;
                let defaults = defaults.clone();
                let runtime = workers.runtime.runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_chats_subscription(&mut stream, &defaults, runtime, *cli).await;
                });
            }
            DaemonRequest::GroupStateSubscribe { mut cli } => {
                apply_defaults(&mut cli, &defaults);
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers.runtime,
                )
                .await;
                let defaults = defaults.clone();
                let runtime = workers.runtime.runtime.clone();
                tokio::spawn(async move {
                    let _ = handle_group_state_subscription(&mut stream, &defaults, runtime, *cli)
                        .await;
                });
            }
            request => {
                let should_shutdown = handle_connection(
                    request,
                    &mut stream,
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers,
                )
                .await?;
                if should_shutdown {
                    break Ok(());
                }
            }
        }
    };

    workers.abort_all().await;
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pid_path);
    shutdown_result
}

fn prepare_socket_dir(parent: &Path, home: &Path) -> std::io::Result<()> {
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

fn is_daemon_owned_socket_dir(parent: &Path, home: &Path) -> bool {
    let dev_dir = home.join("dev");
    parent == dev_dir || parent.starts_with(dev_dir)
}

fn harden_socket_permissions(socket: &Path) -> std::io::Result<()> {
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(DAEMON_SOCKET_MODE))
}

fn authorize_daemon_peer(stream: &UnixStream) -> std::io::Result<()> {
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

fn current_effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

fn daemon_peer_uid_authorized(peer_uid: libc::uid_t, server_uid: libc::uid_t) -> bool {
    peer_uid == server_uid
}

async fn handle_connection(
    request: DaemonRequest,
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &mut DaemonWorkers,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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
            let status = server_status(
                defaults,
                &state,
                workers.runtime.runtime.as_ref(),
                &workers.runtime.stream_watch,
            )
            .await;
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
        DaemonRequest::StreamWatch { mut cli } => {
            apply_defaults(&mut cli, defaults);
            reconcile_app_runtime(
                defaults,
                state.clone(),
                events.clone(),
                &mut workers.runtime,
            )
            .await;
            let output = start_stream_watch(
                *cli,
                defaults,
                workers.runtime.runtime.as_ref(),
                &workers.runtime.stream_watch,
            )
            .await;
            (false, output)
        }
        DaemonRequest::MessagesSubscribe { .. } => (
            false,
            daemon_error(
                false,
                "invalid_daemon_request",
                "messages subscribe must use the streaming daemon path".to_owned(),
            ),
        ),
        DaemonRequest::ChatsSubscribe { .. } => (
            false,
            daemon_error(
                false,
                "invalid_daemon_request",
                "chats subscribe must use the streaming daemon path".to_owned(),
            ),
        ),
        DaemonRequest::GroupStateSubscribe { .. } => (
            false,
            daemon_error(
                false,
                "invalid_daemon_request",
                "groups subscribe-state must use the streaming daemon path".to_owned(),
            ),
        ),
        DaemonRequest::Execute { mut cli } => {
            apply_defaults(&mut cli, defaults);
            if let Some(output) = blocked_daemon_execute_output(cli.as_ref()) {
                write_daemon_output(stream, &output).await;
                return Ok(false);
            }
            if let Some(output) = handle_stream_compose_request(
                &cli,
                defaults,
                state.clone(),
                events.clone(),
                &mut workers.runtime,
                &mut workers.stream_compose,
            )
            .await
            {
                write_daemon_output(stream, &output).await;
                return Ok(false);
            }
            let refresh = app_runtime_refresh_after_execute(&cli);
            if let Some(output) = handle_app_runtime_account_setup_request(
                &cli,
                defaults,
                state.clone(),
                events.clone(),
                &mut workers.runtime,
            )
            .await
            {
                write_daemon_output(stream, &output).await;
                return Ok(false);
            }
            if let Some(output) = handle_app_runtime_command_request(
                &cli,
                defaults,
                state.clone(),
                events.clone(),
                &mut workers.runtime,
            )
            .await
            {
                write_daemon_output(stream, &output).await;
                return Ok(false);
            }
            let output = crate::run_cli_local(*cli).await;
            if output.code == 0 {
                refresh_app_runtime(
                    defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers.runtime,
                    refresh,
                )
                .await;
            }
            (false, output)
        }
    };

    write_daemon_output(stream, &output).await;
    Ok(shutdown)
}

fn blocked_daemon_execute_output(cli: &Cli) -> Option<CliOutput> {
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

fn blocked_daemon_execute_command(
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
        _ => None,
    }
}

async fn write_daemon_output(stream: &mut UnixStream, output: &CliOutput) {
    let Ok(mut response) = serde_json::to_vec(output) else {
        return;
    };
    response.push(b'\n');
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

async fn read_daemon_request(
    stream: &mut UnixStream,
) -> Result<DaemonRequest, Box<dyn std::error::Error + Send + Sync>> {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            if request.is_empty() {
                return Err(DaemonClientError::EmptyResponse.into());
            }
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        if request.len() == MAX_DAEMON_REQUEST_BYTES {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("daemon request exceeds {MAX_DAEMON_REQUEST_BYTES} bytes"),
            )
            .into());
        }
        request.push(byte[0]);
    }
    Ok(serde_json::from_slice(&request)?)
}

async fn handle_messages_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    _state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if is_timeline_messages_subscribe(&cli) {
        return handle_timeline_messages_subscription(stream, defaults, runtime, cli).await;
    }
    let (group_id, limit) = match messages_subscribe_args(&cli) {
        Ok(args) => args,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let stream_manager = runtime.shared_services().agent_streams();
    let mut runtime_subscription = match runtime.subscribe_messages(
        &account_ref,
        marmot_app::AppMessageQuery {
            group_id_hex: group_id.clone(),
            limit,
        },
    ) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let mut seen_messages = HashSet::new();
    let mut seen_stream_previews = HashSet::new();
    let mut event_rx = events.subscribe_messages();
    let mut stream_rx = stream_manager.subscribe();
    if !write_stream_response(
        stream,
        &DaemonStreamResponse::ok(serde_json::json!({
            "trigger": "SubscriptionReady",
            "type": "subscription_ready",
            "group_id": group_id.clone(),
        })),
    )
    .await
    {
        return Ok(());
    }

    let mut display_names_by_sender: HashMap<String, Option<String>> = HashMap::new();
    for message in runtime_subscription.snapshot.drain(..) {
        if !message.message_id_hex.is_empty() {
            seen_messages.insert(message.message_id_hex.clone());
        }
        let display_name = display_names_by_sender
            .entry(message.sender.clone())
            .or_insert_with(|| runtime.display_name_for_account_id(&message.sender))
            .clone();
        let response = message_stream_response(
            app_message_record_json(message, display_name),
            "InitialMessage",
        );
        if !write_stream_response(stream, &response).await {
            return Ok(());
        }
    }

    for response in events.recent_messages() {
        if !write_message_subscription_event(
            stream,
            response,
            group_id.as_deref(),
            &account_ref,
            &mut seen_messages,
            &mut seen_stream_previews,
        )
        .await
        {
            return Ok(());
        }
    }

    for update in stream_manager.recent_updates() {
        let response = agent_stream_update_response(update, false);
        if !write_message_subscription_event(
            stream,
            response,
            group_id.as_deref(),
            &account_ref,
            &mut seen_messages,
            &mut seen_stream_previews,
        )
        .await
        {
            return Ok(());
        }
    }

    if let Some(group_id) = group_id.as_deref() {
        for preview in stream_manager.previews_for_group(Some(&account_ref), group_id) {
            let preview =
                serde_json::to_value(preview).expect("stream preview serialization cannot fail");
            let fingerprint = stream_preview_fingerprint(&preview);
            if !seen_stream_previews.insert(fingerprint) {
                continue;
            }
            let response = stream_preview_response(preview, true);
            if !write_stream_response(stream, &response).await {
                return Ok(());
            }
        }
    }

    loop {
        tokio::select! {
            // Stream-start messages are published before their preview updates; keep that
            // ordering stable when both broadcast channels are ready in the same poll.
            biased;

            update = runtime_subscription.recv() => {
                let Some(update) = update else {
                    return Ok(());
                };
                let response = runtime_message_update_stream_response(update);
                if !write_message_subscription_event(
                    stream,
                    response,
                    group_id.as_deref(),
                    &account_ref,
                    &mut seen_messages,
                    &mut seen_stream_previews,
                )
                .await
                {
                    return Ok(());
                }
            }
            event = event_rx.recv() => {
                match event {
                    Ok(response) => {
                        if !write_message_subscription_event(
                            stream,
                            response,
                            group_id.as_deref(),
                            &account_ref,
                            &mut seen_messages,
                            &mut seen_stream_previews,
                        )
                        .await
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let response = DaemonStreamResponse::err(format!(
                            "message stream lagged: {count} updates dropped"
                        ));
                        if !write_stream_response(stream, &response).await {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
            stream_update = stream_rx.recv() => {
                match stream_update {
                    Ok(update) => {
                        let response = agent_stream_update_response(update, false);
                        if !write_message_subscription_event(
                            stream,
                            response,
                            group_id.as_deref(),
                            &account_ref,
                            &mut seen_messages,
                            &mut seen_stream_previews,
                        )
                        .await
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        let response = DaemonStreamResponse::err(format!(
                            "agent stream update stream lagged: {count} updates dropped"
                        ));
                        if !write_stream_response(stream, &response).await {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

async fn handle_timeline_messages_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (group_id, limit) = match timeline_messages_subscribe_args(&cli) {
        Ok(args) => args,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut runtime_subscription = match runtime.subscribe_timeline_messages(
        &account_ref,
        marmot_app::TimelineMessageQuery {
            group_id_hex: group_id.clone(),
            search: None,
            pagination: marmot_app::TimelinePagination {
                limit,
                ..marmot_app::TimelinePagination::default()
            },
        },
    ) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    if !write_stream_response(
        stream,
        &DaemonStreamResponse::ok(serde_json::json!({
            "trigger": "TimelineSubscriptionReady",
            "type": "timeline_subscription_ready",
            "group_id": group_id.clone(),
        })),
    )
    .await
    {
        return Ok(());
    }

    let initial = timeline_page_stream_response(
        runtime_subscription.snapshot.clone(),
        "InitialTimelinePage",
        &runtime,
    );
    if !write_stream_response(stream, &initial).await {
        return Ok(());
    }

    while let Some(update) = runtime_subscription.recv().await {
        let response = match update {
            marmot_app::RuntimeTimelineMessageUpdate::Page { page } => {
                timeline_page_stream_response(page, "TimelineUpdated", &runtime)
            }
            marmot_app::RuntimeTimelineMessageUpdate::Projection(update) => {
                timeline_projection_stream_response(update, &runtime)
            }
        };
        if !write_stream_response(stream, &response).await {
            return Ok(());
        }
    }
    Ok(())
}

fn daemon_account_ref(defaults: &DaemonDefaults, cli: &Cli) -> Result<String, String> {
    let secret_store =
        crate::resolve_secret_store(defaults.secret_store).map_err(|err| err.to_string())?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home = crate::open_account_home(&defaults.home, secret_store, &keychain_service)
        .map_err(|err| err.to_string())?;
    let account = crate::resolve_account(&account_home, cli.account.clone())
        .map_err(|err| err.to_string())?;
    if !account.local_signing {
        return Err(format!(
            "account {} is not a local signing account",
            account.account_id_hex
        ));
    }
    Ok(account.account_id_hex)
}

fn app_message_record_json(
    message: marmot_app::AppMessageRecord,
    from_display_name: Option<String>,
) -> serde_json::Value {
    crate::message_record_json(message, from_display_name)
}

fn runtime_message_update_stream_response(
    update: marmot_app::RuntimeMessageUpdate,
) -> DaemonStreamResponse {
    match update {
        marmot_app::RuntimeMessageUpdate::Message(message) => message_stream_response(
            runtime_message_json(
                &message.message,
                &message.account_id_hex,
                &message.account_label,
            ),
            "MessageReceived",
        ),
        marmot_app::RuntimeMessageUpdate::AgentStreamStarted(message) => message_stream_response(
            runtime_message_json(
                &message.message,
                &message.account_id_hex,
                &message.account_label,
            ),
            "AgentStreamStarted",
        ),
    }
}

fn chat_stream_response(group: marmot_app::AppGroupRecord, trigger: &str) -> DaemonStreamResponse {
    let group_id = group.group_id_hex.clone();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": "chat",
        "chat": crate::group_json(group),
        "group_id": group_id,
    }))
}

fn group_state_stream_response(
    group: marmot_app::AppGroupRecord,
    trigger: &str,
    mls: Option<serde_json::Value>,
) -> DaemonStreamResponse {
    let group_id = group.group_id_hex.clone();
    let mut result = serde_json::json!({
        "trigger": trigger,
        "type": "group_state",
        "group": crate::group_json(group),
        "group_id": group_id,
    });
    if let Some(mls) = mls {
        result["mls"] = mls;
    }
    DaemonStreamResponse::ok(result)
}

async fn write_message_subscription_event(
    stream: &mut UnixStream,
    response: DaemonStreamResponse,
    group_id: Option<&str>,
    account_id: &str,
    seen_messages: &mut HashSet<String>,
    seen_stream_previews: &mut HashSet<String>,
) -> bool {
    if !stream_response_matches_subscription(&response, group_id, account_id) {
        return true;
    }
    if mark_stream_response_seen(&response, seen_messages, seen_stream_previews) {
        write_stream_response(stream, &response).await
    } else {
        true
    }
}

async fn handle_chats_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let include_archived = match chats_subscribe_args(&cli) {
        Ok(include_archived) => include_archived,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut subscription = match runtime.subscribe_chats(&account_ref, include_archived) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    for chat in subscription.snapshot.drain(..) {
        if !write_stream_response(stream, &chat_stream_response(chat, "InitialChat")).await {
            return Ok(());
        }
    }
    while let Some(chat) = subscription.recv().await {
        if !write_stream_response(stream, &chat_stream_response(chat, "ChatUpdated")).await {
            return Ok(());
        }
    }
    Ok(())
}

async fn handle_group_state_subscription(
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    runtime: Option<marmot_app::MarmotAppRuntime>,
    cli: Cli,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let group_id = match group_state_subscribe_args(&cli) {
        Ok(group_id) => group_id,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let account_ref = match daemon_account_ref(defaults, &cli) {
        Ok(account_ref) => account_ref,
        Err(message) => {
            let _ = write_stream_response(stream, &DaemonStreamResponse::err(message)).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let Some(runtime) = runtime else {
        let _ = write_stream_response(
            stream,
            &DaemonStreamResponse::err("app runtime is not running".to_owned()),
        )
        .await;
        let _ = write_stream_end(stream).await;
        return Ok(());
    };
    let mut subscription = match runtime.subscribe_group_state(&account_ref, &group_id) {
        Ok(subscription) => subscription,
        Err(err) => {
            let _ =
                write_stream_response(stream, &DaemonStreamResponse::err(err.to_string())).await;
            let _ = write_stream_end(stream).await;
            return Ok(());
        }
    };
    let group_id_value = GroupId::new(hex::decode(&group_id)?);
    let initial_mls = runtime
        .group_mls_state(&account_ref, &group_id_value)
        .await
        .ok()
        .map(crate::group_mls_state_json);
    if !write_stream_response(
        stream,
        &group_state_stream_response(
            subscription.snapshot.clone(),
            "InitialGroupState",
            initial_mls,
        ),
    )
    .await
    {
        return Ok(());
    }
    while let Some(group) = subscription.recv().await {
        let mls = runtime
            .group_mls_state(&account_ref, &group_id_value)
            .await
            .ok()
            .map(crate::group_mls_state_json);
        if !write_stream_response(
            stream,
            &group_state_stream_response(group, "GroupStateUpdated", mls),
        )
        .await
        {
            return Ok(());
        }
    }
    Ok(())
}

fn group_state_subscribe_args(cli: &Cli) -> Result<String, String> {
    match &cli.command {
        crate::Command::Groups {
            command: crate::GroupsCommand::SubscribeState { group_id },
        } => crate::normalize_group_id_hex(group_id).map_err(|err| err.to_string()),
        _ => Err("groups subscribe-state requires dm groups subscribe-state".to_owned()),
    }
}

fn chats_subscribe_args(cli: &Cli) -> Result<bool, String> {
    match &cli.command {
        crate::Command::Chats {
            command: crate::ChatsCommand::Subscribe,
        } => Ok(false),
        crate::Command::Chats {
            command: crate::ChatsCommand::SubscribeArchived,
        } => Ok(true),
        _ => Err("chats subscribe requires dm chats subscribe".to_owned()),
    }
}

fn messages_subscribe_args(cli: &Cli) -> Result<(Option<String>, Option<usize>), String> {
    let (group, limit) = match &cli.command {
        crate::Command::Message {
            command: crate::MessageCommand::Subscribe { group, limit },
        }
        | crate::Command::Messages {
            command: crate::MessageCommand::Subscribe { group, limit },
        } => (group, *limit),
        _ => return Err("messages subscribe requires dm messages subscribe".to_owned()),
    };
    let group_id = group
        .as_deref()
        .map(crate::normalize_group_id_hex)
        .transpose()
        .map_err(|err| err.to_string())?;
    Ok((group_id, Some(limit.unwrap_or(50).min(200))))
}

fn is_timeline_messages_subscribe(cli: &Cli) -> bool {
    matches!(
        &cli.command,
        crate::Command::Message {
            command: crate::MessageCommand::Timeline {
                command: crate::MessageTimelineCommand::Subscribe { .. },
            },
        } | crate::Command::Messages {
            command: crate::MessageCommand::Timeline {
                command: crate::MessageTimelineCommand::Subscribe { .. },
            },
        }
    )
}

fn timeline_messages_subscribe_args(cli: &Cli) -> Result<(Option<String>, Option<usize>), String> {
    let (group, limit) = match &cli.command {
        crate::Command::Message {
            command:
                crate::MessageCommand::Timeline {
                    command: crate::MessageTimelineCommand::Subscribe { group, limit },
                },
        }
        | crate::Command::Messages {
            command:
                crate::MessageCommand::Timeline {
                    command: crate::MessageTimelineCommand::Subscribe { group, limit },
                },
        } => (group, *limit),
        _ => {
            return Err(
                "timeline messages subscribe requires dm messages timeline subscribe".to_owned(),
            );
        }
    };
    let group_id = group
        .as_deref()
        .map(crate::normalize_group_id_hex)
        .transpose()
        .map_err(|err| err.to_string())?;
    Ok((group_id, Some(limit.unwrap_or(50).min(200))))
}

fn cli_output_result(output: CliOutput) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(output.stdout.trim())
        .map_err(|err| format!("daemon command returned invalid JSON: {err}"))?;
    if output.code != 0 || value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        let message = value
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                if output.stderr.trim().is_empty() {
                    None
                } else {
                    Some(output.stderr.trim())
                }
            })
            .unwrap_or("daemon command failed");
        return Err(message.to_owned());
    }
    Ok(value
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn stream_preview_fingerprint(preview: &serde_json::Value) -> String {
    let watch_id = preview
        .get("watch_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let status = preview
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let text = preview
        .get("text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let transcript_hash = preview
        .get("transcript_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let error = preview
        .get("error")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    format!("{watch_id}:{status}:{text}:{transcript_hash}:{error}")
}

fn stream_preview_response(preview: serde_json::Value, initial: bool) -> DaemonStreamResponse {
    let trigger = if initial {
        "InitialStreamPreview"
    } else {
        match preview
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
        {
            "completed" => "StreamPreviewCompleted",
            "failed" => "StreamPreviewFailed",
            _ => "StreamPreviewUpdated",
        }
    };
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": "stream_preview",
        "stream_preview": preview,
    }))
}

fn agent_stream_delta_response(delta: crate::AgentStreamDelta) -> DaemonStreamResponse {
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": "AgentStreamDelta",
        "type": "agent_stream_delta",
        "agent_stream_delta": delta,
    }))
}

fn agent_stream_update_response(
    update: marmot_app::AgentStreamUpdate,
    initial: bool,
) -> DaemonStreamResponse {
    match update {
        marmot_app::AgentStreamUpdate::WatchUpdated(report) => {
            let preview =
                serde_json::to_value(report).expect("stream preview serialization cannot fail");
            stream_preview_response(preview, initial)
        }
        marmot_app::AgentStreamUpdate::Delta(delta) => agent_stream_delta_response(delta),
    }
}

fn message_stream_response(message: serde_json::Value, trigger: &str) -> DaemonStreamResponse {
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": message_stream_type(&message),
        "message": message,
    }))
}

fn timeline_page_stream_response(
    page: marmot_app::TimelinePage,
    trigger: &str,
    runtime: &marmot_app::MarmotAppRuntime,
) -> DaemonStreamResponse {
    let messages = page
        .messages
        .into_iter()
        .map(|message| {
            let display_name = runtime.display_name_for_account_id(&message.sender);
            crate::timeline_message_record_json(message, display_name)
        })
        .collect::<Vec<_>>();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": trigger,
        "type": timeline_stream_type(trigger),
        "messages": messages,
        "has_more_before": page.has_more_before,
        "has_more_after": page.has_more_after,
    }))
}

fn timeline_projection_stream_response(
    update: marmot_app::RuntimeProjectionUpdate,
    runtime: &marmot_app::MarmotAppRuntime,
) -> DaemonStreamResponse {
    let changes = update
        .update
        .timeline_changes
        .into_iter()
        .map(|change| timeline_message_change_json(change, runtime))
        .collect::<Vec<_>>();
    let messages = update
        .update
        .timeline_messages
        .into_iter()
        .map(|message| {
            let display_name = runtime.display_name_for_account_id(&message.sender);
            crate::timeline_message_record_json(message, display_name)
        })
        .collect::<Vec<_>>();
    DaemonStreamResponse::ok(serde_json::json!({
        "trigger": "TimelineProjectionUpdated",
        "type": "timeline_projection_updated",
        "account_id": update.account_id_hex,
        "account_label": update.account_label,
        "group_id": update.update.group_id_hex,
        "messages": messages,
        "changes": changes,
        "chat_list_row": update.update.chat_list_row,
        "chat_list_trigger": update.update.chat_list_trigger,
    }))
}

fn timeline_message_change_json(
    change: marmot_app::TimelineMessageChange,
    runtime: &marmot_app::MarmotAppRuntime,
) -> serde_json::Value {
    match change {
        marmot_app::TimelineMessageChange::Upsert { trigger, message } => {
            let display_name = runtime.display_name_for_account_id(&message.sender);
            serde_json::json!({
                "type": "upsert",
                "trigger": trigger,
                "message": crate::timeline_message_record_json(*message, display_name),
            })
        }
        marmot_app::TimelineMessageChange::Remove {
            message_id_hex,
            reason,
        } => serde_json::json!({
            "type": "remove",
            "message_id": message_id_hex,
            "reason": reason,
        }),
    }
}

fn timeline_stream_type(trigger: &str) -> &'static str {
    match trigger {
        "InitialTimelinePage" => "initial_timeline_page",
        "TimelineUpdated" => "timeline_updated",
        _ => "timeline",
    }
}

fn message_stream_type(message: &serde_json::Value) -> &'static str {
    // Agent text stream classification is derived from the inner-event tags and
    // exposed under `agent_text_stream`; prefer it so stream-final chats surface
    // as `agent_stream_final` rather than a bare `message`.
    if let Some(stream_kind) = message
        .get("agent_text_stream")
        .and_then(|stream| stream.get("kind"))
        .and_then(serde_json::Value::as_str)
    {
        return match stream_kind {
            "start" => "agent_stream_start",
            "final" => "agent_stream_final",
            _ => "message",
        };
    }
    let kind = message.get("kind").and_then(serde_json::Value::as_u64);
    let has_imeta = message
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|tag| {
                tag.as_array()
                    .and_then(|values| values.first())
                    .and_then(serde_json::Value::as_str)
                    == Some("imeta")
            })
        });
    match kind {
        Some(MARMOT_APP_EVENT_KIND_REACTION) => "reaction",
        Some(MARMOT_APP_EVENT_KIND_DELETE) => "message_delete",
        Some(MARMOT_APP_EVENT_KIND_CHAT) if has_imeta => "media",
        _ => "message",
    }
}

fn stream_response_matches_subscription(
    response: &DaemonStreamResponse,
    group_id: Option<&str>,
    account_id: &str,
) -> bool {
    let Some(result) = &response.result else {
        return true;
    };
    match result.get("type").and_then(serde_json::Value::as_str) {
        Some("message")
        | Some("reaction")
        | Some("message_delete")
        | Some("media")
        | Some("agent_stream_start")
        | Some("agent_stream_final") => {
            let Some(message) = result.get("message") else {
                return false;
            };
            value_matches_group_and_account(message, group_id, account_id)
        }
        Some("stream_preview") => {
            let Some(preview) = result.get("stream_preview") else {
                return false;
            };
            value_matches_group_and_account(preview, group_id, account_id)
        }
        Some("agent_stream_delta") => {
            let Some(delta) = result.get("agent_stream_delta") else {
                return false;
            };
            value_matches_group_and_account(delta, group_id, account_id)
        }
        _ => false,
    }
}

fn value_matches_group_and_account(
    value: &serde_json::Value,
    group_id: Option<&str>,
    account_id: &str,
) -> bool {
    group_id.is_none_or(|group_id| {
        value.get("group_id").and_then(serde_json::Value::as_str) == Some(group_id)
    }) && value
        .get("account")
        .or_else(|| value.get("account_id"))
        .and_then(serde_json::Value::as_str)
        .is_none_or(|event_account| event_account == account_id)
}

fn mark_stream_response_seen(
    response: &DaemonStreamResponse,
    seen_messages: &mut HashSet<String>,
    seen_stream_previews: &mut HashSet<String>,
) -> bool {
    let Some(result) = &response.result else {
        return true;
    };
    match result.get("type").and_then(serde_json::Value::as_str) {
        Some("message")
        | Some("reaction")
        | Some("message_delete")
        | Some("media")
        | Some("agent_stream_start")
        | Some("agent_stream_final") => result
            .get("message")
            .and_then(|message| message.get("message_id"))
            .and_then(serde_json::Value::as_str)
            .is_none_or(|message_id| seen_messages.insert(message_id.to_owned())),
        Some("stream_preview") => result
            .get("stream_preview")
            .map(stream_preview_fingerprint)
            .is_none_or(|fingerprint| seen_stream_previews.insert(fingerprint)),
        Some("agent_stream_delta") => true,
        _ => true,
    }
}

async fn write_stream_response(stream: &mut UnixStream, response: &DaemonStreamResponse) -> bool {
    let Ok(mut bytes) = serde_json::to_vec(response) else {
        return false;
    };
    bytes.push(b'\n');
    stream.write_all(&bytes).await.is_ok()
}

async fn write_stream_end(stream: &mut UnixStream) -> bool {
    write_stream_response(
        stream,
        &DaemonStreamResponse {
            result: None,
            error: None,
            stream_end: true,
        },
    )
    .await
}

async fn start_stream_watch(
    cli: Cli,
    defaults: &DaemonDefaults,
    runtime: Option<&marmot_app::MarmotAppRuntime>,
    workers: &StreamWatchWorkers,
) -> CliOutput {
    let json = cli.json;
    let Some(runtime) = runtime else {
        return daemon_error(
            json,
            "stream_watch_failed",
            "app runtime is not running".to_owned(),
        );
    };
    let stream_manager = runtime.shared_services().agent_streams();
    let secret_store = match crate::resolve_secret_store(defaults.secret_store) {
        Ok(secret_store) => secret_store,
        Err(err) => return daemon_error(json, "stream_watch_failed", err.to_string()),
    };
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        match crate::open_account_home(&defaults.home, secret_store, &keychain_service) {
            Ok(account_home) => account_home,
            Err(err) => return daemon_error(json, "stream_watch_failed", err.to_string()),
        };
    let app = crate::app_for(
        defaults.home.clone(),
        defaults.relay.clone(),
        account_home.clone(),
    );
    let (report, handle) =
        match spawn_stream_watch(cli, account_home, app, runtime.clone(), stream_manager) {
            Ok(spawned) => spawned,
            Err(message) => return daemon_error(json, "stream_watch_failed", message),
        };
    let watch_id = report.watch_id.clone();
    workers.replace(watch_id, handle);

    stream_watch_output(json, &report)
}

fn spawn_stream_watch(
    mut cli: Cli,
    account_home: marmot_account::AccountHome,
    app: marmot_app::MarmotApp,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
) -> Result<(DaemonStreamWatchReport, JoinHandle<()>), String> {
    let report = stream_manager.start_watch(new_stream_watch_start(&cli)?);
    let watch_id = report.watch_id.clone();

    cli.json = true;
    if let crate::Command::Stream {
        command: crate::StreamCommand::Watch { background, .. },
    } = &mut cli.command
    {
        *background = false;
    }

    let worker_watch_id = watch_id;
    let worker_stream_manager = stream_manager.clone();
    let handle = tokio::spawn(async move {
        let json = cli.json;
        let account_flag = cli.account.clone();
        let command = match cli.command.clone() {
            crate::Command::Stream { command } => command,
            _ => return,
        };
        let output = crate::command_output_result(
            json,
            crate::stream_watch_command_app_with_runtime(
                &account_home,
                &app,
                &runtime,
                command,
                account_flag,
                move |delta| {
                    worker_stream_manager.record_delta(delta.clone());
                },
            )
            .await,
        );
        finish_stream_watch(stream_manager, worker_watch_id, output);
    });

    Ok((report, handle))
}

fn new_stream_watch_start(cli: &Cli) -> Result<marmot_app::AgentStreamWatchStart, String> {
    let crate::Command::Stream {
        command: crate::StreamCommand::Watch {
            group, stream_id, ..
        },
    } = &cli.command
    else {
        return Err("background stream watch requires dm stream watch".to_owned());
    };
    let group_id = crate::normalize_group_id_hex(group).map_err(|err| err.to_string())?;
    let stream_id = stream_id
        .as_deref()
        .map(crate::normalize_hex)
        .transpose()
        .map_err(|err| err.to_string())?;
    let started_at = unix_now();
    Ok(marmot_app::AgentStreamWatchStart {
        account: cli.account.clone(),
        group_id,
        stream_id,
        started_at,
        started_at_millis: unix_now_millis(),
    })
}

fn finish_stream_watch(
    stream_manager: marmot_app::AgentStreamWatchManager,
    watch_id: String,
    output: CliOutput,
) {
    let mut status = "failed".to_owned();
    let mut text = None;
    let mut transcript_hash = None;
    let mut chunk_count = None;
    let mut error = None;
    let mut result = None;
    let mut stream_id = None;

    if output.code == 0 {
        match serde_json::from_str::<serde_json::Value>(output.stdout.trim()) {
            Ok(value) if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true) => {
                let body = value
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                status = "completed".to_owned();
                text = body
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                transcript_hash = body
                    .get("transcript_hash")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                chunk_count = body.get("chunk_count").and_then(serde_json::Value::as_u64);
                stream_id = body
                    .get("stream_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                result = Some(body);
            }
            Ok(value) => {
                error = Some(
                    value
                        .get("error")
                        .and_then(|error| error.get("message"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("stream watch failed")
                        .to_owned(),
                );
            }
            Err(err) => {
                error = Some(format!("stream watch returned invalid JSON: {err}"));
            }
        }
    } else if !output.stderr.trim().is_empty() {
        error = Some(output.stderr.trim().to_owned());
    } else if !output.stdout.trim().is_empty() {
        error = Some(output.stdout.trim().to_owned());
    } else {
        error = Some("stream watch failed".to_owned());
    }

    let _ = stream_manager.finish_watch(
        &watch_id,
        marmot_app::AgentStreamWatchCompletion {
            finished_at: unix_now(),
            status,
            stream_id,
            text,
            transcript_hash,
            chunk_count,
            error,
            result,
        },
    );
}

fn stream_watch_output(json: bool, report: &DaemonStreamWatchReport) -> CliOutput {
    if json {
        return CliOutput {
            code: 0,
            stdout: format!(
                "{}\n",
                serde_json::to_string(&serde_json::json!({
                    "ok": true,
                    "result": report,
                }))
                .expect("JSON response serialization cannot fail")
            ),
            stderr: String::new(),
        };
    }
    CliOutput {
        code: 0,
        stdout: format!("watching stream {}\n", report.watch_id),
        stderr: String::new(),
    }
}

async fn handle_stream_compose_request(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime_host: &mut AppRuntimeHost,
    workers: &mut StreamComposeWorkers,
) -> Option<CliOutput> {
    let crate::Command::Stream { command } = &cli.command else {
        return None;
    };
    match command {
        crate::StreamCommand::ComposeOpen {
            group,
            stream_id,
            quic_candidates,
            insecure_local,
            chunk_bytes,
        } => Some(
            open_stream_compose(
                cli,
                defaults,
                state,
                events,
                runtime_host,
                workers,
                group,
                stream_id.clone(),
                quic_candidates.clone(),
                *insecure_local,
                *chunk_bytes,
            )
            .await,
        ),
        crate::StreamCommand::ComposeAppend { stream_id, text } => {
            Some(append_stream_compose(cli, workers, stream_id, text.join(" ")).await)
        }
        crate::StreamCommand::ComposeFinish { stream_id } => Some(
            finish_stream_compose(
                cli,
                defaults,
                state,
                events,
                runtime_host,
                workers,
                stream_id,
            )
            .await,
        ),
        crate::StreamCommand::ComposeCancel { stream_id } => {
            Some(cancel_stream_compose(cli, workers, stream_id))
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_stream_compose(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime_host: &mut AppRuntimeHost,
    workers: &mut StreamComposeWorkers,
    group: &str,
    stream_id: Option<String>,
    quic_candidates: Vec<String>,
    insecure_local: bool,
    chunk_bytes: usize,
) -> CliOutput {
    let account = cli.account.clone();
    let group_id = match crate::normalize_group_id_hex(group) {
        Ok(group_id) => group_id,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let stream_id = match stream_id
        .map(|stream_id| crate::normalize_hex(&stream_id))
        .transpose()
    {
        Ok(Some(stream_id)) => stream_id,
        Ok(None) => hex::encode(transport_quic_stream::random_stream_id()),
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let Some(candidate) = quic_candidates
        .iter()
        .find(|candidate| candidate.trim().starts_with("quic://"))
        .cloned()
    else {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream compose requires a quic:// candidate".to_owned(),
        );
    };
    let parsed_candidate = match crate::parse_quic_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let candidate_addr = match crate::resolve_quic_candidate_addr(&parsed_candidate).await {
        Ok(addr) => addr,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let trust = match crate::broker_trust(candidate_addr, None, insecure_local) {
        Ok(trust) => trust,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };

    let mut start_cli = cli.clone();
    start_cli.json = true;
    start_cli.command = crate::Command::Stream {
        command: crate::StreamCommand::Start {
            group: group_id.clone(),
            stream_id: Some(stream_id.clone()),
            quic_candidates: quic_candidates.clone(),
        },
    };
    let start =
        match run_hosted_stream_marker_cli_json(&start_cli, defaults, state, events, runtime_host)
            .await
        {
            Ok(result) => result,
            Err(err) => return daemon_error(cli.json, "stream_compose_failed", err),
        };
    let Some(start_message_id) = start
        .get("message_ids")
        .and_then(serde_json::Value::as_array)
        .and_then(|ids| ids.first())
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    else {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream start did not return a start message id".to_owned(),
        );
    };
    let Some(start_account_id) = start
        .get("account_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
    else {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream start did not return an account id".to_owned(),
        );
    };
    let start_event_id = match hex::decode(&start_message_id) {
        Ok(bytes) => cgka_traits::MessageId::new(bytes),
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let stream_id_bytes = match hex::decode(&stream_id) {
        Ok(bytes) => bytes,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let crypto = {
        let Some(runtime) = runtime_host.runtime.as_ref() else {
            return daemon_error(
                cli.json,
                "stream_compose_failed",
                "app runtime is not available for stream crypto".to_owned(),
            );
        };
        match crate::stream_crypto_for_start_event(
            runtime,
            Some(&start_account_id),
            Some(group_id.as_str()),
            Some(stream_id.as_str()),
            &start_message_id,
        )
        .await
        {
            Ok((_, crypto)) => Some(crypto),
            Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
        }
    };

    let key = stream_compose_key(account.as_deref(), &stream_id);
    let (tx, rx) = mpsc::channel(32);
    // Dedicated cancel signal: a bounded channel that can't be starved behind
    // queued append/status/progress commands, so an explicit cancel always
    // reaches the session and a live `Abort` is emitted before shutdown.
    let (cancel_tx, cancel_rx) = mpsc::channel(1);
    let report = DaemonOutgoingStreamReport {
        account,
        group_id,
        stream_id: stream_id.clone(),
        start_message_id,
        candidate: candidate.clone(),
        status: "streaming".to_owned(),
        text: String::new(),
        transcript_hash: None,
        chunk_count: 0,
        error: None,
    };
    let task_report = report.clone();
    let handle = tokio::spawn(async move {
        run_stream_compose_session(
            OpenBrokerTextPublisher {
                broker_addr: candidate_addr,
                server_name: parsed_candidate.server_name,
                trust,
                stream_id: stream_id_bytes,
                start_event_id,
                crypto,
            },
            chunk_bytes,
            rx,
            cancel_rx,
            task_report,
        )
        .await;
    });
    workers.insert(
        key,
        StreamComposeSession {
            tx,
            cancel_tx,
            handle,
        },
    );
    daemon_output(
        cli.json,
        &format!("streaming {}", short_id(&report.stream_id)),
        serde_json::json!(report),
        0,
    )
}

async fn append_stream_compose(
    cli: &Cli,
    workers: &StreamComposeWorkers,
    stream_id: &str,
    text: String,
) -> CliOutput {
    let stream_id = match crate::normalize_hex(stream_id) {
        Ok(stream_id) => stream_id,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let key = stream_compose_key(cli.account.as_deref(), &stream_id);
    let Some(session) = workers.get(&key) else {
        return daemon_error(
            cli.json,
            "stream_compose_not_found",
            format!("no active stream compose session for {stream_id}"),
        );
    };
    let (respond, response) = oneshot::channel();
    if session
        .tx
        .send(StreamComposeCommand::Append { text, respond })
        .await
        .is_err()
    {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream compose session is closed".to_owned(),
        );
    }
    match response.await {
        Ok(Ok(report)) => daemon_output(
            cli.json,
            &format!("streaming {}", short_id(&report.stream_id)),
            serde_json::json!(report),
            0,
        ),
        Ok(Err(err)) => daemon_error(cli.json, "stream_compose_failed", err),
        Err(err) => daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    }
}

async fn finish_stream_compose(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime_host: &mut AppRuntimeHost,
    workers: &mut StreamComposeWorkers,
    stream_id: &str,
) -> CliOutput {
    let stream_id = match crate::normalize_hex(stream_id) {
        Ok(stream_id) => stream_id,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let key = stream_compose_key(cli.account.as_deref(), &stream_id);
    let Some(session) = workers.remove(&key) else {
        return daemon_error(
            cli.json,
            "stream_compose_not_found",
            format!("no active stream compose session for {stream_id}"),
        );
    };
    let (respond, response) = oneshot::channel();
    if session
        .tx
        .send(StreamComposeCommand::Finish { respond })
        .await
        .is_err()
    {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream compose session is closed".to_owned(),
        );
    }
    let report = match response.await {
        Ok(Ok(report)) => report,
        Ok(Err(err)) => return daemon_error(cli.json, "stream_compose_failed", err),
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    if report.text.is_empty() {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream compose text is empty".to_owned(),
        );
    }
    let Some(transcript_hash) = report.transcript_hash.clone() else {
        return daemon_error(
            cli.json,
            "stream_compose_failed",
            "stream compose did not return a transcript hash".to_owned(),
        );
    };

    let mut finish_cli = cli.clone();
    finish_cli.json = true;
    finish_cli.command = crate::Command::Stream {
        command: crate::StreamCommand::Finish {
            group: report.group_id.clone(),
            stream_id: report.stream_id.clone(),
            start_event_id: report.start_message_id.clone(),
            transcript_hash,
            chunk_count: report.chunk_count,
            text: vec![report.text.clone()],
        },
    };
    if let Err(err) =
        run_hosted_stream_marker_cli_json(&finish_cli, defaults, state, events, runtime_host).await
    {
        return daemon_error(cli.json, "stream_compose_failed", err);
    }
    daemon_output(
        cli.json,
        &format!("finished stream {}", short_id(&report.stream_id)),
        serde_json::json!(report),
        0,
    )
}

fn cancel_stream_compose(
    cli: &Cli,
    workers: &mut StreamComposeWorkers,
    stream_id: &str,
) -> CliOutput {
    let stream_id = match crate::normalize_hex(stream_id) {
        Ok(stream_id) => stream_id,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let key = stream_compose_key(cli.account.as_deref(), &stream_id);
    if let Some(session) = workers.remove(&key) {
        // Graceful cancel over the dedicated signal: the compose session emits a
        // live Abort record so online subscribers observe the cancellation, then
        // self-terminates. The signal can't be starved by a full command queue,
        // so only force-abort if that dedicated channel is already gone.
        if session.cancel_tx.try_send(()).is_err() {
            session.handle.abort();
        }
        return daemon_output(
            cli.json,
            &format!("cancelled stream {}", short_id(&stream_id)),
            serde_json::json!({
                "stream_id": stream_id,
                "cancelled": true,
            }),
            0,
        );
    }
    daemon_error(
        cli.json,
        "stream_compose_not_found",
        format!("no active stream compose session for {stream_id}"),
    )
}

async fn run_hosted_stream_marker_cli_json(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime_host: &mut AppRuntimeHost,
) -> Result<serde_json::Value, String> {
    let Some(output) =
        handle_app_runtime_command_request(cli, defaults, state, events, runtime_host).await
    else {
        return Err("stream marker command did not use the daemon runtime".to_owned());
    };
    cli_output_result(output)
}

fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

fn stream_compose_key(account: Option<&str>, stream_id: &str) -> String {
    format!("{}:{stream_id}", account.unwrap_or(""))
}

#[derive(Clone, Debug)]
enum AppRuntimeRefresh {
    None,
    Reconcile,
    RestartSelected(Option<String>),
    CatchUpAll,
}

fn app_runtime_enabled(defaults: &DaemonDefaults) -> bool {
    defaults.relay.is_some()
}

async fn handle_app_runtime_account_setup_request(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
) -> Option<CliOutput> {
    let request = match app_runtime_account_setup_request(cli) {
        Ok(Some(request)) => request,
        Ok(None) => return None,
        Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
    };
    if !app_runtime_enabled(defaults) {
        return None;
    }
    reconcile_app_runtime(defaults, state.clone(), events, host).await;
    let Some(runtime) = &host.runtime else {
        return Some(crate::command_output_result(
            cli.json,
            Err(crate::DmError::MissingRelay),
        ));
    };
    let output = runtime
        .create_or_import_account(request)
        .await
        .map_err(crate::map_account_setup_error)
        .and_then(crate::account_setup_command_output);
    Some(crate::command_output_result(cli.json, output))
}

async fn handle_app_runtime_command_request(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
) -> Option<CliOutput> {
    if !app_runtime_enabled(defaults) || !is_hosted_runtime_command(cli) {
        return None;
    }
    reconcile_app_runtime(defaults, state.clone(), events, host).await;
    let Some(runtime) = &host.runtime else {
        return Some(crate::command_output_result(
            cli.json,
            Err(crate::DmError::MissingRelay),
        ));
    };

    let secret_store = match crate::resolve_secret_store(defaults.secret_store) {
        Ok(secret_store) => secret_store,
        Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
    };
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        match crate::open_account_home(&defaults.home, secret_store, &keychain_service) {
            Ok(account_home) => account_home,
            Err(err) => return Some(crate::command_output_result(cli.json, Err(err))),
        };
    let app = crate::app_for(
        defaults.home.clone(),
        defaults.relay.clone(),
        account_home.clone(),
    );

    let output = match cli.command.clone() {
        crate::Command::Group { command } => {
            crate::group_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Groups { command } => {
            crate::groups_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Message { command } | crate::Command::Messages { command } => {
            crate::message_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Stream { command } => {
            crate::stream_command_app_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Keys { command } => {
            crate::key_package_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::Follows { command } => {
            crate::follows_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Profile { command } => {
            crate::profile_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Relays { command } => {
            crate::relays_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
                cli.relay.clone(),
            )
            .await
        }
        crate::Command::Media { command } => {
            crate::media_command_with_runtime(
                &account_home,
                &app,
                runtime,
                command,
                cli.account.clone(),
            )
            .await
        }
        crate::Command::RelayStats => crate::relay_stats_command_with_runtime(runtime).await,
        _ => return None,
    };
    Some(crate::command_output_result(cli.json, output))
}

fn is_hosted_runtime_command(cli: &Cli) -> bool {
    match &cli.command {
        crate::Command::Group { .. } | crate::Command::Groups { .. } => true,
        crate::Command::Message { command } | crate::Command::Messages { command } => {
            !matches!(command, crate::MessageCommand::Subscribe { .. })
        }
        crate::Command::Stream { command } => matches!(
            command,
            crate::StreamCommand::Start { .. }
                | crate::StreamCommand::Finish { .. }
                | crate::StreamCommand::Watch { .. }
                | crate::StreamCommand::Send {
                    start_event_id: Some(_),
                    ..
                }
        ),
        crate::Command::Keys { .. }
        | crate::Command::Follows { .. }
        | crate::Command::Profile { .. }
        | crate::Command::Relays { .. }
        | crate::Command::RelayStats
        | crate::Command::Media { .. } => true,
        _ => false,
    }
}

fn app_runtime_account_setup_request(
    cli: &Cli,
) -> Result<Option<marmot_app::AccountSetupRequest>, crate::DmError> {
    match &cli.command {
        crate::Command::CreateIdentity => {
            if cli.daemon_default_account_relays.is_empty() {
                return Err(crate::DmError::MissingRelay);
            }
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: None,
                default_relays: crate::relay_endpoints(cli.daemon_default_account_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                publish_missing_relay_lists: false,
                publish_initial_key_package: true,
            }))
        }
        crate::Command::Login {
            identity,
            nsec_stdin,
            ..
        } => {
            crate::validate_materialized_secret_identity("login", identity, *nsec_stdin)?;
            let Some(identity) = identity.clone() else {
                return Err(crate::DmError::MissingLoginIdentity);
            };
            if crate::is_nostr_secret(&identity) && cli.daemon_default_account_relays.is_empty() {
                return Err(crate::DmError::MissingRelay);
            }
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: Some(identity),
                default_relays: crate::relay_endpoints(cli.daemon_default_account_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(cli.daemon_discovery_relays.clone())?,
                publish_missing_relay_lists: true,
                publish_initial_key_package: true,
            }))
        }
        crate::Command::Account {
            command:
                crate::AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    default_relays,
                    bootstrap_relays,
                    publish_missing_relay_lists,
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Create {
                    identity,
                    nsec_stdin,
                    default_relays,
                    bootstrap_relays,
                    publish_missing_relay_lists,
                },
        } => {
            crate::validate_materialized_secret_identity("account create", identity, *nsec_stdin)?;
            Ok(Some(marmot_app::AccountSetupRequest {
                identity: identity.clone(),
                default_relays: crate::relay_endpoints(default_relays.clone())?,
                bootstrap_relays: crate::relay_endpoints(bootstrap_relays.clone())?,
                publish_missing_relay_lists: *publish_missing_relay_lists,
                publish_initial_key_package: false,
            }))
        }
        _ => Ok(None),
    }
}

fn app_runtime_refresh_after_execute(cli: &Cli) -> AppRuntimeRefresh {
    match &cli.command {
        crate::Command::CreateIdentity | crate::Command::Login { .. } => {
            AppRuntimeRefresh::Reconcile
        }
        crate::Command::Account {
            command: crate::AccountCommand::Create { .. },
        } => AppRuntimeRefresh::Reconcile,
        crate::Command::Group { .. } | crate::Command::Groups { .. } => {
            AppRuntimeRefresh::CatchUpAll
        }
        crate::Command::Message { .. }
        | crate::Command::Messages { .. }
        | crate::Command::Stream { .. } => AppRuntimeRefresh::CatchUpAll,
        crate::Command::Sync => AppRuntimeRefresh::RestartSelected(cli.account.clone()),
        _ => AppRuntimeRefresh::None,
    }
}

async fn refresh_app_runtime(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
    refresh: AppRuntimeRefresh,
) {
    if !app_runtime_enabled(defaults) {
        return;
    }
    match refresh {
        AppRuntimeRefresh::None => {}
        AppRuntimeRefresh::Reconcile => {
            reconcile_app_runtime(defaults, state, events, host).await;
        }
        AppRuntimeRefresh::RestartSelected(selector) => {
            if host.runtime.is_none() {
                reconcile_app_runtime(defaults, state, events, host).await;
                return;
            }
            if let Some(account_id) = resolve_app_runtime_account_id(defaults, selector).await {
                if let Some(runtime) = &host.runtime
                    && let Err(err) = runtime.restart_account(&account_id).await
                {
                    record_runtime_activity_error(&state, err.to_string());
                }
            } else {
                reconcile_app_runtime(defaults, state, events, host).await;
            }
        }
        AppRuntimeRefresh::CatchUpAll => {
            reconcile_app_runtime(defaults, state.clone(), events, host).await;
            if let Some(runtime) = &host.runtime
                && let Err(err) = runtime.catch_up_accounts().await
            {
                record_runtime_activity_error(&state, err.to_string());
            }
        }
    }
}

async fn resolve_app_runtime_account_id(
    defaults: &DaemonDefaults,
    selector: Option<String>,
) -> Option<String> {
    let secret_store = crate::resolve_secret_store(defaults.secret_store).ok()?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        crate::open_account_home(&defaults.home, secret_store, &keychain_service).ok()?;
    crate::resolve_account(&account_home, selector)
        .ok()
        .map(|account| account.account_id_hex)
}

async fn reconcile_app_runtime(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    host: &mut AppRuntimeHost,
) {
    if !app_runtime_enabled(defaults) {
        return;
    }

    if host.runtime.is_none() {
        let runtime = match open_app_runtime(defaults) {
            Ok(runtime) => runtime,
            Err(err) => {
                record_runtime_activity_error(&state, err.to_string());
                return;
            }
        };
        let receiver = runtime.subscribe();
        if let Err(err) = runtime.start().await {
            record_runtime_activity_error(&state, err.to_string());
            return;
        }
        host.bridge = Some(spawn_app_runtime_bridge(
            defaults.clone(),
            state.clone(),
            events.clone(),
            host.stream_watch.clone(),
            runtime.clone(),
            runtime.shared_services().agent_streams(),
            receiver,
        ));
        host.runtime = Some(runtime);
        return;
    }

    if let Some(runtime) = &host.runtime {
        if let Err(err) = runtime.reconcile_accounts().await {
            record_runtime_activity_error(&state, err.to_string());
        }
        if host
            .bridge
            .as_ref()
            .is_none_or(|handle| handle.is_finished())
        {
            host.bridge = Some(spawn_app_runtime_bridge(
                defaults.clone(),
                state,
                events,
                host.stream_watch.clone(),
                runtime.clone(),
                runtime.shared_services().agent_streams(),
                runtime.subscribe(),
            ));
        }
    }
}

fn open_app_runtime(
    defaults: &DaemonDefaults,
) -> Result<marmot_app::MarmotAppRuntime, crate::DmError> {
    let secret_store = crate::resolve_secret_store(defaults.secret_store)?;
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home = crate::open_account_home(&defaults.home, secret_store, &keychain_service)?;
    let app = crate::app_for(defaults.home.clone(), defaults.relay.clone(), account_home);
    Ok(app.runtime())
}

fn spawn_app_runtime_bridge(
    defaults: DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    stream_workers: StreamWatchWorkers,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
    mut receiver: broadcast::Receiver<marmot_app::MarmotAppEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    handle_app_runtime_event(
                        &defaults,
                        state.clone(),
                        events.clone(),
                        stream_workers.clone(),
                        runtime.clone(),
                        stream_manager.clone(),
                        event,
                    )
                    .await;
                }
                Err(broadcast::error::RecvError::Lagged(count)) => {
                    record_runtime_activity_error(
                        &state,
                        format!("app runtime event stream lagged: {count} updates dropped"),
                    );
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

async fn handle_app_runtime_event(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    stream_workers: StreamWatchWorkers,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
    event: marmot_app::MarmotAppEvent,
) {
    let started_at = unix_now();
    match event {
        marmot_app::MarmotAppEvent::GroupJoined { group_id, .. } => {
            let summary = marmot_app::SyncSummary {
                joined_groups: vec![group_id],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::GroupStateUpdated { .. } => {}
        marmot_app::MarmotAppEvent::ProjectionUpdated(_) => {}
        marmot_app::MarmotAppEvent::MessageReceived(message) => {
            // Raw message updates keep kind-1200 starts separate as
            // `AgentStreamStarted`; materialized timeline subscriptions include
            // those starts as timeline rows.
            events.publish_message(message_stream_response(
                runtime_message_json(
                    &message.message,
                    &message.account_id_hex,
                    &message.account_label,
                ),
                "MessageReceived",
            ));
            let summary = marmot_app::SyncSummary {
                messages: vec![message.message],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::AgentStreamStarted(message) => {
            events.publish_message(message_stream_response(
                runtime_message_json(
                    &message.message,
                    &message.account_id_hex,
                    &message.account_label,
                ),
                "AgentStreamStarted",
            ));
            let summary = marmot_app::SyncSummary {
                messages: vec![message.message],
                ..marmot_app::SyncSummary::default()
            };
            auto_watch_agent_stream_starts(
                defaults,
                &message.account_id_hex,
                &summary,
                stream_workers,
                runtime,
                stream_manager,
            )
            .await;
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::GroupEvent(group_event) => {
            let summary = marmot_app::SyncSummary {
                events: vec![group_event.event],
                ..marmot_app::SyncSummary::default()
            };
            record_runtime_activity_report(
                &state,
                runtime_activity_report_from_summary(started_at, 1, &summary),
            );
        }
        marmot_app::MarmotAppEvent::AccountError(error) => {
            record_runtime_activity_error(
                &state,
                format!(
                    "app runtime account {} failed: {}",
                    error.account_id_hex, error.message
                ),
            );
        }
    }
}

fn runtime_message_json(
    message: &marmot_app::ReceivedMessage,
    account_id_hex: &str,
    account_label: &str,
) -> serde_json::Value {
    let now = unix_now();
    let is_own_sender = message.sender == account_id_hex || message.sender == account_label;
    let from_display_name = if is_own_sender {
        None
    } else {
        message.sender_display_name.clone()
    };
    let mut value = serde_json::json!({
        "account_id": account_id_hex,
        "message_id": message.message_id_hex,
        "direction": if is_own_sender { "sent" } else { "received" },
        "from": message.sender,
        "from_display_name": from_display_name,
        "group_id": hex::encode(message.group_id.as_slice()),
        "plaintext": message.plaintext,
        "kind": message.kind,
        "tags": message.tags,
        "recorded_at": now,
        "received_at": now,
    });
    if let Some(agent_text_stream) =
        crate::agent_text_stream_payload_value(message.kind, &message.tags, &message.plaintext)
    {
        value["agent_text_stream"] = agent_text_stream;
    }
    value
}

async fn auto_watch_agent_stream_starts(
    defaults: &DaemonDefaults,
    account_id: &str,
    summary: &marmot_app::SyncSummary,
    stream_workers: StreamWatchWorkers,
    runtime: marmot_app::MarmotAppRuntime,
    stream_manager: marmot_app::AgentStreamWatchManager,
) {
    let secret_store = match crate::resolve_secret_store(defaults.secret_store) {
        Ok(secret_store) => secret_store,
        Err(_) => return,
    };
    let keychain_service = crate::resolve_keychain_service(defaults.keychain_service.clone());
    let account_home =
        match crate::open_account_home(&defaults.home, secret_store, &keychain_service) {
            Ok(account_home) => account_home,
            Err(_) => return,
        };
    let app = crate::app_for(
        defaults.home.clone(),
        defaults.relay.clone(),
        account_home.clone(),
    );
    for message in &summary.messages {
        let Some(start) = marmot_app::StreamStartView::from_event(message.kind, &message.tags)
        else {
            continue;
        };
        if start.route != "quic" {
            continue;
        }
        let group_id = hex::encode(message.group_id.as_slice());
        let insecure_local = crate::first_quic_candidate_is_loopback(&start.quic_candidates);
        let stream_id = start.stream_id_hex;
        if stream_manager.watch_exists(Some(account_id), &group_id, Some(stream_id.as_str())) {
            continue;
        }

        let cli = Cli {
            home: Some(defaults.home.clone()),
            socket: None,
            relay: defaults.relay.clone(),
            daemon_discovery_relays: defaults.discovery_relays.clone(),
            daemon_default_account_relays: defaults.default_account_relays.clone(),
            secret_store: defaults.secret_store,
            keychain_service: defaults.keychain_service.clone(),
            account: Some(account_id.to_owned()),
            json: true,
            command: crate::Command::Stream {
                command: crate::StreamCommand::Watch {
                    group: group_id,
                    stream_id: Some(stream_id),
                    server_cert_der_hex: None,
                    insecure_local,
                    background: false,
                },
            },
        };
        if let Ok((report, handle)) = spawn_stream_watch(
            cli,
            account_home.clone(),
            app.clone(),
            runtime.clone(),
            stream_manager.clone(),
        ) {
            stream_workers.replace(report.watch_id, handle);
        }
    }
}

fn empty_runtime_activity_report(started_at: u64) -> DaemonRuntimeActivityReport {
    DaemonRuntimeActivityReport {
        started_at,
        finished_at: started_at,
        accounts: 0,
        events: 0,
        joined_groups: 0,
        messages: 0,
        directory_accounts: 0,
        directory_follows: 0,
        directory_profiles: 0,
        errors: Vec::new(),
    }
}

fn runtime_activity_report_from_summary(
    started_at: u64,
    accounts: usize,
    summary: &marmot_app::SyncSummary,
) -> DaemonRuntimeActivityReport {
    let mut report = empty_runtime_activity_report(started_at);
    report.finished_at = unix_now();
    report.accounts = accounts;
    report.events = summary.events.len();
    report.joined_groups = summary.joined_groups.len();
    report.messages = summary.messages.len();
    report
}

fn record_runtime_activity_error(state: &Arc<Mutex<DaemonState>>, error: String) {
    let started_at = unix_now();
    let mut report = empty_runtime_activity_report(started_at);
    report.finished_at = unix_now();
    report.errors.push(error);
    record_runtime_activity_report(state, report);
}

fn record_runtime_activity_report(
    state: &Arc<Mutex<DaemonState>>,
    report: DaemonRuntimeActivityReport,
) {
    if let Ok(mut state) = state.lock() {
        state.last_runtime_activity = Some(report);
    }
}

fn apply_defaults(cli: &mut Cli, defaults: &DaemonDefaults) {
    cli.home = Some(defaults.home.clone());
    cli.relay = defaults.relay.clone();
    cli.daemon_discovery_relays = defaults.discovery_relays.clone();
    cli.daemon_default_account_relays = defaults.default_account_relays.clone();
    apply_default_account_relays(cli, defaults);
    cli.secret_store = defaults.secret_store;
    cli.keychain_service = defaults.keychain_service.clone();
    cli.socket = None;
}

fn apply_default_account_relays(cli: &mut Cli, defaults: &DaemonDefaults) {
    let default_relays = defaults.default_account_relays.clone();
    let bootstrap_relays = if defaults.discovery_relays.is_empty() {
        default_relays.clone()
    } else {
        defaults.discovery_relays.clone()
    };
    match &mut cli.command {
        crate::Command::Account {
            command:
                crate::AccountCommand::Create {
                    default_relays: command_default_relays,
                    bootstrap_relays: command_bootstrap_relays,
                    ..
                },
        }
        | crate::Command::Accounts {
            command:
                crate::AccountCommand::Create {
                    default_relays: command_default_relays,
                    bootstrap_relays: command_bootstrap_relays,
                    ..
                },
        } => {
            if command_default_relays.is_empty() {
                *command_default_relays = default_relays;
            }
            if command_bootstrap_relays.is_empty() {
                *command_bootstrap_relays = bootstrap_relays;
            }
        }
        _ => {}
    }
}

async fn start_daemon(
    cli: &Cli,
    home: &Path,
    socket: &Path,
    mut discovery_relays: Vec<String>,
    mut default_account_relays: Vec<String>,
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
    detach_daemon_command(&mut command);
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
        "last_runtime_activity": status.last_runtime_activity,
        "relay_health": status.relay_health,
        "stream_watches": status.stream_watches,
    })
}

async fn server_status(
    defaults: &DaemonDefaults,
    state: &Arc<Mutex<DaemonState>>,
    runtime: Option<&marmot_app::MarmotAppRuntime>,
    stream_workers: &StreamWatchWorkers,
) -> DaemonStatus {
    stream_workers.reap_finished();
    let state = state.lock().ok();
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
        pid: state.as_ref().map(|state| state.pid),
        pid_file: Some(defaults.pid_path.clone()),
        stale_pid: None,
        started_at: state.as_ref().map(|state| state.started_at),
        home: Some(defaults.home.clone()),
        log: Some(defaults.log_path.clone()),
        last_runtime_activity: state
            .as_ref()
            .and_then(|state| state.last_runtime_activity.clone()),
        relay_health,
        stream_watches,
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

async fn stream_request(
    socket: &Path,
    request: &DaemonRequest,
    json_output: bool,
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

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let mut had_error = false;
    loop {
        line.clear();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        let response: DaemonStreamResponse = serde_json::from_str(line.trim_end())?;
        if response.stream_end {
            break;
        }
        if response.error.is_some() {
            had_error = true;
        }
        write_client_stream_response(json_output, &response)?;
    }

    Ok(CliOutput {
        code: if had_error { 1 } else { 0 },
        stdout: String::new(),
        stderr: String::new(),
    })
}

fn write_client_stream_response(
    json_output: bool,
    response: &DaemonStreamResponse,
) -> std::io::Result<()> {
    if json_output {
        let mut stdout = std::io::stdout().lock();
        serde_json::to_writer(&mut stdout, response)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        return Ok(());
    }

    if let Some(error) = &response.error {
        let mut stderr = std::io::stderr().lock();
        writeln!(stderr, "error: {}", error.message)?;
        stderr.flush()?;
        return Ok(());
    }

    if let Some(result) = &response.result {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{}", stream_result_plain(result))?;
        stdout.flush()?;
    }
    Ok(())
}

fn normalize_relay_list(relays: Vec<String>) -> Result<Vec<String>, crate::DmError> {
    relays
        .into_iter()
        .map(crate::validate_relay_url)
        .collect::<Result<Vec<_>, _>>()
}

fn stream_result_plain(result: &serde_json::Value) -> String {
    match result.get("type").and_then(serde_json::Value::as_str) {
        Some("message")
        | Some("reaction")
        | Some("message_delete")
        | Some("media")
        | Some("agent_stream_start")
        | Some("agent_stream_final") => {
            let message = result.get("message").unwrap_or(&serde_json::Value::Null);
            let label = match result.get("type").and_then(serde_json::Value::as_str) {
                Some("agent_stream_start") => "agent stream start",
                Some("agent_stream_final") => "agent stream final",
                Some("reaction") => "reaction",
                Some("message_delete") => "message delete",
                Some("media") => "media",
                _ => "message",
            };
            format!(
                "{label} group={} from={}: {}",
                message
                    .get("group_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<unknown>"),
                message
                    .get("from")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<unknown>"),
                message
                    .get("plaintext")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
            )
        }
        Some("stream_preview") => {
            let preview = result
                .get("stream_preview")
                .unwrap_or(&serde_json::Value::Null);
            format!(
                "stream preview {} [{}]: {}",
                preview
                    .get("stream_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<latest>"),
                preview
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("unknown"),
                preview
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
            )
        }
        Some("agent_stream_delta") => {
            let delta = result
                .get("agent_stream_delta")
                .unwrap_or(&serde_json::Value::Null);
            format!(
                "agent stream delta {} #{}: {}",
                delta
                    .get("stream_id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("<unknown>"),
                delta
                    .get("seq")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                delta
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
            )
        }
        Some("timeline_subscription_ready") => {
            let group_id = result
                .get("group_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<all>");
            format!("timeline subscription ready group={group_id}")
        }
        Some("initial_timeline_page") | Some("timeline_updated") => {
            timeline_stream_page_plain(result)
        }
        Some("timeline_projection_updated") => timeline_projection_stream_plain(result),
        _ => result.to_string(),
    }
}

fn timeline_stream_page_plain(result: &serde_json::Value) -> String {
    let label = match result.get("type").and_then(serde_json::Value::as_str) {
        Some("initial_timeline_page") => "initial timeline page",
        Some("timeline_updated") => "timeline updated",
        _ => "timeline",
    };
    let has_more_before = result
        .get("has_more_before")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let has_more_after = result
        .get("has_more_after")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let messages = result
        .get("messages")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if messages.is_empty() {
        return format!(
            "{label} has_more_before={has_more_before} has_more_after={has_more_after}: no timeline messages"
        );
    }
    let body = messages
        .iter()
        .map(timeline_stream_message_plain)
        .collect::<Vec<_>>()
        .join("\n");
    format!("{label} has_more_before={has_more_before} has_more_after={has_more_after}\n{body}")
}

fn timeline_projection_stream_plain(result: &serde_json::Value) -> String {
    let group_id = result
        .get("group_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<all>");
    let changes = result
        .get("changes")
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let chat_list_trigger = result
        .get("chat_list_trigger")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("SnapshotRefresh");
    format!(
        "timeline projection updated group={group_id} changes={changes} chat_list_trigger={chat_list_trigger}"
    )
}

fn timeline_stream_message_plain(message: &serde_json::Value) -> String {
    let deleted = if message
        .get("deleted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        " deleted=true"
    } else {
        ""
    };
    format!(
        "group={} from={}: {}{}",
        message
            .get("group_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>"),
        message
            .get("from")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>"),
        message
            .get("plaintext")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(""),
        deleted
    )
}

fn write_pid_file(pid_path: &Path) -> std::io::Result<()> {
    write_private_file(pid_path, format!("{}\n", std::process::id()))
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
    let mut log = open_private_append_file(log_path)?;
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

fn unix_now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
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

fn relay_error_code(err: &crate::DmError) -> &'static str {
    match err {
        crate::DmError::EmptyRelayUrl => "empty_relay_url",
        crate::DmError::InvalidRelayUrl(_) => "invalid_relay_url",
        _ => "relay_url_error",
    }
}

#[cfg(unix)]
fn detach_daemon_command(command: &mut Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn detach_daemon_command(_command: &mut Command) {}

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

#[cfg(test)]
mod tests {
    use super::*;
    use cgka_traits::GroupId;
    use cgka_traits::MessageId;
    use cgka_traits::agent_text_stream::{
        AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, AgentTextStreamTranscriptV1,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[cfg(unix)]
    fn daemon_pid_and_log_writers_create_private_files() {
        let home = tempfile::tempdir().expect("tempdir");
        let pid_path = home.path().join("dev").join("dmd.pid");
        let log_path = home.path().join("logs").join("dmd.log");

        write_pid_file(&pid_path).expect("write pid file");
        drop(open_daemon_log(&log_path).expect("open daemon log"));

        assert_eq!(
            pid_path
                .parent()
                .expect("pid parent")
                .metadata()
                .expect("pid parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            pid_path
                .metadata()
                .expect("pid metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            log_path
                .parent()
                .expect("log parent")
                .metadata()
                .expect("log parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            log_path
                .metadata()
                .expect("log metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn apply_defaults_overwrites_forwarded_cli_relay_with_daemon_relay() {
        let defaults = DaemonDefaults {
            home: PathBuf::from("/tmp/dm-daemon-home"),
            socket: PathBuf::from("/tmp/dm-daemon.sock"),
            pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
            log_path: PathBuf::from("/tmp/dm-daemon.log"),
            relay: Some("wss://daemon.example".to_owned()),
            discovery_relays: vec!["wss://discovery.example".to_owned()],
            default_account_relays: vec!["wss://account.example".to_owned()],
            secret_store: Some(crate::SecretStoreKind::File),
            keychain_service: Some("daemon-keychain".to_owned()),
        };
        let mut cli = Cli {
            home: None,
            socket: Some(PathBuf::from("/tmp/forwarded.sock")),
            relay: Some("wss://client.example".to_owned()),
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command: crate::Command::Sync,
        };

        apply_defaults(&mut cli, &defaults);

        assert_eq!(cli.relay.as_deref(), Some("wss://daemon.example"));
        assert_eq!(cli.socket, None);
    }

    #[test]
    fn apply_defaults_overwrites_client_storage_scope_with_daemon_defaults() {
        let defaults = DaemonDefaults {
            home: PathBuf::from("/tmp/dm-daemon-home"),
            socket: PathBuf::from("/tmp/dm-daemon.sock"),
            pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
            log_path: PathBuf::from("/tmp/dm-daemon.log"),
            relay: Some("wss://daemon.example".to_owned()),
            discovery_relays: Vec::new(),
            default_account_relays: Vec::new(),
            secret_store: Some(crate::SecretStoreKind::File),
            keychain_service: Some("daemon-keychain".to_owned()),
        };
        let mut cli = Cli {
            home: Some(PathBuf::from("/tmp/client-selected-home")),
            socket: Some(PathBuf::from("/tmp/forwarded.sock")),
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: Some(crate::SecretStoreKind::Keychain),
            keychain_service: Some("client-keychain".to_owned()),
            account: None,
            json: true,
            command: crate::Command::Sync,
        };

        apply_defaults(&mut cli, &defaults);

        assert_eq!(cli.home.as_deref(), Some(defaults.home.as_path()));
        assert_eq!(cli.secret_store, Some(crate::SecretStoreKind::File));
        assert_eq!(cli.keychain_service.as_deref(), Some("daemon-keychain"));
    }

    #[test]
    fn apply_defaults_adds_daemon_account_relays_to_account_create() {
        let defaults = DaemonDefaults {
            home: PathBuf::from("/tmp/dm-daemon-home"),
            socket: PathBuf::from("/tmp/dm-daemon.sock"),
            pid_path: PathBuf::from("/tmp/dm-daemon.pid"),
            log_path: PathBuf::from("/tmp/dm-daemon.log"),
            relay: Some("wss://daemon.example".to_owned()),
            discovery_relays: vec!["wss://discovery.example".to_owned()],
            default_account_relays: vec!["wss://account.example".to_owned()],
            secret_store: Some(crate::SecretStoreKind::File),
            keychain_service: Some("daemon-keychain".to_owned()),
        };
        let mut cli = Cli {
            home: None,
            socket: Some(PathBuf::from("/tmp/forwarded.sock")),
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command: crate::Command::Account {
                command: crate::AccountCommand::Create {
                    identity: None,
                    nsec_stdin: false,
                    default_relays: Vec::new(),
                    bootstrap_relays: Vec::new(),
                    publish_missing_relay_lists: false,
                },
            },
        };

        apply_defaults(&mut cli, &defaults);

        let crate::Command::Account {
            command:
                crate::AccountCommand::Create {
                    default_relays,
                    bootstrap_relays,
                    ..
                },
        } = cli.command
        else {
            panic!("expected account create command");
        };
        assert_eq!(default_relays, vec!["wss://account.example"]);
        assert_eq!(bootstrap_relays, vec!["wss://discovery.example"]);
    }

    fn test_stream_compose_open(
        stream_id: Vec<u8>,
        start_event_id: MessageId,
    ) -> OpenBrokerTextPublisher {
        OpenBrokerTextPublisher {
            broker_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            server_name: "localhost".to_owned(),
            trust: transport_quic_broker::BrokerServerTrust::InsecureLocal,
            stream_id,
            start_event_id,
            crypto: None,
        }
    }

    fn test_stream_compose_report(stream_id: &[u8]) -> DaemonOutgoingStreamReport {
        DaemonOutgoingStreamReport {
            account: Some("account".to_owned()),
            group_id: hex::encode([0x11; 32]),
            stream_id: hex::encode(stream_id),
            start_message_id: hex::encode([0x22; 32]),
            candidate: "quic://127.0.0.1:9".to_owned(),
            status: "streaming".to_owned(),
            text: String::new(),
            transcript_hash: None,
            chunk_count: 0,
            error: None,
        }
    }

    fn expected_stream_transcript_hash(
        stream_id: &[u8],
        start_event_id: &MessageId,
        text: &str,
        chunk_bytes: usize,
    ) -> String {
        expected_stream_transcript_hash_for_appends(stream_id, start_event_id, &[text], chunk_bytes)
    }

    fn expected_stream_transcript_hash_for_appends(
        stream_id: &[u8],
        start_event_id: &MessageId,
        appends: &[&str],
        chunk_bytes: usize,
    ) -> String {
        let mut transcript =
            AgentTextStreamTranscriptV1::new(stream_id.to_vec(), start_event_id.clone());
        let mut seq = 1_u64;
        for text in appends {
            for chunk in transport_quic_stream::split_text_deltas(text, chunk_bytes) {
                transcript.append(seq, AGENT_TEXT_STREAM_RECORD_TEXT_DELTA, &chunk);
                seq += 1;
            }
        }
        hex::encode(transcript.hash())
    }

    #[tokio::test]
    async fn stream_compose_returns_local_transcript_when_broker_connect_is_pending() {
        let stream_id = vec![0xaa; 32];
        let start_event_id = MessageId::new(vec![0xbb; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let session = tokio::spawn(run_stream_compose_session(open, 8, rx, cancel_rx, report));

        let (append_tx, append_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Append {
            text: "hello ".to_owned(),
            respond: append_tx,
        })
        .await
        .unwrap();
        let appended = tokio::time::timeout(Duration::from_millis(250), append_rx)
            .await
            .expect("append should not wait for broker connect")
            .unwrap()
            .unwrap();
        assert_eq!(appended.text, "hello ");
        assert_eq!(appended.chunk_count, 1);

        let (finish_tx, finish_rx) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish { respond: finish_tx })
            .await
            .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), finish_rx)
            .await
            .expect("finish should use local transcript fallback")
            .unwrap()
            .unwrap();

        assert_eq!(finished.status, "finished");
        assert_eq!(finished.text, "hello ");
        assert_eq!(finished.chunk_count, 1);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(
                expected_stream_transcript_hash(&stream_id, &start_event_id, "hello ", 8).as_str()
            )
        );

        session.await.unwrap();
    }

    #[tokio::test]
    async fn stream_compose_final_report_contains_full_transcript_text() {
        let stream_id = vec![0xcc; 32];
        let start_event_id = MessageId::new(vec![0xdd; 32]);
        let open = test_stream_compose_open(stream_id.clone(), start_event_id.clone());
        let report = test_stream_compose_report(&stream_id);
        let (tx, rx) = mpsc::channel(4);
        let (_cancel_tx, cancel_rx) = mpsc::channel(1);
        let session = tokio::spawn(run_stream_compose_session(open, 5, rx, cancel_rx, report));

        for text in ["hello ", "world"] {
            let (respond, response) = oneshot::channel();
            tx.send(StreamComposeCommand::Append {
                text: text.to_owned(),
                respond,
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_millis(250), response)
                .await
                .expect("append should complete")
                .unwrap()
                .unwrap();
        }

        let (respond, response) = oneshot::channel();
        tx.send(StreamComposeCommand::Finish { respond })
            .await
            .unwrap();
        let finished = tokio::time::timeout(Duration::from_millis(250), response)
            .await
            .expect("finish should complete")
            .unwrap()
            .unwrap();

        assert_eq!(finished.text, "hello world");
        assert_eq!(finished.chunk_count, 3);
        assert_eq!(
            finished.transcript_hash.as_deref(),
            Some(
                expected_stream_transcript_hash_for_appends(
                    &stream_id,
                    &start_event_id,
                    &["hello ", "world"],
                    5,
                )
                .as_str()
            )
        );

        session.await.unwrap();
    }

    #[test]
    fn destructive_execute_commands_are_refused_over_daemon() {
        let reset = blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Reset {
            confirm: true,
        }))
        .expect("reset should be blocked");
        let reset_json: serde_json::Value =
            serde_json::from_str(reset.stdout.trim()).expect("reset error JSON");
        assert_eq!(reset.code, 1);
        assert_eq!(reset_json["error"]["code"], "daemon_forbidden");
        assert_eq!(reset_json["error"]["command"], "reset");

        let logout = blocked_daemon_execute_output(&daemon_test_cli(crate::Command::Logout {
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        }))
        .expect("logout should be blocked");
        let logout_json: serde_json::Value =
            serde_json::from_str(logout.stdout.trim()).expect("logout error JSON");
        assert_eq!(logout.code, 1);
        assert_eq!(logout_json["error"]["code"], "daemon_forbidden");
        assert_eq!(logout_json["error"]["command"], "logout");
    }

    #[tokio::test]
    async fn daemon_peer_authorization_accepts_current_uid() {
        let (stream, _peer) = UnixStream::pair().expect("unix stream pair");

        authorize_daemon_peer(&stream).expect("same-uid peer should be authorized");
    }

    #[test]
    fn daemon_peer_authorization_rejects_mismatched_uid_value() {
        let current_uid = current_effective_uid();
        // Lazily compute the fallback: `unwrap_or` would eagerly evaluate
        // `current_uid - 1`, which underflows when running as uid 0 (root).
        let other_uid = current_uid
            .checked_add(1)
            .unwrap_or_else(|| current_uid - 1);

        assert!(!daemon_peer_uid_authorized(other_uid, current_uid));
    }

    #[tokio::test]
    async fn daemon_request_reader_rejects_oversized_requests() {
        let (mut server, mut client) = UnixStream::pair().expect("unix stream pair");
        let writer = tokio::spawn(async move {
            let oversized = vec![b'{'; MAX_DAEMON_REQUEST_BYTES + 1];
            client
                .write_all(&oversized)
                .await
                .expect("write oversized request");
            client.shutdown().await.expect("shutdown client");
        });

        let err = read_daemon_request(&mut server)
            .await
            .expect_err("oversized request should fail");

        assert!(
            err.to_string().contains("daemon request exceeds"),
            "unexpected error: {err}"
        );
        writer.await.expect("writer task");
    }

    fn daemon_test_cli(command: crate::Command) -> Cli {
        Cli {
            home: None,
            socket: None,
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command,
        }
    }

    #[test]
    fn runtime_message_json_marks_account_label_sender_as_me() {
        let message = marmot_app::ReceivedMessage {
            message_id_hex: "01".to_owned(),
            source_message_id_hex: "source-01".to_owned(),
            sender: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            sender_display_name: Some("Alice Example".to_owned()),
            group_id: GroupId::new(vec![0xab; 32]),
            source_epoch: 0,
            plaintext: "hello".to_owned(),
            kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            recorded_at: 0,
        };

        let value = runtime_message_json(
            &message,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Alice Example",
        );

        assert_eq!(value["direction"], "sent");
        assert_eq!(
            value["from"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(
            value["account_id"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(value["from_display_name"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn stream_watch_workers_reap_finished_handles_on_replace() {
        let workers = StreamWatchWorkers::default();
        workers.replace("finished".to_owned(), tokio::spawn(async {}));
        for _ in 0..10 {
            tokio::task::yield_now().await;
            if workers
                .handles
                .lock()
                .map(|handles| handles["finished"].is_finished())
                .unwrap_or(false)
            {
                break;
            }
        }

        workers.replace(
            "running".to_owned(),
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }),
        );

        let handles = workers.handles.lock().expect("worker lock");
        assert!(!handles.contains_key("finished"));
        assert!(handles.contains_key("running"));
        handles["running"].abort();
    }

    #[test]
    fn runtime_message_json_carries_named_peer_display_name() {
        let message = marmot_app::ReceivedMessage {
            message_id_hex: "02".to_owned(),
            source_message_id_hex: "source-02".to_owned(),
            sender: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            sender_display_name: Some("Bob Example".to_owned()),
            group_id: GroupId::new(vec![0xcd; 32]),
            source_epoch: 0,
            plaintext: "hello back".to_owned(),
            kind: cgka_traits::MARMOT_APP_EVENT_KIND_CHAT,
            tags: Vec::new(),
            recorded_at: 0,
        };

        let value = runtime_message_json(
            &message,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "Alice Example",
        );

        assert_eq!(value["direction"], "received");
        assert_eq!(
            value["from"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            value["account_id"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(value["from_display_name"], "Bob Example");
    }

    #[test]
    fn message_subscription_filters_group_events_by_account() {
        let response = DaemonStreamResponse::ok(serde_json::json!({
            "type": "message",
            "message": {
                "account_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "message_id": "01",
                "plaintext": "wrong account copy"
            }
        }));

        assert!(!stream_response_matches_subscription(
            &response,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(stream_response_matches_subscription(
            &response,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(stream_response_matches_subscription(
            &response,
            None,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
    }

    #[test]
    fn messages_subscribe_args_allow_all_groups() {
        let cli = Cli {
            home: None,
            socket: None,
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command: crate::Command::Messages {
                command: crate::MessageCommand::Subscribe {
                    group: None,
                    limit: Some(250),
                },
            },
        };

        assert_eq!(messages_subscribe_args(&cli), Ok((None, Some(200))));
    }

    #[test]
    fn timeline_messages_subscribe_is_routed_by_command_shape() {
        let cli = Cli {
            home: None,
            socket: None,
            relay: None,
            daemon_discovery_relays: Vec::new(),
            daemon_default_account_relays: Vec::new(),
            secret_store: None,
            keychain_service: None,
            account: None,
            json: true,
            command: crate::Command::Messages {
                command: crate::MessageCommand::Timeline {
                    command: crate::MessageTimelineCommand::Subscribe {
                        group: Some("not-hex".to_owned()),
                        limit: Some(25),
                    },
                },
            },
        };

        assert!(is_timeline_messages_subscribe(&cli));
        assert!(timeline_messages_subscribe_args(&cli).is_err());
    }

    #[test]
    fn timeline_stream_plain_output_is_human_readable() {
        let ready = serde_json::json!({
            "type": "timeline_subscription_ready",
            "group_id": "aa"
        });
        assert_eq!(
            stream_result_plain(&ready),
            "timeline subscription ready group=aa"
        );

        let page = serde_json::json!({
            "type": "initial_timeline_page",
            "has_more_before": true,
            "has_more_after": false,
            "messages": [
                {
                    "group_id": "aa",
                    "from": "alice",
                    "plaintext": "hello",
                    "deleted": false
                }
            ]
        });

        assert_eq!(
            stream_result_plain(&page),
            "initial timeline page has_more_before=true has_more_after=false\ngroup=aa from=alice: hello"
        );

        let projection = serde_json::json!({
            "type": "timeline_projection_updated",
            "group_id": "aa",
            "chat_list_trigger": "NewLastMessage",
            "changes": [
                {
                    "type": "upsert",
                    "trigger": "NewMessage",
                    "message": {
                        "message_id": "01",
                        "group_id": "aa",
                        "from": "alice",
                        "plaintext": "hello"
                    }
                }
            ]
        });
        assert_eq!(
            stream_result_plain(&projection),
            "timeline projection updated group=aa changes=1 chat_list_trigger=NewLastMessage"
        );
    }

    #[test]
    fn message_subscription_filters_stream_updates_by_account_when_present() {
        let scoped_delta = DaemonStreamResponse::ok(serde_json::json!({
            "type": "agent_stream_delta",
            "agent_stream_delta": {
                "account": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "stream_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "text": "hello"
            }
        }));
        let accountless_preview = DaemonStreamResponse::ok(serde_json::json!({
            "type": "stream_preview",
            "stream_preview": {
                "group_id": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "stream_id": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                "status": "running",
                "text": "hello"
            }
        }));

        assert!(!stream_response_matches_subscription(
            &scoped_delta,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(stream_response_matches_subscription(
            &scoped_delta,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        assert!(stream_response_matches_subscription(
            &accountless_preview,
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }
}
