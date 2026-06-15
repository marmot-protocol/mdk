//! `dmd` background runtime daemon: accept loop, request dispatch, and module wiring.

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
use tokio::sync::{Mutex as AsyncMutex, broadcast, mpsc, oneshot};
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

mod lifecycle;
mod protocol;
mod responses;
mod runtime_host;
mod stream_workers;
mod subscriptions;

pub use lifecycle::{default_log_path, default_pid_path, default_socket_path};
pub use protocol::{
    DaemonClient, DaemonClientError, DaemonOutgoingStreamReport, DaemonRuntimeActivityReport,
    DaemonStatus, DaemonStreamError, DaemonStreamResponse, DaemonStreamWatchReport,
};

pub(crate) use lifecycle::*;
pub(crate) use protocol::*;
pub(crate) use responses::*;
pub(crate) use runtime_host::*;
pub(crate) use stream_workers::*;
pub(crate) use subscriptions::*;

const DAEMON_EVENT_REPLAY_LIMIT: usize = 256;
const MESSAGE_SUBSCRIPTION_DEDUP_LIMIT: usize = DAEMON_EVENT_REPLAY_LIMIT;
const MAX_DAEMON_REQUEST_BYTES: usize = 1024 * 1024;
/// Upper bound on how long the single accept loop will wait for an authorized
/// client to send its newline-terminated request frame. A same-UID client that
/// connects and then stalls (never writing a newline) must not wedge the loop
/// and starve every other client of `Status`/`Ping`/etc. On timeout the read is
/// treated like any other per-connection failure: report and `continue`.
const DAEMON_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DAEMON_SOCKET_DIR_MODE: u32 = 0o700;
const DAEMON_SOCKET_MODE: u32 = 0o600;

type SharedDaemonWorkers = Arc<AsyncMutex<DaemonWorkers>>;

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
    let workers = SharedDaemonWorkers::default();
    {
        let mut workers_guard = workers.lock().await;
        reconcile_app_runtime(
            &defaults,
            state.clone(),
            events.clone(),
            &mut workers_guard.runtime,
        )
        .await;
    }
    let mut worker_tasks: Vec<JoinHandle<()>> = Vec::new();
    let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
    let shutdown_result = loop {
        worker_tasks.retain(|task| !task.is_finished());
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let defaults = defaults.clone();
                let state = state.clone();
                let events = events.clone();
                let workers = workers.clone();
                let shutdown_tx = shutdown_tx.clone();
                worker_tasks.push(tokio::spawn(async move {
                    handle_daemon_connection(stream, defaults, state, events, workers, shutdown_tx).await;
                }));
            }
            _ = shutdown_rx.recv() => {
                break Ok(());
            }
        }
    };

    for task in worker_tasks {
        task.abort();
        let _ = task.await;
    }
    let mut workers = workers.lock().await;
    workers.abort_all().await;
    let _ = std::fs::remove_file(&socket);
    let _ = std::fs::remove_file(&pid_path);
    shutdown_result
}

async fn handle_daemon_connection(
    mut stream: UnixStream,
    defaults: DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: SharedDaemonWorkers,
    shutdown_tx: mpsc::UnboundedSender<()>,
) {
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
        return;
    }

    let request = match read_daemon_request_within(&mut stream, DAEMON_REQUEST_READ_TIMEOUT).await {
        Ok(request) => request,
        Err(err) => {
            // A single bad/abrupt/oversized/malformed/stalled connection must
            // not take down the daemon or wedge the accept loop. Each accepted
            // connection owns its bounded read in a worker task, so a slow-loris
            // client can only stall itself while the listener keeps accepting.
            write_daemon_output(
                &mut stream,
                &CliOutput {
                    code: 1,
                    stdout: String::new(),
                    stderr: format!("error: {err}\n"),
                },
            )
            .await;
            return;
        }
    };

    match request {
        DaemonRequest::Status => {
            let output = daemon_status_output(&defaults, state, workers).await;
            write_daemon_output(&mut stream, &output).await;
        }
        DaemonRequest::Ping => {
            write_daemon_output(
                &mut stream,
                &CliOutput {
                    code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            )
            .await;
        }
        DaemonRequest::Shutdown => {
            write_daemon_output(
                &mut stream,
                &CliOutput {
                    code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            )
            .await;
            let _ = shutdown_tx.send(());
        }
        DaemonRequest::MessagesSubscribe { mut cli } => {
            apply_defaults(&mut cli, &defaults);
            let runtime = {
                let mut workers_guard = workers.lock().await;
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers_guard.runtime,
                )
                .await;
                workers_guard.runtime.runtime.clone()
            };
            let _ =
                handle_messages_subscription(&mut stream, &defaults, state, events, runtime, *cli)
                    .await;
        }
        DaemonRequest::ChatsSubscribe { mut cli } => {
            apply_defaults(&mut cli, &defaults);
            let runtime = {
                let mut workers_guard = workers.lock().await;
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers_guard.runtime,
                )
                .await;
                workers_guard.runtime.runtime.clone()
            };
            let _ = handle_chats_subscription(&mut stream, &defaults, runtime, *cli).await;
        }
        DaemonRequest::GroupStateSubscribe { mut cli } => {
            apply_defaults(&mut cli, &defaults);
            let runtime = {
                let mut workers_guard = workers.lock().await;
                reconcile_app_runtime(
                    &defaults,
                    state.clone(),
                    events.clone(),
                    &mut workers_guard.runtime,
                )
                .await;
                workers_guard.runtime.runtime.clone()
            };
            let _ = handle_group_state_subscription(&mut stream, &defaults, runtime, *cli).await;
        }
        DaemonRequest::StreamWatch { cli } => {
            let mut workers_guard = workers.lock().await;
            let _ = handle_stream_watch_connection(
                cli,
                &mut stream,
                &defaults,
                state,
                events,
                &mut workers_guard,
            )
            .await;
        }
        DaemonRequest::Execute { cli } => {
            let mut workers_guard = workers.lock().await;
            let _ = handle_execute_connection(
                cli,
                &mut stream,
                &defaults,
                state,
                events,
                &mut workers_guard,
            )
            .await;
        }
    }
}

async fn daemon_status_output(
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    workers: SharedDaemonWorkers,
) -> CliOutput {
    let (runtime, stream_watch) = match workers.try_lock() {
        Ok(workers_guard) => (
            workers_guard.runtime.runtime.clone(),
            workers_guard.runtime.stream_watch.clone(),
        ),
        Err(_) => (None, StreamWatchWorkers::default()),
    };
    let status = server_status(defaults, &state, runtime.as_ref(), &stream_watch).await;
    CliOutput {
        code: 0,
        stdout: serde_json::to_string(&status).expect("daemon status serializes"),
        stderr: String::new(),
    }
}

async fn handle_stream_watch_connection(
    mut cli: Box<Cli>,
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &mut DaemonWorkers,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    write_daemon_output(stream, &output).await;
    Ok(())
}

async fn handle_execute_connection(
    mut cli: Box<Cli>,
    stream: &mut UnixStream,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    workers: &mut DaemonWorkers,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    apply_defaults(&mut cli, defaults);
    if let Some(output) = blocked_daemon_execute_output(cli.as_ref()) {
        write_daemon_output(stream, &output).await;
        return Ok(());
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
        return Ok(());
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
        return Ok(());
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
        return Ok(());
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

    write_daemon_output(stream, &output).await;
    Ok(())
}

#[cfg(test)]
mod tests;
