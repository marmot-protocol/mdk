//! Background stream watch and stream-compose worker management.

use super::*;

#[derive(Clone, Default)]
pub(crate) struct StreamWatchWorkers {
    pub(crate) handles: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

impl StreamWatchWorkers {
    pub(crate) fn replace(&self, watch_id: String, handle: JoinHandle<()>) {
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

    pub(crate) fn reap_finished(&self) {
        if let Ok(mut handles) = self.handles.lock() {
            Self::reap_finished_locked(&mut handles);
        }
    }

    pub(crate) fn reap_finished_locked(handles: &mut HashMap<String, JoinHandle<()>>) {
        handles.retain(|_, handle| !handle.is_finished());
    }

    pub(crate) fn abort_all(&self) {
        if let Ok(mut handles) = self.handles.lock() {
            for (_, handle) in handles.drain() {
                handle.abort();
            }
        }
    }
}

#[derive(Default)]
pub(crate) struct StreamComposeWorkers {
    pub(crate) sessions: HashMap<String, StreamComposeSession>,
}

impl StreamComposeWorkers {
    pub(crate) fn insert(&mut self, key: String, session: StreamComposeSession) {
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

    pub(crate) fn remove(&mut self, key: &str) -> Option<StreamComposeSession> {
        self.sessions.remove(key)
    }

    pub(crate) fn get(&self, key: &str) -> Option<&StreamComposeSession> {
        self.sessions.get(key)
    }

    pub(crate) fn abort_all(&mut self) {
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

pub(crate) struct StreamComposeSession {
    pub(crate) tx: mpsc::Sender<StreamComposeCommand>,
    pub(crate) cancel_tx: mpsc::Sender<()>,
    pub(crate) handle: JoinHandle<()>,
}

pub(crate) async fn start_stream_watch(
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

pub(crate) fn spawn_stream_watch(
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
            crate::commands::stream::stream_watch_command_app_with_runtime(
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

pub(crate) fn new_stream_watch_start(
    cli: &Cli,
) -> Result<marmot_app::AgentStreamWatchStart, String> {
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
        .map(crate::commands::stream::normalize_hex)
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

pub(crate) fn finish_stream_watch(
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

pub(crate) fn stream_watch_output(json: bool, report: &DaemonStreamWatchReport) -> CliOutput {
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

pub(crate) async fn handle_stream_compose_request(
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
pub(crate) async fn open_stream_compose(
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
        .map(|stream_id| crate::commands::stream::normalize_hex(&stream_id))
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
    let parsed_candidate = match crate::commands::stream::parse_quic_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    // Only an explicit local `--insecure-local` opt-in may resolve to a
    // local/private endpoint; otherwise reject unsafe candidates.
    let candidate_addr = match crate::commands::stream::resolve_quic_candidate_addr(
        &parsed_candidate,
        insecure_local,
    )
    .await
    {
        Ok(addr) => addr,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let trust = match crate::commands::stream::broker_trust(candidate_addr, None, insecure_local) {
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
    let (crypto, policy_max_plaintext_frame_len) = {
        let Some(runtime) = runtime_host.runtime.as_ref() else {
            return daemon_error(
                cli.json,
                "stream_compose_failed",
                "app runtime is not available for stream crypto".to_owned(),
            );
        };
        match crate::commands::stream::stream_crypto_for_start_event(
            runtime,
            Some(&start_account_id),
            Some(group_id.as_str()),
            Some(stream_id.as_str()),
            &start_message_id,
        )
        .await
        {
            Ok((_, crypto, policy_max_plaintext_frame_len)) => {
                (Some(crypto), policy_max_plaintext_frame_len)
            }
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
                max_plaintext_frame_len: policy_max_plaintext_frame_len,
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

pub(crate) async fn append_stream_compose(
    cli: &Cli,
    workers: &StreamComposeWorkers,
    stream_id: &str,
    text: String,
) -> CliOutput {
    let stream_id = match crate::commands::stream::normalize_hex(stream_id) {
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

pub(crate) async fn finish_stream_compose(
    cli: &Cli,
    defaults: &DaemonDefaults,
    state: Arc<Mutex<DaemonState>>,
    events: DaemonEventHub,
    runtime_host: &mut AppRuntimeHost,
    workers: &mut StreamComposeWorkers,
    stream_id: &str,
) -> CliOutput {
    let stream_id = match crate::commands::stream::normalize_hex(stream_id) {
        Ok(stream_id) => stream_id,
        Err(err) => return daemon_error(cli.json, "stream_compose_failed", err.to_string()),
    };
    let key = stream_compose_key(cli.account.as_deref(), &stream_id);
    // Keep the session in the workers map until the MLS finish marker is durably
    // published below. Borrow only the command sender (clonable) so the session
    // entry stays intact and the transcript stays retryable if the marker fails.
    let Some(tx) = workers.get(&key).map(|session| session.tx.clone()) else {
        return daemon_error(
            cli.json,
            "stream_compose_not_found",
            format!("no active stream compose session for {stream_id}"),
        );
    };
    let (respond, response) = oneshot::channel();
    if tx
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
        // The finish marker did not publish: leave the session in the workers
        // map so the transcript can be retried instead of being lost.
        return daemon_error(cli.json, "stream_compose_failed", err);
    }
    // Marker published: now it is safe to drop the session.
    workers.remove(&key);
    daemon_output(
        cli.json,
        &format!("finished stream {}", short_id(&report.stream_id)),
        serde_json::json!(report),
        0,
    )
}

pub(crate) fn cancel_stream_compose(
    cli: &Cli,
    workers: &mut StreamComposeWorkers,
    stream_id: &str,
) -> CliOutput {
    let stream_id = match crate::commands::stream::normalize_hex(stream_id) {
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

pub(crate) async fn run_hosted_stream_marker_cli_json(
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

pub(crate) fn short_id(value: &str) -> String {
    value.chars().take(12).collect()
}

pub(crate) fn stream_compose_key(account: Option<&str>, stream_id: &str) -> String {
    format!("{}:{stream_id}", account.unwrap_or(""))
}
