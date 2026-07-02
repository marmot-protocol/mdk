//! Daemon wire protocol: request/response types, framing, and the client.

use super::*;

#[derive(Debug)]
pub(crate) struct BoundedMessageSubscriptionIds {
    pub(crate) ids: HashSet<String>,
    pub(crate) order: VecDeque<String>,
    pub(crate) limit: usize,
}

impl BoundedMessageSubscriptionIds {
    pub(crate) fn with_limit(limit: usize) -> Self {
        Self {
            ids: HashSet::new(),
            order: VecDeque::new(),
            limit,
        }
    }

    pub(crate) fn insert(&mut self, id: String) -> bool {
        if id.is_empty() {
            return true;
        }
        if !self.ids.insert(id.clone()) {
            return false;
        }
        self.order.push_back(id);
        while self.ids.len() > self.limit {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.ids.remove(&oldest);
        }
        true
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.ids.len()
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

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
    #[error("daemon request is {size} bytes, exceeding the {limit} byte limit")]
    RequestTooLarge { size: usize, limit: usize },
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum DaemonRequest {
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
    pub(crate) fn ok(result: serde_json::Value) -> Self {
        Self {
            result: Some(result),
            error: None,
            stream_end: false,
        }
    }

    pub(crate) fn err(message: impl Into<String>) -> Self {
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
pub(crate) struct DaemonEventHub {
    pub(crate) messages: broadcast::Sender<DaemonStreamResponse>,
    pub(crate) recent_messages: Arc<Mutex<VecDeque<DaemonStreamResponse>>>,
}

impl DaemonEventHub {
    pub(crate) fn new() -> Self {
        let (messages, _) = broadcast::channel(1024);
        Self {
            messages,
            recent_messages: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub(crate) fn subscribe_messages(&self) -> broadcast::Receiver<DaemonStreamResponse> {
        self.messages.subscribe()
    }

    pub(crate) fn publish_message(&self, response: DaemonStreamResponse) {
        if let Ok(mut recent) = self.recent_messages.lock() {
            recent.push_back(response.clone());
            while recent.len() > DAEMON_EVENT_REPLAY_LIMIT {
                recent.pop_front();
            }
        }
        let _ = self.messages.send(response);
    }

    pub(crate) fn recent_messages(&self) -> Vec<DaemonStreamResponse> {
        self.recent_messages
            .lock()
            .map(|recent| recent.iter().cloned().collect())
            .unwrap_or_default()
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
    pub(crate) socket: PathBuf,
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

pub(crate) async fn write_daemon_output(stream: &mut UnixStream, output: &CliOutput) {
    let Ok(mut response) = serde_json::to_vec(output) else {
        return;
    };
    response.push(b'\n');
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

pub(crate) async fn read_daemon_request(
    stream: &mut UnixStream,
) -> Result<DaemonRequest, Box<dyn std::error::Error + Send + Sync>> {
    let mut request = Vec::new();
    // Buffer the raw stream so a near-1-MiB frame (e.g. an `Execute` request
    // carrying the whole `Cli`) costs a handful of `read()` syscalls instead of
    // one per byte. Cap the read at one byte past the limit so a client that
    // never sends a newline cannot make us buffer unbounded memory before the
    // size check runs (read_until on a Take adapter stops silently at the limit
    // instead of erroring). Mirrors agent-control's `read_frame`.
    let limit = (MAX_DAEMON_REQUEST_BYTES + 1) as u64;
    let read = {
        let mut reader = BufReader::new(&mut *stream).take(limit);
        reader.read_until(b'\n', &mut request).await?
    };
    if read == 0 {
        return Err(DaemonClientError::EmptyResponse.into());
    }
    // The size cap counts payload bytes only, excluding the framing newline.
    let payload = request.strip_suffix(b"\n").unwrap_or(&request);
    if payload.len() > MAX_DAEMON_REQUEST_BYTES {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("daemon request exceeds {MAX_DAEMON_REQUEST_BYTES} bytes"),
        )
        .into());
    }
    Ok(serde_json::from_slice(payload)?)
}

/// Read a daemon request frame, but give up after `timeout` if the client
/// connects without ever sending a complete newline-terminated frame. This
/// keeps the single accept loop responsive: a stalled (or slow-loris) same-UID
/// client cannot wedge the loop and starve other clients. A timeout surfaces as
/// an `io::Error` of kind `TimedOut`, which the accept loop treats like any
/// other per-connection read failure.
pub(crate) async fn read_daemon_request_within(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<DaemonRequest, Box<dyn std::error::Error + Send + Sync>> {
    match tokio::time::timeout(timeout, read_daemon_request(stream)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "daemon client did not send a request within the read timeout",
        )
        .into()),
    }
}

pub(crate) async fn write_stream_response(
    stream: &mut UnixStream,
    response: &DaemonStreamResponse,
) -> bool {
    let Ok(mut bytes) = serde_json::to_vec(response) else {
        return false;
    };
    bytes.push(b'\n');
    stream.write_all(&bytes).await.is_ok()
}

pub(crate) async fn write_stream_end(stream: &mut UnixStream) -> bool {
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

/// Encode a daemon request as a newline-terminated JSON frame, rejecting
/// payloads that exceed the daemon's per-request size limit before they hit
/// the wire. The daemon enforces the same cap on read (see
/// `read_daemon_request` / `MAX_DAEMON_REQUEST_BYTES`); checking client-side
/// turns an oversized request (e.g. `messages send` with a huge body) into a
/// clear local error instead of a connection the daemon must reject.
pub(crate) fn encode_daemon_request(request: &DaemonRequest) -> Result<Vec<u8>, DaemonClientError> {
    let mut bytes = serde_json::to_vec(request)?;
    // The daemon reads up to and excluding the trailing newline, so compare the
    // JSON payload length (without the framing newline) against the limit.
    if bytes.len() > MAX_DAEMON_REQUEST_BYTES {
        return Err(DaemonClientError::RequestTooLarge {
            size: bytes.len(),
            limit: MAX_DAEMON_REQUEST_BYTES,
        });
    }
    bytes.push(b'\n');
    Ok(bytes)
}

pub(crate) async fn send_request(
    socket: &Path,
    request: &DaemonRequest,
) -> Result<CliOutput, DaemonClientError> {
    let bytes = encode_daemon_request(request)?;
    let mut stream =
        UnixStream::connect(socket)
            .await
            .map_err(|source| DaemonClientError::Connect {
                socket: socket.to_owned(),
                source,
            })?;
    stream.write_all(&bytes).await?;
    stream.shutdown().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    if response.is_empty() {
        return Err(DaemonClientError::EmptyResponse);
    }
    Ok(serde_json::from_slice(&response)?)
}

pub(crate) async fn stream_request(
    socket: &Path,
    request: &DaemonRequest,
    json_output: bool,
) -> Result<CliOutput, DaemonClientError> {
    let bytes = encode_daemon_request(request)?;
    let mut stream =
        UnixStream::connect(socket)
            .await
            .map_err(|source| DaemonClientError::Connect {
                socket: socket.to_owned(),
                source,
            })?;
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

pub(crate) fn write_client_stream_response(
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

pub(crate) fn stream_result_plain(result: &serde_json::Value) -> String {
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

pub(crate) fn timeline_stream_page_plain(result: &serde_json::Value) -> String {
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

pub(crate) fn timeline_projection_stream_plain(result: &serde_json::Value) -> String {
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

pub(crate) fn timeline_stream_message_plain(message: &serde_json::Value) -> String {
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
        crate::commands::messages::timeline_message_display_text(message),
        deleted
    )
}
