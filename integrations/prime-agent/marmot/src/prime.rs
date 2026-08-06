use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use marmot_terminal_harness::{
    Backend, HarnessError, Invocation, Outcome, RunFailure, RunnerEvent,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{sleep, timeout};

const DAEMON_PROTOCOL_NAME: &str = "prime-agent.daemon";
const DAEMON_PROTOCOL_VERSION: u64 = 7;
const DAEMON_SCHEMA_REVISION: u64 = 13;
const DAEMON_APP_VERSION: &str = "0.7.0";
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(10);
const DAEMON_ABORT_TIMEOUT: Duration = Duration::from_secs(2);
const DAEMON_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
const DAEMON_FRAME_OVERHEAD_BYTES: usize = 8 * 1024;
const CONTROL_REPLY_MAX_BYTES: usize = 16 * 1024;
const CONTROL_REPLY_TRUNCATED_SUFFIX: &str = "\n… output truncated";

#[derive(Clone)]
pub(crate) struct PrimeBackend {
    bin: String,
    daemon_socket: PathBuf,
    start_gate: Arc<Mutex<()>>,
    request_seq: Arc<AtomicU64>,
}

impl PrimeBackend {
    pub(crate) fn new(bin: String, daemon_socket: PathBuf) -> Self {
        Self {
            bin,
            daemon_socket,
            start_gate: Arc::new(Mutex::new(())),
            request_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    async fn ensure_daemon(&self, cwd: &Path) -> Result<(), HarnessError> {
        if self.daemon_ready().await? {
            return Ok(());
        }
        let _guard = self.start_gate.lock().await;
        if self.daemon_ready().await? {
            return Ok(());
        }
        if let Some(parent) = self.daemon_socket.parent() {
            fs_private::create_dir_all_private(parent)?;
        }
        let mut child = Command::new(&self.bin)
            .arg("--mode")
            .arg("daemon")
            .arg("--daemon-socket")
            .arg(&self.daemon_socket)
            .current_dir(cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(false)
            .spawn()
            .map_err(|_| HarnessError::BackendSpawn)?;

        let deadline = Instant::now() + DAEMON_START_TIMEOUT;
        loop {
            if self.daemon_ready().await? {
                return Ok(());
            }
            if child
                .try_wait()
                .map_err(|_| HarnessError::BackendSpawn)?
                .is_some()
            {
                return Err(HarnessError::BackendSpawn);
            }
            if Instant::now() >= deadline {
                let _ = child.kill().await;
                return Err(HarnessError::BackendSpawn);
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Reports whether a compatible daemon answers without hiding protocol mismatches.
    async fn daemon_ready(&self) -> Result<bool, HarnessError> {
        match timeout(
            Duration::from_millis(500),
            DaemonConnection::connect(
                &self.daemon_socket,
                self.request_seq.clone(),
                Duration::from_millis(500),
            ),
        )
        .await
        {
            Ok(Ok(_)) => Ok(true),
            Ok(Err(error @ HarnessError::BackendProtocolMismatch)) => Err(error),
            Ok(Err(_)) | Err(_) => Ok(false),
        }
    }

    async fn run_inner(
        &self,
        invocation: &Invocation,
        tx: &mpsc::Sender<RunnerEvent>,
        observed_session: &mut Option<String>,
        observed_session_path: &mut Option<PathBuf>,
        prompt_started: &mut bool,
    ) -> Result<(String, Option<String>), HarnessError> {
        self.ensure_daemon(&invocation.cwd).await?;
        let mut daemon = DaemonConnection::connect(
            &self.daemon_socket,
            self.request_seq.clone(),
            invocation.idle_timeout,
        )
        .await?;

        let (session_id, session_path) = match &invocation.session_path {
            Some(session_path) => {
                let data = daemon
                    .request(
                        json!({
                            "type": "create",
                            "sessionPath": session_path,
                            "name": invocation.session_name,
                            "config": {"cwd": invocation.cwd},
                        }),
                        None,
                    )
                    .await?;
                parse_created_session(&data, Some(session_path))?
            }
            None => match &invocation.session_id {
                Some(session_id) => (session_id.clone(), None),
                None => {
                    let data = daemon
                        .request(
                            json!({
                                "type": "create",
                                "name": invocation.session_name,
                                "config": {"cwd": invocation.cwd},
                            }),
                            None,
                        )
                        .await?;
                    parse_created_session(&data, None)?
                }
            },
        };
        *observed_session = Some(session_id.clone());
        if let Some(session_path) = session_path {
            *observed_session_path = Some(session_path);
        }

        daemon
            .request(
                json!({
                    "type": "attach",
                    "activeSessionId": session_id,
                    "capabilities": [
                        "attach_snapshot",
                        "event_sequence",
                        "slim_attach",
                        "chunked_snapshot"
                    ],
                }),
                None,
            )
            .await?;
        daemon
            .request(
                json!({
                    "type": "set_session_name",
                    "activeSessionId": session_id,
                    "name": invocation.session_name,
                }),
                None,
            )
            .await?;

        match parse_model_command(&invocation.prompt) {
            ModelCommand::NotModel => {
                let (message, images) = prompt_content(invocation).await?;
                *prompt_started = true;
                match daemon
                    .request_raw(
                        json!({
                            "type": "prompt_and_wait",
                            "activeSessionId": session_id,
                            "message": message,
                            "images": images,
                        }),
                        Some(tx),
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(DaemonRequestError::Rejected(message)) => {
                        return Ok((session_id, Some(bounded_control_reply(message))));
                    }
                    Err(error) => return Err(error.into_harness()),
                }
                let data = daemon
                    .request(
                        json!({
                            "type": "get_last_assistant_text",
                            "activeSessionId": session_id,
                        }),
                        None,
                    )
                    .await?;
                let text = data.get("text").and_then(Value::as_str).map(str::to_owned);
                Ok((session_id, text))
            }
            ModelCommand::List => {
                let data = match daemon
                    .request_raw(
                        json!({
                            "type": "get_available_models",
                            "activeSessionId": session_id,
                        }),
                        None,
                    )
                    .await
                {
                    Ok(data) => data,
                    Err(DaemonRequestError::Rejected(message)) => {
                        return Ok((session_id, Some(bounded_control_reply(message))));
                    }
                    Err(error) => return Err(error.into_harness()),
                };
                Ok((
                    session_id,
                    Some(bounded_control_reply(format_models(&data))),
                ))
            }
            ModelCommand::Set { provider, model_id } => {
                let data = match daemon
                    .request_raw(
                        json!({
                            "type": "set_model",
                            "activeSessionId": session_id,
                            "provider": provider,
                            "modelId": model_id,
                        }),
                        None,
                    )
                    .await
                {
                    Ok(data) => data,
                    Err(DaemonRequestError::Rejected(message)) => {
                        return Ok((session_id, Some(bounded_control_reply(message))));
                    }
                    Err(error) => return Err(error.into_harness()),
                };
                let selected = data.get("model").unwrap_or(&data);
                let selected_provider = selected
                    .get("provider")
                    .and_then(Value::as_str)
                    .unwrap_or(&provider);
                let selected_model = selected
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or(&model_id);
                Ok((
                    session_id,
                    Some(bounded_control_reply(format!(
                        "Model set to {selected_provider}/{selected_model}."
                    ))),
                ))
            }
            ModelCommand::Invalid => Ok((
                session_id,
                Some("Usage: /model or /model <provider>/<model>.".to_owned()),
            )),
        }
    }

    async fn abort_session(&self, session_id: &str) {
        let abort = async {
            let mut daemon = DaemonConnection::connect(
                &self.daemon_socket,
                self.request_seq.clone(),
                DAEMON_ABORT_TIMEOUT,
            )
            .await?;
            daemon
                .request(
                    json!({
                        "type": "abort",
                        "activeSessionId": session_id,
                    }),
                    None,
                )
                .await?;
            Ok::<(), HarnessError>(())
        };
        let _ = timeout(DAEMON_ABORT_TIMEOUT, abort).await;
    }
}

#[async_trait]
impl Backend for PrimeBackend {
    fn accepts_attachments(&self) -> bool {
        true
    }

    async fn run(
        &self,
        invocation: Invocation,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> std::result::Result<Outcome, RunFailure> {
        let started = Instant::now();
        let mut observed_session = invocation.session_id.clone();
        let mut observed_session_path = invocation.session_path.clone();
        let mut prompt_started = false;
        let result = match timeout(
            invocation.timeout,
            self.run_inner(
                &invocation,
                &tx,
                &mut observed_session,
                &mut observed_session_path,
                &mut prompt_started,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(HarnessError::BackendTimedOut),
        };
        match result {
            Err(error) => {
                if prompt_started && let Some(session_id) = observed_session.as_deref() {
                    self.abort_session(session_id).await;
                }
                Err(RunFailure {
                    error,
                    observed_session,
                    observed_session_path,
                })
            }
            Ok((session_id, text)) => {
                if let Some(text) = text.filter(|text| !text.is_empty()) {
                    tx.send(RunnerEvent::Text(text))
                        .await
                        .map_err(|_| RunFailure {
                            error: HarnessError::BackendStream,
                            observed_session: Some(session_id.clone()),
                            observed_session_path: observed_session_path.clone(),
                        })?;
                }
                Ok(Outcome {
                    observed_session: Some(session_id),
                    observed_session_path,
                    exit_code: Some(0),
                    error_summary: None,
                    stderr: String::new(),
                    elapsed_ms: started.elapsed().as_millis(),
                })
            }
        }
    }
}

fn parse_created_session(
    data: &Value,
    requested_path: Option<&PathBuf>,
) -> Result<(String, Option<PathBuf>), HarnessError> {
    let session_id = data
        .get("activeSessionId")
        .or_else(|| data.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(HarnessError::BackendStream)?;
    let session_path = data
        .get("sessionFile")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| requested_path.cloned());
    Ok((session_id, session_path))
}

async fn prompt_content(invocation: &Invocation) -> Result<(String, Vec<Value>), HarnessError> {
    let mut message = invocation.prompt.clone();
    let mut image_attachments = Vec::new();
    for attachment in &invocation.attachments {
        if attachment.media_type.starts_with("image/") {
            image_attachments.push(attachment);
        } else {
            message.push_str(&format!(
                "\n\nAttached file `{}` is available at `{}`.",
                attachment.file_name,
                attachment.path.display()
            ));
        }
    }

    let mut projected_frame_bytes = serde_json::to_vec(&message)
        .map_err(|_| HarnessError::BackendStream)?
        .len()
        .checked_add(DAEMON_FRAME_OVERHEAD_BYTES)
        .ok_or(HarnessError::BackendStream)?;
    for attachment in &image_attachments {
        let raw_bytes = tokio::fs::metadata(&attachment.path).await?.len();
        let encoded_bytes = base64_encoded_len(raw_bytes).ok_or(HarnessError::BackendStream)?;
        projected_frame_bytes = projected_frame_bytes
            .checked_add(encoded_bytes)
            .and_then(|size| size.checked_add(attachment.media_type.len() + 64))
            .ok_or(HarnessError::BackendStream)?;
        if projected_frame_bytes > DAEMON_MAX_FRAME_BYTES {
            return Err(HarnessError::BackendStream);
        }
    }

    let mut images = Vec::with_capacity(image_attachments.len());
    for attachment in image_attachments {
        let bytes = tokio::fs::read(&attachment.path).await?;
        images.push(json!({
            "type": "image",
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
            "mimeType": attachment.media_type,
        }));
    }
    Ok((message, images))
}

fn base64_encoded_len(raw_bytes: u64) -> Option<usize> {
    usize::try_from(raw_bytes)
        .ok()?
        .checked_add(2)?
        .checked_div(3)?
        .checked_mul(4)
}

enum DaemonRequestError {
    Harness(HarnessError),
    Rejected(String),
}

impl DaemonRequestError {
    fn into_harness(self) -> HarnessError {
        match self {
            Self::Harness(error) => error,
            Self::Rejected(_) => HarnessError::BackendStream,
        }
    }
}

impl From<HarnessError> for DaemonRequestError {
    fn from(error: HarnessError) -> Self {
        Self::Harness(error)
    }
}

struct DaemonConnection {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
    request_seq: Arc<AtomicU64>,
    idle_timeout: Duration,
    protocol_version: u64,
    client_id: String,
}

impl DaemonConnection {
    async fn connect(
        socket: &Path,
        request_seq: Arc<AtomicU64>,
        idle_timeout: Duration,
    ) -> Result<Self, HarnessError> {
        let stream = UnixStream::connect(socket).await?;
        let (read_half, writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let hello = read_json_line(&mut reader, idle_timeout).await?;
        if hello.get("type").and_then(Value::as_str) != Some("daemon_hello")
            || hello.pointer("/protocol/name").and_then(Value::as_str) != Some(DAEMON_PROTOCOL_NAME)
            || hello.get("appVersion").and_then(Value::as_str) != Some(DAEMON_APP_VERSION)
        {
            return Err(HarnessError::BackendProtocolMismatch);
        }
        let protocol_version = hello
            .pointer("/protocol/version")
            .and_then(Value::as_u64)
            .ok_or(HarnessError::BackendProtocolMismatch)?;
        if protocol_version != DAEMON_PROTOCOL_VERSION {
            return Err(HarnessError::BackendProtocolMismatch);
        }
        let schema_revision = hello
            .get("schemaRevision")
            .and_then(Value::as_u64)
            .ok_or(HarnessError::BackendProtocolMismatch)?;
        if schema_revision != DAEMON_SCHEMA_REVISION {
            return Err(HarnessError::BackendProtocolMismatch);
        }
        Ok(Self {
            reader,
            writer,
            request_seq,
            idle_timeout,
            protocol_version,
            client_id: format!("wn-prime-agent:{}", std::process::id()),
        })
    }

    async fn request(
        &mut self,
        command: Value,
        events: Option<&mpsc::Sender<RunnerEvent>>,
    ) -> Result<Value, HarnessError> {
        self.request_raw(command, events)
            .await
            .map_err(DaemonRequestError::into_harness)
    }

    async fn request_raw(
        &mut self,
        mut command: Value,
        events: Option<&mpsc::Sender<RunnerEvent>>,
    ) -> Result<Value, DaemonRequestError> {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("wn-prime-agent-{}-{seq}", std::process::id());
        command["id"] = Value::String(id.clone());
        let frame = json!({
            "type": "command",
            "id": id,
            "protocol": {"name": DAEMON_PROTOCOL_NAME, "version": self.protocol_version},
            "clientId": self.client_id,
            "command": command,
        });
        write_json_line(&mut self.writer, &frame).await?;

        loop {
            let message = read_json_line(&mut self.reader, self.idle_timeout).await?;
            if message.get("type").and_then(Value::as_str) == Some("response")
                && message.get("id").and_then(Value::as_str) == Some(id.as_str())
            {
                let error =
                    (message.get("success").and_then(Value::as_bool) != Some(true)).then(|| {
                        message
                            .get("error")
                            .and_then(Value::as_str)
                            .unwrap_or("Prime Agent rejected the command.")
                            .to_owned()
                    });
                self.acknowledge(&id).await?;
                if let Some(error) = error {
                    return Err(DaemonRequestError::Rejected(error));
                }
                return Ok(message.get("data").cloned().unwrap_or(Value::Null));
            }
            if let Some(delta) = assistant_text_delta(&message)
                && let Some(events) = events
            {
                events
                    .send(RunnerEvent::Preview(delta.to_owned()))
                    .await
                    .map_err(|_| HarnessError::BackendStream)?;
            }
        }
    }

    async fn acknowledge(&mut self, command_id: &str) -> Result<(), HarnessError> {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("wn-prime-agent-ack-{}-{seq}", std::process::id());
        let frame = json!({
            "type": "command",
            "id": id,
            "protocol": {"name": DAEMON_PROTOCOL_NAME, "version": self.protocol_version},
            "clientId": self.client_id,
            "command": {"id": id, "type": "ack_result", "commandId": command_id},
        });
        write_json_line(&mut self.writer, &frame).await
    }
}

async fn read_json_line(
    reader: &mut BufReader<ReadHalf<UnixStream>>,
    idle_timeout: Duration,
) -> Result<Value, HarnessError> {
    let mut line = Vec::new();
    loop {
        let available = timeout(idle_timeout, reader.fill_buf())
            .await
            .map_err(|_| HarnessError::BackendIdle)??;
        if available.is_empty() {
            return Err(HarnessError::BackendStream);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > DAEMON_MAX_FRAME_BYTES {
            return Err(HarnessError::BackendStream);
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            break;
        }
    }
    serde_json::from_slice(&line).map_err(Into::into)
}

async fn write_json_line(
    writer: &mut WriteHalf<UnixStream>,
    value: &Value,
) -> Result<(), HarnessError> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len().saturating_add(1) > DAEMON_MAX_FRAME_BYTES {
        return Err(HarnessError::BackendStream);
    }
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ModelCommand {
    NotModel,
    List,
    Set { provider: String, model_id: String },
    Invalid,
}

fn parse_model_command(prompt: &str) -> ModelCommand {
    let trimmed = prompt.trim();
    if trimmed == "/model" {
        return ModelCommand::List;
    }
    let Some(selector) = trimmed.strip_prefix("/model ").map(str::trim) else {
        return ModelCommand::NotModel;
    };
    let Some((provider, model_id)) = selector.split_once('/') else {
        return ModelCommand::Invalid;
    };
    if provider.is_empty() || model_id.is_empty() {
        return ModelCommand::Invalid;
    }
    ModelCommand::Set {
        provider: provider.to_owned(),
        model_id: model_id.to_owned(),
    }
}

fn format_models(data: &Value) -> String {
    let models = data
        .get("models")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|model| {
            Some(format!(
                "{}/{} — {}",
                model.get("provider")?.as_str()?,
                model.get("id")?.as_str()?,
                model
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed")
            ))
        })
        .collect::<Vec<_>>();
    if models.is_empty() {
        "Prime Agent reported no available models.".to_owned()
    } else {
        format!("Available models:\n{}", models.join("\n"))
    }
}

fn bounded_control_reply(mut reply: String) -> String {
    if reply.len() <= CONTROL_REPLY_MAX_BYTES {
        return reply;
    }
    let mut keep = CONTROL_REPLY_MAX_BYTES - CONTROL_REPLY_TRUNCATED_SUFFIX.len();
    while !reply.is_char_boundary(keep) {
        keep -= 1;
    }
    reply.truncate(keep);
    reply.push_str(CONTROL_REPLY_TRUNCATED_SUFFIX);
    reply
}

fn assistant_text_delta(message: &Value) -> Option<&str> {
    match message.get("type").and_then(Value::as_str)? {
        "event" => assistant_text_delta(message.get("event")?),
        "session_event" => {
            let event = message.get("event")?;
            if event.get("type").and_then(Value::as_str) != Some("message_update")
                || event
                    .pointer("/assistantMessageEvent/type")
                    .and_then(Value::as_str)
                    != Some("text_delta")
            {
                return None;
            }
            event
                .pointer("/assistantMessageEvent/delta")
                .and_then(Value::as_str)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    fn test_invocation(root: &Path, session_id: Option<String>, prompt: &str) -> Invocation {
        Invocation {
            timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(2),
            cwd: root.to_path_buf(),
            session_id,
            session_path: None,
            session_name: "marmot-daemon-contract".to_owned(),
            prompt: prompt.to_owned(),
            attachments: Vec::new(),
        }
    }

    async fn write_daemon_message(writer: &mut tokio::net::unix::OwnedWriteHalf, message: Value) {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        writer.write_all(&bytes).await.unwrap();
    }

    async fn run_fake_daemon(listener: UnixListener, session_file: PathBuf) {
        let mut actual_connection = 0usize;
        while actual_connection < 4 {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut writer) = stream.into_split();
            write_daemon_message(
                &mut writer,
                json!({
                    "type": "daemon_hello",
                    "appVersion": DAEMON_APP_VERSION,
                    "protocol": {
                        "name": DAEMON_PROTOCOL_NAME,
                        "version": DAEMON_PROTOCOL_VERSION
                    },
                    "schemaRevision": DAEMON_SCHEMA_REVISION
                }),
            )
            .await;
            let mut lines = BufReader::new(read_half).lines();
            let Some(first) = lines.next_line().await.unwrap() else {
                continue;
            };
            actual_connection += 1;
            let mut next = Some(first);
            let mut saw_prompt = false;
            let mut successful_commands = 0usize;
            let mut final_command_id = None;
            let mut rejected_command_id = None;
            while let Some(line) = match next.take() {
                Some(line) => Some(line),
                None => lines.next_line().await.unwrap(),
            } {
                let envelope: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(
                    envelope.get("type").and_then(Value::as_str),
                    Some("command")
                );
                assert_eq!(
                    envelope.pointer("/protocol/name").and_then(Value::as_str),
                    Some(DAEMON_PROTOCOL_NAME)
                );
                assert_eq!(
                    envelope
                        .pointer("/protocol/version")
                        .and_then(Value::as_u64),
                    Some(DAEMON_PROTOCOL_VERSION)
                );
                let id = envelope.get("id").and_then(Value::as_str).unwrap();
                let command = envelope.get("command").unwrap();
                let command_type = command.get("type").and_then(Value::as_str).unwrap();
                if command_type == "ack_result" {
                    let command_id = command.get("commandId").and_then(Value::as_str).unwrap();
                    if rejected_command_id.as_deref() == Some(command_id) {
                        rejected_command_id = None;
                        break;
                    }
                    if final_command_id.as_deref() == Some(command_id) {
                        break;
                    }
                    continue;
                }
                let data = match command_type {
                    "create" => {
                        assert!(actual_connection <= 2, "only prompt runs may create");
                        assert_eq!(
                            command.get("name").and_then(Value::as_str),
                            Some("marmot-daemon-contract")
                        );
                        assert!(command.pointer("/config/name").is_none());
                        let requested_path = command.get("sessionPath").and_then(Value::as_str);
                        if actual_connection == 1 {
                            assert_eq!(requested_path, None);
                        } else {
                            assert_eq!(requested_path, session_file.to_str());
                        }
                        json!({
                            "activeSessionId": "active-session-1",
                            "sessionFile": session_file
                        })
                    }
                    "attach" => {
                        assert_eq!(
                            command.get("activeSessionId").and_then(Value::as_str),
                            Some("active-session-1")
                        );
                        let capabilities = command
                            .get("capabilities")
                            .and_then(Value::as_array)
                            .unwrap();
                        assert!(capabilities.iter().any(|value| value == "slim_attach"));
                        assert!(capabilities.iter().any(|value| value == "chunked_snapshot"));
                        json!({"activeSessionId": "active-session-1"})
                    }
                    "set_session_name" => {
                        assert_eq!(
                            command.get("name").and_then(Value::as_str),
                            Some("marmot-daemon-contract")
                        );
                        Value::Null
                    }
                    "prompt_and_wait" => {
                        if actual_connection == 4 {
                            write_daemon_message(
                                &mut writer,
                                json!({
                                    "type": "response",
                                    "id": id,
                                    "success": false,
                                    "error": "provider login expired"
                                }),
                            )
                            .await;
                            rejected_command_id = Some(id.to_owned());
                            continue;
                        }
                        assert!(actual_connection <= 2);
                        assert!(
                            command
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap()
                                .contains("Attached file `notes.txt` is available at")
                        );
                        let images = command.get("images").and_then(Value::as_array).unwrap();
                        assert_eq!(images.len(), 1);
                        assert_eq!(
                            images[0].get("mimeType").and_then(Value::as_str),
                            Some("image/png")
                        );
                        assert_eq!(images[0].get("data").and_then(Value::as_str), Some("AQID"));
                        write_daemon_message(
                            &mut writer,
                            json!({
                                "type": "session_event",
                                "event": {
                                    "type": "message_update",
                                    "assistantMessageEvent": {"type": "text_delta", "delta": "hello"}
                                }
                            }),
                        )
                        .await;
                        write_daemon_message(
                            &mut writer,
                            json!({
                                "type": "session_event",
                                "event": {
                                    "type": "message_update",
                                    "assistantMessageEvent": {"type": "text_delta", "delta": " world"}
                                }
                            }),
                        )
                        .await;
                        saw_prompt = true;
                        Value::Null
                    }
                    "get_last_assistant_text" => json!({"text": "hello world"}),
                    "set_model" => {
                        assert_eq!(actual_connection, 3);
                        write_daemon_message(
                            &mut writer,
                            json!({
                                "type": "response",
                                "id": id,
                                "command": command_type,
                                "success": false,
                                "error": "missing provider API key"
                            }),
                        )
                        .await;
                        rejected_command_id = Some(id.to_owned());
                        continue;
                    }
                    other => panic!("unexpected daemon command: {other}"),
                };
                write_daemon_message(
                    &mut writer,
                    json!({
                        "type": "response",
                        "id": id,
                        "command": command_type,
                        "success": true,
                        "data": data
                    }),
                )
                .await;
                successful_commands += 1;
                if command_type == "get_last_assistant_text" {
                    final_command_id = Some(id.to_owned());
                }
            }
            assert!(
                rejected_command_id.is_none(),
                "rejected daemon responses must be acknowledged"
            );

            if actual_connection <= 2 {
                assert!(saw_prompt);
            }
            assert!(successful_commands >= 2);
        }
    }

    async fn run_single_prompt_daemon(
        listener: UnixListener,
        session_file: PathBuf,
        expect_resume: bool,
    ) {
        let active_session_id = if expect_resume {
            "restart-resumed-session"
        } else {
            "restart-stable-session"
        };
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut writer) = stream.into_split();
            write_daemon_message(
                &mut writer,
                json!({
                    "type": "daemon_hello",
                    "appVersion": DAEMON_APP_VERSION,
                    "protocol": {
                        "name": DAEMON_PROTOCOL_NAME,
                        "version": DAEMON_PROTOCOL_VERSION
                    },
                    "schemaRevision": DAEMON_SCHEMA_REVISION
                }),
            )
            .await;
            let mut lines = BufReader::new(read_half).lines();
            let Some(first) = lines.next_line().await.unwrap() else {
                continue;
            };
            let mut next = Some(first);
            let mut saw_session_command = false;
            let mut final_command_id = None;
            while let Some(line) = match next.take() {
                Some(line) => Some(line),
                None => lines.next_line().await.unwrap(),
            } {
                let envelope: Value = serde_json::from_str(&line).unwrap();
                let id = envelope.get("id").and_then(Value::as_str).unwrap();
                let command = envelope.get("command").unwrap();
                let command_type = command.get("type").and_then(Value::as_str).unwrap();
                if command_type == "ack_result" {
                    if final_command_id.as_deref()
                        == command.get("commandId").and_then(Value::as_str)
                    {
                        assert!(saw_session_command);
                        return;
                    }
                    continue;
                }
                let data = match command_type {
                    "create" => {
                        saw_session_command = true;
                        let requested_path = command.get("sessionPath").and_then(Value::as_str);
                        if expect_resume {
                            assert_eq!(requested_path, session_file.to_str());
                        } else {
                            assert_eq!(requested_path, None);
                        }
                        json!({
                            "activeSessionId": active_session_id,
                            "sessionFile": session_file
                        })
                    }
                    "attach" => {
                        assert!(saw_session_command, "create must precede attach");
                        assert_eq!(
                            command.get("activeSessionId").and_then(Value::as_str),
                            Some(active_session_id)
                        );
                        saw_session_command = true;
                        json!({"activeSessionId": active_session_id})
                    }
                    "set_session_name" | "prompt_and_wait" => Value::Null,
                    "get_last_assistant_text" => {
                        final_command_id = Some(id.to_owned());
                        json!({"text": "restart recovered"})
                    }
                    other => panic!("unexpected restart daemon command: {other}"),
                };
                write_daemon_message(
                    &mut writer,
                    json!({
                        "type": "response",
                        "id": id,
                        "command": command_type,
                        "success": true,
                        "data": data
                    }),
                )
                .await;
            }
        }
    }

    async fn run_timeout_daemon(
        listener: UnixListener,
        abort_seen: tokio::sync::oneshot::Sender<()>,
    ) {
        let mut abort_seen = Some(abort_seen);
        for connection in 1..=3 {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut writer) = stream.into_split();
            write_daemon_message(
                &mut writer,
                json!({
                    "type": "daemon_hello",
                    "appVersion": DAEMON_APP_VERSION,
                    "protocol": {
                        "name": DAEMON_PROTOCOL_NAME,
                        "version": DAEMON_PROTOCOL_VERSION
                    },
                    "schemaRevision": DAEMON_SCHEMA_REVISION
                }),
            )
            .await;
            let mut lines = BufReader::new(read_half).lines();
            if connection == 1 {
                assert!(lines.next_line().await.unwrap().is_none());
                continue;
            }
            while let Some(line) = lines.next_line().await.unwrap() {
                let envelope: Value = serde_json::from_str(&line).unwrap();
                let id = envelope.get("id").and_then(Value::as_str).unwrap();
                let command = envelope.get("command").unwrap();
                let command_type = command.get("type").and_then(Value::as_str).unwrap();
                if command_type == "ack_result" {
                    continue;
                }
                if connection == 2 && command_type == "prompt_and_wait" {
                    continue;
                }
                let data = match (connection, command_type) {
                    (2, "create") => json!({"activeSessionId": "timed-session"}),
                    (2, "attach" | "set_session_name") => Value::Null,
                    (3, "abort") => {
                        assert_eq!(
                            command.get("activeSessionId").and_then(Value::as_str),
                            Some("timed-session")
                        );
                        abort_seen.take().unwrap().send(()).unwrap();
                        Value::Null
                    }
                    other => panic!("unexpected timeout daemon command: {other:?}"),
                };
                write_daemon_message(
                    &mut writer,
                    json!({
                        "type": "response",
                        "id": id,
                        "command": command_type,
                        "success": true,
                        "data": data
                    }),
                )
                .await;
                if connection == 3 {
                    return;
                }
            }
        }
    }

    #[test]
    fn model_command_requires_provider_and_model() {
        assert_eq!(parse_model_command("/model"), ModelCommand::List);
        assert_eq!(
            parse_model_command("/model anthropic/claude-sonnet-4"),
            ModelCommand::Set {
                provider: "anthropic".to_owned(),
                model_id: "claude-sonnet-4".to_owned(),
            }
        );
        assert_eq!(parse_model_command("/model claude"), ModelCommand::Invalid);
    }

    #[tokio::test]
    async fn timed_out_prompt_is_aborted_in_the_resident_daemon() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("prime-agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (abort_tx, abort_rx) = tokio::sync::oneshot::channel();
        let daemon_task = tokio::spawn(run_timeout_daemon(listener, abort_tx));
        let backend = PrimeBackend::new("unused".to_owned(), socket);
        let mut invocation = test_invocation(temp.path(), None, "hang");
        invocation.timeout = Duration::from_millis(100);
        invocation.idle_timeout = Duration::from_secs(2);
        let (tx, _rx) = mpsc::channel(4);

        let failure = backend.run(invocation, tx).await.unwrap_err();
        assert!(matches!(failure.error, HarnessError::BackendTimedOut));
        timeout(Duration::from_secs(1), abort_rx)
            .await
            .expect("timeout cleanup did not send abort")
            .unwrap();
        daemon_task.await.unwrap();
    }

    #[test]
    fn streaming_event_extracts_only_assistant_text_deltas() {
        let delta = json!({
            "type": "session_event",
            "event": {
                "type": "message_update",
                "assistantMessageEvent": {"type": "text_delta", "delta": "hello"}
            }
        });
        assert_eq!(assistant_text_delta(&delta), Some("hello"));

        let thinking = json!({
            "type": "session_event",
            "event": {
                "type": "message_update",
                "assistantMessageEvent": {"type": "thinking_delta", "delta": "secret"}
            }
        });
        assert_eq!(assistant_text_delta(&thinking), None);
    }

    #[test]
    fn model_list_formats_stable_selectors() {
        let data = json!({"models": [{
            "provider": "anthropic",
            "id": "claude-sonnet-4",
            "name": "Claude Sonnet"
        }]});
        assert_eq!(
            format_models(&data),
            "Available models:\nanthropic/claude-sonnet-4 — Claude Sonnet"
        );
    }

    #[test]
    fn model_control_replies_are_bounded_on_utf8_boundaries() {
        let data = json!({"models": [{
            "provider": "provider",
            "id": "model",
            "name": "é".repeat(CONTROL_REPLY_MAX_BYTES)
        }]});
        let reply = bounded_control_reply(format_models(&data));
        assert!(reply.len() <= CONTROL_REPLY_MAX_BYTES);
        assert!(reply.ends_with(CONTROL_REPLY_TRUNCATED_SUFFIX));
        assert!(std::str::from_utf8(reply.as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn oversized_image_is_rejected_before_base64_encoding() {
        let root = tempfile::tempdir().unwrap();
        let image = root.path().join("oversized.png");
        let file = tokio::fs::File::create(&image).await.unwrap();
        file.set_len(DAEMON_MAX_FRAME_BYTES as u64).await.unwrap();
        let mut invocation = test_invocation(root.path(), None, "inspect image");
        invocation.attachments = vec![marmot_terminal_harness::InvocationAttachment {
            path: image,
            media_type: "image/png".to_owned(),
            file_name: "oversized.png".to_owned(),
        }];

        assert!(matches!(
            prompt_content(&invocation).await,
            Err(HarnessError::BackendStream)
        ));
    }

    #[tokio::test]
    async fn backend_speaks_daemon_protocol_reuses_session_and_forwards_attachments() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("prime.sock");
        let session_file = root.path().join("prime-session.jsonl");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(run_fake_daemon(listener, session_file.clone()));
        let backend = PrimeBackend::new("unused-prime-agent".to_owned(), socket);

        let image = root.path().join("image.png");
        let notes = root.path().join("notes.txt");
        tokio::fs::write(&image, [1_u8, 2, 3]).await.unwrap();
        tokio::fs::write(&notes, b"notes").await.unwrap();
        let mut first = test_invocation(root.path(), None, "inspect both attachments");
        first.attachments = vec![
            marmot_terminal_harness::InvocationAttachment {
                path: image,
                media_type: "image/png".to_owned(),
                file_name: "image.png".to_owned(),
            },
            marmot_terminal_harness::InvocationAttachment {
                path: notes,
                media_type: "text/plain".to_owned(),
                file_name: "notes.txt".to_owned(),
            },
        ];
        let (tx, mut rx) = mpsc::channel(8);
        let first_outcome = backend.run(first, tx).await.unwrap();
        assert_eq!(
            first_outcome.observed_session.as_deref(),
            Some("active-session-1")
        );
        assert_eq!(
            first_outcome.observed_session_path.as_deref(),
            Some(session_file.as_path())
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Preview("hello".to_owned()))
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Preview(" world".to_owned()))
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("hello world".to_owned()))
        );

        let mut second = test_invocation(
            root.path(),
            first_outcome.observed_session.clone(),
            "inspect both attachments",
        );
        second.session_path = first_outcome.observed_session_path.clone();
        second.attachments = vec![
            marmot_terminal_harness::InvocationAttachment {
                path: root.path().join("image.png"),
                media_type: "image/png".to_owned(),
                file_name: "image.png".to_owned(),
            },
            marmot_terminal_harness::InvocationAttachment {
                path: root.path().join("notes.txt"),
                media_type: "text/plain".to_owned(),
                file_name: "notes.txt".to_owned(),
            },
        ];
        let (tx, mut rx) = mpsc::channel(8);
        let second_outcome = backend.run(second, tx).await.unwrap();
        assert_eq!(
            second_outcome.observed_session.as_deref(),
            Some("active-session-1")
        );
        assert_eq!(
            second_outcome.observed_session_path.as_deref(),
            Some(session_file.as_path())
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Preview("hello".to_owned()))
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Preview(" world".to_owned()))
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("hello world".to_owned()))
        );

        let model = test_invocation(
            root.path(),
            second_outcome.observed_session,
            "/model anthropic/claude-sonnet-4",
        );
        let (tx, mut rx) = mpsc::channel(4);
        backend.run(model, tx).await.unwrap();
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("missing provider API key".to_owned()))
        );

        let prompt_with_expired_auth = test_invocation(
            root.path(),
            Some("active-session-1".to_owned()),
            "continue after login expired",
        );
        let (tx, mut rx) = mpsc::channel(4);
        backend.run(prompt_with_expired_auth, tx).await.unwrap();
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("provider login expired".to_owned()))
        );

        server.await.unwrap();
    }

    #[tokio::test]
    async fn backend_resumes_persisted_session_after_daemon_restart() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("prime-restart.sock");
        let session_file = root.path().join("prime-restart-session.jsonl");
        let backend = PrimeBackend::new("unused-prime-agent".to_owned(), socket.clone());

        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(run_single_prompt_daemon(
            listener,
            session_file.clone(),
            false,
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let first = backend
            .run(test_invocation(root.path(), None, "first"), tx)
            .await
            .unwrap();
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("restart recovered".to_owned()))
        );
        assert_eq!(
            first.observed_session.as_deref(),
            Some("restart-stable-session")
        );
        assert_eq!(
            first.observed_session_path.as_deref(),
            Some(session_file.as_path())
        );
        server.await.unwrap();

        std::fs::remove_file(&socket).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(run_single_prompt_daemon(
            listener,
            session_file.clone(),
            true,
        ));
        let (tx, mut rx) = mpsc::channel(4);
        let mut resumed = test_invocation(root.path(), first.observed_session.clone(), "second");
        resumed.session_path = first.observed_session_path.clone();
        let second = backend.run(resumed, tx).await.unwrap();
        assert_eq!(
            second.observed_session.as_deref(),
            Some("restart-resumed-session")
        );
        assert_eq!(
            second.observed_session_path.as_deref(),
            Some(session_file.as_path())
        );
        assert_eq!(
            rx.recv().await,
            Some(RunnerEvent::Text("restart recovered".to_owned()))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ensure_daemon_propagates_unpinned_app_version() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("prime.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (_, mut writer) = stream.into_split();
            write_daemon_message(
                &mut writer,
                json!({
                    "type": "daemon_hello",
                    "appVersion": "0.7.1",
                    "protocol": {
                        "name": DAEMON_PROTOCOL_NAME,
                        "version": DAEMON_PROTOCOL_VERSION
                    },
                    "schemaRevision": DAEMON_SCHEMA_REVISION
                }),
            )
            .await;
        });

        let backend = PrimeBackend::new("unused".to_owned(), socket);
        let result = backend.ensure_daemon(temp.path()).await;
        assert!(matches!(result, Err(HarnessError::BackendProtocolMismatch)));
        server.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires WN_PRIME_AGENT_LIVE_SMOKE=1 and a running authenticated Prime Agent daemon"]
    async fn live_daemon_smoke() {
        assert_eq!(
            std::env::var("WN_PRIME_AGENT_LIVE_SMOKE").as_deref(),
            Ok("1"),
            "set WN_PRIME_AGENT_LIVE_SMOKE=1 to run this test"
        );
        let socket = PathBuf::from(
            std::env::var("WN_PRIME_AGENT_DAEMON_SOCKET")
                .expect("WN_PRIME_AGENT_DAEMON_SOCKET must point to a running daemon"),
        );
        let cwd = std::env::var_os("WN_PRIME_AGENT_LIVE_SMOKE_CWD")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::current_dir().expect("current directory"));
        let backend = PrimeBackend::new(
            std::env::var("WN_PRIME_AGENT_BIN").unwrap_or_else(|_| "prime-agent".to_owned()),
            socket,
        );
        let invocation = Invocation {
            timeout: Duration::from_secs(300),
            idle_timeout: Duration::from_secs(120),
            cwd,
            session_id: None,
            session_path: None,
            session_name: format!("marmot-live-smoke-{}", std::process::id()),
            prompt: "Reply with exactly PRIME_AGENT_CONNECTOR_OK and nothing else.".to_owned(),
            attachments: Vec::new(),
        };
        let (tx, mut rx) = mpsc::channel(16);
        let outcome = backend.run(invocation, tx).await.unwrap();

        let mut final_text = None;
        while let Some(event) = rx.recv().await {
            if let RunnerEvent::Text(text) = event {
                final_text = Some(text);
            }
        }
        assert_eq!(
            final_text.as_deref().map(str::trim),
            Some("PRIME_AGENT_CONNECTOR_OK")
        );
        assert!(
            outcome.observed_session_path.is_some(),
            "live daemon create response must expose sessionFile"
        );
    }
}
