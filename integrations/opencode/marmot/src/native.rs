//! Opt-in native OpenCode transport. Each turn starts a private `opencode serve`
//! and drives its HTTP API, so follow-ups can join the running turn.
use marmot_terminal_harness::{
    Attachment, HarnessError, Invocation, MAX_TURN_TEXT_BYTES, Outcome, RunFailure, RunnerEvent,
    SteerOutcome, current_group_id,
    process::{EnvironmentChange, OwnedProcess},
};
use reqwest::{Client, Method, Url};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    future::{Future, pending},
    path::Path,
    pin::Pin,
    sync::Mutex,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    sync::{mpsc, oneshot},
    time::{Instant, sleep, timeout, timeout_at},
};

/// OpenCode releases whose server API this transport was verified against:
/// a `noReply` user message joins the running loop, and the blocking prompt
/// call returns the loop's final assistant message.
const TESTED_VERSIONS: ((u64, u64, u64), (u64, u64, u64)) = ((1, 18, 32), (1, 20, 0));
/// OpenCode can take over ten seconds to start on a loaded host.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const FOLLOW_UP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const CONFIRM_INTERVAL: Duration = Duration::from_millis(100);
const METADATA_BYTES: usize = 4 * 1024 * 1024;
const USERNAME: &str = "opencode";
const UNANSWERED_NOTICE: &str = "A follow-up reached OpenCode as this turn finished, so it has no answer yet. Send another message to continue.";

pub(crate) struct Native {
    groups: Mutex<HashMap<String, mpsc::Sender<FollowUp>>>,
    /// Readback of a user message can carry every admitted attachment as a data URL.
    response_limit: usize,
}

struct FollowUp {
    text: String,
    files: Vec<String>,
    lease: Option<Box<dyn Send + Sync>>,
    reply: oneshot::Sender<SteerOutcome>,
}

/// Follow-ups still buffered when a turn ends were never submitted, so they
/// are released to run as the next turn, also when the turn is cancelled.
struct FollowUps(mpsc::Receiver<FollowUp>);

struct PendingFollowUp<'a> {
    request: Pin<Box<dyn Future<Output = SteerOutcome> + Send + 'a>>,
    reply: Option<oneshot::Sender<SteerOutcome>>,
    started: bool,
}

impl Drop for PendingFollowUp<'_> {
    fn drop(&mut self) {
        if !self.started
            && let Some(reply) = self.reply.take()
        {
            let _ = reply.send(SteerOutcome::Unavailable);
        }
    }
}

impl Drop for FollowUps {
    fn drop(&mut self) {
        self.0.close();
        while let Ok(follow_up) = self.0.try_recv() {
            let _ = follow_up.reply.send(SteerOutcome::Unavailable);
        }
    }
}

/// Removes this turn's follow-up channel unless a newer turn replaced it.
struct Registration<'a> {
    native: &'a Native,
    group: Option<String>,
    sender: mpsc::Sender<FollowUp>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            let mut groups = self.native.groups.lock().unwrap();
            if groups
                .get(group)
                .is_some_and(|sender| sender.same_channel(&self.sender))
            {
                groups.remove(group);
            }
        }
    }
}

impl Native {
    pub(crate) fn new(max_attachment_bytes: u64) -> Self {
        let encoded = usize::try_from(max_attachment_bytes.div_ceil(3).saturating_mul(4))
            .unwrap_or(usize::MAX);
        Self {
            groups: Mutex::default(),
            response_limit: METADATA_BYTES.saturating_add(encoded),
        }
    }

    pub(crate) fn active(&self, group: &str) -> bool {
        self.groups
            .lock()
            .unwrap()
            .get(group)
            .is_some_and(|sender| !sender.is_closed())
    }

    pub(crate) async fn steer(
        &self,
        group: &str,
        text: &str,
        files: Vec<String>,
        lease: Option<Box<dyn Send + Sync>>,
    ) -> SteerOutcome {
        let sender = self.groups.lock().unwrap().get(group).cloned();
        let Some(sender) = sender else {
            return SteerOutcome::Unavailable;
        };
        let (reply, outcome) = oneshot::channel();
        let follow_up = FollowUp {
            text: text.to_owned(),
            files,
            lease,
            reply,
        };
        if sender.send(follow_up).await.is_err() {
            return SteerOutcome::Unavailable;
        }
        // The turn answers every follow-up it receives. A dropped reply means
        // the turn was cancelled while this one may have been in flight.
        outcome.await.unwrap_or(SteerOutcome::Uncertain)
    }

    fn register(&self, group: Option<String>, sender: mpsc::Sender<FollowUp>) -> Registration<'_> {
        if let Some(group) = &group {
            self.groups
                .lock()
                .unwrap()
                .insert(group.clone(), sender.clone());
        }
        Registration {
            native: self,
            group,
            sender,
        }
    }

    pub(crate) async fn run(
        &self,
        bin: &str,
        invocation: Invocation,
        attachments: &[Attachment],
        environment: Vec<EnvironmentChange>,
        approve_once: bool,
        tx: mpsc::Sender<RunnerEvent>,
    ) -> Result<Outcome, RunFailure> {
        let started = std::time::Instant::now();
        let deadline = Instant::now() + invocation.timeout;
        let mut session = None;
        let result = timeout_at(
            deadline,
            self.turn(
                bin,
                invocation,
                attachments,
                environment,
                approve_once,
                &tx,
                &mut session,
            ),
        )
        .await
        .unwrap_or(Err(HarnessError::BackendTimedOut));
        match result {
            Ok(error_summary) => Ok(Outcome {
                exit_code: Some(if error_summary.is_some() { 1 } else { 0 }),
                observed_session: session,
                error_summary,
                no_side_effects_proven: false,
                stderr: String::new(),
                elapsed_ms: started.elapsed().as_millis(),
            }),
            Err(error) => Err(RunFailure {
                error,
                observed_session: session,
            }),
        }
    }

    /// Runs one turn and returns the model's error summary, if any.
    #[allow(clippy::too_many_arguments)]
    async fn turn(
        &self,
        bin: &str,
        invocation: Invocation,
        attachments: &[Attachment],
        environment: Vec<EnvironmentChange>,
        approve_once: bool,
        tx: &mpsc::Sender<RunnerEvent>,
        observed_session: &mut Option<String>,
    ) -> Result<Option<String>, HarnessError> {
        let files = super::opencode::prepare_attachments(attachments)?;
        let server = Server::start(bin, &invocation.cwd, environment, self.response_limit).await?;
        let session = match invocation.session_id.filter(|id| !id.is_empty()) {
            Some(id) => {
                server.call(Method::GET, &["session", &id], None).await?;
                id
            }
            None => server
                .call(Method::POST, &["session"], Some(json!({})))
                .await?["id"]
                .as_str()
                .ok_or(HarnessError::BackendStream)?
                .to_owned(),
        };
        *observed_session = Some(session.clone());
        let baseline = message_id(server.message_page(&session, None).await?.0.as_ref());

        let prompt = parts(&invocation.prompt, &files)?;
        let message_path = ["session", session.as_str(), "message"];
        let first = server.request(
            Method::POST,
            &message_path,
            &[],
            Some(json!({ "parts": prompt })),
            None,
        );
        tokio::pin!(first);
        // Follow-ups must not be stored ahead of the prompt, so steering opens
        // only after the prompt is visible in the session. A turn that finishes
        // first keeps its answer and is never steered.
        let mut completed = None;
        let confirm_deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut first_id = None;
        while first_id.is_none() && !matches!(completed, Some(Ok(_))) {
            if let Some(message) = server
                .first_user_since(&session, baseline.as_deref())
                .await?
            {
                match stored(&message, &invocation.prompt, &prompt) {
                    Stored::Complete => first_id = message_id(Some(&message)),
                    Stored::ReadFailed => return Err(HarnessError::AttachmentNotProcessed),
                    Stored::Pending => {}
                }
            }
            if first_id.is_some() {
                break;
            }
            if let Some(Err(error)) = completed.take() {
                return Err(error);
            }
            if Instant::now() > confirm_deadline {
                return Err(HarnessError::BackendStream);
            }
            tokio::select! {
                result = &mut first => completed = Some(result),
                () = sleep(CONFIRM_INTERVAL) => {}
            }
        }

        let (sender, receiver) = mpsc::channel(4);
        let mut follow_ups = FollowUps(receiver);
        let registration = first_id
            .is_some()
            .then(|| self.register(current_group_id(), sender));
        // Staged follow-up files must outlive the turn that reads them.
        let mut leases = Vec::new();
        let mut answered = HashSet::new();
        let mut poll = tokio::time::interval(POLL_INTERVAL);
        let mut in_flight: Option<PendingFollowUp<'_>> = None;
        let answer = loop {
            if let Some(result) = completed.take() {
                break result;
            }
            let accepting_follow_up = in_flight.is_none();
            tokio::select! {
                biased;
                result = &mut first => break result,
                result = async {
                    match in_flight.as_mut() {
                        Some(follow_up) => {
                            follow_up.started = true;
                            follow_up.request.as_mut().await
                        }
                        None => pending().await,
                    }
                } => {
                    if let Some(reply) = in_flight.take().and_then(|mut follow_up| follow_up.reply.take()) {
                        let _ = reply.send(result);
                    }
                }
                Some(follow_up) = follow_ups.0.recv(), if accepting_follow_up => {
                    let FollowUp { text, files, lease, reply } = follow_up;
                    leases.extend(lease);
                    let server = &server;
                    let session = &session;
                    in_flight = Some(PendingFollowUp {
                        request: Box::pin(async move { server.follow_up(session, &text, &files).await }),
                        reply: Some(reply),
                        started: false,
                    });
                }
                _ = poll.tick() => {
                    server.answer_requests(approve_once, &mut answered).await?;
                }
            }
        };
        // A polled POST may have been accepted. Its reply is uncertain.
        // Unstarted follow-ups still return unavailable.
        drop(in_flight);
        drop(follow_ups);
        drop(registration);
        let answer = answer?;

        let (texts, unanswered) = match &first_id {
            Some(first_id) => match server.turn_text(&session, first_id).await {
                Ok(text) => text,
                Err(HarnessError::OutputLimitExceeded) => {
                    return Err(HarnessError::OutputLimitExceeded);
                }
                Err(_) => (completed_text(&answer), false),
            },
            None => (completed_text(&answer), false),
        };
        for text in texts
            .into_iter()
            .chain(unanswered.then(|| UNANSWERED_NOTICE.to_owned()))
        {
            tx.send(RunnerEvent::Text(text))
                .await
                .map_err(|_| HarnessError::BackendStream)?;
        }
        drop(leases);
        Ok(answer["info"]
            .get("error")
            .filter(|error| !error.is_null())
            .map(error_summary))
    }
}

struct Server {
    process: OwnedProcess,
    client: Client,
    base: Url,
    password: String,
    response_limit: usize,
}

impl Server {
    async fn start(
        bin: &str,
        cwd: &Path,
        mut environment: Vec<EnvironmentChange>,
        response_limit: usize,
    ) -> Result<Self, HarnessError> {
        let password = random_password()?;
        environment.extend([
            EnvironmentChange::Set {
                name: "OPENCODE_SERVER_USERNAME",
                value: USERNAME.into(),
            },
            EnvironmentChange::Set {
                name: "OPENCODE_SERVER_PASSWORD",
                value: password.clone(),
            },
        ]);
        let mut process = OwnedProcess::spawn(
            bin,
            &["serve", "--hostname", "127.0.0.1", "--port", "0"],
            cwd,
            environment,
        )
        .map_err(|_| HarnessError::BackendSpawn)?;
        let stdout = process.take_stdout().ok_or(HarnessError::BackendSpawn)?;
        let mut stdout = BufReader::new(stdout);
        let port = timeout(STARTUP_TIMEOUT, async {
            loop {
                let mut line = String::new();
                match (&mut stdout).take(4096).read_line(&mut line).await {
                    Ok(0) | Err(_) => return None,
                    Ok(_) => {
                        if let Some(port) = listening_port(&line) {
                            return Some(port);
                        }
                    }
                }
            }
        })
        .await
        .ok()
        .flatten()
        .ok_or(HarnessError::BackendSpawn)?;
        // Keep draining so server logging can never block on a full pipe.
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await;
        });
        let server = Self {
            process,
            client: Client::builder()
                .no_proxy()
                .build()
                .map_err(|_| HarnessError::BackendSpawn)?,
            base: Url::parse(&format!("http://127.0.0.1:{port}/"))
                .map_err(|_| HarnessError::BackendSpawn)?,
            password,
            response_limit,
        };
        let health = server
            .call(Method::GET, &["global", "health"], None)
            .await?;
        let version = health["version"].as_str().unwrap_or_default();
        if !tested_version(version) {
            return Err(HarnessError::Config(format!(
                "native OpenCode transport supports OpenCode 1.18.32 through 1.19.x, found {}",
                if version.is_empty() {
                    "unknown"
                } else {
                    version
                }
            )));
        }
        Ok(server)
    }

    async fn call(
        &self,
        method: Method,
        path: &[&str],
        body: Option<Value>,
    ) -> Result<Value, HarnessError> {
        self.request(method, path, &[], body, Some(REQUEST_TIMEOUT))
            .await
    }

    /// One attempt, never retried: a lost response may still have committed.
    async fn request(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, String)],
        body: Option<Value>,
        limit: Option<Duration>,
    ) -> Result<Value, HarnessError> {
        self.request_with_cursor(method, path, query, body, limit)
            .await
            .map(|(body, _)| body)
    }

    async fn request_with_cursor(
        &self,
        method: Method,
        path: &[&str],
        query: &[(&str, String)],
        body: Option<Value>,
        limit: Option<Duration>,
    ) -> Result<(Value, Option<String>), HarnessError> {
        // The port is only trusted while the server that bound it is alive.
        if self.process.has_exited() {
            return Err(HarnessError::BackendStream);
        }
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| HarnessError::BackendStream)?
            .pop_if_empty()
            .extend(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let mut request = self
            .client
            .request(method, url)
            .basic_auth(USERNAME, Some(&self.password));
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(limit) = limit {
            request = request.timeout(limit);
        }
        let mut response = request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| HarnessError::BackendStream)?;
        let cursor = response
            .headers()
            .get("x-next-cursor")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| HarnessError::BackendStream)?
        {
            if bytes.len() + chunk.len() > self.response_limit {
                return Err(HarnessError::OutputLimitExceeded);
            }
            bytes.extend_from_slice(&chunk);
        }
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).map_err(|_| HarnessError::BackendStream)?
        };
        Ok((body, cursor))
    }

    /// The response budget covers one user message with a full attachment batch.
    /// Follow the server's opaque cursor without using its response's host URL.
    async fn message_page(
        &self,
        session: &str,
        before: Option<&str>,
    ) -> Result<(Option<Value>, Option<String>), HarnessError> {
        let mut query = vec![("limit", "1".to_owned())];
        if let Some(before) = before {
            query.push(("before", before.to_owned()));
        }
        let (body, next) = self
            .request_with_cursor(
                Method::GET,
                &["session", session, "message"],
                &query,
                None,
                Some(REQUEST_TIMEOUT),
            )
            .await?;
        match body {
            Value::Array(mut messages) if messages.len() <= 1 => Ok((messages.pop(), next)),
            _ => Err(HarnessError::BackendStream),
        }
    }

    /// Find the oldest user prompt after the previous turn's last message.
    async fn first_user_since(
        &self,
        session: &str,
        baseline: Option<&str>,
    ) -> Result<Option<Value>, HarnessError> {
        let mut candidate = None;
        let mut cursor = None;
        for _ in 0..64 {
            let (Some(mut message), next) = self.message_page(session, cursor.as_deref()).await?
            else {
                break;
            };
            if message["info"]["id"].as_str() == baseline && baseline.is_some() {
                break;
            }
            if message["info"]["role"] == "user" {
                if let Some(parts) = message["parts"].as_array_mut() {
                    for part in parts {
                        if part["type"] == "file"
                            && part["url"]
                                .as_str()
                                .is_some_and(|url| url.starts_with("data:"))
                        {
                            part["url"] = Value::String("data:".to_owned());
                        }
                    }
                }
                candidate = Some(message);
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        Ok(candidate)
    }

    /// Read backward one message at a time, retaining only bounded reply text.
    async fn turn_text(
        &self,
        session: &str,
        first: &str,
    ) -> Result<(Vec<String>, bool), HarnessError> {
        let mut history = TurnHistory::default();
        let mut cursor = None;
        for _ in 0..1024 {
            let (Some(message), next) = self.message_page(session, cursor.as_deref()).await? else {
                break;
            };
            let is_first = message["info"]["id"].as_str() == Some(first);
            history.record(&message, is_first)?;
            if is_first {
                return Ok(history.finish());
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
        Err(HarnessError::BackendStream)
    }

    /// Adds a user message to the running loop without starting another one.
    async fn follow_up(&self, session: &str, text: &str, files: &[String]) -> SteerOutcome {
        let Ok(expected) = parts(text, files) else {
            return SteerOutcome::Unavailable;
        };
        let result = self
            .request(
                Method::POST,
                &["session", session, "message"],
                &[],
                Some(json!({ "parts": expected, "noReply": true })),
                Some(FOLLOW_UP_TIMEOUT),
            )
            .await;
        match result {
            Ok(message) if stored(&message, text, &expected) == Stored::Complete => {
                SteerOutcome::Accepted
            }
            // Never resend: the message may be stored even without a usable reply.
            _ => SteerOutcome::Uncertain,
        }
    }

    /// Answers this session's permission and question requests once each.
    async fn answer_requests(
        &self,
        approve_once: bool,
        answered: &mut HashSet<String>,
    ) -> Result<(), HarnessError> {
        for (kind, reply_path, body) in [
            ("permission", "reply", json!({ "reply": "once" })),
            // There is no question UI. Rejecting lets the model ask in its reply.
            ("question", "reject", json!({})),
        ] {
            let requests = self.call(Method::GET, &[kind], None).await?;
            for request in requests.as_array().into_iter().flatten() {
                let Some(id) = request["id"].as_str() else {
                    continue;
                };
                // The server is private to this turn, so every request is
                // ours, including those from subagent sessions.
                if !answered.insert(format!("{kind}:{id}")) {
                    continue;
                }
                if kind == "permission" && !approve_once {
                    return Err(HarnessError::Config(
                        "OpenCode asked for a permission that needs interactive approval".into(),
                    ));
                }
                self.call(Method::POST, &[kind, id, reply_path], Some(body.clone()))
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Stored {
    Complete,
    Pending,
    ReadFailed,
}

/// Whether a user message holds the exact text and every requested file.
/// The text and file parts are written separately, so partial readback is pending.
fn stored(message: &Value, text: &str, expected: &[Value]) -> Stored {
    let actual = message["parts"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if actual.iter().any(|part| {
        part["synthetic"] == true
            && part["text"]
                .as_str()
                .is_some_and(|text| text.starts_with("Read tool failed to read "))
    }) {
        return Stored::ReadFailed;
    }
    let has_text = actual
        .iter()
        .any(|part| part["type"] == "text" && part["synthetic"] != true && part["text"] == text);
    // Read keeps a text file as a file part, or replaces media with a data URL.
    let has_files = expected.iter().skip(1).all(|file| {
        actual.iter().any(|part| {
            part["type"] == "file"
                && part["filename"] == file["filename"]
                && (part["url"] == file["url"]
                    || part["url"]
                        .as_str()
                        .is_some_and(|url| url.starts_with("data:")))
        })
    });
    if message["info"]["role"] == "user" && has_text && has_files {
        Stored::Complete
    } else {
        Stored::Pending
    }
}

fn parts(text: &str, files: &[String]) -> Result<Vec<Value>, HarnessError> {
    let mut parts = vec![json!({ "type": "text", "text": text })];
    for file in files {
        let path = Path::new(file);
        let url = Url::from_file_path(path).map_err(|_| HarnessError::AttachmentInvalid)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(HarnessError::AttachmentInvalid)?;
        parts.push(
            json!({ "type": "file", "mime": "text/plain", "url": url.as_str(), "filename": name }),
        );
    }
    Ok(parts)
}

fn message_id(message: Option<&Value>) -> Option<String> {
    message?["info"]["id"].as_str().map(str::to_owned)
}

/// Collect a turn from newest to oldest while dropping each page's media and metadata.
#[derive(Default)]
struct TurnHistory {
    replies: Vec<Vec<String>>,
    bytes: usize,
    unanswered: Option<bool>,
}

impl TurnHistory {
    fn record(&mut self, message: &Value, is_first: bool) -> Result<(), HarnessError> {
        match message["info"]["role"].as_str() {
            Some("user") => {
                self.unanswered.get_or_insert(!is_first);
            }
            Some("assistant") => {
                self.unanswered.get_or_insert(false);
                let texts = completed_text(message);
                self.bytes = self
                    .bytes
                    .saturating_add(texts.iter().map(String::len).sum());
                if self.bytes > MAX_TURN_TEXT_BYTES {
                    return Err(HarnessError::OutputLimitExceeded);
                }
                self.replies.push(texts);
            }
            _ => {}
        }
        Ok(())
    }

    fn finish(self) -> (Vec<String>, bool) {
        (
            self.replies.into_iter().rev().flatten().collect(),
            self.unanswered.unwrap_or(false),
        )
    }
}

fn completed_text(message: &Value) -> Vec<String> {
    message["parts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|part| {
            part["type"] == "text" && part["synthetic"] != true && !part["time"]["end"].is_null()
        })
        .filter_map(|part| part["text"].as_str())
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Same shape as the CLI transport's error summary.
fn error_summary(error: &Value) -> String {
    let mut summary = error["name"].as_str().unwrap_or("error").to_owned();
    if let Some(status) = error["data"]["statusCode"].as_u64() {
        summary.push_str(&format!(" status={status}"));
    }
    summary
}

fn listening_port(line: &str) -> Option<u16> {
    let rest = line.split("listening on http://127.0.0.1:").nth(1)?;
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .map_or(rest, |end| &rest[..end]);
    digits.parse().ok().filter(|port| *port != 0)
}

fn tested_version(version: &str) -> bool {
    let mut numbers = version.split(['.', '-', '+']).map(str::parse::<u64>);
    let (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch))) =
        (numbers.next(), numbers.next(), numbers.next())
    else {
        return false;
    };
    let (low, high) = TESTED_VERSIONS;
    (low..high).contains(&(major, minor, patch))
}

/// Per-turn server password, so a stale or foreign listener cannot reuse it.
fn random_password() -> Result<String, HarnessError> {
    let mut bytes = [0_u8; 32];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, &mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, role: &str, parts: Value) -> Value {
        json!({ "info": { "id": id, "role": role }, "parts": parts })
    }

    fn text(value: &str) -> Value {
        json!({ "type": "text", "text": value, "time": { "start": 1, "end": 2 } })
    }

    #[test]
    fn turn_text_keeps_every_answer_and_flags_a_late_follow_up() {
        let first = message("m1", "user", json!([text("question")]));
        let early = message("m2", "assistant", json!([text("partial answer")]));
        let follow_up = message("m3", "user", json!([text("also this")]));
        let last = message(
            "m4",
            "assistant",
            json!([
                text("final answer"),
                { "type": "text", "text": "streaming", "time": { "start": 3 } },
                { "type": "text", "text": "hidden", "synthetic": true, "time": { "end": 4 } },
            ]),
        );
        let read = |messages: &[Value]| {
            let mut history = TurnHistory::default();
            for (index, message) in messages.iter().enumerate().rev() {
                history.record(message, index == 0).unwrap();
            }
            history.finish()
        };
        let (texts, unanswered) = read(&[first.clone(), early.clone(), follow_up.clone(), last]);
        assert_eq!(texts, ["partial answer", "final answer"]);
        assert!(!unanswered);
        let (texts, unanswered) = read(&[first.clone(), early, follow_up]);
        assert_eq!(texts, ["partial answer"]);
        assert!(unanswered);
        assert_eq!(read(&[first]), (vec![], false));
    }

    #[tokio::test]
    async fn history_pages_keep_earlier_text_when_multiple_media_batches_fill_the_budget() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let server = Server {
            process: OwnedProcess::spawn("sleep", &["30"], Path::new("."), vec![]).unwrap(),
            client: Client::builder().no_proxy().build().unwrap(),
            base: format!("http://{}", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
            password: "test".to_owned(),
            response_limit: 768,
        };
        let media = json!([{
            "type": "file",
            "url": format!("data:image/png;base64,{}", "x".repeat(512)),
        }]);
        let pages = [
            ("", "prev-1", message("late", "user", media.clone())),
            (
                "&before=prev-1",
                "prev-2",
                message("answer", "assistant", json!([text("kept")])),
            ),
            ("&before=prev-2", "", message("first", "user", media)),
        ];
        let replies = async {
            for (before, next, item) in pages {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut line = String::new();
                socket.read_line(&mut line).await.unwrap();
                assert_eq!(
                    line,
                    format!("GET /session/room/message?limit=1{before} HTTP/1.1\r\n")
                );
                loop {
                    line.clear();
                    assert_ne!(socket.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                let body = json!([item]).to_string();
                assert!(body.len() < server.response_limit);
                let cursor = if next.is_empty() {
                    String::new()
                } else {
                    format!("X-Next-Cursor: {next}\r\n")
                };
                socket.get_mut().write_all(format!(
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n{cursor}\r\n{body}",
                    body.len(),
                ).as_bytes()).await.unwrap();
            }
        };
        let (result, ()) = timeout(Duration::from_secs(5), async {
            tokio::join!(server.turn_text("room", "first"), replies)
        })
        .await
        .unwrap();
        assert_eq!(result.unwrap(), (vec!["kept".to_owned()], true));
    }

    #[test]
    fn stored_requires_exact_text_and_every_file() {
        let expected = parts("hi", &["/tmp/a.txt".into(), "/tmp/b.png".into()]).unwrap();
        let file_a = json!({ "type": "file", "filename": "a.txt", "url": "file:///tmp/a.txt" });
        let file_b =
            json!({ "type": "file", "filename": "b.png", "url": "data:image/png;base64,AA" });
        let user = |parts| message("m", "user", parts);
        assert_eq!(
            stored(&user(json!([text("hi"), file_a, file_b])), "hi", &expected),
            Stored::Complete
        );
        assert_eq!(
            stored(&user(json!([text("hi"), file_a])), "hi", &expected),
            Stored::Pending
        );
        assert_eq!(
            stored(&user(json!([text("hi!"), file_a, file_b])), "hi", &expected),
            Stored::Pending
        );
        assert_eq!(
            stored(
                &message("m", "assistant", json!([text("hi"), file_a, file_b])),
                "hi",
                &expected
            ),
            Stored::Pending
        );
        let failed = json!({ "type": "text", "synthetic": true, "text": "Read tool failed to read /tmp/b.png" });
        assert_eq!(
            stored(&user(json!([text("hi"), file_a, failed])), "hi", &expected),
            Stored::ReadFailed
        );
    }

    #[test]
    fn server_handshake_parsing_is_strict() {
        assert_eq!(
            listening_port("opencode server listening on http://127.0.0.1:43123\n"),
            Some(43123)
        );
        assert_eq!(listening_port("listening on http://0.0.0.0:4096"), None);
        assert_eq!(listening_port("listening on http://127.0.0.1:0"), None);
        assert!(tested_version("1.18.32"));
        assert!(tested_version("1.19.5"));
        assert!(!tested_version("1.18.31"));
        assert!(!tested_version("1.20.0"));
        assert!(!tested_version("dev"));
    }

    #[tokio::test]
    async fn follow_ups_are_group_scoped_and_end_with_their_turn() {
        let native = Native::new(1);
        let (first, mut first_rx) = mpsc::channel(4);
        let (second, _second_rx) = mpsc::channel(4);
        let registration = native.register(Some("first".into()), first);
        let _other = native.register(Some("second".into()), second);
        assert!(native.active("first"));
        let (outcome, delivered) =
            tokio::join!(native.steer("first", "more", vec![], None), async {
                let follow_up = first_rx.recv().await.unwrap();
                assert_eq!(follow_up.text, "more");
                follow_up.reply.send(SteerOutcome::Accepted).unwrap();
            });
        let () = delivered;
        assert_eq!(outcome, SteerOutcome::Accepted);
        first_rx.close();
        assert!(!native.active("first"));
        assert_eq!(
            native.steer("first", "late", vec![], None).await,
            SteerOutcome::Unavailable
        );
        drop(registration);
        assert!(native.groups.lock().unwrap().get("first").is_none());
        assert!(native.active("second"));
    }

    #[tokio::test]
    async fn dropped_unstarted_follow_up_remains_available_to_queue() {
        let (reply, outcome) = oneshot::channel();
        drop(PendingFollowUp {
            request: Box::pin(pending()),
            reply: Some(reply),
            started: false,
        });
        assert_eq!(outcome.await.unwrap(), SteerOutcome::Unavailable);
    }

    #[tokio::test]
    async fn cancelled_turn_reports_an_in_flight_follow_up_as_uncertain() {
        let native = Native::new(1);
        let (sender, mut receiver) = mpsc::channel(4);
        let original = native.register(Some("room".into()), sender);
        let (outcome, ()) = tokio::join!(native.steer("room", "more", vec![], None), async {
            let follow_up = receiver.recv().await.unwrap();
            drop(follow_up);
        });
        assert_eq!(outcome, SteerOutcome::Uncertain);
        let (successor, _successor_rx) = mpsc::channel(4);
        let _next = native.register(Some("room".into()), successor);
        drop(original);
        assert!(native.active("room"));
    }
}
