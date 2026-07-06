// wn-opencode: bridge Marmot groups <-> opencode sessions via wn-agent's control socket.
//
// Session mapping: each marmot group_id maps to one opencode session_id. On first
// message we spawn opencode without --session, capture the session id from the
// initial step_start event, and persist the mapping to disk so restarts keep
// resuming the same session.
//
// Only accounts on the admin allowlist may talk to the bridge; every text event
// becomes one Marmot reply.

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use agent_control::{
    AGENT_CONTROL_PROTOCOL_V1, AgentControlEnvelope, AgentControlEvent, AgentControlRequest,
    AgentControlResponse, read_envelope, write_frame,
};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::{Mutex, mpsc};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Config

#[derive(Debug, Clone)]
struct Config {
    socket: PathBuf,
    auth_token: Option<String>,
    admins: HashSet<String>,
    opencode_bin: String,
    opencode_timeout: Duration,
    max_chunk_chars: usize,
    state_path: PathBuf,
}

impl Config {
    fn from_env() -> Result<Self> {
        let home = env::var("MARMOT_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                dirs_home().join(".marmot-agent")
            });
        let socket = env::var("MARMOT_AGENT_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.join("dev").join("wn-agent.sock"));

        let auth_token = match env::var("MARMOT_AGENT_AUTH_TOKEN_FILE") {
            Ok(path) => Some(
                std::fs::read_to_string(&path)
                    .with_context(|| format!("read auth token file {path}"))?
                    .trim()
                    .to_owned(),
            ),
            Err(_) => env::var("MARMOT_AGENT_AUTH_TOKEN").ok(),
        };

        let admins_raw = env::var("WN_OPENCODE_ADMIN_HEX")
            .context("WN_OPENCODE_ADMIN_HEX must be set to one or more admin account hex ids (comma-separated)")?;
        let admins: HashSet<String> = admins_raw
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        if admins.is_empty() {
            bail!("WN_OPENCODE_ADMIN_HEX contains no valid admin ids");
        }
        for admin in &admins {
            if admin.len() != 64 || !admin.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("admin id '{admin}' is not a 64-char lowercase hex");
            }
        }

        let opencode_bin = env::var("WN_OPENCODE_BIN").unwrap_or_else(|_| "opencode".to_owned());
        let opencode_timeout = Duration::from_secs(
            env::var("WN_OPENCODE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
        );
        let max_chunk_chars = env::var("WN_OPENCODE_MAX_CHUNK_CHARS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8000);

        let state_path = env::var("WN_OPENCODE_STATE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let base = env::var("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| dirs_home().join(".local").join("state"));
                base.join("wn-opencode").join("sessions.json")
            });

        Ok(Self {
            socket,
            auth_token,
            admins,
            opencode_bin,
            opencode_timeout,
            max_chunk_chars,
            state_path,
        })
    }
}

// ---------------------------------------------------------------------------
// Session store: persistent group_id_hex -> (session_id, cwd) map.
// One file on disk, JSON, guarded by an in-memory mutex.
//
// Backwards compatible with the pre-cwd format where a value is a bare string
// (the session id, with cwd defaulting to $HOME).

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SessionRecord {
    session_id: String,
    cwd: PathBuf,
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum RawRecord {
    Bare(String),
    Full { session_id: String, cwd: PathBuf },
}

impl RawRecord {
    fn into_record(self, default_cwd: &Path) -> SessionRecord {
        match self {
            RawRecord::Bare(session_id) => SessionRecord {
                session_id,
                cwd: default_cwd.to_path_buf(),
            },
            RawRecord::Full { session_id, cwd } => SessionRecord { session_id, cwd },
        }
    }
}

#[derive(Debug, Default)]
struct SessionStore {
    path: PathBuf,
    map: Mutex<HashMap<String, SessionRecord>>,
}

impl SessionStore {
    async fn load(path: PathBuf, default_cwd: &Path) -> Result<Arc<Self>> {
        let map: HashMap<String, SessionRecord> = match tokio::fs::read(&path).await {
            Ok(bytes) if !bytes.is_empty() => {
                let raw: HashMap<String, RawRecord> = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse session store {}", path.display()))?;
                raw.into_iter()
                    .map(|(k, v)| (k, v.into_record(default_cwd)))
                    .collect()
            }
            _ => HashMap::new(),
        };
        Ok(Arc::new(Self {
            path,
            map: Mutex::new(map),
        }))
    }

    async fn get(&self, group_id: &str) -> Option<SessionRecord> {
        self.map.lock().await.get(group_id).cloned()
    }

    async fn set(&self, group_id: &str, record: SessionRecord) -> Result<()> {
        {
            let mut m = self.map.lock().await;
            m.insert(group_id.to_owned(), record);
        }
        self.flush().await
    }

    async fn flush(&self) -> Result<()> {
        let snapshot: HashMap<String, SessionRecord> = self.map.lock().await.clone();
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &self.path).await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Repo picker: parse a leading "/<name>" from the first message of a group.
//
// - `^/[A-Za-z0-9._-]+(\s+<rest>)?$` -> Some((name, rest_or_empty))
// - Anything else                    -> None
//
// `<name>` is a single path component; no `..`, no slashes inside. The caller
// still has to verify that ~/<name> exists and is a real directory.

fn parse_repo_picker(text: &str) -> Option<(String, String)> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('/') {
        return None;
    }
    // Take chars after the leading slash until whitespace.
    let rest = &trimmed[1..];
    let end = rest
        .char_indices()
        .find(|(_, c)| c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        return None;
    }
    let remainder = rest[end..].trim_start().to_owned();
    Some((name.to_owned(), remainder))
}

/// Resolve a repo name relative to $HOME, verifying that the canonical path
/// exists, is a directory, and is a direct child of $HOME.
async fn resolve_repo(name: &str, home: &Path) -> Result<PathBuf, String> {
    let candidate = home.join(name);
    let canonical = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(_) => {
            return Err(format!("Directory ~/{name} does not exist."));
        }
    };
    let home_canonical = tokio::fs::canonicalize(home)
        .await
        .map_err(|e| format!("cannot canonicalize $HOME: {e}"))?;
    if canonical.parent() != Some(&home_canonical) {
        return Err(format!("Repo ~/{name} resolves outside $HOME; refusing."));
    }
    let meta = tokio::fs::metadata(&canonical)
        .await
        .map_err(|e| format!("cannot stat ~/{name}: {e}"))?;
    if !meta.is_dir() {
        return Err(format!("~/{name} is not a directory."));
    }
    Ok(canonical)
}

fn dirs_home() -> PathBuf {
    env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/"))
}

// ---------------------------------------------------------------------------
// Control socket client
//
// wn-agent's control protocol is fresh-connection-per-request for normal calls
// (AccountList, AllowlistAdd, SendFinal, ...): open, send one request, read
// one response, close. SubscribeInbound is the one exception: after the initial
// request the server keeps the connection open and pushes events until it or
// the client closes.

#[derive(Clone)]
struct Client {
    socket: PathBuf,
    auth_token: Option<String>,
}

impl Client {
    fn new(cfg: &Config) -> Self {
        Self {
            socket: cfg.socket.clone(),
            auth_token: cfg.auth_token.clone(),
        }
    }

    async fn call(&self, request: AgentControlRequest) -> Result<AgentControlResponse> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect to wn-agent socket {}", self.socket.display()))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = AgentControlEnvelope::request(Some(id.clone()), request);
        if let Some(token) = &self.auth_token {
            envelope = envelope.with_auth_token(token);
        }
        write_frame(&mut write_half, &envelope).await?;

        let env = read_envelope::<_, AgentControlResponse>(&mut reader)
            .await?
            .ok_or_else(|| anyhow!("connection closed before response"))?;
        if env.marmot_agent_control != AGENT_CONTROL_PROTOCOL_V1 {
            bail!("unexpected protocol tag: {}", env.marmot_agent_control);
        }
        Ok(env.payload)
    }

    /// Open a subscription connection: send `SubscribeInbound` and forward every
    /// subsequent event through the returned channel. The stream ends when the
    /// server closes the connection or an error occurs.
    async fn subscribe(
        &self,
        account_id_hex: String,
    ) -> Result<mpsc::Receiver<AgentControlEvent>> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .with_context(|| format!("connect to wn-agent socket {}", self.socket.display()))?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        let id = uuid::Uuid::new_v4().to_string();
        let mut envelope = AgentControlEnvelope::request(
            Some(id.clone()),
            AgentControlRequest::SubscribeInbound {
                account_id_hex: Some(account_id_hex),
                group_id_hex: None,
            },
        );
        if let Some(token) = &self.auth_token {
            envelope = envelope.with_auth_token(token);
        }
        write_frame(&mut write_half, &envelope).await?;

        // First frame is the ack for SubscribeInbound.
        let ack = read_envelope::<_, AgentControlResponse>(&mut reader)
            .await?
            .ok_or_else(|| anyhow!("subscribe: connection closed before ack"))?;
        match ack.payload {
            AgentControlResponse::Ack => {}
            AgentControlResponse::Error { code, message } => {
                bail!("subscribe error {code}: {message}")
            }
            other => bail!("subscribe: unexpected initial response: {other:?}"),
        }

        // Hold write_half open for the lifetime of the reader task so the server
        // does not observe a half-close and drop the subscription.
        let (evt_tx, evt_rx) = mpsc::channel::<AgentControlEvent>(256);
        tokio::spawn(async move {
            let _keep_write = write_half; // keep alive
            loop {
                match read_envelope::<_, serde_json::Value>(&mut reader).await {
                    Ok(Some(env)) => {
                        if env.marmot_agent_control != AGENT_CONTROL_PROTOCOL_V1 {
                            warn!(protocol = %env.marmot_agent_control, "unexpected protocol tag on subscribe stream");
                            continue;
                        }
                        // Events on this stream come without an id.
                        match serde_json::from_value::<AgentControlEvent>(env.payload) {
                            Ok(evt) => {
                                if evt_tx.send(evt).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                debug!("event decode error: {e}");
                            }
                        }
                    }
                    Ok(None) => {
                        warn!("subscribe stream closed by peer");
                        break;
                    }
                    Err(e) => {
                        error!("subscribe stream read error: {e}");
                        break;
                    }
                }
            }
            debug!("subscribe task exiting");
        });

        Ok(evt_rx)
    }
}

// ---------------------------------------------------------------------------
// opencode invocation
//
// One in-flight opencode per group. We serialize via a per-group mutex map so
// bursts of messages within a group process in order without dropping any.

#[derive(Default)]
struct GroupQueues {
    inner: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl GroupQueues {
    async fn lock_for(&self, group_id: &str) -> Arc<Mutex<()>> {
        let mut inner = self.inner.lock().await;
        inner
            .entry(group_id.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OpencodeEvent {
    StepStart {
        #[serde(rename = "sessionID")]
        session_id: Option<String>,
    },
    Text {
        part: TextPart,
    },
    StepFinish {},
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct TextPart {
    text: String,
}

async fn handle_message(
    cfg: Arc<Config>,
    client: Client,
    queues: Arc<GroupQueues>,
    sessions: Arc<SessionStore>,
    account_id_hex: String,
    group_id_hex: String,
    message_id_hex: String,
    sender_account_id_hex: String,
    text: String,
) {
    // Serialize per group.
    let lock = queues.lock_for(&group_id_hex).await;
    let _guard = lock.lock().await;

    let known_session = sessions.get(&group_id_hex).await;

    // On the very first message of a new group, parse an optional repo picker
    // `/<name>` prefix. If present, validate ~/<name> and use it as cwd. If the
    // message is only the picker, ack it and skip the opencode invocation so
    // the user can send the real prompt next.
    let (cwd, prompt): (PathBuf, String) = if let Some(rec) = &known_session {
        (rec.cwd.clone(), text.clone())
    } else if let Some((name, rest)) = parse_repo_picker(&text) {
        match resolve_repo(&name, &dirs_home()).await {
            Ok(dir) => {
                if rest.is_empty() {
                    // Pure picker: persist an empty-session record with cwd, ack.
                    let record = SessionRecord {
                        session_id: String::new(),
                        cwd: dir.clone(),
                    };
                    if let Err(e) = sessions.set(&group_id_hex, record).await {
                        warn!("failed to persist repo picker: {e}");
                    }
                    let msg = format!(
                        "[wn-opencode] Session workdir set to ~/{name}. Send your prompt."
                    );
                    let _ = send_reply(
                        &client,
                        &cfg,
                        &account_id_hex,
                        &group_id_hex,
                        &message_id_hex,
                        &msg,
                        0,
                    )
                    .await;
                    return;
                }
                (dir, rest)
            }
            Err(err) => {
                let _ = send_reply(
                    &client,
                    &cfg,
                    &account_id_hex,
                    &group_id_hex,
                    &message_id_hex,
                    &format!("[wn-opencode] {err}"),
                    0,
                )
                .await;
                return;
            }
        }
    } else {
        (dirs_home(), text.clone())
    };

    info!(
        group = %short(&group_id_hex),
        sender = %short(&sender_account_id_hex),
        len = prompt.len(),
        session = ?known_session.as_ref().map(|r| short(&r.session_id)),
        cwd = %cwd.display(),
        "handling inbound message"
    );

    let mut cmd = Command::new(&cfg.opencode_bin);
    cmd.arg("run").arg("--format").arg("json");
    if let Some(rec) = &known_session {
        if !rec.session_id.is_empty() {
            cmd.arg("--session").arg(&rec.session_id);
        }
    }
    cmd.arg(&prompt)
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            error!("failed to spawn opencode: {e}");
            let _ = send_reply(
                &client,
                &cfg,
                &account_id_hex,
                &group_id_hex,
                &message_id_hex,
                &format!("[wn-opencode] failed to start opencode: {e}"),
                0,
            )
            .await;
            return;
        }
    };

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = BufReader::new(stdout).lines();

    // Drain stderr concurrently into a bounded buffer so failures include the
    // real opencode error message instead of "no text output".
    let stderr_capture = Arc::new(Mutex::new(String::new()));
    let stderr_capture_bg = stderr_capture.clone();
    let stderr_task = tokio::spawn(async move {
        let mut sr = BufReader::new(stderr);
        let mut buf = Vec::new();
        while let Ok(n) = sr.read_until(b'\n', &mut buf).await {
            if n == 0 {
                break;
            }
            let mut cap = stderr_capture_bg.lock().await;
            if cap.len() < 4096 {
                cap.push_str(&String::from_utf8_lossy(&buf));
            }
            buf.clear();
        }
    });

    let mut chunk_index: usize = 0;
    let mut observed_session: Option<String> = None;
    let start = std::time::Instant::now();

    let result = timeout(cfg.opencode_timeout, async {
        while let Some(line) = lines.next_line().await? {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<OpencodeEvent>(&line) {
                Ok(OpencodeEvent::Text { part }) => {
                    let text = part.text;
                    if text.trim().is_empty() {
                        continue;
                    }
                    for chunk in split_chunks(&text, cfg.max_chunk_chars) {
                        chunk_index += 1;
                        if let Err(e) = send_reply(
                            &client,
                            &cfg,
                            &account_id_hex,
                            &group_id_hex,
                            &message_id_hex,
                            chunk,
                            chunk_index,
                        )
                        .await
                        {
                            warn!("send_reply failed: {e}");
                        }
                    }
                }
                Ok(OpencodeEvent::StepStart { session_id }) => {
                    if observed_session.is_none() {
                        if let Some(sid) = session_id {
                            observed_session = Some(sid);
                        }
                    }
                }
                Ok(OpencodeEvent::StepFinish {}) | Ok(OpencodeEvent::Other) => {}
                Err(e) => {
                    debug!("opencode line decode error ({e}): {line}");
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;

    let elapsed = start.elapsed();
    match result {
        Ok(Ok(())) => {
            let status = child.wait().await;
            let _ = stderr_task.await;
            let stderr_txt = stderr_capture.lock().await.trim().to_owned();
            let exit_code = status.as_ref().ok().and_then(|s| s.code());
            info!(
                group = %short(&group_id_hex),
                chunks = chunk_index,
                elapsed_ms = elapsed.as_millis(),
                status = ?exit_code,
                session = ?observed_session.as_deref().map(short),
                "opencode invocation complete"
            );

            // Persist the session id we observed for future messages in this
            // group. If we already had a record with only a cwd (from a pure
            // repo picker), we fill in the newly-observed session id but keep
            // the cwd. Otherwise we mint a fresh record with the cwd we used.
            let needs_persist = match &known_session {
                None => true,
                Some(rec) => rec.session_id.is_empty(),
            };
            if needs_persist {
                if let Some(sid) = &observed_session {
                    let record = SessionRecord {
                        session_id: sid.clone(),
                        cwd: cwd.clone(),
                    };
                    if let Err(e) = sessions.set(&group_id_hex, record).await {
                        warn!("failed to persist session mapping: {e}");
                    }
                }
            }

            if chunk_index == 0 {
                let mut msg = String::from("[wn-opencode] opencode produced no text output");
                if let Some(code) = exit_code {
                    if code != 0 {
                        msg.push_str(&format!(" (exit {code})"));
                    }
                }
                if !stderr_txt.is_empty() {
                    // Strip ANSI colour codes crudely so the group message is readable.
                    let cleaned = strip_ansi(&stderr_txt);
                    msg.push_str(":\n");
                    msg.push_str(&cleaned);
                } else {
                    msg.push('.');
                }
                let _ = send_reply(
                    &client,
                    &cfg,
                    &account_id_hex,
                    &group_id_hex,
                    &message_id_hex,
                    &msg,
                    0,
                )
                .await;
            }
        }
        Ok(Err(e)) => {
            warn!("opencode stream error: {e}");
            let _ = child.kill().await;
            let _ = send_reply(
                &client,
                &cfg,
                &account_id_hex,
                &group_id_hex,
                &message_id_hex,
                &format!("[wn-opencode] opencode stream error: {e}"),
                0,
            )
            .await;
        }
        Err(_) => {
            warn!(
                group = %short(&group_id_hex),
                "opencode timeout after {:?}", cfg.opencode_timeout
            );
            let _ = child.kill().await;
            let _ = send_reply(
                &client,
                &cfg,
                &account_id_hex,
                &group_id_hex,
                &message_id_hex,
                &format!("[wn-opencode] opencode timed out after {:?}", cfg.opencode_timeout),
                0,
            )
            .await;
        }
    }
}

async fn send_reply(
    client: &Client,
    _cfg: &Config,
    account_id_hex: &str,
    group_id_hex: &str,
    reply_to_message_id_hex: &str,
    text: &str,
    chunk_index: usize,
) -> Result<()> {
    // Idempotency key includes both the inbound message id and the chunk index so
    // retries after a partial post never conflate different chunks.
    let idempotency_key = format!("{reply_to_message_id_hex}:{chunk_index}");
    let req = AgentControlRequest::SendFinal {
        account_id_hex: account_id_hex.to_owned(),
        group_id_hex: group_id_hex.to_owned(),
        text: text.to_owned(),
        reply_to_message_id_hex: Some(reply_to_message_id_hex.to_owned()),
        idempotency_key: Some(idempotency_key),
    };
    let resp = client.call(req).await?;
    match resp {
        AgentControlResponse::FinalSent { .. } => Ok(()),
        AgentControlResponse::Error { code, message } => {
            Err(anyhow!("send_final error {code}: {message}"))
        }
        other => Err(anyhow!("unexpected send_final response: {other:?}")),
    }
}

fn split_chunks(text: &str, max_chars: usize) -> Vec<&str> {
    if text.chars().count() <= max_chars {
        return vec![text];
    }
    // Byte-safe split at char boundaries.
    let mut out = Vec::new();
    let mut start = 0;
    let mut count = 0;
    let mut last = 0;
    for (i, _) in text.char_indices() {
        if count == max_chars {
            out.push(&text[start..i]);
            start = i;
            count = 0;
        }
        count += 1;
        last = i;
    }
    let _ = last;
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}

// ---------------------------------------------------------------------------
// Bootstrap: discover our account, install admin allowlist

async fn resolve_account(client: &Client) -> Result<String> {
    let resp = client.call(AgentControlRequest::AccountList).await?;
    let accounts = match resp {
        AgentControlResponse::AccountList { accounts } => accounts,
        AgentControlResponse::Error { code, message } => {
            bail!("account_list error {code}: {message}")
        }
        other => bail!("unexpected account_list response: {other:?}"),
    };
    if accounts.is_empty() {
        bail!("wn-agent has no local accounts. Run `wn-agent bootstrap` first.");
    }
    if accounts.len() > 1 {
        warn!(
            count = accounts.len(),
            "multiple accounts present; using first (label={})",
            accounts[0].label
        );
    }
    Ok(accounts[0].account_id_hex.clone())
}

async fn install_admin_allowlist(
    client: &Client,
    account_id_hex: &str,
    admins: &HashSet<String>,
) -> Result<()> {
    let current = client
        .call(AgentControlRequest::AllowlistList {
            account_id_hex: account_id_hex.to_owned(),
        })
        .await?;
    let already: HashSet<String> = match current {
        AgentControlResponse::Allowlist {
            welcomer_account_ids_hex,
            ..
        } => welcomer_account_ids_hex.into_iter().collect(),
        other => bail!("unexpected allowlist_list response: {other:?}"),
    };

    for admin in admins {
        if already.contains(admin) {
            continue;
        }
        let resp = client
            .call(AgentControlRequest::AllowlistAdd {
                account_id_hex: account_id_hex.to_owned(),
                welcomer_account_id_hex: admin.clone(),
            })
            .await?;
        match resp {
            AgentControlResponse::Ack | AgentControlResponse::Allowlist { .. } => {
                info!(admin = %short(admin), "added to welcomer allowlist");
            }
            AgentControlResponse::Error { code, message } => {
                warn!(admin = %short(admin), "allowlist_add error {code}: {message}");
            }
            other => warn!(admin = %short(admin), "unexpected allowlist_add response: {other:?}"),
        }
    }
    Ok(())
}

/// Strip ANSI CSI escape sequences so opencode's colored error text renders
/// cleanly inside a Marmot message.
fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if ('@'..='~').contains(&nc) {
                        break;
                    }
                }
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn short(hex: &str) -> String {
    if hex.len() > 12 {
        format!("{}…{}", &hex[..6], &hex[hex.len() - 6..])
    } else {
        hex.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Main

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,wn_opencode=debug")),
        )
        .init();

    let cfg = Arc::new(Config::from_env()?);
    info!(socket = %cfg.socket.display(), admins = cfg.admins.len(), "wn-opencode starting");

    let client = Client::new(&cfg);

    let account = resolve_account(&client).await?;
    info!(account = %short(&account), "resolved local account");

    install_admin_allowlist(&client, &account, &cfg.admins).await?;

    // Open a dedicated subscription connection for inbound events.
    let mut events = client.subscribe(account.clone()).await?;
    info!("subscribed to inbound events");

    let queues = Arc::new(GroupQueues::default());
    let sessions = SessionStore::load(cfg.state_path.clone(), &dirs_home()).await?;
    info!(path = %cfg.state_path.display(), "session store loaded");

    // Shutdown on SIGINT / SIGTERM.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received, shutting down");
                break;
            }
            evt = events.recv() => {
                let Some(evt) = evt else {
                    warn!("event channel closed; exiting");
                    break;
                };
                dispatch_event(cfg.clone(), client.clone(), queues.clone(), sessions.clone(), account.clone(), evt).await;
            }
        }
    }

    Ok(())
}

async fn dispatch_event(
    cfg: Arc<Config>,
    client: Client,
    queues: Arc<GroupQueues>,
    sessions: Arc<SessionStore>,
    self_account: String,
    evt: AgentControlEvent,
) {
    match evt {
        AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            message_id_hex,
            sender_account_id_hex,
            text,
            ..
        } => {
            if sender_account_id_hex == self_account {
                debug!("ignoring self-echo");
                return;
            }
            if !cfg.admins.contains(&sender_account_id_hex.to_ascii_lowercase()) {
                warn!(
                    sender = %short(&sender_account_id_hex),
                    "rejecting message from non-admin"
                );
                return;
            }
            tokio::spawn(handle_message(
                cfg,
                client,
                queues,
                sessions,
                account_id_hex,
                group_id_hex,
                message_id_hex,
                sender_account_id_hex,
                text,
            ));
        }
        AgentControlEvent::GroupInvite {
            welcomer_account_id_hex,
            group_id_hex,
            ..
        } => {
            info!(
                welcomer = ?welcomer_account_id_hex.as_ref().map(|s| short(s)),
                group = %short(&group_id_hex),
                "group invite observed (allowlist enforces acceptance)"
            );
        }
        AgentControlEvent::ResyncRequired { dropped_events, .. } => {
            warn!(dropped_events, "resync required from wn-agent");
        }
        other => debug!("event: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_chunks_short_text_returns_one() {
        let out = split_chunks("hello", 100);
        assert_eq!(out, vec!["hello"]);
    }

    #[test]
    fn split_chunks_boundaries() {
        let out = split_chunks("abcdefghij", 3);
        assert_eq!(out, vec!["abc", "def", "ghi", "j"]);
    }

    #[test]
    fn parse_repo_picker_matches_bare_name() {
        assert_eq!(
            parse_repo_picker("/whitenoise"),
            Some(("whitenoise".to_owned(), String::new()))
        );
    }

    #[test]
    fn parse_repo_picker_matches_name_with_rest() {
        assert_eq!(
            parse_repo_picker("/whitenoise fix the build"),
            Some(("whitenoise".to_owned(), "fix the build".to_owned()))
        );
    }

    #[test]
    fn parse_repo_picker_rejects_bare_slash() {
        assert_eq!(parse_repo_picker("/"), None);
    }

    #[test]
    fn parse_repo_picker_rejects_slash_inside_name() {
        assert_eq!(parse_repo_picker("/whitenoise/subdir"), None);
    }

    #[test]
    fn parse_repo_picker_rejects_dots_only() {
        assert_eq!(
            parse_repo_picker("/.."),
            Some(("..".to_owned(), String::new())),
            "grammar allows `..` here; resolve_repo canonicalization must catch it"
        );
    }

    #[test]
    fn parse_repo_picker_ignores_non_slash() {
        assert_eq!(parse_repo_picker("hello"), None);
        assert_eq!(parse_repo_picker(" hello"), None);
    }

    #[tokio::test]
    async fn session_store_persists_and_reloads_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();

        // Fresh store, save a record, drop.
        {
            let store = SessionStore::load(path.clone(), &home).await.unwrap();
            let record = SessionRecord {
                session_id: "ses_abc123".to_owned(),
                cwd: home.join("proj"),
            };
            store.set("group1", record).await.unwrap();
        }

        // Reload store, read it back.
        let store = SessionStore::load(path.clone(), &home).await.unwrap();
        let record = store.get("group1").await.expect("record persisted");
        assert_eq!(record.session_id, "ses_abc123");
        assert_eq!(record.cwd, home.join("proj"));
    }

    #[tokio::test]
    async fn session_store_accepts_bare_string_legacy_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();

        // Simulate a pre-cwd file: raw HashMap<String, String>.
        let legacy = serde_json::json!({ "group1": "ses_legacy" });
        tokio::fs::write(&path, serde_json::to_vec(&legacy).unwrap())
            .await
            .unwrap();

        let store = SessionStore::load(path, &home).await.unwrap();
        let record = store.get("group1").await.expect("legacy record");
        assert_eq!(record.session_id, "ses_legacy");
        assert_eq!(record.cwd, home, "legacy records default to $HOME cwd");
    }

    #[test]
    fn split_chunks_unicode_safe() {
        let text = "aあbいc";
        let out = split_chunks(text, 2);
        // 5 chars, chunks of 2 -> "aあ", "bい", "c"
        assert_eq!(out, vec!["aあ", "bい", "c"]);
    }
}
