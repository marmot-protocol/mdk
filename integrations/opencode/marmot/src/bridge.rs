use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_control::AgentControlEvent;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::chunking::split_reply_chunks;
use crate::config::{Config, dirs_home};
use crate::control::ControlClient;
use crate::error::{HarnessError, Result};
use crate::opencode::{Invocation, Outcome, RunnerEvent};
use crate::repo_picker::{parse_repo_picker, resolve_repo};
use crate::store::{SessionRecord, SessionStore};

pub(crate) const TRACE_TARGET: &str = "wn_opencode";

const DEDUPE_LIMIT: usize = 2048;
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const SEND_RETRY_ATTEMPTS: usize = 3;

pub(crate) async fn run(config: Config) -> Result<()> {
    info!(
        target: TRACE_TARGET,
        method = "startup",
        allowed_senders = config.allowed_senders.len(),
        max_reply_bytes = config.max_reply_bytes,
        "wn-opencode starting"
    );

    let client = ControlClient::new(
        config.socket.clone(),
        config.auth_token.clone(),
        config.request_timeout,
    );
    let account_ref = resolve_account(&client, config.account_id_hex.as_deref()).await?;
    install_allowlist(&client, &account_ref, &config.allowed_senders).await?;

    let sessions = Arc::new(SessionStore::load(config.state_path.clone(), &dirs_home())?);
    let queues = Arc::new(GroupQueues::new(config.max_pending_per_group));
    let ctx = Arc::new(BridgeContext {
        cfg: Arc::new(config),
        client,
        account_ref,
        sessions,
        queues,
        dedupe: Arc::new(InboundDedupe::new(DEDUPE_LIMIT)),
    });

    subscribe_loop(ctx).await
}

struct BridgeContext {
    cfg: Arc<Config>,
    client: ControlClient,
    account_ref: String,
    sessions: Arc<SessionStore>,
    queues: Arc<GroupQueues>,
    dedupe: Arc<InboundDedupe>,
}

async fn subscribe_loop(ctx: Arc<BridgeContext>) -> Result<()> {
    let mut reconnect = RECONNECT_INITIAL;
    loop {
        match ctx.client.subscribe(ctx.account_ref.clone()).await {
            Ok(mut events) => {
                info!(
                    target: TRACE_TARGET,
                    method = "subscribe_inbound",
                    "subscribed to inbound events"
                );
                reconnect = RECONNECT_INITIAL;
                match drain_events(ctx.clone(), &mut events).await? {
                    DrainOutcome::Shutdown => return Ok(()),
                    DrainOutcome::Disconnected => {}
                }
            }
            Err(err) => {
                warn!(
                    target: TRACE_TARGET,
                    method = "subscribe_inbound",
                    error_kind = err.privacy_safe_kind(),
                    "failed to subscribe to inbound events"
                );
            }
        }

        sleep(reconnect).await;
        reconnect = (reconnect * 2).min(RECONNECT_MAX);
    }
}

enum DrainOutcome {
    Shutdown,
    Disconnected,
}

async fn drain_events(
    ctx: Arc<BridgeContext>,
    events: &mut mpsc::Receiver<AgentControlEvent>,
) -> Result<DrainOutcome> {
    let mut shutdown = Box::pin(shutdown_signal());
    loop {
        tokio::select! {
            result = &mut shutdown => {
                if let Err(err) = result {
                    warn!(
                        target: TRACE_TARGET,
                        method = "shutdown",
                        error_kind = err.privacy_safe_kind(),
                        "shutdown signal handler failed"
                    );
                    return Err(err);
                }
                info!(
                    target: TRACE_TARGET,
                    method = "shutdown",
                    "shutdown signal received"
                );
                return Ok(DrainOutcome::Shutdown);
            }
            event = events.recv() => {
                let Some(event) = event else {
                    warn!(
                        target: TRACE_TARGET,
                        method = "subscribe_inbound",
                        event = "channel_closed",
                        "inbound event channel closed"
                    );
                    return Ok(DrainOutcome::Disconnected);
                };
                dispatch_event(ctx.clone(), event).await;
            }
        }
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn dispatch_event(ctx: Arc<BridgeContext>, event: AgentControlEvent) {
    match event {
        AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            message_id_hex,
            sender_account_id_hex,
            text,
            ..
        } => {
            if sender_account_id_hex == ctx.account_ref {
                debug!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "self_echo",
                    "ignoring inbound event"
                );
                return;
            }
            if !ctx
                .cfg
                .allowed_senders
                .contains(&sender_account_id_hex.to_ascii_lowercase())
            {
                warn!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "sender_rejected",
                    "ignoring inbound event from unauthorized sender"
                );
                return;
            }
            if !ctx.dedupe.insert(message_id_hex.clone()).await {
                debug!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "duplicate",
                    "ignoring duplicate inbound event"
                );
                return;
            }
            let Some(permit) = ctx.queues.try_enter(&group_id_hex).await else {
                warn!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "queue_full",
                    "rejecting inbound event because group queue is full"
                );
                let ctx_for_reply = ctx.clone();
                tokio::spawn(async move {
                    let _ = send_reply(
                        &ctx_for_reply,
                        &account_id_hex,
                        &group_id_hex,
                        &message_id_hex,
                        "[wn-opencode] too many prompts are already queued for this group; try again shortly.",
                        0,
                    )
                    .await;
                });
                return;
            };

            let inbound = InboundPrompt {
                account_ref: account_id_hex,
                group_ref: group_id_hex,
                message_ref: message_id_hex,
                text,
            };
            tokio::spawn(handle_message(ctx, inbound, permit));
        }
        AgentControlEvent::GroupInvite { .. } => {
            info!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "group_invite",
                "group invite observed"
            );
        }
        AgentControlEvent::ResyncRequired { dropped_events, .. } => {
            warn!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "resync_required",
                dropped_events,
                "inbound event resync required"
            );
        }
        _ => {
            debug!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "ignored",
                "ignoring unsupported event"
            );
        }
    }
}

#[derive(Debug)]
struct InboundPrompt {
    account_ref: String,
    group_ref: String,
    message_ref: String,
    text: String,
}

async fn handle_message(ctx: Arc<BridgeContext>, inbound: InboundPrompt, permit: GroupPermit) {
    let _serial = permit.serial.lock().await;
    let known_session = ctx.sessions.get(&inbound.group_ref);
    let (cwd, prompt) = match resolve_cwd_and_prompt(&ctx, &inbound, known_session.as_ref()).await {
        Ok(Some(value)) => value,
        Ok(None) => return,
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "handle_message",
                error_kind = err.privacy_safe_kind(),
                "failed to prepare inbound prompt"
            );
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                "[wn-opencode] failed to prepare this prompt.",
                0,
            )
            .await;
            return;
        }
    };

    info!(
        target: TRACE_TARGET,
        method = "handle_message",
        prompt_bytes = prompt.len(),
        has_session = known_session
            .as_ref()
            .is_some_and(|record| !record.session_id.is_empty()),
        "handling inbound prompt"
    );

    let session_id = known_session
        .as_ref()
        .and_then(|record| (!record.session_id.is_empty()).then(|| record.session_id.clone()));
    let invocation = Invocation {
        bin: ctx.cfg.opencode_bin.clone(),
        timeout: ctx.cfg.opencode_timeout,
        cwd: cwd.clone(),
        session_id,
        prompt,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let runner = tokio::spawn(crate::opencode::run(invocation, tx));
    let mut chunk_index = 0usize;
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Text(text) => {
                for chunk in split_reply_chunks(&text, ctx.cfg.max_reply_bytes) {
                    chunk_index += 1;
                    if let Err(err) = send_reply(
                        &ctx,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        chunk,
                        chunk_index,
                    )
                    .await
                    {
                        warn!(
                            target: TRACE_TARGET,
                            method = "send_final",
                            error_kind = err.privacy_safe_kind(),
                            "failed to send opencode reply chunk"
                        );
                    }
                }
            }
        }
    }

    match runner.await {
        Ok(Ok(outcome)) => {
            finish_success(ctx, inbound, known_session, cwd, outcome, chunk_index).await;
        }
        Ok(Err(err)) => {
            warn!(
                target: TRACE_TARGET,
                method = "opencode_run",
                error_kind = err.privacy_safe_kind(),
                "opencode invocation failed"
            );
            let text = match err {
                HarnessError::OpencodeTimedOut => {
                    "[wn-opencode] opencode timed out before producing a complete response."
                }
                HarnessError::OpencodeSpawn => {
                    "[wn-opencode] failed to start opencode; check WN_OPENCODE_BIN."
                }
                _ => "[wn-opencode] opencode failed while streaming its response.",
            };
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                text,
                0,
            )
            .await;
        }
        Err(err) => {
            let err = HarnessError::from(err);
            warn!(
                target: TRACE_TARGET,
                method = "opencode_run",
                error_kind = err.privacy_safe_kind(),
                "opencode task join failed"
            );
        }
    }
}

async fn finish_success(
    ctx: Arc<BridgeContext>,
    inbound: InboundPrompt,
    known_session: Option<SessionRecord>,
    cwd: PathBuf,
    outcome: Outcome,
    chunk_count: usize,
) {
    info!(
        target: TRACE_TARGET,
        method = "opencode_run",
        chunk_count,
        elapsed_ms = outcome.elapsed_ms,
        exit_code = outcome.exit_code.unwrap_or(-1),
        observed_session = outcome.observed_session.is_some(),
        "opencode invocation completed"
    );

    let needs_persist = known_session
        .as_ref()
        .is_none_or(|record| record.session_id.is_empty());
    if needs_persist
        && let Some(session_id) = outcome.observed_session
        && let Err(err) = ctx
            .sessions
            .set(&inbound.group_ref, SessionRecord { session_id, cwd })
    {
        warn!(
            target: TRACE_TARGET,
            method = "session_store",
            error_kind = err.privacy_safe_kind(),
            "failed to persist opencode session"
        );
    }

    if chunk_count == 0 {
        let mut message = match outcome.error_summary {
            Some(summary) => format!("[wn-opencode] opencode reported {summary}"),
            None => String::from("[wn-opencode] opencode produced no text output"),
        };
        if let Some(code) = outcome.exit_code
            && code != 0
        {
            message.push_str(&format!(" (exit {code})"));
        }
        if outcome.stderr.is_empty() {
            message.push('.');
        } else {
            message.push_str(":\n");
            message.push_str(&outcome.stderr);
        }
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &message,
            0,
        )
        .await;
    }
}

async fn resolve_cwd_and_prompt(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
    known_session: Option<&SessionRecord>,
) -> Result<Option<(PathBuf, String)>> {
    if let Some(record) = known_session {
        return Ok(Some((record.cwd.clone(), inbound.text.clone())));
    }

    let Some((name, rest)) = parse_repo_picker(&inbound.text) else {
        return Ok(Some((dirs_home(), inbound.text.clone())));
    };
    let cwd = match resolve_repo(&name, &dirs_home()).await {
        Ok(cwd) => cwd,
        Err(err) => {
            let text = err.to_string();
            send_reply(
                ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &format!("[wn-opencode] {text}"),
                0,
            )
            .await?;
            return Ok(None);
        }
    };
    if rest.is_empty() {
        ctx.sessions.set(
            &inbound.group_ref,
            SessionRecord {
                session_id: String::new(),
                cwd,
            },
        )?;
        send_reply(
            ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &format!("[wn-opencode] Session workdir set to ~/{name}. Send your prompt."),
            0,
        )
        .await?;
        return Ok(None);
    }
    Ok(Some((cwd, rest)))
}

async fn resolve_account(client: &ControlClient, preferred: Option<&str>) -> Result<String> {
    let accounts = client.account_list().await?;
    if let Some(preferred) = preferred {
        if accounts
            .iter()
            .any(|account| account.account_id_hex == preferred)
        {
            return Ok(preferred.to_owned());
        }
        return Err(HarnessError::Config(
            "configured account id is not present in wn-agent".to_owned(),
        ));
    }
    if accounts.is_empty() {
        return Err(HarnessError::Config(
            "wn-agent has no local accounts; run wn-agent bootstrap first".to_owned(),
        ));
    }
    if accounts.len() > 1 {
        warn!(
            target: TRACE_TARGET,
            method = "account_list",
            count = accounts.len(),
            "multiple accounts available; using first"
        );
    }
    Ok(accounts[0].account_id_hex.clone())
}

async fn install_allowlist(
    client: &ControlClient,
    account_ref: &str,
    allowed: &HashSet<String>,
) -> Result<()> {
    let current = client.allowlist_list(account_ref).await?;
    for sender in allowed {
        if current.contains(sender) {
            continue;
        }
        client.allowlist_add(account_ref, sender).await?;
        info!(
            target: TRACE_TARGET,
            method = "allowlist_add",
            "added allowed sender to welcomer allowlist"
        );
    }
    Ok(())
}

async fn send_reply(
    ctx: &BridgeContext,
    account_ref: &str,
    group_ref: &str,
    reply_to_ref: &str,
    text: &str,
    chunk_index: usize,
) -> Result<()> {
    let mut last_error: Option<HarnessError> = None;
    for attempt in 1..=SEND_RETRY_ATTEMPTS {
        match ctx
            .client
            .send_final(account_ref, group_ref, reply_to_ref, text, chunk_index)
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) if err.retryable() && attempt < SEND_RETRY_ATTEMPTS => {
                last_error = Some(err);
                sleep(Duration::from_millis(100 * attempt as u64)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or(HarnessError::ControlClosed))
}

struct GroupQueues {
    limit: usize,
    inner: Mutex<HashMap<String, Arc<GroupQueue>>>,
}

struct GroupQueue {
    serial: Arc<Mutex<()>>,
    pending: Arc<Semaphore>,
}

struct GroupPermit {
    serial: Arc<Mutex<()>>,
    _pending: OwnedSemaphorePermit,
}

impl GroupQueues {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn try_enter(&self, group_ref: &str) -> Option<GroupPermit> {
        let queue = {
            let mut inner = self.inner.lock().await;
            inner
                .entry(group_ref.to_owned())
                .or_insert_with(|| {
                    Arc::new(GroupQueue {
                        serial: Arc::new(Mutex::new(())),
                        pending: Arc::new(Semaphore::new(self.limit)),
                    })
                })
                .clone()
        };
        let pending = queue.pending.clone().try_acquire_owned().ok()?;
        Some(GroupPermit {
            serial: queue.serial.clone(),
            _pending: pending,
        })
    }
}

struct InboundDedupe {
    limit: usize,
    inner: Mutex<InboundDedupeInner>,
}

#[derive(Default)]
struct InboundDedupeInner {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl InboundDedupe {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            inner: Mutex::new(InboundDedupeInner::default()),
        }
    }

    async fn insert(&self, message_ref: String) -> bool {
        let mut inner = self.inner.lock().await;
        if inner.seen.contains(&message_ref) {
            return false;
        }
        inner.seen.insert(message_ref.clone());
        inner.order.push_back(message_ref);
        while inner.order.len() > self.limit {
            if let Some(oldest) = inner.order.pop_front() {
                inner.seen.remove(&oldest);
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dedupe_rejects_repeated_message_refs() {
        let dedupe = InboundDedupe::new(8);
        assert!(dedupe.insert("m1".to_owned()).await);
        assert!(!dedupe.insert("m1".to_owned()).await);
        assert!(dedupe.insert("m2".to_owned()).await);
    }

    #[tokio::test]
    async fn group_queue_enforces_pending_limit() {
        let queues = GroupQueues::new(1);
        let first = queues.try_enter("g").await;
        assert!(first.is_some());
        assert!(queues.try_enter("g").await.is_none());
        drop(first);
        assert!(queues.try_enter("g").await.is_some());
    }
}
