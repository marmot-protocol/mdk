use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_control::{AgentControlAccount, AgentControlEvent};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::chunking::split_reply_chunks;
use crate::config::{Config, dirs_home};
use crate::control::ControlClient;
use crate::error::{HarnessError, Result};
use crate::opencode::{Invocation, Outcome, RunFailure, RunnerEvent};
use crate::repo_picker::{parse_repo_picker, resolve_repo, validate_session_cwd};
use crate::store::{SessionRecord, SessionStore};

pub(crate) const TRACE_TARGET: &str = "wn_opencode";

const DEDUPE_LIMIT: usize = 2048;
const GROUP_QUEUE_LIMIT: usize = 4096;
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
                    DrainOutcome::Reconnect => {}
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

        let mut shutdown = Box::pin(shutdown_signal());
        tokio::select! {
            _ = sleep(reconnect) => {}
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
                return Ok(());
            }
        }
        reconnect = (reconnect * 2).min(RECONNECT_MAX);
    }
}

enum DrainOutcome {
    Shutdown,
    Reconnect,
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
                    return Ok(DrainOutcome::Reconnect);
                };
                match dispatch_event(ctx.clone(), event).await {
                    DispatchOutcome::Continue => {}
                    DispatchOutcome::Reconnect => return Ok(DrainOutcome::Reconnect),
                }
            }
        }
    }
}

enum DispatchOutcome {
    Continue,
    Reconnect,
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

async fn dispatch_event(ctx: Arc<BridgeContext>, event: AgentControlEvent) -> DispatchOutcome {
    match event {
        AgentControlEvent::InboundMessage {
            account_id_hex,
            group_id_hex,
            message_id_hex,
            sender_account_id_hex,
            text,
            ..
        } => {
            let sender_ref = sender_account_id_hex.to_ascii_lowercase();
            if sender_ref == ctx.account_ref {
                debug!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "self_echo",
                    "ignoring inbound event"
                );
                return DispatchOutcome::Continue;
            }
            if !ctx.cfg.allowed_senders.contains(&sender_ref) {
                warn!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "sender_rejected",
                    "ignoring inbound event from unauthorized sender"
                );
                return DispatchOutcome::Continue;
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
                    if let Err(err) = send_reply(
                        &ctx_for_reply,
                        &account_id_hex,
                        &group_id_hex,
                        &message_id_hex,
                        "[wn-opencode] too many prompts are already queued for this group; try again shortly.",
                        0,
                    )
                    .await
                    {
                        warn!(
                            target: TRACE_TARGET,
                            method = "queue_full_reply",
                            error_kind = err.privacy_safe_kind(),
                            "failed to send queue-full reply"
                        );
                    }
                });
                return DispatchOutcome::Continue;
            };
            if !ctx.dedupe.insert(message_id_hex.clone()).await {
                debug!(
                    target: TRACE_TARGET,
                    method = "dispatch_event",
                    event = "duplicate",
                    "ignoring duplicate inbound event"
                );
                return DispatchOutcome::Continue;
            }

            let inbound = InboundPrompt {
                account_ref: account_id_hex,
                group_ref: group_id_hex,
                message_ref: message_id_hex,
                text,
            };
            tokio::spawn(handle_message(ctx, inbound, permit));
            DispatchOutcome::Continue
        }
        AgentControlEvent::GroupInvite { .. } => {
            info!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "group_invite",
                "group invite observed"
            );
            DispatchOutcome::Continue
        }
        AgentControlEvent::ResyncRequired { dropped_events, .. } => {
            warn!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "resync_required",
                dropped_events,
                "inbound event resync required; reconnecting subscription"
            );
            DispatchOutcome::Reconnect
        }
        _ => {
            debug!(
                target: TRACE_TARGET,
                method = "dispatch_event",
                event = "ignored",
                "ignoring unsupported event"
            );
            DispatchOutcome::Continue
        }
    }
}

struct InboundPrompt {
    account_ref: String,
    group_ref: String,
    message_ref: String,
    text: String,
}

async fn handle_message(ctx: Arc<BridgeContext>, inbound: InboundPrompt, permit: GroupPermit) {
    let _serial = permit.serial.lock().await;
    let known_session = ctx.sessions.get(&inbound.group_ref).await;
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
        idle_timeout: ctx.cfg.opencode_idle_timeout,
        cwd: cwd.clone(),
        session_id,
        prompt,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let runner = tokio::spawn(crate::opencode::run(invocation, tx));
    let mut chunk_index = 0usize;
    let mut delivered_chunks = 0usize;
    let mut delivery_failed = false;
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Text(text) => {
                if delivery_failed {
                    continue;
                }
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
                        delivery_failed = true;
                        break;
                    } else {
                        delivered_chunks += 1;
                    }
                }
            }
        }
    }

    match runner.await {
        Ok(Ok(outcome)) => {
            finish_success(
                ctx,
                inbound,
                known_session,
                cwd,
                outcome,
                DeliveryReport {
                    chunk_count: delivered_chunks,
                    failed: delivery_failed,
                    failure_chunk_index: chunk_index + 1,
                },
            )
            .await;
        }
        Ok(Err(RunFailure {
            error: err,
            observed_session,
        })) => {
            if let Err(store_err) = persist_observed_session_if_unset(
                &ctx.sessions,
                &inbound.group_ref,
                known_session.as_ref(),
                cwd,
                observed_session,
            )
            .await
            {
                warn!(
                    target: TRACE_TARGET,
                    method = "session_store",
                    error_kind = store_err.privacy_safe_kind(),
                    "failed to persist opencode session"
                );
            }
            warn!(
                target: TRACE_TARGET,
                method = "opencode_run",
                error_kind = err.privacy_safe_kind(),
                "opencode invocation failed"
            );
            let text = match err {
                HarnessError::OpencodeIdle => format!(
                    "[wn-opencode] opencode went silent for {}s without producing output; killing the invocation.",
                    ctx.cfg.opencode_idle_timeout.as_secs()
                ),
                HarnessError::OpencodeTimedOut => {
                    "[wn-opencode] opencode timed out before producing a complete response."
                        .to_owned()
                }
                HarnessError::OpencodeSpawn => {
                    "[wn-opencode] failed to start opencode; check WN_OPENCODE_BIN.".to_owned()
                }
                _ => "[wn-opencode] opencode failed while streaming its response.".to_owned(),
            };
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &text,
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
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                "[wn-opencode] opencode failed while completing this prompt.",
                0,
            )
            .await;
        }
    }
}

async fn finish_success(
    ctx: Arc<BridgeContext>,
    inbound: InboundPrompt,
    known_session: Option<SessionRecord>,
    cwd: PathBuf,
    outcome: Outcome,
    delivery: DeliveryReport,
) {
    info!(
        target: TRACE_TARGET,
        method = "opencode_run",
        chunk_count = delivery.chunk_count,
        elapsed_ms = outcome.elapsed_ms,
        exit_code = outcome.exit_code.unwrap_or(-1),
        observed_session = outcome.observed_session.is_some(),
        stderr_bytes = outcome.stderr.len(),
        delivery_failed = delivery.failed,
        "opencode invocation completed"
    );

    let needs_persist = known_session
        .as_ref()
        .is_none_or(|record| record.session_id.is_empty());
    if !delivery.failed
        && needs_persist
        && let Some(session_id) = outcome.observed_session
        && let Err(err) = persist_observed_session_if_unset(
            &ctx.sessions,
            &inbound.group_ref,
            known_session.as_ref(),
            cwd,
            Some(session_id),
        )
        .await
    {
        warn!(
            target: TRACE_TARGET,
            method = "session_store",
            error_kind = err.privacy_safe_kind(),
            "failed to persist opencode session"
        );
    }

    if delivery.failed {
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            "[wn-opencode] failed to deliver the complete opencode response; some chunks may be missing.",
            delivery.failure_chunk_index,
        )
        .await;
    } else if delivery.chunk_count == 0 {
        let mut message = match outcome.error_summary {
            Some(summary) => format!("[wn-opencode] opencode reported {summary}"),
            None => String::from("[wn-opencode] opencode produced no text output"),
        };
        if let Some(code) = outcome.exit_code
            && code != 0
        {
            message.push_str(&format!(" (exit {code})"));
        }
        message.push('.');
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

struct DeliveryReport {
    chunk_count: usize,
    failed: bool,
    failure_chunk_index: usize,
}

async fn persist_observed_session_if_unset(
    sessions: &SessionStore,
    group_ref: &str,
    known_session: Option<&SessionRecord>,
    cwd: PathBuf,
    observed_session: Option<String>,
) -> Result<()> {
    let needs_persist = known_session
        .as_ref()
        .is_none_or(|record| record.session_id.is_empty());
    if needs_persist && let Some(session_id) = observed_session {
        sessions
            .set(group_ref, SessionRecord { session_id, cwd })
            .await?;
    }
    Ok(())
}

async fn resolve_cwd_and_prompt(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
    known_session: Option<&SessionRecord>,
) -> Result<Option<(PathBuf, String)>> {
    if let Some(record) = known_session {
        let cwd = validate_session_cwd(&record.cwd, &dirs_home()).await?;
        return Ok(Some((cwd, inbound.text.clone())));
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
        ctx.sessions
            .set(
                &inbound.group_ref,
                SessionRecord {
                    session_id: String::new(),
                    cwd,
                },
            )
            .await?;
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
        if let Some(account_ref) = find_account_ref(&accounts, preferred) {
            return Ok(account_ref);
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
        return Err(HarnessError::Config(
            "multiple local accounts are present; set WN_OPENCODE_ACCOUNT_ID_HEX".to_owned(),
        ));
    }
    Ok(accounts[0].account_id_hex.clone())
}

fn find_account_ref(accounts: &[AgentControlAccount], preferred: &str) -> Option<String> {
    accounts
        .iter()
        .find(|account| account.account_id_hex.eq_ignore_ascii_case(preferred))
        .map(|account| account.account_id_hex.clone())
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
    active: AtomicUsize,
}

struct GroupPermit {
    queue: Arc<GroupQueue>,
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
        let mut inner = self.inner.lock().await;
        if inner.len() >= GROUP_QUEUE_LIMIT {
            inner.retain(|_, queue| queue.active.load(Ordering::Relaxed) != 0);
        }
        if inner.len() >= GROUP_QUEUE_LIMIT && !inner.contains_key(group_ref) {
            return None;
        }
        let queue = inner
            .entry(group_ref.to_owned())
            .or_insert_with(|| {
                Arc::new(GroupQueue {
                    serial: Arc::new(Mutex::new(())),
                    pending: Arc::new(Semaphore::new(self.limit)),
                    active: AtomicUsize::new(0),
                })
            })
            .clone();
        let pending = queue.pending.clone().try_acquire_owned().ok()?;
        queue.active.fetch_add(1, Ordering::Relaxed);
        Some(GroupPermit {
            queue: queue.clone(),
            serial: queue.serial.clone(),
            _pending: pending,
        })
    }
}

impl Drop for GroupPermit {
    fn drop(&mut self) {
        self.queue.active.fetch_sub(1, Ordering::Relaxed);
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
    use crate::store::SessionStore;

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

    #[test]
    fn find_account_ref_matches_case_insensitively() {
        let account = AgentControlAccount {
            account_id_hex: "AA".repeat(32),
            label: "terminal-harness-agent".to_owned(),
            local_signing: true,
        };
        assert_eq!(
            find_account_ref(&[account], &"aa".repeat(32)),
            Some("AA".repeat(32))
        );
    }

    #[tokio::test]
    async fn persist_observed_session_only_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(path.clone(), &home).unwrap();
        let cwd = home.join("proj");

        persist_observed_session_if_unset(
            &store,
            "group1",
            None,
            cwd.clone(),
            Some("ses_new".to_owned()),
        )
        .await
        .unwrap();
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_new");
        assert_eq!(record.cwd, cwd);

        persist_observed_session_if_unset(
            &store,
            "group1",
            Some(&record),
            cwd.clone(),
            Some("ses_other".to_owned()),
        )
        .await
        .unwrap();
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_new");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn backpressured_runner_failure_session_can_be_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(home.join("sessions.json"), &home).unwrap();
        let (tx, _rx) = mpsc::channel(1);
        let failure = crate::opencode::run(
            Invocation {
                bin: concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/mock-opencode.sh"
                )
                .to_owned(),
                timeout: Duration::from_millis(200),
                idle_timeout: Duration::from_secs(5),
                cwd: home.clone(),
                session_id: None,
                prompt: "session-backpressure".to_owned(),
            },
            tx,
        )
        .await
        .unwrap_err();

        assert!(matches!(failure.error, HarnessError::OpencodeTimedOut));
        persist_observed_session_if_unset(
            &store,
            "group1",
            None,
            home.clone(),
            failure.observed_session,
        )
        .await
        .unwrap();
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_backpressure");
        assert_eq!(record.cwd, home);
    }
}
