use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_control::{AgentControlAccount, AgentControlEvent};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::chunking::split_reply_chunks;
use crate::control::{ActivePreview, ControlClient};
use crate::error::{HarnessError, Result};
use crate::repo_picker::{RepoPicker, parse_repo_picker, resolve_repo, validate_session_cwd};
use crate::store::{SessionRecord, SessionStore};
use crate::{
    Backend, Config, Invocation, Outcome, RunFailure, RunnerEvent, TRACE_TARGET, dirs_home,
};

const DEDUPE_LIMIT: usize = 2048;
const GROUP_QUEUE_LIMIT: usize = 4096;
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const SEND_RETRY_ATTEMPTS: usize = 3;

/// Connects to `wn-agent`, subscribes to allowed prompts, and runs the backend.
pub async fn run<B: Backend>(config: Config, backend: B) -> Result<()> {
    info!(
        target: TRACE_TARGET,
        method = "startup",
        allowed_senders = config.allowed_senders.len(),
        max_reply_bytes = config.max_reply_bytes,
        harness = config.spec.display_name,
        "terminal harness starting"
    );

    let home = dirs_home()?;
    let client = ControlClient::new(
        config.socket.clone(),
        config.auth_token.clone(),
        config.request_timeout,
        config.spec.reply_prefix,
    );
    let account_ref = resolve_account(
        &client,
        config.account_id_hex.as_deref(),
        config.spec.account_env_name,
    )
    .await?;
    install_allowlist(&client, &account_ref, &config.allowed_senders).await?;

    let sessions = Arc::new(SessionStore::load(config.state_path.clone(), &home)?);
    let queues = Arc::new(GroupQueues::new(config.max_pending_per_group));
    let ctx = Arc::new(BridgeContext {
        cfg: Arc::new(config),
        client,
        account_ref,
        sessions,
        queues,
        dedupe: Arc::new(InboundDedupe::new(DEDUPE_LIMIT)),
        backend: Arc::new(backend),
        home,
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
    backend: Arc<dyn Backend>,
    home: PathBuf,
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
            message,
            ..
        } => {
            let sender_ref = message.sender.account_id_hex.to_ascii_lowercase();
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
                        &message.message_id_hex,
                        &format!("[{}] too many prompts are already queued for this group; try again shortly.", ctx_for_reply.cfg.spec.reply_prefix),
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
            if !ctx.dedupe.insert(message.message_id_hex.clone()).await {
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
                message_ref: message.message_id_hex,
                text: message.text,
                media: message.media,
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
    media: Vec<agent_control::AgentControlMediaRef>,
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
                &format!(
                    "[{}] failed to prepare this prompt.",
                    ctx.cfg.spec.reply_prefix
                ),
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
    let session_name = known_session
        .as_ref()
        .and_then(|record| record.session_name.clone())
        .unwrap_or_else(|| session_name_for_group(&inbound.group_ref));
    let mut attachments = Vec::new();
    if ctx.backend.accepts_attachments() {
        attachments.reserve(inbound.media.len());
        for media in &inbound.media {
            match ctx
                .client
                .download_media(&inbound.account_ref, &inbound.group_ref, media.clone())
                .await
            {
                Ok(attachment) => attachments.push(attachment),
                Err(err) => {
                    warn!(
                        target: TRACE_TARGET,
                        method = "download_media",
                        error_kind = err.privacy_safe_kind(),
                        "failed to download inbound attachment"
                    );
                    let _ = send_reply(
                        &ctx,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        &format!(
                            "[{}] failed to prepare an attached file.",
                            ctx.cfg.spec.reply_prefix
                        ),
                        0,
                    )
                    .await;
                    return;
                }
            }
        }
    }
    let invocation = Invocation {
        timeout: ctx.cfg.backend_timeout,
        idle_timeout: ctx.cfg.backend_idle_timeout,
        cwd: cwd.clone(),
        session_id,
        session_name: session_name.clone(),
        prompt,
        attachments,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let backend = ctx.backend.clone();
    let runner = tokio::spawn(async move { backend.run(invocation, tx).await });
    let mut chunk_index = 0usize;
    let mut delivered_chunks = 0usize;
    let mut delivery_failed = false;
    let mut preview = None;
    let mut preview_disabled = ctx.cfg.quic_candidates.is_empty();
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Preview(delta) => {
                if preview_disabled || delta.is_empty() {
                    continue;
                }
                if preview.is_none() {
                    match ctx
                        .client
                        .stream_begin(
                            &inbound.account_ref,
                            &inbound.group_ref,
                            &inbound.message_ref,
                            ctx.cfg.quic_candidates.clone(),
                        )
                        .await
                    {
                        Ok(active) => preview = Some(PreviewDelivery::new(active)),
                        Err(err) => {
                            warn!(
                                target: TRACE_TARGET,
                                method = "stream_begin",
                                error_kind = err.privacy_safe_kind(),
                                "failed to begin backend preview; continuing with durable delivery"
                            );
                            preview_disabled = true;
                        }
                    }
                }
                if let Some(active) = preview.as_mut() {
                    if let Err(err) = ctx.client.stream_append(&active.handle, &delta).await {
                        warn!(
                            target: TRACE_TARGET,
                            method = "stream_append",
                            error_kind = err.privacy_safe_kind(),
                            "failed to append backend preview; continuing with durable delivery"
                        );
                        if let Some(active) = preview.take() {
                            let _ = ctx.client.stream_cancel(&active.handle).await;
                        }
                        preview_disabled = true;
                    } else {
                        active.append(&delta);
                    }
                }
            }
            RunnerEvent::Text(text) => {
                if delivery_failed {
                    continue;
                }
                if let Some(active) = preview.take() {
                    if active.matches(&text) && text.len() <= ctx.cfg.max_reply_bytes {
                        let transcript_hash_hex = hex::encode(Sha256::digest(text.as_bytes()));
                        match finalize_preview(
                            &ctx.client,
                            &active.handle,
                            &inbound.message_ref,
                            &text,
                            &transcript_hash_hex,
                            active.chunk_count,
                        )
                        .await
                        {
                            PreviewFinalizeOutcome::Finalized => {
                                delivered_chunks += 1;
                                preview_disabled = true;
                                continue;
                            }
                            PreviewFinalizeOutcome::Fallback(err) => {
                                warn!(
                                    target: TRACE_TARGET,
                                    method = "stream_finalize",
                                    error_kind = err.privacy_safe_kind(),
                                    "failed to finalize backend preview; falling back to durable delivery"
                                );
                            }
                            PreviewFinalizeOutcome::Uncertain(err) => {
                                warn!(
                                    target: TRACE_TARGET,
                                    method = "stream_finalize",
                                    error_kind = err.privacy_safe_kind(),
                                    "backend preview finalization remained uncertain; refusing duplicate durable delivery"
                                );
                                let _ = ctx.client.stream_cancel(&active.handle).await;
                                preview_disabled = true;
                                delivery_failed = true;
                                continue;
                            }
                        }
                    }
                    let _ = ctx.client.stream_cancel(&active.handle).await;
                    preview_disabled = true;
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
                            "failed to send backend reply chunk"
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

    if let Some(active) = preview.take() {
        let _ = ctx.client.stream_cancel(&active.handle).await;
    }

    match runner.await {
        Ok(Ok(outcome)) => {
            finish_success(
                ctx,
                inbound,
                known_session,
                cwd,
                session_name,
                outcome,
                DeliveryReport {
                    chunk_count: delivered_chunks,
                    failed: delivery_failed,
                    failure_chunk_index: chunk_index + 1,
                },
            )
            .await;
        }
        Ok(Err(failure)) => {
            warn!(
                target: TRACE_TARGET,
                method = "backend_run",
                error_kind = failure.error.privacy_safe_kind(),
                "backend invocation failed"
            );
            let text = handle_backend_run_failure(
                &ctx.cfg,
                &ctx.sessions,
                &inbound.group_ref,
                known_session.as_ref(),
                cwd,
                session_name,
                &failure,
            )
            .await;
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
                method = "backend_run",
                error_kind = err.privacy_safe_kind(),
                "backend task join failed"
            );
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &format!(
                    "[{}] {} failed while completing this prompt.",
                    ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
                ),
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
    session_name: String,
    outcome: Outcome,
    delivery: DeliveryReport,
) {
    info!(
        target: TRACE_TARGET,
        method = "backend_run",
        chunk_count = delivery.chunk_count,
        elapsed_ms = outcome.elapsed_ms,
        exit_code = outcome.exit_code.unwrap_or(-1),
        observed_session = outcome.observed_session.is_some(),
        stderr_bytes = outcome.stderr.len(),
        delivery_failed = delivery.failed,
        "backend invocation completed"
    );

    let needs_persist = known_session
        .as_ref()
        .is_none_or(|record| record.session_id.is_empty() || record.session_name.is_none());
    if !delivery.failed
        && needs_persist
        && let Some(session_id) = outcome.observed_session
        && let Err(err) = persist_observed_session_if_unset(
            &ctx.sessions,
            &inbound.group_ref,
            known_session.as_ref(),
            cwd,
            session_name,
            Some(session_id),
        )
        .await
    {
        warn!(
            target: TRACE_TARGET,
            method = "session_store",
            error_kind = err.privacy_safe_kind(),
            "failed to persist backend session"
        );
    }

    if delivery.failed {
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &format!(
                "[{}] failed to deliver the complete {} response; some chunks may be missing.",
                ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
            ),
            delivery.failure_chunk_index,
        )
        .await;
    } else if delivery.chunk_count == 0 {
        let mut message = match outcome.error_summary {
            Some(summary) => format!(
                "[{}] {} reported {summary}",
                ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
            ),
            None => format!(
                "[{}] {} produced no text output",
                ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
            ),
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

#[derive(Debug, PartialEq, Eq)]
enum PreviewFinalizeFailureAction {
    Retry,
    Fallback,
    Uncertain,
}

enum PreviewFinalizeOutcome {
    Finalized,
    Fallback(HarnessError),
    Uncertain(HarnessError),
}

fn preview_finalize_failure_action(
    error: &HarnessError,
    attempt: usize,
) -> PreviewFinalizeFailureAction {
    if error.retryable() && attempt < SEND_RETRY_ATTEMPTS {
        PreviewFinalizeFailureAction::Retry
    } else if matches!(error, HarnessError::ControlRejected { .. }) {
        // An explicit server rejection is the only response that proves the
        // stream final did not publish. Malformed, mismatched, closed, or timed
        // out responses are ambiguous after the external send side effect.
        PreviewFinalizeFailureAction::Fallback
    } else {
        PreviewFinalizeFailureAction::Uncertain
    }
}

async fn finalize_preview(
    client: &ControlClient,
    preview: &ActivePreview,
    reply_to_ref: &str,
    final_text: &str,
    transcript_hash_hex: &str,
    chunk_count: u64,
) -> PreviewFinalizeOutcome {
    for attempt in 1..=SEND_RETRY_ATTEMPTS {
        match client
            .stream_finalize(
                preview,
                reply_to_ref,
                final_text,
                transcript_hash_hex,
                chunk_count,
            )
            .await
        {
            Ok(()) => return PreviewFinalizeOutcome::Finalized,
            Err(error) => match preview_finalize_failure_action(&error, attempt) {
                PreviewFinalizeFailureAction::Retry => {
                    sleep(Duration::from_millis(100 * attempt as u64)).await;
                }
                PreviewFinalizeFailureAction::Fallback => {
                    return PreviewFinalizeOutcome::Fallback(error);
                }
                PreviewFinalizeFailureAction::Uncertain => {
                    return PreviewFinalizeOutcome::Uncertain(error);
                }
            },
        }
    }
    unreachable!("preview finalize retry loop always returns on its final attempt")
}

struct PreviewDelivery {
    handle: ActivePreview,
    transcript_hash: Sha256,
    transcript_bytes: usize,
    chunk_count: u64,
}

impl PreviewDelivery {
    fn new(handle: ActivePreview) -> Self {
        Self {
            handle,
            transcript_hash: Sha256::new(),
            transcript_bytes: 0,
            chunk_count: 0,
        }
    }

    fn append(&mut self, delta: &str) {
        self.transcript_hash.update(delta.as_bytes());
        self.transcript_bytes = self.transcript_bytes.saturating_add(delta.len());
        self.chunk_count += 1;
    }

    fn matches(&self, text: &str) -> bool {
        self.transcript_bytes == text.len()
            && self.transcript_hash.clone().finalize() == Sha256::digest(text.as_bytes())
    }
}

async fn handle_backend_run_failure(
    config: &Config,
    sessions: &SessionStore,
    group_ref: &str,
    known_session: Option<&SessionRecord>,
    cwd: PathBuf,
    session_name: String,
    failure: &RunFailure,
) -> String {
    if let Err(store_err) = persist_observed_session_if_unset(
        sessions,
        group_ref,
        known_session,
        cwd,
        session_name,
        failure.observed_session.clone(),
    )
    .await
    {
        warn!(
            target: TRACE_TARGET,
            method = "session_store",
            error_kind = store_err.privacy_safe_kind(),
            "failed to persist backend session"
        );
    }

    match &failure.error {
        HarnessError::BackendIdle => format!(
            "[{}] {} went silent for {}s without producing output; killing the invocation.",
            config.spec.reply_prefix,
            config.spec.display_name,
            config.backend_idle_timeout.as_secs()
        ),
        HarnessError::BackendTimedOut => {
            format!(
                "[{}] {} timed out before producing a complete response.",
                config.spec.reply_prefix, config.spec.display_name
            )
        }
        HarnessError::BackendSpawn => {
            format!(
                "[{}] failed to start {}; check {}.",
                config.spec.reply_prefix, config.spec.display_name, config.spec.bin_env_name
            )
        }
        _ => format!(
            "[{}] {} failed while streaming its response.",
            config.spec.reply_prefix, config.spec.display_name
        ),
    }
}

async fn persist_observed_session_if_unset(
    sessions: &SessionStore,
    group_ref: &str,
    known_session: Option<&SessionRecord>,
    cwd: PathBuf,
    session_name: String,
    observed_session: Option<String>,
) -> Result<()> {
    let needs_persist = known_session
        .as_ref()
        .is_none_or(|record| record.session_id.is_empty() || record.session_name.is_none());
    if needs_persist && let Some(session_id) = observed_session {
        sessions
            .set(
                group_ref,
                SessionRecord {
                    session_id,
                    cwd,
                    session_name: Some(session_name),
                },
            )
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
        let cwd = validate_session_cwd(&record.cwd, &ctx.home).await?;
        return Ok(Some((cwd, inbound.text.clone())));
    }

    let (name, rest) = match parse_repo_picker(&inbound.text) {
        RepoPicker::Absent => return Ok(Some((ctx.home.clone(), inbound.text.clone()))),
        RepoPicker::Invalid => {
            send_reply(
                ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &format!("[{}] Invalid workdir picker. Use /<path> with non-empty path segments containing only ASCII letters, digits, '.', '_', or '-'. Do not use '.' or '..' segments.", ctx.cfg.spec.reply_prefix),
                0,
            )
            .await?;
            return Ok(None);
        }
        RepoPicker::Valid { path, prompt } => (path, prompt),
    };
    let cwd = match resolve_repo(&name, &ctx.home).await {
        Ok(cwd) => cwd,
        Err(err) => {
            let text = err.to_string();
            send_reply(
                ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &format!("[{}] {text}", ctx.cfg.spec.reply_prefix),
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
                    session_name: Some(session_name_for_group(&inbound.group_ref)),
                },
            )
            .await?;
        send_reply(
            ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &format!(
                "[{}] Session workdir set to ~/{name}. Send your prompt.",
                ctx.cfg.spec.reply_prefix
            ),
            0,
        )
        .await?;
        return Ok(None);
    }
    Ok(Some((cwd, rest)))
}

fn session_name_for_group(group_ref: &str) -> String {
    let digest = hex::encode(Sha256::digest(group_ref.as_bytes()));
    format!("marmot-{}", &digest[..32])
}

async fn resolve_account(
    client: &ControlClient,
    preferred: Option<&str>,
    account_env_name: &'static str,
) -> Result<String> {
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
        return Err(HarnessError::Config(format!(
            "multiple local accounts are present; set {account_env_name}"
        )));
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

    fn test_config(root: &std::path::Path) -> Config {
        Config {
            socket: root.join("socket"),
            auth_token: None,
            allowed_senders: HashSet::new(),
            account_id_hex: None,
            request_timeout: Duration::from_secs(1),
            max_reply_bytes: 30_000,
            max_pending_per_group: 4,
            state_path: root.join("sessions.json"),
            backend_timeout: Duration::from_secs(60),
            backend_idle_timeout: Duration::from_secs(45),
            quic_candidates: Vec::new(),
            spec: crate::ConfigSpec {
                env_prefix: "WN_OPENCODE",
                default_home_name: "harnesses",
                default_bin: "opencode",
                display_name: "opencode",
                reply_prefix: "wn-opencode",
                bin_env_name: "WN_OPENCODE_BIN",
                account_env_name: "WN_OPENCODE_ACCOUNT_ID_HEX",
                legacy_allowed_senders_env: Some("WN_OPENCODE_ADMIN_HEX"),
            },
        }
    }

    #[test]
    fn preview_delivery_hashes_deltas_without_retaining_the_transcript() {
        let mut preview = PreviewDelivery::new(ActivePreview {
            stream_id_hex: "stream".to_owned(),
            stream_capability: "capability".to_owned(),
        });
        preview.append("hello");
        preview.append(" world");

        assert!(preview.matches("hello world"));
        assert!(!preview.matches("hello world!"));
        assert_eq!(preview.chunk_count, 2);
    }

    #[test]
    fn preview_finalize_only_falls_back_after_a_definitive_rejection() {
        let timeout = HarnessError::ControlTimedOut {
            method: "stream_finalize",
        };
        assert_eq!(
            preview_finalize_failure_action(&timeout, 1),
            PreviewFinalizeFailureAction::Retry
        );
        assert_eq!(
            preview_finalize_failure_action(&timeout, SEND_RETRY_ATTEMPTS),
            PreviewFinalizeFailureAction::Uncertain
        );

        let malformed = HarnessError::UnexpectedResponse {
            method: "stream_finalize",
            response: "empty_stream_finalized",
        };
        assert_eq!(
            preview_finalize_failure_action(&malformed, 1),
            PreviewFinalizeFailureAction::Uncertain
        );

        let rejected = HarnessError::ControlRejected {
            method: "stream_finalize",
            code: "stream_not_found".to_owned(),
        };
        assert_eq!(
            preview_finalize_failure_action(&rejected, 1),
            PreviewFinalizeFailureAction::Fallback
        );
    }

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
            "marmot-group1".to_owned(),
            Some("ses_new".to_owned()),
        )
        .await
        .unwrap();
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_new");
        assert_eq!(record.cwd, cwd);
        assert_eq!(record.session_name.as_deref(), Some("marmot-group1"));

        persist_observed_session_if_unset(
            &store,
            "group1",
            Some(&record),
            cwd.clone(),
            "marmot-other".to_owned(),
            Some("ses_other".to_owned()),
        )
        .await
        .unwrap();
        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_new");
    }

    #[tokio::test]
    async fn run_failure_path_persists_first_session_and_selects_idle_reply() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(home.join("sessions.json"), &home).unwrap();
        let failure = RunFailure {
            error: HarnessError::BackendIdle,
            observed_session: Some("ses_idle".to_owned()),
        };

        let reply = handle_backend_run_failure(
            &test_config(&home),
            &store,
            "group1",
            None,
            home.clone(),
            "marmot-group1".to_owned(),
            &failure,
        )
        .await;

        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_idle");
        assert_eq!(record.cwd, home);
        assert_eq!(record.session_name.as_deref(), Some("marmot-group1"));
        assert_eq!(
            reply,
            "[wn-opencode] opencode went silent for 45s without producing output; killing the invocation."
        );
    }

    #[test]
    fn backend_session_name_is_stable_without_exposing_group_id() {
        let group_ref = "a1b2c3d4".repeat(8);
        let first = session_name_for_group(&group_ref);
        let second = session_name_for_group(&group_ref);

        assert_eq!(first, second);
        assert!(first.starts_with("marmot-"));
        assert!(!first.contains(&group_ref));
    }
}
