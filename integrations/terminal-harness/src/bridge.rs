use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_control::{AgentControlAccount, AgentControlEvent};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, info, warn};

use crate::chunking::split_reply_chunks;
use crate::control::ControlClient;
use crate::error::{HarnessError, Result};
use crate::repo_picker::{RepoPicker, parse_repo_picker, resolve_repo, validate_session_cwd};
use crate::store::{
    FinalDeliveryRecord, FinalDeliveryStore, RecoveryKind, RecoveryRecord, RecoveryStatus,
    RecoveryStore, SessionRecord, SessionStore,
};
use crate::{
    Backend, Config, Invocation, Outcome, RunFailure, RunnerEvent, TRACE_TARGET, dirs_home,
};

const DEDUPE_LIMIT: usize = 2048;
const GROUP_QUEUE_LIMIT: usize = 4096;
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const SEND_RETRY_ATTEMPTS: usize = 3;
const LIVENESS_UNKNOWN_TEXT: &str = "The backend is still running, but the connector cannot confirm progress. No action is needed; it will keep checking until the configured total limit.";
const TEXT_FINAL_ACK_UNKNOWN_TEXT: &str = "The backend finished, but the connector could not confirm delivery of its final response. No action is needed; it is reconciling delivery.";

/// Connects to `wn-agent`, subscribes to allowed prompts, and runs the backend.
pub async fn run<B: Backend>(config: Config, backend: B) -> Result<()> {
    let execution_support = backend.execution_support();
    info!(
        target: TRACE_TARGET,
        method = "startup",
        allowed_senders = config.allowed_senders.len(),
        max_reply_bytes = config.max_reply_bytes,
        harness = config.spec.display_name,
        execution_profile = config.execution_profile.as_str(),
        approval_support = execution_support.approvals.as_str(),
        isolation_support = execution_support.isolation.as_str(),
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
    let recovery = Arc::new(RecoveryStore::load(
        config.state_path.with_extension("recovery.json"),
    )?);
    let deliveries = Arc::new(FinalDeliveryStore::load(
        config.state_path.with_extension("delivery.json"),
    )?);
    reconcile_pending_deliveries(&client, &deliveries).await;
    let queues = Arc::new(GroupQueues::new(config.max_pending_per_group));
    let ctx = Arc::new(BridgeContext {
        cfg: Arc::new(config),
        client,
        account_ref,
        sessions,
        recovery,
        deliveries,
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
    recovery: Arc<RecoveryStore>,
    deliveries: Arc<FinalDeliveryStore>,
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
    let mut reconcile = interval(Duration::from_secs(30));
    reconcile.set_missed_tick_behavior(MissedTickBehavior::Delay);
    reconcile.tick().await;
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
            _ = reconcile.tick() => {
                reconcile_pending_deliveries(&ctx.client, &ctx.deliveries).await;
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
            let disposition = classify_prompt(&message.text);
            let permit = if matches!(
                disposition,
                PromptDisposition::RetryLast | PromptDisposition::DiscardLast
            ) {
                ctx.queues.enter_recovery(&group_id_hex).await
            } else {
                ctx.queues.try_enter_waiter(&group_id_hex).await
            };
            let Some(permit) = permit else {
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

#[derive(Debug, PartialEq, Eq)]
enum PromptDisposition {
    ResetSession,
    RetryLast,
    DiscardLast,
    Forward {
        prompt: String,
        allow_workdir_picker: bool,
    },
}

fn classify_prompt(text: &str) -> PromptDisposition {
    match text.trim() {
        "/reset-session" => PromptDisposition::ResetSession,
        "/retry-last" => PromptDisposition::RetryLast,
        "/discard-last" => PromptDisposition::DiscardLast,
        "//reset-session" => PromptDisposition::Forward {
            prompt: "/reset-session".to_owned(),
            allow_workdir_picker: false,
        },
        _ => PromptDisposition::Forward {
            prompt: text.to_owned(),
            allow_workdir_picker: true,
        },
    }
}

async fn handle_message(ctx: Arc<BridgeContext>, inbound: InboundPrompt, mut permit: GroupPermit) {
    let mut inbound = inbound;
    let disposition = classify_prompt(&inbound.text);
    let recovery_command = matches!(
        disposition,
        PromptDisposition::RetryLast | PromptDisposition::DiscardLast
    );

    let _serial = if recovery_command {
        match permit.serial.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                let text = format!(
                    "[{}] Recovery commands are unavailable while a turn is active.",
                    ctx.cfg.spec.reply_prefix
                );
                let _ = send_reply(
                    &ctx,
                    &inbound.account_ref,
                    &inbound.group_ref,
                    &inbound.message_ref,
                    &text,
                    0,
                )
                .await;
                return;
            }
        }
    } else {
        let mut recovery_changes = permit.queue.recovery_changed.subscribe();
        let mut delivery_changes = ctx.deliveries.subscribe();
        loop {
            while fifo_is_blocked(&ctx, &inbound.group_ref).await {
                tokio::select! {
                    result = recovery_changes.changed() => {
                        if result.is_err() {
                            return;
                        }
                    }
                    result = delivery_changes.changed() => {
                        if result.is_err() {
                            return;
                        }
                    }
                }
            }
            let Some(pending) = permit.queue.pending.clone().try_acquire_owned().ok() else {
                let text = format!(
                    "[{}] too many prompts are already queued for this group; try again shortly.",
                    ctx.cfg.spec.reply_prefix
                );
                let _ = send_reply(
                    &ctx,
                    &inbound.account_ref,
                    &inbound.group_ref,
                    &inbound.message_ref,
                    &text,
                    0,
                )
                .await;
                return;
            };
            let guard = permit.serial.lock().await;
            if !fifo_is_blocked(&ctx, &inbound.group_ref).await {
                permit._pending = Some(pending);
                permit._waiting.take();
                break guard;
            }
            drop(guard);
            drop(pending);
        }
    };

    let mut retrying = false;
    let forced_run = match disposition {
        PromptDisposition::ResetSession => {
            handle_session_reset(&ctx, &inbound).await;
            return;
        }
        PromptDisposition::DiscardLast => {
            let message = match ctx.recovery.discard(&inbound.group_ref).await {
                Ok(true) => {
                    permit
                        .queue
                        .recovery_changed
                        .send_modify(|generation| *generation = generation.wrapping_add(1));
                    format!(
                        "[{}] The saved recovery was discarded; queued work can continue.",
                        ctx.cfg.spec.reply_prefix
                    )
                }
                Ok(false) => format!(
                    "[{}] There is no saved recovery to discard.",
                    ctx.cfg.spec.reply_prefix
                ),
                Err(err) => {
                    warn!(target: TRACE_TARGET, method = "discard_recovery", error_kind = err.privacy_safe_kind(), "failed to discard recovery record");
                    format!(
                        "[{}] Failed to discard the saved recovery.",
                        ctx.cfg.spec.reply_prefix
                    )
                }
            };
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &message,
                0,
            )
            .await;
            return;
        }
        PromptDisposition::RetryLast => {
            let record = match ctx.recovery.begin_retry(&inbound.group_ref).await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    let _ = send_reply(
                        &ctx,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        &format!(
                            "[{}] There is no retryable saved recovery.",
                            ctx.cfg.spec.reply_prefix
                        ),
                        0,
                    )
                    .await;
                    return;
                }
                Err(err) => {
                    warn!(target: TRACE_TARGET, method = "retry_recovery", error_kind = err.privacy_safe_kind(), "failed to consume recovery record");
                    let _ = send_reply(
                        &ctx,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        &format!(
                            "[{}] Failed to start the saved recovery.",
                            ctx.cfg.spec.reply_prefix
                        ),
                        0,
                    )
                    .await;
                    return;
                }
            };
            retrying = true;
            Some((record.cwd, Some(record.session_id), record.prompt))
        }
        PromptDisposition::Forward {
            prompt,
            allow_workdir_picker,
        } => {
            inbound.text = prompt;
            let known_session = ctx.sessions.get(&inbound.group_ref).await;
            match resolve_cwd_and_prompt(
                &ctx,
                &inbound,
                known_session.as_ref(),
                allow_workdir_picker,
            )
            .await
            {
                Ok(Some((cwd, prompt))) => Some((
                    cwd,
                    known_session.as_ref().and_then(|record| {
                        (!record.session_id.is_empty()).then(|| record.session_id.clone())
                    }),
                    prompt,
                )),
                Ok(None) => return,
                Err(err) => {
                    warn!(target: TRACE_TARGET, method = "handle_message", error_kind = err.privacy_safe_kind(), "failed to prepare inbound prompt");
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
            }
        }
    };

    let Some((cwd, session_id, prompt)) = forced_run else {
        return;
    };
    let known_session = ctx.sessions.get(&inbound.group_ref).await;

    info!(
        target: TRACE_TARGET,
        method = "handle_message",
        prompt_bytes = prompt.len(),
        has_session = known_session
            .as_ref()
            .is_some_and(|record| !record.session_id.is_empty()),
        "handling inbound prompt"
    );

    let recovery_prompt = prompt.clone();
    let invocation = Invocation {
        timeout: ctx.cfg.backend_timeout,
        idle_timeout: ctx.cfg.backend_idle_timeout,
        cwd: cwd.clone(),
        session_id,
        prompt,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let backend = ctx.backend.clone();
    let runner = tokio::spawn(async move { backend.run(invocation, tx).await });
    let mut chunk_index = 0usize;
    let mut delivered_chunks = 0usize;
    let mut delivery_failed = false;
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Text(text) => {
                let mut staged = Vec::new();
                for chunk in split_reply_chunks(&text, ctx.cfg.max_reply_bytes) {
                    chunk_index += 1;
                    match stage_backend_reply(
                        &ctx,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        chunk,
                        chunk_index,
                    )
                    .await
                    {
                        Ok(key) => staged.push((key, chunk.to_owned(), chunk_index)),
                        Err(err) => {
                            warn!(target: TRACE_TARGET, method = "stage_final", error_kind = err.privacy_safe_kind(), "failed to persist backend reply chunk");
                            delivery_failed = true;
                        }
                    }
                }
                if delivery_failed {
                    continue;
                }
                for (key, chunk, index) in staged {
                    if let Err(err) = send_staged_backend_reply(
                        &ctx,
                        &key,
                        &inbound.account_ref,
                        &inbound.group_ref,
                        &inbound.message_ref,
                        &chunk,
                        index,
                    )
                    .await
                    {
                        warn!(target: TRACE_TARGET, method = "send_final", error_kind = err.privacy_safe_kind(), "failed to send backend reply chunk");
                        delivery_failed = true;
                        break;
                    }
                    delivered_chunks += 1;
                }
            }
            RunnerEvent::LivenessUnknown => {
                let text = format!("[{}] {LIVENESS_UNKNOWN_TEXT}", ctx.cfg.spec.reply_prefix);
                if let Err(err) = send_reply(
                    &ctx,
                    &inbound.account_ref,
                    &inbound.group_ref,
                    &inbound.message_ref,
                    &text,
                    0,
                )
                .await
                {
                    warn!(target: TRACE_TARGET, method = "liveness_status", error_kind = err.privacy_safe_kind(), "failed to send liveness status");
                }
            }
        }
    }

    match runner.await {
        Ok(Ok(outcome)) => {
            if retrying
                && outcome.exit_code == Some(0)
                && ctx.recovery.discard(&inbound.group_ref).await.is_ok()
            {
                permit
                    .queue
                    .recovery_changed
                    .send_modify(|generation| *generation = generation.wrapping_add(1));
            }
            finish_success(
                ctx,
                inbound,
                known_session,
                cwd,
                recovery_prompt,
                outcome,
                DeliveryReport {
                    chunk_count: delivered_chunks,
                    failed: delivery_failed,
                    status_chunk_index: chunk_index + 1,
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
            if retrying && let Err(err) = ctx.recovery.reset_retry(&inbound.group_ref).await {
                warn!(target: TRACE_TARGET, method = "retry_recovery", error_kind = err.privacy_safe_kind(), "failed to restore retryable recovery state");
            }
            let text = handle_backend_run_failure(
                FailureRecoveryContext {
                    config: &ctx.cfg,
                    sessions: &ctx.sessions,
                    recovery: &ctx.recovery,
                },
                &inbound.group_ref,
                known_session.as_ref(),
                cwd,
                recovery_prompt,
                &failure,
            )
            .await;
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &text,
                chunk_index + 1,
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
            if retrying && let Err(reset_err) = ctx.recovery.reset_retry(&inbound.group_ref).await {
                warn!(target: TRACE_TARGET, method = "retry_recovery", error_kind = reset_err.privacy_safe_kind(), "failed to restore retryable recovery state");
            }
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &format!(
                    "[{}] {} failed while completing this prompt.",
                    ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
                ),
                chunk_index + 1,
            )
            .await;
        }
    }
}

async fn fifo_is_blocked(ctx: &BridgeContext, group_ref: &str) -> bool {
    ctx.recovery.get(group_ref).await.is_some() || ctx.deliveries.has_group(group_ref).await
}

async fn handle_session_reset(ctx: &BridgeContext, inbound: &InboundPrompt) {
    let message = match ctx.sessions.reset_session(&inbound.group_ref).await {
        Ok(true) => format!(
            "[{}] Session reset. The next prompt will start a new {} session in the preserved workdir.",
            ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
        ),
        Ok(false) => format!(
            "[{}] No {} session is recorded for this group.",
            ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
        ),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "session_reset",
                error_kind = err.privacy_safe_kind(),
                "failed to reset backend session"
            );
            format!(
                "[{}] Failed to reset the {} session.",
                ctx.cfg.spec.reply_prefix, ctx.cfg.spec.display_name
            )
        }
    };
    if let Err(err) = send_reply(
        ctx,
        &inbound.account_ref,
        &inbound.group_ref,
        &inbound.message_ref,
        &message,
        0,
    )
    .await
    {
        warn!(
            target: TRACE_TARGET,
            method = "session_reset_reply",
            error_kind = err.privacy_safe_kind(),
            "failed to send session-reset reply"
        );
    }
}

async fn finish_success(
    ctx: Arc<BridgeContext>,
    inbound: InboundPrompt,
    known_session: Option<SessionRecord>,
    cwd: PathBuf,
    recovery_prompt: String,
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
        .is_none_or(|record| record.session_id.is_empty());
    if needs_persist
        && let Some(session_id) = outcome.observed_session.clone()
        && let Err(err) = persist_observed_session_if_unset(
            &ctx.sessions,
            &inbound.group_ref,
            known_session.as_ref(),
            cwd.clone(),
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

    let completion_route = completion_route(&outcome, &delivery);
    if completion_route == CompletionRoute::NonzeroExit {
        let session_id = outcome
            .observed_session
            .clone()
            .or_else(|| {
                known_session
                    .as_ref()
                    .map(|record| record.session_id.clone())
            })
            .filter(|value| !value.is_empty());
        let message = if let Some(session_id) = session_id {
            let kind = recovery_kind_for_outcome(&outcome);
            if let Err(err) = persist_recovery_record(
                &ctx.recovery,
                &inbound.group_ref,
                recovery_prompt,
                cwd,
                session_id,
                kind,
            )
            .await
            {
                warn!(target: TRACE_TARGET, method = "recovery_store", error_kind = err.privacy_safe_kind(), "failed to persist recovery record");
                format!(
                    "[{}] The backend exited and this attempt cannot be resumed. Send a new prompt or `/reset-session`.",
                    ctx.cfg.spec.reply_prefix
                )
            } else {
                recovery_resolution_message(ctx.cfg.spec.reply_prefix, kind)
            }
        } else {
            format!(
                "[{}] The backend exited and this attempt cannot be resumed. Send a new prompt or `/reset-session`.",
                ctx.cfg.spec.reply_prefix
            )
        };
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &message,
            delivery.status_chunk_index,
        )
        .await;
    } else if completion_route == CompletionRoute::TextFinalAckUnknown {
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &format!(
                "[{}] {TEXT_FINAL_ACK_UNKNOWN_TEXT}",
                ctx.cfg.spec.reply_prefix
            ),
            delivery.status_chunk_index,
        )
        .await;
    } else if completion_route == CompletionRoute::NoText {
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
            delivery.status_chunk_index,
        )
        .await;
    }
}

struct DeliveryReport {
    chunk_count: usize,
    failed: bool,
    status_chunk_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionRoute {
    NonzeroExit,
    TextFinalAckUnknown,
    NoText,
    Complete,
}

fn completion_route(outcome: &Outcome, delivery: &DeliveryReport) -> CompletionRoute {
    if outcome.exit_code.is_some_and(|code| code != 0) {
        CompletionRoute::NonzeroExit
    } else if delivery.failed {
        CompletionRoute::TextFinalAckUnknown
    } else if delivery.chunk_count == 0 {
        CompletionRoute::NoText
    } else {
        CompletionRoute::Complete
    }
}

fn recovery_kind_for_outcome(outcome: &Outcome) -> RecoveryKind {
    if outcome.no_side_effects_proven {
        RecoveryKind::FailedResumable
    } else {
        RecoveryKind::UncertainOutcome
    }
}

async fn persist_recovery_record(
    recovery: &RecoveryStore,
    group_ref: &str,
    prompt: String,
    cwd: PathBuf,
    session_id: String,
    kind: RecoveryKind,
) -> Result<()> {
    recovery
        .set(
            group_ref,
            RecoveryRecord {
                prompt,
                cwd,
                session_id,
                kind,
                status: RecoveryStatus::Pending,
            },
        )
        .await
}

struct FailureRecoveryContext<'a> {
    config: &'a Config,
    sessions: &'a SessionStore,
    recovery: &'a RecoveryStore,
}

async fn handle_backend_run_failure(
    context: FailureRecoveryContext<'_>,
    group_ref: &str,
    known_session: Option<&SessionRecord>,
    cwd: PathBuf,
    prompt: String,
    failure: &RunFailure,
) -> String {
    let FailureRecoveryContext {
        config,
        sessions,
        recovery,
    } = context;
    let resumable_session = failure
        .observed_session
        .clone()
        .or_else(|| known_session.map(|record| record.session_id.clone()))
        .filter(|value| !value.is_empty());
    if let Err(store_err) = persist_observed_session_if_unset(
        sessions,
        group_ref,
        known_session,
        cwd.clone(),
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
        HarnessError::BackendTimedOut => {
            if let Some(session_id) = resumable_session {
                let record = RecoveryRecord {
                    prompt,
                    cwd,
                    session_id,
                    kind: RecoveryKind::PolicyLimit,
                    status: RecoveryStatus::Pending,
                };
                if let Err(err) = recovery.set(group_ref, record).await {
                    warn!(target: TRACE_TARGET, method = "recovery_store", error_kind = err.privacy_safe_kind(), "failed to persist recovery record");
                    format!(
                        "[{}] The backend exited and this attempt cannot be resumed. Send a new prompt or `/reset-session`.",
                        config.spec.reply_prefix
                    )
                } else {
                    recovery_resolution_message(config.spec.reply_prefix, RecoveryKind::PolicyLimit)
                }
            } else {
                format!(
                    "[{}] The backend exited and this attempt cannot be resumed. Send a new prompt or `/reset-session`.",
                    config.spec.reply_prefix
                )
            }
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

fn recovery_resolution_message(prefix: &str, kind: RecoveryKind) -> String {
    let text = match kind {
        RecoveryKind::NotResponding => {
            "The connector stopped this attempt and saved the backend session. Send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        }
        RecoveryKind::FailedResumable => {
            "The backend exited before completing, and its session was saved. Send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        }
        RecoveryKind::UncertainOutcome => {
            "This attempt stopped with an uncertain outcome and may have applied side effects. Review the results, then send `/retry-last` only if replay is safe, or `/discard-last` to abandon it and continue queued work."
        }
        RecoveryKind::PolicyLimit => {
            "The configured time limit ended this attempt. The backend session was saved; send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        }
    };
    format!("[{prefix}] {text}")
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
    allow_workdir_picker: bool,
) -> Result<Option<(PathBuf, String)>> {
    if let Some(record) = known_session {
        let cwd = validate_session_cwd(&record.cwd, &ctx.home).await?;
        return Ok(Some((cwd, inbound.text.clone())));
    }
    if !allow_workdir_picker {
        return Ok(Some((ctx.home.clone(), inbound.text.clone())));
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

async fn reconcile_pending_deliveries(client: &ControlClient, store: &FinalDeliveryStore) {
    for (key, record) in store.list().await {
        match send_final_with_retry(
            client,
            &record.account_ref,
            &record.group_ref,
            &record.reply_to_ref,
            &record.text,
            record.chunk_index,
        )
        .await
        {
            Ok(()) => {
                if let Err(err) = store.remove(&key).await {
                    warn!(target: TRACE_TARGET, method = "final_reconcile", error_kind = err.privacy_safe_kind(), "failed to clear reconciled final-delivery record");
                }
            }
            Err(err) => {
                warn!(target: TRACE_TARGET, method = "final_reconcile", error_kind = err.privacy_safe_kind(), "final-delivery reconciliation remains pending")
            }
        }
    }
}

async fn stage_backend_reply(
    ctx: &BridgeContext,
    account_ref: &str,
    group_ref: &str,
    reply_to_ref: &str,
    text: &str,
    chunk_index: usize,
) -> Result<String> {
    let key = format!("{group_ref}:{reply_to_ref}:{chunk_index}");
    ctx.deliveries
        .set(
            &key,
            FinalDeliveryRecord {
                account_ref: account_ref.to_owned(),
                group_ref: group_ref.to_owned(),
                reply_to_ref: reply_to_ref.to_owned(),
                text: text.to_owned(),
                chunk_index,
            },
        )
        .await?;
    Ok(key)
}

async fn send_staged_backend_reply(
    ctx: &BridgeContext,
    key: &str,
    account_ref: &str,
    group_ref: &str,
    reply_to_ref: &str,
    text: &str,
    chunk_index: usize,
) -> Result<()> {
    send_final_with_retry(
        &ctx.client,
        account_ref,
        group_ref,
        reply_to_ref,
        text,
        chunk_index,
    )
    .await?;
    ctx.deliveries.remove(key).await?;
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
    send_final_with_retry(
        &ctx.client,
        account_ref,
        group_ref,
        reply_to_ref,
        text,
        chunk_index,
    )
    .await
}

async fn send_final_with_retry(
    client: &ControlClient,
    account_ref: &str,
    group_ref: &str,
    reply_to_ref: &str,
    text: &str,
    chunk_index: usize,
) -> Result<()> {
    let mut last_error: Option<HarnessError> = None;
    for attempt in 1..=SEND_RETRY_ATTEMPTS {
        match client
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
    waiting: Arc<Semaphore>,
    active: AtomicUsize,
    recovery_changed: tokio::sync::watch::Sender<u64>,
}

struct GroupPermit {
    queue: Arc<GroupQueue>,
    serial: Arc<Mutex<()>>,
    _waiting: Option<OwnedSemaphorePermit>,
    _pending: Option<OwnedSemaphorePermit>,
}

impl GroupQueues {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            inner: Mutex::new(HashMap::new()),
        }
    }

    async fn queue(&self, group_ref: &str) -> Option<Arc<GroupQueue>> {
        let mut inner = self.inner.lock().await;
        if inner.len() >= GROUP_QUEUE_LIMIT {
            inner.retain(|_, queue| queue.active.load(Ordering::Relaxed) != 0);
        }
        if inner.len() >= GROUP_QUEUE_LIMIT && !inner.contains_key(group_ref) {
            return None;
        }
        Some(
            inner
                .entry(group_ref.to_owned())
                .or_insert_with(|| {
                    let (recovery_changed, _) = tokio::sync::watch::channel(0);
                    Arc::new(GroupQueue {
                        serial: Arc::new(Mutex::new(())),
                        pending: Arc::new(Semaphore::new(self.limit)),
                        waiting: Arc::new(Semaphore::new(self.limit)),
                        active: AtomicUsize::new(0),
                        recovery_changed,
                    })
                })
                .clone(),
        )
    }

    async fn try_enter_waiter(&self, group_ref: &str) -> Option<GroupPermit> {
        let queue = self.queue(group_ref).await?;
        let waiting = queue.waiting.clone().try_acquire_owned().ok()?;
        queue.active.fetch_add(1, Ordering::Relaxed);
        Some(GroupPermit {
            queue: queue.clone(),
            serial: queue.serial.clone(),
            _waiting: Some(waiting),
            _pending: None,
        })
    }

    async fn enter_recovery(&self, group_ref: &str) -> Option<GroupPermit> {
        let queue = self.queue(group_ref).await?;
        queue.active.fetch_add(1, Ordering::Relaxed);
        Some(GroupPermit {
            queue: queue.clone(),
            serial: queue.serial.clone(),
            _waiting: None,
            _pending: None,
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
            execution_profile: crate::ExecutionProfile::Inherit,
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

    #[tokio::test]
    async fn dedupe_rejects_repeated_message_refs() {
        let dedupe = InboundDedupe::new(8);
        assert!(dedupe.insert("m1".to_owned()).await);
        assert!(!dedupe.insert("m1".to_owned()).await);
        assert!(dedupe.insert("m2".to_owned()).await);
    }

    #[tokio::test]
    async fn group_queue_enforces_waiting_limit_but_recovery_bypasses_it() {
        let queues = GroupQueues::new(1);
        let first = queues.try_enter_waiter("g").await;
        assert!(first.is_some());
        assert_eq!(first.as_ref().unwrap().queue.pending.available_permits(), 1);
        assert!(queues.try_enter_waiter("g").await.is_none());
        let recovery = queues.enter_recovery("g").await;
        assert!(recovery.is_some());
        drop(recovery);
        drop(first);
        assert!(queues.try_enter_waiter("g").await.is_some());
    }

    #[test]
    fn reset_command_is_exact_and_has_a_literal_escape() {
        assert_eq!(
            classify_prompt("/reset-session"),
            PromptDisposition::ResetSession
        );
        assert_eq!(
            classify_prompt("  /reset-session\n"),
            PromptDisposition::ResetSession
        );
        assert_eq!(
            classify_prompt("//reset-session"),
            PromptDisposition::Forward {
                prompt: "/reset-session".to_owned(),
                allow_workdir_picker: false,
            }
        );
        assert_eq!(
            classify_prompt("/reset-session please"),
            PromptDisposition::Forward {
                prompt: "/reset-session please".to_owned(),
                allow_workdir_picker: true,
            }
        );
    }

    #[test]
    fn recovery_commands_are_exact_and_similar_text_stays_conversational() {
        assert_eq!(
            classify_prompt(" /retry-last\n"),
            PromptDisposition::RetryLast
        );
        assert_eq!(
            classify_prompt("/discard-last"),
            PromptDisposition::DiscardLast
        );
        assert_eq!(
            classify_prompt("retry"),
            PromptDisposition::Forward {
                prompt: "retry".to_owned(),
                allow_workdir_picker: true,
            }
        );
        assert_eq!(
            classify_prompt("/goal retry-last"),
            PromptDisposition::Forward {
                prompt: "/goal retry-last".to_owned(),
                allow_workdir_picker: true,
            }
        );
        assert_eq!(
            classify_prompt("/retry-last please"),
            PromptDisposition::Forward {
                prompt: "/retry-last please".to_owned(),
                allow_workdir_picker: true,
            }
        );
    }

    #[test]
    fn recovery_copy_is_typed_and_uncertainty_is_not_overstated() {
        let not_responding = recovery_resolution_message("wn", RecoveryKind::NotResponding);
        let failed = recovery_resolution_message("wn", RecoveryKind::FailedResumable);
        let uncertain = recovery_resolution_message("wn", RecoveryKind::UncertainOutcome);
        let policy = recovery_resolution_message("wn", RecoveryKind::PolicyLimit);
        assert!(not_responding.contains("connector stopped this attempt"));
        assert!(failed.contains("backend exited before completing"));
        assert!(uncertain.contains("may have applied side effects"));
        assert!(policy.contains("configured time limit"));
        for text in [&not_responding, &failed, &policy] {
            assert!(!text.contains("side effects"));
            assert!(text.contains("backend"));
        }
        for text in [&not_responding, &failed, &uncertain, &policy] {
            assert!(text.contains("/retry-last"));
            assert!(text.contains("/discard-last"));
            assert!(!text.contains("killing the invocation"));
        }
    }

    #[test]
    fn completion_matrix_prioritizes_nonzero_recovery_over_delivery_reconciliation() {
        let failed_delivery = DeliveryReport {
            chunk_count: 0,
            failed: true,
            status_chunk_index: 2,
        };
        let uncertain = Outcome {
            observed_session: Some("session".to_owned()),
            exit_code: Some(64),
            error_summary: Some("failed".to_owned()),
            no_side_effects_proven: false,
            stderr: String::new(),
            elapsed_ms: 1,
        };
        assert_eq!(
            completion_route(&uncertain, &failed_delivery),
            CompletionRoute::NonzeroExit
        );
        assert_eq!(
            recovery_kind_for_outcome(&uncertain),
            RecoveryKind::UncertainOutcome
        );

        let proven = Outcome {
            no_side_effects_proven: true,
            ..uncertain
        };
        assert_eq!(
            recovery_kind_for_outcome(&proven),
            RecoveryKind::FailedResumable
        );
        let completed = Outcome {
            exit_code: Some(0),
            ..proven
        };
        assert_eq!(
            completion_route(&completed, &failed_delivery),
            CompletionRoute::TextFinalAckUnknown
        );
    }

    #[tokio::test]
    async fn nonzero_completion_persists_pending_recovery_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecoveryStore::load(dir.path().join("recovery.json")).unwrap();
        persist_recovery_record(
            &store,
            "group",
            "private prompt".to_owned(),
            dir.path().join("repo"),
            "session".to_owned(),
            RecoveryKind::UncertainOutcome,
        )
        .await
        .unwrap();
        let record = store.get("group").await.unwrap();
        assert_eq!(record.kind, RecoveryKind::UncertainOutcome);
        assert_eq!(record.status, RecoveryStatus::Pending);
        assert_eq!(record.session_id, "session");
    }

    #[test]
    fn fixed_in_progress_and_reconciliation_copy_is_exact() {
        assert_eq!(
            LIVENESS_UNKNOWN_TEXT,
            "The backend is still running, but the connector cannot confirm progress. No action is needed; it will keep checking until the configured total limit."
        );
        assert_eq!(
            TEXT_FINAL_ACK_UNKNOWN_TEXT,
            "The backend finished, but the connector could not confirm delivery of its final response. No action is needed; it is reconciling delivery."
        );
    }

    #[tokio::test]
    async fn recovery_signal_broadcasts_and_serial_lock_rejects_active_resolution() {
        let queues = GroupQueues::new(1);
        let waiter = queues.try_enter_waiter("g").await.unwrap();
        let mut changes = waiter.queue.recovery_changed.subscribe();
        waiter
            .queue
            .recovery_changed
            .send_modify(|generation| *generation += 1);
        tokio::time::timeout(Duration::from_millis(50), changes.changed())
            .await
            .unwrap()
            .unwrap();

        let recovery = queues.enter_recovery("g").await.unwrap();
        let active = recovery.serial.lock().await;
        assert!(recovery.serial.try_lock().is_err());
        drop(active);
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

    #[tokio::test]
    async fn post_reset_observation_records_a_new_session_in_the_preserved_workdir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let home = dir.path().to_path_buf();
        let cwd = home.join("proj");
        let store = SessionStore::load(path, &home).unwrap();
        store
            .set(
                "group1",
                SessionRecord {
                    session_id: "ses_old".to_owned(),
                    cwd: cwd.clone(),
                },
            )
            .await
            .unwrap();
        assert!(store.reset_session("group1").await.unwrap());

        let reset_record = store.get("group1").await.unwrap();
        persist_observed_session_if_unset(
            &store,
            "group1",
            Some(&reset_record),
            reset_record.cwd.clone(),
            Some("ses_new".to_owned()),
        )
        .await
        .unwrap();

        let current = store.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_new");
        assert_eq!(current.cwd, cwd);
    }

    #[tokio::test]
    async fn total_limit_persists_session_and_recovery_record() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let store = SessionStore::load(home.join("sessions.json"), &home).unwrap();
        let recovery = RecoveryStore::load(home.join("recovery.json")).unwrap();

        let failure = RunFailure {
            error: HarnessError::BackendTimedOut,
            observed_session: Some("ses_idle".to_owned()),
        };

        let config = test_config(&home);
        let reply = handle_backend_run_failure(
            FailureRecoveryContext {
                config: &config,
                sessions: &store,
                recovery: &recovery,
            },
            "group1",
            None,
            home.clone(),
            "private prompt".to_owned(),
            &failure,
        )
        .await;

        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_idle");
        assert_eq!(record.cwd, home);
        assert_eq!(
            reply,
            "[wn-opencode] The configured time limit ended this attempt. The backend session was saved; send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        );
        let recovery = recovery.get("group1").await.unwrap();
        assert_eq!(recovery.kind, RecoveryKind::PolicyLimit);
        assert_eq!(recovery.status, RecoveryStatus::Pending);
    }
}
