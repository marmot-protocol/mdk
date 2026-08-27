use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_control::{AgentControlAccount, AgentControlEvent, AgentControlMediaRef};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tracing::{debug, info, warn};

use crate::chunking::split_reply_chunks;
use crate::commands::{self, ChatCommand, Routed};
use crate::control::{ControlClient, DownloadedMedia};
use crate::error::{HarnessError, Result};
use crate::repo_picker::{RepoPicker, parse_repo_picker, resolve_repo, validate_session_cwd};
use crate::store::{
    FinalDeliveryRecord, FinalDeliveryStore, RecoveryKind, RecoveryRecord, RecoveryStatus,
    RecoveryStore, SessionRecord, SessionStore,
};
use crate::{
    Attachment, Backend, Config, Invocation, Outcome, RunFailure, RunnerEvent, TRACE_TARGET,
    dirs_home,
};

const DEDUPE_LIMIT: usize = 2048;
const GROUP_QUEUE_LIMIT: usize = 4096;
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const SEND_RETRY_ATTEMPTS: usize = 3;
const LIVENESS_UNKNOWN_TEXT: &str = "The backend is still running, but the connector cannot confirm progress. No action is needed; it will keep checking until the configured total limit.";
const TEXT_FINAL_ACK_UNKNOWN_TEXT: &str = "The backend finished, but the connector could not confirm delivery of its final response. No action is needed; it is reconciling delivery.";
const INCOMPLETE_FINAL_TEXT: &str = "The backend finished, but the connector could not persist the complete final response. Send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work.";

/// Connects to `wn-agent`, subscribes to allowed prompts, and runs the backend.
pub async fn run<B: Backend>(config: Config, backend: B) -> Result<()> {
    reconcile_attachment_staging(&config.attachment_staging_root)?;
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
        reconciliation_slot: ReconciliationSlot::new(),
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
    reconciliation_slot: ReconciliationSlot,
    queues: Arc<GroupQueues>,
    dedupe: Arc<InboundDedupe>,
    backend: Arc<dyn Backend>,
    home: PathBuf,
}

struct ReconciliationSlot {
    semaphore: Arc<Semaphore>,
}

impl ReconciliationSlot {
    fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(1)),
        }
    }

    fn try_enter(&self) -> Option<OwnedSemaphorePermit> {
        self.semaphore.clone().try_acquire_owned().ok()
    }

    #[cfg(test)]
    fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
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
                if let Some(permit) = ctx.reconciliation_slot.try_enter() {
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        reconcile_pending_deliveries(&ctx.client, &ctx.deliveries).await;
                    });
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
            let disposition = classify_prompt(&message.text);
            let permit = acquire_dispatch_permit(&ctx.queues, &group_id_hex, &disposition).await;
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
    media: Vec<AgentControlMediaRef>,
}

#[derive(Debug, PartialEq, Eq)]
enum PromptDisposition {
    ResetSession,
    RetryLast,
    DiscardLast,
    HarnessCommand(ChatCommand),
    Usage(&'static str),
    Forward {
        prompt: String,
        allow_workdir_picker: bool,
    },
}

fn classify_prompt(text: &str) -> PromptDisposition {
    match commands::route(text) {
        Routed::Command(ChatCommand::NewSession) => PromptDisposition::ResetSession,
        Routed::Command(ChatCommand::RetryLast) => PromptDisposition::RetryLast,
        Routed::Command(ChatCommand::DiscardLast) => PromptDisposition::DiscardLast,
        Routed::Command(command) => PromptDisposition::HarnessCommand(command),
        Routed::Usage(usage) => PromptDisposition::Usage(usage),
        Routed::Literal(prompt) => PromptDisposition::Forward {
            prompt,
            allow_workdir_picker: false,
        },
        Routed::Prompt(prompt) => PromptDisposition::Forward {
            prompt,
            allow_workdir_picker: true,
        },
    }
}

fn is_inspect_disposition(disposition: &PromptDisposition) -> bool {
    matches!(
        disposition,
        PromptDisposition::Usage(_)
            | PromptDisposition::HarnessCommand(
                ChatCommand::Help | ChatCommand::Status | ChatCommand::Pwd | ChatCommand::GoalShow
            )
    )
}

async fn acquire_dispatch_permit(
    queues: &GroupQueues,
    group_ref: &str,
    disposition: &PromptDisposition,
) -> Option<GroupPermit> {
    if matches!(
        disposition,
        PromptDisposition::RetryLast | PromptDisposition::DiscardLast
    ) || is_inspect_disposition(disposition)
    {
        queues.enter_without_waiter_quota(group_ref).await
    } else {
        queues.try_enter_waiter(group_ref).await
    }
}

async fn handle_message(ctx: Arc<BridgeContext>, inbound: InboundPrompt, mut permit: GroupPermit) {
    let mut inbound = inbound;
    let disposition = classify_prompt(&inbound.text);
    if is_inspect_disposition(&disposition) {
        match disposition {
            PromptDisposition::HarnessCommand(command) => {
                handle_command(&ctx, &inbound, command).await;
            }
            PromptDisposition::Usage(usage) => {
                send_command_reply(&ctx, &inbound, usage).await;
            }
            _ => unreachable!("inspect dispositions are read-only commands or usage"),
        }
        return;
    }
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
            handle_command(&ctx, &inbound, ChatCommand::NewSession).await;
            return;
        }
        PromptDisposition::HarnessCommand(command) => {
            handle_command(&ctx, &inbound, command).await;
            return;
        }
        PromptDisposition::Usage(usage) => {
            send_command_reply(&ctx, &inbound, usage).await;
            return;
        }
        PromptDisposition::DiscardLast => {
            let recovery = ctx.recovery.discard(&inbound.group_ref).await;
            let incomplete = ctx
                .deliveries
                .discard_incomplete_final(&inbound.group_ref)
                .await;
            if let Err(err) = &recovery {
                warn!(target: TRACE_TARGET, method = "discard_recovery", error_kind = err.privacy_safe_kind(), "failed to discard recovery record");
            }
            if let Err(err) = &incomplete {
                warn!(target: TRACE_TARGET, method = "discard_incomplete_final", error_kind = err.privacy_safe_kind(), "failed to discard incomplete-final barrier");
            }
            let message = match (recovery, incomplete) {
                (Err(_), _) | (_, Err(_)) => format!(
                    "[{}] Failed to discard the saved recovery.",
                    ctx.cfg.spec.reply_prefix
                ),
                (Ok(false), Ok(false)) => format!(
                    "[{}] There is no saved recovery to discard.",
                    ctx.cfg.spec.reply_prefix
                ),
                (Ok(recovery_cleared), Ok(_)) => {
                    if recovery_cleared {
                        permit
                            .queue
                            .recovery_changed
                            .send_modify(|generation| *generation = generation.wrapping_add(1));
                    }
                    format!(
                        "[{}] The saved recovery was discarded; queued work can continue.",
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
            let record = match begin_validated_retry(&ctx.recovery, &inbound.group_ref, &ctx.home)
                .await
            {
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
            inbound.media = record.media.clone();
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

    let goal = known_session
        .as_ref()
        .and_then(|record| record.goal.as_deref());
    let (recovery_prompt, prompt) = prepare_prompt(goal, prompt);

    info!(
        target: TRACE_TARGET,
        method = "handle_message",
        prompt_bytes = prompt.len(),
        has_session = known_session
            .as_ref()
            .is_some_and(|record| !record.session_id.is_empty()),
        has_goal = goal.is_some(),
        "handling inbound prompt"
    );

    let attachment_batch = match prepare_attachment_batch(&ctx, &inbound).await {
        Ok(batch) => batch,
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "prepare_attachments",
                error_kind = err.privacy_safe_kind(),
                attachment_count = inbound.media.len(),
                "failed to prepare inbound attachments"
            );
            let _ = send_reply(
                &ctx,
                &inbound.account_ref,
                &inbound.group_ref,
                &inbound.message_ref,
                &attachment_failure_reply(&ctx.cfg, &err),
                0,
            )
            .await;
            return;
        }
    };
    let attachments = attachment_batch
        .as_ref()
        .map_or_else(Vec::new, |batch| batch.attachments.clone());
    let invocation = Invocation {
        timeout: ctx.cfg.backend_timeout,
        idle_timeout: ctx.cfg.backend_idle_timeout,
        cwd: cwd.clone(),
        session_id,
        prompt,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let backend = ctx.backend.clone();
    let runner = tokio::spawn(async move {
        // The staging lease lives in the backend task so its paths cannot
        // disappear while that task still has access to them.
        let _attachment_batch = attachment_batch;
        backend
            .run_with_attachments(invocation, attachments, tx)
            .await
    });
    // Dropping a JoinHandle detaches its task. Abort explicitly when this
    // message handler is cancelled so the task drops its staging lease too.
    let _runner_abort = AbortBackendOnDrop(runner.abort_handle());
    let mut chunk_index = 0usize;
    let mut delivered_chunks = 0usize;
    let mut delivery_failed = false;
    let mut persist_failed = false;
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Text(text) => {
                let staged = match stage_text_chunks(
                    &FinalReplyTarget {
                        deliveries: &ctx.deliveries,
                        account_ref: &inbound.account_ref,
                        group_ref: &inbound.group_ref,
                        reply_to_ref: &inbound.message_ref,
                    },
                    &text,
                    ctx.cfg.max_reply_bytes,
                    &mut chunk_index,
                    &mut persist_failed,
                )
                .await
                {
                    Ok(staged) => staged,
                    Err(err) => {
                        warn!(target: TRACE_TARGET, method = "stage_final", error_kind = err.privacy_safe_kind(), "failed to persist incomplete-final barrier");
                        Vec::new()
                    }
                };
                if persist_failed {
                    delivery_failed = true;
                }
                if persist_failed || delivery_failed {
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
                chunk_index += 1;
                if let Err(err) = send_reply(
                    &ctx,
                    &inbound.account_ref,
                    &inbound.group_ref,
                    &inbound.message_ref,
                    &text,
                    chunk_index,
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
            if retrying && outcome.exit_code == Some(0) && !persist_failed {
                match ctx.recovery.discard(&inbound.group_ref).await {
                    Ok(_) => {
                        permit
                            .queue
                            .recovery_changed
                            .send_modify(|generation| *generation = generation.wrapping_add(1));
                    }
                    Err(err) => {
                        warn!(target: TRACE_TARGET, method = "discard_recovery", error_kind = err.privacy_safe_kind(), "failed to discard completed recovery record");
                        if let Err(reset_err) = ctx.recovery.reset_retry(&inbound.group_ref).await {
                            warn!(target: TRACE_TARGET, method = "retry_recovery", error_kind = reset_err.privacy_safe_kind(), "failed to restore retryable recovery state");
                        }
                    }
                }
                if let Err(err) = ctx
                    .deliveries
                    .discard_incomplete_final(&inbound.group_ref)
                    .await
                {
                    warn!(target: TRACE_TARGET, method = "discard_incomplete_final", error_kind = err.privacy_safe_kind(), "failed to discard incomplete-final barrier");
                }
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
                    persist_failed,
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
                inbound.media.clone(),
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

async fn begin_validated_retry(
    recovery: &RecoveryStore,
    group_ref: &str,
    home: &std::path::Path,
) -> Result<Option<RecoveryRecord>> {
    let Some(mut record) = recovery.begin_retry(group_ref).await? else {
        return Ok(None);
    };
    match validate_session_cwd(&record.cwd, home).await {
        Ok(cwd) => {
            record.cwd = cwd;
            Ok(Some(record))
        }
        Err(err) => {
            for attempt in 0..3 {
                match recovery.reset_retry(group_ref).await {
                    Ok(_) => return Err(err),
                    Err(reset_err) if attempt < 2 => {
                        warn!(target: TRACE_TARGET, method = "retry_recovery", error_kind = reset_err.privacy_safe_kind(), "retrying recovery-state restoration after workdir validation");
                        sleep(Duration::from_millis(50 * (attempt + 1))).await;
                    }
                    Err(reset_err) => return Err(reset_err),
                }
            }
            unreachable!("bounded retry loop always returns")
        }
    }
}

async fn fifo_is_blocked(ctx: &BridgeContext, group_ref: &str) -> bool {
    ctx.recovery.get(group_ref).await.is_some() || ctx.deliveries.blocks_group(group_ref).await
}

struct AttachmentBatch {
    _directory: tempfile::TempDir,
    attachments: Vec<Attachment>,
}

struct AbortBackendOnDrop(AbortHandle);

impl Drop for AbortBackendOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn validate_attachment_count(count: usize, maximum: usize) -> Result<()> {
    if count > maximum {
        return Err(HarnessError::AttachmentCountLimit);
    }
    Ok(())
}

fn add_attachment_bytes(current: u64, next: u64, maximum: u64) -> Result<u64> {
    let total = current
        .checked_add(next)
        .ok_or(HarnessError::AttachmentBytesLimit)?;
    if total > maximum {
        return Err(HarnessError::AttachmentBytesLimit);
    }
    Ok(total)
}

fn staged_attachment_name(index: usize, file_name: &str) -> String {
    let leaf = std::path::Path::new(file_name)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("attachment");
    let mut sanitized = String::with_capacity(leaf.len().min(128));
    for character in leaf.chars().take(128) {
        sanitized.push(
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            },
        );
    }
    let sanitized = sanitized.trim_matches(['.', '_']);
    let sanitized = if sanitized.is_empty() {
        "attachment"
    } else {
        sanitized
    };
    format!("{index:03}-{sanitized}")
}

fn reconcile_attachment_staging(root: &std::path::Path) -> Result<()> {
    fs_private::create_dir_all_private(root)?;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path())?;
        } else {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

async fn prepare_attachment_batch(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
) -> Result<Option<AttachmentBatch>> {
    validate_attachment_count(inbound.media.len(), ctx.cfg.max_attachments)?;
    if inbound.media.is_empty() {
        return Ok(None);
    }
    let directory = tempfile::Builder::new()
        .prefix("batch-")
        .tempdir_in(&ctx.cfg.attachment_staging_root)?;
    let mut attachments = Vec::with_capacity(inbound.media.len());
    let mut aggregate_bytes = 0_u64;
    for (index, media) in inbound.media.iter().cloned().enumerate() {
        let downloaded = ctx
            .client
            .download_media(&inbound.account_ref, &inbound.group_ref, media)
            .await?;
        aggregate_bytes = add_attachment_bytes(
            aggregate_bytes,
            downloaded.size_bytes,
            ctx.cfg.max_attachment_bytes,
        )?;
        attachments.push(stage_downloaded_attachment(
            directory.path(),
            index,
            downloaded,
        )?);
    }
    Ok(Some(AttachmentBatch {
        _directory: directory,
        attachments,
    }))
}

fn stage_downloaded_attachment(
    directory: &std::path::Path,
    index: usize,
    downloaded: DownloadedMedia,
) -> Result<Attachment> {
    let metadata =
        fs::symlink_metadata(&downloaded.path).map_err(|_| HarnessError::AttachmentInvalid)?;
    if !metadata.file_type().is_file() || !owner_can_read(&metadata) {
        return Err(HarnessError::AttachmentInvalid);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut source = options
        .open(&downloaded.path)
        .map_err(|_| HarnessError::AttachmentInvalid)?;
    let opened_metadata = source
        .metadata()
        .map_err(|_| HarnessError::AttachmentInvalid)?;
    if !opened_metadata.is_file()
        || !owner_can_read(&opened_metadata)
        || opened_metadata.len() != downloaded.size_bytes
    {
        return Err(HarnessError::AttachmentInvalid);
    }

    let file_name = staged_attachment_name(index, &downloaded.file_name);
    let destination_path = directory.join(&file_name);
    let mut destination = fs_private::create_new_private(&destination_path)?;
    let copied = {
        let mut bounded_source = (&mut source).take(downloaded.size_bytes);
        io::copy(&mut bounded_source, &mut destination)?
    };
    let mut extra = [0_u8; 1];
    let has_extra = source.read(&mut extra)? != 0;
    destination.sync_all()?;
    if copied != downloaded.size_bytes || has_extra {
        return Err(HarnessError::AttachmentInvalid);
    }
    Ok(Attachment {
        path: destination_path,
        media_type: downloaded.media_type,
        file_name,
        size_bytes: copied,
    })
}

#[cfg(unix)]
fn owner_can_read(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == unsafe { libc::geteuid() } && metadata.mode() & 0o400 != 0
}

#[cfg(not(unix))]
fn owner_can_read(_metadata: &fs::Metadata) -> bool {
    true
}

fn attachment_failure_reply(config: &Config, error: &HarnessError) -> String {
    let detail = match error {
        HarnessError::AttachmentCountLimit => "too many attachments",
        HarnessError::AttachmentBytesLimit => "the attachment batch is too large",
        HarnessError::AttachmentUnsupported => "one or more attachment types are unsupported",
        _ => "an attachment could not be downloaded and validated",
    };
    format!(
        "[{}] could not process this turn because {detail}; no backend turn was started.",
        config.spec.reply_prefix
    )
}

async fn handle_command(ctx: &BridgeContext, inbound: &InboundPrompt, command: ChatCommand) {
    let record = ctx.sessions.get(&inbound.group_ref).await;
    let body =
        match command {
            ChatCommand::Help => commands::help_text(ctx.cfg.spec.display_name),
            ChatCommand::Status => status_text(ctx, record.as_ref()),
            ChatCommand::Pwd => match record.as_ref().and_then(|record| record.cwd.as_deref()) {
                Some(cwd) => format!("Working directory: {}", display_home_path(cwd, &ctx.home)),
                None => "No working directory is selected yet. Use `/cd <path>`.".to_owned(),
            },
            ChatCommand::NewSession => new_session_body(ctx, inbound).await,
            ChatCommand::Cd { path } => {
                change_workdir_body(ctx, inbound, record.as_ref(), &path).await
            }
            ChatCommand::GoalShow => {
                match record.as_ref().and_then(|record| record.goal.as_deref()) {
                    Some(goal) => format!("Standing goal:\n{goal}"),
                    None => "No standing goal is set. Use `/goal <text>`.".to_owned(),
                }
            }
            ChatCommand::GoalClear => match set_goal(ctx, &inbound.group_ref, None).await {
                Ok(()) => "Standing goal cleared.".to_owned(),
                Err(()) => "Failed to clear the standing goal.".to_owned(),
            },
            ChatCommand::GoalSet { text } => {
                match set_goal(ctx, &inbound.group_ref, Some(text)).await {
                    Ok(()) => {
                        "Standing goal set. It is prepended to every prompt in this chat until you send `/goal clear`."
                            .to_owned()
                    }
                    Err(()) => "Failed to set the standing goal.".to_owned(),
                }
            }
            ChatCommand::RetryLast | ChatCommand::DiscardLast => {
                unreachable!("recovery commands are handled before generic command dispatch")
            }
        };
    send_command_reply(ctx, inbound, &body).await;
}

async fn new_session_body(ctx: &BridgeContext, inbound: &InboundPrompt) -> String {
    match ctx.sessions.reset_session(&inbound.group_ref).await {
        Ok(true) => format!(
            "Session reset. The next prompt will start a new {} session in the preserved workdir.",
            ctx.cfg.spec.display_name
        ),
        Ok(false) => format!(
            "No {} session is recorded for this chat.",
            ctx.cfg.spec.display_name
        ),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "session_reset",
                error_kind = err.privacy_safe_kind(),
                "failed to reset backend session"
            );
            format!("Failed to reset the {} session.", ctx.cfg.spec.display_name)
        }
    }
}

async fn change_workdir_body(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
    record: Option<&SessionRecord>,
    path: &str,
) -> String {
    let cwd = match resolve_repo(path, &ctx.home).await {
        Ok(cwd) => cwd,
        Err(err) => return err.to_string(),
    };
    let had_session = record.is_some_and(|record| !record.session_id.is_empty());
    match ctx.sessions.set_workdir(&inbound.group_ref, cwd).await {
        Ok(()) if had_session => format!(
            "Working directory set to ~/{path}. The previous {} session was ended; the next prompt starts a new one.",
            ctx.cfg.spec.display_name
        ),
        Ok(()) => format!("Working directory set to ~/{path}. Send your prompt."),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "set_workdir",
                error_kind = err.privacy_safe_kind(),
                "failed to record selected workdir"
            );
            "Failed to set the working directory.".to_owned()
        }
    }
}

async fn set_goal(
    ctx: &BridgeContext,
    group_ref: &str,
    goal: Option<String>,
) -> std::result::Result<(), ()> {
    ctx.sessions.set_goal(group_ref, goal).await.map_err(|err| {
        warn!(
            target: TRACE_TARGET,
            method = "set_goal",
            error_kind = err.privacy_safe_kind(),
            "failed to record standing goal"
        );
    })
}

fn status_text(ctx: &BridgeContext, record: Option<&SessionRecord>) -> String {
    let workdir = match record.and_then(|record| record.cwd.as_deref()) {
        Some(cwd) => display_home_path(cwd, &ctx.home),
        None => "not selected".to_owned(),
    };
    let session = if record.is_some_and(|record| !record.session_id.is_empty()) {
        "active"
    } else {
        "none"
    };
    let goal = record
        .and_then(|record| record.goal.as_deref())
        .unwrap_or("none");
    format!(
        "backend: {}\nworkdir: {workdir}\nsession: {session}\nexecution profile: {}\ngoal: {goal}",
        ctx.cfg.spec.display_name,
        ctx.cfg.execution_profile.as_str()
    )
}

fn prepare_prompt(goal: Option<&str>, prompt: String) -> (String, String) {
    // Recovery persists the original user prompt. Persisting the expanded form
    // would prepend a standing goal again when `/retry-last` re-enters this path.
    let recovery_prompt = prompt.clone();
    let invocation_prompt = match goal {
        Some(goal) => commands::apply_goal(goal, &prompt),
        None => prompt,
    };
    (recovery_prompt, invocation_prompt)
}

/// Renders a stored workdir as a `$HOME`-relative display path for chat replies.
fn display_home_path(cwd: &std::path::Path, home: &std::path::Path) -> String {
    match cwd.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_owned(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => "outside $HOME".to_owned(),
    }
}

async fn send_command_reply(ctx: &BridgeContext, inbound: &InboundPrompt, body: &str) {
    let text = format!("[{}] {body}", ctx.cfg.spec.reply_prefix);
    for (index, chunk) in split_reply_chunks(&text, ctx.cfg.max_reply_bytes)
        .into_iter()
        .enumerate()
    {
        if let Err(err) = send_reply(
            ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            chunk,
            index,
        )
        .await
        {
            warn!(
                target: TRACE_TARGET,
                method = "command_reply",
                error_kind = err.privacy_safe_kind(),
                "failed to send harness command reply"
            );
            return;
        }
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
                inbound.media.clone(),
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
    } else if completion_route == CompletionRoute::IncompleteFinal {
        let session_id = outcome
            .observed_session
            .clone()
            .or_else(|| {
                known_session
                    .as_ref()
                    .map(|record| record.session_id.clone())
            })
            .filter(|value| !value.is_empty());
        if let Some(session_id) = session_id
            && let Err(err) = persist_recovery_record(
                &ctx.recovery,
                &inbound.group_ref,
                recovery_prompt,
                inbound.media.clone(),
                cwd,
                session_id,
                RecoveryKind::UncertainOutcome,
            )
            .await
        {
            warn!(target: TRACE_TARGET, method = "recovery_store", error_kind = err.privacy_safe_kind(), "failed to persist recovery record");
        }
        let _ = send_reply(
            &ctx,
            &inbound.account_ref,
            &inbound.group_ref,
            &inbound.message_ref,
            &format!("[{}] {INCOMPLETE_FINAL_TEXT}", ctx.cfg.spec.reply_prefix),
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
    persist_failed: bool,
    status_chunk_index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionRoute {
    NonzeroExit,
    IncompleteFinal,
    TextFinalAckUnknown,
    NoText,
    Complete,
}

fn completion_route(outcome: &Outcome, delivery: &DeliveryReport) -> CompletionRoute {
    if outcome.exit_code != Some(0) {
        CompletionRoute::NonzeroExit
    } else if delivery.persist_failed {
        CompletionRoute::IncompleteFinal
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
    media: Vec<AgentControlMediaRef>,
    cwd: PathBuf,
    session_id: String,
    kind: RecoveryKind,
) -> Result<()> {
    recovery
        .set(
            group_ref,
            RecoveryRecord {
                prompt,
                media,
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
    media: Vec<AgentControlMediaRef>,
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
                    media,
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
        HarnessError::AttachmentUnsupported => format!(
            "[{}] {} does not support this attachment batch; no backend turn was started.",
            config.spec.reply_prefix, config.spec.display_name
        ),
        _ => {
            if let Some(session_id) = resumable_session {
                if let Err(err) = persist_recovery_record(
                    recovery,
                    group_ref,
                    prompt,
                    media,
                    cwd,
                    session_id,
                    RecoveryKind::UncertainOutcome,
                )
                .await
                {
                    warn!(target: TRACE_TARGET, method = "recovery_store", error_kind = err.privacy_safe_kind(), "failed to persist recovery record");
                    format!(
                        "[{}] The backend exited and this attempt cannot be resumed. Send a new prompt or `/reset-session`.",
                        config.spec.reply_prefix
                    )
                } else {
                    recovery_resolution_message(
                        config.spec.reply_prefix,
                        RecoveryKind::UncertainOutcome,
                    )
                }
            } else {
                format!(
                    "[{}] {} failed while streaming its response.",
                    config.spec.reply_prefix, config.spec.display_name
                )
            }
        }
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
        sessions.record_session(group_ref, session_id, cwd).await?;
    }
    Ok(())
}

async fn resolve_cwd_and_prompt(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
    known_session: Option<&SessionRecord>,
    allow_workdir_picker: bool,
) -> Result<Option<(PathBuf, String)>> {
    if let Some(selected) = known_session.and_then(|record| record.cwd.as_deref()) {
        let cwd = validate_session_cwd(selected, &ctx.home).await?;
        return Ok(Some((cwd, inbound.text.clone())));
    }
    if !allow_workdir_picker {
        return Ok(Some((ctx.home.clone(), inbound.text.clone())));
    }

    let (name, rest) = match parse_repo_picker(&inbound.text) {
        RepoPicker::Absent => return Ok(Some((ctx.home.clone(), inbound.text.clone()))),
        RepoPicker::Invalid => {
            send_command_reply(
                ctx,
                inbound,
                "Invalid workdir picker. Use /<path> with non-empty path segments containing only ASCII letters, digits, '.', '_', or '-'. Do not use '.' or '..' segments. Send /help for the harness commands.",
            )
            .await;
            return Ok(None);
        }
        RepoPicker::Valid { path, prompt } => (path, prompt),
    };
    let cwd = match resolve_repo(&name, &ctx.home).await {
        Ok(cwd) => cwd,
        Err(err) => {
            send_command_reply(
                ctx,
                inbound,
                &format!("{err} Send /help for the harness commands."),
            )
            .await;
            return Ok(None);
        }
    };
    if rest.is_empty() {
        ctx.sessions.set_workdir(&inbound.group_ref, cwd).await?;
        send_command_reply(
            ctx,
            inbound,
            &format!("Session workdir set to ~/{name}. Send your prompt."),
        )
        .await;
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
    for (key, record) in store.list_reconcilable().await {
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

struct FinalReplyTarget<'a> {
    deliveries: &'a FinalDeliveryStore,
    account_ref: &'a str,
    group_ref: &'a str,
    reply_to_ref: &'a str,
}

async fn stage_text_chunks(
    target: &FinalReplyTarget<'_>,
    text: &str,
    max_reply_bytes: usize,
    chunk_index: &mut usize,
    persist_failed: &mut bool,
) -> Result<Vec<(String, String, usize)>> {
    if *persist_failed {
        return Ok(Vec::new());
    }
    let mut staged = Vec::new();
    for chunk in split_reply_chunks(text, max_reply_bytes) {
        *chunk_index += 1;
        match stage_delivery_record(
            target.deliveries,
            target.account_ref,
            target.group_ref,
            target.reply_to_ref,
            chunk,
            *chunk_index,
        )
        .await
        {
            Ok(key) => staged.push((key, chunk.to_owned(), *chunk_index)),
            Err(err) => {
                warn!(target: TRACE_TARGET, method = "stage_final", error_kind = err.privacy_safe_kind(), "failed to persist backend reply chunk");
                *persist_failed = true;
                target
                    .deliveries
                    .mark_incomplete_final(target.group_ref, target.reply_to_ref)
                    .await?;
                break;
            }
        }
    }
    Ok(staged)
}

async fn stage_delivery_record(
    deliveries: &FinalDeliveryStore,
    account_ref: &str,
    group_ref: &str,
    reply_to_ref: &str,
    text: &str,
    chunk_index: usize,
) -> Result<String> {
    let key = format!("{group_ref}:{reply_to_ref}:{chunk_index}");
    deliveries
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

    /// Admits inspect and recovery commands without consuming the waiting quota
    /// or taking the serial lock.
    async fn enter_without_waiter_quota(&self, group_ref: &str) -> Option<GroupPermit> {
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
    use agent_control::{
        AgentControlEnvelope, AgentControlRequest, AgentControlResponse,
        AgentControlSendMaintenanceDisposition, read_envelope, write_frame,
    };
    use async_trait::async_trait;
    use tokio::io::BufReader;
    use tokio::net::UnixListener;

    #[test]
    fn attachment_names_are_sanitized_and_keep_stable_ordering() {
        assert_eq!(
            staged_attachment_name(0, "../../screen shot.PNG"),
            "000-screen_shot.PNG"
        );
        assert_eq!(
            staged_attachment_name(1, "\u{0000}\u{0001}"),
            "001-attachment"
        );
    }

    #[test]
    fn attachment_count_limit_rejects_before_download() {
        assert!(validate_attachment_count(8, 8).is_ok());
        let error = validate_attachment_count(9, 8).unwrap_err();
        assert_eq!(error.privacy_safe_kind(), "attachment_count_limit");
    }

    #[test]
    fn attachment_byte_limit_is_checked_without_overflow() {
        assert_eq!(add_attachment_bytes(3, 4, 7).unwrap(), 7);
        assert!(matches!(
            add_attachment_bytes(4, 4, 7),
            Err(HarnessError::AttachmentBytesLimit)
        ));
        assert!(matches!(
            add_attachment_bytes(u64::MAX, 1, u64::MAX),
            Err(HarnessError::AttachmentBytesLimit)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn downloaded_files_are_copied_privately_and_batch_drop_cleans_them() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let borrowed = root.path().join("borrowed.png");
        fs_private::write_private(&borrowed, b"image-one").unwrap();
        let staging = root.path().join("staging");
        reconcile_attachment_staging(&staging).unwrap();
        let directory = tempfile::Builder::new()
            .prefix("batch-")
            .tempdir_in(&staging)
            .unwrap();
        let batch_path = directory.path().to_path_buf();
        let first = stage_downloaded_attachment(
            directory.path(),
            0,
            DownloadedMedia {
                path: borrowed,
                media_type: "image/png".to_owned(),
                file_name: "../first image.png".to_owned(),
                size_bytes: 9,
            },
        )
        .unwrap();
        assert_eq!(first.file_name, "000-first_image.png");
        assert_eq!(fs::read(&first.path).unwrap(), b"image-one");
        assert_eq!(
            fs::metadata(&first.path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(directory);
        assert!(!batch_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_symlink_sources_and_restart_removes_stale_batches() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let borrowed = root.path().join("borrowed.txt");
        fs_private::write_private(&borrowed, b"private").unwrap();
        let link = root.path().join("link.txt");
        symlink(&borrowed, &link).unwrap();
        let fifo = root.path().join("pipe");
        {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let fifo_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
        }
        let staging = root.path().join("staging");
        reconcile_attachment_staging(&staging).unwrap();
        let stale = staging.join("batch-stale");
        fs_private::create_dir_all_private(&stale).unwrap();
        fs_private::write_private(&stale.join("copy"), b"private").unwrap();
        assert!(matches!(
            stage_downloaded_attachment(
                &staging,
                0,
                DownloadedMedia {
                    path: link,
                    media_type: "text/plain".to_owned(),
                    file_name: "link.txt".to_owned(),
                    size_bytes: 7,
                },
            ),
            Err(HarnessError::AttachmentInvalid)
        ));
        assert!(matches!(
            stage_downloaded_attachment(
                &staging,
                1,
                DownloadedMedia {
                    path: fifo,
                    media_type: "application/octet-stream".to_owned(),
                    file_name: "pipe".to_owned(),
                    size_bytes: 0,
                },
            ),
            Err(HarnessError::AttachmentInvalid)
        ));
        reconcile_attachment_staging(&staging).unwrap();
        assert!(fs::read_dir(staging).unwrap().next().is_none());
    }

    #[tokio::test]
    async fn abort_guard_cancels_detached_backend_task() {
        let runner = tokio::spawn(std::future::pending::<()>());
        let guard = AbortBackendOnDrop(runner.abort_handle());
        drop(guard);
        assert!(runner.await.unwrap_err().is_cancelled());
    }

    fn test_config(root: &std::path::Path) -> Config {
        Config {
            socket: root.join("socket"),
            auth_token: None,
            allowed_senders: HashSet::new(),
            account_id_hex: None,
            request_timeout: Duration::from_secs(1),
            max_reply_bytes: 30_000,
            max_pending_per_group: 4,
            max_attachments: 8,
            max_attachment_bytes: 64 * 1024 * 1024,
            attachment_staging_root: root.join("attachments"),
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

    #[derive(Default)]
    struct RecordingBackend {
        invocations: Mutex<Vec<Invocation>>,
    }

    #[async_trait]
    impl Backend for RecordingBackend {
        async fn run(
            &self,
            invocation: Invocation,
            _tx: mpsc::Sender<RunnerEvent>,
        ) -> std::result::Result<Outcome, RunFailure> {
            self.invocations.lock().await.push(invocation);
            Ok(Outcome {
                observed_session: None,
                exit_code: Some(0),
                error_summary: None,
                no_side_effects_proven: false,
                stderr: String::new(),
                elapsed_ms: 1,
            })
        }
    }

    fn spawn_final_server(socket: &std::path::Path) -> tokio::task::JoinHandle<()> {
        let listener = UnixListener::bind(socket).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                let request: AgentControlEnvelope<AgentControlRequest> =
                    read_envelope(&mut reader).await.unwrap().unwrap();
                assert!(matches!(
                    request.payload,
                    AgentControlRequest::SendFinal { .. }
                ));
                let response = AgentControlEnvelope::request(
                    request.id,
                    AgentControlResponse::FinalSent {
                        message_ids_hex: vec!["reply".to_owned()],
                        maintenance_disposition: AgentControlSendMaintenanceDisposition::Ready,
                    },
                );
                write_frame(&mut write_half, &response).await.unwrap();
            }
        })
    }

    fn test_context(
        root: &std::path::Path,
        home: &std::path::Path,
        backend: Arc<RecordingBackend>,
    ) -> (Arc<BridgeContext>, tokio::task::JoinHandle<()>) {
        std::fs::create_dir_all(home).unwrap();
        let config = test_config(root);
        let server = spawn_final_server(&config.socket);
        let sessions = Arc::new(SessionStore::load(config.state_path.clone(), home).unwrap());
        let recovery = Arc::new(
            RecoveryStore::load(config.state_path.with_extension("recovery.json")).unwrap(),
        );
        let deliveries = Arc::new(
            FinalDeliveryStore::load(config.state_path.with_extension("delivery.json")).unwrap(),
        );
        let ctx = Arc::new(BridgeContext {
            client: ControlClient::new(
                config.socket.clone(),
                None,
                Duration::from_secs(1),
                "wn-test",
            ),
            cfg: Arc::new(config),
            account_ref: "account".to_owned(),
            sessions,
            recovery,
            deliveries,
            reconciliation_slot: ReconciliationSlot::new(),
            queues: Arc::new(GroupQueues::new(4)),
            dedupe: Arc::new(InboundDedupe::new(8)),
            backend,
            home: home.to_path_buf(),
        });
        (ctx, server)
    }

    async fn dispatch_test_message(ctx: Arc<BridgeContext>, message_ref: &str, text: &str) -> bool {
        let disposition = classify_prompt(text);
        let Some(permit) = acquire_dispatch_permit(&ctx.queues, "group", &disposition).await else {
            return false;
        };
        handle_message(
            ctx,
            InboundPrompt {
                account_ref: "account".to_owned(),
                group_ref: "group".to_owned(),
                message_ref: message_ref.to_owned(),
                text: text.to_owned(),
                media: Vec::new(),
            },
            permit,
        )
        .await;
        true
    }

    #[tokio::test]
    async fn dedupe_rejects_repeated_message_refs() {
        let dedupe = InboundDedupe::new(8);
        assert!(dedupe.insert("m1".to_owned()).await);
        assert!(!dedupe.insert("m1".to_owned()).await);
        assert!(dedupe.insert("m2".to_owned()).await);
    }

    #[test]
    fn reconnect_while_reconciliation_is_pending_keeps_maximum_concurrency_one() {
        let slot = ReconciliationSlot::new();

        let old_drain = slot.try_enter().expect("first drain starts reconciliation");
        assert_eq!(slot.available_permits(), 0);
        assert!(
            slot.try_enter().is_none(),
            "a reconnecting drain must share the process-lifetime reconciliation guard"
        );

        drop(old_drain);
        assert_eq!(slot.available_permits(), 1);
        assert!(slot.try_enter().is_some());
    }

    #[tokio::test]
    async fn bridge_commands_and_usage_never_invoke_backend_or_picker() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let backend = Arc::new(RecordingBackend::default());
        let (ctx, server) = test_context(root.path(), &home, backend.clone());

        dispatch_test_message(ctx.clone(), "help", "/help").await;
        dispatch_test_message(ctx.clone(), "bad-cd", "/cd a b").await;
        dispatch_test_message(ctx.clone(), "bad-retry", "/retry-last please").await;
        dispatch_test_message(ctx.clone(), "session-status", "/session-status").await;

        assert!(backend.invocations.lock().await.is_empty());
        assert!(ctx.sessions.get("group").await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn inspect_commands_reply_while_recovery_fifo_is_blocked() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let repo = home.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let backend = Arc::new(RecordingBackend::default());
        let (ctx, server) = test_context(root.path(), &home, backend.clone());
        ctx.recovery
            .set(
                "group",
                RecoveryRecord {
                    prompt: "private prompt".to_owned(),
                    cwd: repo.clone(),
                    session_id: "session".to_owned(),
                    media: Vec::new(),
                    kind: RecoveryKind::UncertainOutcome,
                    status: RecoveryStatus::Pending,
                },
            )
            .await
            .unwrap();
        assert!(fifo_is_blocked(&ctx, "group").await);
        let mut waiters = Vec::new();
        while let Some(permit) = ctx.queues.try_enter_waiter("group").await {
            waiters.push(permit);
        }
        assert!(
            !waiters.is_empty(),
            "queued prompts must be able to exhaust the waiter quota"
        );

        for (message_ref, text) in [
            ("help", "/help"),
            ("status", "/status"),
            ("pwd", "/pwd"),
            ("goal-show", "/goal"),
        ] {
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(500),
                    dispatch_test_message(ctx.clone(), message_ref, text),
                )
                .await
                .expect("inspect command must not wait on recovery or waiter quota")
            );
        }

        assert!(backend.invocations.lock().await.is_empty());
        assert!(
            !dispatch_test_message(ctx.clone(), "cd-full", "/cd repo").await,
            "mutating commands must not steal a waiter while the quota is full"
        );
        drop(waiters);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                dispatch_test_message(ctx.clone(), "cd", "/cd repo"),
            )
            .await
            .is_err(),
            "mutating commands still wait on the recovery FIFO"
        );
        assert!(ctx.sessions.get("group").await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn bridge_literal_and_goal_invoke_backend_once_with_exact_prompt() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let repo = home.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let backend = Arc::new(RecordingBackend::default());
        let (ctx, server) = test_context(root.path(), &home, backend.clone());
        ctx.sessions
            .set_workdir("group", repo.canonicalize().unwrap())
            .await
            .unwrap();

        dispatch_test_message(ctx.clone(), "literal", "  //status \n").await;
        dispatch_test_message(ctx.clone(), "set-goal", "/goal finish the migration").await;
        dispatch_test_message(ctx.clone(), "prompt", "check status").await;

        let invocations = backend.invocations.lock().await;
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].prompt, "  /status \n");
        assert_eq!(
            invocations[1].prompt,
            commands::apply_goal("finish the migration", "check status")
        );
        assert_eq!(
            invocations[1]
                .prompt
                .matches("Standing goal for this chat")
                .count(),
            1
        );
        drop(invocations);
        server.abort();
    }

    #[tokio::test]
    async fn group_queue_enforces_waiting_limit_but_recovery_bypasses_it() {
        let queues = GroupQueues::new(1);
        let first = queues.try_enter_waiter("g").await;
        assert!(first.is_some());
        assert_eq!(first.as_ref().unwrap().queue.pending.available_permits(), 1);
        assert!(queues.try_enter_waiter("g").await.is_none());
        let inspect = queues.enter_without_waiter_quota("g").await;
        assert!(inspect.is_some());
        drop(inspect);
        let recovery = queues.enter_without_waiter_quota("g").await;
        assert!(recovery.is_some());
        drop(recovery);
        drop(first);
        assert!(queues.try_enter_waiter("g").await.is_some());
    }

    #[test]
    fn reset_command_is_reserved_and_has_a_literal_escape() {
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
            PromptDisposition::Usage("`/reset-session` takes no arguments.")
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
            PromptDisposition::HarnessCommand(ChatCommand::GoalSet {
                text: "retry-last".to_owned(),
            })
        );
        assert_eq!(
            classify_prompt("/retry-last please"),
            PromptDisposition::Usage("`/retry-last` takes no arguments.")
        );
    }

    #[test]
    fn recovery_reapplies_a_standing_goal_exactly_once() {
        let (persisted, first_invocation) =
            prepare_prompt(Some("finish the migration"), "check status".to_owned());
        let (persisted_again, retry_invocation) =
            prepare_prompt(Some("finish the migration"), persisted.clone());

        assert_eq!(persisted, "check status");
        assert_eq!(persisted_again, "check status");
        assert_eq!(retry_invocation, first_invocation);
        assert_eq!(
            retry_invocation
                .matches("Standing goal for this chat")
                .count(),
            1
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
            persist_failed: false,
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
        let signal_terminated = Outcome {
            observed_session: Some("session".to_owned()),
            exit_code: None,
            error_summary: Some("terminated".to_owned()),
            no_side_effects_proven: true,
            stderr: String::new(),
            elapsed_ms: 1,
        };
        assert_eq!(
            completion_route(&signal_terminated, &failed_delivery),
            CompletionRoute::NonzeroExit
        );

        let completed = Outcome {
            exit_code: Some(0),
            ..proven
        };
        assert_eq!(
            completion_route(&completed, &failed_delivery),
            CompletionRoute::TextFinalAckUnknown
        );

        let persist_failed = DeliveryReport {
            persist_failed: true,
            ..failed_delivery
        };
        assert_eq!(
            completion_route(&completed, &persist_failed),
            CompletionRoute::IncompleteFinal
        );
        let persist_failed_nonzero = Outcome {
            no_side_effects_proven: false,
            exit_code: Some(64),
            observed_session: Some("session".to_owned()),
            error_summary: Some("failed".to_owned()),
            stderr: String::new(),
            elapsed_ms: 1,
        };
        assert_eq!(
            completion_route(&persist_failed_nonzero, &persist_failed),
            CompletionRoute::NonzeroExit
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
            Vec::new(),
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
        assert_eq!(
            INCOMPLETE_FINAL_TEXT,
            "The backend finished, but the connector could not persist the complete final response. Send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        );
        assert!(!INCOMPLETE_FINAL_TEXT.contains("No action is needed"));
        assert!(!INCOMPLETE_FINAL_TEXT.contains("reconciling delivery"));
        assert!(INCOMPLETE_FINAL_TEXT.contains("/retry-last"));
        assert!(INCOMPLETE_FINAL_TEXT.contains("/discard-last"));
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

        let recovery = queues.enter_without_waiter_quota("g").await.unwrap();
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
        assert_eq!(record.cwd.as_deref(), Some(cwd.as_path()));

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
            .record_session("group1", "ses_old".to_owned(), cwd.clone())
            .await
            .unwrap();
        store
            .set_goal("group1", Some("keep the workdir".to_owned()))
            .await
            .unwrap();
        assert!(store.reset_session("group1").await.unwrap());

        let reset_record = store.get("group1").await.unwrap();
        persist_observed_session_if_unset(
            &store,
            "group1",
            Some(&reset_record),
            reset_record.cwd.clone().unwrap(),
            Some("ses_new".to_owned()),
        )
        .await
        .unwrap();

        let current = store.get("group1").await.unwrap();
        assert_eq!(current.session_id, "ses_new");
        assert_eq!(current.cwd.as_deref(), Some(cwd.as_path()));
        assert_eq!(current.goal.as_deref(), Some("keep the workdir"));
    }

    #[tokio::test]
    async fn retry_validation_canonicalizes_inside_home_and_restores_invalid_record() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("repo")).unwrap();
        let recovery = RecoveryStore::load(dir.path().join("recovery.json")).unwrap();
        let record = RecoveryRecord {
            prompt: "private prompt".to_owned(),
            media: Vec::new(),
            cwd: home.join("repo").join("..").join("repo"),
            session_id: "session".to_owned(),
            kind: RecoveryKind::PolicyLimit,
            status: RecoveryStatus::Pending,
        };
        recovery.set("valid", record.clone()).await.unwrap();

        let validated = begin_validated_retry(&recovery, "valid", &home)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(validated.cwd, home.join("repo").canonicalize().unwrap());
        assert_eq!(validated.status, RecoveryStatus::Retrying);

        recovery
            .set(
                "invalid",
                RecoveryRecord {
                    cwd: home.join("missing"),
                    ..record
                },
            )
            .await
            .unwrap();
        assert!(
            begin_validated_retry(&recovery, "invalid", &home)
                .await
                .is_err()
        );
        assert_eq!(
            recovery.get("invalid").await.unwrap().status,
            RecoveryStatus::Pending
        );
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
            Vec::new(),
            &failure,
        )
        .await;

        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_idle");
        assert_eq!(record.cwd.as_deref(), Some(home.as_path()));
        assert_eq!(
            reply,
            "[wn-opencode] The configured time limit ended this attempt. The backend session was saved; send `/retry-last` to retry it, or `/discard-last` to abandon it and continue queued work."
        );
        let recovery = recovery.get("group1").await.unwrap();
        assert_eq!(recovery.kind, RecoveryKind::PolicyLimit);
        assert_eq!(recovery.status, RecoveryStatus::Pending);
    }

    struct UnusedBackend;

    #[async_trait::async_trait]
    impl Backend for UnusedBackend {
        async fn run(
            &self,
            _invocation: Invocation,
            _tx: mpsc::Sender<RunnerEvent>,
        ) -> std::result::Result<Outcome, RunFailure> {
            Err(RunFailure {
                error: HarnessError::BackendStream,
                observed_session: None,
            })
        }
    }

    #[tokio::test]
    async fn default_backend_rejects_non_empty_attachment_batch_without_running() {
        let root = tempfile::tempdir().unwrap();
        let invocation = Invocation {
            timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            cwd: root.path().to_path_buf(),
            session_id: Some("existing-session".to_owned()),
            prompt: "text accompanying a file".to_owned(),
        };
        let attachment = Attachment {
            path: root.path().join("staged.png"),
            media_type: "image/png".to_owned(),
            file_name: "000-staged.png".to_owned(),
            size_bytes: 1,
        };
        let (tx, _rx) = mpsc::channel(1);

        let failure = UnusedBackend
            .run_with_attachments(invocation, vec![attachment], tx)
            .await
            .unwrap_err();

        assert!(matches!(failure.error, HarnessError::AttachmentUnsupported));
        assert_eq!(
            failure.observed_session.as_deref(),
            Some("existing-session")
        );
    }

    fn test_bridge_context(root: &std::path::Path) -> BridgeContext {
        let cfg = test_config(root);
        BridgeContext {
            cfg: Arc::new(cfg.clone()),
            client: ControlClient::new(
                cfg.socket.clone(),
                None,
                cfg.request_timeout,
                cfg.spec.reply_prefix,
            ),
            account_ref: "account".to_owned(),
            sessions: Arc::new(SessionStore::load(root.join("sessions.json"), root).unwrap()),
            recovery: Arc::new(RecoveryStore::load(root.join("recovery.json")).unwrap()),
            deliveries: Arc::new(FinalDeliveryStore::load(root.join("delivery.json")).unwrap()),
            reconciliation_slot: ReconciliationSlot::new(),
            queues: Arc::new(GroupQueues::new(4)),
            dedupe: Arc::new(InboundDedupe::new(8)),
            backend: Arc::new(UnusedBackend),
            home: root.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn incomplete_final_persist_failure_raises_discardable_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = test_bridge_context(dir.path());
        let mut chunk_index = 0usize;
        let mut persist_failed = false;

        let target = FinalReplyTarget {
            deliveries: &ctx.deliveries,
            account_ref: "account",
            group_ref: "group",
            reply_to_ref: "message",
        };
        let first = stage_text_chunks(&target, "aaaa", 4, &mut chunk_index, &mut persist_failed)
            .await
            .unwrap();
        assert_eq!(first.len(), 1);
        assert!(!persist_failed);

        ctx.deliveries.fail_next_set();
        let second = stage_text_chunks(
            &target,
            "bbbbcccc",
            4,
            &mut chunk_index,
            &mut persist_failed,
        )
        .await
        .unwrap();
        assert!(persist_failed);
        assert!(second.is_empty());

        let later = stage_text_chunks(&target, "dddd", 4, &mut chunk_index, &mut persist_failed)
            .await
            .unwrap();
        assert!(later.is_empty());

        let records = ctx.deliveries.list().await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1.chunk_index, 1);
        assert_eq!(records[0].1.text, "aaaa");
        assert!(ctx.deliveries.list_reconcilable().await.is_empty());
        assert!(fifo_is_blocked(&ctx, "group").await);

        ctx.deliveries.remove(&records[0].0).await.unwrap();
        assert!(
            !ctx.deliveries.has_group("group").await,
            "barrier must outlive removed delivery records"
        );
        assert!(fifo_is_blocked(&ctx, "group").await);
        assert!(ctx.deliveries.list_reconcilable().await.is_empty());

        let copy = format!("[{}] {INCOMPLETE_FINAL_TEXT}", ctx.cfg.spec.reply_prefix);
        assert!(!copy.contains(TEXT_FINAL_ACK_UNKNOWN_TEXT));
        assert!(!copy.contains("No action is needed"));
        assert!(copy.contains("/retry-last"));
        assert!(copy.contains("/discard-last"));
        assert_eq!(
            completion_route(
                &Outcome {
                    observed_session: Some("session".to_owned()),
                    exit_code: Some(0),
                    error_summary: None,
                    no_side_effects_proven: true,
                    stderr: String::new(),
                    elapsed_ms: 1,
                },
                &DeliveryReport {
                    chunk_count: 1,
                    failed: true,
                    persist_failed: true,
                    status_chunk_index: 3,
                },
            ),
            CompletionRoute::IncompleteFinal
        );

        assert!(
            ctx.deliveries
                .discard_incomplete_final("group")
                .await
                .unwrap()
        );
        assert!(!fifo_is_blocked(&ctx, "group").await);
        assert!(ctx.deliveries.list().await.is_empty());
    }

    #[tokio::test]
    async fn post_spawn_stream_failure_persists_uncertain_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        std::fs::create_dir_all(home.join("repo")).unwrap();
        let store = SessionStore::load(home.join("sessions.json"), &home).unwrap();
        let recovery = RecoveryStore::load(home.join("recovery.json")).unwrap();
        store
            .record_session("group1", "ses_stream".to_owned(), home.join("repo"))
            .await
            .unwrap();

        let failure = RunFailure {
            error: HarnessError::BackendStream,
            observed_session: Some("ses_stream".to_owned()),
        };
        let media = vec![AgentControlMediaRef {
            media_type: "image/png".to_owned(),
            file_name: "screen.png".to_owned(),
            ciphertext_sha256: "cipher".to_owned(),
            plaintext_sha256: "plain".to_owned(),
            nonce_hex: "nonce".to_owned(),
            version: "encrypted-media-v1".to_owned(),
            source_epoch: 7,
            locators: Vec::new(),
            dim: None,
            thumbhash: None,
        }];
        let config = test_config(&home);
        let reply = handle_backend_run_failure(
            FailureRecoveryContext {
                config: &config,
                sessions: &store,
                recovery: &recovery,
            },
            "group1",
            store.get("group1").await.as_ref(),
            home.join("repo"),
            "private prompt".to_owned(),
            media.clone(),
            &failure,
        )
        .await;

        assert_eq!(
            reply,
            recovery_resolution_message("wn-opencode", RecoveryKind::UncertainOutcome)
        );
        assert!(!reply.contains("failed while streaming"));
        let record = recovery.get("group1").await.unwrap();
        assert_eq!(record.kind, RecoveryKind::UncertainOutcome);
        assert_eq!(record.status, RecoveryStatus::Pending);
        assert_eq!(record.session_id, "ses_stream");
        assert_eq!(record.media, media);

        let retried = begin_validated_retry(&recovery, "group1", &home)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retried.status, RecoveryStatus::Retrying);
        assert_eq!(retried.session_id, "ses_stream");
        assert_eq!(retried.media, media);

        let streaming = handle_backend_run_failure(
            FailureRecoveryContext {
                config: &config,
                sessions: &store,
                recovery: &recovery,
            },
            "group2",
            None,
            home.clone(),
            "private prompt".to_owned(),
            Vec::new(),
            &RunFailure {
                error: HarnessError::BackendStream,
                observed_session: None,
            },
        )
        .await;
        assert!(streaming.contains("failed while streaming"));
        assert!(recovery.get("group2").await.is_none());
    }

    #[tokio::test]
    async fn successful_retry_discard_failure_restores_pending() {
        let dir = tempfile::tempdir().unwrap();
        let store = RecoveryStore::load(dir.path().join("recovery.json")).unwrap();
        store
            .set(
                "group",
                RecoveryRecord {
                    prompt: "private prompt".to_owned(),
                    media: Vec::new(),
                    cwd: dir.path().join("repo"),
                    session_id: "session".to_owned(),
                    kind: RecoveryKind::UncertainOutcome,
                    status: RecoveryStatus::Retrying,
                },
            )
            .await
            .unwrap();
        std::fs::create_dir(dir.path().join("recovery.json.tmp")).unwrap();

        assert!(store.discard("group").await.is_err());
        assert_eq!(
            store.get("group").await.unwrap().status,
            RecoveryStatus::Retrying
        );
        std::fs::remove_dir(dir.path().join("recovery.json.tmp")).unwrap();
        assert!(store.reset_retry("group").await.unwrap());
        assert_eq!(
            store.get("group").await.unwrap().status,
            RecoveryStatus::Pending
        );
        assert!(store.begin_retry("group").await.unwrap().is_some());
    }
}
