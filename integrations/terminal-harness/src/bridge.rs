use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use agent_control::{AgentControlAccount, AgentControlEvent, AgentControlMediaUpload};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::artifacts::{
    ArtifactDeliveryContext, ArtifactOutbox, PendingArtifactBatch, prepare_manifest_path,
    remove_staged_files, stage_artifacts, validate_staged_batch,
};
use crate::chunking::split_reply_chunks;
use crate::control::ControlClient;
use crate::error::{HarnessError, Result};
use crate::repo_picker::{RepoPicker, parse_repo_picker, resolve_repo, validate_session_cwd};
use crate::store::{SessionRecord, SessionStore};
use crate::{
    ArtifactOutput, ArtifactOutputRequest, ArtifactSupport, Backend, Config, Invocation, Outcome,
    RunFailure, RunnerEvent, TRACE_TARGET, dirs_home,
};

const DEDUPE_LIMIT: usize = 2048;
const GROUP_QUEUE_LIMIT: usize = 4096;
const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const SEND_RETRY_ATTEMPTS: usize = 3;

/// Connects to `wn-agent`, subscribes to allowed prompts, and runs the backend.
pub async fn run<B: Backend>(config: Config, backend: B) -> Result<()> {
    let execution_support = backend.execution_support();
    validate_artifact_support(
        config.artifact_exports.enabled(),
        backend.artifact_support(),
    )?;
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

    let outbox_path = config.artifact_exports.outbox_path().to_path_buf();
    let outbox = if config.artifact_exports.enabled() {
        ArtifactOutbox::load(outbox_path)?
    } else {
        ArtifactOutbox::disabled(outbox_path)
    };
    let outbox = Arc::new(Mutex::new(outbox));
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
        outbox,
        home,
    });

    if ctx.cfg.artifact_exports.enabled() {
        retry_pending_artifacts(&ctx).await;
    }

    subscribe_loop(ctx).await
}

fn validate_artifact_support(enabled: bool, support: ArtifactSupport) -> Result<()> {
    if enabled && support != ArtifactSupport::CompletionFile {
        return Err(HarnessError::Config(
            "artifact exports are enabled for a backend without typed completion-file support"
                .to_owned(),
        ));
    }
    Ok(())
}

struct BridgeContext {
    cfg: Arc<Config>,
    client: ControlClient,
    account_ref: String,
    sessions: Arc<SessionStore>,
    queues: Arc<GroupQueues>,
    dedupe: Arc<InboundDedupe>,
    backend: Arc<dyn Backend>,
    outbox: Arc<Mutex<ArtifactOutbox>>,
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
    Forward {
        prompt: String,
        allow_workdir_picker: bool,
    },
}

fn classify_prompt(text: &str) -> PromptDisposition {
    match text.trim() {
        "/reset-session" => PromptDisposition::ResetSession,
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

async fn handle_message(ctx: Arc<BridgeContext>, inbound: InboundPrompt, permit: GroupPermit) {
    let _serial = permit.serial.lock().await;
    let mut inbound = inbound;
    let allow_workdir_picker = match classify_prompt(&inbound.text) {
        PromptDisposition::ResetSession => {
            handle_session_reset(&ctx, &inbound).await;
            return;
        }
        PromptDisposition::Forward {
            prompt,
            allow_workdir_picker,
        } => {
            inbound.text = prompt;
            allow_workdir_picker
        }
    };

    let known_session = ctx.sessions.get(&inbound.group_ref).await;
    let (cwd, prompt) =
        match resolve_cwd_and_prompt(&ctx, &inbound, known_session.as_ref(), allow_workdir_picker)
            .await
        {
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
    let (artifact_authorization, artifact_setup_failed) = match ctx
        .cfg
        .artifact_exports
        .authorize(&inbound.group_ref, &inbound.message_ref)
    {
        Ok(authorization) => (authorization, false),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "artifact_authorize",
                error_kind = err.privacy_safe_kind(),
                "failed to mint artifact authorization"
            );
            (None, true)
        }
    };
    let artifact_output = if let Some(authorization) = artifact_authorization.as_ref() {
        match prepare_manifest_path(&inbound.message_ref) {
            Ok(path) => Some(ArtifactOutputRequest::from_authorization(
                path,
                authorization,
            )),
            Err(err) => {
                warn!(
                    target: TRACE_TARGET,
                    method = "artifact_manifest_prepare",
                    error_kind = err.privacy_safe_kind(),
                    "failed to prepare typed artifact manifest"
                );
                None
            }
        }
    } else {
        None
    };
    let artifact_setup_failed =
        artifact_setup_failed || (artifact_authorization.is_some() && artifact_output.is_none());
    let invocation = Invocation {
        timeout: ctx.cfg.backend_timeout,
        idle_timeout: ctx.cfg.backend_idle_timeout,
        cwd: cwd.clone(),
        session_id,
        prompt,
        artifact_output,
    };
    let (tx, mut rx) = mpsc::channel(16);
    let backend = ctx.backend.clone();
    let runner = tokio::spawn(async move { backend.run(invocation, tx).await });
    let mut buffered_text = Vec::new();
    let mut artifact_outputs: Vec<ArtifactOutput> = Vec::new();
    while let Some(event) = rx.recv().await {
        match event {
            RunnerEvent::Text(text) => {
                buffered_text.push(text);
            }
            RunnerEvent::Artifacts(outputs) => artifact_outputs.extend(outputs),
        }
    }

    match runner.await {
        Ok(Ok(outcome)) => {
            let mut delivered_chunks = 0usize;
            let mut delivery_failed = false;
            if artifact_setup_failed {
                let _ = send_artifact_status(
                    &ctx,
                    &inbound,
                    1,
                    "rejected because the connector could not initialize its private export state",
                    1,
                )
                .await;
            } else if !artifact_outputs.is_empty() {
                if let Some(authorization) = artifact_authorization.as_ref() {
                    deliver_artifact_outputs(
                        &ctx,
                        &inbound,
                        authorization,
                        (!buffered_text.is_empty()).then(|| buffered_text.join("\n\n")),
                        &artifact_outputs,
                        1,
                    )
                    .await;
                } else {
                    let _ = send_artifact_status(
                        &ctx,
                        &inbound,
                        artifact_outputs.len(),
                        "rejected because this group has no active artifact grant",
                        1,
                    )
                    .await;
                }
            } else {
                'messages: for text in &buffered_text {
                    for chunk in split_reply_chunks(text, ctx.cfg.max_reply_bytes) {
                        delivered_chunks += 1;
                        if send_reply(
                            &ctx,
                            &inbound.account_ref,
                            &inbound.group_ref,
                            &inbound.message_ref,
                            chunk,
                            delivered_chunks,
                        )
                        .await
                        .is_err()
                        {
                            delivery_failed = true;
                            break 'messages;
                        }
                    }
                }
            }
            let terminal_delivery_count = if artifact_setup_failed || !artifact_outputs.is_empty() {
                1
            } else {
                delivered_chunks
            };
            finish_success(
                ctx,
                inbound,
                known_session,
                cwd,
                outcome,
                DeliveryReport {
                    chunk_count: terminal_delivery_count,
                    failed: delivery_failed,
                    failure_chunk_index: delivered_chunks + 1,
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
                &failure,
                ctx.cfg.backend_idle_timeout,
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

async fn deliver_artifact_outputs(
    ctx: &Arc<BridgeContext>,
    inbound: &InboundPrompt,
    authorization: &crate::artifacts::ArtifactAuthorization,
    caption: Option<String>,
    outputs: &[ArtifactOutput],
    status_chunk_index: usize,
) {
    let batch = match stage_artifacts(
        &ctx.cfg.artifact_exports,
        ArtifactDeliveryContext {
            reply_prefix: ctx.cfg.spec.reply_prefix,
            account_ref: &inbound.account_ref,
            group_ref: &inbound.group_ref,
            message_ref: &inbound.message_ref,
            caption,
        },
        authorization,
        outputs,
    ) {
        Ok(batch) => batch,
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "artifact_stage",
                error_kind = err.privacy_safe_kind(),
                artifact_count = outputs.len(),
                "rejected backend artifact output"
            );
            let reason = match err {
                HarnessError::ArtifactOutsideAllowedRoots => {
                    "rejected because it is outside the configured export roots"
                }
                HarnessError::ArtifactUnsafeSource => {
                    "rejected because it is not a regular non-symlink file"
                }
                HarnessError::ArtifactInvalidMetadata => {
                    "rejected because its structured metadata is invalid"
                }
                HarnessError::ArtifactLimitsExceeded => {
                    "rejected because it exceeds the connector media limits"
                }
                _ => "rejected by the connector safety policy",
            };
            let _ =
                send_artifact_status(ctx, inbound, outputs.len(), reason, status_chunk_index).await;
            return;
        }
    };

    if let Err(err) = ctx.outbox.lock().await.record(batch.clone()) {
        warn!(
            target: TRACE_TARGET,
            method = "artifact_outbox_record",
            error_kind = err.privacy_safe_kind(),
            artifact_count = outputs.len(),
            "failed to persist artifact delivery intent"
        );
        let _ = send_artifact_status(
            ctx,
            inbound,
            outputs.len(),
            "rejected because durable delivery state could not be recorded",
            status_chunk_index,
        )
        .await;
        for artifact in batch.artifacts {
            let _ = std::fs::remove_file(artifact.path);
        }
        return;
    }

    match send_pending_artifact_batch(ctx, &batch).await {
        Ok(()) => complete_artifact_batch(ctx, &batch.idempotency_key).await,
        Err(err) => {
            if err.artifact_validation_failed() {
                discard_artifact_batch(ctx, &batch.idempotency_key).await;
            }
            warn!(
                target: TRACE_TARGET,
                method = "send_media",
                error_kind = err.privacy_safe_kind(),
                artifact_count = outputs.len(),
                "artifact delivery remains pending"
            );
            let reason = if err.artifact_validation_failed() {
                "was rejected because the staged bytes no longer match durable delivery state"
            } else {
                "is pending automatic retry after a delivery failure"
            };
            let _ =
                send_artifact_status(ctx, inbound, outputs.len(), reason, status_chunk_index).await;
        }
    }
}

async fn retry_pending_artifacts(ctx: &Arc<BridgeContext>) {
    if !ctx.cfg.artifact_exports.enabled() {
        return;
    }
    let pending = ctx.outbox.lock().await.pending();
    for batch in pending {
        match send_pending_artifact_batch(ctx, &batch).await {
            Ok(()) => complete_artifact_batch(ctx, &batch.idempotency_key).await,
            Err(err) => {
                if err.artifact_validation_failed() {
                    discard_artifact_batch(ctx, &batch.idempotency_key).await;
                }
                warn!(
                    target: TRACE_TARGET,
                    method = "send_media_retry",
                    error_kind = err.privacy_safe_kind(),
                    artifact_count = batch.artifacts.len(),
                    "durable artifact delivery remains pending"
                );
            }
        }
    }
}

async fn send_pending_artifact_batch(
    ctx: &BridgeContext,
    batch: &PendingArtifactBatch,
) -> Result<()> {
    validate_staged_batch(&ctx.cfg.artifact_exports, ctx.cfg.spec.reply_prefix, batch)?;
    let attachments = batch
        .artifacts
        .iter()
        .map(|artifact| AgentControlMediaUpload {
            path: artifact.path.to_string_lossy().into_owned(),
            media_type: artifact.media_type.clone(),
            file_name: artifact.file_name.clone(),
            dim: None,
            thumbhash: None,
        })
        .collect::<Vec<_>>();
    let mut last_error = None;
    for attempt in 0..SEND_RETRY_ATTEMPTS {
        match ctx
            .client
            .send_artifacts(
                &batch.account_ref,
                &batch.group_ref,
                attachments.clone(),
                batch.caption.clone(),
                batch.idempotency_key.clone(),
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(err) if err.retryable() && attempt + 1 < SEND_RETRY_ATTEMPTS => {
                last_error = Some(err);
                sleep(Duration::from_millis(200 * (attempt as u64 + 1))).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_error.unwrap_or(HarnessError::ControlClosed))
}

async fn discard_artifact_batch(ctx: &BridgeContext, key: &str) {
    match ctx.outbox.lock().await.complete(key) {
        Ok(paths) => remove_staged_files(&ctx.cfg.artifact_exports, paths),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "artifact_outbox_discard",
                error_kind = err.privacy_safe_kind(),
                "failed to discard invalid artifact delivery intent"
            );
        }
    }
}

async fn complete_artifact_batch(ctx: &BridgeContext, key: &str) {
    match ctx.outbox.lock().await.complete(key) {
        Ok(paths) => remove_staged_files(&ctx.cfg.artifact_exports, paths),
        Err(err) => {
            warn!(
                target: TRACE_TARGET,
                method = "artifact_outbox_complete",
                error_kind = err.privacy_safe_kind(),
                "artifact delivery succeeded but durable completion cleanup failed"
            );
        }
    }
}

async fn send_artifact_status(
    ctx: &BridgeContext,
    inbound: &InboundPrompt,
    artifact_count: usize,
    reason: &str,
    chunk_index: usize,
) -> Result<()> {
    let details = (1..=artifact_count)
        .map(|index| format!("Artifact {index}: {reason}."))
        .collect::<Vec<_>>()
        .join("\n");
    send_reply(
        ctx,
        &inbound.account_ref,
        &inbound.group_ref,
        &inbound.message_ref,
        &format!("[{}] {details}", ctx.cfg.spec.reply_prefix),
        chunk_index,
    )
    .await
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

async fn handle_backend_run_failure(
    config: &Config,
    sessions: &SessionStore,
    group_ref: &str,
    known_session: Option<&SessionRecord>,
    cwd: PathBuf,
    failure: &RunFailure,
    idle_timeout: Duration,
) -> String {
    if let Err(store_err) = persist_observed_session_if_unset(
        sessions,
        group_ref,
        known_session,
        cwd,
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
            idle_timeout.as_secs()
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
    use sha2::Digest;
    use std::os::unix::net::UnixListener;

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
            artifact_exports: crate::ArtifactExportConfig::default(),
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

    struct NoopBackend;

    #[async_trait::async_trait]
    impl Backend for NoopBackend {
        async fn run(
            &self,
            _invocation: Invocation,
            _tx: mpsc::Sender<RunnerEvent>,
        ) -> std::result::Result<Outcome, RunFailure> {
            unreachable!("retry test does not invoke a backend")
        }
    }

    #[tokio::test]
    async fn dedupe_rejects_repeated_message_refs() {
        assert!(validate_artifact_support(false, ArtifactSupport::Unsupported).is_ok());
        assert!(validate_artifact_support(true, ArtifactSupport::Unsupported).is_err());
        assert!(validate_artifact_support(true, ArtifactSupport::CompletionFile).is_ok());

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

    #[tokio::test]
    async fn restart_retry_replays_durable_send_media_and_cleans_staged_file() {
        let root = tempfile::tempdir().unwrap();
        let socket = root.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::UnixListener::from_std(listener).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(read_half);
            let request: agent_control::AgentControlEnvelope<agent_control::AgentControlRequest> =
                agent_control::read_envelope(&mut reader)
                    .await
                    .unwrap()
                    .unwrap();
            let agent_control::AgentControlRequest::SendMedia { caption, .. } = request.payload
            else {
                panic!("expected send_media request");
            };
            assert_eq!(caption.as_deref(), Some("Report attached"));
            let response = agent_control::AgentControlEnvelope::request(
                request.id,
                agent_control::AgentControlResponse::FinalSent {
                    message_ids_hex: vec!["sent".to_owned()],
                    maintenance_disposition: Default::default(),
                },
            );
            agent_control::write_frame(&mut write_half, &response)
                .await
                .unwrap();
        });

        let staged = root.path().join("staged.bin");
        fs_private::write_private(&staged, b"payload").unwrap();
        let outbox_path = root.path().join("outbox.json");
        let mut outbox = ArtifactOutbox::load(outbox_path.clone()).unwrap();
        let artifacts = vec![crate::artifacts::StagedArtifact {
            path: staged.clone(),
            media_type: "application/octet-stream".to_owned(),
            file_name: "result.bin".to_owned(),
            size_bytes: 7,
            plaintext_sha256: hex::encode(sha2::Sha256::digest(b"payload")),
        }];
        let idempotency_key = crate::artifacts::artifact_idempotency_key(
            "wn-opencode",
            "account",
            "group",
            "inbound",
            Some("Report attached"),
            &artifacts,
        )
        .unwrap();
        outbox
            .record(PendingArtifactBatch {
                idempotency_key,
                account_ref: "account".to_owned(),
                group_ref: "group".to_owned(),
                reply_to_message_ref: "inbound".to_owned(),
                caption: Some("Report attached".to_owned()),
                artifacts,
            })
            .unwrap();
        let mut config = test_config(root.path());
        config.artifact_exports = crate::ArtifactExportConfig::new(
            true,
            vec![crate::ArtifactExportGrant {
                group_id_hex: "group".to_owned(),
                export_root: root.path().to_path_buf(),
                ttl_seconds: 300,
            }],
            root.path().to_path_buf(),
            outbox_path.clone(),
        );
        let sessions = SessionStore::load(config.state_path.clone(), root.path()).unwrap();
        let persisted = ArtifactOutbox::load(outbox_path.clone()).unwrap().pending();
        validate_staged_batch(&config.artifact_exports, "wn-opencode", &persisted[0]).unwrap();
        let ctx = Arc::new(BridgeContext {
            cfg: Arc::new(config),
            client: ControlClient::new(socket, None, Duration::from_secs(5), "wn-test"),
            account_ref: "account".to_owned(),
            sessions: Arc::new(sessions),
            queues: Arc::new(GroupQueues::new(1)),
            dedupe: Arc::new(InboundDedupe::new(8)),
            backend: Arc::new(NoopBackend),
            outbox: Arc::new(Mutex::new(
                ArtifactOutbox::load(outbox_path.clone()).unwrap(),
            )),
            home: root.path().to_path_buf(),
        });

        tokio::time::timeout(Duration::from_secs(3), retry_pending_artifacts(&ctx))
            .await
            .expect("artifact retry timed out");
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("fake control server timed out")
            .unwrap();
        assert!(
            ArtifactOutbox::load(outbox_path)
                .unwrap()
                .pending()
                .is_empty()
        );
        assert!(!staged.exists());
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
            &failure,
            Duration::from_secs(45),
        )
        .await;

        let record = store.get("group1").await.unwrap();
        assert_eq!(record.session_id, "ses_idle");
        assert_eq!(record.cwd, home);
        assert_eq!(
            reply,
            "[wn-opencode] opencode went silent for 45s without producing output; killing the invocation."
        );
    }
}
