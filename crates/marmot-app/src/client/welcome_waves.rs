//! Welcome waves that run beside the account worker's writer (mdk#3466).
//!
//! A wave is one publish of Welcomes: a founding create's, an invite's, the
//! startup retry's, or those a confirmed commit or a maintenance pass
//! releases. The managed worker turns the runtime's detached mode on
//! ([`AppClient::detach_welcome_waves`]). Each wave is then prepared on the
//! writer, with its attempt records, its holds and its reserved ids. A task
//! makes only the wave's relay publishes and holds nothing of the client. The
//! writer settles the wave on the client that started it
//! ([`AppClient::settle_welcome_wave`]): it finishes the results in input
//! order, or abandons the wave if its task ended early. An abandoned Welcome
//! stays owed. Maintenance retries its fanout record, and the next open's
//! startup retry sends it.
//!
//! A wave returns once each of its passes is done, while the relays a pass
//! was still waiting on keep answering in a wave of their own, started by
//! the wave's task as it returns ([`WelcomeWaveResults::remaining`]). The
//! writer settles the wave at once, then takes that remaining wave up like
//! any other: its settle records the late answers, and cancelling it leaves
//! those relays to maintenance, as before.
//!
//! Every wave counts toward the app's waves in flight
//! ([`WelcomeWavesInFlight`]) until its relay task ends or is aborted: a
//! create's or an invite's from before its host is answered
//! ([`AppClient::count_welcome_wave`]), any other from its start. Runtime
//! shutdown keeps the relay plane up until none counts or its bound passes
//! (L3).
//!
//! Two publishes stay on the writer: a pending create's first Welcome, which
//! confirms its group, and `redeliver_welcome`. A caller that needs a wave's
//! outcome before it goes on awaits the wave in place
//! ([`AppClient::drive_unpublished_welcome_delivery`]): device pairing, and
//! direct `AppClient` callers.

use super::*;
use marmot_session::AccountDeviceEffects;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinError, JoinHandle};

/// What settling a wave does once its results are finished.
pub(crate) enum WelcomeWaveTail {
    /// The startup retry of every Welcome owed at open.
    Startup {
        observation: Option<crate::ProductObservation>,
        welcome_ids: Vec<String>,
    },
    /// A founding create's Welcomes, with what its publish left.
    Founding {
        group_id: GroupId,
        audit_context: Box<AuditEventContext>,
        welcome_intents: Vec<String>,
        effects: Box<AccountDeviceEffects>,
        published: bool,
        /// Set when the publishes ran in the wave, which then records them.
        telemetry: Option<PerformanceRecorder>,
        started: Instant,
    },
    /// An invite's owed Welcomes.
    Invite {
        group_id: GroupId,
        welcome_ids: Vec<String>,
        effects: Box<AccountDeviceEffects>,
        /// Set when the publishes ran in the wave, which then records them.
        telemetry: Option<PerformanceRecorder>,
        started: Instant,
    },
    /// Welcomes a confirmed commit or a maintenance pass released.
    Released,
    /// The relays a settled wave's passes were still waiting on. Their
    /// Welcomes' first attempts have settled, so nothing waits for this
    /// wave but the shutdown bound.
    Remaining,
}

impl WelcomeWaveTail {
    pub(crate) fn is_founding(&self) -> bool {
        matches!(self, Self::Founding { .. })
    }

    pub(crate) fn is_remaining(&self) -> bool {
        matches!(self, Self::Remaining)
    }
}

/// A wave's relay task. Dropping it aborts the task, so no publish outlives
/// the worker or the client generation that started it.
pub(crate) struct WelcomeWaveRun(pub(crate) JoinHandle<WelcomeWaveResults>);

/// What a wave's relay task returns.
pub(crate) struct WelcomeWaveResults {
    pub(crate) completed: Vec<CompletedWelcomePublishTask>,
    /// The wave that goes on asking the relays its passes were still waiting
    /// on, already running. Dropping it stops them.
    pub(crate) remaining: Option<Box<StartedWelcomeWave>>,
}

impl WelcomeWaveRun {
    pub(crate) fn abort_handle(&self) -> AbortHandle {
        self.0.abort_handle()
    }
}

impl Future for WelcomeWaveRun {
    type Output = Result<WelcomeWaveResults, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl Drop for WelcomeWaveRun {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A wave whose publishes are running.
pub(crate) struct StartedWelcomeWave {
    pub(crate) run: WelcomeWaveRun,
    /// Every id the wave reserved, released when it settles.
    pub(crate) message_ids: Vec<MessageId>,
    pub(crate) tail: WelcomeWaveTail,
}

/// The Welcome waves whose relay tasks run, or whose create or invite has
/// answered its host, across every client of one app (mdk#3466 L3). Runtime
/// shutdown keeps the relay plane up while any counts.
#[derive(Clone)]
pub(crate) struct WelcomeWavesInFlight(Arc<watch::Sender<usize>>);

impl Default for WelcomeWavesInFlight {
    fn default() -> Self {
        Self(Arc::new(watch::channel(0).0))
    }
}

impl WelcomeWavesInFlight {
    fn hold(&self) -> WelcomeWaveHold {
        self.0.send_modify(|running| *running += 1);
        WelcomeWaveHold(self.0.clone())
    }

    /// Wait until no wave's relay task runs, or until `deadline`.
    pub(crate) async fn ended_by(&self, deadline: tokio::time::Instant) {
        let mut running = self.0.subscribe();
        let _ = tokio::time::timeout_at(deadline, running.wait_for(|running| *running == 0)).await;
    }
}

/// One wave's count in [`WelcomeWavesInFlight`], held by its relay task, or
/// by its create or invite from the host's answer until the wave started.
#[must_use = "a wave counts only while its hold lives"]
pub(crate) struct WelcomeWaveHold(Arc<watch::Sender<usize>>);

impl Drop for WelcomeWaveHold {
    fn drop(&mut self) {
        self.0.send_modify(|running| *running -= 1);
    }
}

/// Where a stashed create or invite delivery stands once its writer part
/// is done.
enum StashedDelivery {
    /// Nothing runs beside the writer: it is settled.
    Settled(WelcomeDelivery),
    /// Its publishes run in this wave.
    Running(Box<StartedWelcomeWave>),
}

/// Run `tasks` as one wave's relay task, or nothing when there are none.
/// The task captures only the prepared publishes: each holds a transport
/// handle, a clock and its exact attempts, nothing of the client. It counts
/// in `in_flight` until it ends or is aborted. As it returns, it starts the
/// relays its passes left answering as their own wave, which counts before
/// this one stops counting.
fn spawn_welcome_wave(
    tasks: Vec<PreparedWelcomePublishTask>,
    in_flight: &WelcomeWavesInFlight,
) -> Option<(WelcomeWaveRun, Vec<MessageId>)> {
    if tasks.is_empty() {
        return None;
    }
    let message_ids = tasks
        .iter()
        .flat_map(|task| task.message_ids().iter().cloned())
        .collect();
    let publishes =
        futures::future::join_all(tasks.into_iter().map(PreparedWelcomePublishTask::run));
    let hold = in_flight.hold();
    let in_flight = in_flight.clone();
    let run = WelcomeWaveRun(tokio::spawn(async move {
        let _hold = hold;
        let mut completed = publishes.await;
        let remaining = completed
            .iter_mut()
            .filter_map(CompletedWelcomePublishTask::take_remaining)
            .collect();
        let remaining = spawn_welcome_wave(remaining, &in_flight).map(|(run, message_ids)| {
            Box::new(StartedWelcomeWave {
                run,
                message_ids,
                tail: WelcomeWaveTail::Remaining,
            })
        });
        WelcomeWaveResults {
            completed,
            remaining,
        }
    }));
    Some((run, message_ids))
}

impl AppClient {
    /// Have the runtime leave every detachable Welcome wave to this client,
    /// which starts it beside the writer. Only the managed account worker
    /// turns this on: it takes each started wave
    /// ([`Self::take_started_welcome_waves`]) and settles it.
    pub(crate) fn detach_welcome_waves(&mut self) {
        self.runtime.set_detached_welcome_waves(true);
    }

    /// Count the wave a create or an invite is about to start, before its
    /// host is answered (mdk#3466 L3). A shutdown the host begins from that
    /// answer then keeps the relay plane up for the wave. Drop the hold once
    /// [`Self::start_unpublished_welcome_delivery`] returns: by then the wave
    /// counts on its own, or none started.
    pub(crate) fn count_welcome_wave(&self) -> WelcomeWaveHold {
        self.app.welcome_waves_in_flight.hold()
    }

    /// The waves started since the last call, in the order they started. A
    /// wave the runtime released since (a confirmed commit's, a maintenance
    /// pass's) is started here.
    pub(crate) fn take_started_welcome_waves(&mut self) -> Vec<StartedWelcomeWave> {
        self.start_released_welcome_waves();
        std::mem::take(&mut self.started_welcome_waves)
    }

    fn start_released_welcome_waves(&mut self) {
        for task in self.runtime.take_prepared_welcome_tasks() {
            if let Some((run, message_ids)) =
                spawn_welcome_wave(vec![task], &self.app.welcome_waves_in_flight)
            {
                self.started_welcome_waves.push(StartedWelcomeWave {
                    run,
                    message_ids,
                    tail: WelcomeWaveTail::Released,
                });
            }
        }
    }

    /// Publish the Welcome obligations stashed at the canonical create or
    /// invite boundary, and wait for them. Device pairing and direct
    /// `AppClient` callers use it; the managed worker starts the delivery
    /// instead ([`Self::start_unpublished_welcome_delivery`]) and settles its
    /// wave when the publishes return.
    pub(crate) async fn drive_unpublished_welcome_delivery(
        &mut self,
        telemetry: Option<&PerformanceRecorder>,
    ) -> WelcomeDelivery {
        match self.start_stashed_welcome_delivery(telemetry).await {
            StashedDelivery::Settled(delivery) => delivery,
            StashedDelivery::Running(wave) => {
                let StartedWelcomeWave {
                    run,
                    message_ids,
                    tail,
                } = *wave;
                let completed = run.await;
                self.settle_welcome_wave(message_ids, tail, completed).await
            }
        }
    }

    /// Start the Welcome delivery stashed at the canonical create or invite
    /// boundary. What stays on the writer runs here: the create's route
    /// sync and warm pass. The wave is left for the worker to take. Returns
    /// whether one runs; with none, the delivery has settled.
    pub(crate) async fn start_unpublished_welcome_delivery(
        &mut self,
        telemetry: Option<&PerformanceRecorder>,
    ) -> bool {
        match self.start_stashed_welcome_delivery(telemetry).await {
            StashedDelivery::Running(wave) => {
                self.started_welcome_waves.push(*wave);
                true
            }
            StashedDelivery::Settled(_) => false,
        }
    }

    async fn start_stashed_welcome_delivery(
        &mut self,
        telemetry: Option<&PerformanceRecorder>,
    ) -> StashedDelivery {
        let Some(work) = self.unpublished_welcome_delivery.take() else {
            return StashedDelivery::Settled(WelcomeDelivery::Delivered);
        };
        // A wave the runtime released before this one keeps its own tail.
        self.start_released_welcome_waves();
        let started = Instant::now();
        match work.kind {
            UnpublishedWelcomeKind::Founding {
                effects,
                welcome_intents,
            } => {
                // The canonical group already populated routing. Its REQs and
                // founding Welcome publication can progress independently.
                let adapter = self.adapter.clone();
                let sync = TransportGroupSync {
                    account_id: adapter.account_id().clone(),
                    group_subscriptions: self.routing.group_subscriptions(),
                    since: self.subscription_rebuild_since(),
                };
                self.pending_runtime_group_subscription_refresh = true;
                let step = self.lane_step(crate::RuntimePerformanceOperation::RouteRefresh);
                let in_flight = self.app.welcome_waves_in_flight.clone();
                let register = async {
                    let started = Instant::now();
                    let result = adapter
                        .sync_account_groups(sync)
                        .await
                        .map_err(AppError::from);
                    step.finish(&result);
                    record_app_performance(
                        telemetry,
                        AppPerformanceOperation::GroupCreateSubscriptionRefresh,
                        started.elapsed(),
                        result.is_ok(),
                    );
                    result
                };
                let publish = async {
                    let result = self
                        .runtime
                        .publish_prepared_session_effects_with_audit_context(
                            effects,
                            work.audit_context.clone(),
                        )
                        .await
                        .map_err(AppError::from);
                    // Detached, the publish only prepared the wave: start it
                    // now, beside the route sync, as the inline publish ran.
                    let run =
                        spawn_welcome_wave(self.runtime.take_prepared_welcome_tasks(), &in_flight);
                    if run.is_none() {
                        record_app_performance(
                            telemetry,
                            AppPerformanceOperation::GroupCreateWelcomePublish,
                            started.elapsed(),
                            result.is_ok(),
                        );
                    }
                    (result, run)
                };
                let ((publish_result, run), registered) = tokio::join!(publish, register);
                let published = publish_result.is_ok();
                self.pending_runtime_group_subscription_refresh = registered.is_err();
                match registered {
                    Ok(()) => self.warm_encrypted_media_epoch_secrets("post_subscription_sync"),
                    Err(error) => tracing::warn!(
                        target: "marmot_app::client",
                        method = "create_group_subscription_refresh",
                        error_kind = error.privacy_safe_kind(),
                        "confirmed group creation could not refresh subscriptions immediately"
                    ),
                }
                let effects = recover_post_canonical_result(
                    "publish_prepared_founding_group",
                    publish_result,
                );
                let tail = WelcomeWaveTail::Founding {
                    group_id: work.group_id,
                    audit_context: Box::new(work.audit_context),
                    welcome_intents,
                    effects: Box::new(effects),
                    published,
                    telemetry: run.as_ref().and(telemetry.cloned()),
                    started,
                };
                self.stashed_delivery(tail, run).await
            }
            UnpublishedWelcomeKind::Invite { welcome_ids } => {
                let publish_result = self
                    .runtime
                    .deliver_owed_welcomes_with_audit_context(
                        &welcome_ids,
                        work.group_id.clone(),
                        work.audit_context,
                    )
                    .await
                    .map_err(AppError::from);
                let run = spawn_welcome_wave(
                    self.runtime.take_prepared_welcome_tasks(),
                    &self.app.welcome_waves_in_flight,
                );
                if run.is_none() {
                    record_app_performance(
                        telemetry,
                        AppPerformanceOperation::GroupInviteWelcomePublish,
                        started.elapsed(),
                        publish_result.is_ok(),
                    );
                }
                let effects = match publish_result {
                    Ok(effects) => effects,
                    Err(error) => {
                        tracing::warn!(
                            target: "marmot_app::client",
                            method = "drive_unpublished_welcome_delivery",
                            error_kind = error.privacy_safe_kind(),
                            "confirmed invite outpaced Welcome fanout; pending obligations remain retryable"
                        );
                        if run.is_none() {
                            return StashedDelivery::Settled(WelcomeDelivery::Undelivered);
                        }
                        AccountDeviceEffects::default()
                    }
                };
                let welcome_ids = welcome_ids
                    .iter()
                    .map(|id| hex::encode(id.as_slice()))
                    .collect::<Vec<_>>();
                let tail = WelcomeWaveTail::Invite {
                    group_id: work.group_id,
                    welcome_ids,
                    effects: Box::new(effects),
                    telemetry: run.as_ref().and(telemetry.cloned()),
                    started,
                };
                self.stashed_delivery(tail, run).await
            }
        }
    }

    async fn stashed_delivery(
        &mut self,
        tail: WelcomeWaveTail,
        run: Option<(WelcomeWaveRun, Vec<MessageId>)>,
    ) -> StashedDelivery {
        match run {
            Some((run, message_ids)) => StashedDelivery::Running(Box::new(StartedWelcomeWave {
                run,
                message_ids,
                tail,
            })),
            None => StashedDelivery::Settled(
                self.finish_welcome_wave_tail(tail, AccountDeviceEffects::default(), true)
                    .await,
            ),
        }
    }

    /// Start one bounded retry of every Welcome the engine owes at open. The
    /// same read lets the runtime watch the Welcomes still staged with their
    /// commits, so maintenance delivers them once those commits confirm.
    ///
    /// Only relay I/O moves into the wave. Exact artifacts, endpoint
    /// snapshots and attempt reservations stay with this client, so the worker
    /// keeps processing deliveries and commands without a second retry for
    /// the same message id.
    pub(crate) fn start_startup_welcome_retry(&mut self) {
        let (welcome_ids, task) = match self
            .runtime
            .prepare_owed_welcome_retry_task_with_audit_context(AuditEventContext::default())
        {
            Ok(Some(retry)) => retry,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "start_startup_welcome_retry",
                    error_kind = AppError::from(error).privacy_safe_kind(),
                    "could not prepare retained Welcome obligations at startup"
                );
                return;
            }
        };
        let welcome_ids = welcome_ids
            .iter()
            .map(|id| hex::encode(id.as_slice()))
            .collect::<Vec<_>>();
        let observation = if task.message_ids().is_empty() {
            None
        } else {
            self.app.product_analytics.begin(
                crate::ProductFamily::Welcome,
                "retry",
                crate::ProductUnit::Attempt,
            )
        };
        if let Some((run, message_ids)) =
            spawn_welcome_wave(vec![task], &self.app.welcome_waves_in_flight)
        {
            self.started_welcome_waves.push(StartedWelcomeWave {
                run,
                message_ids,
                tail: WelcomeWaveTail::Startup {
                    observation,
                    welcome_ids,
                },
            });
        }
    }

    /// Settle a wave on the client that started it. Finish what its task
    /// published, in input order, or abandon it if the task panicked or was
    /// cancelled, then run the wave's tail. The results of a group that is
    /// gone (see [`Self::welcome_wave_group_gone`]) are dropped first, so the
    /// wave changes nothing of it. The wave of the relays it left answering
    /// is started here, for the worker to take up.
    pub(crate) async fn settle_welcome_wave(
        &mut self,
        message_ids: Vec<MessageId>,
        tail: WelcomeWaveTail,
        run: Result<WelcomeWaveResults, JoinError>,
    ) -> WelcomeDelivery {
        let mut effects = AccountDeviceEffects::default();
        let finished = match run {
            Ok(WelcomeWaveResults {
                completed,
                remaining,
            }) => {
                if let Some(remaining) = remaining {
                    self.started_welcome_waves.push(*remaining);
                }
                let mut finished = true;
                for mut task in completed {
                    task.drop_gone_groups(|group_id| self.welcome_wave_group_gone(group_id));
                    match self.runtime.finish_welcome_publish_task(task).await {
                        Ok(output) => effects.extend(output),
                        // As an inline wave's error fails its caller, the
                        // task's results go with it. Its Welcomes stay owed.
                        Err(error) => {
                            finished = false;
                            tracing::warn!(
                                target: "marmot_app::client",
                                method = "settle_welcome_wave",
                                error_kind = AppError::from(error).privacy_safe_kind(),
                                "a Welcome wave left obligations pending"
                            );
                        }
                    }
                }
                finished
            }
            Err(error) => {
                self.runtime.abandon_welcome_publish_task(&message_ids);
                tracing::warn!(
                    target: "marmot_app::client",
                    method = "settle_welcome_wave",
                    error_kind = if error.is_panic() { "panic" } else { "cancelled" },
                    "a Welcome wave's relay task ended before it was settled"
                );
                false
            }
        };
        self.finish_welcome_wave_tail(tail, effects, finished).await
    }

    async fn finish_welcome_wave_tail(
        &mut self,
        tail: WelcomeWaveTail,
        wave: AccountDeviceEffects,
        finished: bool,
    ) -> WelcomeDelivery {
        match tail {
            WelcomeWaveTail::Startup {
                observation,
                welcome_ids,
            } => {
                if let Some(observation) = observation {
                    observation.finish(if !finished {
                        "failure"
                    } else if wave.failures.is_empty() && wave.welcome_failures.is_empty() {
                        "confirmed"
                    } else {
                        "pending"
                    });
                }
                if finished {
                    let _ = self.clear_delivered_welcome_rows(&welcome_ids, &wave);
                    self.remember_published_reports(&wave);
                }
                WelcomeDelivery::of(finished, &wave)
            }
            WelcomeWaveTail::Founding {
                group_id,
                audit_context,
                welcome_intents,
                mut effects,
                published,
                telemetry,
                started,
            } => {
                record_app_performance(
                    telemetry.as_ref(),
                    AppPerformanceOperation::GroupCreateWelcomePublish,
                    started.elapsed(),
                    published && finished,
                );
                if self.welcome_wave_group_gone(&group_id) {
                    return WelcomeDelivery::Undelivered;
                }
                effects.extend(wave);
                let delivery = WelcomeDelivery::of(published && finished, &effects);
                recover_post_canonical_result(
                    "clear_delivered_welcome_rows",
                    self.clear_delivered_welcome_rows(&welcome_intents, &effects),
                );
                // Non-fatal here: this classification only logs, so no
                // refusal is lost to an early return. It still arms through the
                // same gate, so no publishing seam reaches the bare check.
                recover_post_canonical_result(
                    "classify_founding_welcome_publish",
                    self.observe_recovery_evidence_then_fail_if_publish_failed(&effects)
                        .await,
                );
                self.record_human_action_succeeded(&group_id, &audit_context, &effects);
                self.remember_published_reports(&effects);
                delivery
            }
            WelcomeWaveTail::Invite {
                group_id,
                welcome_ids,
                mut effects,
                telemetry,
                started,
            } => {
                record_app_performance(
                    telemetry.as_ref(),
                    AppPerformanceOperation::GroupInviteWelcomePublish,
                    started.elapsed(),
                    finished,
                );
                if !finished || self.welcome_wave_group_gone(&group_id) {
                    return WelcomeDelivery::Undelivered;
                }
                effects.extend(wave);
                let _ = self.clear_delivered_welcome_rows(&welcome_ids, &effects);
                self.remember_published_reports(&effects);
                WelcomeDelivery::of(true, &effects)
            }
            WelcomeWaveTail::Released | WelcomeWaveTail::Remaining => {
                self.remember_published_reports(&wave);
                WelcomeDelivery::of(finished, &wave)
            }
        }
    }

    /// Whether a wave's Welcomes no longer concern `group_id`: the group is
    /// gone from the engine's records or forgotten, this account left it or
    /// was removed from it, or its chat was deleted locally. A device group
    /// never enters the chat list, so only a group the host may see is
    /// judged by the list. A record that cannot be read counts as present.
    fn welcome_wave_group_gone(&self, group_id: &GroupId) -> bool {
        match self.stored_group(group_id) {
            Ok(None) => return true,
            Ok(Some(group)) if group.is_terminal() => return true,
            Ok(Some(_)) => {}
            Err(_) => return false,
        }
        if self.is_group_forgotten(group_id).unwrap_or(false) {
            return true;
        }
        self.ensure_group(group_id).is_err() && self.host_may_see_group(group_id)
    }
}

#[cfg(test)]
mod tests {
    use super::WelcomeWavesInFlight;
    use std::time::Duration;
    use tokio::time::Instant;

    /// L3's shutdown gate: with no wave in flight it doesn't wait; with one,
    /// it waits until the wave's relay task ends, or until the deadline.
    #[tokio::test(start_paused = true)]
    async fn the_shutdown_gate_waits_only_while_a_wave_runs_and_until_its_deadline() {
        let in_flight = WelcomeWavesInFlight::default();
        let start = Instant::now();
        in_flight.ended_by(start + Duration::from_secs(2)).await;
        assert_eq!(Instant::now(), start, "no wave in flight, no wait");

        let wave = in_flight.hold();
        let opened = tokio::spawn({
            let in_flight = in_flight.clone();
            async move {
                in_flight.ended_by(start + Duration::from_secs(2)).await;
                Instant::now()
            }
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        drop(wave);
        assert_eq!(
            opened.await.unwrap(),
            start + Duration::from_secs(1),
            "the gate opens when the last wave ends"
        );

        let _still_running = in_flight.hold();
        in_flight.ended_by(start + Duration::from_secs(3)).await;
        assert_eq!(
            Instant::now(),
            start + Duration::from_secs(3),
            "a wave still running holds the gate until the deadline"
        );
    }
}
