//! The account worker's running Welcome waves (mdk#3466).
//!
//! A wave's relay task runs beside the writer, and the writer settles the
//! wave as one unit on the client that started it (see
//! `client::welcome_waves`). This keeps the running waves of the worker's
//! current client, and the `Drain`s and pending-deliveries reads that wait
//! for them: each is answered once every wave started before the worker took
//! it up has settled (W7, W8). A wave started later never extends the wait.
//!
//! Every wave belongs to one client generation. Before the worker replaces
//! its client it cancels that client's waves and settles each on it
//! ([`WelcomeRuns::settle_all`]). Before the worker returns it cancels every
//! wave and waits for its task to end ([`WelcomeRuns::end`]). A stop or an
//! unlink first settles each wave that already returned and cancels and
//! joins the rest ([`WelcomeRuns::stop`]). On runtime shutdown it first
//! settles each wave whose task ends within the shutdown bound
//! ([`WelcomeRuns::settle_until`], L3), the remaining wave of the relays a
//! settled wave left answering included, then cancels and joins the rest
//! ([`WelcomeRuns::cancel_and_join`]). Each happens before the worker's audit
//! recording closes. A cancelled wave records nothing, a remaining wave
//! included: its relays stay owed and are retried after their backoff.
//!
//! A read of the pending deliveries waits as a `Drain` does, beside the
//! writer, so it answers with each earlier wave's first attempt settled, as
//! it did when the worker published Welcomes inline. Neither waits for a
//! remaining wave, whose Welcomes' first attempts have settled. Each wait answers
//! where its last wave settles: on the writer once the wave settles, or on
//! the replaced client before the worker drops it. At runtime shutdown a
//! wait whose waves settle within the bound answers with its result, or
//! with a storage error once `shutdown_and_close` has closed storage:
//! whether a reply wins over shutdown is not a host contract. A wait still
//! parked when the worker returns gets the error a queued command gets
//! ([`WelcomeRuns::end`]).

use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinError};
use tokio::time::{Instant as TokioInstant, timeout_at};

use super::RuntimeSharedServices;
use super::read_queue::ReadReply;
use crate::client::welcome_waves::{StartedWelcomeWave, WelcomeWaveResults, WelcomeWaveTail};
use crate::{AppClient, AppError, PendingWelcomeDelivery};
use cgka_traits::MessageId;

/// The reply of a pending-deliveries read waiting for earlier waves (W8).
pub(super) type PendingDeliveriesReply = ReadReply<Result<Vec<PendingWelcomeDelivery>, AppError>>;

/// A wave whose relay task ended, with what settling it needs.
pub(super) struct EndedRun {
    id: u64,
    message_ids: Vec<MessageId>,
    tail: WelcomeWaveTail,
    run: Result<WelcomeWaveResults, JoinError>,
}

#[derive(Default)]
pub(super) struct WelcomeRuns {
    running: FuturesUnordered<BoxFuture<'static, EndedRun>>,
    /// The waves not yet settled, by start order, and whether waits wait
    /// for each: every wave but a remaining one.
    in_flight: Vec<(u64, AbortHandle, bool)>,
    next_id: u64,
    /// Each waiting `Drain`, with the first wave id it does not wait for.
    drains: Vec<(u64, oneshot::Sender<()>)>,
    /// Each waiting pending-deliveries read, with the first wave id it does
    /// not wait for.
    reads: Vec<(u64, PendingDeliveriesReply)>,
}

impl WelcomeRuns {
    /// Take the waves `client` started since the last call.
    pub(super) fn adopt(&mut self, client: &mut AppClient) {
        for wave in client.take_started_welcome_waves() {
            self.run(wave);
        }
    }

    fn run(
        &mut self,
        StartedWelcomeWave {
            run,
            message_ids,
            tail,
        }: StartedWelcomeWave,
    ) {
        let id = self.next_id;
        self.next_id += 1;
        self.in_flight
            .push((id, run.abort_handle(), !tail.is_remaining()));
        self.running.push(Box::pin(async move {
            let run = run.await;
            EndedRun {
                id,
                message_ids,
                tail,
                run,
            }
        }));
    }

    pub(super) fn is_running(&self) -> bool {
        !self.running.is_empty()
    }

    /// The next wave whose relay task ended, or none while none runs.
    pub(super) async fn next(&mut self) -> Option<EndedRun> {
        self.running.next().await
    }

    /// Settle `ended` on `client`, the writer. Returns whether it was a
    /// founding create's wave, whose push-share retry follows it.
    pub(super) async fn settle(&mut self, client: &mut AppClient, ended: EndedRun) -> bool {
        let EndedRun {
            id,
            message_ids,
            tail,
            run,
        } = ended;
        let founding = tail.is_founding();
        // An undelivered Welcome stays owed; its pending event reports it.
        let _ = client.settle_welcome_wave(message_ids, tail, run).await;
        self.in_flight.retain(|(running, ..)| *running != id);
        founding
    }

    /// Answer `respond` once every wave started so far has settled.
    pub(super) fn drain(
        &mut self,
        respond: oneshot::Sender<()>,
        client: &AppClient,
        shared: &RuntimeSharedServices,
    ) {
        self.drains.push((self.next_id, respond));
        self.answer_waiting(client, shared);
    }

    /// Answer `respond` with the pending deliveries once every wave started
    /// so far has settled (W8).
    pub(super) fn read_pending_deliveries(
        &mut self,
        mut respond: PendingDeliveriesReply,
        client: &AppClient,
        shared: &RuntimeSharedServices,
    ) {
        // The worker has taken the read up: its wait on the worker ends here.
        respond.dispatched();
        self.reads.push((self.next_id, respond));
        self.answer_waiting(client, shared);
    }

    /// Whether every wave below `upto` has settled.
    fn settled(&self) -> impl Fn(u64) -> bool + use<> {
        let oldest = self
            .in_flight
            .iter()
            .find(|(.., waited)| *waited)
            .map(|(id, ..)| *id);
        move |upto| oldest.is_none_or(|oldest| oldest >= upto)
    }

    /// Answer each `Drain` and pending-deliveries read whose waves have all
    /// settled. A read answers with the list computed now. The worker calls
    /// this where it takes a wait up and where a wave settles.
    pub(super) fn answer_waiting(&mut self, client: &AppClient, shared: &RuntimeSharedServices) {
        let settled = self.settled();
        let (ready, waiting) = std::mem::take(&mut self.drains)
            .into_iter()
            .partition::<Vec<_>, _>(|(upto, _)| settled(*upto));
        self.drains = waiting;
        for (_, respond) in ready {
            let _ = super::reply(respond, (), client);
        }
        let (ready, waiting) = std::mem::take(&mut self.reads)
            .into_iter()
            .partition::<Vec<_>, _>(|(upto, _)| settled(*upto));
        self.reads = waiting;
        for (_, respond) in ready {
            let permit = shared.observer.product().permit();
            let _ = super::respond_diagnosed(
                shared,
                permit.as_ref(),
                respond,
                client.pending_welcome_deliveries(),
                client,
            );
        }
    }

    /// Before the worker replaces `client`: cancel its waves and settle each
    /// on it. A wave whose task already returned is finished, and any other
    /// is abandoned, its Welcomes left owed. The remaining wave a finished
    /// wave starts is cancelled and abandoned too. Every `Drain` and
    /// pending-deliveries read is then answered on `client`, before the
    /// worker drops it and backs off to reopen.
    pub(super) async fn settle_all(
        &mut self,
        client: &mut AppClient,
        shared: &RuntimeSharedServices,
    ) {
        self.adopt(client);
        for (_, abort, _) in &self.in_flight {
            abort.abort();
        }
        while let Some(EndedRun {
            message_ids,
            tail,
            run,
            ..
        }) = self.running.next().await
        {
            let _ = client.settle_welcome_wave(message_ids, tail, run).await;
            self.adopt(client);
            for (_, abort, _) in &self.in_flight {
                abort.abort();
            }
        }
        self.in_flight.clear();
        self.answer_waiting(client, shared);
    }

    /// On runtime shutdown, before [`Self::end`]: settle each wave on
    /// `client` as its task ends, until none runs or `deadline` passes, and
    /// answer the waits each settle completes (L3). A founding wave's
    /// push-share retry is left for the next start.
    pub(super) async fn settle_until(
        &mut self,
        client: &mut AppClient,
        shared: &RuntimeSharedServices,
        deadline: TokioInstant,
    ) {
        self.adopt(client);
        while let Ok(Some(ended)) = timeout_at(deadline, self.running.next()).await {
            self.settle(client, ended).await;
            self.adopt(client);
            self.answer_waiting(client, shared);
        }
    }

    /// When the worker stops with its client, before its audit recording
    /// closes (a stop or an unlink): settle each wave whose task already
    /// returned, as the worker would have, and cancel the rest, waiting for
    /// each ([`Self::cancel_and_join`]).
    pub(super) async fn stop(&mut self, client: &mut AppClient) {
        self.cancel_and_join(Some(client), true).await;
    }

    /// Cancel every wave and wait for its task to end, and for the task of
    /// each remaining wave a returned wave started. A cancelled wave records
    /// nothing: its Welcomes and relays stay owed. A wave whose task returned
    /// before its cancel took effect holds real answers. On `client`, when
    /// there is one, a remaining wave that returned is settled, and with
    /// `settle_first` a first wave too. The shutdown bound passes `false`:
    /// its deadline is over, and a first wave's settle can wait on relays.
    /// Each task is waited for, never polled once: a task that has finished
    /// can still read as not ready.
    pub(super) async fn cancel_and_join(
        &mut self,
        mut client: Option<&mut AppClient>,
        settle_first: bool,
    ) {
        if let Some(client) = client.as_deref_mut() {
            self.adopt(client);
        }
        for (_, abort, _) in &self.in_flight {
            abort.abort();
        }
        let mut remaining = Vec::new();
        while let Some(ended) = self.running.next().await {
            if ended.run.is_ok()
                && (settle_first || ended.tail.is_remaining())
                && let Some(client) = client.as_deref_mut()
            {
                // The remaining wave it started stops asking before its
                // settle, which can wait on relays, begins.
                if let Ok(results) = &ended.run
                    && let Some(wave) = &results.remaining
                {
                    wave.run.abort_handle().abort();
                }
                self.settle(client, ended).await;
                self.adopt(client);
                continue;
            }
            if let Ok(results) = ended.run {
                remaining.extend(results.remaining.map(|wave| *wave));
            }
        }
        for wave in remaining {
            wave.run.abort_handle().abort();
            let _ = wave.run.await;
        }
        self.in_flight.clear();
    }

    /// When the worker returns: cancel every wave and wait for its task to
    /// end ([`Self::cancel_and_join`]). Nothing is settled, and undelivered
    /// Welcomes stay owed. A waiting `Drain` gets the error a queued command
    /// gets when the worker exits, and so does a waiting pending-deliveries
    /// read, which is answered with it.
    pub(super) async fn end(&mut self) {
        self.cancel_and_join(None, false).await;
        self.drains.clear();
        for (_, respond) in self.reads.drain(..) {
            let _ = respond.send(Err(AppError::TransportClosed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::welcome_waves::WelcomeWaveRun;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Sets its flag when the task holding it is dropped.
    struct Stopped(Arc<AtomicBool>);

    impl Drop for Stopped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// L2 with a remaining wave: a wave that returned before the worker
    /// ended, its remaining wave still asking a relay, is never settled, and
    /// the end cancels that remaining wave and waits for its task to stop.
    #[tokio::test(flavor = "current_thread")]
    async fn the_end_stops_the_remaining_wave_of_a_wave_never_settled() {
        let stopped = Arc::new(AtomicBool::new(false));
        let holds = Stopped(stopped.clone());
        let remaining = WelcomeWaveRun(tokio::spawn(async move {
            let _holds = holds;
            std::future::pending::<WelcomeWaveResults>().await
        }));
        let returned = WelcomeWaveRun(tokio::spawn(async move {
            WelcomeWaveResults {
                completed: Vec::new(),
                remaining: Some(Box::new(StartedWelcomeWave {
                    run: remaining,
                    message_ids: Vec::new(),
                    tail: WelcomeWaveTail::Remaining,
                })),
            }
        }));
        let mut runs = WelcomeRuns::default();
        runs.run(StartedWelcomeWave {
            run: returned,
            message_ids: Vec::new(),
            tail: WelcomeWaveTail::Released,
        });
        // On this thread, the wave's task runs to its return here.
        tokio::task::yield_now().await;

        runs.end().await;

        assert!(
            stopped.load(Ordering::SeqCst),
            "the remaining wave's task has stopped when the end returns"
        );
    }
}
