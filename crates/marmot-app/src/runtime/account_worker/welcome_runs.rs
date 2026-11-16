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
//! wave and waits for its task to end ([`WelcomeRuns::end`]).
//!
//! A read of the pending deliveries waits as a `Drain` does, beside the
//! writer, so it answers with each earlier wave's first attempt settled, as
//! it did when the worker published Welcomes inline. Once its waves have
//! settled, the worker answers it in a turn of its own after the shutdown
//! arms ([`WelcomeRuns::has_answerable`]), as a queued command waits for its
//! turn: a stopping worker leaves it for [`WelcomeRuns::end`].

use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinError};

use cgka_traits::MessageId;
use marmot_session::CompletedWelcomePublishTask;

use super::RuntimeSharedServices;
use super::read_queue::ReadReply;
use crate::client::welcome_waves::{StartedWelcomeWave, WelcomeWaveTail};
use crate::{AppClient, AppError, PendingWelcomeDelivery};

/// The reply of a pending-deliveries read waiting for earlier waves (W8).
pub(super) type PendingDeliveriesReply = ReadReply<Result<Vec<PendingWelcomeDelivery>, AppError>>;

/// A wave whose relay task ended, with what settling it needs.
pub(super) struct EndedRun {
    id: u64,
    message_ids: Vec<MessageId>,
    tail: WelcomeWaveTail,
    run: Result<Vec<CompletedWelcomePublishTask>, JoinError>,
}

#[derive(Default)]
pub(super) struct WelcomeRuns {
    running: FuturesUnordered<BoxFuture<'static, EndedRun>>,
    /// The waves not yet settled, by start order.
    in_flight: Vec<(u64, AbortHandle)>,
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
        for StartedWelcomeWave {
            run,
            message_ids,
            tail,
        } in client.take_started_welcome_waves()
        {
            let id = self.next_id;
            self.next_id += 1;
            self.in_flight.push((id, run.abort_handle()));
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
        self.in_flight.retain(|(running, _)| *running != id);
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

    /// Whether a `Drain` or pending-deliveries read waits on no unsettled
    /// wave, so [`Self::answer_waiting`] would answer it.
    pub(super) fn has_answerable(&self) -> bool {
        let settled = self.settled();
        self.drains.iter().any(|(upto, _)| settled(*upto))
            || self.reads.iter().any(|(upto, _)| settled(*upto))
    }

    /// Whether every wave below `upto` has settled.
    fn settled(&self) -> impl Fn(u64) -> bool + use<> {
        let oldest = self.in_flight.first().map(|(id, _)| *id);
        move |upto| oldest.is_none_or(|oldest| oldest >= upto)
    }

    /// Answer each `Drain` and pending-deliveries read whose waves have all
    /// settled. A read answers with the list computed now. The worker calls
    /// this only where it takes a command up, or in a turn of its own after
    /// the shutdown arms.
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
    /// is abandoned, its Welcomes left owed. Every `Drain` and
    /// pending-deliveries read is then answerable, in the worker's next turn.
    pub(super) async fn settle_all(&mut self, client: &mut AppClient) {
        self.adopt(client);
        for (_, abort) in &self.in_flight {
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
        }
        self.in_flight.clear();
    }

    /// When the worker returns: cancel every wave and wait for its task to
    /// end. Nothing is settled, and undelivered Welcomes stay owed. A waiting
    /// `Drain` gets the error a queued command gets when the worker exits, and
    /// so does a waiting pending-deliveries read, which is answered with it.
    pub(super) async fn end(&mut self) {
        for (_, abort) in &self.in_flight {
            abort.abort();
        }
        while self.running.next().await.is_some() {}
        self.in_flight.clear();
        self.drains.clear();
        for (_, respond) in self.reads.drain(..) {
            let _ = respond.send(Err(AppError::TransportClosed));
        }
    }
}
