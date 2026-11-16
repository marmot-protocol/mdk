//! The account worker's running Welcome waves (mdk#3466).
//!
//! A wave's relay task runs beside the writer, and the writer settles the
//! wave as one unit on the client that started it (see
//! `client::welcome_waves`). This keeps the running waves of the worker's
//! current client, and the `Drain`s that wait for them: a `Drain` is answered
//! once every wave started before it has settled.
//!
//! Every wave belongs to one client generation. Before the worker replaces
//! its client it cancels that client's waves and settles each on it
//! ([`WelcomeRuns::settle_all`]). Before the worker returns it cancels every
//! wave and waits for its task to end ([`WelcomeRuns::end`]).

use futures::StreamExt;
use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinError};

use cgka_traits::MessageId;
use marmot_session::CompletedWelcomePublishTask;

use crate::AppClient;
use crate::client::welcome_waves::{StartedWelcomeWave, WelcomeWaveTail};

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
    pub(super) fn drain(&mut self, respond: oneshot::Sender<()>, client: &AppClient) {
        self.drains.push((self.next_id, respond));
        self.answer_drains(client);
    }

    /// Answer each `Drain` whose waves have all settled.
    pub(super) fn answer_drains(&mut self, client: &AppClient) {
        let oldest = self.in_flight.first().map(|(id, _)| *id);
        let (ready, waiting) = std::mem::take(&mut self.drains)
            .into_iter()
            .partition::<Vec<_>, _>(|(upto, _)| oldest.is_none_or(|oldest| oldest >= *upto));
        self.drains = waiting;
        for (_, respond) in ready {
            let _ = super::reply(respond, (), client);
        }
    }

    /// Before the worker replaces `client`: cancel its waves and settle each
    /// on it. A wave whose task already returned is finished, and any other
    /// is abandoned, its Welcomes left owed. Every `Drain` is then answered.
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
        self.answer_drains(client);
    }

    /// When the worker returns: cancel every wave and wait for its task to
    /// end. Nothing is settled, and undelivered Welcomes stay owed. A waiting
    /// `Drain` gets the error a queued command gets when the worker exits.
    pub(super) async fn end(&mut self) {
        for (_, abort) in &self.in_flight {
            abort.abort();
        }
        while self.running.next().await.is_some() {}
        self.in_flight.clear();
        self.drains.clear();
    }
}
