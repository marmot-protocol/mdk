//! The account worker's lookups of invited recipients' inbox lists
//! (mdk#2261; see `client::welcome_route_lookups`).
//!
//! At each loop turn the worker starts the lookups the session owes, at most
//! [`LOOKUPS_PER_ACCOUNT`] at once and one per recipient, each beside the
//! writer, and stops each running one whose recipient no owed Welcome is
//! addressed to any more: its task is aborted at its next wait, so a relay
//! read it has not started never starts. Each continuation runs on the
//! writer as one unit. A lookup
//! belongs to the client that started it: before the worker replaces its
//! client it cancels them ([`WelcomeRouteLookups::replace`]), and the next
//! client's session owes its own; before the worker returns it cancels them
//! and waits for their tasks ([`WelcomeRouteLookups::end`]).

use futures::future::select_all;
use tokio_util::sync::CancellationToken;

use crate::AppClient;
use crate::client::welcome_route_lookups::RunningRouteLookup;
use cgka_traits::MemberId;

/// The most lookups one account runs at once.
pub(super) const LOOKUPS_PER_ACCOUNT: usize = 4;

#[derive(Default)]
pub(super) struct WelcomeRouteLookups {
    running: Vec<RunningRouteLookup>,
    /// Cancels the current client's lookups that have not started.
    cancel: CancellationToken,
    /// Lookups of a replaced client, still finishing. The worker waits for
    /// them when it returns.
    retired: Vec<RunningRouteLookup>,
}

/// A lookup that ended: its recipient, and whether it answered.
pub(super) struct Ended {
    recipient: MemberId,
    answered: bool,
}

impl WelcomeRouteLookups {
    /// Stop the lookups no owed Welcome needs any more, and start the ones
    /// `client`'s session owes, up to the bound.
    pub(super) fn adopt(&mut self, client: &AppClient) {
        let running = self
            .running
            .iter()
            .map(|lookup| lookup.recipient().clone())
            .collect::<Vec<_>>();
        let plan = client.plan_welcome_route_lookups(LOOKUPS_PER_ACCOUNT, &running);
        // Dropped, a lookup aborts its task.
        self.running
            .retain(|lookup| !plan.stop.contains(lookup.recipient()));
        for start in plan.start {
            self.running.push(start.spawn(self.cancel.clone()));
        }
    }

    pub(super) fn is_running(&self) -> bool {
        !self.running.is_empty()
    }

    /// The first lookup to end. Pending while none runs. Cancel-safe.
    pub(super) async fn next(&mut self) -> Ended {
        if self.running.is_empty() {
            return std::future::pending().await;
        }
        let (answered, index, _) = select_all(
            self.running
                .iter_mut()
                .map(|lookup| Box::pin(lookup.result())),
        )
        .await;
        let lookup = self.running.swap_remove(index);
        Ended {
            recipient: lookup.recipient().clone(),
            answered,
        }
    }

    /// The continuation, on the writer. Returns whether it released a
    /// recipient's retry, so session maintenance should run now.
    pub(super) fn settle(&mut self, client: &AppClient, ended: Ended) -> bool {
        match client.finish_welcome_route_lookup(&ended.recipient, ended.answered) {
            Ok(released) => released,
            Err(error) => {
                // The pacing stays, and the next paced attempt owes another
                // lookup.
                tracing::warn!(
                    target: "marmot_app::runtime",
                    method = "settle_welcome_route_lookup",
                    error_kind = error.privacy_safe_kind(),
                    "inbox lookup result not installed"
                );
                false
            }
        }
    }

    /// Before the worker replaces its client: cancel its lookups. Their
    /// results never reach the next client.
    pub(super) fn replace(&mut self) {
        self.retired.retain(|lookup| !lookup.is_finished());
        self.cancel.cancel();
        self.cancel = CancellationToken::new();
        self.retired.append(&mut self.running);
    }

    /// When the worker returns: cancel the lookups and wait for their tasks.
    pub(super) async fn end(&mut self) {
        self.cancel.cancel();
        for lookup in self.running.drain(..).chain(self.retired.drain(..)) {
            lookup.end().await;
        }
    }
}
