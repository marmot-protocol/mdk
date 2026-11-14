//! The live-tail seam.
//!
//! While a live REQ stays open in one healthy generation, its relay sends it
//! everything stored from the REQ's tail start on, so those seconds are not
//! owed while the generation lasts. The ledger never holds a tail: storage's
//! debt reads stay durable-only (goal − covered − parked − retired), and the
//! runner subtracts the tail in memory. A tail can lapse with no event, as
//! soon as its relay is no longer connected on the generation's own
//! connection, so it is a query: every debt read asks again, and no answer
//! outlives the worker turn that read it. A healthy tail is never fencing and
//! never charged; once its generation breaks, its seconds are owed until a
//! later EOSE or a fetch proves them.

use storage_sqlite::{SqliteAppStorage, TransportReconciliationRoute};

use crate::client::AppClient;
use crate::client::history_recovery::recovery_coverage::LiveTails;

/// One worker turn's read of the live tails.
pub(crate) trait LiveTailRead: Send + Sync {
    /// The last second the ledger must prove on `relay` for `route` at `now`:
    /// the second before a standing tail starts there, else `now`.
    fn owed_until(&self, route: &TransportReconciliationRoute, relay: &str, now: u64) -> u64;
}

impl LiveTailRead for LiveTails {
    fn owed_until(&self, route: &TransportReconciliationRoute, relay: &str, now: u64) -> u64 {
        LiveTails::owed_until(self, route, relay, now)
    }
}

impl AppClient {
    /// The live tails a runner's debt turn subtracts, read now: it
    /// re-observes the adapter and asks the relay client whether each
    /// generation's relay is still connected
    /// ([`AppClient::live_tails`](crate::client::AppClient)). The worker calls
    /// this at the start of every debt turn and drops the answer with the
    /// turn; the account worker's runner host calls it from PR 5 (mdk#2660).
    pub(crate) async fn recovery_runner_live_tails(
        &self,
        app: &SqliteAppStorage,
        now: u64,
    ) -> Box<dyn LiveTailRead> {
        let live = self.live_tails(app, now).await;
        Box::new(PostJoinTails {
            live,
            collecting: self
                .history_recovery
                .state
                .runner_post_join
                .values()
                .filter(|collection| collection.active && collection.collecting)
                .map(|collection| (collection.route.clone(), collection.until))
                .collect(),
        })
    }
}

/// A joined copy owes a finite collection through its activation time, even
/// inside an otherwise healthy live tail. After completion ordinary tail
/// authority resumes; this never authorizes periodic history polling.
struct PostJoinTails {
    live: LiveTails,
    collecting: std::collections::BTreeMap<TransportReconciliationRoute, u64>,
}

impl LiveTailRead for PostJoinTails {
    fn owed_until(&self, route: &TransportReconciliationRoute, relay: &str, now: u64) -> u64 {
        self.collecting
            .get(route)
            .copied()
            .unwrap_or_else(|| self.live.owed_until(route, relay, now))
            .min(now)
    }
}
