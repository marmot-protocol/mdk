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

/// One worker turn's read of the live tails.
pub(crate) trait LiveTailRead: Send + Sync {
    /// The last second the ledger must prove on `relay` for `route` at `now`:
    /// the second before a standing tail starts there, else `now`.
    fn owed_until(&self, route: &TransportReconciliationRoute, relay: &str, now: u64) -> u64;
}

/// No tail stands: everything through `now` is owed. This subtracts nothing,
/// so the runner never treats an unproven second as covered.
pub(crate) struct OwedThroughNow;

impl LiveTailRead for OwedThroughNow {
    fn owed_until(&self, _route: &TransportReconciliationRoute, _relay: &str, now: u64) -> u64 {
        now
    }
}

impl AppClient {
    /// The live tails a runner's debt turn subtracts, read now. The worker
    /// calls this at the start of every debt turn and drops the answer with
    /// the turn.
    ///
    /// Until the capped live boundary (PR 2d) lands this owes everything;
    /// then it returns `AppClient::live_tails(app, now)`, which re-observes
    /// the adapter and asks the relay client whether each generation's relay
    /// is still connected.
    // The account worker's runner host calls this from PR 5 (mdk#2660).
    #[allow(dead_code)]
    pub(crate) async fn recovery_runner_live_tails(
        &self,
        _app: &SqliteAppStorage,
        _now: u64,
    ) -> Box<dyn LiveTailRead> {
        Box::new(OwedThroughNow)
    }
}
