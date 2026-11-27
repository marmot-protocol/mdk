//! Relay health's inbox check: one bounded read per relay of this account's
//! gift wraps (kind 1059 addressed to it), answered with the signer the
//! account worker holds, on the relay plane's isolated inspection client:
//! its own short-lived connection per relay, never a pooled one, so it
//! cannot disturb the account's live subscriptions or their authentication,
//! and it counts toward no relay liveness, publish accounting or telemetry.
//! The
//! account worker runs it beside its loop and owns its result (see
//! `runtime::account_worker::relay_checks`); this module is the probe and
//! what its answers establish. No event payload is kept.
//!
//! A run that reaches no relay establishes nothing: with every relay
//! unreachable or timed out, this device may simply be offline. A relay's
//! silence counts only beside a relay of the same run that answered.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use cgka_traits::TransportEndpoint;

use transport_nostr::{DirectoryInspectionError, MarmotRelayPlane};
use transport_nostr_peeler::MarmotNostrSigner;

use super::{RelayHealthFault, RelayHealthState};

/// The longest one relay's probe takes before it is reported `TimedOut`.
const RELAY_CHECK_WAIT: Duration = Duration::from_secs(15);
// A relay inspection must end on its own terms (EOSE, CLOSED, its timeout)
// before this per-relay budget cuts it off as `TimedOut`.
const _: () = assert!(
    RELAY_CHECK_WAIT.as_millis() > transport_nostr::DIRECTORY_INSPECTION_WAIT.as_millis(),
    "RELAY_CHECK_WAIT must outlast one relay inspection"
);

/// The most relays one run dials.
pub(crate) const MAX_CHECKED_RELAYS: usize = 16;

/// What one inbox check established about one relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckRecord {
    pub(crate) state: RelayHealthState,
    pub(crate) fault: Option<RelayHealthFault>,
    /// When the run asked, in Unix seconds.
    pub(crate) checked_at_unix: u64,
}

/// An account's established checks and the relays a check is running for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CheckSnapshot {
    pub(crate) results: BTreeMap<String, CheckRecord>,
    pub(crate) checking: BTreeSet<String>,
}

/// Each relay of one run, with what it established, `None` for nothing.
pub(crate) type RunOutcome = BTreeMap<String, Option<CheckRecord>>;

/// What a run needs to dial.
pub(crate) struct RunInputs {
    pub(crate) plane: MarmotRelayPlane,
    pub(crate) account_id_hex: String,
    /// The signer the account worker holds.
    pub(crate) signer: Arc<dyn MarmotNostrSigner>,
    /// It is the account's own key, which always answers a NIP-42
    /// challenge at once; a remote or host signer may not, so a refusal
    /// under it proves nothing.
    pub(crate) local_key: bool,
}

/// Run the inbox check of `relays`: every relay at once, each within
/// [`RELAY_CHECK_WAIT`]. Every probe is a future of this one, never a task
/// of its own, so dropping this future (the worker cancelling its check)
/// drops every probe and stops its relay connection with it.
pub(crate) async fn run(relays: &BTreeSet<String>, inputs: &RunInputs) -> RunOutcome {
    let probes = relays.iter().map(|relay| async move {
        let probe = inputs.plane.inspect_inbox(
            TransportEndpoint(relay.clone()),
            inputs.account_id_hex.clone(),
            inputs.signer.clone(),
        );
        let result = tokio::time::timeout(RELAY_CHECK_WAIT, probe)
            .await
            .unwrap_or(Err(DirectoryInspectionError::TimedOut));
        (relay.clone(), result)
    });
    let results = futures::future::join_all(probes)
        .await
        .into_iter()
        .collect();
    established(results, inputs.local_key, crate::unix_now_seconds())
}

/// What a run's `results` establish about each relay.
pub(crate) fn established(
    results: BTreeMap<String, Result<(), DirectoryInspectionError>>,
    local_key: bool,
    checked_at_unix: u64,
) -> RunOutcome {
    use DirectoryInspectionError::*;
    use RelayHealthState::{Failing, Healthy, Suspected};
    // The offline rule: a relay that did not connect or answer in time says
    // something about itself only beside one that answered in the same run.
    let answered = results.values().any(|result| {
        !matches!(
            result,
            Err(Unreachable | TimedOut | InvalidRequest | LocalBusy)
        )
    });
    // Only the account's own key always answers a NIP-42 challenge; under a
    // remote or host signer a refusal may be the signer's silence.
    let refused = if local_key { Failing } else { Suspected };
    results
        .into_iter()
        .map(|(relay, result)| {
            let state = match result {
                Ok(()) => Some((Healthy, None)),
                Err(AuthenticationRequired | AuthenticationRejected) => {
                    Some((refused, Some(RelayHealthFault::AuthenticationRequired)))
                }
                // The relay's reply to the AUTH went unread (a refusal cannot
                // be told from a rate limit), or the signer did not produce a
                // usable signature: never `Failing`.
                Err(
                    AuthenticationUnconfirmed | AuthenticationTimedOut | AuthenticationSignerFailed,
                ) => Some((Suspected, Some(RelayHealthFault::AuthenticationRequired))),
                Err(PaymentRequired) => Some((refused, Some(RelayHealthFault::PaymentRequired))),
                Err(Restricted) => Some((refused, Some(RelayHealthFault::Restricted))),
                Err(Unexplained) => Some((Suspected, Some(RelayHealthFault::Unexplained))),
                Err(Unreachable) => {
                    answered.then_some((Suspected, Some(RelayHealthFault::Unreachable)))
                }
                Err(TimedOut) => answered.then_some((Suspected, Some(RelayHealthFault::TimedOut))),
                // A rate limit, of the read or of its authentication, is no
                // fault; a request this device could not
                // send, or an answer the inbox read never gives, says nothing
                // of the relay.
                Err(
                    RateLimited
                    | AuthenticationRateLimited
                    | InvalidRequest
                    | Incomplete
                    | LocalBusy
                    | Partial { .. },
                ) => None,
            };
            let record = state.map(|(state, fault)| CheckRecord {
                state,
                fault,
                checked_at_unix,
            });
            (relay, record)
        })
        .collect()
}
