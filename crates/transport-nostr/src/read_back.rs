//! Reading a pending commit back from the relays that may hold it (mdk#2332).
//!
//! One REQ per relay, for the exact event id with `limit` 1, sent on the
//! account's anonymous publish pool: no signer answers AUTH there, and its
//! events reach no ingest. Only a copy that verifies as the exact event
//! counts as found. An EOSE without it is a relay that answered and does not
//! hold it; anything else answers nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use cgka_traits::{MemberId, TransportEndpoint, TransportReadBack};
use nostr_sdk::prelude::EventId;
use tokio::time::Instant;
use transport_nostr_adapter::{
    NostrAcquisitionCancellation, NostrAcquisitionEnd, NostrAcquisitionEndpoint,
    NostrAcquisitionLimits, NostrAcquisitionRequest, NostrAcquisitionScope, NostrRelayClient,
    NostrSdkRelayClient,
};
use transport_nostr_peeler::NostrTransportEvent;

use crate::known_limits::event_json_bytes;
use crate::safety::{RelaySafetyPolicy, canonical_relay, same_relay};

/// The read-back REQs one account sends one relay in an hour, at most. A read
/// past the cap is not sent, and answers nothing.
pub(crate) const READ_BACK_REQS_PER_RELAY_HOUR: usize = 8;
const READ_BACK_WINDOW: Duration = Duration::from_secs(60 * 60);
/// How long one read waits for every relay it asks.
pub(crate) const READ_BACK_WAIT: Duration = Duration::from_secs(10);

/// The read-back REQs each account sent each relay in the last hour. It lives
/// on the relay plane, so every adapter for an account shares it.
#[derive(Default)]
pub(crate) struct ReadBackBudget(Mutex<HashMap<(MemberId, String), VecDeque<Instant>>>);

impl ReadBackBudget {
    /// Spend one of `account`'s reads of `relay`, in its canonical spelling,
    /// at `now`, or refuse when the last hour already spent them all.
    pub(crate) fn take(&self, account: &MemberId, relay: &str, now: Instant) -> bool {
        let mut sent = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        sent.retain(|_, times| {
            while times
                .front()
                .is_some_and(|&at| now.saturating_duration_since(at) >= READ_BACK_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let times = sent.entry((account.clone(), relay.to_owned())).or_default();
        if times.len() >= READ_BACK_REQS_PER_RELAY_HOUR {
            return false;
        }
        times.push_back(now);
        true
    }
}

/// One read: an answer per endpoint, in order, and how many relays it sent a
/// REQ and how many returned the exact event.
pub(crate) struct ReadBackOutcome {
    pub(crate) answers: Vec<TransportReadBack>,
    pub(crate) requests: usize,
    pub(crate) found: usize,
}

/// Read `event` back from each of `endpoints` on `client`. An endpoint the
/// host-safety rule refuses, or one over the cap, is never asked. Spellings of
/// one relay share one REQ.
pub(crate) async fn read_back(
    client: &NostrSdkRelayClient,
    safety: &RelaySafetyPolicy,
    budget: &ReadBackBudget,
    account_id: &MemberId,
    event: &NostrTransportEvent,
    endpoints: &[TransportEndpoint],
) -> ReadBackOutcome {
    let mut outcome = ReadBackOutcome {
        answers: vec![TransportReadBack::NoAnswer; endpoints.len()],
        requests: 0,
        found: 0,
    };
    let Ok(frozen) = event.to_verified_nostr_event() else {
        return outcome;
    };
    let now = Instant::now();
    let mut asked: Vec<(TransportEndpoint, Vec<usize>)> = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let Some(relay) = safety.admitted_spelling(endpoint) else {
            continue;
        };
        if let Some((_, indexes)) = asked
            .iter_mut()
            .find(|(asked, _)| same_relay(&asked.0, &relay.0))
        {
            indexes.push(index);
        } else if budget.take(account_id, &canonical_relay(&relay.0), now) {
            asked.push((relay, vec![index]));
        }
    }
    if asked.is_empty() {
        return outcome;
    }
    // Room for the exact event however the relay serializes it; a copy past
    // this is not the event.
    let event_bytes = event_json_bytes(event).saturating_mul(2).max(4_096);
    let request = NostrAcquisitionRequest {
        account_id: account_id.clone(),
        scope: NostrAcquisitionScope::KnownEventIds(vec![frozen.id.to_bytes()]),
        endpoints: asked.iter().map(|(relay, _)| relay.clone()).collect(),
        limits: NostrAcquisitionLimits {
            max_endpoints: asked.len(),
            max_requested_event_ids: 1,
            max_received_items_per_endpoint: 1,
            max_serialized_event_bytes_per_endpoint: event_bytes,
            max_duration: READ_BACK_WAIT,
        },
    };
    outcome.requests = asked.len();
    let Ok(result) = client
        .acquire_history(request, NostrAcquisitionCancellation::new())
        .await
    else {
        return outcome;
    };
    for result in result.endpoints {
        let Some((_, indexes)) = asked.iter().find(|(relay, _)| relay == &result.endpoint) else {
            continue;
        };
        let answer = answer_of(&result, frozen.id);
        outcome.found += usize::from(answer == TransportReadBack::Found);
        for &index in indexes {
            outcome.answers[index] = answer;
        }
    }
    outcome
}

/// What one relay's answer says about the event `id` names. The SDK drops a
/// copy that fails verification before it gets here; this checks again.
pub(crate) fn answer_of(result: &NostrAcquisitionEndpoint, id: EventId) -> TransportReadBack {
    if result.events.iter().any(|returned| {
        returned
            .to_verified_nostr_event()
            .is_ok_and(|returned| returned.id == id)
    }) {
        TransportReadBack::Found
    } else if result.end == NostrAcquisitionEnd::RequestPolicySatisfied {
        TransportReadBack::NotFound
    } else {
        TransportReadBack::NoAnswer
    }
}
