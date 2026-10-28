//! [`SweepRelay`] over one relay of a [`NostrSdkRelayClient`]'s pool.
//!
//! It dials nothing: the endpoint must already be in the client's pool, which
//! admits relays only through the dial-safety chokepoint. An endpoint missing
//! from the pool reads as unreachable.
//!
//! nostr-sdk's EOSE parser drops NIP-67 hints, so slice REQs read `more` off
//! the wire through the client's hint tap ([`super::hint_tap`]). A client
//! built without the tap ([`NostrSdkRelayClient::new`]), a relay that sends no
//! hint, or a REQ the tap can't single out reports none. Either way the sweep
//! proves the slice by counting against the NIP-11 cap.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use nostr_sdk::prelude::{
    AcquisitionEnd, AcquisitionLimits, Client, Event, EventId, Filter, RelayAcquisition, RelayUrl,
    ReqTarget, SyncDirection, SyncOptions,
};
use tokio::sync::Semaphore;

use super::hint_tap::{EoseHints, HintWatch};
use super::{
    ClosedReason, RelayCaps, SecondReply, SliceQuery, SliceReply, SweepRelay, SweepRoute,
    UnreachableKind,
};
use crate::NostrSdkRelayClient;
use crate::sdk_client::{neg_sync_dry_run, sweep_eose_hints, sweep_neg_credit};

/// Default bytes one reply may carry. A full wok page is 5,000 events.
const REPLY_MAX_BYTES: usize = 64 * 1024 * 1024;
/// Ids per exact-id REQ when the relay publishes no cap.
const DEFAULT_IDS_PER_REQUEST: usize = 500;
/// `limit` on a one-second NIP-77 comparison, well under strfry's NEG ceiling
/// (5,000,000). A set that fills it may hide more ids, so it proves nothing.
const SECOND_NEG_LIMIT: usize = 100_000;

pub struct SdkSweepRelay {
    client: Client,
    endpoint: RelayUrl,
    caps: RelayCaps,
    neg_credit: Arc<Semaphore>,
    eose_hints: Option<Arc<EoseHints>>,
    request_timeout: Duration,
    reply_max_bytes: usize,
}

impl SdkSweepRelay {
    /// `caps` comes from the relay's NIP-11 document ([`RelayCaps::from_nip11`]).
    pub fn new(
        relay_client: &NostrSdkRelayClient,
        endpoint: RelayUrl,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Self {
        Self {
            client: relay_client.client().clone(),
            neg_credit: sweep_neg_credit(relay_client, &endpoint),
            eose_hints: sweep_eose_hints(relay_client),
            endpoint,
            caps,
            request_timeout,
            reply_max_bytes: REPLY_MAX_BYTES,
        }
    }

    /// Event JSON bytes one reply may carry. A slice over it is split, as a
    /// full reply is.
    pub fn with_reply_max_bytes(mut self, bytes: usize) -> Self {
        self.reply_max_bytes = bytes.max(1);
        self
    }

    /// One bounded REQ to this relay, closed at EOSE.
    async fn acquire(&self, filter: Filter, max_items: usize) -> Option<RelayAcquisition> {
        let limits =
            AcquisitionLimits::new(1, max_items, self.reply_max_bytes, self.request_timeout);
        let target = ReqTarget::manual([(self.endpoint.clone(), vec![filter])]);
        let handle = self.client.acquire_events(target, limits).await.ok()?;
        let mut report = handle.finish().await.ok()?;
        report.relays.remove(&self.endpoint)
    }
}

/// A terminal acquisition end other than a complete reply.
fn failed_end(end: AcquisitionEnd) -> Result<(), FailedEnd> {
    match end {
        AcquisitionEnd::Completed => Ok(()),
        AcquisitionEnd::Rejected(message) | AcquisitionEnd::RelayClosed(message) => {
            Err(FailedEnd::Closed(ClosedReason::from_message(&message)))
        }
        AcquisitionEnd::AuthenticationFailed => Err(FailedEnd::Closed(ClosedReason(Some(
            cgka_traits::TransportEndpointRejectionCategory::AuthRequired,
        )))),
        // More than one reply may hold: a cut, never a proof.
        AcquisitionEnd::ItemBudgetExceeded
        | AcquisitionEnd::ByteBudgetExceeded
        | AcquisitionEnd::ExitLimitReached => Err(FailedEnd::Cut),
        AcquisitionEnd::TimedOut => Err(FailedEnd::Unreachable(UnreachableKind::TimedOut)),
        // The reply was lost on its way in, or never started: nothing of it is
        // trusted, and the relay is retried like a dropped connection.
        AcquisitionEnd::Disconnected
        | AcquisitionEnd::Cancelled
        | AcquisitionEnd::ReceiveLoss(_)
        | AcquisitionEnd::InvalidMessage
        | AcquisitionEnd::ReceiverClosed
        | AcquisitionEnd::Failed(_) => Err(FailedEnd::Unreachable(UnreachableKind::Disconnected)),
    }
}

enum FailedEnd {
    Closed(ClosedReason),
    Cut,
    Unreachable(UnreachableKind),
}

#[async_trait]
impl SweepRelay for SdkSweepRelay {
    fn caps(&self) -> RelayCaps {
        self.caps
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        let limit = query.limit.map_or(usize::MAX, |limit| limit as usize);
        let filter = query.filter();
        // Registered before the REQ goes out; its EOSE fills it in.
        let watch = self
            .eose_hints
            .as_ref()
            .map(|hints| hints.watch(&self.endpoint, &filter));
        // One over the limit, so a relay that ignores `limit` reads as a cut.
        let Some(reply) = self.acquire(filter, limit.saturating_add(1)).await else {
            return SliceReply::Unreachable(UnreachableKind::Disconnected);
        };
        match failed_end(reply.end) {
            Ok(()) => SliceReply::Answered {
                received: reply.raw_received_items,
                events: reply.events.into_iter().collect(),
                more: watch.as_ref().is_some_and(HintWatch::more),
            },
            Err(FailedEnd::Cut) => SliceReply::Answered {
                events: Vec::new(),
                received: usize::MAX,
                more: true,
            },
            Err(FailedEnd::Closed(reason)) => SliceReply::Closed(reason),
            Err(FailedEnd::Unreachable(kind)) => SliceReply::Unreachable(kind),
        }
    }

    async fn fetch_second(&self, route: SweepRoute, second: u64, cap: Option<u32>) -> SecondReply {
        if !self.caps.negentropy {
            return SecondReply::Unproven;
        }
        let Ok(Some(relay)) = self.client.relay(&self.endpoint).await else {
            return SecondReply::Unreachable(UnreachableKind::Disconnected);
        };
        let options = SyncOptions::new()
            .initial_timeout(self.request_timeout)
            .idle_timeout(self.request_timeout)
            .direction(SyncDirection::Down)
            .dry_run();
        let deadline = tokio::time::Instant::now() + self.request_timeout;
        let ids = match neg_sync_dry_run(
            &relay,
            route.second_filter(second, second).limit(SECOND_NEG_LIMIT),
            options,
            self.neg_credit.clone(),
            deadline,
        )
        .await
        {
            Ok(ids) => ids,
            Err(NegFailure::Closed(reason)) => return SecondReply::Closed(reason),
            Err(NegFailure::Unreachable(kind)) => return SecondReply::Unreachable(kind),
            Err(NegFailure::Unproven) => return SecondReply::Unproven,
        };
        if ids.len() >= SECOND_NEG_LIMIT {
            return SecondReply::Unproven;
        }
        let mut wanted = ids.into_iter().collect::<Vec<EventId>>();
        wanted.sort();
        let per_request = cap
            .map_or(DEFAULT_IDS_PER_REQUEST, |cap| cap as usize)
            .max(1);
        let mut events = Vec::with_capacity(wanted.len());
        let mut pending = wanted
            .chunks(per_request)
            .rev()
            .map(<[EventId]>::to_vec)
            .collect::<Vec<_>>();
        while let Some(chunk) = pending.pop() {
            // An explicit limit, so a relay's default page cannot short the chunk.
            let filter = route
                .second_filter(second, second)
                .ids(chunk.iter().copied())
                .limit(chunk.len());
            let Some(reply) = self.acquire(filter, chunk.len().saturating_add(1)).await else {
                return SecondReply::Unreachable(UnreachableKind::Disconnected);
            };
            match failed_end(reply.end) {
                Ok(()) => {}
                Err(FailedEnd::Closed(reason)) => return SecondReply::Closed(reason),
                Err(FailedEnd::Unreachable(kind)) => return SecondReply::Unreachable(kind),
                // Large events can outgrow the byte budget: split the chunk
                // and ask again. One id that still does not fit stays unproven.
                Err(FailedEnd::Cut) if chunk.len() > 1 => {
                    let (older, newer) = chunk.split_at(chunk.len() / 2);
                    pending.push(newer.to_vec());
                    pending.push(older.to_vec());
                    continue;
                }
                Err(FailedEnd::Cut) => return SecondReply::Unproven,
            }
            let asked = chunk.iter().copied().collect::<HashSet<_>>();
            let got = reply
                .events
                .into_iter()
                .filter(|event| asked.contains(&event.id))
                .collect::<Vec<Event>>();
            // A relay that claimed an id and then withheld it proves nothing.
            if got.len() != asked.len() {
                return SecondReply::Unproven;
            }
            events.extend(got);
        }
        SecondReply::Complete(events)
    }
}

/// Why a NIP-77 comparison of one second failed.
pub(crate) enum NegFailure {
    Closed(ClosedReason),
    Unreachable(UnreachableKind),
    /// No NIP-77, or a protocol error: the second stays unproven.
    Unproven,
}
