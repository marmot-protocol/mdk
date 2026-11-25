//! [`SweepRelay`] over one relay of a [`NostrSdkRelayClient`]'s pool, and the
//! same relay as a [`CompareRelay`] for the recovery runner's NIP-77
//! comparisons.
//!
//! It dials nothing: the endpoint must already be in the client's pool, which
//! admits relays only through the dial-safety chokepoint. An endpoint missing
//! from the pool reads as unreachable.
//!
//! Every REQ is a finite request ([`crate::finite_req`]): its replies never
//! reach the SDK's reader, so a large page delays no live message, and its
//! EOSE keeps its NIP-67 hints: `more` splits the slice, and `auth` reads as
//! the relay asking for authentication. A reply retried after authentication
//! joins two pages, so it splits the slice too. A relay that sends no hint is
//! proven by counting against the NIP-11 cap. A client built
//! without finite requests ([`NostrSdkRelayClient::new`]) reads as
//! unreachable.
//!
//! An interrupted relay cancels its request in flight rather than dropping
//! it: a cancelled request still reports every event byte it received, so a
//! cut reply is metered like any other. Its NIP-77 exchanges carry ids, not
//! events, and are dropped.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use cgka_traits::TransportEndpointRejectionCategory;
use nostr_sdk::prelude::{
    Client, Event, EventId, Filter, Relay, RelayUrl, SyncDirection, SyncOptions, Timestamp,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{
    ClosedReason, RelayCaps, SecondReply, SliceQuery, SliceReply, SweepRange, SweepRelay,
    SweepRoute, UnreachableKind,
};
use crate::NostrSdkRelayClient;
use crate::compare::{CompareRelay, CompareReply, IdsReply, LocalItem};
use crate::finite_req::{FiniteEnd, FiniteLimits, FiniteReply, FiniteRequests};
use crate::sdk_client::{NegCompared, neg_sync_dry_run, sweep_finite_requests, sweep_neg_credit};

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
    caps: Option<RelayCaps>,
    neg_credit: Arc<Semaphore>,
    finite: Option<FiniteRequests>,
    request_timeout: Duration,
    reply_max_bytes: usize,
    /// Event bytes read since [`SweepRelay::take_fetched_bytes`] last ran.
    fetched_bytes: AtomicU64,
    /// Set by [`SweepRelay::interrupt`]: the acquisition in flight is
    /// cancelled, and nothing more is asked.
    interrupted: CancellationToken,
}

impl SdkSweepRelay {
    /// `caps` comes from the relay's NIP-11 document ([`RelayCaps::from_nip11`]).
    pub fn new(
        relay_client: &NostrSdkRelayClient,
        endpoint: RelayUrl,
        caps: RelayCaps,
        request_timeout: Duration,
    ) -> Self {
        Self::from_optional_caps(relay_client, endpoint, Some(caps), request_timeout)
    }

    /// Without a current or previously read NIP-11 document, a sweep may try
    /// NIP-77 to prove a single second after ordinary slice counts failed.
    pub fn from_optional_caps(
        relay_client: &NostrSdkRelayClient,
        endpoint: RelayUrl,
        caps: Option<RelayCaps>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            client: relay_client.client().clone(),
            neg_credit: sweep_neg_credit(relay_client, &endpoint),
            finite: sweep_finite_requests(relay_client),
            endpoint,
            caps,
            request_timeout,
            reply_max_bytes: REPLY_MAX_BYTES,
            fetched_bytes: AtomicU64::new(0),
            interrupted: CancellationToken::new(),
        }
    }

    /// Event JSON bytes one reply may carry. A slice over it is split, as a
    /// full reply is.
    pub fn with_reply_max_bytes(mut self, bytes: usize) -> Self {
        self.reply_max_bytes = bytes.max(1);
        self
    }

    /// A NIP-77 comparison of `filter` with `items` that downloads nothing,
    /// under the request timeout. An interruption drops it: it carries ids,
    /// not events, so there is nothing to meter.
    async fn neg_compare(
        &self,
        relay: &Relay,
        filter: Filter,
        items: Vec<(EventId, Timestamp)>,
    ) -> Result<NegCompared, NegFailure> {
        let options = SyncOptions::new()
            .initial_timeout(self.request_timeout)
            .idle_timeout(self.request_timeout)
            .direction(SyncDirection::Down)
            .dry_run();
        let deadline = tokio::time::Instant::now() + self.request_timeout;
        tokio::select! {
            compared = neg_sync_dry_run(
                relay,
                filter,
                items,
                options,
                self.neg_credit.clone(),
                deadline,
            ) => compared,
            () = self.interrupted.cancelled() => {
                Err(NegFailure::Unreachable(UnreachableKind::Disconnected))
            }
        }
    }

    /// A relay that refused the NEG-OPEN itself. With no document, that
    /// refusal means it cannot prove the second, as a document that omits
    /// NIP-77 says (mdk#3264); its REQ still answered. A rate limit is waited
    /// out, and an `auth-required:` or `error:` refusal may pass on a later
    /// attempt.
    fn second_declined(&self, reason: ClosedReason) -> SecondReply {
        use TransportEndpointRejectionCategory as Category;
        match reason.0 {
            _ if self.caps.is_some() => SecondReply::Closed(reason),
            Some(Category::RateLimited) => SecondReply::Closed(reason),
            Some(Category::AuthRequired | Category::Error) => SecondReply::Inconclusive,
            _ => SecondReply::Unproven,
        }
    }

    /// Refusal of an optional probe does not refuse the ordinary history
    /// request that just succeeded. An explicit rate limit still applies.
    fn second_refused(&self, reason: ClosedReason) -> SecondReply {
        if self.caps.is_none() && reason.0 != Some(TransportEndpointRejectionCategory::RateLimited)
        {
            SecondReply::Inconclusive
        } else {
            SecondReply::Closed(reason)
        }
    }

    /// One finite REQ to this relay, closed at EOSE. An interruption cancels
    /// it, and its partial reply still reports the bytes it read; `None` once
    /// interrupted before it began, or when the relay is not in the pool.
    async fn acquire(&self, filter: Filter, max_items: usize) -> Option<FiniteReply> {
        if self.interrupted.is_cancelled() {
            return None;
        }
        let finite = self.finite.as_ref()?;
        let relay = self.client.relay(&self.endpoint).await.ok()??;
        let limits = FiniteLimits {
            max_items,
            max_event_bytes: self.reply_max_bytes,
            timeout: self.request_timeout,
        };
        let reply = finite
            .fetch(&relay, vec![filter], limits, &self.interrupted)
            .await;
        self.fetched_bytes
            .fetch_add(reply.fetched_bytes, Ordering::Relaxed);
        Some(reply)
    }
}

/// A terminal request end other than a complete reply.
fn failed_end(end: FiniteEnd) -> Result<(), FailedEnd> {
    match end {
        FiniteEnd::Eose => Ok(()),
        FiniteEnd::Closed(message) => Err(FailedEnd::Closed(ClosedReason::from_message(&message))),
        // More than one reply may hold: a cut, never a proof.
        FiniteEnd::ItemLimit | FiniteEnd::ByteLimit => Err(FailedEnd::Cut),
        FiniteEnd::TimedOut => Err(FailedEnd::Unreachable(UnreachableKind::TimedOut)),
        // The reply was lost on its way in, or never started: nothing of it is
        // trusted, and the relay is retried like a dropped connection.
        FiniteEnd::Disconnected
        | FiniteEnd::Cancelled
        | FiniteEnd::InvalidMessage
        | FiniteEnd::SetupFailed => Err(FailedEnd::Unreachable(UnreachableKind::Disconnected)),
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
        self.caps.unwrap_or_default()
    }

    async fn fetch_slice(&self, query: SliceQuery) -> SliceReply {
        let limit = query.limit.map_or(usize::MAX, |limit| limit as usize);
        // One over the limit, so a relay that ignores `limit` reads as a cut.
        let Some(reply) = self.acquire(query.filter(), limit.saturating_add(1)).await else {
            return SliceReply::Unreachable(UnreachableKind::Disconnected);
        };
        match failed_end(reply.end) {
            // NIP-67 `auth` after the finite request's retry: the relay may
            // still hold events back until the client authenticates, so it
            // stands as an `auth-required:` refusal would; splitting the
            // slice cannot help.
            Ok(()) if reply.auth => SliceReply::Closed(ClosedReason(Some(
                TransportEndpointRejectionCategory::AuthRequired,
            ))),
            // Two attempts' pages, which no count proves as one: split the
            // slice and ask again, now authenticated.
            Ok(()) if reply.retried => SliceReply::Answered {
                events: Vec::new(),
                received: reply.raw_items,
                more: true,
            },
            Ok(()) => SliceReply::Answered {
                received: reply.raw_items,
                events: reply.events,
                more: reply.more,
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
        if self.caps.is_some_and(|caps| !caps.negentropy) {
            return SecondReply::Unproven;
        }
        let Ok(Some(relay)) = self.client.relay(&self.endpoint).await else {
            return SecondReply::Unreachable(UnreachableKind::Disconnected);
        };
        let ids = match self
            .neg_compare(
                &relay,
                route.second_filter(second, second).limit(SECOND_NEG_LIMIT),
                Vec::new(),
            )
            .await
        {
            Ok(compared) => compared.remote,
            Err(NegFailure::Declined(reason)) => return self.second_declined(reason),
            Err(NegFailure::Closed(reason)) => return self.second_refused(reason),
            // A relay that ignores an unadvertised NEG-OPEN still answered its REQ.
            Err(NegFailure::Unreachable(UnreachableKind::TimedOut)) if self.caps.is_none() => {
                return SecondReply::Inconclusive;
            }
            Err(NegFailure::Unreachable(kind)) => return SecondReply::Unreachable(kind),
            Err(NegFailure::Unproven) => return SecondReply::Unproven,
            Err(NegFailure::Inconclusive) => return SecondReply::Inconclusive,
            // Not the relay's answer: retried like a dropped connection, never
            // a second the relay cannot prove.
            Err(NegFailure::Local) => {
                return SecondReply::Unreachable(UnreachableKind::Disconnected);
            }
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
                Err(FailedEnd::Closed(reason)) => return self.second_refused(reason),
                Err(FailedEnd::Unreachable(kind)) => return SecondReply::Unreachable(kind),
                // Large events can outgrow the byte budget: split the chunk
                // and ask again.
                Err(FailedEnd::Cut) if chunk.len() > 1 => {
                    let (older, newer) = chunk.split_at(chunk.len() / 2);
                    pending.push(newer.to_vec());
                    pending.push(older.to_vec());
                    continue;
                }
                // The budget counts every frame before duplicates are
                // dropped, so a cut one-id reply is not an event that fits
                // no reply (64 MiB is far above any relay's event limit): a
                // later attempt may prove the second.
                Err(FailedEnd::Cut) => return SecondReply::Inconclusive,
            }
            let asked = chunk.iter().copied().collect::<HashSet<_>>();
            let got = reply
                .events
                .into_iter()
                .filter(|event| asked.contains(&event.id))
                .collect::<Vec<Event>>();
            // A relay that claimed an id and then withheld it proves nothing
            // now; it may have dropped the event since listing it, so a
            // later attempt may prove the second.
            if got.len() != asked.len() {
                return SecondReply::Inconclusive;
            }
            events.extend(got);
        }
        SecondReply::Complete(events)
    }

    fn take_fetched_bytes(&self) -> u64 {
        self.fetched_bytes.swap(0, Ordering::Relaxed)
    }

    /// Cancel the acquisition in flight, which then reports what it read, and
    /// stop a second's id fetch issuing more chunks.
    fn interrupt(&self) -> bool {
        self.interrupted.cancel();
        true
    }
}

#[async_trait]
impl CompareRelay for SdkSweepRelay {
    fn caps(&self) -> RelayCaps {
        self.caps.unwrap_or_default()
    }

    async fn compare(
        &self,
        route: SweepRoute,
        window: SweepRange,
        local: &[LocalItem],
        limit: usize,
    ) -> CompareReply {
        let Ok(Some(relay)) = self.client.relay(&self.endpoint).await else {
            return CompareReply::Unreachable(UnreachableKind::Disconnected);
        };
        let items = local
            .iter()
            .map(|item| (item.id, Timestamp::from_secs(item.created_at)))
            .collect();
        match self
            .neg_compare(
                &relay,
                route.second_filter(window.since, window.until).limit(limit),
                items,
            )
            .await
        {
            Ok(compared) => CompareReply::Compared {
                missing: compared.remote.into_iter().collect(),
                relay_set: compared.relay_set,
            },
            Err(NegFailure::Closed(reason) | NegFailure::Declined(reason)) => {
                CompareReply::Closed(reason)
            }
            Err(NegFailure::Unreachable(kind)) => CompareReply::Unreachable(kind),
            // A comparison falls back to a sweep either way.
            Err(NegFailure::Unproven | NegFailure::Inconclusive) => CompareReply::Unsupported,
            // Not the relay's fault: retried like a dropped connection.
            Err(NegFailure::Local) => CompareReply::Unreachable(UnreachableKind::Disconnected),
        }
    }

    async fn fetch_ids(&self, route: SweepRoute, window: SweepRange, ids: &[EventId]) -> IdsReply {
        let mut events = Vec::with_capacity(ids.len());
        let mut pending = vec![ids.to_vec()];
        while let Some(chunk) = pending.pop() {
            if chunk.is_empty() {
                continue;
            }
            // An explicit limit, so a relay's default page cannot short the chunk.
            let filter = route
                .second_filter(window.since, window.until)
                .ids(chunk.iter().copied())
                .limit(chunk.len());
            let Some(reply) = self.acquire(filter, chunk.len().saturating_add(1)).await else {
                return IdsReply::Unreachable(UnreachableKind::Disconnected);
            };
            match failed_end(reply.end) {
                Ok(()) => events.extend(reply.events),
                Err(FailedEnd::Closed(reason)) => return IdsReply::Closed(reason),
                Err(FailedEnd::Unreachable(kind)) => return IdsReply::Unreachable(kind),
                // Large events can outgrow the byte budget: split the chunk
                // and ask again. One id that still does not fit is left out,
                // and the caller reads it as withheld.
                Err(FailedEnd::Cut) if chunk.len() > 1 => {
                    let (older, newer) = chunk.split_at(chunk.len() / 2);
                    pending.push(newer.to_vec());
                    pending.push(older.to_vec());
                }
                Err(FailedEnd::Cut) => {}
            }
        }
        IdsReply::Answered(events)
    }

    fn take_fetched_bytes(&self) -> u64 {
        SweepRelay::take_fetched_bytes(self)
    }

    fn interrupt(&self) -> bool {
        SweepRelay::interrupt(self)
    }
}

/// Why a NIP-77 comparison failed.
pub(crate) enum NegFailure {
    Closed(ClosedReason),
    /// The relay answered the NEG-OPEN with NEG-ERR before any NEG-MSG: it
    /// never began reconciling.
    Declined(ClosedReason),
    Unreachable(UnreachableKind),
    /// The relay said it lacks NIP-77: the second stays unproven.
    Unproven,
    /// An exchange that proved nothing this time (a malformed message, an
    /// SDK protocol error): a later attempt may complete it.
    Inconclusive,
    /// A local fault, not the relay's.
    Local,
}

#[cfg(test)]
mod tests {
    use cgka_traits::TransportEndpointRejectionCategory as Category;

    use super::*;

    #[test]
    fn request_ends_never_manufacture_completeness() {
        #[derive(Debug, PartialEq, Eq)]
        enum End {
            Complete,
            Closed(Option<Category>),
            Cut,
            Unreachable(UnreachableKind),
        }
        for (input, expected) in [
            (FiniteEnd::Eose, End::Complete),
            (
                FiniteEnd::Closed("restricted: private diagnostic".into()),
                End::Closed(Some(Category::Restricted)),
            ),
            (
                FiniteEnd::Closed("private diagnostic".into()),
                End::Closed(None),
            ),
            (
                FiniteEnd::Closed("auth-required: sign in".into()),
                End::Closed(Some(Category::AuthRequired)),
            ),
            (FiniteEnd::ItemLimit, End::Cut),
            (FiniteEnd::ByteLimit, End::Cut),
            (
                FiniteEnd::TimedOut,
                End::Unreachable(UnreachableKind::TimedOut),
            ),
            (
                FiniteEnd::Disconnected,
                End::Unreachable(UnreachableKind::Disconnected),
            ),
            (
                FiniteEnd::Cancelled,
                End::Unreachable(UnreachableKind::Disconnected),
            ),
            (
                FiniteEnd::InvalidMessage,
                End::Unreachable(UnreachableKind::Disconnected),
            ),
            (
                FiniteEnd::SetupFailed,
                End::Unreachable(UnreachableKind::Disconnected),
            ),
        ] {
            let actual = match failed_end(input) {
                Ok(()) => End::Complete,
                Err(FailedEnd::Closed(reason)) => End::Closed(reason.0),
                Err(FailedEnd::Cut) => End::Cut,
                Err(FailedEnd::Unreachable(kind)) => End::Unreachable(kind),
            };
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn an_endpoint_missing_from_the_pool_stays_unreachable() {
        let sdk = NostrSdkRelayClient::from_builder(crate::network_proxy::nostr_builder(Ok(None)));
        let relay = SdkSweepRelay::new(
            &sdk,
            RelayUrl::parse("wss://missing.example.com").unwrap(),
            RelayCaps {
                max_limit: Some(500),
                negentropy: true,
            },
            Duration::from_secs(1),
        );
        assert!(sdk.client().relays().all().await.is_empty());
        let route = SweepRoute::Group {
            nostr_group_id: [7; 32],
        };
        let range = SweepRange { since: 1, until: 2 };
        assert!(matches!(
            CompareRelay::compare(&relay, route, range, &[], 5).await,
            CompareReply::Unreachable(UnreachableKind::Disconnected)
        ));
        assert!(matches!(
            relay.fetch_second(route, 1, Some(500)).await,
            SecondReply::Unreachable(UnreachableKind::Disconnected)
        ));
        assert!(sdk.client().relays().all().await.is_empty());
        sdk.shutdown().await;
    }

    /// A client built without finite requests cannot sweep: its relay reads
    /// as unreachable, never as a page the relay answered.
    #[tokio::test]
    async fn a_client_without_finite_requests_reads_as_unreachable() {
        let sdk = NostrSdkRelayClient::new(Client::default());
        let endpoint = RelayUrl::parse("wss://opaque.invalid").unwrap();
        // In the pool but never connected: nothing is dialed.
        sdk.client().add_relay(endpoint.clone()).await.unwrap();
        let relay = SdkSweepRelay::new(
            &sdk,
            endpoint,
            RelayCaps {
                max_limit: Some(500),
                negentropy: true,
            },
            Duration::from_secs(1),
        );
        let query = SliceQuery {
            route: SweepRoute::Group {
                nostr_group_id: [7; 32],
            },
            since: 1,
            until: 2,
            limit: Some(500),
        };
        assert!(matches!(
            relay.fetch_slice(query).await,
            SliceReply::Unreachable(UnreachableKind::Disconnected)
        ));
        sdk.shutdown().await;
    }

    /// A local fault in a NIP-77 read is not the relay's answer: a second's
    /// id read retries it like a dropped connection, as a comparison does,
    /// and never reads it as a second the relay cannot prove.
    #[tokio::test]
    async fn a_local_negentropy_fault_is_retried_not_unproven() {
        let sdk = NostrSdkRelayClient::from_builder(crate::network_proxy::nostr_builder(Ok(None)));
        let endpoint = RelayUrl::parse("wss://local-fault.invalid").unwrap();
        // In the pool but never connected: nothing is dialed.
        sdk.client().add_relay(endpoint.clone()).await.unwrap();
        let relay = SdkSweepRelay::new(
            &sdk,
            endpoint,
            RelayCaps {
                max_limit: Some(500),
                negentropy: true,
            },
            Duration::from_secs(1),
        );
        // A closed NEG credit fails before anything is sent.
        relay.neg_credit.close();
        let route = SweepRoute::Group {
            nostr_group_id: [7; 32],
        };
        let range = SweepRange { since: 1, until: 2 };
        assert!(matches!(
            CompareRelay::compare(&relay, route, range, &[], 5).await,
            CompareReply::Unreachable(UnreachableKind::Disconnected)
        ));
        assert!(matches!(
            relay.fetch_second(route, 1, Some(500)).await,
            SecondReply::Unreachable(UnreachableKind::Disconnected)
        ));
        sdk.shutdown().await;
    }
}
