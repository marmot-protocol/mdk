//! Bounded reads for verified public-event previews.
//!
//! Only exact event IDs, complete coordinates, NIP-09 kind-5 `#e`/`#a`
//! requests by a known author, and that author's kind-0 metadata can be asked
//! for. Every request uses a fresh anonymous SDK client whose only WebSocket
//! transport is [`PinnedPublicEventTransport`]: endpoints pass
//! [`super::RelaySafetyPolicy`], hostnames are resolved once, every address is
//! validated and the socket is pinned before TLS (see
//! `public_event_transport.rs`). At most four relays, the caller's absolute
//! deadline, a raw wire-byte budget charged below TLS/WebSocket parsing and an
//! item budget charged on decoded messages before the SDK verifies or
//! deduplicates anything. A phase meter is a child of the caller's
//! request-wide meter, so the totals hold across relays and phases. Each phase
//! owns its sockets and force-closes them when it ends or is cancelled.
//! Nothing here verifies, persists or logs event data; callers own admission.

use std::sync::Arc;
use std::time::Duration;

use cgka_traits::TransportEndpoint;
use nostr_sdk::prelude::{
    AcquisitionLimits, Client as NostrSdkClient, EventId, Filter, Kind, PublicKey, RelayUrl,
    ReqTarget, SingleLetterTag,
};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout, timeout_at};

use super::public_event_transport::{
    CloseSocketsOnDrop, PinnedPublicEventTransport, PublicEventSocketRegistry,
    PublicEventTrafficLimits, PublicEventTrafficMeter,
};
use super::{DIRECTORY_RELAY_CONNECT_WAIT, RelaySafetyPolicy};

/// Maximum relays one public-event preview request may contact.
pub(crate) const PUBLIC_EVENT_QUERY_MAX_RELAYS: usize = 4;

/// One narrow filter shape. Values are canonical lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PublicEventQueryFilter {
    EventId {
        event_id_hex: String,
    },
    Coordinate {
        kind: u16,
        author_hex: String,
        identifier: String,
    },
    EventDeletions {
        event_id_hex: String,
        author_hex: String,
    },
    /// `coordinate` is the NIP-01 `a` value: `kind:pubkey:identifier`.
    CoordinateDeletions {
        coordinate: String,
        author_hex: String,
    },
    AuthorMetadata {
        author_hex: String,
    },
}

/// Received-traffic budget for one phase across all of its relays. The
/// request-wide meter passed alongside it bounds every phase together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PublicEventQueryBudget {
    pub(crate) max_items: usize,
    pub(crate) max_bytes: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PublicEventQueryOutcome {
    /// Distinct serialized events in arrival order, within the budget.
    pub(crate) events_json: Vec<String>,
    /// Raw `EVENT` envelopes this phase received, duplicates, invalid and
    /// over-budget frames included.
    pub(crate) received_items: usize,
    /// Raw wire bytes this phase received (TLS, HTTP upgrade and every
    /// WebSocket frame, fragments included).
    pub(crate) received_bytes: usize,
}

impl super::MarmotRelayPlane {
    /// Query safe relays for public-event preview evidence. Unsafe, retired or
    /// policy-rejected endpoints are dropped before any dial, and the pinned
    /// transport re-checks each dial. An empty outcome says nothing about
    /// whether the events exist.
    pub(crate) async fn query_public_events(
        &self,
        endpoints: Vec<TransportEndpoint>,
        filters: Vec<PublicEventQueryFilter>,
        budget: PublicEventQueryBudget,
        request: &Arc<PublicEventTrafficMeter>,
        deadline: Instant,
    ) -> PublicEventQueryOutcome {
        let policy = self.inner.relay_safety.clone();
        let endpoints = policy.retain_safe_endpoints(endpoints, "public event query");
        query_public_events_on(policy, endpoints, filters, budget, request, deadline).await
    }
}

fn sdk_filter(filter: &PublicEventQueryFilter) -> Option<Filter> {
    let tag = |name: char| SingleLetterTag::from_char(name).ok();
    Some(match filter {
        PublicEventQueryFilter::EventId { event_id_hex } => Filter::new()
            .ids([EventId::from_hex(event_id_hex).ok()?])
            .limit(1),
        PublicEventQueryFilter::Coordinate {
            kind,
            author_hex,
            identifier,
        } => {
            let filter = Filter::new()
                .kind(Kind::from(*kind))
                .authors([PublicKey::parse(author_hex).ok()?])
                .limit(4);
            // Ordinary replaceable kinds carry no `d` tag.
            if (30_000..40_000).contains(kind) {
                filter.custom_tags(tag('d')?, [identifier.clone()])
            } else {
                filter
            }
        }
        PublicEventQueryFilter::EventDeletions {
            event_id_hex,
            author_hex,
        } => Filter::new()
            .kind(Kind::from(5u16))
            .authors([PublicKey::parse(author_hex).ok()?])
            .custom_tags(tag('e')?, [event_id_hex.clone()])
            .limit(4),
        PublicEventQueryFilter::CoordinateDeletions {
            coordinate,
            author_hex,
        } => Filter::new()
            .kind(Kind::from(5u16))
            .authors([PublicKey::parse(author_hex).ok()?])
            .custom_tags(tag('a')?, [coordinate.clone()])
            .limit(4),
        PublicEventQueryFilter::AuthorMetadata { author_hex } => Filter::new()
            .kind(Kind::from(0u16))
            .authors([PublicKey::parse(author_hex).ok()?])
            .limit(1),
    })
}

/// Execute one bounded phase over already-sanitized endpoints.
pub(super) async fn query_public_events_on(
    policy: RelaySafetyPolicy,
    endpoints: Vec<TransportEndpoint>,
    filters: Vec<PublicEventQueryFilter>,
    budget: PublicEventQueryBudget,
    request: &Arc<PublicEventTrafficMeter>,
    deadline: Instant,
) -> PublicEventQueryOutcome {
    let mut outcome = PublicEventQueryOutcome::default();
    if budget.max_items == 0
        || budget.max_bytes == 0
        || filters.is_empty()
        || request.is_exhausted()
    {
        return outcome;
    }
    let Some(filters) = filters.iter().map(sdk_filter).collect::<Option<Vec<_>>>() else {
        return outcome;
    };
    let mut urls = endpoints
        .iter()
        .filter_map(|endpoint| RelayUrl::parse(endpoint.as_str()).ok())
        .collect::<Vec<_>>();
    urls.sort();
    urls.dedup();
    urls.truncate(PUBLIC_EVENT_QUERY_MAX_RELAYS);
    if urls.is_empty() {
        return outcome;
    }
    let phase = PublicEventTrafficMeter::child(
        request,
        PublicEventTrafficLimits {
            max_items: budget.max_items,
            max_bytes: budget.max_bytes,
            max_messages: usize::MAX,
        },
    );
    // Every socket of this phase; dropping the guard (phase end or caller
    // cancellation) forcibly closes them all and refuses new dials.
    let sockets = PublicEventSocketRegistry::new();
    let _close_sockets = CloseSocketsOnDrop(sockets.clone());
    // A request-owned anonymous client: discovered targets never join a shared
    // pool, and closing it stops reconnects for every relay this phase added.
    // No signer means an optional NIP-42 challenge cannot close the fetch.
    let client = NostrSdkClient::builder()
        .websocket_transport(PinnedPublicEventTransport::new(
            policy,
            phase.clone(),
            sockets.clone(),
            deadline,
        ))
        .build();
    let _ = timeout_at(
        deadline,
        acquire(&client, urls, filters, budget, deadline, &mut outcome),
    )
    .await;
    // The phase is over: drop every descriptor now, even though SDK cleanup
    // may still run its own longer close timeout.
    sockets.close_all();
    client.shutdown().await;
    // Actual raw traffic, not the SDK's verified and deduplicated result.
    outcome.received_items = phase.items();
    outcome.received_bytes = phase.bytes();
    outcome
}

async fn acquire(
    client: &NostrSdkClient,
    urls: Vec<RelayUrl>,
    filters: Vec<Filter>,
    budget: PublicEventQueryBudget,
    deadline: Instant,
    outcome: &mut PublicEventQueryOutcome,
) {
    let mut connects = JoinSet::new();
    for url in urls {
        if client.add_relay(url.clone()).await.is_err() {
            continue;
        }
        let client = client.clone();
        connects.spawn(async move {
            let connected = matches!(
                timeout(
                    DIRECTORY_RELAY_CONNECT_WAIT,
                    client.connect_relay(url.clone())
                )
                .await,
                Ok(Ok(()))
            );
            (url, connected)
        });
    }
    let mut connected = Vec::new();
    while let Some(result) = connects.join_next().await {
        if let Ok((url, true)) = result {
            connected.push(url);
        }
    }
    if connected.is_empty() {
        return;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return;
    }
    // The SDK's own acquisition bounds are a second, retained-event limit; the
    // pinned transport has already charged every raw frame.
    let per_relay_items = (budget.max_items / connected.len()).max(1);
    let per_relay_bytes = (budget.max_bytes / connected.len()).max(1);
    let relay_count = connected.len();
    let target = ReqTarget::manual(connected.into_iter().map(|url| (url, filters.clone())));
    let Ok(handle) = client
        .acquire_events(
            target,
            AcquisitionLimits::new(
                relay_count,
                per_relay_items,
                per_relay_bytes,
                remaining.mul_f32(0.9).max(Duration::from_millis(1)),
            ),
        )
        .await
    else {
        return;
    };
    let Ok(report) = handle.finish().await else {
        return;
    };
    let mut retained_bytes = 0usize;
    for relay in report.relays.values() {
        for event in &relay.events {
            let json = event.as_json();
            if outcome.events_json.contains(&json) {
                continue;
            }
            retained_bytes = retained_bytes.saturating_add(json.len());
            if outcome.events_json.len() >= budget.max_items || retained_bytes > budget.max_bytes {
                return;
            }
            outcome.events_json.push(json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::local_relay::MockRelay;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

    fn request_meter() -> Arc<PublicEventTrafficMeter> {
        PublicEventTrafficMeter::new(PublicEventTrafficLimits {
            max_items: 16,
            max_bytes: 4 * 1024 * 1024,
            max_messages: 64,
        })
    }

    async fn published_notes(count: usize) -> (MockRelay, TransportEndpoint, Vec<String>) {
        let relay = MockRelay::run().await.unwrap();
        let url = relay.url().await;
        let keys = Keys::generate();
        let publisher = NostrSdkClient::default();
        publisher.add_relay(url.clone()).await.unwrap();
        publisher.connect_relay(url.clone()).await.unwrap();
        let mut ids = Vec::new();
        for index in 0..count {
            let event = EventBuilder::new(Kind::TextNote, format!("note {index}"))
                .finalize(&keys)
                .unwrap();
            ids.push(event.id.to_hex());
            publisher.send_event(&event).await.unwrap();
        }
        publisher.shutdown().await;
        (relay, TransportEndpoint(url.to_string()), ids)
    }

    fn id_filters(ids: &[String]) -> Vec<PublicEventQueryFilter> {
        ids.iter()
            .map(|id| PublicEventQueryFilter::EventId {
                event_id_hex: id.clone(),
            })
            .collect()
    }

    #[tokio::test]
    async fn public_event_query_matches_exact_ids_and_charges_its_budget() {
        let (_relay, endpoint, ids) = published_notes(3).await;
        let policy = RelaySafetyPolicy::with_allow_loopback(true);
        let deadline = Instant::now() + Duration::from_secs(5);

        let request = request_meter();
        let exact = query_public_events_on(
            policy.clone(),
            vec![endpoint.clone()],
            id_filters(&ids[1..2]),
            PublicEventQueryBudget {
                max_items: 8,
                max_bytes: 1024 * 1024,
            },
            &request,
            deadline,
        )
        .await;
        assert_eq!(exact.events_json.len(), 1);
        assert!(exact.events_json[0].contains(&ids[1]));
        assert!(exact.received_items >= 1);
        assert!(exact.received_bytes >= exact.events_json[0].len());

        let request = request_meter();
        let bounded = query_public_events_on(
            policy,
            vec![endpoint],
            id_filters(&ids),
            PublicEventQueryBudget {
                max_items: 2,
                max_bytes: 1024 * 1024,
            },
            &request,
            deadline,
        )
        .await;
        assert!(bounded.events_json.len() <= 2);
        assert!(bounded.received_items <= 3);
        assert_eq!(request.items(), bounded.received_items);
    }

    #[tokio::test]
    async fn the_request_meter_is_shared_across_phases() {
        let (_relay, endpoint, ids) = published_notes(2).await;
        let policy = RelaySafetyPolicy::with_allow_loopback(true);
        let deadline = Instant::now() + Duration::from_secs(5);
        let phase = PublicEventQueryBudget {
            max_items: 8,
            max_bytes: 1024 * 1024,
        };
        let request = PublicEventTrafficMeter::new(PublicEventTrafficLimits {
            max_items: 1,
            max_bytes: 4 * 1024 * 1024,
            max_messages: 64,
        });
        let first = query_public_events_on(
            policy.clone(),
            vec![endpoint.clone()],
            id_filters(&ids[..1]),
            phase,
            &request,
            deadline,
        )
        .await;
        assert_eq!(first.events_json.len(), 1);
        let second = query_public_events_on(
            policy,
            vec![endpoint],
            id_filters(&ids[1..]),
            phase,
            &request,
            deadline,
        )
        .await;
        assert!(
            second.events_json.is_empty(),
            "the second phase cannot exceed the request-wide item budget"
        );
        assert!(request.is_exhausted());
        assert_eq!(
            request.items(),
            first.received_items + second.received_items
        );
    }

    #[tokio::test]
    async fn the_pinned_transport_refuses_loopback_without_the_dev_flag() {
        let (_relay, endpoint, ids) = published_notes(1).await;
        let request = request_meter();
        let outcome = query_public_events_on(
            RelaySafetyPolicy::default(),
            vec![endpoint],
            id_filters(&ids),
            PublicEventQueryBudget {
                max_items: 8,
                max_bytes: 1024 * 1024,
            },
            &request,
            Instant::now() + Duration::from_secs(5),
        )
        .await;
        assert_eq!(outcome, PublicEventQueryOutcome::default());
        assert_eq!(request.items() + request.bytes(), 0, "nothing was received");
    }

    #[tokio::test]
    async fn public_event_query_rejects_malformed_filters_without_dialing() {
        let request = request_meter();
        let outcome = query_public_events_on(
            RelaySafetyPolicy::default(),
            vec![TransportEndpoint("wss://relay.example".to_owned())],
            vec![PublicEventQueryFilter::EventId {
                event_id_hex: "not-hex".to_owned(),
            }],
            PublicEventQueryBudget {
                max_items: 1,
                max_bytes: 1,
            },
            &request,
            Instant::now() + Duration::from_secs(1),
        )
        .await;
        assert_eq!(outcome, PublicEventQueryOutcome::default());
    }

    #[test]
    fn replaceable_coordinates_omit_the_identifier_tag() {
        let author = Keys::generate().public_key().to_hex();
        let replaceable = sdk_filter(&PublicEventQueryFilter::Coordinate {
            kind: 10002,
            author_hex: author.clone(),
            identifier: String::new(),
        })
        .unwrap();
        let addressable = sdk_filter(&PublicEventQueryFilter::Coordinate {
            kind: 30023,
            author_hex: author,
            identifier: "entry".to_owned(),
        })
        .unwrap();
        let d = SingleLetterTag::from_char('d').unwrap();
        assert!(!replaceable.generic_tags.contains_key(&d));
        assert!(
            addressable
                .generic_tags
                .get(&d)
                .is_some_and(|values| values.contains("entry"))
        );
    }
}
