use super::*;
use cgka_traits::{MemberId, TransportEndpoint};
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase,
    PolicyResult, QueryPolicy,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use transport_nostr_adapter::{NostrAcquisitionLimits, NostrReconciliationItem, NostrRelayEvent};

const ROUTE: [u8; 32] = [0x61; 32];
const HISTORY_START: u64 = 1_700_000_000;
const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const GOAL: storage_sqlite::RecoveryDemandTicket = storage_sqlite::RecoveryDemandTicket {
    id: [0; 16],
    revision: 0,
};

#[derive(Clone, Default, Debug)]
struct HoldOlderPage {
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
    hold: bool,
    requests: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Notify>,
}

impl QueryPolicy for HoldOlderPage {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if self.hold
                && query
                    .until
                    .is_some_and(|until| until.as_secs() <= HISTORY_START + 1_000)
            {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                self.entered.store(true, Ordering::SeqCst);
                if !self.released.load(Ordering::SeqCst) {
                    released.await;
                }
            }
            PolicyResult::Accept
        })
    }
}

struct ReleaseGate(HoldOlderPage);

impl Drop for ReleaseGate {
    fn drop(&mut self) {
        self.0.released.store(true, Ordering::SeqCst);
        self.0.release.notify_waiters();
    }
}

struct WindowFixture {
    relay: LocalRelay,
    database: MemoryDatabase,
    plane: MarmotRelayPlane,
    account: MemberId,
    endpoint: TransportEndpoint,
    cache: EpochGapWindows,
    goal: storage_sqlite::RecoveryDemandTicket,
    ids: Vec<String>,
}

impl WindowFixture {
    async fn start(
        timestamps: impl IntoIterator<Item = u64>,
        body_bytes: usize,
        policy: Option<HoldOlderPage>,
    ) -> Self {
        let keys = Keys::parse(KEY).unwrap();
        let database = MemoryDatabase::with_opts(MemoryDatabaseOptions {
            events: true,
            max_events: Some(8_192),
        });
        let body = "x".repeat(body_bytes);
        let mut ids = Vec::new();
        for (index, timestamp) in timestamps.into_iter().enumerate() {
            let event = EventBuilder::new(Kind::MlsGroupMessage, format!("history-{index}:{body}"))
                .tags([Tag::custom("h", [hex::encode(ROUTE)])])
                .custom_created_at(Timestamp::from_secs(timestamp))
                .finalize(&keys)
                .unwrap();
            database
                .save_event(&serde_json::from_str(event.as_json().as_str()).unwrap())
                .await
                .unwrap();
            ids.push((timestamp, event.id.to_hex()));
        }
        ids.sort_unstable();
        let ids = ids.into_iter().map(|(_, id)| id).collect();
        let mut builder = RelayBuilder::default()
            .max_filter_limit(256)
            .database(database.clone());
        if let Some(policy) = policy {
            builder = builder.query_policy(policy);
        }
        let relay = LocalRelay::new(builder);
        relay.run().await.unwrap();
        let endpoint = TransportEndpoint(relay.url().await.to_string());
        let plane = MarmotRelayPlane::full_history_with_loopback(true);
        let account = MemberId::new(keys.public_key().to_bytes().to_vec());
        plane
            .set_transport_signer(&account, Arc::new(keys))
            .await
            .unwrap();
        Self {
            relay,
            database,
            plane,
            account,
            endpoint,
            cache: Default::default(),
            goal: GOAL,
            ids,
        }
    }

    async fn add_invalid(&self, created_at: u64, count: usize) {
        let keys = Keys::parse(KEY).unwrap();
        for index in 0..count {
            let event = EventBuilder::new(Kind::MlsGroupMessage, format!("invalid-{index}"))
                .tags([Tag::custom("h", [hex::encode(ROUTE)])])
                .custom_created_at(Timestamp::from_secs(created_at))
                .finalize(&keys)
                .unwrap();
            let mut event = serde_json::to_value(event).unwrap();
            event["sig"] = serde_json::Value::String("00".repeat(64));
            self.database
                .save_event(&serde_json::from_value(event).unwrap())
                .await
                .unwrap();
        }
    }

    fn request(&self, limits: NostrAcquisitionLimits) -> NostrAcquisitionRequest {
        NostrAcquisitionRequest {
            account_id: self.account.clone(),
            scope: NostrAcquisitionScope::GroupWindow {
                transport_group_id: ROUTE,
                since: HISTORY_START,
                until: HISTORY_START + 10_000,
                newest: Some(256),
            },
            endpoints: vec![self.endpoint.clone()],
            limits,
        }
    }

    async fn fetch(
        &self,
        local: &[NostrReconciliationItem],
        limits: NostrAcquisitionLimits,
    ) -> (Vec<NostrRelayEvent>, WindowProgress) {
        fetch_epoch_gap_window(
            &self.plane,
            self.request(limits),
            local,
            &self.cache,
            (0, 0, 0),
            self.goal,
            tokio::time::Instant::now() + limits.max_duration,
        )
        .await
    }

    fn acknowledge(
        &self,
        local: &mut Vec<NostrReconciliationItem>,
        events: &[NostrRelayEvent],
        mut progress: WindowProgress,
    ) {
        for event in events {
            let mut event_id = [0; 32];
            hex::decode_to_slice(&event.event.id, &mut event_id).unwrap();
            local.push(NostrReconciliationItem {
                event_id,
                created_at: event.event.created_at,
            });
        }
        for observation in &mut progress {
            observation.offered.clear();
        }
        keep_window_progress(
            &self.cache,
            &HashSet::from([(self.goal.id, self.goal.revision)]),
            progress,
        );
    }

    async fn recover(&self, limits: NostrAcquisitionLimits) -> Vec<String> {
        let mut local = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..64 {
            let (events, progress) = self.fetch(&local, limits).await;
            ids.extend(events.iter().map(|event| event.event.id.clone()));
            self.acknowledge(&mut local, &events, progress);
            if ids.len() == self.ids.len() {
                break;
            }
        }
        ids
    }

    async fn shutdown(self) {
        self.plane.shutdown().await;
        self.relay.shutdown();
    }
}

fn production_limits() -> NostrAcquisitionLimits {
    NostrAcquisitionLimits {
        max_endpoints: 1,
        max_requested_event_ids: 1,
        max_received_items_per_endpoint: EPOCH_GAP_WINDOW_MAX_EVENTS_PER_RELAY,
        max_serialized_event_bytes_per_endpoint: EPOCH_GAP_WINDOW_MAX_BYTES_PER_RELAY,
        max_duration: EPOCH_GAP_WINDOW_MAX_DURATION,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_beyond_newest_page() {
    let fixture =
        WindowFixture::start((0..700).map(|index| HISTORY_START + index / 2), 0, None).await;
    assert_eq!(
        fixture.recover(production_limits()).await,
        fixture.ids,
        "tied page boundaries return every event once, oldest first across passes"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumes_item_budget_cut() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let limits = NostrAcquisitionLimits {
        max_received_items_per_endpoint: 512,
        ..production_limits()
    };
    let (events, progress) = fixture.fetch(&[], limits).await;
    assert!(events.is_empty(), "a cut must not release the newer suffix");
    fixture.acknowledge(&mut Vec::new(), &events, progress);
    assert_eq!(
        fixture.recover(limits).await,
        fixture.ids,
        "later passes resume below the cut instead of refetching the same newest page"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_over_four_mebibytes() {
    let fixture =
        WindowFixture::start((0..4_096).map(|index| HISTORY_START + index), 1_100, None).await;
    let (events, progress) = fixture.fetch(&[], production_limits()).await;
    assert!(
        events.is_empty(),
        "the retained window exceeds the production whole-pass byte budget"
    );
    fixture.acknowledge(&mut Vec::new(), &events, progress);
    assert_eq!(
        fixture.recover(production_limits()).await,
        fixture.ids,
        "a large retained window must not permanently hide even a near-newest missing commit"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn floor_advance_keeps_frontier() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let limits = NostrAcquisitionLimits {
        max_received_items_per_endpoint: 512,
        ..production_limits()
    };
    let (events, progress) = fixture.fetch(&[], limits).await;
    assert!(events.is_empty());
    fixture.acknowledge(&mut Vec::new(), &events, progress);
    let mut request = fixture.request(limits);
    request.scope = NostrAcquisitionScope::GroupWindow {
        transport_group_id: ROUTE,
        since: HISTORY_START + 1,
        until: HISTORY_START + 10_000,
        newest: Some(256),
    };
    let (events, _) = fetch_epoch_gap_window(
        &fixture.plane,
        request,
        &[],
        &fixture.cache,
        (0, 0, 0),
        GOAL,
        tokio::time::Instant::now() + limits.max_duration,
    )
    .await;
    assert_eq!(
        events.first().map(|event| &event.event.id),
        fixture.ids.get(1),
        "normal same-route floor advance must resume below the cut, not spend another pass at the newest page"
    );
    assert!(events.windows(2).all(|pair| {
        (pair[0].event.created_at, &pair[0].event.id)
            < (pair[1].event.created_at, &pair[1].event.id)
    }));
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_tie_keeps_gap() {
    let fixture = WindowFixture::start(
        [HISTORY_START]
            .into_iter()
            .chain(std::iter::repeat_n(HISTORY_START + 1, 255)),
        0,
        None,
    )
    .await;
    fixture.add_invalid(HISTORY_START + 1, 1).await;
    let (older, progress) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        older
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        vec![&fixture.ids[0]],
        "a saturated second must not hide the strictly older input"
    );
    let mut local = Vec::new();
    fixture.acknowledge(&mut local, &older, progress);
    assert!(
        fixture
            .fetch(&local, production_limits())
            .await
            .0
            .is_empty(),
        "255 validated events do not make a full raw boundary second complete"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_page_reaches_older() {
    let fixture = WindowFixture::start([HISTORY_START], 0, None).await;
    fixture.add_invalid(HISTORY_START + 1, 256).await;
    let (events, _) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        events
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        fixture.ids.iter().collect::<Vec<_>>(),
        "a page filtered to zero events must still reach the older retained input"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_page_is_fetched_again() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let (first, _) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        first.first().map(|event| &event.event.id),
        fixture.ids.first()
    );
    let (retried, _) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        retried
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        first
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        "network completion alone must not advance past an unadmitted owned page"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_cut_keeps_other_page() {
    let healthy = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let duplicate =
        WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let gate = HoldOlderPage {
        hold: true,
        ..Default::default()
    };
    let stalled = WindowFixture::start(
        (0..700).map(|index| HISTORY_START + index),
        0,
        Some(gate.clone()),
    )
    .await;
    let _release = ReleaseGate(gate.clone());
    let mut request = healthy.request(NostrAcquisitionLimits {
        max_endpoints: 3,
        max_duration: Duration::from_secs(1),
        ..production_limits()
    });
    request
        .endpoints
        .extend([duplicate.endpoint.clone(), stalled.endpoint.clone()]);
    let (events, progress) = tokio::time::timeout(
        Duration::from_secs(5),
        fetch_epoch_gap_window(
            &healthy.plane,
            request,
            &[],
            &healthy.cache,
            (0, 0, 0),
            GOAL,
            tokio::time::Instant::now() + Duration::from_secs(1),
        ),
    )
    .await
    .expect("the stalled older page must respect the shared deadline");
    assert!(
        gate.entered.load(Ordering::SeqCst),
        "the cut must occur after a full newest page"
    );
    assert_eq!(
        events.first().map(|event| &event.event.id),
        healthy.ids.first()
    );
    assert!(
        events
            .iter()
            .all(|event| event.endpoint != stalled.endpoint),
        "the cut relay must not contribute a newer suffix"
    );
    assert_eq!(
        events
            .iter()
            .map(|event| &event.event.id)
            .collect::<HashSet<_>>()
            .len(),
        events.len(),
        "completed relays must not duplicate one another's deliveries"
    );
    healthy.acknowledge(&mut Vec::new(), &events, progress);
    gate.released.store(true, Ordering::SeqCst);
    gate.release.notify_waiters();
    let (retried, _) = stalled.fetch(&[], production_limits()).await;
    assert_eq!(
        retried.first().map(|event| &event.event.id),
        stalled.ids.first(),
        "requests that arrive after release must reach the oldest input"
    );
    healthy.shutdown().await;
    duplicate.shutdown().await;
    stalled.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inventory_change_reopens_span() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let mut local = fixture
        .ids
        .iter()
        .enumerate()
        .map(|(index, id)| NostrReconciliationItem {
            event_id: hex::decode(id).unwrap().try_into().unwrap(),
            created_at: HISTORY_START + index as u64,
        })
        .collect::<Vec<_>>();
    let mut cut = production_limits();
    cut.max_received_items_per_endpoint = 500;
    let (events, progress) = fixture.fetch(&local, cut).await;
    assert!(events.is_empty());
    assert!(
        progress[0].hint.bounds.last().unwrap().until < local.last().unwrap().created_at,
        "the held newest span was skipped before the cut"
    );
    fixture.acknowledge(&mut local, &events, progress);

    let released = local.pop().unwrap();
    let limits = production_limits();
    let (events, _) = fetch_epoch_gap_window(
        &fixture.plane,
        fixture.request(limits),
        &local,
        &fixture.cache,
        (0, 0, 1),
        fixture.goal,
        tokio::time::Instant::now() + limits.max_duration,
    )
    .await;
    let released_id = hex::encode(released.event_id);
    assert_eq!(
        events
            .iter()
            .map(|event| event.event.id.as_str())
            .collect::<Vec<_>>(),
        vec![released_id.as_str()]
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boundary_stack_is_bounded() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    fixture.cache.lock().unwrap().entries.insert(
        (ROUTE, fixture.endpoint.as_str().to_owned()),
        EpochGapWindow {
            generation: (0, 0, 0),
            goal: GOAL,
            origin_since: HISTORY_START,
            until: HISTORY_START + 10_000,
            since: HISTORY_START,
            bounds: (700..700 + EPOCH_GAP_WINDOW_MAX_BOUNDARIES as u64)
                .rev()
                .map(|second| EpochGapBound::new(HISTORY_START + second))
                .collect(),
            last_used: 0,
        },
    );
    let (events, progress) = fixture.fetch(&[], production_limits()).await;
    assert!(
        events.is_empty(),
        "a full hint cannot release unsearched newer history"
    );
    assert_eq!(
        progress[0].hint.bounds.len(),
        EPOCH_GAP_WINDOW_MAX_BOUNDARIES,
        "another full page must not grow long-lived range metadata past its cap"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filtered_page_keeps_oldest() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    fixture.add_invalid(HISTORY_START + 701, 1).await;
    let page = fixture
        .plane
        .acquire_history(
            fixture.request(NostrAcquisitionLimits {
                max_received_items_per_endpoint: 257,
                ..production_limits()
            }),
            NostrAcquisitionCancellation::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        page.endpoints[0].stats.received_items, 255,
        "the SDK filters one raw event out of a full 256-event relay page"
    );
    assert_eq!(page.endpoints[0].stats.raw_received_items, 256);
    assert_eq!(
        fixture.recover(production_limits()).await,
        fixture.ids,
        "SDK filtering must not turn a full relay page into the end of history"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn short_page_is_not_refetched() {
    let witness = HoldOlderPage::default();
    let fixture = WindowFixture::start(
        (20..40).map(|index| HISTORY_START + index),
        0,
        Some(witness.clone()),
    )
    .await;
    let (events, _) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        events
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        fixture.ids.iter().collect::<Vec<_>>()
    );
    assert_eq!(
        witness.requests.load(Ordering::SeqCst),
        2,
        "one short page plus its empty older probe, not a second page download"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_prefix_resumes() {
    let fixture =
        WindowFixture::start((0..4_096).map(|index| HISTORY_START + index), 1_100, None).await;
    let mut local = fixture
        .ids
        .iter()
        .enumerate()
        .skip(1)
        .map(|(index, id)| NostrReconciliationItem {
            event_id: hex::decode(id).unwrap().try_into().unwrap(),
            created_at: HISTORY_START + index as u64,
        })
        .collect::<Vec<_>>();
    let (events, progress) = fixture.fetch(&local, production_limits()).await;
    assert!(
        events.is_empty(),
        "the held prefix exceeds one pass's byte budget"
    );
    fixture.acknowledge(&mut local, &events, progress);
    let (events, _) = fixture.fetch(&local, production_limits()).await;
    assert_eq!(
        events
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        vec![&fixture.ids[0]],
        "held spans resume without redownloading their newer suffix"
    );
    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_page_is_refetched() {
    let fixture = WindowFixture::start((0..700).map(|index| HISTORY_START + index), 0, None).await;
    let (events, progress) = fixture.fetch(&[], production_limits()).await;
    assert!(!events.is_empty());
    // The peer offered a page, but none of its candidates was retained.
    keep_window_progress(
        &fixture.cache,
        &HashSet::from([(GOAL.id, GOAL.revision)]),
        progress,
    );
    assert!(fixture.cache.lock().unwrap().entries.is_empty());
    let (retried, _) = fixture.fetch(&[], production_limits()).await;
    assert_eq!(
        retried
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>(),
        events
            .iter()
            .map(|event| &event.event.id)
            .collect::<Vec<_>>()
    );
    fixture.shutdown().await;
}

#[test]
fn hint_lru_stays_bounded() {
    let cache = EpochGapWindows::default();
    let progress = (0..=EPOCH_GAP_WINDOW_MAX_HINTS)
        .map(|index| WindowObservation {
            key: (ROUTE, format!("wss://peer-{index}.example")),
            hint: EpochGapWindow {
                generation: (0, 0, 0),
                goal: GOAL,
                origin_since: HISTORY_START,
                since: HISTORY_START,
                until: HISTORY_START + 10_000,
                bounds: vec![EpochGapBound::new(HISTORY_START + index as u64)],
                last_used: 0,
            },
            reached: true,
            offered: HashMap::new(),
        })
        .collect();
    keep_window_progress(&cache, &HashSet::from([(GOAL.id, GOAL.revision)]), progress);
    let cache = cache.lock().unwrap();
    assert_eq!(cache.entries.len(), EPOCH_GAP_WINDOW_MAX_HINTS);
    assert!(
        !cache
            .entries
            .contains_key(&(ROUTE, "wss://peer-0.example".into()))
    );
    assert_eq!(
        std::mem::size_of::<EpochGapBound>() * EPOCH_GAP_WINDOW_MAX_BOUNDARIES,
        32 * 1024
    );
}
