//! Catch-up must not advance a group's epoch past history it knows about but
//! has not downloaded yet (mdk#2086). The relay fixture serves every event
//! only through NIP-77 comparison and exact-ID fetches, and keeps one early
//! application message from those fetches until the member has acquired the
//! later commits.

use super::*;
use nostr_relay_builder::prelude::{
    Backend, BoxedFuture, DatabaseError, DatabaseEventStatus, Event, EventId, Events,
    Filter as RelayFilter, MemoryDatabase, MemoryDatabaseOptions, NostrDatabase, PolicyResult,
    QueryPolicy, SaveEventStatus, SingleLetterTag, Timestamp as RelayTimestamp,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{Client as NostrSdkClient, Filter, Kind, RelayCapabilities, ReqTarget};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Mutex;

#[derive(Clone, Debug)]
struct ComparisonOnlyRelay {
    inner: MemoryDatabase,
    /// Group route whose broad queries see nothing older than `cutoff`.
    route: Arc<Mutex<Option<String>>>,
    cutoff: Arc<Mutex<Option<RelayTimestamp>>>,
    /// Exact-ID queries answer without these events while they are listed.
    withheld: Arc<Mutex<HashSet<EventId>>>,
}

/// Refuses exact-ID queries for the listed events. A refusal is not an answer,
/// so recovery keeps retrying without spending its parking budget.
#[derive(Clone, Debug, Default)]
struct RefusedIds(Arc<Mutex<HashSet<EventId>>>);

impl QueryPolicy for RefusedIds {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let refused = self.0.lock().unwrap();
            if query
                .ids
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| refused.contains(id)))
            {
                PolicyResult::Reject("restricted: not yet".into())
            } else {
                PolicyResult::Accept
            }
        })
    }
}

/// How the relay keeps the early message from Bob.
#[derive(Clone, Copy)]
enum Unavailable {
    /// Requests for it are refused; recovery keeps retrying.
    Refused,
    /// Requests for it end without it; recovery eventually parks.
    Withheld,
}

impl NostrDatabase for ComparisonOnlyRelay {
    fn backend(&self) -> Backend {
        self.inner.backend()
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxedFuture<'a, Result<SaveEventStatus, DatabaseError>> {
        self.inner.save_event(event)
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<DatabaseEventStatus, DatabaseError>> {
        self.inner.check_id(event_id)
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxedFuture<'a, Result<Option<Event>, DatabaseError>> {
        self.inner.event_by_id(event_id)
    }

    fn count(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<usize, DatabaseError>> {
        self.inner.count(filter)
    }

    fn query(&self, mut filter: RelayFilter) -> BoxedFuture<'_, Result<Events, DatabaseError>> {
        Box::pin(async move {
            let route = self.route.lock().unwrap().clone();
            let cutoff = *self.cutoff.lock().unwrap();
            let broad_group_query = filter.ids.is_none()
                && route.as_ref().is_some_and(|route| {
                    filter
                        .generic_tags
                        .get(&SingleLetterTag::from_char('h').unwrap())
                        .is_some_and(|values| values.contains(route))
                });
            if broad_group_query && let Some(cutoff) = cutoff {
                filter.since = Some(filter.since.map_or(cutoff, |since| since.max(cutoff)));
            }
            if let Some(ids) = filter.ids.as_mut() {
                let withheld = self.withheld.lock().unwrap();
                ids.retain(|id| !withheld.contains(id));
                if ids.is_empty() {
                    return Ok(Events::new(&filter));
                }
            }
            self.inner.query(filter).await
        })
    }

    fn negentropy_items(
        &self,
        filter: RelayFilter,
    ) -> BoxedFuture<'_, Result<Vec<(EventId, RelayTimestamp)>, DatabaseError>> {
        // The inventory stays complete, so the comparison names the withheld
        // message as missing.
        self.inner.negentropy_items(filter)
    }

    fn delete(&self, filter: RelayFilter) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.delete(filter)
    }

    fn wipe(&self) -> BoxedFuture<'_, Result<(), DatabaseError>> {
        self.inner.wipe()
    }
}

async fn route_event_ids(
    inspector: &NostrSdkClient,
    url: &str,
    route: &[u8; 32],
) -> HashSet<nostr_sdk::prelude::EventId> {
    inspector
        .fetch_events(ReqTarget::single(
            url,
            [Filter::new().kind(Kind::MlsGroupMessage)],
        ))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap()
        .into_iter()
        .filter(|event| {
            let transport =
                transport_nostr_peeler::NostrTransportEvent::from_nostr_event(event).unwrap();
            matches!(
                transport.to_transport_message().unwrap().envelope,
                cgka_traits::transport::TransportEnvelope::GroupMessage { transport_group_id }
                    if transport_group_id.as_slice() == route
            )
        })
        .map(|event| event.id)
        .collect()
}

/// More commits than the retained-epoch window, so the early message's epoch
/// is gone once the member applies them all.
const LATER_COMMITS: usize = 7;
const EARLY_MESSAGE: &str = "before the commits";

/// Bob, offline, misses one message then `LATER_COMMITS` commits. He comes
/// back able to learn of them only through comparison, and the relay
/// withholds the early message from exact-ID fetches.
struct OfflineCatchUp {
    relay: LocalRelay,
    refused: RefusedIds,
    app: MarmotApp,
    runtime: crate::MarmotAppRuntime,
    bob: String,
    group: GroupId,
    target_epoch: u64,
    _dir: tempfile::TempDir,
}

impl OfflineCatchUp {
    async fn start(unavailable: Unavailable) -> Self {
        let database = ComparisonOnlyRelay {
            inner: MemoryDatabase::with_opts(MemoryDatabaseOptions {
                events: true,
                max_events: Some(256),
            }),
            route: Arc::new(Mutex::new(None)),
            cutoff: Arc::new(Mutex::new(None)),
            withheld: Arc::new(Mutex::new(HashSet::new())),
        };
        let refused = RefusedIds::default();
        let relay = LocalRelay::new(
            RelayBuilder::default()
                .query_policy(refused.clone())
                .database(database.clone()),
        );
        relay.run().await.unwrap();
        let url = relay.url().await.to_string();
        let dir = tempfile::tempdir().unwrap();
        let home = AccountHome::open(dir.path());
        let alice = home.create_account("alice").unwrap();
        let bob = home.create_account("bob").unwrap();
        let config = crate::MarmotAppConfig::default()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_settlement_quiescence_ms(100)
            .with_dev_epoch_backfill_retry_backoff_ms(100);
        let app = MarmotApp::with_relay_and_config(dir.path(), url.clone(), config);
        crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, &url);
        let runtime = crate::MarmotAppRuntime::new(app.clone());
        runtime.reconcile_accounts().await.unwrap();
        runtime.publish_key_package(&bob.label).await.unwrap();
        let group = runtime
            .create_group_with_options(
                &alice.label,
                "catch-up hold",
                std::slice::from_ref(&bob.account_id_hex),
                AppCreateGroupOptions {
                    relays: Some(vec![url.clone()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        timeout(Duration::from_secs(20), async {
            loop {
                runtime.catch_up_accounts().await.unwrap();
                if app
                    .group(&bob.label, &hex::encode(&group))
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Bob joins the group");
        let joined_epoch = runtime
            .group_mls_state(&alice.label, &group)
            .await
            .unwrap()
            .epoch;
        timeout(Duration::from_secs(15), async {
            while runtime
                .group_mls_state(&bob.label, &group)
                .await
                .unwrap()
                .epoch
                != joined_epoch
            {
                runtime.catch_up_accounts().await.unwrap();
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("Bob reaches Alice's epoch");
        let route: [u8; 32] = hex::decode(
            app.group(&alice.label, &hex::encode(&group))
                .unwrap()
                .unwrap()
                .nostr_routing
                .nostr_group_id_hex,
        )
        .unwrap()
        .try_into()
        .unwrap();
        let inspector = NostrSdkClient::builder().build();
        inspector
            .add_relay(url.clone())
            .capabilities(RelayCapabilities::READ)
            .await
            .unwrap();
        inspector.connect().await;

        runtime
            .accounts()
            .deactivate_account(&bob.label)
            .await
            .unwrap();
        let before = route_event_ids(&inspector, &url, &route).await;
        runtime
            .send_message(&alice.label, &group, EARLY_MESSAGE.as_bytes().to_vec())
            .await
            .unwrap();
        let early = route_event_ids(&inspector, &url, &route)
            .await
            .into_iter()
            .find(|id| !before.contains(id))
            .expect("the relay retains the early message");
        for index in 0..LATER_COMMITS {
            runtime
                .update_group_profile(&alice.label, &group, Some(format!("name {index}")), None)
                .await
                .unwrap();
        }
        let target_epoch = runtime
            .group_mls_state(&alice.label, &group)
            .await
            .unwrap()
            .epoch;
        assert_eq!(target_epoch, joined_epoch + LATER_COMMITS as u64);
        let commits = route_event_ids(&inspector, &url, &route)
            .await
            .into_iter()
            .filter(|id| !before.contains(id) && *id != early)
            .collect::<Vec<_>>();
        assert_eq!(commits.len(), LATER_COMMITS);

        *database.route.lock().unwrap() = Some(hex::encode(route));
        *database.cutoff.lock().unwrap() =
            Some(RelayTimestamp::from_secs(crate::unix_now_seconds() + 3_600));
        let early = EventId::from_byte_array(early.to_bytes());
        match unavailable {
            Unavailable::Refused => refused.0.lock().unwrap().insert(early),
            Unavailable::Withheld => database.withheld.lock().unwrap().insert(early),
        };
        runtime
            .accounts()
            .sign_in_account(&bob.label)
            .await
            .unwrap();
        runtime.reconcile_accounts().await.unwrap();

        let storage = app.account_storage(&bob.label).unwrap();
        let route_key = storage_sqlite::TransportReconciliationRoute::Group(route);
        timeout(Duration::from_secs(30), async {
            while !commits.iter().all(|commit| {
                storage
                    .retained_recovery_event(
                        &route_key,
                        &commit.to_bytes(),
                        None,
                        crate::unix_now_seconds(),
                    )
                    .unwrap()
            }) {
                runtime.catch_up_accounts().await.unwrap();
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("comparison acquires every later commit");
        Self {
            relay,
            refused,
            app,
            runtime,
            bob: bob.label,
            group,
            target_epoch,
            _dir: dir,
        }
    }

    async fn bob_epoch(&self) -> u64 {
        self.runtime
            .group_mls_state(&self.bob, &self.group)
            .await
            .unwrap()
            .epoch
    }

    fn bob_sees_early_message(&self) -> bool {
        self.app
            .messages(&self.bob)
            .unwrap()
            .iter()
            .any(|message| message.plaintext == EARLY_MESSAGE)
    }

    fn held(&self) -> bool {
        use cgka_traits::storage::HistoryAcquisitionHoldStorage;
        self.app
            .account_storage(&self.bob)
            .unwrap()
            .history_acquisition_held(&self.group)
            .unwrap()
    }

    async fn close(self) {
        self.runtime.shutdown_and_close().await.unwrap();
        self.relay.shutdown();
    }
}

#[tokio::test]
async fn catch_up_holds_epochs_until_known_history_is_downloaded() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = OfflineCatchUp::start(Unavailable::Refused).await;
    // Bob has every commit and the comparison still names the early message.
    // Give convergence many settlement windows: without a hold he applies
    // the commits here and drops the early message's epoch.
    let _ = timeout(Duration::from_secs(3), async {
        while fixture.bob_epoch().await < fixture.target_epoch {
            fixture.runtime.catch_up_accounts().await.unwrap();
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await;

    fixture.refused.0.lock().unwrap().clear();
    let caught_up = timeout(Duration::from_secs(30), async {
        loop {
            fixture.runtime.catch_up_accounts().await.unwrap();
            if fixture.bob_epoch().await >= fixture.target_epoch && fixture.bob_sees_early_message()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    let bob_epoch = fixture.bob_epoch().await;
    assert!(
        caught_up.is_ok(),
        "Bob reaches epoch {} (at {bob_epoch}) and decrypts the early message",
        fixture.target_epoch
    );
    assert!(!fixture.held(), "the hold ends once nothing is missing");
    fixture.close().await;
}

#[tokio::test]
async fn history_that_never_arrives_releases_the_hold_with_a_notice() {
    let _serial = BOUNDED_WORKER_FIXTURE_LOCK.lock().await;
    let fixture = OfflineCatchUp::start(Unavailable::Withheld).await;
    // Recovery gives up on the withheld message after its quiet passes. The
    // group then converges and the loss is surfaced instead of silent.
    let released = timeout(Duration::from_secs(30), async {
        loop {
            fixture.runtime.catch_up_accounts().await.unwrap();
            if fixture.bob_epoch().await >= fixture.target_epoch {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(released.is_ok(), "parking releases the hold");
    assert!(!fixture.held());
    assert!(!fixture.bob_sees_early_message());
    assert!(
        !fixture
            .runtime
            .history_notices(&fixture.bob)
            .await
            .unwrap()
            .is_empty(),
        "the undownloaded message is reported as possibly missing history"
    );
    fixture.close().await;
}
