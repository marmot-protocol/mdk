//! mdk#2332: a group relay's copy of this account's own pending commit
//! confirms it on every app receive path. The account already holds the
//! event, as it holds every event it published, so each path that skips held
//! events before ingest must still pass this one copy: the live receive, the
//! sync drain and native admission, including after a restart, whose seen set
//! is durable, and through the account worker. Every other copy of an own
//! event is skipped as before.

use super::*;
use crate::tests::{ScriptedPushRelayClient, client_on_app_relay_plane, epoch_gap_probe};
use cgka_traits::storage::OutboundFanoutStorage as _;
use cgka_traits::{
    FanoutAcknowledgement, FanoutMlsState, MessageId, OutboundFanout, SendAcceptDisposition,
    TransportEndpoint,
};
use marmot_account::AccountHome;
use std::sync::Arc;
use transport_nostr_adapter::{NostrRelayEvent, ReplayBatchTake};
use transport_nostr_peeler::NostrTransportEvent;

const ECHO_A: &str = "wss://echo-a.example";
const ECHO_B: &str = "wss://echo-b.example";

/// Alice renamed her group, and neither relay answered the publish: the
/// commit waits, frozen, for a relay to show it holds the event.
struct PendingCommit {
    _dir: tempfile::TempDir,
    app: crate::MarmotApp,
    client: AppClient,
    group: GroupId,
    /// The group's Nostr routing id, for a barrier event on its route.
    route: String,
    /// An app message Alice published, and holds, before the rename.
    earlier: NostrTransportEvent,
    commit: NostrTransportEvent,
}

async fn pending_commit() -> PendingCommit {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = crate::MarmotApp::with_relays(dir.path(), vec![ECHO_A.into(), ECHO_B.into()])
        .with_test_relay_client(relay.clone());
    let mut client = client_on_app_relay_plane(&app, "alice").await;
    let group = client
        .create_group("own echo", &[])
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    client.prepare_transport().await.unwrap();
    client.send(&group, b"before the rename").await.unwrap();
    let earlier = relay.attempted_events().last().unwrap().clone();

    relay.fail_publishes_as_possibly_exposed();
    let renamed = client
        .update_group_profile(&group, Some("renamed"), None)
        .await
        .unwrap();
    assert_eq!(
        renamed.accept_disposition,
        SendAcceptDisposition::CompletionUnknown
    );
    let fanouts = client.runtime.outbound_fanouts_for_group(&group).unwrap();
    let pending = fanouts
        .iter()
        .find(|fanout| matches!(fanout.mls_state(), FanoutMlsState::Pending(_)))
        .expect("the rename waits for a relay");
    let commit = NostrTransportEvent::from_transport_message(&pending.request().message).unwrap();
    assert_ne!(commit.id, earlier.id);
    // The premise: the account holds both events it published.
    let receipts = client.transport_receipts().unwrap();
    assert!(receipts.contains(&earlier.id));
    assert!(receipts.contains(&commit.id));
    drop(receipts);
    let route = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .unwrap()
        .nostr_routing
        .nostr_group_id_hex;
    PendingCommit {
        _dir: dir,
        app,
        client,
        group,
        route,
        earlier,
        commit,
    }
}

impl PendingCommit {
    /// The account as a process that restarts with the commit pending opens
    /// it: groups only seeded, as the account worker opens them, and the
    /// commit still held, since the seen set is durable.
    async fn reopened(self) -> Self {
        let Self {
            _dir,
            app,
            client,
            group,
            route,
            earlier,
            commit,
        } = self;
        drop(client);
        assert!(
            app.load_state("alice")
                .unwrap()
                .seen_events
                .contains(&commit.id)
        );
        let client = app
            .local_client_with_relay_plane_and_hydration(
                "alice",
                &app.relay_plane,
                None,
                true,
                None,
            )
            .await
            .unwrap();
        assert!(client.runtime.unhydrated_group_ids().contains(&group));
        Self {
            _dir,
            app,
            client,
            group,
            route,
            earlier,
            commit,
        }
    }

    /// The account's delivery of `event` from relay `endpoint`, built as
    /// its router receives one.
    async fn delivery(
        &self,
        endpoint: &str,
        event: &NostrTransportEvent,
    ) -> cgka_traits::TransportDelivery {
        let mut deliveries = self
            .client
            .adapter
            .recovered_deliveries(NostrRelayEvent {
                endpoint: TransportEndpoint(endpoint.into()),
                subscription_id: None,
                event: event.clone(),
            })
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1, "the account's group route takes it");
        deliveries.pop().unwrap()
    }

    fn assert_confirmed_by_echo(&self) {
        assert_confirmed_by_echo(
            &self
                .client
                .runtime
                .outbound_fanouts_for_group(&self.group)
                .unwrap(),
            &self.commit,
        );
    }
}

/// `event` as relay `endpoint` sends it on the account's group route.
async fn relay_copy(
    relay_plane: &crate::MarmotRelayPlane,
    endpoint: &str,
    event: &NostrTransportEvent,
) {
    let delivered = relay_plane
        .handle_relay_event_for_test(NostrRelayEvent {
            endpoint: TransportEndpoint(endpoint.into()),
            subscription_id: None,
            event: event.clone(),
        })
        .await
        .unwrap();
    assert_eq!(delivered, 1, "the account's group route takes the copy");
}

/// The commit is confirmed, and relay A holds it by its echo. Relay B, which
/// never answered, is still owed the event, so the fanout is kept.
fn assert_confirmed_by_echo(fanouts: &[OutboundFanout], commit: &NostrTransportEvent) {
    let (state, acknowledgement) = commit_state(fanouts, commit);
    assert_eq!(state, FanoutMlsState::Confirmed);
    assert_eq!(acknowledgement, Some(FanoutAcknowledgement::Echo));
}

fn commit_state(
    fanouts: &[OutboundFanout],
    commit: &NostrTransportEvent,
) -> (FanoutMlsState, Option<FanoutAcknowledgement>) {
    let id = MessageId::new(hex::decode(&commit.id).unwrap());
    let fanout = fanouts
        .iter()
        .find(|fanout| fanout.is_frozen_event(&id))
        .expect("the commit's fanout is kept while relay B is owed");
    let index = fanout
        .target_index_of(&TransportEndpoint(ECHO_A.into()))
        .unwrap();
    (fanout.mls_state(), fanout.target_acknowledgement(index))
}

/// After a restart, the live receive returns the commit's copy, skipping the
/// earlier own message's copy queued ahead of it, and ingesting it confirms
/// the commit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_receive_passes_an_own_echo_of_a_commit_left_pending_by_a_restart() {
    let mut fixture = pending_commit().await.reopened().await;
    // A barrier: a receive that skipped the commit's copy returns this.
    let barrier = epoch_gap_probe(&fixture.route, unix_now_seconds(), "own-echo-barrier");
    for event in [&fixture.earlier, &fixture.commit, &barrier] {
        let delivery = fixture.delivery(ECHO_A, event).await;
        fixture
            .app
            .relay_plane
            .route_account_delivery_for_test(delivery);
    }

    let transport_nostr::AccountDeliveryReceive::Delivery(delivery) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        fixture.client.receive_next_delivery(),
    )
    .await
    .expect("a copy is queued")
    .unwrap() else {
        panic!("no delivery was lost");
    };
    assert_eq!(
        hex::encode(delivery.message.id.as_slice()),
        fixture.commit.id,
        "the earlier own message is skipped, and the commit's copy is not"
    );
    // Neither copy hydrated the group: what hydration announces reaches the
    // host only through the ingest that follows.
    assert!(
        fixture
            .client
            .runtime
            .unhydrated_group_ids()
            .contains(&fixture.group)
    );
    fixture
        .client
        .ingest_received_delivery(*delivery)
        .await
        .unwrap();
    fixture.assert_confirmed_by_echo();
}

/// After a restart, a sync's drain takes the same queued copies through its
/// own skip, and the commit confirms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sync_passes_an_own_echo_of_a_commit_left_pending_by_a_restart() {
    let mut fixture = pending_commit().await.reopened().await;
    for event in [&fixture.earlier, &fixture.commit] {
        let delivery = fixture.delivery(ECHO_A, event).await;
        fixture
            .app
            .relay_plane
            .route_account_delivery_for_test(delivery);
    }
    fixture.client.sync().await.unwrap();
    fixture.assert_confirmed_by_echo();
}

/// Native admission takes a fetched copy of the commit from relay A and
/// confirms it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_admission_passes_a_pending_commits_own_echo() {
    let mut fixture = pending_commit().await;
    let fetched = fixture.delivery(ECHO_A, &fixture.commit).await;
    let client = &mut fixture.client;
    assert!(client.recovery_owner.native_batch.is_none());
    client.recovery_owner.native_ingress = None;
    let mut ingress = client
        .adapter
        .open_replay_ingress(vec![fetched])
        .await
        .unwrap();
    let batch = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let mut changes = client.adapter.replay_changes().await;
            match ingress.take_batch(Some(&fixture.group)).await {
                ReplayBatchTake::Ready(batch) => break batch,
                ReplayBatchTake::Pending => {
                    super::native_ingress::wait_native_change(&mut changes).await;
                }
                ReplayBatchTake::Empty => panic!("the fetched copy owns the group's range"),
            }
        }
    })
    .await
    .expect("the fetched copy reaches its group boundary");
    client.recovery_owner.native_ingress = Some(ingress);
    client.recovery_owner.native_batch = Some(batch);

    assert!(client.admit_native_turn(None).await.unwrap());
    fixture.assert_confirmed_by_echo();
}

/// A commit a previous process left pending confirms through the account
/// worker of the next: the seen set that holds the event is durable, and the
/// group the new session opens is hydrated before its copy is judged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_worker_passes_an_own_echo_of_a_commit_left_pending_by_a_restart() {
    let PendingCommit {
        _dir,
        app,
        client,
        group,
        commit,
        ..
    } = pending_commit().await;
    drop(client);
    assert!(
        app.load_state("alice")
            .unwrap()
            .seen_events
            .contains(&commit.id),
        "the restarted account still holds the commit"
    );

    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    relay_copy(runtime.shared_services().relay_plane(), ECHO_A, &commit).await;
    let storage = app.account_storage("alice").unwrap();
    let confirmed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let fanouts = storage.list_outbound_fanouts_for_group(&group).unwrap();
            if commit_state(&fanouts, &commit).0 == FanoutMlsState::Confirmed {
                break fanouts;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the worker confirms the commit by its echo");
    assert_confirmed_by_echo(&confirmed, &commit);
    runtime.shutdown().await;
}
