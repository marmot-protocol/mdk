//! The account worker's holds that step 3 of the runtime-concurrency pass
//! moves off it (step 3 PR 0). Each test pins one hold as it is today: while
//! one step waits on a relay or a server, the worker takes no other work, or
//! keeps what it takes for later. The PR that moves the step flips its test.
//! The hold of a full set of media transfer permits is pinned by
//! `full_media_capacity_queues` beside the worker. Two holds have no test. A
//! manual reconnect's only hold is its own 5 s wait when no connection
//! attempt starts, which no fixture reaches without a test-only seam. An own
//! echo of a pending commit never reaches ingest on the worker: each publish
//! pass marks its event seen, so the worker skips the echo, and the echo's
//! drive of the group's fanouts (#3430) does not run there today. Two more
//! hold the worker in a command that enters no unit and get no test of
//! their own: a host-requested sign-in check reads the slots whose read the
//! maintenance tick's test holds, and an image update awaits a group image
//! upload, which the plan's hold list leaves out.
//!
//! Each hold is read from the worker's own series, never from a wall-clock
//! wait. A held step's span stays in flight. A command queued behind it stays
//! in flight in `mutation_queue_behind_<unit>`, or in its own host span when
//! no long unit is running. A delivery doesn't start `worker_unit_delivery`.
//!
//! Most of these holds take no command at all while held: the worker is
//! inside one command's future, and nothing in it acknowledges progress. So
//! these tests read each hold at the point where the step is held and the
//! other work is queued and unanswered. A test's flip asserts the positive,
//! the other work answered while the step is still held, which needs no such
//! boundary. A Welcome fanout's unit answers hydration requests while held,
//! so its test also fences on one.
//! Every held set includes an account-key command: a KeyPackage publish,
//! keyed on the account rather than a group, a peer or a new group. After a
//! test's PR flips it, that command still waits for the held step (rule 6).
//! The media permit hold parks only the media command, so its test holds no
//! other command.

use marmot_observability::{PerformanceRecorder, RuntimePerformanceSnapshot};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::*;

const SETTLE: Duration = Duration::from_secs(10);

fn sample(telemetry: &PerformanceRecorder, operation: RuntimeOp) -> RuntimePerformanceSnapshot {
    telemetry
        .snapshot()
        .runtime_operations
        .into_iter()
        .find(|sample| sample.operation == operation)
        .unwrap()
}

/// Wait until `ready` holds, checked again at each yield. If it doesn't
/// hold within the settle bound, the test fails with `what`.
async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    timeout(SETTLE, async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

/// A host call on its own task, whose answer the test awaits later.
type HostCall = JoinHandle<Result<(), AppError>>;

fn send(runtime: &crate::MarmotAppRuntime, group: &GroupId) -> HostCall {
    let (runtime, group) = (runtime.clone(), group.clone());
    tokio::spawn(async move {
        runtime
            .send_message("alice", &group, b"held behind".to_vec())
            .await
            .map(drop)
    })
}

fn rename(runtime: &crate::MarmotAppRuntime, group: &GroupId) -> HostCall {
    let (runtime, group) = (runtime.clone(), group.clone());
    tokio::spawn(async move {
        runtime
            .update_group_profile("alice", &group, Some("renamed".into()), None)
            .await
            .map(drop)
    })
}

/// The account-key command each held set includes.
fn publish_key_package(runtime: &crate::MarmotAppRuntime) -> HostCall {
    let runtime = runtime.clone();
    tokio::spawn(async move { runtime.publish_key_package("alice").await.map(drop) })
}

/// A read the worker answers in its main loop.
fn started_fresh(runtime: &crate::MarmotAppRuntime) -> HostCall {
    let runtime = runtime.clone();
    tokio::spawn(async move { runtime.started_fresh("alice").await.map(drop) })
}

fn none_answered(calls: &[HostCall], hold: &str) {
    let answered = calls.iter().filter(|call| call.is_finished()).count();
    assert_eq!(answered, 0, "{answered} commands answered through {hold}");
}

async fn all_answered(calls: Vec<HostCall>) {
    for call in calls {
        timeout(SETTLE, call)
            .await
            .expect("a held command is answered once its hold ends")
            .unwrap()
            .unwrap();
    }
}

/// Every mutation queued behind a unit counts once in its series, and none
/// is still waiting there or was dropped.
fn mutations_taken_up(
    telemetry: &PerformanceRecorder,
    series: RuntimeOp,
    before: &RuntimePerformanceSnapshot,
    queued: u64,
) {
    let after = sample(telemetry, series);
    assert_eq!(after.successes - before.successes, queued, "{series:?}");
    assert_eq!(after.cancelled, before.cancelled, "{series:?}");
    assert_eq!(after.in_flight, before.in_flight, "{series:?}");
}

/// A group event for `group` from another key, tagged as the group's live
/// traffic is: the worker has no receipt for it, so it admits it as a
/// delivery. Its content needn't decrypt.
fn foreign_group_event(
    app: &MarmotApp,
    group: &GroupId,
) -> transport_nostr_peeler::NostrTransportEvent {
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag};
    let routing = app
        .group("alice", &hex::encode(group.as_slice()))
        .unwrap()
        .expect("local group projection")
        .nostr_routing;
    let event = EventBuilder::new(Kind::MlsGroupMessage, "held delivery")
        .tag(Tag::custom("h", [routing.nostr_group_id_hex]))
        .finalize(&Keys::generate())
        .unwrap();
    transport_nostr_peeler::NostrTransportEvent::from_nostr_event(&event).unwrap()
}

/// Route `event` to the account's worker as a live delivery for `group`.
fn deliver(
    app: &MarmotApp,
    account: &marmot_account::AccountSummary,
    group: &GroupId,
    event: &transport_nostr_peeler::NostrTransportEvent,
) {
    app.relay_plane
        .route_account_delivery_for_test(cgka_traits::TransportDelivery {
            account_id: cgka_traits::MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
            group_id_hint: Some(group.clone()),
            message: event.to_transport_message().unwrap(),
            received_at: cgka_traits::Timestamp(crate::unix_now_seconds()),
            source: cgka_traits::TransportDeliverySource {
                transport: cgka_traits::transport::TransportSource("nostr".into()),
                plane: cgka_traits::TransportDeliveryPlane::Group,
                endpoint: None,
                subscription_id: None,
                wire: None,
            },
        });
}

/// Alice's runtime over a scripted relay, with these groups created first,
/// memberless, and her worker past startup.
struct Alice<const N: usize> {
    app: MarmotApp,
    account: marmot_account::AccountSummary,
    relay: Arc<ScriptedPushRelayClient>,
    runtime: crate::MarmotAppRuntime,
    groups: [GroupId; N],
}

async fn alice_with_groups<const N: usize>(dir: &tempfile::TempDir, names: [&str; N]) -> Alice<N> {
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut groups = Vec::new();
    {
        let mut client = app.client("alice").await.unwrap();
        for name in names {
            let created = client.create_group(name, &[]).await.unwrap();
            groups.push(created.operation.expect("eligible fixture members"));
        }
    }
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    let groups = <[GroupId; N]>::try_from(groups).unwrap();
    Alice {
        app,
        account,
        relay,
        runtime,
        groups,
    }
}

/// Hold 1, flipped by step 3 PR 4: a send waiting on its relays keeps the
/// worker inside the send. A send to another group, a change to that
/// group, a KeyPackage publish and a delivery all wait until the relays
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_send_holds_another_groups_work_and_a_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let Alice {
        app,
        account,
        relay,
        runtime,
        groups: [x, y],
    } = alice_with_groups(&dir, ["x", "y"]).await;
    let telemetry = runtime.shared_services().observer.performance().clone();
    let delivered = foreign_group_event(&app, &y);

    relay.block_next_publish();
    let held = send(&runtime, &x);
    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the send to X reaches its relays");
    assert_eq!(sample(&telemetry, RuntimeOp::WorkerUnitSend).in_flight, 1);
    let receives = sample(&telemetry, RuntimeOp::WorkerUnitDelivery);
    deliver(&app, &account, &y, &delivered);
    let before = sample(&telemetry, RuntimeOp::MutationQueueBehindSend);
    let waiting = vec![
        send(&runtime, &y),
        rename(&runtime, &y),
        publish_key_package(&runtime),
    ];
    until("each command queues behind the held send", || {
        sample(&telemetry, RuntimeOp::MutationQueueBehindSend).in_flight == before.in_flight + 3
    })
    .await;
    none_answered(&waiting, "a held send");
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitDelivery).started,
        receives.started,
        "the worker took a delivery inside a held send"
    );

    relay.release_publish();
    all_answered(vec![held]).await;
    all_answered(waiting).await;
    mutations_taken_up(&telemetry, RuntimeOp::MutationQueueBehindSend, &before, 3);
    until("the worker takes the delivery once the send ends", || {
        sample(&telemetry, RuntimeOp::WorkerUnitDelivery).started > receives.started
    })
    .await;
    runtime.shutdown_and_close().await.unwrap();
}

/// Hold 2, flipped by step 3 PR 1: a create whose member KeyPackage lookup
/// waits on the directory relays keeps the worker inside the create. Every
/// command waits: a send, a KeyPackage publish and a read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_key_package_resolution_holds_every_command() {
    let (_dir, app, members, fetcher) = crate::tests::member_resolution_fixture(1, false).await;
    app.account_home().create_account("alice").unwrap();
    let group = {
        let mut client = app.client("alice").await.unwrap();
        client
            .create_group("other", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members")
    };
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();
    runtime.reconcile_accounts().await.unwrap();
    for account in ["alice", members[0].label.as_str()] {
        crate::worker_fences::worker_startup_finished(&runtime, account)
            .await
            .unwrap();
    }

    let (entered, release) = fetcher.hold_fetches();
    let creating = tokio::spawn({
        let runtime = runtime.clone();
        let member = members[0].account_id_hex.clone();
        async move {
            runtime
                .create_group("alice", "held", &[member], None)
                .await
                .map(drop)
        }
    });
    timeout(SETTLE, entered.notified())
        .await
        .expect("the create reaches the directory relays");
    assert_eq!(
        sample(&telemetry, RuntimeOp::KeyPackageResolution).in_flight,
        1
    );
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitInviteOrCreate).in_flight,
        1
    );
    let mutations = sample(&telemetry, RuntimeOp::MutationQueueBehindInviteOrCreate);
    let reads = sample(&telemetry, RuntimeOp::ReadQueueBehindInviteOrCreate);
    let waiting = vec![
        send(&runtime, &group),
        publish_key_package(&runtime),
        started_fresh(&runtime),
    ];
    until("each command queues behind the held lookup", || {
        sample(&telemetry, RuntimeOp::MutationQueueBehindInviteOrCreate).in_flight
            == mutations.in_flight + 2
            && sample(&telemetry, RuntimeOp::ReadQueueBehindInviteOrCreate).in_flight
                == reads.in_flight + 1
    })
    .await;
    none_answered(&waiting, "a held KeyPackage lookup");

    release.notify_one();
    all_answered(vec![creating]).await;
    all_answered(waiting).await;
    mutations_taken_up(
        &telemetry,
        RuntimeOp::MutationQueueBehindInviteOrCreate,
        &mutations,
        2,
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A relay's HTTP side that accepts each request for its NIP-11 document
/// and answers only once released.
struct HeldDocument {
    relay: String,
    release: watch::Sender<bool>,
}

impl HeldDocument {
    async fn start() -> Self {
        const DOCUMENT: &str = r#"{"limitation":{"max_message_length":2097152}}"#;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = format!("ws://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (release, released) = watch::channel(false);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut released = released.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0; 1024];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => head.extend_from_slice(&buf[..read]),
                        }
                    }
                    if released.wait_for(|released| *released).await.is_err() {
                        return;
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/nostr+json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{DOCUMENT}",
                        DOCUMENT.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { relay, release }
    }

    fn release(&self) {
        self.release.send_replace(true);
    }
}

/// Hold 3, flipped by step 3 PR 1: an invite whose Welcome is over 64 KiB
/// reads the invitee's inbox relay's NIP-11 document for its limit, and while
/// that read waits, the worker stays inside the invite. Every command waits:
/// a send, a KeyPackage publish and a read. The group's profile, routing and
/// app state fill its context, which every Welcome carries, so the Welcome
/// is large while each commit stays under 64 KiB.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_relay_document_in_an_invites_size_check_holds_every_command() {
    let document = HeldDocument::start().await;
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    // The members run no worker, so no list of their own replaces the inbox
    // Alice knows for each.
    let members_dir = tempfile::tempdir().unwrap();
    let members_app = MarmotApp::with_relay(members_dir.path(), "wss://relay.example")
        .with_test_relay_client(relay.clone());
    let mut members = Vec::new();
    for label in ["bob", "carol", "dave", "erin"] {
        let member = AccountHome::open(members_dir.path())
            .create_account(label)
            .unwrap();
        members_app
            .client(label)
            .await
            .unwrap()
            .publish_key_package()
            .await
            .unwrap();
        members.push(member.account_id_hex);
    }
    // Sixteen group relays of the longest URL the routing component takes.
    let group_relays = (0..cgka_traits::app_components::NOSTR_ROUTING_MAX_RELAYS)
        .map(|index| {
            let host = format!("wss://relay{index:02}.example/");
            let length = cgka_traits::app_components::NOSTR_RELAY_URL_MAX_LEN - host.len();
            format!("{host}{}", "a".repeat(length))
        })
        .collect();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        group_relays,
        crate::MarmotAppConfig::white_noise().with_allow_loopback_relay_endpoints(true),
    )
    .with_test_relay_client(relay.clone());
    let (invitee, founders) = members.split_last().unwrap();
    for member in founders {
        crate::tests::remember_test_member_inbox(&app, member, "wss://relay.example");
    }
    crate::tests::remember_test_member_inbox(&app, invitee, &document.relay);
    let [large, other] = {
        let mut client = app.client("alice").await.unwrap();
        let founders: Vec<&str> = founders.iter().map(String::as_str).collect();
        let mut groups = Vec::new();
        for (name, members) in [("large", &founders[..]), ("other", &[][..])] {
            let created = client.create_group(name, members).await.unwrap();
            groups.push(created.operation.expect("eligible fixture members"));
        }
        <[GroupId; 2]>::try_from(groups).unwrap()
    };
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();
    runtime.reconcile_accounts().await.unwrap();
    crate::worker_fences::worker_startup_finished(&runtime, "alice")
        .await
        .unwrap();
    let description = "d".repeat(cgka_traits::app_components::GROUP_PROFILE_DESCRIPTION_MAX_LEN);
    runtime
        .update_group_profile("alice", &large, None, Some(description))
        .await
        .unwrap();
    // Two entries fill the 8192 encoded bytes of app-owned state, each
    // with its two-byte id and two-byte length prefix.
    for offset in 0..2 {
        let component = cgka_traits::app_components::APP_OWNED_APP_COMPONENT_ID_START + offset;
        runtime
            .update_app_component("alice", &large, component, vec![0x5a; 4092])
            .await
            .unwrap();
    }
    let largest_commit = relay
        .attempted_events()
        .iter()
        .filter(|event| event.kind == transport_nostr_peeler::KIND_MARMOT_GROUP_MESSAGE)
        .map(|event| serde_json::to_vec(event).unwrap().len())
        .max()
        .unwrap();
    assert!(
        largest_commit <= 64 * 1024,
        "a {largest_commit}-byte commit would read its group relays' documents"
    );
    assert_eq!(sample(&telemetry, RuntimeOp::RelayLimitLookup).started, 0);

    let inviting = tokio::spawn({
        let runtime = runtime.clone();
        let (large, invitee) = (large.clone(), invitee.clone());
        async move {
            runtime
                .invite_members("alice", &large, &[invitee])
                .await
                .map(drop)
        }
    });
    until(
        "the invite's size check reads the inbox relay's document",
        || sample(&telemetry, RuntimeOp::RelayLimitLookup).in_flight == 1,
    )
    .await;
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitInviteOrCreate).in_flight,
        1
    );
    let mutations = sample(&telemetry, RuntimeOp::MutationQueueBehindInviteOrCreate);
    let reads = sample(&telemetry, RuntimeOp::ReadQueueBehindInviteOrCreate);
    let waiting = vec![
        send(&runtime, &other),
        publish_key_package(&runtime),
        started_fresh(&runtime),
    ];
    until("each command queues behind the held document", || {
        sample(&telemetry, RuntimeOp::MutationQueueBehindInviteOrCreate).in_flight
            == mutations.in_flight + 2
            && sample(&telemetry, RuntimeOp::ReadQueueBehindInviteOrCreate).in_flight
                == reads.in_flight + 1
    })
    .await;
    none_answered(&waiting, "a held relay document");

    document.release();
    all_answered(vec![inviting]).await;
    all_answered(waiting).await;
    mutations_taken_up(
        &telemetry,
        RuntimeOp::MutationQueueBehindInviteOrCreate,
        &mutations,
        2,
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// Hold 4, flipped by step 3 PR 6: a create's founding Welcome fanout runs
/// on the worker after the create answers, and while its gift wrap waits on
/// the relays, the worker keeps every command it takes for after the
/// fanout. A send to another group and a KeyPackage publish wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_welcome_fanout_holds_a_send_to_another_group() {
    let dir = tempfile::tempdir().unwrap();
    let bob = AccountHome::open(dir.path()).create_account("bob").unwrap();
    let Alice {
        app,
        relay,
        runtime,
        groups: [other],
        ..
    } = alice_with_groups(&dir, ["other"]).await;
    let telemetry = runtime.shared_services().observer.performance().clone();
    crate::tests::remember_test_member_inbox(&app, &bob.account_id_hex, "wss://relay.example");
    runtime.publish_key_package("bob").await.unwrap();

    relay.block_next_publish_of_kind(transport_nostr_peeler::KIND_NIP59_GIFT_WRAP);
    runtime
        .create_group(
            "alice",
            "held welcome",
            std::slice::from_ref(&bob.account_id_hex),
            None,
        )
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    timeout(SETTLE, relay.wait_for_blocked_publish())
        .await
        .expect("the founding Welcome reaches its relays");
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitWelcomeFanout).in_flight,
        1
    );
    let before = sample(&telemetry, RuntimeOp::MutationQueueBehindWelcomeFanout);
    let waiting = vec![send(&runtime, &other), publish_key_package(&runtime)];
    until("each command queues behind the held fanout", || {
        sample(&telemetry, RuntimeOp::MutationQueueBehindWelcomeFanout).in_flight
            == before.in_flight + 2
    })
    .await;
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    held_unit_took_queued_commands(&lane.commands).await;
    none_answered(&waiting, "a held Welcome fanout");
    assert_eq!(
        sample(&telemetry, RuntimeOp::MutationQueueBehindWelcomeFanout).in_flight,
        before.in_flight + 2,
        "the fanout keeps what it takes waiting"
    );

    relay.release_publish();
    all_answered(waiting).await;
    mutations_taken_up(
        &telemetry,
        RuntimeOp::MutationQueueBehindWelcomeFanout,
        &before,
        2,
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// Hold 5, flipped by step 3 PR 2: a group subscription refresh waiting on
/// the relays holds `BuildMediaImetaTag`, which refreshes the account's
/// group routes before it answers. The group's route was refused when it
/// was made, which arms the worker's retry of it. The tag and a KeyPackage
/// publish are sent only once that retry's subscribe is held, so both queue
/// behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_subscription_refresh_holds_the_media_imeta_tag() {
    let dir = tempfile::tempdir().unwrap();
    let Alice { relay, runtime, .. } = alice_with_groups(&dir, []).await;
    let telemetry = runtime.shared_services().observer.performance().clone();
    relay.refuse_group_subscribes(true);
    let group = runtime
        .create_group("alice", "unrouted", &[], None)
        .await
        .unwrap()
        .operation
        .expect("eligible fixture members");
    // The create's founding fanout routes the group too; a read waits it out.
    runtime.started_fresh("alice").await.unwrap();

    relay.block_next_subscribe();
    relay.refuse_group_subscribes(false);
    timeout(SETTLE, relay.wait_for_blocked_subscribe())
        .await
        .expect("the worker's retry subscribes the refused route");
    assert_eq!(sample(&telemetry, RuntimeOp::RouteRefresh).in_flight, 1);
    let lane = runtime.accounts().worker_lane("alice").await.unwrap();
    let free = lane.commands.capacity();
    let reads = sample(&telemetry, RuntimeOp::ReadQueueR8);
    let tag = tokio::spawn({
        let runtime = runtime.clone();
        async move {
            runtime
                .build_media_imeta_tag("alice", &group, imeta_reference())
                .await
        }
    });
    let key_package = publish_key_package(&runtime);
    // Both sit in the lane, and the tag's read is not taken up.
    until(
        "the tag and the KeyPackage publish queue behind the refresh",
        || {
            lane.commands.capacity() + 2 <= free
                && sample(&telemetry, RuntimeOp::ReadQueueR8).in_flight == reads.in_flight + 1
        },
    )
    .await;
    assert_eq!(sample(&telemetry, RuntimeOp::RouteRefresh).in_flight, 1);
    assert!(
        !tag.is_finished(),
        "the tag answered through a held refresh"
    );
    none_answered(std::slice::from_ref(&key_package), "a held refresh");

    relay.release_subscribe();
    // The reference names no upload, so the tag may refuse it: the answer,
    // not its content, is what waited.
    let _ = timeout(SETTLE, tag)
        .await
        .expect("the tag answers once the refresh ends")
        .unwrap();
    all_answered(vec![key_package]).await;
    assert_eq!(
        sample(&telemetry, RuntimeOp::ReadQueueR8).in_flight,
        reads.in_flight
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// Hold 8, flipped by step 3 PR 1: a sign-in check reading the account's
/// KeyPackage slots from its relays keeps the worker inside the maintenance
/// tick that runs it. Every command waits, a send, a KeyPackage publish and a
/// read, and so does a delivery. After PR 1 the KeyPackage publish still
/// waits, as an account-key command (rule 6).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_sign_in_slot_read_holds_every_command_and_a_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let account = AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        "wss://relay.example",
        crate::MarmotAppConfig::white_noise()
            .with_allow_loopback_relay_endpoints(true)
            .with_dev_device_groups(true),
    )
    .with_test_relay_client(relay.clone());
    crate::tests::remember_test_member_inbox(&app, &account.account_id_hex, "wss://relay.example");
    // Alice's published KeyPackage gives her a slot, which the check reads.
    let group = {
        let mut client = app.client("alice").await.unwrap();
        client.publish_key_package().await.unwrap();
        client
            .create_group("other", &[])
            .await
            .unwrap()
            .operation
            .expect("eligible fixture members")
    };
    let delivered = foreign_group_event(&app, &group);
    let (entered, release) = relay.hold_next_slot_read();
    let runtime = crate::MarmotAppRuntime::new(app.clone());
    let telemetry = runtime.shared_services().observer.performance().clone();
    runtime.reconcile_accounts().await.unwrap();
    timeout(SETTLE, entered.notified())
        .await
        .expect("the first maintenance tick checks for sign-ins");
    assert_eq!(sample(&telemetry, RuntimeOp::SignInSlotRead).in_flight, 1);
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitMaintenance).in_flight,
        1
    );
    let receives = sample(&telemetry, RuntimeOp::WorkerUnitDelivery);
    deliver(&app, &account, &group, &delivered);
    let mutations = sample(&telemetry, RuntimeOp::MutationQueueBehindMaintenance);
    let reads = sample(&telemetry, RuntimeOp::ReadQueueBehindMaintenance);
    let waiting = vec![
        send(&runtime, &group),
        publish_key_package(&runtime),
        started_fresh(&runtime),
    ];
    until("each command queues behind the held slot read", || {
        sample(&telemetry, RuntimeOp::MutationQueueBehindMaintenance).in_flight
            == mutations.in_flight + 2
            && sample(&telemetry, RuntimeOp::ReadQueueBehindMaintenance).in_flight
                == reads.in_flight + 1
    })
    .await;
    none_answered(&waiting, "a held sign-in slot read");
    assert_eq!(
        sample(&telemetry, RuntimeOp::WorkerUnitDelivery).started,
        receives.started,
        "the worker took a delivery inside a held sign-in check"
    );

    release.notify_one();
    all_answered(waiting).await;
    mutations_taken_up(
        &telemetry,
        RuntimeOp::MutationQueueBehindMaintenance,
        &mutations,
        2,
    );
    until("the worker takes the delivery once the check ends", || {
        sample(&telemetry, RuntimeOp::WorkerUnitDelivery).started > receives.started
    })
    .await;
    runtime.shutdown_and_close().await.unwrap();
}

fn imeta_reference() -> MediaAttachmentReference {
    MediaAttachmentReference {
        locators: Vec::new(),
        ciphertext_sha256: "00".repeat(32),
        plaintext_sha256: "00".repeat(32),
        nonce_hex: "00".repeat(12),
        file_name: "held.png".into(),
        media_type: "image/png".into(),
        version: "held".into(),
        source_epoch: 0,
        source_epoch_identity: None,
        dim: None,
        thumbhash: None,
    }
}
