//! Installed sticker list (kind 10031) publication against a multi-device
//! account. A device that cannot read the current remote winner must not sign
//! and publish a list built from its stale cached base: the newer timestamp
//! would replace concurrent installs and uninstalls made on other devices.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cgka_traits::TransportEndpoint;
use marmot_app::{AccountSetupRequest, MarmotApp, MarmotAppConfig, MarmotAppRuntime};
use nostr_relay_builder::prelude::{
    BoxedFuture, Filter as RelayFilter, Kind as RelayKind, PolicyResult, QueryPolicy,
};
use nostr_relay_builder::{LocalRelay, RelayBuilder};
use nostr_sdk::prelude::{
    Client as NostrSdkClient, EventBuilder, Filter, FinalizeEvent, Keys, Kind, PublicKey, RelayUrl,
    ReqTarget, Tag, Timestamp as NostrTimestamp, ToBech32,
};
use tokio::time::{Duration, timeout};
use transport_nostr_adapter::{NostrRelayClient, NostrSdkRelayClient};
use transport_nostr_peeler::NostrTransportEvent;

const USER_STICKER_PACKS_KIND: u16 = 10031;

/// Stall installed-list reads while armed so the app's bounded read never
/// reaches end-of-stored-events. Writes stay accepted, which is the relay
/// shape that lets a stale publication succeed after a failed refresh. A
/// stalled read is also the shape a plain fetch reports as an empty success,
/// so this covers the refresh needing completion evidence, not only an error.
#[derive(Clone, Debug, Default)]
struct StallInstalledListReadsWhileArmed {
    armed: Arc<AtomicBool>,
    stalled: Arc<AtomicUsize>,
}

impl QueryPolicy for StallInstalledListReadsWhileArmed {
    fn admit_query<'a>(
        &'a self,
        query: &'a RelayFilter,
        _addr: &'a SocketAddr,
    ) -> BoxedFuture<'a, PolicyResult> {
        Box::pin(async move {
            let installed_list = query
                .kinds
                .as_ref()
                .is_some_and(|kinds| kinds.contains(&RelayKind::Custom(USER_STICKER_PACKS_KIND)));
            if installed_list && self.armed.load(Ordering::SeqCst) {
                self.stalled.fetch_add(1, Ordering::SeqCst);
                while self.armed.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            PolicyResult::Accept
        })
    }
}

fn install_mock_keyring() {
    static KEYRING_INIT: std::sync::Once = std::sync::Once::new();
    KEYRING_INIT.call_once(|| {
        if keyring_core::get_default_store().is_none() {
            let store = keyring_core::mock::Store::new().expect("create mock keyring store");
            keyring_core::set_default_store(store);
        }
    });
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

fn endpoint(url: &str) -> TransportEndpoint {
    TransportEndpoint(url.to_owned())
}

async fn publish_signed(relay_url: &str, keys: &Keys, kind: u16, tags: Vec<Tag>, created_at: u64) {
    let signed = EventBuilder::new(Kind::Custom(kind), "")
        .tags(tags)
        .custom_created_at(NostrTimestamp::from_secs(created_at))
        .finalize(keys)
        .expect("sign test event");
    let transport_event =
        NostrTransportEvent::from_nostr_event(&signed).expect("dto from signed event");
    let relay_client = NostrSdkRelayClient::new(NostrSdkClient::builder().build());
    relay_client
        .publish_event(&[endpoint(relay_url)], &transport_event, 1)
        .await
        .expect("publish test event");
}

async fn publish_installed_list(relay_url: &str, keys: &Keys, packs: &[&str], created_at: u64) {
    let tags = packs
        .iter()
        .map(|pack| Tag::custom("a", [(*pack).to_owned()]))
        .collect();
    publish_signed(relay_url, keys, USER_STICKER_PACKS_KIND, tags, created_at).await;
}

/// The NIP-01 winner of the account's installed list as the relay serves it:
/// newest `created_at`, lowest id on ties.
async fn remote_installed_list(relay_url: &str, author: PublicKey) -> (u64, Vec<String>) {
    let client = NostrSdkClient::builder().build();
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    let events = client
        .fetch_events(ReqTarget::manual(vec![(
            RelayUrl::parse(relay_url).unwrap(),
            vec![
                Filter::new()
                    .author(author)
                    .kind(Kind::Custom(USER_STICKER_PACKS_KIND)),
            ],
        )]))
        .timeout(Duration::from_secs(5))
        .await
        .unwrap();
    let mut events = events.into_iter().collect::<Vec<_>>();
    events.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    let winner = events.first().expect("an installed list is published");
    let packs = winner
        .tags
        .iter()
        .filter_map(|tag| {
            let tag = tag.as_slice();
            (tag.first().map(String::as_str) == Some("a")).then(|| tag[1].clone())
        })
        .collect();
    (winner.created_at.as_secs(), packs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_installed_list_refresh_blocks_stale_publication_until_rebase() {
    install_mock_keyring();
    let policy = StallInstalledListReadsWhileArmed::default();
    let relay = LocalRelay::new(RelayBuilder::default().query_policy(policy.clone()));
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();

    let keys = Keys::generate();
    let now = unix_now();
    for (kind, tag) in [
        (10002, Tag::custom("r", [url.clone(), "write".to_owned()])),
        (10050, Tag::custom("relay", [url.clone()])),
    ] {
        publish_signed(&url, &keys, kind, vec![tag], now - 60).await;
    }
    let pack_a = format!("30031:{}:alpha", Keys::generate().public_key().to_hex());
    let pack_b = format!("30031:{}:beta", Keys::generate().public_key().to_hex());
    // This device last saw only `pack_a` installed.
    publish_installed_list(&url, &keys, &[&pack_a], now - 40).await;

    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        url.clone(),
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    let account = timeout(
        Duration::from_secs(40),
        runtime.create_or_import_account(AccountSetupRequest {
            identity: None,
            import_nsec: Some(zeroize::Zeroizing::new(
                keys.secret_key().to_bech32().unwrap(),
            )),
            default_relays: vec![endpoint(&url)],
            bootstrap_relays: vec![endpoint(&url)],
            publish_missing_relay_lists: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("account import completes")
    .expect("account import succeeds");
    let account_id = account.account.account_id_hex.clone();
    let synced = app.sync_sticker_packs(&account_id).await.unwrap();
    assert_eq!(
        synced.installed, 1,
        "the cached base is the older remote list"
    );
    assert_eq!(synced.pending_operations, 0);

    // Another device installs `pack_b` on top of the same list.
    publish_installed_list(&url, &keys, &[&pack_a, &pack_b], now - 20).await;

    // Reads fail transiently while writes still succeed.
    policy.armed.store(true, Ordering::SeqCst);
    app.uninstall_sticker_pack(&account_id, &pack_a)
        .await
        .expect("local intent is recorded while the refresh is unavailable");
    assert!(
        policy.stalled.load(Ordering::SeqCst) >= 1,
        "the installed-list refresh must have been attempted and timed out"
    );
    // Reads recover. Nothing below the app has run yet, so the relay still
    // shows exactly what the failed-refresh path left behind.
    policy.armed.store(false, Ordering::SeqCst);
    let (created_at, packs) = remote_installed_list(&url, keys.public_key()).await;
    assert_eq!(
        packs,
        vec![pack_a.clone(), pack_b.clone()],
        "no list may be published over a base that could not be refreshed"
    );
    assert_eq!(created_at, now - 20);
    let listed = app
        .sticker_packs(&account_id, true, None, None)
        .unwrap()
        .into_iter()
        .map(|pack| pack.coordinate)
        .collect::<Vec<_>>();
    assert!(
        !listed.contains(&pack_a),
        "the local uninstall stays visible as pending intent"
    );

    // The retry refreshes first, rebases the uninstall, then publishes.
    let synced = app.sync_sticker_packs(&account_id).await.unwrap();
    assert_eq!(
        synced.pending_operations, 0,
        "the rebased operation was published"
    );
    assert_eq!(synced.installed, 1);
    let (created_at, packs) = remote_installed_list(&url, keys.public_key()).await;
    assert_eq!(
        packs,
        vec![pack_b],
        "the concurrent remote install survives the local uninstall"
    );
    assert!(created_at > now - 20);

    runtime.shutdown().await;
}
