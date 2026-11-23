//! Sticker and emoji set relay behavior against local relays.
//!
//! - Installed list (kind 10031) publication against a multi-device account.
//!   A device that cannot read the current remote winner must not sign and
//!   publish a list built from its stale cached base: the newer timestamp
//!   would replace concurrent installs and uninstalls made on other devices.
//! - Pack (kind 30031) lookup with relay hints. Hints add candidates; they
//!   never hide a newer version on the account's own relays.
//! - Cached installed packs refresh even outside the newest public-pack window.
//! - Pack reads also reach the runtime's configured relays; the installed list
//!   still publishes only to the account's relays.
//! - Emoji set reads use the same relays as pack reads.

// Test fixtures dial local relays directly; the proxy policy is crate-private.
#![allow(clippy::disallowed_methods)]

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
    let relay_client = NostrSdkRelayClient::from_builder(NostrSdkClient::builder());
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
    storage_sqlite::relax_storage_for_test_process();
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
    let stalled_before_sync = policy.stalled.load(Ordering::SeqCst);
    let synced = app
        .sync_sticker_packs(&account_id)
        .await
        .expect("sync may refresh public packs without a complete installed-list read");
    assert!(
        policy.stalled.load(Ordering::SeqCst) > stalled_before_sync,
        "sync must attempt its own installed-list refresh"
    );
    assert_eq!(synced.installed, 0, "the pending uninstall stays visible");
    assert_eq!(
        synced.pending_operations, 1,
        "sync must not publish pending intent over an incomplete installed-list read"
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

fn pack_tags(author: &Keys, identifier: &str, title: &str, shortcode: &str) -> Vec<Tag> {
    use sonar_stickers::{PackAddress, Sticker, StickerPack, build_pack_tags};
    let hash = "11".repeat(32);
    let pack = StickerPack::new(
        PackAddress::new(author.public_key().to_hex(), identifier.to_owned()).unwrap(),
        title.to_owned(),
        None,
        None,
        vec![
            Sticker::new(
                shortcode.to_owned(),
                format!("https://cdn.example/{hash}.png"),
                hash.clone(),
                "image/png".to_owned(),
                Some(32),
                Some(32),
                None,
                None,
            )
            .unwrap(),
        ],
        None,
    )
    .unwrap();
    build_pack_tags(&pack)
        .into_iter()
        .map(|tag| {
            let fields: Vec<String> =
                serde_json::from_str(&serde_json::to_string(&tag).unwrap()).unwrap();
            Tag::parse(fields).unwrap()
        })
        .collect()
}

fn pack_naddr(author: &Keys, identifier: &str, hint: &str) -> String {
    let mut coordinate = nostr::nips::nip01::Coordinate::new(
        Kind::Custom(sonar_stickers::STICKER_PACK_KIND),
        author.public_key(),
    );
    coordinate.identifier = identifier.to_owned();
    nostr::nips::nip19::Nip19Coordinate::new(coordinate, [RelayUrl::parse(hint).unwrap()])
        .to_bech32()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_hint_cannot_hide_a_newer_pack_on_account_relays() {
    storage_sqlite::relax_storage_for_test_process();
    install_mock_keyring();
    let account_relay = LocalRelay::new(RelayBuilder::default());
    account_relay.run().await.unwrap();
    let account_url = account_relay.url().await.to_string();
    let hint_relay = LocalRelay::new(RelayBuilder::default());
    hint_relay.run().await.unwrap();
    let hint_url = hint_relay.url().await.to_string();

    let keys = Keys::generate();
    let now = unix_now();
    for (kind, tag) in [
        (
            10002,
            Tag::custom("r", [account_url.clone(), "write".to_owned()]),
        ),
        (10050, Tag::custom("relay", [account_url.clone()])),
    ] {
        publish_signed(&account_url, &keys, kind, vec![tag], now - 60).await;
    }
    let author = Keys::generate();
    let pack_kind = sonar_stickers::STICKER_PACK_KIND;
    // The hint relay only knows an older version of `cats`; the account relay
    // has the current one. `birds` is the other way round. A third pack
    // exists only behind the hint.
    publish_signed(
        &hint_url,
        &author,
        pack_kind,
        pack_tags(&author, "cats", "Old", "wave"),
        now - 100,
    )
    .await;
    publish_signed(
        &account_url,
        &author,
        pack_kind,
        pack_tags(&author, "cats", "New", "wave"),
        now - 50,
    )
    .await;
    publish_signed(
        &hint_url,
        &author,
        pack_kind,
        pack_tags(&author, "dogs", "Hinted", "wave"),
        now - 50,
    )
    .await;
    publish_signed(
        &account_url,
        &author,
        pack_kind,
        pack_tags(&author, "birds", "Old", "wave"),
        now - 100,
    )
    .await;
    publish_signed(
        &hint_url,
        &author,
        pack_kind,
        pack_tags(&author, "birds", "New", "wave"),
        now - 50,
    )
    .await;

    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        account_url.clone(),
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
            default_relays: vec![endpoint(&account_url)],
            bootstrap_relays: vec![endpoint(&account_url)],
            publish_missing_relay_lists: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("account import completes")
    .expect("account import succeeds");
    let account_id = account.account.account_id_hex;

    let cats = app
        .fetch_sticker_pack(&account_id, &pack_naddr(&author, "cats", &hint_url))
        .await
        .expect("the pack resolves");
    assert_eq!(
        cats.title, "New",
        "the account relay's newer version must win over the hinted one"
    );
    assert_eq!(
        share_hints(&app, &account_id, &cats.coordinate),
        vec![spelled(&account_url)],
        "the hint relay served only the version that lost"
    );
    let dogs = app
        .fetch_sticker_pack(&account_id, &pack_naddr(&author, "dogs", &hint_url))
        .await
        .expect("a pack only the hint relay holds still resolves");
    assert_eq!(dogs.title, "Hinted");

    // The hint holds the newer version. Later reads that see only the older
    // one (discovery, and the installed refresh, which has no hints) never
    // replace the hint relay in the share link.
    let birds = app
        .install_sticker_pack(&account_id, &pack_naddr(&author, "birds", &hint_url))
        .await
        .expect("the hinted pack installs");
    assert_eq!(birds.title, "New");
    assert_eq!(
        share_hints(&app, &account_id, &birds.coordinate),
        vec![spelled(&hint_url)]
    );
    app.sync_sticker_packs(&account_id).await.unwrap();
    let birds = app
        .sticker_pack(&account_id, &birds.coordinate)
        .unwrap()
        .unwrap();
    assert_eq!(birds.title, "New");
    assert_eq!(
        share_hints(&app, &account_id, &birds.coordinate),
        vec![spelled(&hint_url)],
        "a relay that sent only the older version is not a hint"
    );

    // A newer version later appears only on the account relay. The sync that
    // stores it replaces the hints: the hint relay no longer holds the
    // version that link would resolve to.
    publish_signed(
        &account_url,
        &author,
        pack_kind,
        pack_tags(&author, "birds", "Newest", "wave"),
        now - 10,
    )
    .await;
    app.sync_sticker_packs(&account_id).await.unwrap();
    let birds = app
        .sticker_pack(&account_id, &birds.coordinate)
        .unwrap()
        .unwrap();
    assert_eq!(birds.title, "Newest");
    assert_eq!(
        share_hints(&app, &account_id, &birds.coordinate),
        vec![spelled(&account_url)]
    );

    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_refreshes_installed_packs() {
    storage_sqlite::relax_storage_for_test_process();
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
        publish_signed(&url, &keys, kind, vec![tag], now - 400).await;
    }
    let author = Keys::generate();
    let pack_kind = sonar_stickers::STICKER_PACK_KIND;
    let coordinate = format!("{pack_kind}:{}:installed", author.public_key().to_hex());
    publish_signed(
        &url,
        &author,
        pack_kind,
        pack_tags(&author, "installed", "Original", "wave"),
        now - 300,
    )
    .await;
    publish_installed_list(&url, &keys, &[&coordinate], now - 300).await;

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
    let account_id = account.account.account_id_hex;
    app.sync_sticker_packs(&account_id).await.unwrap();
    let cached = app.sticker_pack(&account_id, &coordinate).unwrap().unwrap();
    assert!(cached.installed);
    assert_eq!(cached.title, "Original");
    assert_eq!(cached.stickers.len(), 1);
    assert_eq!(cached.stickers[0].shortcode, "wave");

    publish_signed(
        &url,
        &author,
        pack_kind,
        pack_tags(&author, "installed", "Replacement", "dance"),
        now - 200,
    )
    .await;
    // Explicit timestamps keep every filler newer than the replacement,
    // excluding the installed address from the newest-100 discovery request.
    for index in 0..100 {
        publish_signed(
            &url,
            &author,
            pack_kind,
            pack_tags(&author, &format!("filler-{index}"), "Filler", "wave"),
            now - 100 + index,
        )
        .await;
    }

    policy.armed.store(true, Ordering::SeqCst);
    let synced = app.sync_sticker_packs(&account_id).await.unwrap();
    assert!(
        policy.stalled.load(Ordering::SeqCst) >= 1,
        "the final sync must refresh packs despite an incomplete installed-list read"
    );
    assert_eq!(synced.discovered, 100);
    assert_eq!(synced.installed, 1);
    assert_eq!(synced.pending_operations, 0);
    let refreshed = app.sticker_pack(&account_id, &coordinate).unwrap().unwrap();
    assert!(refreshed.installed);
    assert_eq!(refreshed.created_at, now - 200);
    assert_eq!(refreshed.title, "Replacement");
    assert_eq!(refreshed.stickers.len(), 1);
    assert_eq!(refreshed.stickers[0].shortcode, "dance");

    policy.armed.store(false, Ordering::SeqCst);
    let (created_at, packs) = remote_installed_list(&url, keys.public_key()).await;
    assert_eq!(created_at, now - 300);
    assert_eq!(packs, vec![coordinate]);

    runtime.shutdown().await;
}

/// The relay hints in a share link, in order.
fn link_relays(link: &str) -> Vec<String> {
    url::Url::parse(link)
        .unwrap()
        .query_pairs()
        .filter(|(key, _)| key == "relay")
        .map(|(_, relay)| relay.into_owned())
        .collect()
}

/// `relay` as share-link hints spell it.
fn spelled(relay: &str) -> String {
    RelayUrl::parse(relay).unwrap().to_string()
}

/// The relay hints `account_id`'s share link for `pack` carries.
fn share_hints(app: &MarmotApp, account_id: &str, pack: &str) -> Vec<String> {
    link_relays(&app.sticker_pack_share_link(account_id, pack).unwrap())
}

/// How many installed lists (kind 10031) `author` has on `relay_url`.
async fn installed_list_count(relay_url: &str, author: PublicKey) -> usize {
    let client = NostrSdkClient::builder().build();
    client.add_relay(relay_url).await.unwrap();
    client.connect().await;
    client
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
        .unwrap()
        .len()
}

/// An imported account whose NIP-65 relay is `account_url`, on an app whose
/// configured relay is `configured_url`.
async fn import_account_on(
    account_url: &str,
    configured_url: &str,
) -> (tempfile::TempDir, MarmotApp, MarmotAppRuntime, Keys, String) {
    import_account_with_outbox(&[account_url.to_owned()], configured_url).await
}

/// An imported account whose NIP-65 relays are `account_urls`, its lists
/// published on the first, on an app whose configured relay is
/// `configured_url`.
async fn import_account_with_outbox(
    account_urls: &[String],
    configured_url: &str,
) -> (tempfile::TempDir, MarmotApp, MarmotAppRuntime, Keys, String) {
    let account_url = account_urls[0].as_str();
    let keys = Keys::generate();
    let now = unix_now();
    let outbox = account_urls
        .iter()
        .map(|url| Tag::custom("r", [url.clone(), "write".to_owned()]))
        .collect();
    publish_signed(account_url, &keys, 10002, outbox, now - 600).await;
    publish_signed(
        account_url,
        &keys,
        10050,
        vec![Tag::custom("relay", [account_url.to_owned()])],
        now - 600,
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relay_and_config(
        dir.path(),
        configured_url.to_owned(),
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
            default_relays: vec![endpoint(account_url)],
            bootstrap_relays: vec![endpoint(account_url)],
            publish_missing_relay_lists: true,
            ..AccountSetupRequest::default()
        }),
    )
    .await
    .expect("account import completes")
    .expect("account import succeeds");
    let account_id = account.account.account_id_hex;
    (dir, app, runtime, keys, account_id)
}

/// Packs often live only on the host's configured relays, which an imported
/// account's relay list need not name. Reads reach them; the installed list
/// still publishes to the account's relays alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configured_relays_serve_pack_reads_but_not_the_installed_list() {
    storage_sqlite::relax_storage_for_test_process();
    install_mock_keyring();
    // Eight outbox relays: enough to fill every share-link hint slot on their
    // own. Only the last holds a pack.
    let mut account_relays = Vec::new();
    let mut account_urls = Vec::new();
    for _ in 0..8 {
        let relay = LocalRelay::new(RelayBuilder::default());
        relay.run().await.unwrap();
        account_urls.push(relay.url().await.to_string());
        account_relays.push(relay);
    }
    let account_url = account_urls[0].clone();
    let configured_relay = LocalRelay::new(RelayBuilder::default());
    configured_relay.run().await.unwrap();
    let configured_url = configured_relay.url().await.to_string();

    let author = Keys::generate();
    let pack_kind = sonar_stickers::STICKER_PACK_KIND;
    let now = unix_now();
    for identifier in ["default", "browse"] {
        publish_signed(
            &configured_url,
            &author,
            pack_kind,
            pack_tags(&author, identifier, identifier, "wave"),
            now - 100,
        )
        .await;
    }
    publish_signed(
        &account_urls[7],
        &author,
        pack_kind,
        pack_tags(&author, "eighth", "eighth", "wave"),
        now - 100,
    )
    .await;
    let default_pack = format!("{pack_kind}:{}:default", author.public_key().to_hex());
    let browse_pack = format!("{pack_kind}:{}:browse", author.public_key().to_hex());
    let eighth_pack = format!("{pack_kind}:{}:eighth", author.public_key().to_hex());
    let (_dir, app, runtime, keys, account_id) =
        import_account_with_outbox(&account_urls, &configured_url).await;

    let installed = app
        .install_sticker_pack(&account_id, &default_pack)
        .await
        .expect("a pack only the configured relay holds installs");
    assert!(installed.installed);

    let synced = app.sync_sticker_packs(&account_id).await.unwrap();
    assert_eq!(
        synced.discovered, 3,
        "discovery reaches the configured relay"
    );
    assert_eq!(synced.pending_operations, 0);
    let browsable = app
        .sticker_packs(&account_id, false, None, None)
        .unwrap()
        .into_iter()
        .map(|pack| pack.coordinate)
        .collect::<Vec<_>>();
    assert!(browsable.contains(&browse_pack));
    // Share links name the relays that served each pack, not the relays
    // that were queried.
    for pack in [&default_pack, &browse_pack] {
        assert_eq!(
            share_hints(&app, &account_id, pack),
            vec![spelled(&configured_url)]
        );
    }
    assert_eq!(
        share_hints(&app, &account_id, &eighth_pack),
        vec![spelled(&account_urls[7])]
    );

    let (_, packs) = remote_installed_list(&account_url, keys.public_key()).await;
    assert_eq!(packs, vec![default_pack]);
    assert_eq!(
        installed_list_count(&configured_url, keys.public_key()).await,
        0,
        "the installed list is never published to a configured relay"
    );
    drop(account_relays);

    runtime.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn newest_pack_version_wins_across_account_and_configured_relays() {
    storage_sqlite::relax_storage_for_test_process();
    install_mock_keyring();
    let account_relay = LocalRelay::new(RelayBuilder::default());
    account_relay.run().await.unwrap();
    let account_url = account_relay.url().await.to_string();
    let configured_relay = LocalRelay::new(RelayBuilder::default());
    configured_relay.run().await.unwrap();
    let configured_url = configured_relay.url().await.to_string();

    let author = Keys::generate();
    let pack_kind = sonar_stickers::STICKER_PACK_KIND;
    let now = unix_now();
    // Each source holds the newer version of one pack and the older of the other.
    for (identifier, newer_url, older_url) in [
        ("cats", &configured_url, &account_url),
        ("dogs", &account_url, &configured_url),
    ] {
        publish_signed(
            older_url,
            &author,
            pack_kind,
            pack_tags(&author, identifier, "Old", "wave"),
            now - 100,
        )
        .await;
        publish_signed(
            newer_url,
            &author,
            pack_kind,
            pack_tags(&author, identifier, "New", "wave"),
            now - 50,
        )
        .await;
    }
    let (_dir, app, runtime, _keys, account_id) =
        import_account_on(&account_url, &configured_url).await;

    for identifier in ["cats", "dogs"] {
        let coordinate = format!("{pack_kind}:{}:{identifier}", author.public_key().to_hex());
        let pack = app
            .fetch_sticker_pack(&account_id, &coordinate)
            .await
            .expect("the pack resolves");
        assert_eq!(pack.title, "New", "{identifier}: the newer version wins");
    }

    runtime.shutdown().await;
}

fn emoji_set_tags(identifier: &str, title: &str) -> Vec<Tag> {
    vec![
        Tag::custom("d", [identifier.to_owned()]),
        Tag::custom("title", [title.to_owned()]),
        Tag::custom(
            "emoji",
            ["wave".to_owned(), "https://cdn.example/wave.png".to_owned()],
        ),
    ]
}

/// Emoji sets read from the same relays as sticker packs: a set only the
/// configured relay holds is discovered, fetched and resolved from the
/// account's list, and the newest version wins across both sources.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emoji_set_reads_reach_configured_relays() {
    use marmot_app::{EMOJI_SET_KIND, USER_EMOJI_LIST_KIND};

    storage_sqlite::relax_storage_for_test_process();
    install_mock_keyring();
    let account_relay = LocalRelay::new(RelayBuilder::default());
    account_relay.run().await.unwrap();
    let account_url = account_relay.url().await.to_string();
    let configured_relay = LocalRelay::new(RelayBuilder::default());
    configured_relay.run().await.unwrap();
    let configured_url = configured_relay.url().await.to_string();

    let author = Keys::generate();
    let now = unix_now();
    let coordinate = |identifier: &str| {
        format!(
            "{EMOJI_SET_KIND}:{}:{identifier}",
            author.public_key().to_hex()
        )
    };
    for (url, identifier, title, created_at) in [
        (&configured_url, "configured", "Configured", now - 100),
        (&configured_url, "both", "Old", now - 100),
        (&account_url, "both", "New", now - 50),
    ] {
        publish_signed(
            url,
            &author,
            EMOJI_SET_KIND,
            emoji_set_tags(identifier, title),
            created_at,
        )
        .await;
    }
    let (_dir, app, runtime, keys, account_id) =
        import_account_on(&account_url, &configured_url).await;
    // The account's own list lives on its relay and points at a set only the
    // configured relay holds.
    publish_signed(
        &account_url,
        &keys,
        USER_EMOJI_LIST_KIND,
        vec![
            Tag::custom("a", [coordinate("pointed")]),
            Tag::custom(
                "emoji",
                ["mine".to_owned(), "https://cdn.example/mine.png".to_owned()],
            ),
        ],
        now - 40,
    )
    .await;
    // A newer list only on the configured relay is never read: the account's
    // own list comes from its relays alone.
    publish_signed(
        &configured_url,
        &keys,
        USER_EMOJI_LIST_KIND,
        vec![
            Tag::custom("a", [coordinate("configured")]),
            Tag::custom(
                "emoji",
                [
                    "decoy".to_owned(),
                    "https://cdn.example/decoy.png".to_owned(),
                ],
            ),
        ],
        now - 30,
    )
    .await;

    // Each read starts from an empty cache for the set it checks, so none
    // passes on a set another read stored.
    let fetched = app
        .fetch_emoji_set(&account_id, &coordinate("configured"))
        .await
        .expect("a set only the configured relay holds resolves");
    assert_eq!(fetched.title.as_deref(), Some("Configured"));

    let synced = app.sync_emoji_sets(&account_id, None).await.unwrap();
    assert_eq!(
        synced.discovered, 2,
        "discovery reaches the configured relay"
    );
    let both = app
        .emoji_set(&account_id, &coordinate("both"))
        .await
        .unwrap()
        .expect("discovered");
    assert_eq!(both.title.as_deref(), Some("New"), "the newer version wins");

    // Published after discovery, so only the list's pointer read can find it.
    publish_signed(
        &configured_url,
        &author,
        EMOJI_SET_KIND,
        emoji_set_tags("pointed", "Pointed"),
        now - 100,
    )
    .await;
    let list = app.user_emoji_list(&account_id).await.unwrap();
    assert_eq!(
        list.sets
            .iter()
            .map(|set| set.coordinate.clone())
            .collect::<Vec<_>>(),
        vec![coordinate("pointed")]
    );
    assert!(list.missing_set_coordinates.is_empty());
    // Fetching the list by its own address, even through an `naddr` hinting
    // the relay with the newer decoy, reads the account's relays only.
    let mut own_list =
        nostr::nips::nip01::Coordinate::new(Kind::Custom(USER_EMOJI_LIST_KIND), keys.public_key());
    own_list.identifier = String::new();
    let hinted_naddr = nostr::nips::nip19::Nip19Coordinate::new(
        own_list,
        [RelayUrl::parse(&configured_url).unwrap()],
    )
    .to_bech32()
    .unwrap();
    for input in [
        format!("{USER_EMOJI_LIST_KIND}:{}:", keys.public_key().to_hex()),
        hinted_naddr,
    ] {
        let own = app.fetch_emoji_set(&account_id, &input).await.unwrap();
        assert_eq!(
            own.emoji
                .iter()
                .map(|emoji| emoji.shortcode.as_str())
                .collect::<Vec<_>>(),
            ["mine"],
            "{input}"
        );
    }
    let list = app.user_emoji_list(&account_id).await.unwrap();
    assert_eq!(
        list.own_emoji
            .expect("the account's list has an emoji")
            .emoji
            .iter()
            .map(|emoji| emoji.shortcode.as_str())
            .collect::<Vec<_>>(),
        ["mine"]
    );

    runtime.shutdown().await;
}
