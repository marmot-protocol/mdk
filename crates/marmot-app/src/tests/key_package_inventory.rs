use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use cgka_engine::key_package::key_package_metadata;
use cgka_traits::engine::KeyPackage;
use cgka_traits::{MemberId, TransportEndpoint};
use marmot_account::{AccountHome, AccountSummary};
use transport_nostr_adapter::{
    KIND_MARMOT_INBOX_RELAY_LIST, KIND_MARMOT_KEY_PACKAGE, KIND_NIP65_RELAY_LIST,
};
use transport_nostr_peeler::NostrTransportEvent;

use super::{
    MemberResolutionDirectoryFetcher, ScriptedPushRelayClient, fresh_key_package_for_account,
    key_package_cache_exists, write_key_package_cache,
};
use crate::runtime::{AccountSetupRequest, SignOutOptions};
use crate::{
    AccountKeyPackageLocalState, KeyPackageDeletionTarget, MarmotApp, MarmotAppRuntime,
    MarmotRelayPlane,
};

const DIRECTORY: &str = "wss://directory.example";
const SLOT: &str = "stable-slot";
const OTHER_SLOT: &str = "other-slot";

fn endpoint(url: &str) -> TransportEndpoint {
    TransportEndpoint(url.to_owned())
}

fn key_package_event(
    account: &AccountSummary,
    key_package: KeyPackage,
    slot_id: &str,
    created_at: u64,
) -> NostrTransportEvent {
    let metadata = key_package_metadata(&key_package).unwrap();
    transport_nostr_adapter::NostrKeyPackagePublication {
        account_id: MemberId::new(hex::decode(&account.account_id_hex).unwrap()),
        key_package,
        key_package_slot_id: slot_id.to_owned(),
        key_package_ref: metadata.key_package_ref_hex,
        mls_ciphersuite: format!("0x{:04x}", metadata.ciphersuite),
        mls_extensions: metadata
            .mls_extensions
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        mls_proposals: metadata
            .mls_proposals
            .iter()
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        app_components: metadata
            .app_components
            .iter()
            .copied()
            .filter(|id| *id >= cgka_traits::app_components::PRIVATE_USE_APP_COMPONENT_ID_START)
            .map(|id| format!("0x{id:04x}"))
            .collect(),
        publish_endpoints: vec![endpoint(DIRECTORY)],
    }
    .to_event_at(created_at)
    .unwrap()
}

fn invalidate_key_package_event(mut event: NostrTransportEvent) -> NostrTransportEvent {
    if let Some(tag) = event.tags.iter_mut().find(|tag| {
        tag.first()
            .is_some_and(|name| name == "mls_protocol_version")
    }) {
        *tag = vec!["mls_protocol_version".into(), "9.9".into()];
    }
    event
}

fn relay_list_events(account_id_hex: &str, relays: &[&str]) -> Vec<NostrTransportEvent> {
    let nip65_tags = relays
        .iter()
        .map(|relay| vec!["r".into(), (*relay).into(), "write".into()])
        .collect();
    vec![
        NostrTransportEvent::new_unsigned(
            account_id_hex.to_owned(),
            KIND_NIP65_RELAY_LIST,
            nip65_tags,
            String::new(),
        ),
        NostrTransportEvent::new_unsigned(
            account_id_hex.to_owned(),
            KIND_MARMOT_INBOX_RELAY_LIST,
            vec![vec!["relay".into(), relays[0].into()]],
            String::new(),
        ),
    ]
}

fn seed_fetcher(
    fetcher: &MemberResolutionDirectoryFetcher,
    account: &AccountSummary,
    events: Vec<NostrTransportEvent>,
    relays: &[&str],
) {
    let mut all = relay_list_events(&account.account_id_hex, relays);
    all.extend(events);
    *fetcher.events.lock().unwrap() = all;
}

fn seed_fetcher_by_endpoint(
    fetcher: &MemberResolutionDirectoryFetcher,
    account: &AccountSummary,
    by_endpoint: HashMap<String, Vec<NostrTransportEvent>>,
    relays: &[&str],
) {
    let lists = relay_list_events(&account.account_id_hex, relays);
    let mut mapped = HashMap::new();
    for (endpoint, mut events) in by_endpoint {
        let mut with_lists = lists.clone();
        with_lists.append(&mut events);
        mapped.insert(endpoint, with_lists);
    }
    *fetcher.events_by_endpoint.lock().unwrap() = mapped;
}

fn assert_key_package_queries_use_limit_12(fetcher: &MemberResolutionDirectoryFetcher) {
    let requests = fetcher.requests.lock().unwrap().clone();
    let queries = requests
        .iter()
        .flat_map(|request| request.queries.iter())
        .filter(|query| query.kind == KIND_MARMOT_KEY_PACKAGE)
        .collect::<Vec<_>>();
    assert!(
        !queries.is_empty(),
        "listing must issue a KeyPackage directory query"
    );
    assert!(
        queries.iter().all(|query| query.limit == 12),
        "KeyPackage queries must keep the existing fetch budget"
    );
}

fn kind5_targets(relay: &ScriptedPushRelayClient) -> Vec<String> {
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == 5)
        .filter_map(|event| {
            event
                .tags
                .iter()
                .find(|tag| tag.first().is_some_and(|name| name == "e"))
                .and_then(|tag| tag.get(1).cloned())
        })
        .collect()
}

async fn inventory_fixture() -> (
    tempfile::TempDir,
    MarmotApp,
    AccountSummary,
    Arc<MemberResolutionDirectoryFetcher>,
    Arc<ScriptedPushRelayClient>,
) {
    let directory = tempfile::tempdir().unwrap();
    let home = AccountHome::open(directory.path());
    let account = home.create_account("inventory").unwrap();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app =
        MarmotApp::with_relay(directory.path(), DIRECTORY).with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay.clone(),
        fetcher.clone(),
        false,
    );
    (directory, app, account, fetcher, relay)
}

async fn same_slot_events(
    app: &MarmotApp,
    account: &AccountSummary,
) -> (
    NostrTransportEvent,
    NostrTransportEvent,
    NostrTransportEvent,
) {
    let older_pkg = fresh_key_package_for_account(app, account, false).await;
    let newer_pkg = fresh_key_package_for_account(app, account, false).await;
    let other_pkg = fresh_key_package_for_account(app, account, false).await;
    (
        key_package_event(account, older_pkg, SLOT, 10),
        key_package_event(account, newer_pkg, SLOT, 20),
        key_package_event(account, other_pkg, OTHER_SLOT, 15),
    )
}

#[tokio::test]
async fn account_key_package_records_collapses_lagging_relay_events() {
    let (_dir, app, account, fetcher, relay) = inventory_fixture().await;
    let (older, newer, other) = same_slot_events(&app, &account).await;
    let invalid = invalidate_key_package_event(key_package_event(
        &account,
        fresh_key_package_for_account(&app, &account, false).await,
        SLOT,
        30,
    ));
    seed_fetcher(
        &fetcher,
        &account,
        vec![
            older.clone(),
            newer.clone(),
            other.clone(),
            invalid,
            newer.clone(),
        ],
        &[DIRECTORY],
    );

    let listing = app
        .account_key_package_records(&account.label, vec![endpoint(DIRECTORY)], Vec::new())
        .await
        .unwrap();
    let history = app
        .account_key_package_relay_events(&account.label, vec![endpoint(DIRECTORY)])
        .await
        .unwrap();
    assert_key_package_queries_use_limit_12(&fetcher);
    assert_eq!(
        listing
            .iter()
            .filter(|record| record.relay)
            .map(|record| record.key_package_event_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([newer.id.as_str(), other.id.as_str()])
    );
    assert_eq!(
        history
            .iter()
            .map(|event| event.key_package_event_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([older.id.as_str(), newer.id.as_str(), other.id.as_str()])
    );
    assert_eq!(
        history
            .iter()
            .filter(|event| event.is_current)
            .map(|event| event.key_package_event_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([newer.id.as_str(), other.id.as_str()])
    );
    assert!(relay.published_events.lock().unwrap().is_empty());

    seed_fetcher(
        &fetcher,
        &account,
        vec![other.clone(), newer.clone(), older.clone()],
        &[DIRECTORY],
    );
    fetcher.requests.lock().unwrap().clear();
    let reversed = app
        .account_key_package_records(&account.label, vec![endpoint(DIRECTORY)], Vec::new())
        .await
        .unwrap();
    assert_eq!(
        reversed
            .iter()
            .filter(|record| record.relay)
            .map(|record| record.key_package_event_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([newer.id.as_str(), other.id.as_str()])
    );
}

#[tokio::test]
async fn relay_history_unions_duplicate_event_ids_across_endpoints() {
    let (_dir, app, account, fetcher, _relay) = inventory_fixture().await;
    let (older, newer, _other) = same_slot_events(&app, &account).await;
    const SECOND: &str = "wss://shared.example";
    let mut by_endpoint = HashMap::new();
    by_endpoint.insert(DIRECTORY.into(), vec![older.clone(), newer.clone()]);
    by_endpoint.insert(SECOND.into(), vec![newer.clone(), older.clone()]);
    seed_fetcher_by_endpoint(&fetcher, &account, by_endpoint, &[DIRECTORY, SECOND]);

    let duplicated = app
        .account_key_package_relay_events(
            &account.label,
            vec![endpoint(DIRECTORY), endpoint(SECOND)],
        )
        .await
        .unwrap();
    let current = duplicated
        .iter()
        .find(|event| event.key_package_event_id == newer.id)
        .expect("current event");
    assert!(current.is_current);
    assert_eq!(
        current.source_relays,
        vec![DIRECTORY.to_owned(), SECOND.to_owned()]
    );
    assert_eq!(
        duplicated
            .iter()
            .filter(|event| event.key_package_event_id == older.id
                || event.key_package_event_id == newer.id)
            .count(),
        2
    );
}

#[tokio::test]
async fn superseded_key_package_event_remains_deletable() {
    let (_dir, app, account, fetcher, relay) = inventory_fixture().await;
    let (older, newer, _other) = same_slot_events(&app, &account).await;
    seed_fetcher(
        &fetcher,
        &account,
        vec![older.clone(), newer.clone()],
        &[DIRECTORY],
    );
    write_key_package_cache(
        &app,
        &account,
        SLOT,
        newer.tag_value("i").expect("current event has an i tag"),
        &newer.id,
    );

    let history = app
        .account_key_package_relay_events(&account.label, vec![endpoint(DIRECTORY)])
        .await
        .unwrap();
    let superseded = history
        .iter()
        .find(|event| event.key_package_event_id == older.id)
        .expect("older event remains in history");
    assert!(!superseded.is_current);
    assert!(relay.published_events.lock().unwrap().is_empty());

    let accepted = app
        .delete_key_package_event(
            &account.label,
            &superseded.key_package_event_id,
            superseded
                .source_relays
                .iter()
                .cloned()
                .map(TransportEndpoint)
                .collect(),
        )
        .await
        .unwrap();
    assert!(accepted >= 1);
    assert_eq!(kind5_targets(&relay), vec![older.id.clone()]);
    assert!(key_package_cache_exists(&app, &account.label));

    let listing = app
        .account_key_package_records(&account.label, vec![endpoint(DIRECTORY)], Vec::new())
        .await
        .unwrap();
    assert!(
        listing
            .iter()
            .any(|record| record.relay && record.key_package_event_id == newer.id)
    );
}

#[tokio::test]
async fn bulk_key_package_cleanup_includes_superseded_events() {
    let directory = tempfile::tempdir().unwrap();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app =
        MarmotApp::with_relay(directory.path(), DIRECTORY).with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay.clone(),
        fetcher.clone(),
        false,
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(DIRECTORY)],
            bootstrap_relays: vec![endpoint(DIRECTORY)],
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let account = created.account;
    let (older, newer, _other) = same_slot_events(&app, &account).await;
    seed_fetcher(
        &fetcher,
        &account,
        vec![older.clone(), newer.clone()],
        &[DIRECTORY],
    );
    write_key_package_cache(&app, &account, SLOT, "local-only-ref", "");

    let history = runtime
        .account_key_package_relay_events(&account.account_id_hex, vec![endpoint(DIRECTORY)])
        .await
        .unwrap();
    assert_eq!(history.len(), 2);

    let outcome = runtime
        .sign_out(
            &account.account_id_hex,
            SignOutOptions {
                delete_key_packages: true,
            },
        )
        .await
        .unwrap();
    let deleted = kind5_targets(&relay);
    assert_eq!(
        deleted.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([older.id.clone(), newer.id.clone()])
    );
    assert_eq!(deleted.len(), 2);
    assert!(outcome.key_packages_deleted >= 2);
    assert!(!deleted.iter().any(|id| id.is_empty()));
}

#[tokio::test]
async fn wipe_bulk_cleanup_includes_superseded_events() {
    let directory = tempfile::tempdir().unwrap();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app =
        MarmotApp::with_relay(directory.path(), DIRECTORY).with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay.clone(),
        fetcher.clone(),
        false,
    );
    let runtime = MarmotAppRuntime::new(app.clone());
    runtime.start().await.unwrap();
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(DIRECTORY)],
            bootstrap_relays: vec![endpoint(DIRECTORY)],
            publish_initial_key_package: false,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    let account = created.account;
    let (older, newer, _other) = same_slot_events(&app, &account).await;
    seed_fetcher(
        &fetcher,
        &account,
        vec![older.clone(), newer.clone()],
        &[DIRECTORY],
    );

    let outcome = runtime
        .sign_out_and_wipe(&account.account_id_hex)
        .await
        .unwrap();
    let deleted = kind5_targets(&relay);
    assert_eq!(
        deleted.iter().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([older.id.clone(), newer.id.clone()])
    );
    assert!(outcome.key_packages_deleted >= 2);
}

#[tokio::test]
async fn listing_does_not_publish_and_partial_deletion_still_uses_explicit_targets() {
    let (_dir, app, account, fetcher, relay) = inventory_fixture().await;
    let (older, newer, _other) = same_slot_events(&app, &account).await;
    seed_fetcher(
        &fetcher,
        &account,
        vec![older.clone(), newer.clone()],
        &[DIRECTORY],
    );
    relay.script([true, false]);
    let _ = app
        .account_key_package_records(&account.label, vec![endpoint(DIRECTORY)], Vec::new())
        .await
        .unwrap();
    assert!(
        relay
            .published_events
            .lock()
            .unwrap()
            .iter()
            .all(|event| event.kind != 5)
    );

    let results = app
        .delete_key_package_events(
            &account.label,
            vec![
                KeyPackageDeletionTarget {
                    event_id_hex: older.id.clone(),
                    source_relays: vec![endpoint(DIRECTORY)],
                },
                KeyPackageDeletionTarget {
                    event_id_hex: newer.id.clone(),
                    source_relays: vec![endpoint(DIRECTORY)],
                },
            ],
        )
        .await
        .unwrap();
    assert!(results[0].result.is_ok());
    assert!(results[1].result.is_err());
}

async fn runtime_inventory_fixture() -> (
    tempfile::TempDir,
    MarmotAppRuntime,
    AccountSummary,
    Arc<MemberResolutionDirectoryFetcher>,
    Arc<ScriptedPushRelayClient>,
) {
    let directory = tempfile::tempdir().unwrap();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    let mut app =
        MarmotApp::with_relay(directory.path(), DIRECTORY).with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay.clone(),
        fetcher.clone(),
        false,
    );
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();
    let created = runtime
        .create_identity(AccountSetupRequest {
            default_relays: vec![endpoint(DIRECTORY)],
            bootstrap_relays: vec![endpoint(DIRECTORY)],
            publish_initial_key_package: true,
            ..AccountSetupRequest::default()
        })
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    (directory, runtime, created.account, fetcher, relay)
}

fn published_key_package_events(relay: &ScriptedPushRelayClient) -> Vec<NostrTransportEvent> {
    relay
        .published_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.kind == KIND_MARMOT_KEY_PACKAGE)
        .cloned()
        .collect()
}

fn assert_local_only_invariants(entries: &[crate::AccountKeyPackageInventoryEntry]) {
    assert!(
        entries.iter().all(|entry| {
            entry.record.local
                && !entry.record.relay
                && entry.local_state != AccountKeyPackageLocalState::NotLocal
                && entry.record.local == entry.local_state.is_local()
        }),
        "local inventory must stay local-only with typed durable states"
    );
}

fn current_ref(entries: &[crate::AccountKeyPackageInventoryEntry]) -> Option<&str> {
    entries
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
        .map(|entry| entry.record.key_package_ref_hex.as_str())
}

fn is_mixed_retained_without_new_current(
    entries: &[crate::AccountKeyPackageInventoryEntry],
    previous_current_ref: &str,
) -> bool {
    let retained_previous = entries.iter().any(|entry| {
        entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial
            && entry.record.key_package_ref_hex == previous_current_ref
    });
    retained_previous && current_ref(entries).is_none()
}

struct InventorySeamHandshake {
    hook: Arc<dyn Fn() + Send + Sync>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

fn inventory_seam_handshake() -> InventorySeamHandshake {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let hook_entered = entered.clone();
    let hook_release = release.clone();
    InventorySeamHandshake {
        hook: Arc::new(move || {
            hook_entered.notify_one();
            let (lock, cvar) = &*hook_release;
            let mut released = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            while !*released {
                released = cvar
                    .wait(released)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }),
        entered,
        release,
    }
}

impl InventorySeamHandshake {
    fn release_read(&self) {
        let (lock, cvar) = &*self.release;
        *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        cvar.notify_one();
    }
}

// Release the reader even if an assertion fails, so runtime teardown cannot
// strand a blocking snapshot hook.
impl Drop for InventorySeamHandshake {
    fn drop(&mut self) {
        self.release_read();
    }
}

fn assert_coherent_rotation_inventory(
    entries: &[crate::AccountKeyPackageInventoryEntry],
    previous_current_ref: &str,
) {
    assert!(
        !is_mixed_retained_without_new_current(entries, previous_current_ref),
        "previously current package must not be retained while the new current owned package is missing"
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
            .count(),
        1,
        "coherent inventory must include exactly one Current package"
    );
    let current =
        current_ref(entries).expect("coherent inventory must include exactly one Current package");
    if current == previous_current_ref {
        assert!(
            entries.iter().all(|entry| {
                entry.local_state != AccountKeyPackageLocalState::RetainedPrivateMaterial
                    || entry.record.key_package_ref_hex != previous_current_ref
            }),
            "pre-rotation snapshot must still classify the previous package as Current"
        );
    } else {
        assert!(
            entries.iter().any(|entry| {
                entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial
                    && entry.record.key_package_ref_hex == previous_current_ref
            }),
            "post-rotation snapshot must retain the previous current package"
        );
    }
}

#[tokio::test]
async fn local_inventory_reports_current_then_retained_after_rotation() {
    let (_dir, runtime, account, fetcher, _relay) = runtime_inventory_fixture().await;
    let before = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].local_state, AccountKeyPackageLocalState::Current);
    assert_local_only_invariants(&before);
    let current_ref = before[0].record.key_package_ref_hex.clone();
    assert_eq!(fetcher.requests.lock().unwrap().len(), 0);

    runtime
        .rotate_key_package(&account.account_id_hex)
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let after = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    assert_eq!(after.len(), 2);
    assert_local_only_invariants(&after);
    let current = after
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
        .expect("rotated package is current");
    let retained = after
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial)
        .expect("superseded package stays retained");
    assert_ne!(current.record.key_package_ref_hex, current_ref);
    assert_eq!(retained.record.key_package_ref_hex, current_ref);
    assert!(retained.record.key_package_event_id.is_empty());
    assert_eq!(fetcher.requests.lock().unwrap().len(), 0);
    runtime.shutdown().await;
}

#[tokio::test]
async fn local_inventory_reports_signed_pending_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let fetcher = Arc::new(MemberResolutionDirectoryFetcher::default());
    let relay = Arc::new(ScriptedPushRelayClient::default());
    relay.block_next_publish();
    let mut app =
        MarmotApp::with_relay(directory.path(), DIRECTORY).with_test_relay_client(relay.clone());
    app.relay_plane = MarmotRelayPlane::new_with_directory_fetcher_for_test(
        Some(Duration::from_secs(120)),
        relay.clone(),
        fetcher.clone(),
        false,
    );
    let runtime = MarmotAppRuntime::new(app);
    runtime.start().await.unwrap();
    let create_runtime = runtime.clone();
    let mut create = tokio::spawn(async move {
        create_runtime
            .create_identity_local_ready(AccountSetupRequest {
                default_relays: vec![endpoint(DIRECTORY)],
                bootstrap_relays: vec![endpoint(DIRECTORY)],
                publish_initial_key_package: true,
                ..AccountSetupRequest::default()
            })
            .await
    });
    relay.wait_for_blocked_publish().await;
    let created = tokio::time::timeout(Duration::from_secs(5), &mut create)
        .await
        .expect("local ready must not wait for publication")
        .unwrap()
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let local = runtime
        .local_account_key_packages(&created.account.account_id_hex)
        .unwrap();
    assert_eq!(local.len(), 1);
    assert_eq!(
        local[0].local_state,
        AccountKeyPackageLocalState::PendingReplacement
    );
    assert!(local[0].record.local);
    assert!(!local[0].record.relay);
    assert!(!local[0].record.key_package_event_id.is_empty());
    assert_eq!(fetcher.requests.lock().unwrap().len(), 0);
    relay.release_publish();
    runtime.shutdown().await;
}

#[tokio::test]
async fn cache_metadata_without_owned_bundle_is_not_local() {
    let (_dir, app, account, fetcher, _relay) = inventory_fixture().await;
    write_key_package_cache(&app, &account, SLOT, "cache-only-ref", "event-cache");
    let runtime = MarmotAppRuntime::new(app);
    let listing = runtime.local_account_key_packages(&account.label).unwrap();
    assert!(listing.is_empty());
    assert_eq!(fetcher.requests.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn refresh_merges_current_echo_and_keeps_retained_local_only() {
    let (_dir, runtime, account, fetcher, relay) = runtime_inventory_fixture().await;
    runtime
        .rotate_key_package(&account.account_id_hex)
        .await
        .unwrap();
    let local = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    let current = local
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
        .expect("current");
    let current_pkg = runtime
        .key_package_maintenance_status(&account.account_id_hex)
        .await
        .unwrap()
        .and_then(|lifecycle| lifecycle.current_key_package)
        .expect("owned current package");
    assert_eq!(
        key_package_metadata(&current_pkg)
            .unwrap()
            .key_package_ref_hex,
        current.record.key_package_ref_hex
    );
    let echo = published_key_package_events(&relay)
        .into_iter()
        .find(|event| event.id == current.record.key_package_event_id)
        .expect("rotated current event was published");
    seed_fetcher(&fetcher, &account, vec![echo.clone()], &[DIRECTORY]);

    let refreshed = runtime
        .refresh_account_key_packages(&account.account_id_hex, vec![endpoint(DIRECTORY)])
        .await
        .unwrap();
    let current_row = refreshed
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
        .expect("one current");
    assert!(current_row.record.local && current_row.record.relay);
    assert_eq!(current_row.record.key_package_event_id, echo.id);
    let retained = refreshed
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial)
        .expect("retained remains");
    assert!(retained.record.local);
    assert!(!retained.record.relay);
    runtime.shutdown().await;
}

#[tokio::test]
async fn failed_refresh_does_not_mutate_or_delete_local_inventory() {
    let (_dir, runtime, account, fetcher, _relay) = runtime_inventory_fixture().await;
    let before = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    fetcher.fail_all_fetches();
    let error = runtime
        .refresh_account_key_packages(&account.account_id_hex, vec![endpoint(DIRECTORY)])
        .await
        .expect_err("refresh must surface the fetch failure");
    assert!(
        matches!(error, crate::AppError::RelayDirectory(_)),
        "unexpected refresh error: {error:?}"
    );
    let after = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    assert_eq!(before, after);
    runtime.shutdown().await;
}

#[tokio::test]
async fn empty_bootstrap_refresh_still_queries_the_network() {
    let (_dir, runtime, account, fetcher, _relay) = runtime_inventory_fixture().await;
    seed_fetcher(&fetcher, &account, Vec::new(), &[DIRECTORY]);
    fetcher.requests.lock().unwrap().clear();
    let _ = runtime
        .refresh_account_key_packages(&account.account_id_hex, Vec::new())
        .await;
    assert!(
        !fetcher.requests.lock().unwrap().is_empty(),
        "empty bootstrap must not turn refresh into an offline API"
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn concurrent_refresh_uses_post_rotation_local_snapshot() {
    let (_dir, runtime, account, fetcher, relay) = runtime_inventory_fixture().await;
    let before = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    let original_ref = before[0].record.key_package_ref_hex.clone();
    let original_event = published_key_package_events(&relay)
        .into_iter()
        .find(|event| event.id == before[0].record.key_package_event_id)
        .expect("initial current event was published");
    seed_fetcher(&fetcher, &account, vec![original_event], &[DIRECTORY]);
    runtime.catch_up_accounts().await.unwrap();
    let (entered, release) = fetcher.hold_fetches();
    let account_id = account.account_id_hex.clone();
    let (refreshed, ()) = tokio::join!(
        runtime.refresh_account_key_packages(&account_id, vec![endpoint(DIRECTORY)]),
        async {
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .expect("refresh must reach the held directory fetch");
            runtime.rotate_key_package(&account_id).await.unwrap();
            release.notify_one();
        }
    );
    let refreshed = refreshed.unwrap();
    let current = refreshed
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::Current)
        .expect("post-rotation current");
    assert_ne!(current.record.key_package_ref_hex, original_ref);
    let retained = refreshed
        .iter()
        .find(|entry| entry.local_state == AccountKeyPackageLocalState::RetainedPrivateMaterial)
        .expect("pre-rotation package is retained");
    assert_eq!(retained.record.key_package_ref_hex, original_ref);
    runtime.shutdown().await;
}

#[tokio::test]
async fn legacy_inventory_uses_post_rotation_snapshot_and_matches_typed_records() {
    let (_dir, runtime, account, fetcher, relay) = runtime_inventory_fixture().await;
    let before = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    let original_ref = before[0].record.key_package_ref_hex.clone();
    seed_fetcher(
        &fetcher,
        &account,
        published_key_package_events(&relay),
        &[DIRECTORY],
    );
    runtime.catch_up_accounts().await.unwrap();
    let (entered, release) = fetcher.hold_fetches();
    let (legacy, ()) = tokio::join!(
        runtime.account_key_packages(&account.account_id_hex, vec![endpoint(DIRECTORY)]),
        async {
            tokio::time::timeout(Duration::from_secs(2), entered.notified())
                .await
                .expect("legacy inventory must reach the held fetch");
            runtime
                .rotate_key_package(&account.account_id_hex)
                .await
                .unwrap();
            release.notify_one();
        }
    );
    let legacy = legacy.unwrap();
    let local = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    let current = current_ref(&local).unwrap();
    assert_ne!(current, original_ref);
    assert!(
        legacy
            .iter()
            .any(|record| record.key_package_ref_hex == current && record.local)
    );
    let typed = runtime
        .refresh_account_key_packages(&account.account_id_hex, vec![endpoint(DIRECTORY)])
        .await
        .unwrap();
    assert_eq!(
        legacy,
        typed
            .into_iter()
            .map(|entry| entry.record)
            .collect::<Vec<_>>()
    );
    runtime.shutdown().await;
}

async fn rotate_while_inventory_snapshot_is_held(
    runtime: &MarmotAppRuntime,
    account_id: &str,
    seam: &InventorySeamHandshake,
) {
    let started = Arc::new(tokio::sync::Notify::new());
    let mut rotate = tokio::spawn({
        let runtime = runtime.clone();
        let account_id = account_id.to_owned();
        let started = started.clone();
        async move {
            started.notify_one();
            runtime.rotate_key_package(&account_id).await
        }
    });
    started.notified().await;
    // The writer must remain blocked until ownership and lifecycle have both
    // been read. Removing the real snapshot wrapper makes this assertion fail.
    let blocked = tokio::time::timeout(Duration::from_secs(2), &mut rotate).await;
    seam.release_read();
    assert!(
        blocked.is_err(),
        "rotation crossed the held inventory snapshot"
    );
    tokio::time::timeout(Duration::from_secs(5), rotate)
        .await
        .expect("rotation after the snapshot must finish")
        .unwrap()
        .unwrap();
}

async fn interleave_local_at_inventory_seam(
    runtime: &MarmotAppRuntime,
    account_id: &str,
) -> Vec<crate::AccountKeyPackageInventoryEntry> {
    let seam = inventory_seam_handshake();
    runtime.set_inventory_snapshot_between_reads_for_test(Some(seam.hook.clone()));
    let local_account = account_id.to_owned();
    let local_runtime = runtime.clone();
    let local_read = tokio::task::spawn_blocking(move || {
        local_runtime.local_account_key_packages(&local_account)
    });
    tokio::time::timeout(Duration::from_secs(2), seam.entered.notified())
        .await
        .expect("local snapshot must reach the ownership/lifecycle seam");
    rotate_while_inventory_snapshot_is_held(runtime, account_id, &seam).await;
    let local = tokio::time::timeout(Duration::from_secs(5), local_read)
        .await
        .expect("local snapshot must finish")
        .unwrap()
        .unwrap();
    runtime.set_inventory_snapshot_between_reads_for_test(None);
    local
}

async fn interleave_refresh_at_inventory_seam(
    runtime: &MarmotAppRuntime,
    account_id: &str,
) -> Vec<crate::AccountKeyPackageInventoryEntry> {
    let seam = inventory_seam_handshake();
    runtime.set_inventory_snapshot_between_reads_for_test(Some(seam.hook.clone()));
    let refresh_account = account_id.to_owned();
    let refresh_runtime = runtime.clone();
    let refresh = tokio::spawn(async move {
        refresh_runtime
            .refresh_account_key_packages(&refresh_account, vec![endpoint(DIRECTORY)])
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), seam.entered.notified())
        .await
        .expect("refresh snapshot must reach the ownership/lifecycle seam");
    rotate_while_inventory_snapshot_is_held(runtime, account_id, &seam).await;
    let refreshed = tokio::time::timeout(Duration::from_secs(5), refresh)
        .await
        .expect("refresh snapshot must finish")
        .unwrap()
        .unwrap();
    runtime.set_inventory_snapshot_between_reads_for_test(None);
    refreshed
}

fn current_inventory_ref(runtime: &MarmotAppRuntime, account_id: &str) -> String {
    current_ref(&runtime.local_account_key_packages(account_id).unwrap())
        .expect("current after interleave")
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inventory_stays_coherent_when_rotation_interleaves_ownership_and_lifecycle() {
    let (_dir, runtime, account, fetcher, relay) = runtime_inventory_fixture().await;
    let before = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    let original_ref = before[0].record.key_package_ref_hex.clone();
    let owned_before = runtime
        .app_for_test()
        .capture_durably_owned_key_packages_for_test(&account.label)
        .unwrap();

    runtime
        .rotate_key_package(&account.account_id_hex)
        .await
        .unwrap();
    let lifecycle_after = runtime
        .app_for_test()
        .capture_key_package_lifecycle_for_test(&account.label)
        .unwrap();
    let mixed = runtime
        .app_for_test()
        .project_local_account_key_package_inventory_for_test(
            &account.label,
            owned_before,
            lifecycle_after,
        )
        .unwrap();
    assert!(
        is_mixed_retained_without_new_current(&mixed, &original_ref),
        "split ownership/lifecycle reads must be able to drop the new current package"
    );

    let local_after_split = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    assert_coherent_rotation_inventory(&local_after_split, &original_ref);
    assert_ne!(
        current_ref(&local_after_split).expect("snapshot current"),
        original_ref.as_str()
    );

    let snapshot_previous = current_inventory_ref(&runtime, &account.account_id_hex);
    seed_fetcher(
        &fetcher,
        &account,
        published_key_package_events(&relay),
        &[DIRECTORY],
    );
    let local = interleave_local_at_inventory_seam(&runtime, &account.account_id_hex).await;
    assert_coherent_rotation_inventory(&local, &snapshot_previous);
    let refresh_previous = current_inventory_ref(&runtime, &account.account_id_hex);
    seed_fetcher(
        &fetcher,
        &account,
        published_key_package_events(&relay),
        &[DIRECTORY],
    );
    let refreshed = interleave_refresh_at_inventory_seam(&runtime, &account.account_id_hex).await;
    assert_coherent_rotation_inventory(&refreshed, &refresh_previous);

    runtime.shutdown().await;
}

#[tokio::test]
async fn signed_out_and_unknown_account_local_reads() {
    let (_dir, runtime, account, fetcher, _relay) = runtime_inventory_fixture().await;
    runtime
        .sign_out(
            &account.account_id_hex,
            SignOutOptions {
                delete_key_packages: false,
            },
        )
        .await
        .unwrap();
    fetcher.requests.lock().unwrap().clear();
    let local = runtime
        .local_account_key_packages(&account.account_id_hex)
        .unwrap();
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].local_state, AccountKeyPackageLocalState::Current);
    assert_eq!(fetcher.requests.lock().unwrap().len(), 0);
    assert!(
        runtime
            .local_account_key_packages("missing-account")
            .is_err()
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn local_read_rejects_terminal_close_without_reopening() {
    let (_dir, runtime, account, _fetcher, _relay) = runtime_inventory_fixture().await;
    runtime.shutdown_and_close().await.unwrap();
    let error = runtime
        .local_account_key_packages(&account.account_id_hex)
        .expect_err("closed storage must stay closed");
    assert!(
        matches!(error, crate::AppError::Storage(_)),
        "unexpected close error: {error:?}"
    );
}
