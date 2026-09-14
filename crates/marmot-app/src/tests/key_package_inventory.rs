use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
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
use crate::{KeyPackageDeletionTarget, MarmotApp, MarmotAppRuntime, MarmotRelayPlane};

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
