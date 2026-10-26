//! Public event previews over a real `MarmotApp`: its runtime, relay plane and
//! per-account caches. The directory's own preview tests stay with previews.

use cgka_traits::TransportEndpoint;
use marmot_account::AccountHome;
use nostr::event::Event;
use nostr::nips::nip01::Coordinate;
use nostr::nips::nip19::{Nip19Coordinate, Nip19Event, ToBech32};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, RelayUrl, Tag, Timestamp};
use nostr_sdk::local_relay::MockRelay;
use nostr_sdk::prelude::Client;

use crate::{AppError, MarmotApp};
use nostr_directory::{
    EVENT_DELETION_QUERY_LIMIT, MAX_PUBLIC_EVENT_REFERENCES, PublicEventPreview,
    PublicEventPreviewRead,
};

fn signed(keys: &Keys, kind: u16, created_at: u64, content: &str, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::from(kind), content)
        .tags(tags)
        .custom_created_at(Timestamp::from_secs(created_at))
        .finalize(keys)
        .unwrap()
}

fn tag(values: &[&str]) -> Tag {
    Tag::parse(values.iter().copied()).unwrap()
}

fn coordinate(keys: &Keys, kind: u16, identifier: &str) -> Coordinate {
    Coordinate::new(Kind::from(kind), keys.public_key()).identifier(identifier)
}

fn naddr(coordinate: &Coordinate) -> String {
    Nip19Coordinate::new(coordinate.clone(), std::iter::empty::<RelayUrl>())
        .to_bech32()
        .unwrap()
}

async fn publish(relay: &MockRelay, events: &[&Event]) {
    let client = Client::default();
    let url = relay.url().await;
    client.add_relay(url.clone()).await.unwrap();
    client.connect_relay(url).await.unwrap();
    for event in events {
        client.send_event(event).await.unwrap();
    }
    client.shutdown().await;
}

fn present_json(read: &PublicEventPreviewRead) -> Event {
    match &read.preview {
        PublicEventPreview::Present { event_json, .. } => Event::from_json(event_json).unwrap(),
        other => panic!("expected a present preview, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_event_preview_cache_round_trips_across_runtime_restart() {
    let relay = MockRelay::run().await.unwrap();
    let keys = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let note = signed(&keys, 1, base, "note", Vec::new());
    let d = || vec![tag(&["d", "entry"])];
    let older = signed(&keys, 30023, base + 1, "first", d());
    let newer = signed(&keys, 30023, base + 2, "second", d());
    let regretted = signed(&keys, 1, base + 3, "regretted", Vec::new());
    let deletion = signed(
        &keys,
        5,
        base + 4,
        "",
        vec![tag(&["e", &regretted.id.to_hex()])],
    );
    publish(&relay, &[&note, &older, &newer, &deletion]).await;
    // A hint relay that never processed the deletion still serves the note.
    let stale = MockRelay::run().await.unwrap();
    publish(&stale, &[&regretted]).await;

    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    home.create_account("alice").unwrap();
    home.create_account("bob").unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![relay.url().await.to_string()]);
    let runtime = app.runtime();

    let note_ref = note.id.to_bech32().unwrap();
    let article_ref = naddr(&coordinate(&keys, 30023, "entry"));
    // The link names the wrong author; the real author's deletion still counts.
    let regretted_ref = Nip19Event::new(regretted.id)
        .author(Keys::generate().public_key())
        .relays([stale.url().await])
        .to_bech32()
        .unwrap();
    let missing_ref = "ab".repeat(32);
    assert_eq!(
        runtime
            .cached_public_event_previews("alice", std::slice::from_ref(&note_ref))
            .unwrap()[0]
            .preview,
        PublicEventPreview::Missing
    );
    let resolved = runtime
        .resolve_public_event_preview("alice", &note_ref)
        .await
        .unwrap();
    assert_eq!(resolved.reference, note_ref);
    assert_eq!(present_json(&resolved), note);
    let resolved = runtime
        .resolve_public_event_preview("alice", &article_ref)
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), newer);
    let resolved = runtime
        .resolve_public_event_preview("alice", &regretted_ref)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Deleted);
    let resolved = runtime
        .resolve_public_event_preview("alice", "not a reference")
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Unsupported);

    // Each account has its own cache.
    assert_eq!(
        runtime
            .cached_public_event_previews("bob", std::slice::from_ref(&note_ref))
            .unwrap()[0]
            .preview,
        PublicEventPreview::Missing
    );
    let batch = vec![
        note_ref.clone(),
        article_ref.clone(),
        regretted_ref.clone(),
        note.id.to_hex(),
        missing_ref.clone(),
        "garbage".to_owned(),
    ];
    let states = |reads: &[PublicEventPreviewRead]| {
        reads
            .iter()
            .map(|read| match read.preview {
                PublicEventPreview::Present { .. } => "present",
                PublicEventPreview::Deleted => "deleted",
                PublicEventPreview::Missing => "missing",
                PublicEventPreview::Unsupported => "unsupported",
            })
            .collect::<Vec<_>>()
    };
    let before = runtime
        .cached_public_event_previews("alice", &batch)
        .unwrap();
    let expected = [
        "present",
        "present",
        "deleted",
        "present",
        "missing",
        "unsupported",
    ];
    assert_eq!(states(&before), expected);
    assert_eq!(
        before
            .iter()
            .map(|read| read.reference.as_str())
            .collect::<Vec<_>>(),
        batch.iter().map(String::as_str).collect::<Vec<_>>()
    );
    runtime.shutdown_and_close().await.unwrap();
    relay.shutdown();
    stale.shutdown();

    // Offline restart: cached reads never wait on the network.
    let app = MarmotApp::with_relay(dir.path(), "ws://127.0.0.1:1");
    let runtime = app.runtime();
    let after = runtime
        .cached_public_event_previews("alice", &batch)
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(present_json(&after[1]), newer);
    // A cached event-ID preview resolves locally without a relay.
    let resolved = runtime
        .resolve_public_event_preview("alice", &note_ref)
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), note);
    // A failed fetch is not stored as a miss, and keeps nothing.
    let resolved = runtime
        .resolve_public_event_preview("alice", &missing_ref)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Missing);
    runtime.shutdown_and_close().await.unwrap();
}

/// Deletions the first query cannot attribute are fetched from the verified
/// author: crowded event-ID answers, an article linked by ID, and an `naddr`
/// version deleted by ID on another relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletion_follow_ups_reach_the_verified_author() {
    let relay = MockRelay::run().await.unwrap();
    let stale = MockRelay::run().await.unwrap();
    let keys = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let d = || vec![tag(&["d", "entry"])];

    // Sixteen newer third-party requests fill the unattributed answer.
    let note = signed(&keys, 1, base, "note", Vec::new());
    let e = || vec![tag(&["e", &note.id.to_hex()])];
    let real = signed(&keys, 5, base + 1, "", e());
    let spam = (0..EVENT_DELETION_QUERY_LIMIT)
        .map(|index| signed(&Keys::generate(), 5, base + 10 + index as u64, "", e()))
        .collect::<Vec<_>>();
    // An article linked by ID, deleted only by coordinate.
    let article = signed(&keys, 30023, base, "article", vec![tag(&["d", "other"])]);
    let a_deletion = signed(
        &keys,
        5,
        base + 1,
        "",
        vec![tag(&["a", &coordinate(&keys, 30023, "other").to_string()])],
    );
    // An `naddr` whose newest version was deleted by ID.
    let v1 = signed(&keys, 30023, base, "v1", d());
    let v2 = signed(&keys, 30023, base + 1, "v2", d());
    let v2_deletion = signed(&keys, 5, base + 2, "", vec![tag(&["e", &v2.id.to_hex()])]);

    let mut on_relay = vec![&real, &a_deletion, &v1, &v2_deletion];
    on_relay.extend(spam.iter());
    publish(&relay, &on_relay).await;
    publish(&stale, &[&note, &article, &v2]).await;

    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec![relay.url().await.to_string()]);
    let runtime = app.runtime();
    let hint = stale.url().await;
    let nevent = |id| {
        Nip19Event::new(id)
            .relays([hint.clone()])
            .to_bech32()
            .unwrap()
    };
    let naddr_ref = Nip19Coordinate::new(coordinate(&keys, 30023, "entry"), [hint.clone()])
        .to_bech32()
        .unwrap();

    for reference in [nevent(note.id), nevent(article.id)] {
        let resolved = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert_eq!(resolved.preview, PublicEventPreview::Deleted);
    }
    let resolved = runtime
        .resolve_public_event_preview("alice", &naddr_ref)
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), v1);
    runtime.shutdown_and_close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cached_reads_reject_oversized_batches() {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    let app = MarmotApp::with_relay(dir.path(), "ws://127.0.0.1:1");
    let runtime = app.runtime();
    let references = vec!["ab".repeat(32); MAX_PUBLIC_EVENT_REFERENCES + 1];
    assert!(matches!(
        runtime.cached_public_event_previews("alice", &references),
        Err(AppError::InvalidPublicEventReferences(_))
    ));
    let references = vec!["garbage".to_owned(); MAX_PUBLIC_EVENT_REFERENCES];
    assert!(
        runtime
            .cached_public_event_previews("alice", &references)
            .unwrap()
            .iter()
            .all(|read| read.preview == PublicEventPreview::Unsupported)
    );
    runtime.shutdown_and_close().await.unwrap();
}

#[test]
fn relay_hints_pass_the_discovered_endpoint_safety_rule() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".to_owned()],
        crate::MarmotAppConfig::white_noise().with_open_ranking_provider(None, Vec::new()),
    );
    let hints = [
        "ws://127.0.0.1:7777",
        "wss://10.0.0.1",
        "ws://plaintext.example",
        "wss://hint.example",
        "wss://relay.example",
        "wss://third.example",
    ]
    .map(|url| TransportEndpoint(url.to_owned()))
    .to_vec();
    assert_eq!(
        app.directory().public_event_query_relays_for_test(hints),
        ["wss://hint.example", "wss://relay.example"]
            .map(|url| TransportEndpoint(RelayUrl::parse(url).unwrap().to_string()))
    );
}

/// `MarmotApp::directory()` builds a new service per call, so the cooldowns
/// must live in the app's shared state rather than in the service.
#[test]
fn refresh_cooldowns_outlive_the_service_that_started_them() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays(dir.path(), vec!["wss://relay.example".to_owned()]);
    let key = "alice\nnote".to_owned();
    assert!(
        !app.directory()
            .public_event_refresh_cooling_down_for_test(&key)
    );
    app.directory()
        .start_public_event_refresh_cooldown_for_test(key.clone());
    assert!(
        app.directory()
            .public_event_refresh_cooling_down_for_test(&key)
    );
    assert!(
        app.clone()
            .directory()
            .public_event_refresh_cooling_down_for_test(&key)
    );
}
