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

use crate::{AppError, MarmotApp, MarmotAppConfig, MarmotDeployment};
use nostr_directory::{
    AccountRelayListStatus, EVENT_DELETION_QUERY_LIMIT, MAX_PUBLIC_EVENT_REFERENCES,
    PublicEventPreview, PublicEventPreviewRead,
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

/// A loopback test app with White Noise's deployment, except that its
/// discovery indexers are `indexers`: these tests must never dial the real
/// public indexers `MarmotApp::with_relays` carries.
fn app_with_indexers(
    root: &std::path::Path,
    relays: Vec<String>,
    indexers: Vec<String>,
) -> MarmotApp {
    let deployment = MarmotDeployment {
        discovery_indexer_relays: indexers,
        ..MarmotDeployment::white_noise()
    };
    MarmotApp::with_relays_and_config(
        root,
        relays,
        MarmotAppConfig::white_noise()
            .with_deployment(deployment)
            .with_allow_loopback_relay_endpoints(true)
            .with_open_ranking_provider(None, Vec::new()),
    )
}

/// A temporary home with account `alice`.
fn alice_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    AccountHome::open(dir.path())
        .create_account("alice")
        .unwrap();
    dir
}

async fn url(relay: &MockRelay) -> String {
    relay.url().await.to_string()
}

/// A NIP-65 relay list whose only relay is `write`, marked write-only.
fn relay_list(keys: &Keys, created_at: u64, write: &str) -> Event {
    signed(
        keys,
        10002,
        created_at,
        "",
        vec![tag(&["r", write, "write"])],
    )
}

fn nevent_by(id: nostr::prelude::EventId, author: &Keys) -> String {
    Nip19Event::new(id)
        .author(author.public_key())
        .to_bech32()
        .unwrap()
}

/// Nothing is stored for `reference`.
fn assert_uncached(runtime: &crate::MarmotAppRuntime, reference: &str) {
    assert_eq!(
        runtime
            .cached_public_event_previews("alice", &[reference.to_owned()])
            .unwrap()[0]
            .preview,
        PublicEventPreview::Missing
    );
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
    let app = app_with_indexers(dir.path(), vec![relay.url().await.to_string()], Vec::new());
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
    let app = app_with_indexers(dir.path(), vec!["ws://127.0.0.1:1".to_owned()], Vec::new());
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
    let app = app_with_indexers(dir.path(), vec![relay.url().await.to_string()], Vec::new());
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

/// Hint-less references the operational relays miss resolve from the
/// deployment's discovery indexers, after the operational relays: a hit there,
/// or on a hint relay, sends no supplementary query, so a deletion only the
/// indexer holds is never read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hintless_references_resolve_from_discovery_indexers() {
    let operational = MockRelay::run().await.unwrap();
    let hint = MockRelay::run().await.unwrap();
    let indexer = MockRelay::run().await.unwrap();
    let keys = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let by_note1 = signed(&keys, 1, base, "only on the indexer", Vec::new());
    let by_hex = signed(&keys, 1, base + 1, "also only on the indexer", Vec::new());
    let on_operational = signed(&keys, 1, base + 2, "operational", Vec::new());
    let on_hint = signed(&keys, 1, base + 3, "hinted", Vec::new());
    let deletes = |event: &Event| {
        signed(
            &keys,
            5,
            base + 10,
            "",
            vec![tag(&["e", &event.id.to_hex()])],
        )
    };
    let (late_operational, late_hint) = (deletes(&on_operational), deletes(&on_hint));
    publish(&operational, &[&on_operational]).await;
    publish(&hint, &[&on_hint]).await;
    publish(
        &indexer,
        &[
            &by_note1,
            &by_hex,
            &on_operational,
            &on_hint,
            &late_operational,
            &late_hint,
        ],
    )
    .await;

    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![url(&indexer).await],
    );
    let runtime = app.runtime();
    for (reference, expected) in [
        (by_note1.id.to_bech32().unwrap(), &by_note1),
        (by_hex.id.to_hex(), &by_hex),
        (on_operational.id.to_bech32().unwrap(), &on_operational),
        (
            Nip19Event::new(on_hint.id)
                .relays([hint.url().await])
                .to_bech32()
                .unwrap(),
            &on_hint,
        ),
    ] {
        let resolved = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert_eq!(&present_json(&resolved), expected, "{reference}");
    }
    runtime.shutdown_and_close().await.unwrap();
}

/// `nevent` authors and `naddr` coordinates route the supplementary query to
/// the author's NIP-65 write relays, read from the indexers or the directory
/// cache. A claimed author only routes: it never admits another event, and
/// its own deletions do not count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authors_route_lookups_to_their_write_relays() {
    let operational = MockRelay::run().await.unwrap();
    let indexer = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let cached_relay = MockRelay::run().await.unwrap();
    let forger_relay = MockRelay::run().await.unwrap();
    let (author, cached_author, forger) = (Keys::generate(), Keys::generate(), Keys::generate());
    let base = Timestamp::now().as_secs() - 1_000;

    let note = signed(&author, 1, base, "note", Vec::new());
    let article = signed(&author, 30023, base, "article", vec![tag(&["d", "entry"])]);
    let cached_note = signed(&cached_author, 1, base, "cached route", Vec::new());
    // The forger names itself as author of someone else's note, serves the
    // real note with its own deletion of it, and its own unrelated note.
    let borrowed = signed(&author, 1, base + 1, "borrowed", Vec::new());
    let forged_deletion = signed(
        &forger,
        5,
        base + 2,
        "",
        vec![tag(&["e", &borrowed.id.to_hex()])],
    );
    let forger_note = signed(&forger, 1, base + 3, "forger", Vec::new());
    publish(
        &indexer,
        &[
            &relay_list(&author, base, &url(&author_relay).await),
            &relay_list(&forger, base, &url(&forger_relay).await),
        ],
    )
    .await;
    publish(&author_relay, &[&note, &article]).await;
    publish(&cached_relay, &[&cached_note]).await;
    publish(&forger_relay, &[&borrowed, &forged_deletion, &forger_note]).await;

    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![url(&indexer).await],
    );
    // A cached relay list is used without asking the indexers, which do not
    // hold this author's list.
    let mut cached = AccountRelayListStatus::empty();
    cached.nip65.created_at = base;
    cached.nip65.write_relays = vec![url(&cached_relay).await];
    cached.nip65.relays = cached.nip65.write_relays.clone();
    cached.refresh();
    app.directory()
        .remember_directory_relay_lists(&cached_author.public_key().to_hex(), &cached)
        .unwrap();
    let runtime = app.runtime();

    let resolve = |reference: String| {
        let runtime = runtime.clone();
        async move {
            runtime
                .resolve_public_event_preview("alice", &reference)
                .await
                .unwrap()
        }
    };
    assert_eq!(
        present_json(&resolve(nevent_by(note.id, &author)).await),
        note
    );
    assert_eq!(
        present_json(&resolve(naddr(&coordinate(&author, 30023, "entry"))).await),
        article
    );
    assert_eq!(
        present_json(&resolve(nevent_by(cached_note.id, &cached_author)).await),
        cached_note
    );
    assert_eq!(
        present_json(&resolve(nevent_by(borrowed.id, &forger)).await),
        borrowed
    );
    let absent = signed(&author, 1, base + 4, "never published", Vec::new());
    let reference = nevent_by(absent.id, &forger);
    assert_eq!(
        resolve(reference.clone()).await.preview,
        PublicEventPreview::Missing
    );
    assert_uncached(&runtime, &reference);
    runtime.shutdown_and_close().await.unwrap();
}

/// An uncached author's relay list is read from the discovery indexers only,
/// never the directory or operational relays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uncached_author_relay_lists_come_only_from_indexers() {
    let operational = MockRelay::run().await.unwrap();
    let indexer = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let author = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let note = signed(&author, 1, base, "note", Vec::new());
    publish(
        &operational,
        &[&relay_list(&author, base, &url(&author_relay).await)],
    )
    .await;
    publish(&author_relay, &[&note]).await;

    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![url(&indexer).await],
    );
    let runtime = app.runtime();
    let reference = nevent_by(note.id, &author);
    let resolved = runtime
        .resolve_public_event_preview("alice", &reference)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Missing);
    assert_uncached(&runtime, &reference);
    runtime.shutdown_and_close().await.unwrap();
}

/// A supplementary query that cannot finish confirms nothing and stores no
/// miss. An author relay list read that does not finish skips the author
/// route, still asks the indexers, and records no relay list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unfinished_supplementary_reads_leave_references_retryable() {
    let unreachable = "ws://127.0.0.1:1".to_owned();
    let operational = MockRelay::run().await.unwrap();
    let indexer = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let author = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let on_indexer = signed(&author, 1, base, "on the indexer", Vec::new());
    let on_author_relay = signed(&author, 1, base + 1, "on the write relay", Vec::new());
    publish(
        &indexer,
        &[
            &relay_list(&author, base, &url(&author_relay).await),
            &on_indexer,
        ],
    )
    .await;
    publish(&author_relay, &[&on_author_relay]).await;

    // Only an unreachable indexer: nothing resolves, nothing is stored.
    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![unreachable.clone()],
    );
    let runtime = app.runtime();
    let reference = on_indexer.id.to_hex();
    let resolved = runtime
        .resolve_public_event_preview("alice", &reference)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Missing);
    assert_uncached(&runtime, &reference);
    runtime.shutdown_and_close().await.unwrap();

    // One indexer unreachable: the relay list read is partial, so the write
    // relay is never asked, but the reachable indexer still answers.
    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![unreachable, url(&indexer).await],
    );
    let runtime = app.runtime();
    let resolved = runtime
        .resolve_public_event_preview("alice", &nevent_by(on_indexer.id, &author))
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), on_indexer);
    let reference = nevent_by(on_author_relay.id, &author);
    let resolved = runtime
        .resolve_public_event_preview("alice", &reference)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Missing);
    assert_uncached(&runtime, &reference);
    let recorded = app
        .directory()
        .directory_entry_for_test(&author.public_key().to_hex())
        .unwrap();
    assert!(
        recorded.is_none_or(|entry| entry.relay_lists.nip65.created_at == 0),
        "a partial read must not record the author's relay list"
    );
    runtime.shutdown_and_close().await.unwrap();
}

/// A deletion on any queried relay suppresses the preview: the operational
/// relays, an indexer or an author's write relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deletions_count_across_every_queried_relay() {
    let operational = MockRelay::run().await.unwrap();
    let indexer = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let author = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let deletes = |event: &Event| {
        signed(
            &author,
            5,
            base + 10,
            "",
            vec![tag(&["e", &event.id.to_hex()])],
        )
    };
    let deleted_on_operational = signed(&author, 1, base, "one", Vec::new());
    let deleted_on_author_relay = signed(&author, 1, base + 1, "two", Vec::new());
    publish(&operational, &[&deletes(&deleted_on_operational)]).await;
    publish(
        &indexer,
        &[
            &relay_list(&author, base, &url(&author_relay).await),
            &deleted_on_operational,
            &deleted_on_author_relay,
        ],
    )
    .await;
    publish(&author_relay, &[&deletes(&deleted_on_author_relay)]).await;

    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![url(&indexer).await],
    );
    let runtime = app.runtime();
    for reference in [
        deleted_on_operational.id.to_hex(),
        nevent_by(deleted_on_author_relay.id, &author),
    ] {
        let resolved = runtime
            .resolve_public_event_preview("alice", &reference)
            .await
            .unwrap();
        assert_eq!(resolved.preview, PublicEventPreview::Deleted, "{reference}");
    }
    runtime.shutdown_and_close().await.unwrap();
}

/// The supplementary query asks every discovery indexer first, then author
/// write relays in the room left: at most four of them and eight in all,
/// never an unsafe, duplicate or already-queried endpoint.
#[test]
fn supplementary_relays_put_indexers_first_within_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec!["wss://relay.example".to_owned()],
        MarmotAppConfig::white_noise().with_open_ranking_provider(None, Vec::new()),
    );
    let endpoints = |urls: &[&str]| {
        urls.iter()
            .map(|url| TransportEndpoint((*url).to_owned()))
            .collect::<Vec<_>>()
    };
    let canonical = |urls: &[&str]| {
        urls.iter()
            .map(|url| TransportEndpoint(RelayUrl::parse(url).unwrap().to_string()))
            .collect::<Vec<_>>()
    };
    let directory = app.directory();
    let queried = directory.public_event_query_relays_for_test(endpoints(&["wss://hint.example"]));
    let plan = |indexers: &[&str], authors: &[&str]| {
        directory.public_event_supplementary_relays_for_test(
            &queried,
            &endpoints(indexers),
            endpoints(authors),
        )
    };

    assert_eq!(
        plan(
            &[
                "wss://index1.example",
                "wss://relay.example",
                "ws://127.0.0.1:7777",
                "wss://index2.example",
                "wss://index1.example",
            ],
            &[
                "wss://index2.example",
                "wss://hint.example",
                "wss://10.0.0.1",
                "wss://write1.example",
                "wss://write2.example",
                "wss://write3.example",
                "wss://write4.example",
                "wss://write5.example",
            ],
        ),
        canonical(&[
            "wss://index1.example",
            "wss://index2.example",
            "wss://write1.example",
            "wss://write2.example",
            "wss://write3.example",
            "wss://write4.example",
        ])
    );
    let indexers = [
        "wss://index1.example",
        "wss://index2.example",
        "wss://index3.example",
        "wss://index4.example",
        "wss://index5.example",
    ];
    let writes = [
        "wss://write1.example",
        "wss://write2.example",
        "wss://write3.example",
        "wss://write4.example",
    ];
    // White Noise's shape: five indexers leave room for three write relays.
    let mut expected = indexers.to_vec();
    expected.extend(&writes[..3]);
    assert_eq!(plan(&indexers, &writes), canonical(&expected));
    // A full write-relay list never displaces an indexer.
    let many = [
        indexers.as_slice(),
        &[
            "wss://index6.example",
            "wss://index7.example",
            "wss://index8.example",
            "wss://index9.example",
        ],
    ]
    .concat();
    assert_eq!(plan(&many, &writes), canonical(&many[..8]));
    // Neutral deployments pass no indexers: only author relays remain.
    assert_eq!(plan(&[], &writes), canonical(&writes));
    assert!(plan(&[], &[]).is_empty());
    // Relays are compared by identity, not spelling, before either cap: other
    // spellings of indexers or queried relays never take an author slot, so
    // the real write relay after them is still asked.
    assert_eq!(
        plan(
            &[
                "wss://index1.example",
                "wss://index2.example",
                "wss://index3.example",
                "wss://index4.example",
                "wss://index5.example",
                "wss://INDEX1.example:443/",
                "wss://relay.example/",
            ],
            &[
                "wss://index1.example/",
                "wss://Index2.Example",
                "wss://index3.example:443",
                "wss://hint.example/",
                "wss://write1.example",
            ],
        ),
        canonical(&[
            "wss://index1.example",
            "wss://index2.example",
            "wss://index3.example",
            "wss://index4.example",
            "wss://index5.example",
            "wss://write1.example",
        ])
    );
}

/// White Noise passes five indexers, which may each hold a different signed
/// version of an author's relay list. Every reply fits the read, so the author
/// route survives and the newest version picks the write relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_list_reads_hold_one_version_from_every_indexer() {
    let operational = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let mut indexers = Vec::new();
    for _ in 0..5 {
        indexers.push(MockRelay::run().await.unwrap());
    }
    let author = Keys::generate();
    let base = Timestamp::now().as_secs() - 1_000;
    let note = signed(&author, 1, base, "only on the write relay", Vec::new());
    publish(&author_relay, &[&note]).await;
    let newest = indexers.len() - 1;
    for (version, indexer) in indexers.iter().enumerate() {
        let write = if version == newest {
            url(&author_relay).await
        } else {
            format!("wss://old{version}.example")
        };
        publish(
            indexer,
            &[&relay_list(&author, base + version as u64, &write)],
        )
        .await;
    }

    let dir = alice_home();
    let mut indexer_urls = Vec::new();
    for indexer in &indexers {
        indexer_urls.push(url(indexer).await);
    }
    let app = app_with_indexers(dir.path(), vec![url(&operational).await], indexer_urls);
    let runtime = app.runtime();
    let resolved = runtime
        .resolve_public_event_preview("alice", &nevent_by(note.id, &author))
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), note);
    runtime.shutdown_and_close().await.unwrap();
}

/// A neutral deployment configures no indexers, so a miss dials none: the
/// supplementary query gets only author relays, and here there are none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn neutral_deployments_never_dial_indexers() {
    let operational = MockRelay::run().await.unwrap();
    let dir = alice_home();
    let app = MarmotApp::with_relays_and_config(
        dir.path(),
        vec![url(&operational).await],
        MarmotAppConfig::default().with_allow_loopback_relay_endpoints(true),
    );
    assert!(app.discovery_indexer_relays().is_empty());
    let queried = app
        .directory()
        .public_event_query_relays_for_test(Vec::new());
    assert!(
        app.directory()
            .public_event_supplementary_relays_for_test(
                &queried,
                &app.discovery_indexer_relays(),
                Vec::new()
            )
            .is_empty()
    );
    let runtime = app.runtime();
    let reference = "ab".repeat(32);
    let resolved = runtime
        .resolve_public_event_preview("alice", &reference)
        .await
        .unwrap();
    assert_eq!(resolved.preview, PublicEventPreview::Missing);
    assert_uncached(&runtime, &reference);
    runtime.shutdown_and_close().await.unwrap();
}

/// A relay-list version dated past the allowed clock skew is not current: it
/// never outranks the current version, as everywhere else in the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn future_dated_relay_lists_never_pick_the_write_relays() {
    let operational = MockRelay::run().await.unwrap();
    let current = MockRelay::run().await.unwrap();
    let future = MockRelay::run().await.unwrap();
    let author_relay = MockRelay::run().await.unwrap();
    let author = Keys::generate();
    let now = Timestamp::now().as_secs();
    let note = signed(
        &author,
        1,
        now - 1_000,
        "only on the write relay",
        Vec::new(),
    );
    publish(&author_relay, &[&note]).await;
    publish(
        &current,
        &[&relay_list(&author, now - 500, &url(&author_relay).await)],
    )
    .await;
    publish(
        &future,
        &[&relay_list(
            &author,
            now + 86_400,
            "wss://elsewhere.example",
        )],
    )
    .await;

    let dir = alice_home();
    let app = app_with_indexers(
        dir.path(),
        vec![url(&operational).await],
        vec![url(&current).await, url(&future).await],
    );
    let runtime = app.runtime();
    let resolved = runtime
        .resolve_public_event_preview("alice", &nevent_by(note.id, &author))
        .await
        .unwrap();
    assert_eq!(present_json(&resolved), note);
    runtime.shutdown_and_close().await.unwrap();
}
