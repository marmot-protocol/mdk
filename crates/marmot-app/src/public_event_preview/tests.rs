use marmot_account::AccountHome;
use nostr::nips::nip19::{Nip19Coordinate, Nip19Event, ToBech32};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp};
use nostr_sdk::local_relay::MockRelay;
use nostr_sdk::prelude::Client;

use super::*;

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

fn shown(event: &Event, deleted_through: Option<u64>) -> Option<Row> {
    Some(Row {
        event: Some(Box::new(event.clone())),
        deleted_through,
    })
}

fn deleted(through: u64) -> Option<Row> {
    Some(Row {
        event: None,
        deleted_through: Some(through),
    })
}

#[test]
fn references_parse_to_canonical_targets() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "hi", Vec::new());
    let id = note.id;
    let relay = RelayUrl::parse("wss://hint.example").unwrap();
    let nevent = Nip19Event::new(id)
        .author(keys.public_key())
        .relays([relay.clone()])
        .to_bech32()
        .unwrap();

    for raw in [
        id.to_hex(),
        id.to_hex().to_uppercase(),
        id.to_bech32().unwrap(),
        format!("nostr:{}", id.to_bech32().unwrap()),
        nevent.clone(),
    ] {
        let parsed = parse_reference(&raw).unwrap();
        assert_eq!(parsed.target, Target::EventId(id), "{raw}");
        assert_eq!(parsed.target.cache_key(), format!("event:{}", id.to_hex()));
    }
    let parsed = parse_reference(&nevent).unwrap();
    assert_eq!(
        parsed.relay_hints,
        vec![TransportEndpoint(relay.to_string())]
    );

    let article = coordinate(&keys, 30023, "entry");
    let parsed = parse_reference(&naddr(&article)).unwrap();
    assert_eq!(parsed.target, Target::Coordinate(article.clone()));
    assert_eq!(
        parsed.target.cache_key(),
        format!("coordinate:30023:{}:entry", keys.public_key().to_hex())
    );
    assert!(parse_reference(&naddr(&coordinate(&keys, 0, ""))).is_some());
    assert!(parse_reference(&naddr(&coordinate(&keys, 10002, ""))).is_some());

    for raw in [
        String::new(),
        "not a reference".to_owned(),
        keys.public_key().to_bech32().unwrap(),
        // Kind 41 is not replaceable by coordinate, and a kind-1 naddr has no
        // single current version.
        naddr(&coordinate(&keys, 41, "")),
        naddr(&coordinate(&keys, 1, "")),
        // A replaceable kind with a `d` identifier names no event.
        naddr(&coordinate(&keys, 0, "entry")),
        "a".repeat(MAX_REFERENCE_BYTES + 1),
    ] {
        assert!(parse_reference(&raw).is_none(), "{raw}");
    }
}

#[test]
fn event_id_admission_requires_exact_match_and_author_deletion() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let other = signed(&keys, 1, 11, "other", Vec::new());
    let target = Target::EventId(note.id);
    let e = tag(&["e", &note.id.to_hex()]);
    let deletion = signed(&keys, 5, 20, "", vec![e.clone()]);
    let forged = signed(&Keys::generate(), 5, 20, "", vec![e]);

    assert_eq!(admit(&target, None, &[]), None);
    assert_eq!(admit(&target, None, std::slice::from_ref(&other)), None);
    assert_eq!(
        admit(&target, None, &[other, note.clone()]),
        shown(&note, None)
    );
    assert_eq!(
        admit(&target, None, &[note.clone(), forged.clone()]),
        shown(&note, None),
        "a deletion by anyone but the author is ignored"
    );
    let cached = shown(&note, None).unwrap();
    assert_eq!(
        admit(&target, Some(&cached), std::slice::from_ref(&deletion)),
        deleted(20),
        "the cached event supplies the author when relays no longer serve it"
    );
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&deletion)),
        None,
        "an unattributable deletion stores nothing"
    );
    let marker = deleted(20).unwrap();
    assert_eq!(
        admit(&target, Some(&marker), &[note]),
        Some(marker),
        "a relay that kept the event cannot restore it"
    );
}

#[test]
fn full_unattributed_deletion_answers_trigger_an_author_query() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let e = || vec![tag(&["e", &note.id.to_hex()])];
    let spam = (0..EVENT_DELETION_QUERY_LIMIT)
        .map(|index| signed(&Keys::generate(), 5, 20 + index as u64, "", e()))
        .collect::<Vec<_>>();
    let mut fetched = spam.clone();
    fetched.push(note.clone());
    assert_eq!(
        crowded_deletion_author(&note.id, None, &fetched),
        Some(keys.public_key())
    );
    // The author already answered, the answer was not full, or the event is
    // unknown: no follow-up.
    let mut answered = fetched.clone();
    answered.push(signed(&keys, 5, 50, "", e()));
    assert_eq!(crowded_deletion_author(&note.id, None, &answered), None);
    assert_eq!(
        crowded_deletion_author(&note.id, None, &[note.clone(), spam[0].clone()]),
        None
    );
    assert_eq!(crowded_deletion_author(&note.id, None, &spam), None);
    assert_eq!(
        crowded_deletion_author(&note.id, Some(&note), &spam),
        Some(keys.public_key())
    );
}

#[test]
fn deletions_apply_in_either_tag_form() {
    let keys = Keys::generate();
    let d = || vec![tag(&["d", "entry"])];
    let article = coordinate(&keys, 30023, "entry");
    let a = tag(&["a", &article.to_string()]);
    let v1 = signed(&keys, 30023, 10, "v1", d());
    let v2 = signed(&keys, 30023, 20, "v2", d());

    // A `note`/`nevent` link to an article version honours an `a` deletion
    // dated at or after that version, and only those.
    let a_deletion = signed(&keys, 5, 15, "", vec![a]);
    assert_eq!(
        admit(
            &Target::EventId(v1.id),
            None,
            &[v1.clone(), a_deletion.clone()]
        ),
        deleted(15)
    );
    assert_eq!(
        admit(&Target::EventId(v2.id), None, &[v2.clone(), a_deletion]),
        shown(&v2, None)
    );

    // An `naddr` link honours an `e` deletion of a version: that version and
    // every older one stay hidden.
    let target = Target::Coordinate(article);
    let e_deletion = signed(&keys, 5, 30, "", vec![tag(&["e", &v2.id.to_hex()])]);
    assert_eq!(
        admit(&target, None, &[v1.clone(), v2.clone(), e_deletion]),
        deleted(20)
    );
    let v3 = signed(&keys, 30023, 40, "v3", d());
    assert_eq!(
        admit(&target, deleted(20).as_ref(), &[v1, v2, v3.clone()]),
        shown(&v3, Some(20))
    );
}

#[test]
fn coordinate_admission_keeps_newest_version_and_deletion_bound() {
    let keys = Keys::generate();
    let article = coordinate(&keys, 30023, "entry");
    let target = Target::Coordinate(article.clone());
    let d = || vec![tag(&["d", "entry"])];
    let v1 = signed(&keys, 30023, 10, "v1", d());
    let v2 = signed(&keys, 30023, 20, "v2", d());
    let v2_twin = signed(&keys, 30023, 20, "v2 twin", d());
    let other_d = signed(&keys, 30023, 30, "other", vec![tag(&["d", "other"])]);
    let other_author = signed(&Keys::generate(), 30023, 30, "x", d());
    let a = tag(&["a", &article.to_string()]);
    let deletion = signed(&keys, 5, 25, "", vec![a.clone()]);
    let forged = signed(&Keys::generate(), 5, 40, "", vec![a]);

    assert_eq!(
        admit(
            &target,
            None,
            &[v1.clone(), v2.clone(), other_d, other_author]
        ),
        shown(&v2, None)
    );
    let lower = if v2.id < v2_twin.id { &v2 } else { &v2_twin };
    assert_eq!(
        admit(&target, None, &[v2.clone(), v2_twin.clone()]),
        shown(lower, None),
        "equal timestamps keep the lower ID"
    );
    let cached = shown(&v2, None).unwrap();
    assert_eq!(
        admit(&target, Some(&cached), std::slice::from_ref(&v1)),
        Some(cached.clone()),
        "an older version never replaces a newer cached one"
    );
    assert_eq!(
        admit(&target, Some(&cached), &[v2.clone(), forged.clone()]),
        Some(cached.clone())
    );
    assert_eq!(
        admit(&target, None, &[forged]),
        None,
        "another key's `a` deletion sets no bound"
    );
    assert_eq!(
        admit(&target, Some(&cached), std::slice::from_ref(&deletion)),
        deleted(25)
    );
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&deletion)),
        deleted(25),
        "an `a` deletion bounds the coordinate with no version in hand"
    );

    // A newer version is shown again, and the row keeps the bound, so a stale
    // relay serving only old versions can never bring them back.
    let v3 = signed(&keys, 30023, 30, "v3", d());
    let row = admit(
        &target,
        deleted(25).as_ref(),
        &[v1.clone(), v2.clone(), v3.clone()],
    );
    assert_eq!(row, shown(&v3, Some(25)));
    assert_eq!(admit(&target, row.as_ref(), &[v1, v2]), row);
}

#[test]
fn refresh_rules_follow_target_kind_and_completeness() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let event = Target::EventId(note.id);
    let article = Target::Coordinate(coordinate(&keys, 30023, "entry"));
    let stored = |row: Option<Row>, complete| Stored {
        row: row.unwrap(),
        complete,
        fetched_at: 1_000,
    };
    let fresh = 1_000 + 30 * 60 - 1;
    let stale = 1_000 + 30 * 60;
    assert!(needs_refresh(&event, None, 1_000));
    let complete = stored(shown(&note, None), true);
    assert!(!needs_refresh(&event, Some(&complete), u64::MAX));
    let partial = stored(shown(&note, None), false);
    assert!(!needs_refresh(&event, Some(&partial), fresh));
    assert!(needs_refresh(&event, Some(&partial), stale));
    let marker = stored(deleted(5), false);
    assert!(!needs_refresh(&event, Some(&marker), u64::MAX));
    assert!(!needs_refresh(&article, Some(&complete), fresh));
    assert!(needs_refresh(&article, Some(&complete), stale));
}

fn previews_table() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../directory/cache/v2.sql"))
        .unwrap();
    conn
}

fn fetched_at(conn: &Connection, key: &str) -> (u64, bool) {
    let stored = read_row(conn, key).unwrap().unwrap();
    (stored.fetched_at, stored.complete)
}

#[test]
fn incomplete_fetches_never_confirm_a_row() {
    let keys = Keys::generate();
    let conn = previews_table();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let key = "event:note";
    let target = Target::EventId(note.id);
    let fetched = std::slice::from_ref(&note);

    persist_refresh(&conn, key, &target, fetched, false, 100).unwrap();
    assert_eq!(fetched_at(&conn, key), (100, false));
    persist_refresh(&conn, key, &target, fetched, false, 200).unwrap();
    assert_eq!(fetched_at(&conn, key), (100, false), "not re-dated");
    persist_refresh(&conn, key, &target, fetched, true, 300).unwrap();
    assert_eq!(fetched_at(&conn, key), (300, true));
    persist_refresh(&conn, key, &target, &[], true, 400).unwrap();
    assert_eq!(fetched_at(&conn, key), (400, true));
}

#[test]
fn rows_round_trip_and_trim_least_recently_used() {
    let keys = Keys::generate();
    let conn = previews_table();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    write_row(&conn, "event:a", &shown(&note, None).unwrap(), true, 100).unwrap();
    let stored = read_row(&conn, "event:a").unwrap().unwrap();
    assert_eq!(stored.row, shown(&note, None).unwrap());
    assert_eq!((stored.fetched_at, stored.complete), (100, true));
    assert!(matches!(
        read_preview(&conn, "event:a").unwrap(),
        Some(PublicEventPreview::Present {
            fetched_at: 100,
            ..
        })
    ));
    write_row(&conn, "event:a", &deleted(20).unwrap(), true, 50).unwrap();
    assert_eq!(
        read_row(&conn, "event:a").unwrap().unwrap().row,
        deleted(20).unwrap()
    );
    assert_eq!(
        read_preview(&conn, "event:a").unwrap(),
        Some(PublicEventPreview::Deleted)
    );
    assert!(read_row(&conn, "event:missing").unwrap().is_none());

    // Rows with a deletion time go last, whatever their age: `event:a` was
    // touched first, yet survives a full budget of newer plain rows.
    for index in 0..MAX_ENTRIES {
        write_row(
            &conn,
            &format!("event:{index:04}"),
            &shown(&note, None).unwrap(),
            true,
            300,
        )
        .unwrap();
        trim(&conn).unwrap();
    }
    let count = |conn: &Connection| -> i64 {
        conn.query_row("SELECT count(*) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap()
    };
    assert_eq!(count(&conn), MAX_ENTRIES);
    assert!(read_row(&conn, "event:a").unwrap().is_some());
    assert!(read_row(&conn, "event:0000").unwrap().is_none());

    // The byte budget evicts too.
    let large = signed(&keys, 1, 10, &"x".repeat(200 * 1024), Vec::new());
    for index in 0..100 {
        write_row(
            &conn,
            &format!("event:large{index}"),
            &shown(&large, None).unwrap(),
            true,
            400,
        )
        .unwrap();
        trim(&conn).unwrap();
    }
    let total: i64 = conn
        .query_row("SELECT sum(bytes) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(total <= MAX_TOTAL_BYTES);
    assert!(read_row(&conn, "event:large99").unwrap().is_some());
    assert!(read_row(&conn, "event:a").unwrap().is_some());
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

#[tokio::test]
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

#[tokio::test]
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
        crate::MarmotAppConfig::default().with_open_ranking_provider(None, Vec::new()),
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
        app.public_event_query_relays(hints),
        ["wss://hint.example", "wss://relay.example"]
            .map(|url| TransportEndpoint(RelayUrl::parse(url).unwrap().to_string()))
    );
}
