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

fn present(event: &Event) -> Admission {
    Admission::Present(Box::new(event.clone()))
}

fn stored(event: &Event) -> Stored {
    Stored::Present {
        event: Box::new(event.clone()),
        fetched_at: 1,
    }
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
    assert_eq!(parsed.author_hint, Some(keys.public_key()));
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

    assert_eq!(admit(&target, None, &[]), Admission::Keep);
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&other)),
        Admission::Keep
    );
    assert_eq!(admit(&target, None, &[other, note.clone()]), present(&note));
    assert_eq!(
        admit(&target, None, &[note.clone(), forged.clone()]),
        present(&note),
        "a deletion by anyone but the author is ignored"
    );
    assert_eq!(
        admit(
            &target,
            Some(&stored(&note)),
            std::slice::from_ref(&deletion)
        ),
        Admission::Deleted {
            created_at: 20,
            deletion_id: deletion.id,
        },
        "the cached event supplies the author when relays no longer serve it"
    );
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&deletion)),
        Admission::Keep,
        "an unattributable deletion stores nothing"
    );
    let marker = Stored::Deleted {
        created_at: 20,
        fetched_at: 1,
    };
    assert_eq!(
        admit(&target, Some(&marker), &[note]),
        Admission::Keep,
        "a relay that kept the event cannot restore it"
    );
}

#[test]
fn coordinate_admission_keeps_newest_version_and_honours_deletions() {
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
        present(&v2)
    );
    let lower = if v2.id < v2_twin.id { &v2 } else { &v2_twin };
    assert_eq!(
        admit(&target, None, &[v2.clone(), v2_twin.clone()]),
        present(lower),
        "equal timestamps keep the lower ID"
    );
    assert_eq!(
        admit(&target, Some(&stored(&v2)), std::slice::from_ref(&v1)),
        present(&v2),
        "an older version never replaces a newer cached one"
    );
    assert_eq!(
        admit(&target, Some(&stored(&v2)), &[v2.clone(), forged]),
        present(&v2)
    );
    let deleted = Admission::Deleted {
        created_at: 25,
        deletion_id: deletion.id,
    };
    assert_eq!(
        admit(&target, Some(&stored(&v2)), std::slice::from_ref(&deletion)),
        deleted
    );

    let marker = Stored::Deleted {
        created_at: 25,
        fetched_at: 1,
    };
    assert_eq!(
        admit(&target, Some(&marker), &[v1, v2.clone()]),
        Admission::Confirm,
        "versions up to the deletion stay deleted"
    );
    let v3 = signed(&keys, 30023, 30, "v3", d());
    assert_eq!(
        admit(&target, Some(&marker), &[v2, v3.clone(), deletion]),
        present(&v3),
        "a version newer than the deletion is valid again"
    );
}

#[test]
fn coordinate_rows_refetch_after_thirty_minutes_and_event_ids_never() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let event = Target::EventId(note.id);
    let article = Target::Coordinate(coordinate(&keys, 30023, "entry"));
    let row = Stored::Present {
        event: Box::new(note),
        fetched_at: 1_000,
    };
    assert!(needs_refresh(&event, None, 1_000));
    assert!(!needs_refresh(&event, Some(&row), u64::MAX));
    assert!(!needs_refresh(&article, Some(&row), 1_000 + 30 * 60 - 1));
    assert!(needs_refresh(&article, Some(&row), 1_000 + 30 * 60));
}

fn previews_table() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../directory/cache/v2.sql"))
        .unwrap();
    conn
}

#[test]
fn rows_round_trip_and_trim_least_recently_used() {
    let keys = Keys::generate();
    let conn = previews_table();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    write_admission(&conn, "event:a", present(&note), 100).unwrap();
    let Some(Stored::Present { event, fetched_at }) = read_row(&conn, "event:a").unwrap() else {
        panic!("expected a present row");
    };
    assert_eq!((*event, fetched_at), (note.clone(), 100));
    write_admission(
        &conn,
        "event:a",
        Admission::Deleted {
            created_at: 20,
            deletion_id: note.id,
        },
        200,
    )
    .unwrap();
    assert!(matches!(
        read_row(&conn, "event:a").unwrap(),
        Some(Stored::Deleted {
            created_at: 20,
            fetched_at: 200
        })
    ));
    assert!(read_row(&conn, "event:missing").unwrap().is_none());

    // The entry budget evicts the least recently touched row first.
    for index in 0..MAX_ENTRIES {
        write_admission(&conn, &format!("event:{index:04}"), present(&note), 300).unwrap();
    }
    let count = |conn: &Connection| -> i64 {
        conn.query_row("SELECT count(*) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap()
    };
    assert_eq!(count(&conn), MAX_ENTRIES);
    assert!(read_row(&conn, "event:a").unwrap().is_none());

    // The byte budget evicts too.
    let large = signed(&keys, 1, 10, &"x".repeat(200 * 1024), Vec::new());
    for index in 0..100 {
        write_admission(&conn, &format!("event:large{index}"), present(&large), 400).unwrap();
    }
    let total: i64 = conn
        .query_row("SELECT sum(bytes) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(total <= MAX_TOTAL_BYTES);
    assert!(read_row(&conn, "event:large99").unwrap().is_some());
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
    let regretted_ref = Nip19Event::new(regretted.id)
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
