use nostr::nips::nip19::{Nip19Coordinate, Nip19Event, ToBech32};
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp};

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

fn shown_row(event: &Event, deleted_through: Option<u64>) -> Row {
    Row {
        event: Some(Box::new(event.clone())),
        deleted_through,
    }
}

fn deleted_row(through: u64) -> Row {
    Row {
        event: None,
        deleted_through: Some(through),
    }
}

fn shown(event: &Event, deleted_through: Option<u64>) -> Admitted {
    Admitted::Row(shown_row(event, deleted_through))
}

fn deleted(through: u64) -> Admitted {
    Admitted::Row(deleted_row(through))
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

    assert_eq!(admit(&target, None, &[]), Admitted::Nothing);
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&other)),
        Admitted::Nothing
    );
    assert_eq!(
        admit(&target, None, &[other, note.clone()]),
        shown(&note, None)
    );
    assert_eq!(
        admit(&target, None, &[note.clone(), forged.clone()]),
        shown(&note, None),
        "a deletion by anyone but the author is ignored"
    );
    let cached = shown_row(&note, None);
    assert_eq!(
        admit(&target, Some(&cached), std::slice::from_ref(&deletion)),
        deleted(20),
        "the cached event supplies the author when relays no longer serve it"
    );
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&deletion)),
        Admitted::Nothing,
        "an unattributable deletion stores nothing"
    );
    let marker = deleted_row(20);
    assert_eq!(
        admit(&target, Some(&marker), &[note]),
        Admitted::Row(marker),
        "a relay that kept the event cannot restore it"
    );
}

fn queries(filters: &[Filter]) -> Vec<serde_json::Value> {
    filters
        .iter()
        .map(|filter| serde_json::to_value(filter).unwrap())
        .collect()
}

#[test]
fn follow_up_deletion_queries_cover_what_the_first_query_could_not() {
    let keys = Keys::generate();
    let author = keys.public_key();
    let deletions = || Filter::new().kind(Kind::EventDeletion).author(author);

    // An event-ID answer that came back full without the author's deletion.
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let target = Target::EventId(note.id);
    let e = || vec![tag(&["e", &note.id.to_hex()])];
    let spam = (0..EVENT_DELETION_QUERY_LIMIT)
        .map(|index| signed(&Keys::generate(), 5, 20 + index as u64, "", e()))
        .collect::<Vec<_>>();
    let mut fetched = spam.clone();
    fetched.push(note.clone());
    let author_e = vec![deletions().event(note.id).limit(4)];
    assert_eq!(
        queries(&follow_up_deletions(&target, None, &fetched)),
        queries(&author_e)
    );
    assert_eq!(
        queries(&follow_up_deletions(&target, Some(&note), &spam)),
        queries(&author_e)
    );
    let mut answered = fetched.clone();
    answered.push(signed(&keys, 5, 50, "", e()));
    assert!(follow_up_deletions(&target, None, &answered).is_empty());
    assert!(follow_up_deletions(&target, None, &[note.clone(), spam[0].clone()]).is_empty());
    assert!(follow_up_deletions(&target, None, &spam).is_empty());

    // An article linked by ID: ask for its coordinate's deletions once.
    let article = signed(&keys, 30023, 10, "v1", vec![tag(&["d", "entry"])]);
    let entry = coordinate(&keys, 30023, "entry");
    let target = Target::EventId(article.id);
    assert_eq!(
        queries(&follow_up_deletions(
            &target,
            None,
            std::slice::from_ref(&article)
        )),
        queries(&[deletions().coordinate(&entry).limit(4)])
    );
    assert!(
        follow_up_deletions(&target, Some(&article), std::slice::from_ref(&article)).is_empty()
    );

    // `naddr` versions this refresh found, other than the cached one.
    let v2 = signed(&keys, 30023, 20, "v2", vec![tag(&["d", "entry"])]);
    let target = Target::Coordinate(entry);
    assert_eq!(
        queries(&follow_up_deletions(
            &target,
            Some(&article),
            &[article.clone(), v2.clone()]
        )),
        queries(&[deletions().events([v2.id]).limit(8)])
    );
    assert!(
        follow_up_deletions(&target, Some(&article), std::slice::from_ref(&article)).is_empty()
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

    // An `naddr` link honours an `e` deletion of a version: that version goes,
    // and the previous one becomes current.
    let target = Target::Coordinate(article);
    let e_deletion = signed(&keys, 5, 30, "", vec![tag(&["e", &v2.id.to_hex()])]);
    assert_eq!(
        admit(&target, None, &[v1.clone(), v2.clone(), e_deletion.clone()]),
        shown(&v1, None)
    );
    // With no other version in hand, the key goes back to unknown.
    assert_eq!(
        admit(
            &target,
            Some(&shown_row(&v2, None)),
            std::slice::from_ref(&e_deletion)
        ),
        Admitted::Cleared
    );
    assert_eq!(
        admit(&target, None, std::slice::from_ref(&e_deletion)),
        Admitted::Nothing
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
    let cached = shown_row(&v2, None);
    assert_eq!(
        admit(&target, Some(&cached), std::slice::from_ref(&v1)),
        Admitted::Row(cached.clone()),
        "an older version never replaces a newer cached one"
    );
    assert_eq!(
        admit(&target, Some(&cached), &[v2.clone(), forged.clone()]),
        Admitted::Row(cached.clone())
    );
    assert_eq!(
        admit(&target, None, &[forged]),
        Admitted::Nothing,
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
    let row = shown_row(&v3, Some(25));
    assert_eq!(
        admit(
            &target,
            Some(&deleted_row(25)),
            &[v1.clone(), v2.clone(), v3.clone()]
        ),
        Admitted::Row(row.clone())
    );
    assert_eq!(admit(&target, Some(&row), &[v1, v2]), Admitted::Row(row));
}

#[test]
fn refresh_rules_follow_target_kind_and_completeness() {
    let keys = Keys::generate();
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let event = Target::EventId(note.id);
    let article = Target::Coordinate(coordinate(&keys, 30023, "entry"));
    let stored = |row: Row, complete| Stored {
        row,
        complete,
        fetched_at: 1_000,
    };
    let fresh = 1_000 + 30 * 60 - 1;
    let stale = 1_000 + 30 * 60;
    assert!(needs_refresh(&event, None, 1_000));
    let complete = stored(shown_row(&note, None), true);
    assert!(!needs_refresh(&event, Some(&complete), u64::MAX));
    let partial = stored(shown_row(&note, None), false);
    assert!(!needs_refresh(&event, Some(&partial), fresh));
    assert!(needs_refresh(&event, Some(&partial), stale));
    let marker = stored(deleted_row(5), false);
    assert!(!needs_refresh(&event, Some(&marker), u64::MAX));
    assert!(!needs_refresh(&article, Some(&complete), fresh));
    assert!(needs_refresh(&article, Some(&complete), stale));
}

fn previews_table() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../cache/v2.sql")).unwrap();
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
    write_row(&conn, "event:a", &shown_row(&note, None), true, 100).unwrap();
    let stored = read_row(&conn, "event:a").unwrap().unwrap();
    assert_eq!(stored.row, shown_row(&note, None));
    assert_eq!((stored.fetched_at, stored.complete), (100, true));
    assert!(matches!(
        read_preview(&conn, "event:a").unwrap(),
        Some(PublicEventPreview::Present {
            fetched_at: 100,
            ..
        })
    ));
    write_row(&conn, "event:a", &deleted_row(20), true, 50).unwrap();
    assert_eq!(
        read_row(&conn, "event:a").unwrap().unwrap().row,
        deleted_row(20)
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
            &shown_row(&note, None),
            true,
            300,
        )
        .unwrap();
        trim(&conn, "event:none").unwrap();
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
            &shown_row(&large, None),
            true,
            400,
        )
        .unwrap();
        trim(&conn, "event:none").unwrap();
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

#[test]
fn a_cache_full_of_deletion_markers_still_admits_new_previews() {
    let keys = Keys::generate();
    let conn = previews_table();
    for index in 0..MAX_ENTRIES {
        write_row(
            &conn,
            &format!("event:{index:04}"),
            &deleted_row(5),
            true,
            100,
        )
        .unwrap();
    }
    let note = signed(&keys, 1, 10, "note", Vec::new());
    let key = format!("event:{}", note.id.to_hex());
    persist_refresh(
        &conn,
        &key,
        &Target::EventId(note.id),
        std::slice::from_ref(&note),
        true,
        200,
    )
    .unwrap();
    assert!(matches!(
        read_preview(&conn, &key).unwrap(),
        Some(PublicEventPreview::Present { .. })
    ));
    assert!(read_row(&conn, "event:0000").unwrap().is_none());
    let count: i64 = conn
        .query_row("SELECT count(*) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, MAX_ENTRIES);
}
