use super::*;
use marmot_account::AccountHome;
use nostr::prelude::{EventBuilder, FinalizeEvent, Keys, Kind, Tag, Timestamp};

fn fixture() -> (tempfile::TempDir, PublicEventCache) {
    let dir = tempfile::tempdir().unwrap();
    let cache = PublicEventCache::open(
        &dir.path().join("events.sqlite3"),
        &SqlCipherKey::new("public-event-test").unwrap(),
        Duration::from_secs(300),
    )
    .unwrap();
    (dir, cache)
}
fn signed(keys: &Keys, kind: u16, at: u64, body: &str) -> Event {
    EventBuilder::new(Kind::from(kind), body)
        .custom_created_at(Timestamp::from_secs(at))
        .tags([Tag::parse(["d", "entry"]).unwrap()])
        .finalize(keys)
        .unwrap()
}
fn super_reference(event: &Event) -> PublicEventReference {
    PublicEventReference {
        event_id_hex: Some(event.id.to_hex()),
        author_pubkey_hex: Some(event.pubkey.to_hex()),
        kind: Some(u32::from(event.kind.as_u16())),
        identifier: None,
    }
}
fn address(keys: &Keys, kind: u32) -> PublicEventReference {
    PublicEventReference {
        event_id_hex: None,
        author_pubkey_hex: Some(keys.public_key().to_hex()),
        kind: Some(kind),
        identifier: Some(if kind >= 30_000 { "entry" } else { "" }.into()),
    }
}

#[test]
fn verified_event_survives_close_and_offline_reopen() {
    let (dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "Complete public event");
    let reference = super_reference(&event);
    let admitted = cache
        .admit(&reference, &[event.as_json()], 1000)
        .unwrap()
        .unwrap();
    cache.close().unwrap();
    assert!(cache.lookup(&reference, 1000).is_err());
    let reopened = PublicEventCache::open(
        &dir.path().join("events.sqlite3"),
        &SqlCipherKey::new("public-event-test").unwrap(),
        Duration::from_secs(300),
    )
    .unwrap();
    assert_eq!(Some(admitted), reopened.lookup(&reference, 1001).unwrap());
}

#[test]
fn invalid_signatures_ids_and_coordinates_never_replace_valid_data() {
    let (_dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "Verified original");
    let reference = super_reference(&event);
    let known = cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    let mut altered = serde_json::to_value(&event).unwrap();
    altered["content"] = serde_json::json!("tampered");
    assert_eq!(
        known,
        cache
            .admit(&reference, &[altered.to_string(), "invalid".into()], 1001)
            .unwrap()
    );
    let mut wrong_kind = reference.clone();
    wrong_kind.kind = Some(30023);
    let mut wrong_author = reference.clone();
    wrong_author.author_pubkey_hex = Some("0".repeat(64));
    assert_eq!(known, cache.lookup(&wrong_kind, 1001).unwrap());
    assert_eq!(
        event.as_json(),
        cache
            .admit(&wrong_author, &[], 1001)
            .unwrap()
            .unwrap()
            .event_json
    );
    assert_eq!(
        known,
        cache.lookup(&reference, 1001).unwrap(),
        "optional lookup hints do not change the signed identity"
    );
    let other = signed(&Keys::generate(), 1, 1000, "different signed event");
    assert_eq!(
        known,
        cache.admit(&reference, &[other.as_json()], 1001).unwrap()
    );
}

#[test]
fn signed_events_from_another_author_or_kind_cannot_fill_a_coordinate() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let reference = address(&keys, 30023);
    let wrong_author = signed(&Keys::generate(), 30023, 1000, "wrong author");
    let wrong_kind = signed(&keys, 30063, 1000, "wrong kind");
    assert_eq!(
        None,
        cache
            .admit(
                &reference,
                &[wrong_author.as_json(), wrong_kind.as_json()],
                1000
            )
            .unwrap()
    );
}

#[test]
fn address_selection_is_monotonic_and_ties_use_lowest_id() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let reference = address(&keys, 30023);
    let older = signed(&keys, 30023, 900, "older");
    let a = signed(&keys, 30023, 1000, "tie a");
    let b = signed(&keys, 30023, 1000, "tie b");
    let lower = if a.id < b.id { &a } else { &b };
    let result = cache
        .admit(
            &reference,
            &[older.as_json(), b.as_json(), a.as_json()],
            1000,
        )
        .unwrap()
        .unwrap();
    assert_eq!(lower.id, Event::from_json(&result.event_json).unwrap().id);
    assert_eq!(
        Some(result.clone()),
        cache.admit(&reference, &[older.as_json()], 1001).unwrap()
    );
    assert_eq!(
        Some(result),
        cache.admit(&reference, &[older.as_json()], 1).unwrap(),
        "clock rollback cannot replace an admitted newer event"
    );
    let newer = signed(&keys, 30023, 1001, "newer");
    assert_eq!(
        newer.id,
        Event::from_json(
            &cache
                .admit(&reference, &[newer.as_json()], 1001)
                .unwrap()
                .unwrap()
                .event_json
        )
        .unwrap()
        .id
    );
}

#[test]
fn future_policy_and_stale_refresh_keep_offline_data() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let reference = address(&keys, 30023);
    let event = signed(&keys, 30023, 1000, "known");
    cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    let future = signed(&keys, 30023, 1301, "future");
    assert_eq!(
        event.id,
        Event::from_json(
            &cache
                .admit(&reference, &[future.as_json()], 1000)
                .unwrap()
                .unwrap()
                .event_json
        )
        .unwrap()
        .id
    );
    let stale = cache.lookup(&reference, 1900).unwrap().unwrap();
    assert!(stale.refresh_recommended);
    assert_eq!(Some(stale), cache.admit(&reference, &[], 1900).unwrap());
    let id = super_reference(&event);
    cache.admit(&id, &[event.as_json()], 1000).unwrap();
    assert!(
        !cache
            .lookup(&id, 100_000)
            .unwrap()
            .unwrap()
            .refresh_recommended
    );
}

#[test]
fn normal_replaceable_coordinates_require_an_empty_identifier() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    for kind in [0u16, 3, 10002] {
        let reference = address(&keys, kind.into());
        let event = signed(&keys, kind, 1000, "replaceable");
        assert!(
            cache
                .admit(&reference, &[event.as_json()], 1000)
                .unwrap()
                .is_some()
        );
    }
    let mut invalid = address(&keys, 10002);
    invalid.identifier = Some("entry".into());
    assert!(cache.lookup(&invalid, 1000).is_err());
    assert!(cache.lookup(&address(&keys, 1), 1000).is_err());
}

#[test]
fn the_first_d_tag_determines_the_coordinate_even_when_it_has_no_value() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let event = EventBuilder::new(Kind::from(30023), "first d wins")
        .custom_created_at(Timestamp::from_secs(1000))
        .tags([
            Tag::parse(["d"]).unwrap(),
            Tag::parse(["d", "entry"]).unwrap(),
        ])
        .finalize(&keys)
        .unwrap();
    assert_eq!(
        None,
        cache
            .admit(&address(&keys, 30023), &[event.as_json()], 1000)
            .unwrap()
    );
    let mut empty = address(&keys, 30023);
    empty.identifier = Some(String::new());
    assert!(
        cache
            .admit(&empty, &[event.as_json()], 1000)
            .unwrap()
            .is_some()
    );
}

#[test]
fn oversized_batches_are_rejected_without_losing_known_data() {
    let (_dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "known");
    let reference = super_reference(&event);
    let known = cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    assert!(
        cache
            .admit(&reference, &vec![event.as_json(); MAX_CANDIDATES + 1], 1001)
            .is_err()
    );
    assert!(
        cache
            .admit(&reference, &["x".repeat(MAX_EVENT_BYTES + 1)], 1001)
            .is_err()
    );
    assert_eq!(known, cache.lookup(&reference, 1001).unwrap());
}

#[test]
fn malformed_cache_rows_are_removed_and_return_a_safe_miss() {
    let (_dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "known");
    let reference = super_reference(&event);
    cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    cache
        .conn
        .lock()
        .unwrap()
        .execute("UPDATE public_event_previews SET event_json='invalid'", [])
        .unwrap();
    assert_eq!(None, cache.lookup(&reference, 1001).unwrap());
    let count: i64 = cache
        .conn
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(0, count);
}

#[test]
fn cache_enforces_count_and_byte_budgets_without_evicting_selected_row() {
    let (_dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "selected");
    let reference = super_reference(&event);
    cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    let mut conn = cache.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    for i in 0..MAX_ENTRIES {
        tx.execute(
            "INSERT INTO public_event_previews (cache_key, event_json, received_at, touched_at, bytes)
             VALUES (?1, 'fixture', 1, 1, 1)",
            [format!("fixture:{i}")],
        )
        .unwrap();
    }
    PublicEventCache::trim(&tx, &cache.provenance, &reference.key().unwrap()).unwrap();
    let count: i64 = tx
        .query_row("SELECT count(*) FROM public_event_previews", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(MAX_ENTRIES, count);
    tx.execute(
        "UPDATE public_event_previews SET bytes=262144 WHERE cache_key LIKE 'fixture:%'",
        [],
    )
    .unwrap();
    PublicEventCache::trim(&tx, &cache.provenance, &reference.key().unwrap()).unwrap();
    let bytes: i64 = tx
        .query_row("SELECT sum(bytes) FROM public_event_previews", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(bytes <= MAX_TOTAL_BYTES);
    tx.commit().unwrap();
    drop(conn);
    assert!(cache.lookup(&reference, 1001).unwrap().is_some());
}

#[test]
fn per_account_handles_keys_removal_and_terminal_close_are_isolated() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let bob = home.create_account("bob").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let a = app.public_event_cache_for_account(&alice).unwrap();
    let b = app.public_event_cache_for_account(&bob).unwrap();
    let event = signed(&Keys::generate(), 1, 1000, "only alice");
    let reference = super_reference(&event);
    a.admit(&reference, &[event.as_json()], 1000).unwrap();
    assert_eq!(None, b.lookup(&reference, 1000).unwrap());
    let keys = app.account_home().load_signing_keys("alice").unwrap();
    let path = app.public_event_cache_path("alice");
    let event_key = app
        .sqlcipher_key(
            "alice",
            &keys,
            &path,
            SqlcipherDatabaseKind::PublicEventCache,
        )
        .unwrap();
    let other_key = app
        .sqlcipher_key(
            "alice",
            &keys,
            &app.account_dir("alice").join("directory-test.sqlite3"),
            SqlcipherDatabaseKind::DirectoryCache,
        )
        .unwrap();
    assert_ne!(event_key.as_secret_str(), other_key.as_secret_str());
    app.drop_account_caches("alice");
    assert!(a.lookup(&reference, 1000).is_err());
    assert!(b.lookup(&reference, 1000).is_ok());
    app.close_storage().unwrap();
    assert!(b.lookup(&reference, 1000).is_err());
    assert!(app.public_event_cache_for_account(&bob).is_err());
}

#[test]
fn reference_parser_rejects_secret_and_profile_identifiers() {
    assert!(PublicEventReference::parse("nsec1invalid").is_err());
    assert!(PublicEventReference::parse("npub1invalid").is_err());
    assert!(PublicEventReference::parse(&"f".repeat(65)).is_err());
    let parsed = PublicEventReference::parse(&format!("nostr:{}", "A".repeat(64))).unwrap();
    assert_eq!(Some("a".repeat(64)), parsed.event_id_hex);
}

#[test]
fn note_nevent_and_naddr_decode_constraints_without_using_relay_hints_as_identity() {
    use nostr::nips::nip19::{Nip19Coordinate, Nip19Event, ToBech32};
    use nostr::prelude::Coordinate;
    let keys = Keys::generate();
    let event = signed(&keys, 1, 1000, "reference fixture");
    let note = event.id.to_bech32().unwrap();
    assert_eq!(
        Some(event.id.to_hex()),
        PublicEventReference::parse(&note).unwrap().event_id_hex
    );
    let pointer = Nip19Event::from(&event).to_bech32().unwrap();
    assert_eq!(
        super_reference(&event),
        PublicEventReference::parse(&pointer).unwrap()
    );
    let coordinate = Nip19Coordinate::new(
        Coordinate::new(Kind::from(30023), keys.public_key()).identifier("entry"),
        std::iter::empty(),
    );
    assert_eq!(
        address(&keys, 30023),
        PublicEventReference::parse(&coordinate.to_bech32().unwrap()).unwrap()
    );
}

fn deletion(keys: &Keys, at: u64, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::from(5), "")
        .custom_created_at(Timestamp::from_secs(at))
        .tags(tags)
        .finalize(keys)
        .unwrap()
}

fn e_tag(event: &Event) -> Tag {
    Tag::parse(["e", event.id.to_hex().as_str()]).unwrap()
}

fn a_tag(keys: &Keys, kind: u16, identifier: &str) -> Tag {
    let value = format!("{kind}:{}:{identifier}", keys.public_key().to_hex());
    Tag::parse(["a", value.as_str()]).unwrap()
}

fn id_reference(event: &Event) -> PublicEventReference {
    PublicEventReference {
        event_id_hex: Some(event.id.to_hex()),
        author_pubkey_hex: None,
        kind: None,
        identifier: None,
    }
}

fn is_deleted(result: &PublicEventCacheResult) -> bool {
    matches!(result, PublicEventCacheResult::AuthoritativeDeleted(_))
}

fn present_id(result: &PublicEventCacheResult) -> Option<String> {
    match result {
        PublicEventCacheResult::Present(preview) => {
            Some(Event::from_json(&preview.event_json).unwrap().id.to_hex())
        }
        _ => None,
    }
}

fn count(cache: &PublicEventCache, table: &str) -> i64 {
    cache
        .conn
        .lock()
        .unwrap()
        .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

#[test]
fn authenticated_deletion_wins_while_forged_unknown_and_recursive_requests_are_ignored() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let note = signed(&keys, 1, 1000, "public note");
    let reference = id_reference(&note);
    cache.admit(&reference, &[note.as_json()], 2000).unwrap();

    let forged = deletion(&Keys::generate(), 1100, vec![e_tag(&note)]);
    let kept = cache
        .admit_state(&reference, &[forged.as_json()], 2000)
        .unwrap();
    assert_eq!(
        Some(note.id.to_hex()),
        present_id(&kept),
        "other authors cannot delete"
    );

    // An unknown ID gains no authority from an nevent author hint.
    let unknown = signed(&keys, 1, 1000, "never cached");
    let hinted = PublicEventReference {
        event_id_hex: Some(unknown.id.to_hex()),
        author_pubkey_hex: Some(keys.public_key().to_hex()),
        kind: Some(1),
        identifier: None,
    };
    let unauthenticated = deletion(&keys, 1100, vec![e_tag(&unknown)]);
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache
            .admit_state(&hinted, &[unauthenticated.as_json()], 2000)
            .unwrap()
    );
    assert_eq!(0, count(&cache, "public_event_tombstones"));

    // A deletion of a deletion has no effect on the first request.
    let first = deletion(&keys, 1200, vec![e_tag(&unknown)]);
    let recursive = deletion(&keys, 1300, vec![e_tag(&first)]);
    let first_reference = id_reference(&first);
    let first_state = cache
        .admit_state(
            &first_reference,
            &[first.as_json(), recursive.as_json()],
            2000,
        )
        .unwrap();
    assert_eq!(Some(first.id.to_hex()), present_id(&first_state));

    let authentic = deletion(&keys, 1400, vec![e_tag(&note)]);
    let deleted = cache
        .admit_state(&reference, &[authentic.as_json()], 2000)
        .unwrap();
    let PublicEventCacheResult::AuthoritativeDeleted(evidence) = &deleted else {
        panic!("authenticated deletion must win");
    };
    assert_eq!(authentic.as_json(), evidence.deletion_event_json);
    assert_eq!(PUBLIC_EVENT_PROJECTION_VERSION, evidence.projection_version);
    assert!(is_deleted(
        &cache
            .admit_state(&reference, &[note.as_json()], 2001)
            .unwrap()
    ));
    assert_eq!(None, cache.lookup(&reference, 2002).unwrap());
    assert_eq!(
        1,
        count(&cache, "public_event_previews"),
        "only the separately referenced kind-5 event remains"
    );
}

#[test]
fn coordinate_deletions_fence_older_versions_and_aliases_without_blocking_newer_ones() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let v1 = signed(&keys, 30023, 1000, "v1");
    let v2 = signed(&keys, 30023, 1100, "v2");
    let selected = cache
        .admit_state(&naddr, &[v1.as_json(), v2.as_json()], 2000)
        .unwrap();
    assert_eq!(Some(v2.id.to_hex()), present_id(&selected));

    // Deleting the selected version by ID keeps its rank as a fence.
    let by_id = deletion(&keys, 1200, vec![e_tag(&v2)]);
    assert!(is_deleted(
        &cache.admit_state(&naddr, &[by_id.as_json()], 2000).unwrap()
    ));
    assert!(
        is_deleted(&cache.admit_state(&naddr, &[v1.as_json()], 2000).unwrap()),
        "an older replacement must not resurrect"
    );
    let v3 = signed(&keys, 30023, 1300, "v3");
    assert_eq!(
        Some(v3.id.to_hex()),
        present_id(&cache.admit_state(&naddr, &[v3.as_json()], 2000).unwrap())
    );

    // A coordinate request covers every version up to its creation time.
    let by_address = deletion(&keys, 1400, vec![a_tag(&keys, 30023, "entry")]);
    assert!(is_deleted(
        &cache
            .admit_state(&naddr, &[by_address.as_json()], 2000)
            .unwrap()
    ));
    assert!(is_deleted(
        &cache.admit_state(&naddr, &[v3.as_json()], 2000).unwrap()
    ));
    let v4 = signed(&keys, 30023, 1500, "v4");
    assert_eq!(
        Some(v4.id.to_hex()),
        present_id(&cache.admit_state(&naddr, &[v4.as_json()], 2000).unwrap())
    );

    // An exact-ID alias of the same version is removed in the same transaction.
    let alias = id_reference(&v4);
    assert_eq!(
        Some(v4.id.to_hex()),
        present_id(&cache.admit_state(&alias, &[v4.as_json()], 2000).unwrap())
    );
    let later = deletion(&keys, 1600, vec![a_tag(&keys, 30023, "entry")]);
    assert!(is_deleted(
        &cache.admit_state(&naddr, &[later.as_json()], 2000).unwrap()
    ));
    assert!(is_deleted(&cache.lookup_state(&alias, 2000).unwrap()));
    assert!(is_deleted(
        &cache.admit_state(&alias, &[v4.as_json()], 2000).unwrap()
    ));

    // Coordinate requests by another author have no effect.
    let v5 = signed(&keys, 30023, 1700, "v5");
    cache.admit_state(&naddr, &[v5.as_json()], 2000).unwrap();
    let intruder = Keys::generate();
    let forged = deletion(&intruder, 1800, vec![a_tag(&keys, 30023, "entry")]);
    assert_eq!(
        Some(v5.id.to_hex()),
        present_id(
            &cache
                .admit_state(&naddr, &[forged.as_json()], 2000)
                .unwrap()
        )
    );
}

#[test]
fn deletion_evidence_is_reverified_and_corruption_fails_closed() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    for (column, value) in [
        ("proof_sig", "00".repeat(64)),
        ("deletion_json", "invalid".to_owned()),
        ("projection_version", "2".to_owned()),
    ] {
        let note = signed(&keys, 1, 1000, column);
        let reference = id_reference(&note);
        let request = deletion(&keys, 1100, vec![e_tag(&note)]);
        assert!(is_deleted(
            &cache
                .admit_state(&reference, &[note.as_json(), request.as_json()], 2000)
                .unwrap()
        ));
        cache
            .conn
            .lock()
            .unwrap()
            .execute(
                &format!("UPDATE public_event_tombstones SET {column} = ?1 WHERE cache_key = ?2"),
                params![value, format!("event:{}", note.id.to_hex())],
            )
            .unwrap();
        assert!(
            cache.lookup_state(&reference, 2000).is_err(),
            "{column} corruption must not read as a miss"
        );
        assert!(
            cache
                .admit_state(&reference, &[note.as_json()], 2000)
                .is_err()
        );
    }

    // An unknown projection version is retained, not rewritten.
    let (_dir, cache) = fixture();
    let note = signed(&keys, 1, 1000, "future format");
    let reference = id_reference(&note);
    cache.admit(&reference, &[note.as_json()], 2000).unwrap();
    cache
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE public_event_previews SET projection_version = 2",
            [],
        )
        .unwrap();
    assert!(cache.lookup_state(&reference, 2000).is_err());
    assert_eq!(1, count(&cache, "public_event_previews"));
}

#[test]
fn schema_one_migrates_in_place_and_unknown_schemas_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.sqlite3");
    let key = SqlCipherKey::new("public-event-test").unwrap();
    let keys = Keys::generate();
    let note = signed(&keys, 1, 1000, "schema one");
    let article = signed(&keys, 30023, 1000, "schema one article");
    {
        let conn = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
        for (cache_key, json) in [
            (format!("event:{}", note.id.to_hex()), note.as_json()),
            (address(&keys, 30023).key().unwrap(), article.as_json()),
            ("event:broken".to_owned(), "invalid".to_owned()),
        ] {
            conn.execute(
                "INSERT INTO public_event_previews VALUES (?1, ?2, 1000, 1000, ?3)",
                params![cache_key, json, json.len() as i64],
            )
            .unwrap();
        }
    }
    let cache = PublicEventCache::open(&path, &key, Duration::from_secs(300)).unwrap();
    assert_eq!(
        Some(note.id.to_hex()),
        present_id(&cache.lookup_state(&id_reference(&note), 1001).unwrap())
    );
    assert_eq!(
        Some(article.id.to_hex()),
        present_id(&cache.lookup_state(&address(&keys, 30023), 1001).unwrap())
    );
    assert_eq!(2, count(&cache, "public_event_previews"));
    assert_eq!(0, count(&cache, "public_event_tombstones"));
    assert_eq!(
        1,
        count(&cache, "public_event_tombstone_inventory"),
        "the migration authenticates the empty tombstone inventory"
    );
    let cohort: String = cache
        .conn
        .lock()
        .unwrap()
        .query_row(
            "SELECT cohort_key FROM public_event_previews WHERE rank_event_id = ?1",
            [article.id.to_hex()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(address(&keys, 30023).key().unwrap(), cohort);
    let version: i64 = cache
        .conn
        .lock()
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(SCHEMA_VERSION, version);
    cache
        .conn
        .lock()
        .unwrap()
        .execute_batch("PRAGMA user_version = 9;")
        .unwrap();
    cache.close().unwrap();
    assert!(PublicEventCache::open(&path, &key, Duration::from_secs(300)).is_err());
    let conn = Connection::open(&path).unwrap();
    open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
    let retained: i64 = conn
        .query_row("SELECT count(*) FROM public_event_previews", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(2, retained, "an unknown schema is never recreated");
}

#[test]
fn unreleased_unauthenticated_schema_two_fails_closed_without_rewriting() {
    // Schema 2 kept provenance unauthenticated and schema 3 had no
    // authenticated tombstone inventory; neither was released.
    for unreleased in [2_i64, 3] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sqlite3");
        let key = SqlCipherKey::new("public-event-test").unwrap();
        let note = signed(&Keys::generate(), 1, 1000, "unreleased schema");
        {
            let conn = Connection::open(&path).unwrap();
            open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
            conn.execute_batch(SCHEMA_V1).unwrap();
            conn.execute(
                "INSERT INTO public_event_previews VALUES (?1, ?2, 1000, 1000, ?3)",
                params![
                    format!("event:{}", note.id.to_hex()),
                    note.as_json(),
                    note.as_json().len() as i64
                ],
            )
            .unwrap();
            conn.execute_batch(&format!("PRAGMA user_version = {unreleased};"))
                .unwrap();
        }
        assert!(
            PublicEventCache::open(&path, &key, Duration::from_secs(300)).is_err(),
            "unauthenticated provenance is never silently signed (schema {unreleased})"
        );
        let conn = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(unreleased, version);
        let retained: i64 = conn
            .query_row("SELECT count(*) FROM public_event_previews", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(1, retained);
    }
}

fn signed_d(keys: &Keys, kind: u16, at: u64, body: &str, identifier: &str) -> Event {
    EventBuilder::new(Kind::from(kind), body)
        .custom_created_at(Timestamp::from_secs(at))
        .tags([Tag::parse(["d", identifier]).unwrap()])
        .finalize(keys)
        .unwrap()
}

fn address_d(keys: &Keys, kind: u32, identifier: &str) -> PublicEventReference {
    PublicEventReference {
        event_id_hex: None,
        author_pubkey_hex: Some(keys.public_key().to_hex()),
        kind: Some(kind),
        identifier: Some(identifier.into()),
    }
}

#[test]
fn cold_coordinate_batches_fence_their_verified_selection() {
    let (_dir, cache) = fixture();
    let now = 5000;

    // [target, valid e deletion] on an empty cache is authoritative, in
    // either order, and the exact-ID alias agrees.
    for inverted in [false, true] {
        let keys = Keys::generate();
        let naddr = address(&keys, 30023);
        let target = signed(&keys, 30023, 1000, "cold target");
        let request = deletion(&keys, 1100, vec![e_tag(&target)]);
        let batch = if inverted {
            vec![request.as_json(), target.as_json()]
        } else {
            vec![target.as_json(), request.as_json()]
        };
        let state = cache.admit_state(&naddr, &batch, now).unwrap();
        let PublicEventCacheResult::AuthoritativeDeleted(evidence) = &state else {
            panic!("a cold verified deletion must not read as Missing: {state:?}");
        };
        assert_eq!(request.as_json(), evidence.deletion_event_json);
        assert!(is_deleted(&cache.lookup_state(&naddr, now).unwrap()));
        assert!(is_deleted(
            &cache.lookup_state(&id_reference(&target), now).unwrap()
        ));
        assert!(
            is_deleted(&cache.admit_state(&naddr, &[target.as_json()], now).unwrap()),
            "replaying the target cannot resurrect it"
        );
    }

    // A deletion by another author has no authority.
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let target = signed(&keys, 30023, 1000, "kept");
    let forged = deletion(&Keys::generate(), 1100, vec![e_tag(&target)]);
    assert_eq!(
        Some(target.id.to_hex()),
        present_id(
            &cache
                .admit_state(&naddr, &[target.as_json(), forged.as_json()], now)
                .unwrap()
        )
    );

    // A deletion naming an unknown target authenticates nothing.
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let unseen = signed(&keys, 30023, 1000, "never admitted");
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache
            .admit_state(
                &naddr,
                &[deletion(&keys, 1100, vec![e_tag(&unseen)]).as_json()],
                now
            )
            .unwrap()
    );

    // Deleting the latest version fences the older one too.
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let older = signed(&keys, 30023, 1000, "older");
    let latest = signed(&keys, 30023, 1200, "latest");
    let request = deletion(&keys, 1300, vec![e_tag(&latest)]);
    assert!(is_deleted(
        &cache
            .admit_state(
                &naddr,
                &[older.as_json(), latest.as_json(), request.as_json()],
                now
            )
            .unwrap()
    ));
    assert!(is_deleted(
        &cache.admit_state(&naddr, &[older.as_json()], now).unwrap()
    ));

    // Deleting an older version leaves the latest selected.
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let older = signed(&keys, 30023, 1000, "older");
    let latest = signed(&keys, 30023, 1200, "latest");
    let request = deletion(&keys, 1300, vec![e_tag(&older)]);
    assert_eq!(
        Some(latest.id.to_hex()),
        present_id(
            &cache
                .admit_state(
                    &naddr,
                    &[older.as_json(), latest.as_json(), request.as_json()],
                    now
                )
                .unwrap()
        )
    );
    assert!(is_deleted(
        &cache.lookup_state(&id_reference(&older), now).unwrap()
    ));

    // Same-second ties: the lowest ID is the selection.
    for delete_lowest in [true, false] {
        let keys = Keys::generate();
        let naddr = address(&keys, 30023);
        let a = signed(&keys, 30023, 1000, "tie a");
        let b = signed(&keys, 30023, 1000, "tie b");
        let (lowest, highest) = if a.id < b.id { (&a, &b) } else { (&b, &a) };
        let deleted = if delete_lowest { lowest } else { highest };
        let request = deletion(&keys, 1100, vec![e_tag(deleted)]);
        let state = cache
            .admit_state(&naddr, &[a.as_json(), b.as_json(), request.as_json()], now)
            .unwrap();
        if delete_lowest {
            assert!(
                is_deleted(&state),
                "the tie loser cannot replace the deleted selection"
            );
        } else {
            assert_eq!(Some(lowest.id.to_hex()), present_id(&state));
        }
    }
}

#[test]
fn a_cohort_over_its_tombstone_cap_is_evicted_whole() {
    let (_dir, cache) = fixture();
    let now = 6000;
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let newest = signed(&keys, 30023, 5000, "newest");
    assert_eq!(
        Some(newest.id.to_hex()),
        present_id(&cache.admit_state(&naddr, &[newest.as_json()], now).unwrap())
    );
    let versions: Vec<Event> = (0..=MAX_COHORT_TOMBSTONES as u64)
        .map(|i| signed(&keys, 30023, 1000 + i, &format!("version {i}")))
        .collect();
    let delete = |version: &Event, at: u64| {
        cache
            .admit_state(
                &id_reference(version),
                &[
                    version.as_json(),
                    deletion(&keys, at, vec![e_tag(version)]).as_json(),
                ],
                now,
            )
            .unwrap()
    };
    for (i, version) in versions
        .iter()
        .enumerate()
        .take(MAX_COHORT_TOMBSTONES as usize)
    {
        assert!(is_deleted(&delete(version, 2000 + i as u64)));
    }
    assert_eq!(
        MAX_COHORT_TOMBSTONES,
        count(&cache, "public_event_tombstones")
    );
    // While any of the cohort is retained, its oldest deleted version cannot
    // come back by exact ID and the newer selection stays.
    assert!(is_deleted(
        &cache
            .admit_state(&id_reference(&versions[0]), &[versions[0].as_json()], now)
            .unwrap()
    ));
    assert_eq!(
        Some(newest.id.to_hex()),
        present_id(&cache.lookup_state(&naddr, now).unwrap())
    );

    // The 65th deletion evicts the whole cohort: selection, aliases, evidence.
    let last = versions.last().unwrap();
    assert_eq!(
        PublicEventCacheResult::Missing,
        delete(last, 3000),
        "members of an evicted cohort do not return from the same batch"
    );
    assert_eq!(0, count(&cache, "public_event_tombstones"));
    assert_eq!(0, count(&cache, "public_event_previews"));
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache.lookup_state(&naddr, now).unwrap()
    );
    // Complete eviction ends local deletion knowledge: the cohort starts over
    // exactly like a cold cache.
    assert_eq!(
        Some(versions[0].id.to_hex()),
        present_id(
            &cache
                .admit_state(&id_reference(&versions[0]), &[versions[0].as_json()], now)
                .unwrap()
        )
    );
}

#[test]
fn tombstone_provenance_is_mac_bound_and_tampering_fails_closed() {
    let now = 5000;
    let other_author = Keys::generate().public_key().to_hex();
    let tampering: Vec<(&str, Option<String>)> = vec![
        ("rank_created_at = rank_created_at + 1000", None),
        ("rank_created_at = rank_created_at - 1", None),
        ("rank_event_id = ?2", Some("0".repeat(64))),
        ("target_kind = 30024", None),
        ("target_kind = 1", None),
        ("fences_selection = 1 - fences_selection", None),
        ("received_at = received_at + 1", None),
        ("proof_pubkey = ?2", Some(other_author)),
        (
            "proof_event_id = NULL, proof_pubkey = NULL, proof_sig = NULL",
            None,
        ),
        ("provenance_mac = zeroblob(32)", None),
        ("projection_version = 2", None),
    ];
    for (assignment, value) in tampering {
        let (_dir, cache) = fixture();
        let keys = Keys::generate();
        let naddr = address(&keys, 30023);
        let target = signed(&keys, 30023, 1000, "target");
        assert!(is_deleted(
            &cache
                .admit_state(
                    &naddr,
                    &[
                        target.as_json(),
                        deletion(&keys, 1100, vec![e_tag(&target)]).as_json()
                    ],
                    now
                )
                .unwrap()
        ));
        let cache_key = format!("event:{}", target.id.to_hex());
        {
            let conn = cache.conn.lock().unwrap();
            let sql =
                format!("UPDATE public_event_tombstones SET {assignment} WHERE cache_key = ?1");
            let changed = match &value {
                Some(value) => conn.execute(&sql, params![cache_key, value]),
                None => conn.execute(&sql, params![cache_key]),
            }
            .unwrap();
            assert_eq!(1, changed, "{assignment}");
        }
        assert!(
            cache.lookup_state(&id_reference(&target), now).is_err(),
            "{assignment} must fail closed for the exact ID"
        );
        assert!(
            cache.lookup_state(&naddr, now).is_err(),
            "{assignment} must fail closed for the coordinate"
        );
    }
}

#[test]
fn moving_or_rewriting_signed_evidence_cannot_suppress_other_content() {
    let now = 5000;
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let other = address_d(&keys, 30023, "other");
    let target = signed(&keys, 30023, 1000, "target");
    let unrelated = signed_d(&keys, 30023, 900, "unrelated", "other");
    assert_eq!(
        Some(unrelated.id.to_hex()),
        present_id(
            &cache
                .admit_state(&other, &[unrelated.as_json()], now)
                .unwrap()
        )
    );
    assert!(is_deleted(
        &cache
            .admit_state(
                &naddr,
                &[
                    target.as_json(),
                    deletion(&keys, 1100, vec![e_tag(&target)]).as_json()
                ],
                now
            )
            .unwrap()
    ));
    let cache_key = format!("event:{}", target.id.to_hex());

    // Both signatures stay valid, but the retained cohort and rank now claim
    // to fence the unrelated coordinate above its selection.
    cache
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE public_event_tombstones SET cohort_key = ?2 WHERE cache_key = ?1",
            params![cache_key, other.key().unwrap()],
        )
        .unwrap();
    assert!(
        cache.lookup_state(&other, now).is_err(),
        "a moved tombstone fails closed instead of reading as a deletion"
    );
    assert!(cache.lookup_state(&id_reference(&target), now).is_err());

    // A different valid deletion by the same author still breaks the MAC.
    let (_dir, cache) = fixture();
    assert!(is_deleted(
        &cache
            .admit_state(
                &naddr,
                &[
                    target.as_json(),
                    deletion(&keys, 1100, vec![e_tag(&target)]).as_json()
                ],
                now
            )
            .unwrap()
    ));
    let substitute = deletion(&keys, 1200, vec![e_tag(&target)]);
    cache
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE public_event_tombstones SET deletion_json = ?2 WHERE cache_key = ?1",
            params![cache_key, substitute.as_json()],
        )
        .unwrap();
    assert!(cache.lookup_state(&id_reference(&target), now).is_err());

    // Rewriting a selection row's rank columns cannot change its fence: the
    // row is re-derived from its signed event and dropped as malformed.
    let (_dir, cache) = fixture();
    let selection = signed(&keys, 30023, 1000, "selection");
    cache
        .admit_state(&naddr, &[selection.as_json()], now)
        .unwrap();
    cache
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE public_event_previews SET rank_created_at = 9999, cohort_key = ?1",
            params![other.key().unwrap()],
        )
        .unwrap();
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache.lookup_state(&naddr, now).unwrap()
    );
    assert_eq!(0, count(&cache, "public_event_previews"));
}

#[test]
fn eviction_removes_whole_cohorts_and_documents_the_end_of_deletion_knowledge() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let naddr = address(&keys, 30023);
    let v2 = signed(&keys, 30023, 1100, "v2");
    let v3 = signed(&keys, 30023, 1300, "v3");
    cache.admit(&naddr, &[v2.as_json()], 2000).unwrap();
    cache
        .admit(
            &naddr,
            &[deletion(&keys, 1200, vec![e_tag(&v2)]).as_json()],
            2000,
        )
        .unwrap();
    cache.admit(&naddr, &[v3.as_json()], 2000).unwrap();
    cache
        .admit(&id_reference(&v3), &[v3.as_json()], 2000)
        .unwrap();
    let note = signed(&Keys::generate(), 1, 1000, "protected");
    let protected = id_reference(&note);
    cache.admit(&protected, &[note.as_json()], 3000).unwrap();
    assert_eq!(3, count(&cache, "public_event_previews"));
    assert_eq!(1, count(&cache, "public_event_tombstones"));
    {
        let mut conn = cache.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..(MAX_ENTRIES - 2) {
            tx.execute(
                "INSERT INTO public_event_previews (cache_key, event_json, received_at, touched_at, bytes)
                 VALUES (?1, 'fixture', 1, 5000, 1)",
                [format!("fixture:{i}")],
            )
            .unwrap();
        }
        PublicEventCache::trim(&tx, &cache.provenance, &protected.key().unwrap()).unwrap();
        tx.commit().unwrap();
    }
    // The coordinate, its exact-ID alias and its tombstone left together.
    assert_eq!(0, count(&cache, "public_event_tombstones"));
    assert_eq!(MAX_ENTRIES - 1, count(&cache, "public_event_previews"));
    assert!(cache.lookup(&protected, 3001).unwrap().is_some());
    assert_eq!(None, cache.lookup(&id_reference(&v3), 3001).unwrap());
    // Complete eviction ends local deletion knowledge for that cohort.
    assert_eq!(
        Some(v2.id.to_hex()),
        present_id(&cache.admit_state(&naddr, &[v2.as_json()], 3001).unwrap())
    );
}

#[test]
fn refresh_admission_coalesces_cools_down_and_stays_bounded() {
    let (_dir, cache) = fixture();
    let RefreshAdmission::Lead(lease) = cache.begin_refresh("event:a") else {
        panic!("first refresh leads");
    };
    let RefreshAdmission::Coalesced(waiter) = cache.begin_refresh("event:a") else {
        panic!("a concurrent refresh coalesces");
    };
    drop(lease);
    assert!(
        waiter.has_changed().is_err(),
        "dropping the lead wakes waiters"
    );
    let RefreshAdmission::Lead(mut lease) = cache.begin_refresh("event:a") else {
        panic!("an unattempted refresh starts no cooldown");
    };
    lease.mark_attempted();
    drop(lease);
    assert!(matches!(
        cache.begin_refresh("event:a"),
        RefreshAdmission::CoolingDown
    ));
    let leases = (0..MAX_INFLIGHT_REFRESHES)
        .map(|i| match cache.begin_refresh(&format!("event:{i}")) {
            RefreshAdmission::Lead(lease) => lease,
            _ => panic!("capacity remains"),
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        cache.begin_refresh("event:overflow"),
        RefreshAdmission::Saturated
    ));
    drop(leases);
}

#[test]
fn stale_handle_incarnations_cannot_persist_late_refreshes() {
    let dir = tempfile::tempdir().unwrap();
    let home = AccountHome::open(dir.path());
    let alice = home.create_account("alice").unwrap();
    let app = MarmotApp::with_relay(dir.path(), "wss://relay.example");
    let event = signed(&Keys::generate(), 1, 1000, "late refresh");
    let reference = id_reference(&event);
    let first = app.public_event_cache_for_account(&alice).unwrap();
    assert!(app.public_event_cache_is_current("alice", &first));
    app.drop_account_caches("alice");
    assert!(!app.public_event_cache_is_current("alice", &first));
    let second = app.public_event_cache_for_account(&alice).unwrap();
    assert!(!app.public_event_cache_is_current("alice", &first));
    assert!(app.public_event_cache_is_current("alice", &second));
    assert!(first.admit(&reference, &[event.as_json()], 2000).is_err());
    assert_eq!(None, second.lookup(&reference, 2000).unwrap());
    app.close_storage().unwrap();
    assert!(!app.public_event_cache_is_current("alice", &second));
}

#[test]
fn relocated_renamed_or_missing_tombstones_cannot_resurrect_the_original_coordinate() {
    let now = 5000;
    let cases = [
        "move the evidence to another cohort",
        "rename its index key",
        "delete the evidence row",
        "delete the inventory",
        "forge the inventory",
        "understate the inventory count",
    ];
    for (case, description) in cases.iter().enumerate() {
        let (_dir, cache) = fixture();
        let keys = Keys::generate();
        let naddr = address(&keys, 30023);
        let other = address_d(&keys, 30023, "other");
        let older = signed(&keys, 30023, 1000, "older");
        let latest = signed(&keys, 30023, 1100, "latest");
        let unrelated = signed_d(&keys, 30023, 900, "unrelated", "other");
        cache
            .admit_state(&other, &[unrelated.as_json()], now)
            .unwrap();
        assert_eq!(
            Some(latest.id.to_hex()),
            present_id(
                &cache
                    .admit_state(&naddr, &[older.as_json(), latest.as_json()], now)
                    .unwrap()
            )
        );
        assert!(is_deleted(
            &cache
                .admit_state(
                    &naddr,
                    &[deletion(&keys, 1200, vec![e_tag(&latest)]).as_json()],
                    now
                )
                .unwrap()
        ));
        // Untampered, the deleted selection fences the older version.
        assert!(is_deleted(
            &cache.admit_state(&naddr, &[older.as_json()], now).unwrap()
        ));
        assert_eq!(1, count(&cache, "public_event_tombstones"));
        let cache_key = format!("event:{}", latest.id.to_hex());
        {
            let conn = cache.conn.lock().unwrap();
            let changed = match case {
                0 => conn.execute(
                    "UPDATE public_event_tombstones SET cohort_key = ?2 WHERE cache_key = ?1",
                    params![cache_key, other.key().unwrap()],
                ),
                1 => conn.execute(
                    "UPDATE public_event_tombstones SET cache_key = ?2 WHERE cache_key = ?1",
                    params![cache_key, format!("event:{}", "0".repeat(64))],
                ),
                2 => conn.execute(
                    "DELETE FROM public_event_tombstones WHERE cache_key = ?1",
                    [&cache_key],
                ),
                3 => conn.execute("DELETE FROM public_event_tombstone_inventory", []),
                4 => conn.execute(
                    "UPDATE public_event_tombstone_inventory SET inventory_mac = zeroblob(32)",
                    [],
                ),
                _ => conn.execute(
                    "UPDATE public_event_tombstone_inventory SET tombstone_count = 0",
                    [],
                ),
            }
            .unwrap();
            assert_eq!(1, changed, "{description}");
        }
        // The original coordinate neither reads as present nor as missing...
        assert!(
            cache.lookup_state(&naddr, now).is_err(),
            "{description}: original coordinate read"
        );
        // ...its older version cannot be admitted again...
        assert!(
            cache.admit_state(&naddr, &[older.as_json()], now).is_err(),
            "{description}: older admission"
        );
        assert!(
            cache
                .admit_state(&id_reference(&older), &[older.as_json()], now)
                .is_err(),
            "{description}: older exact-ID admission"
        );
        assert!(
            cache
                .admit_state(&id_reference(&latest), &[latest.as_json()], now)
                .is_err(),
            "{description}: deleted exact-ID admission"
        );
        // ...and neither the destination nor a batch read trusts the index.
        assert!(cache.lookup_state(&other, now).is_err(), "{description}");
        assert!(
            cache
                .lookup_states(&[other.clone(), naddr.clone()], now)
                .is_err(),
            "{description}"
        );
    }
}

#[test]
fn the_inventory_scan_reads_only_its_covering_index() {
    let (_dir, cache) = fixture();
    let conn = cache.conn.lock().unwrap();
    let plan: Vec<String> = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {INVENTORY_SCAN_SQL}"))
        .unwrap()
        .query_map([MAX_ENTRIES + 1], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("COVERING INDEX public_event_tombstones_inventory")),
        "signed payload pages are never read to verify the inventory: {plan:?}"
    );
}

#[test]
fn byte_budget_recomputes_every_retained_field_and_ignores_understated_sizes() {
    let (_dir, cache) = fixture();
    let event = signed(&Keys::generate(), 1, 1000, "selected");
    let reference = id_reference(&event);
    cache.admit(&reference, &[event.as_json()], 1000).unwrap();
    let keys = Keys::generate();
    let note = signed(&keys, 1, 1000, "deleted");
    assert!(is_deleted(
        &cache
            .admit_state(
                &id_reference(&note),
                &[
                    note.as_json(),
                    deletion(&keys, 1100, vec![e_tag(&note)]).as_json()
                ],
                1000
            )
            .unwrap()
    ));
    {
        let conn = cache.conn.lock().unwrap();
        let (stored, logical, deletion_bytes): (i64, i64, i64) = conn
            .query_row(
                &format!(
                    "SELECT bytes, {TOMBSTONE_LOGICAL_BYTES_SQL}, octet_length(deletion_json)
                     FROM public_event_tombstones"
                ),
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored, logical, "stored and recomputed accounting agree");
        assert!(
            logical > deletion_bytes + 64 + 2 * 70 + 256,
            "keys, proof, rank ID and MAC are charged, not only the signed JSON"
        );
        conn.execute("UPDATE public_event_tombstones SET bytes = 1", [])
            .unwrap();
        conn.execute("UPDATE public_event_previews SET bytes = 1", [])
            .unwrap();
        let (_, total) = PublicEventCache::retained_totals(&conn).unwrap();
        assert!(
            total >= logical + INVENTORY_BYTES + event.as_json().len() as i64,
            "an understated stored size is never trusted"
        );
    }
    // About 34 MiB of retained payload whose stored sizes claim one byte each.
    {
        let mut conn = cache.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        let payload = "x".repeat(220 * 1024);
        for i in 0..160 {
            tx.execute(
                "INSERT INTO public_event_previews (cache_key, event_json, received_at, touched_at, bytes)
                 VALUES (?1, ?2, 1, 1, 1)",
                params![format!("fixture:{i}"), payload],
            )
            .unwrap();
        }
        let (_, before) = PublicEventCache::retained_totals(&tx).unwrap();
        assert!(before > MAX_TOTAL_BYTES);
        PublicEventCache::trim(&tx, &cache.provenance, &reference.key().unwrap()).unwrap();
        let (_, after) = PublicEventCache::retained_totals(&tx).unwrap();
        assert!(after <= MAX_TOTAL_BYTES, "{after} bytes remain");
        tx.commit().unwrap();
    }
    assert!(cache.lookup(&reference, 1001).unwrap().is_some());
    assert!(
        is_deleted(&cache.lookup_state(&id_reference(&note), 1001).unwrap()),
        "least recently touched cohorts went first; the inventory stayed authentic"
    );
}

#[test]
fn oversized_coordinates_are_rejected_for_immutable_ids_without_reduced_deletion_semantics() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    for size in [1025, 200 * 1024] {
        let event = signed_d(
            &keys,
            30023,
            1000,
            "unsupported coordinate",
            &"d".repeat(size),
        );
        assert!(event.as_json().len() <= MAX_EVENT_BYTES);
        let exact = id_reference(&event);
        assert_eq!(
            PublicEventCacheResult::Missing,
            cache.admit_state(&exact, &[event.as_json()], 5000).unwrap()
        );
        assert_eq!(
            PublicEventCacheResult::Missing,
            cache.lookup_state(&exact, 5000).unwrap()
        );
    }
    assert_eq!(0, count(&cache, "public_event_previews"));
    assert_eq!(0, count(&cache, "public_event_tombstones"));
}

#[test]
fn migration_rejects_oversized_coordinates_and_enforces_index_inclusive_limits() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.sqlite3");
    let key = SqlCipherKey::new("public-event-test").unwrap();
    let keys = Keys::generate();
    let oversized = signed_d(&keys, 30023, 1000, "unsupported", &"x".repeat(1025));
    {
        let mut conn = Connection::open(&path).unwrap();
        open_hardened_sqlcipher(&conn, &key, SqlCipherHardening::live_cache()).unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
        let tx = conn.transaction().unwrap();
        for i in 0..128 {
            let identifier = format!("{i:04}{}", "d".repeat(1020));
            let event = signed_d(&keys, 30023, 1000, &"x".repeat(250 * 1024), &identifier);
            let cache_key = address_d(&keys, 30023, &identifier).key().unwrap();
            let json = event.as_json();
            assert!(json.len() <= MAX_EVENT_BYTES);
            tx.execute(
                "INSERT INTO public_event_previews VALUES (?1, ?2, 5000, 5000, ?3)",
                params![cache_key, json, json.len() as i64],
            )
            .unwrap();
        }
        let json = oversized.as_json();
        tx.execute(
            "INSERT INTO public_event_previews VALUES (?1, ?2, 5000, 5000, ?3)",
            params![
                id_reference(&oversized).key().unwrap(),
                json,
                json.len() as i64
            ],
        )
        .unwrap();
        tx.commit().unwrap();
    }
    let cache = PublicEventCache::open(&path, &key, Duration::from_secs(300)).unwrap();
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache.lookup_state(&id_reference(&oversized), 5000).unwrap()
    );
    let conn = cache.conn.lock().unwrap();
    let (rows, bytes) = PublicEventCache::retained_totals(&conn).unwrap();
    assert!(rows <= MAX_ENTRIES && bytes <= MAX_TOTAL_BYTES);
    assert!(
        rows < 128,
        "migration evicts entire cohorts before its commit"
    );
}

#[test]
fn exact_id_deletion_promotes_a_coordinate_fence_without_repeated_evidence_and_survives_reopen() {
    let (dir, cache) = fixture();
    let keys = Keys::generate();
    let event = signed(&keys, 30023, 1000, "deleted coordinate");
    let request = deletion(&keys, 1100, vec![e_tag(&event)]);
    assert!(is_deleted(
        &cache
            .admit_state(
                &id_reference(&event),
                &[event.as_json(), request.as_json()],
                1200
            )
            .unwrap()
    ));
    let coordinate = address(&keys, 30023);
    assert!(is_deleted(
        &cache
            .admit_state(&coordinate, &[event.as_json()], 1201)
            .unwrap()
    ));
    cache.close().unwrap();
    let reopened = PublicEventCache::open(
        &dir.path().join("events.sqlite3"),
        &SqlCipherKey::new("public-event-test").unwrap(),
        Duration::from_secs(300),
    )
    .unwrap();
    assert!(is_deleted(
        &reopened.lookup_state(&coordinate, 1202).unwrap()
    ));
    let newer = signed(&keys, 30023, 1203, "newer live selection");
    assert_eq!(
        Some(newer.id.to_hex()),
        present_id(
            &reopened
                .admit_state(&coordinate, &[newer.as_json()], 1203)
                .unwrap()
        )
    );
    assert_eq!(
        Some(newer.id.to_hex()),
        present_id(
            &reopened
                .admit_state(&coordinate, &[event.as_json()], 1204)
                .unwrap()
        )
    );
}

#[test]
fn retained_exact_id_rank_fences_promote_the_original_evidence_not_an_older_target() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let older = signed(&keys, 30023, 900, "older");
    let newer = signed(&keys, 30023, 1000, "deleted newer");
    let request = deletion(&keys, 1100, vec![e_tag(&newer)]);
    assert!(is_deleted(
        &cache
            .admit_state(
                &id_reference(&newer),
                &[newer.as_json(), request.as_json()],
                1200
            )
            .unwrap()
    ));
    let coordinate = address(&keys, 30023);
    assert!(is_deleted(
        &cache
            .admit_state(&coordinate, &[older.as_json()], 1201)
            .unwrap()
    ));
    assert_eq!(
        PublicEventCacheResult::Missing,
        cache.lookup_state(&id_reference(&older), 1201).unwrap()
    );
    assert_eq!(1, count(&cache, "public_event_tombstones"));
}

#[test]
fn coordinate_fence_promotion_trims_overfull_inventory_before_authenticating_it() {
    let (_dir, cache) = fixture();
    let keys = Keys::generate();
    let v1 = signed(&keys, 30023, 900, "v1");
    let v2 = signed(&keys, 30023, 1000, "v2");
    let v3 = signed(&keys, 30023, 1100, "deleted v3");
    let now = 5000;
    let mut conn = cache.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    for i in 0..1023 {
        let target = signed(&keys, 1, 1000 + i, &format!("unrelated {i}"));
        let request = deletion(&keys, 4000, vec![e_tag(&target)]);
        PublicEventCache::record_event_tombstone(
            &tx,
            &cache.provenance,
            &target,
            &request,
            false,
            now,
        )
        .unwrap();
    }
    let request_v3 = deletion(&keys, 4000, vec![e_tag(&v3)]);
    PublicEventCache::record_event_tombstone(&tx, &cache.provenance, &v3, &request_v3, false, now)
        .unwrap();
    PublicEventCache::write_inventory(&tx, &cache.provenance).unwrap();
    tx.commit().unwrap();
    drop(conn);
    let request_v1 = deletion(&keys, 4000, vec![e_tag(&v1)]);
    let coordinate = address(&keys, 30023);
    assert!(is_deleted(
        &cache
            .admit_state(
                &coordinate,
                &[v1.as_json(), v2.as_json(), request_v1.as_json()],
                now
            )
            .unwrap()
    ));
    assert!(count(&cache, "public_event_tombstones") <= MAX_ENTRIES);
    assert!(is_deleted(&cache.lookup_state(&coordinate, now).unwrap()));
}
