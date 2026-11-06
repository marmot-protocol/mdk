use super::*;
use crate::SqliteAccountStorage;

const LIMITS: EmojiSetInstallLimits = EmojiSetInstallLimits {
    max_sets: 2,
    max_total_bytes: 64,
};

fn storage() -> SqliteAppStorage {
    SqliteAccountStorage::in_memory().unwrap().app_storage()
}

fn coordinate(identifier: &str) -> String {
    format!("30030:{}:{identifier}", "aa".repeat(32))
}

fn discovered(identifier: &str, event_id: &str, created_at: u64) -> StoredEmojiSet {
    StoredEmojiSet {
        coordinate: coordinate(identifier),
        kind: 30030,
        author_pubkey_hex: "aa".repeat(32),
        identifier: identifier.to_owned(),
        version: StoredEmojiSetVersion {
            event_id_hex: event_id.to_owned(),
            created_at,
        },
        title: Some(format!("{identifier} set")),
        description: None,
        image_url: None,
        emoji: vec![StoredEmojiSetEntry {
            shortcode: "Wave_1".to_owned(),
            url: "https://cdn.example/wave.png".to_owned(),
        }],
        skipped: vec![StoredEmojiSkip {
            position: 1,
            shortcode: None,
            reason: "invalid_shortcode".to_owned(),
        }],
        skipped_count: 1,
    }
}

fn snapshot(identifier: &str, event_id: &str) -> StoredInstalledEmojiSet {
    StoredInstalledEmojiSet {
        coordinate: coordinate(identifier),
        kind: 30030,
        author_pubkey_hex: "aa".repeat(32),
        identifier: identifier.to_owned(),
        version: StoredEmojiSetVersion {
            event_id_hex: event_id.to_owned(),
            created_at: 10,
        },
        title: Some(format!("{identifier} set")),
        description: None,
        installed_at: 100,
        emoji_count: 0,
        byte_len: 0,
    }
}

fn emoji(shortcode: &str, bytes: &[u8]) -> (StoredInstalledEmoji, Vec<u8>) {
    (
        StoredInstalledEmoji {
            shortcode: shortcode.to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
            mime: "image/png".to_owned(),
            width: 16,
            height: 16,
            frames: 1,
            byte_len: bytes.len() as u64,
        },
        bytes.to_vec(),
    )
}

#[test]
fn discovered_set_replacement_follows_nip01_order() {
    let store = storage();
    let current = discovered("cats", &"bb".repeat(32), 10);
    assert!(store.replace_emoji_set_if_newer(&current).unwrap());
    assert_eq!(
        store.emoji_set(&current.coordinate).unwrap(),
        Some(current.clone())
    );

    // Older, and an equal timestamp with a higher id, both lose.
    let mut older = discovered("cats", &"aa".repeat(32), 9);
    older.title = Some("older".to_owned());
    assert!(!store.replace_emoji_set_if_newer(&older).unwrap());
    let mut tie_high = discovered("cats", &"cc".repeat(32), 10);
    tie_high.title = Some("tie high".to_owned());
    assert!(!store.replace_emoji_set_if_newer(&tie_high).unwrap());

    // An equal timestamp with a lower id, then a newer version, win.
    let mut tie_low = discovered("cats", &"ab".repeat(32), 10);
    tie_low.emoji.clear();
    assert!(store.replace_emoji_set_if_newer(&tie_low).unwrap());
    assert!(
        store
            .emoji_set(&tie_low.coordinate)
            .unwrap()
            .unwrap()
            .emoji
            .is_empty()
    );

    let mut bad = discovered("cats", "", 11);
    assert!(store.replace_emoji_set_if_newer(&bad).is_err());
    bad.version.event_id_hex = "AB".repeat(32);
    assert!(store.replace_emoji_set_if_newer(&bad).is_err());
}

#[test]
fn search_matches_title_author_and_shortcode_literally() {
    let store = storage();
    let mut dogs = discovered("dogs", &"bb".repeat(32), 20);
    dogs.author_pubkey_hex = "cd".repeat(32);
    dogs.title = Some("100% Dogs".to_owned());
    dogs.emoji[0].shortcode = "bork".to_owned();
    store.replace_emoji_set_if_newer(&dogs).unwrap();
    store
        .replace_emoji_set_if_newer(&discovered("cats", &"cc".repeat(32), 10))
        .unwrap();

    let found = |search: &str| {
        store
            .emoji_sets(false, Some(search), 50)
            .unwrap()
            .into_iter()
            .map(|set| set.identifier)
            .collect::<Vec<_>>()
    };
    assert_eq!(found("DOGS"), vec!["dogs"]);
    assert_eq!(found(&"cd".repeat(4)), vec!["dogs"]);
    assert_eq!(found("BORK"), vec!["dogs"]);
    assert_eq!(found("wave_"), vec!["cats"]);
    // LIKE metacharacters are literal.
    assert_eq!(found("100%"), vec!["dogs"]);
    assert!(found("1%0").is_empty());
    assert_eq!(found("  "), vec!["dogs", "cats"]);
}

#[test]
fn install_pins_bytes_hash_and_version_until_reinstall() {
    let store = storage();
    let set = discovered("cats", &"bb".repeat(32), 10);
    store.replace_emoji_set_if_newer(&set).unwrap();
    let first = emoji("Wave_1", b"first image");
    assert_eq!(
        store
            .install_emoji_set(
                &snapshot("cats", &"bb".repeat(32)),
                std::slice::from_ref(&first),
                LIMITS
            )
            .unwrap(),
        EmojiSetInstallOutcome::Installed
    );

    // A newer discovered version changes the URL; the installed bytes and
    // version do not move.
    let mut newer = discovered("cats", &"cc".repeat(32), 11);
    newer.emoji[0].url = "https://elsewhere.example/wave.png".to_owned();
    store.replace_emoji_set_if_newer(&newer).unwrap();
    let (row, bytes) = store
        .installed_custom_emoji_bytes(&set.coordinate, "Wave_1")
        .unwrap()
        .unwrap();
    assert_eq!(bytes, first.1);
    assert_eq!(row.emoji, first.0);
    let installed = store.installed_emoji_set(&set.coordinate).unwrap().unwrap();
    assert_eq!(installed.version.event_id_hex, "bb".repeat(32));
    assert_eq!((installed.emoji_count, installed.byte_len), (1, 11));

    // Reinstalling replaces the snapshot as a whole.
    let second = emoji("Other", b"second");
    store
        .install_emoji_set(
            &snapshot("cats", &"cc".repeat(32)),
            std::slice::from_ref(&second),
            LIMITS,
        )
        .unwrap();
    assert!(
        store
            .installed_custom_emoji_bytes(&set.coordinate, "Wave_1")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .installed_custom_emoji_bytes(&set.coordinate, "Other")
            .unwrap()
            .unwrap()
            .1,
        second.1
    );

    // Bytes that do not hash to their recorded digest never land.
    let mut forged = emoji("Forged", b"real");
    forged.1 = b"swap".to_vec();
    assert!(
        store
            .install_emoji_set(&snapshot("cats", &"cc".repeat(32)), &[forged], LIMITS)
            .is_err()
    );
    assert!(
        store
            .install_emoji_set(&snapshot("cats", &"cc".repeat(32)), &[], LIMITS)
            .is_err()
    );
}

#[test]
fn install_caps_refuse_without_changing_existing_snapshots() {
    let store = storage();
    for (name, id) in [("a", "aa"), ("b", "bb")] {
        store
            .install_emoji_set(
                &snapshot(name, &id.repeat(32)),
                &[emoji("x", &[0; 16])],
                LIMITS,
            )
            .unwrap();
    }
    assert_eq!(
        store
            .install_emoji_set(
                &snapshot("c", &"cc".repeat(32)),
                &[emoji("x", &[0; 1])],
                LIMITS
            )
            .unwrap(),
        EmojiSetInstallOutcome::TooManySets
    );
    // A reinstall at the set cap is allowed, but not past the byte budget.
    assert_eq!(
        store
            .install_emoji_set(
                &snapshot("a", &"aa".repeat(32)),
                &[emoji("y", &[1; 49])],
                LIMITS
            )
            .unwrap(),
        EmojiSetInstallOutcome::OverByteBudget
    );
    assert_eq!(
        store
            .install_emoji_set(
                &snapshot("a", &"aa".repeat(32)),
                &[emoji("y", &[1; 48])],
                LIMITS
            )
            .unwrap(),
        EmojiSetInstallOutcome::Installed
    );
    // The refused installs left nothing behind; the reinstall kept its place.
    let rows = store.installed_custom_emoji().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| (row.set_coordinate.clone(), row.emoji.shortcode.clone()))
            .collect::<Vec<_>>(),
        vec![
            (coordinate("a"), "y".to_owned()),
            (coordinate("b"), "x".to_owned())
        ]
    );
    assert_eq!(
        store
            .installed_emoji_bytes_excluding(&coordinate("a"))
            .unwrap(),
        16
    );
}

#[test]
fn uninstall_removes_stored_bytes_and_unprotects_discovery() {
    let store = storage();
    let set = discovered("cats", &"bb".repeat(32), 1);
    store.replace_emoji_set_if_newer(&set).unwrap();
    store
        .replace_emoji_set_if_newer(&discovered("dogs", &"cc".repeat(32), 2))
        .unwrap();
    store
        .install_emoji_set(
            &snapshot("cats", &"bb".repeat(32)),
            &[emoji("Wave_1", b"png")],
            LIMITS,
        )
        .unwrap();

    // Installed sets survive pruning, whatever their age.
    assert_eq!(store.prune_uninstalled_emoji_sets(1, &[]).unwrap(), 1);
    assert!(store.emoji_set(&set.coordinate).unwrap().is_some());
    assert!(store.emoji_set(&coordinate("dogs")).unwrap().is_none());
    assert_eq!(
        store.emoji_sets(true, None, 10).unwrap(),
        vec![store.emoji_set(&set.coordinate).unwrap().unwrap()]
    );

    assert!(store.uninstall_emoji_set(&set.coordinate).unwrap());
    assert!(!store.uninstall_emoji_set(&set.coordinate).unwrap());
    let bytes_left: i64 = store
        .lock()
        .unwrap()
        .query_row("SELECT COUNT(*) FROM app_installed_emoji", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(bytes_left, 0);
    assert!(store.installed_custom_emoji().unwrap().is_empty());
    assert!(store.emoji_sets(true, None, 10).unwrap().is_empty());

    // `keep` protects a set the caller is about to return.
    store
        .replace_emoji_set_if_newer(&discovered("dogs", &"cc".repeat(32), 2))
        .unwrap();
    assert_eq!(
        store
            .prune_uninstalled_emoji_sets(1, std::slice::from_ref(&set.coordinate))
            .unwrap(),
        1
    );
    assert!(store.emoji_set(&set.coordinate).unwrap().is_some());
}

#[test]
fn corrupt_stored_bytes_fail_the_read() {
    let store = storage();
    store
        .install_emoji_set(
            &snapshot("cats", &"bb".repeat(32)),
            &[emoji("Wave_1", b"png")],
            LIMITS,
        )
        .unwrap();
    store
        .lock()
        .unwrap()
        .execute("UPDATE app_installed_emoji SET bytes = X'00'", [])
        .unwrap();
    assert!(
        store
            .installed_custom_emoji_bytes(&coordinate("cats"), "Wave_1")
            .is_err()
    );
}
