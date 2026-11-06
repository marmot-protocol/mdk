use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

/// NIP-51 emoji sets (kind 30030, and a user's kind-10030 list read as one
/// set): the discovered text-only projection, and installed snapshots that
/// pin one set version and hold each emoji's validated bytes and hash.
pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_emoji_sets (
    coordinate TEXT PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL,
    author_pubkey_hex TEXT NOT NULL,
    identifier TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    title TEXT,
    description TEXT,
    image_url TEXT,
    skipped_json TEXT NOT NULL,
    skipped_count INTEGER NOT NULL
);

CREATE INDEX idx_app_emoji_sets_created_at
    ON app_emoji_sets (created_at DESC, event_id_hex ASC);

CREATE TABLE app_emoji_set_entries (
    set_coordinate TEXT NOT NULL,
    shortcode TEXT NOT NULL,
    url TEXT NOT NULL,
    position INTEGER NOT NULL,
    PRIMARY KEY (set_coordinate, shortcode),
    FOREIGN KEY (set_coordinate) REFERENCES app_emoji_sets(coordinate) ON DELETE CASCADE
);

CREATE TABLE app_installed_emoji_sets (
    coordinate TEXT PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL,
    author_pubkey_hex TEXT NOT NULL,
    identifier TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    title TEXT,
    description TEXT,
    installed_at INTEGER NOT NULL,
    position INTEGER NOT NULL
);

CREATE TABLE app_installed_emoji (
    set_coordinate TEXT NOT NULL,
    shortcode TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mime TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    frames INTEGER NOT NULL,
    byte_len INTEGER NOT NULL,
    bytes BLOB NOT NULL,
    position INTEGER NOT NULL,
    PRIMARY KEY (set_coordinate, shortcode),
    FOREIGN KEY (set_coordinate) REFERENCES app_installed_emoji_sets(coordinate) ON DELETE CASCADE
);
"#,
    )
    .storage()
}
