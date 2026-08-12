use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
ALTER TABLE chat_list_rows ADD COLUMN last_message_tags_json TEXT;

CREATE TABLE app_sticker_packs (
    coordinate TEXT PRIMARY KEY NOT NULL,
    author_pubkey_hex TEXT NOT NULL,
    identifier TEXT NOT NULL,
    event_id_hex TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    cover_json TEXT,
    license TEXT
);

CREATE INDEX idx_app_sticker_packs_created_at
    ON app_sticker_packs (created_at DESC, event_id_hex ASC);

CREATE TABLE app_stickers (
    pack_coordinate TEXT NOT NULL,
    shortcode TEXT NOT NULL,
    url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mime TEXT NOT NULL,
    width INTEGER,
    height INTEGER,
    alt TEXT,
    emoji TEXT,
    position INTEGER NOT NULL,
    PRIMARY KEY (pack_coordinate, shortcode),
    FOREIGN KEY (pack_coordinate) REFERENCES app_sticker_packs(coordinate) ON DELETE CASCADE
);

CREATE UNIQUE INDEX idx_app_stickers_pack_hash
    ON app_stickers (pack_coordinate, sha256);

CREATE TABLE app_sticker_install_state (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    source_event_id_hex TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE app_installed_sticker_packs (
    pack_coordinate TEXT PRIMARY KEY NOT NULL,
    position INTEGER NOT NULL
);

CREATE TABLE app_sticker_install_operations (
    pack_coordinate TEXT PRIMARY KEY NOT NULL,
    installed INTEGER NOT NULL CHECK (installed IN (0, 1)),
    requested_at INTEGER NOT NULL
);

CREATE INDEX idx_app_sticker_install_operations_order
    ON app_sticker_install_operations (requested_at ASC, pack_coordinate ASC);

CREATE TABLE app_sticker_outbox_events (
    event_id_hex TEXT PRIMARY KEY NOT NULL,
    kind INTEGER NOT NULL,
    event_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"#,
    )
    .storage()
}
