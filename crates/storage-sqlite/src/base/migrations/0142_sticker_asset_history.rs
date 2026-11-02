use crate::SqliteResultExt;
use cgka_traits::storage::StorageResult;
use rusqlite::Transaction;

pub(crate) fn apply(tx: &Transaction<'_>) -> StorageResult<()> {
    tx.execute_batch(
        r#"
CREATE TABLE app_sticker_assets (
    pack_coordinate TEXT NOT NULL,
    shortcode TEXT NOT NULL,
    url TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    mime TEXT NOT NULL,
    width INTEGER,
    height INTEGER,
    alt TEXT,
    emoji TEXT,
    PRIMARY KEY (pack_coordinate, shortcode, sha256),
    FOREIGN KEY (pack_coordinate) REFERENCES app_sticker_packs(coordinate) ON DELETE CASCADE
);

INSERT INTO app_sticker_assets (
    pack_coordinate, shortcode, url, sha256, mime, width, height, alt, emoji
)
SELECT pack_coordinate, shortcode, url, sha256, mime, width, height, alt, emoji
FROM app_stickers;
"#,
    )
    .storage()
}
