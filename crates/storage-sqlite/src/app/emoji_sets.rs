//! NIP-51 emoji sets: the discovered projection (text only: shortcodes and
//! URLs, never image bytes) and installed snapshots. An installed snapshot
//! pins one set version (its event id) and holds each emoji's validated bytes
//! with their SHA-256, so a later change of URL or image cannot replace what
//! the user installed. Installed snapshots never reference the discovered
//! projection: pruning or replacing a discovered set leaves them unchanged.

use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{SqliteAppStorage, SqliteResultExt, u64_to_i64, usize_to_i64};

/// Discovered sets returned by one listing.
const MAX_EMOJI_SET_LISTING: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEmojiSetVersion {
    pub event_id_hex: String,
    pub created_at: u64,
}

/// One valid `["emoji", shortcode, url]` entry of a discovered set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEmojiSetEntry {
    pub shortcode: String,
    pub url: String,
}

/// An `emoji` tag the parser dropped. `position` counts `emoji` tags from 0;
/// `shortcode` is kept only when it is itself valid. `reason` is the app's
/// stable reason code. A set records at most a bounded number of these;
/// [`StoredEmojiSet::skipped_count`] counts them all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEmojiSkip {
    pub position: u32,
    pub shortcode: Option<String>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEmojiSet {
    pub coordinate: String,
    pub kind: u16,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub version: StoredEmojiSetVersion,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
    pub emoji: Vec<StoredEmojiSetEntry>,
    pub skipped: Vec<StoredEmojiSkip>,
    pub skipped_count: u32,
}

/// An installed snapshot's set row. `emoji_count` and `byte_len` are derived
/// from its emoji rows when read and ignored when installing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInstalledEmojiSet {
    pub coordinate: String,
    pub kind: u16,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub version: StoredEmojiSetVersion,
    pub title: Option<String>,
    pub description: Option<String>,
    pub installed_at: u64,
    pub emoji_count: u32,
    pub byte_len: u64,
}

/// What an installed emoji's bytes were validated as.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInstalledEmoji {
    pub shortcode: String,
    pub sha256: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub frames: u32,
    pub byte_len: u64,
}

/// One installed emoji with the set it came from, for a picker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInstalledEmojiRow {
    pub set_coordinate: String,
    pub set_title: Option<String>,
    pub author_pubkey_hex: String,
    pub emoji: StoredInstalledEmoji,
}

/// Account-wide caps an install must fit, checked in its transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmojiSetInstallLimits {
    pub max_sets: usize,
    pub max_total_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmojiSetInstallOutcome {
    Installed,
    /// Installing a new set would exceed `max_sets`; nothing changed.
    TooManySets,
    /// The snapshot plus every other installed set's bytes would exceed
    /// `max_total_bytes`; nothing changed.
    OverByteBudget,
}

impl SqliteAppStorage {
    /// Replace one discovered set when the incoming version wins NIP-01
    /// replacement (newer `created_at`, then the lowest event id). The set
    /// row and its entries change in one transaction.
    pub fn replace_emoji_set_if_newer(&self, set: &StoredEmojiSet) -> StorageResult<bool> {
        require_canonical_event_id(&set.version)?;
        let skipped_json = serde_json::to_string(&set.skipped)
            .map_err(|err| StorageError::Serialization(err.to_string()))?;
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let existing = emoji_set_version_tx(&conn, &set.coordinate)?;
            if !replacement_wins(existing.as_ref(), &set.version) {
                return Ok(false);
            }
            conn.execute(
                "INSERT INTO app_emoji_sets (
                    coordinate, kind, author_pubkey_hex, identifier, event_id_hex,
                    created_at, title, description, image_url, skipped_json, skipped_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(coordinate) DO UPDATE SET
                    kind = excluded.kind,
                    author_pubkey_hex = excluded.author_pubkey_hex,
                    identifier = excluded.identifier,
                    event_id_hex = excluded.event_id_hex,
                    created_at = excluded.created_at,
                    title = excluded.title,
                    description = excluded.description,
                    image_url = excluded.image_url,
                    skipped_json = excluded.skipped_json,
                    skipped_count = excluded.skipped_count",
                params![
                    &set.coordinate,
                    i64::from(set.kind),
                    &set.author_pubkey_hex,
                    &set.identifier,
                    &set.version.event_id_hex,
                    u64_to_i64(set.version.created_at)?,
                    set.title.as_deref(),
                    set.description.as_deref(),
                    set.image_url.as_deref(),
                    &skipped_json,
                    i64::from(set.skipped_count),
                ],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM app_emoji_set_entries WHERE set_coordinate = ?1",
                params![&set.coordinate],
            )
            .storage()?;
            for (position, entry) in set.emoji.iter().enumerate() {
                conn.execute(
                    "INSERT INTO app_emoji_set_entries (set_coordinate, shortcode, url, position)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        &set.coordinate,
                        &entry.shortcode,
                        &entry.url,
                        usize_to_i64(position)?
                    ],
                )
                .storage()?;
            }
            Ok(true)
        })
    }

    /// Drop the oldest discovered sets beyond `limit`. Installed sets and the
    /// coordinates in `keep` stay, whatever their age.
    pub fn prune_uninstalled_emoji_sets(
        &self,
        limit: usize,
        keep: &[String],
    ) -> StorageResult<usize> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let coordinates = {
                let mut stmt = conn
                    .prepare(
                        "SELECT coordinate FROM app_emoji_sets
                         ORDER BY created_at ASC, event_id_hex ASC",
                    )
                    .storage()?;
                stmt.query_map([], |row| row.get::<_, String>(0))
                    .storage()?
                    .collect::<Result<Vec<_>, _>>()
                    .storage()?
            };
            let installed = installed_coordinates_tx(&conn)?;
            let excess = coordinates.len().saturating_sub(limit);
            let mut removed = 0;
            for coordinate in coordinates {
                if removed == excess {
                    break;
                }
                if installed.contains(&coordinate) || keep.contains(&coordinate) {
                    continue;
                }
                conn.execute(
                    "DELETE FROM app_emoji_set_entries WHERE set_coordinate = ?1",
                    params![&coordinate],
                )
                .storage()?;
                conn.execute(
                    "DELETE FROM app_emoji_sets WHERE coordinate = ?1",
                    params![&coordinate],
                )
                .storage()?;
                removed += 1;
            }
            Ok(removed)
        })
    }

    pub fn emoji_set(&self, coordinate: &str) -> StorageResult<Option<StoredEmojiSet>> {
        let conn = self.lock()?;
        emoji_set_tx(&conn, coordinate)
    }

    /// Discovered sets, newest first, or installed ones in install order.
    /// `search` matches, case-insensitively and literally, the title, the
    /// description, the author's hex key or any valid entry's shortcode.
    pub fn emoji_sets(
        &self,
        installed_only: bool,
        search: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<StoredEmojiSet>> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, MAX_EMOJI_SET_LISTING);
        let pattern = search
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                let escaped = value
                    .to_lowercase()
                    .replace('!', "!!")
                    .replace('%', "!%")
                    .replace('_', "!_");
                format!("%{escaped}%")
            });
        let coordinates = {
            let mut stmt = conn
                .prepare(
                    "SELECT s.coordinate FROM app_emoji_sets s
                     LEFT JOIN app_installed_emoji_sets i ON i.coordinate = s.coordinate
                     WHERE (?1 = 0 OR i.coordinate IS NOT NULL)
                       AND (i.coordinate IS NOT NULL
                            OR EXISTS (SELECT 1 FROM app_emoji_set_entries e
                                       WHERE e.set_coordinate = s.coordinate))
                       AND (?2 IS NULL
                            OR lower(COALESCE(s.title, '')) LIKE ?2 ESCAPE '!'
                            OR lower(COALESCE(s.description, '')) LIKE ?2 ESCAPE '!'
                            OR s.author_pubkey_hex LIKE ?2 ESCAPE '!'
                            OR EXISTS (
                                SELECT 1 FROM app_emoji_set_entries e
                                WHERE e.set_coordinate = s.coordinate
                                  AND lower(e.shortcode) LIKE ?2 ESCAPE '!'))
                     ORDER BY CASE WHEN ?1 = 1 THEN i.position END ASC,
                              s.created_at DESC, s.event_id_hex ASC
                     LIMIT ?3",
                )
                .storage()?;
            stmt.query_map(
                params![
                    i64::from(installed_only),
                    pattern.as_deref(),
                    usize_to_i64(limit)?
                ],
                |row| row.get::<_, String>(0),
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
        };
        coordinates
            .into_iter()
            .map(|coordinate| emoji_set_tx(&conn, &coordinate)?.ok_or(StorageError::NotFound))
            .collect()
    }

    /// Installed snapshots in install order.
    pub fn installed_emoji_sets(&self) -> StorageResult<Vec<StoredInstalledEmojiSet>> {
        let conn = self.lock()?;
        installed_sets_tx(&conn, None)
    }

    pub fn installed_emoji_set(
        &self,
        coordinate: &str,
    ) -> StorageResult<Option<StoredInstalledEmojiSet>> {
        let conn = self.lock()?;
        Ok(installed_sets_tx(&conn, Some(coordinate))?
            .into_iter()
            .next())
    }

    /// Bytes held by every installed set except `coordinate`, which an
    /// install of `coordinate` would replace.
    pub fn installed_emoji_bytes_excluding(&self, coordinate: &str) -> StorageResult<u64> {
        let conn = self.lock()?;
        installed_bytes_excluding_tx(&conn, coordinate)
    }

    /// Install (or reinstall) one snapshot atomically: its previous emoji go,
    /// the new ones land with their bytes. Every emoji's bytes must hash to
    /// its `sha256` and match its `byte_len`. A reinstall keeps its place in
    /// the install order; a new set goes last.
    pub fn install_emoji_set(
        &self,
        set: &StoredInstalledEmojiSet,
        emoji: &[(StoredInstalledEmoji, Vec<u8>)],
        limits: EmojiSetInstallLimits,
    ) -> StorageResult<EmojiSetInstallOutcome> {
        require_canonical_event_id(&set.version)?;
        if emoji.is_empty() {
            return Err(StorageError::Backend(
                "an installed emoji set needs at least one emoji".to_owned(),
            ));
        }
        let mut new_bytes = 0_u64;
        for (meta, bytes) in emoji {
            if meta.byte_len != bytes.len() as u64
                || hex::encode(Sha256::digest(bytes)) != meta.sha256
            {
                return Err(StorageError::Backend(
                    "installed emoji bytes do not match their hash".to_owned(),
                ));
            }
            new_bytes = new_bytes.saturating_add(meta.byte_len);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let installed = installed_coordinates_tx(&conn)?;
            let reinstall = installed.contains(&set.coordinate);
            if !reinstall && installed.len() >= limits.max_sets {
                return Ok(EmojiSetInstallOutcome::TooManySets);
            }
            let others = installed_bytes_excluding_tx(&conn, &set.coordinate)?;
            if others.saturating_add(new_bytes) > limits.max_total_bytes {
                return Ok(EmojiSetInstallOutcome::OverByteBudget);
            }
            let position: i64 = if reinstall {
                conn.query_row(
                    "SELECT position FROM app_installed_emoji_sets WHERE coordinate = ?1",
                    params![&set.coordinate],
                    |row| row.get(0),
                )
                .storage()?
            } else {
                conn.query_row(
                    "SELECT COALESCE(MAX(position) + 1, 0) FROM app_installed_emoji_sets",
                    [],
                    |row| row.get(0),
                )
                .storage()?
            };
            conn.execute(
                "DELETE FROM app_installed_emoji WHERE set_coordinate = ?1",
                params![&set.coordinate],
            )
            .storage()?;
            conn.execute(
                "INSERT INTO app_installed_emoji_sets (
                    coordinate, kind, author_pubkey_hex, identifier, event_id_hex,
                    created_at, title, description, installed_at, position
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(coordinate) DO UPDATE SET
                    kind = excluded.kind,
                    author_pubkey_hex = excluded.author_pubkey_hex,
                    identifier = excluded.identifier,
                    event_id_hex = excluded.event_id_hex,
                    created_at = excluded.created_at,
                    title = excluded.title,
                    description = excluded.description,
                    installed_at = excluded.installed_at,
                    position = excluded.position",
                params![
                    &set.coordinate,
                    i64::from(set.kind),
                    &set.author_pubkey_hex,
                    &set.identifier,
                    &set.version.event_id_hex,
                    u64_to_i64(set.version.created_at)?,
                    set.title.as_deref(),
                    set.description.as_deref(),
                    u64_to_i64(set.installed_at)?,
                    position,
                ],
            )
            .storage()?;
            for (index, (meta, bytes)) in emoji.iter().enumerate() {
                conn.execute(
                    "INSERT INTO app_installed_emoji (
                        set_coordinate, shortcode, sha256, mime, width, height,
                        frames, byte_len, bytes, position
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        &set.coordinate,
                        &meta.shortcode,
                        &meta.sha256,
                        &meta.mime,
                        i64::from(meta.width),
                        i64::from(meta.height),
                        i64::from(meta.frames),
                        u64_to_i64(meta.byte_len)?,
                        bytes,
                        usize_to_i64(index)?,
                    ],
                )
                .storage()?;
            }
            Ok(EmojiSetInstallOutcome::Installed)
        })
    }

    /// Remove an installed snapshot and every stored emoji byte it holds.
    /// Returns whether it was installed.
    pub fn uninstall_emoji_set(&self, coordinate: &str) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute(
                "DELETE FROM app_installed_emoji WHERE set_coordinate = ?1",
                params![coordinate],
            )
            .storage()?;
            let removed = conn
                .execute(
                    "DELETE FROM app_installed_emoji_sets WHERE coordinate = ?1",
                    params![coordinate],
                )
                .storage()?;
            Ok(removed > 0)
        })
    }

    /// Every installed emoji, by set install order then the set's own order.
    pub fn installed_custom_emoji(&self) -> StorageResult<Vec<StoredInstalledEmojiRow>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT e.set_coordinate, s.title, s.author_pubkey_hex, e.shortcode,
                        e.sha256, e.mime, e.width, e.height, e.frames, e.byte_len
                 FROM app_installed_emoji e
                 JOIN app_installed_emoji_sets s ON s.coordinate = e.set_coordinate
                 ORDER BY s.position ASC, e.position ASC",
            )
            .storage()?;
        stmt.query_map([], installed_row_from_row)
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()
    }

    /// One installed emoji's stored bytes, checked against its stored hash.
    pub fn installed_custom_emoji_bytes(
        &self,
        coordinate: &str,
        shortcode: &str,
    ) -> StorageResult<Option<(StoredInstalledEmojiRow, Vec<u8>)>> {
        let conn = self.lock()?;
        let found = conn
            .query_row(
                "SELECT e.set_coordinate, s.title, s.author_pubkey_hex, e.shortcode,
                        e.sha256, e.mime, e.width, e.height, e.frames, e.byte_len, e.bytes
                 FROM app_installed_emoji e
                 JOIN app_installed_emoji_sets s ON s.coordinate = e.set_coordinate
                 WHERE e.set_coordinate = ?1 AND e.shortcode = ?2",
                params![coordinate, shortcode],
                |row| Ok((installed_row_from_row(row)?, row.get::<_, Vec<u8>>(10)?)),
            )
            .optional()
            .storage()?;
        let Some((row, bytes)) = found else {
            return Ok(None);
        };
        if row.emoji.byte_len != bytes.len() as u64
            || hex::encode(Sha256::digest(&bytes)) != row.emoji.sha256
        {
            return Err(StorageError::Backend(
                "stored custom emoji failed its hash check".to_owned(),
            ));
        }
        Ok(Some((row, bytes)))
    }
}

/// An empty or non-canonical id would read as "no stored version" or win
/// every tie; reject it before writing.
fn require_canonical_event_id(version: &StoredEmojiSetVersion) -> StorageResult<()> {
    let id = version.event_id_hex.as_bytes();
    if id.len() == 64
        && id
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(StorageError::Backend(
            "emoji set event id must be 64 lowercase hex characters".to_owned(),
        ))
    }
}

fn replacement_wins(
    existing: Option<&StoredEmojiSetVersion>,
    incoming: &StoredEmojiSetVersion,
) -> bool {
    match existing {
        None => true,
        Some(existing) if incoming.created_at != existing.created_at => {
            incoming.created_at > existing.created_at
        }
        Some(existing) => incoming.event_id_hex < existing.event_id_hex,
    }
}

fn emoji_set_version_tx(
    conn: &Connection,
    coordinate: &str,
) -> StorageResult<Option<StoredEmojiSetVersion>> {
    conn.query_row(
        "SELECT event_id_hex, created_at FROM app_emoji_sets WHERE coordinate = ?1",
        params![coordinate],
        |row| {
            Ok(StoredEmojiSetVersion {
                event_id_hex: row.get(0)?,
                created_at: nonnegative_u64(row.get(1)?, 1)?,
            })
        },
    )
    .optional()
    .storage()
}

fn emoji_set_tx(conn: &Connection, coordinate: &str) -> StorageResult<Option<StoredEmojiSet>> {
    let row = conn
        .query_row(
            "SELECT coordinate, kind, author_pubkey_hex, identifier, event_id_hex,
                    created_at, title, description, image_url, skipped_json, skipped_count
             FROM app_emoji_sets WHERE coordinate = ?1",
            params![coordinate],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    kind_from(row.get(1)?, 1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    StoredEmojiSetVersion {
                        event_id_hex: row.get(4)?,
                        created_at: nonnegative_u64(row.get(5)?, 5)?,
                    },
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    u32_from(row.get(10)?, 10)?,
                ))
            },
        )
        .optional()
        .storage()?;
    let Some((
        coordinate,
        kind,
        author_pubkey_hex,
        identifier,
        version,
        title,
        description,
        image_url,
        skipped_json,
        skipped_count,
    )) = row
    else {
        return Ok(None);
    };
    let skipped = serde_json::from_str(&skipped_json)
        .map_err(|err| StorageError::Serialization(err.to_string()))?;
    let emoji = {
        let mut stmt = conn
            .prepare(
                "SELECT shortcode, url FROM app_emoji_set_entries
                 WHERE set_coordinate = ?1 ORDER BY position ASC",
            )
            .storage()?;
        stmt.query_map(params![&coordinate], |row| {
            Ok(StoredEmojiSetEntry {
                shortcode: row.get(0)?,
                url: row.get(1)?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?
    };
    Ok(Some(StoredEmojiSet {
        coordinate,
        kind,
        author_pubkey_hex,
        identifier,
        version,
        title,
        description,
        image_url,
        emoji,
        skipped,
        skipped_count,
    }))
}

fn installed_coordinates_tx(conn: &Connection) -> StorageResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT coordinate FROM app_installed_emoji_sets ORDER BY position ASC")
        .storage()?;
    stmt.query_map([], |row| row.get::<_, String>(0))
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
}

fn installed_bytes_excluding_tx(conn: &Connection, coordinate: &str) -> StorageResult<u64> {
    let bytes: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(byte_len), 0) FROM app_installed_emoji
             WHERE set_coordinate != ?1",
            params![coordinate],
            |row| row.get(0),
        )
        .storage()?;
    Ok(u64::try_from(bytes).unwrap_or(0))
}

fn installed_sets_tx(
    conn: &Connection,
    only: Option<&str>,
) -> StorageResult<Vec<StoredInstalledEmojiSet>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.coordinate, s.kind, s.author_pubkey_hex, s.identifier, s.event_id_hex,
                    s.created_at, s.title, s.description, s.installed_at,
                    COUNT(e.shortcode), COALESCE(SUM(e.byte_len), 0)
             FROM app_installed_emoji_sets s
             LEFT JOIN app_installed_emoji e ON e.set_coordinate = s.coordinate
             WHERE ?1 IS NULL OR s.coordinate = ?1
             GROUP BY s.coordinate
             ORDER BY s.position ASC",
        )
        .storage()?;
    stmt.query_map(params![only], |row| {
        Ok(StoredInstalledEmojiSet {
            coordinate: row.get(0)?,
            kind: kind_from(row.get(1)?, 1)?,
            author_pubkey_hex: row.get(2)?,
            identifier: row.get(3)?,
            version: StoredEmojiSetVersion {
                event_id_hex: row.get(4)?,
                created_at: nonnegative_u64(row.get(5)?, 5)?,
            },
            title: row.get(6)?,
            description: row.get(7)?,
            installed_at: nonnegative_u64(row.get(8)?, 8)?,
            emoji_count: u32_from(row.get(9)?, 9)?,
            byte_len: nonnegative_u64(row.get(10)?, 10)?,
        })
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn installed_row_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredInstalledEmojiRow> {
    Ok(StoredInstalledEmojiRow {
        set_coordinate: row.get(0)?,
        set_title: row.get(1)?,
        author_pubkey_hex: row.get(2)?,
        emoji: StoredInstalledEmoji {
            shortcode: row.get(3)?,
            sha256: row.get(4)?,
            mime: row.get(5)?,
            width: u32_from(row.get(6)?, 6)?,
            height: u32_from(row.get(7)?, 7)?,
            frames: u32_from(row.get(8)?, 8)?,
            byte_len: nonnegative_u64(row.get(9)?, 9)?,
        },
    })
}

fn kind_from(value: i64, column: usize) -> rusqlite::Result<u16> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn u32_from(value: i64, column: usize) -> rusqlite::Result<u32> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn nonnegative_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

#[cfg(test)]
#[path = "emoji_sets_tests.rs"]
mod tests;
