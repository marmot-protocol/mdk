use std::collections::HashSet;

use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::{SqliteAccountStorage, SqliteResultExt, bool_i64, u64_to_i64, usize_to_i64};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSticker {
    pub shortcode: String,
    pub url: String,
    pub sha256: String,
    pub mime: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub alt: Option<String>,
    pub emoji: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStickerPackVersion {
    pub event_id_hex: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStickerPack {
    pub coordinate: String,
    pub author_pubkey_hex: String,
    pub identifier: String,
    pub version: StoredStickerPackVersion,
    pub title: String,
    pub description: Option<String>,
    pub cover: Option<StoredSticker>,
    pub stickers: Vec<StoredSticker>,
    pub license: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredInstalledStickerState {
    pub version: Option<StoredStickerPackVersion>,
    pub packs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStickerInstallOperation {
    pub pack_coordinate: String,
    pub installed: bool,
    pub requested_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStickerOutboxEvent {
    pub event_id_hex: String,
    pub kind: u64,
    pub event_json: String,
    pub created_at: u64,
}

impl SqliteAccountStorage {
    /// Atomically replace one addressable pack only when the incoming NIP-01
    /// replacement wins. Newer `created_at` wins; equal timestamps choose the
    /// lowest event id. Pack metadata and items change in one transaction so a
    /// reader never observes a half-replaced pack.
    pub fn replace_sticker_pack_if_newer(&self, pack: &StoredStickerPack) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let existing = sticker_pack_version_tx(&conn, &pack.coordinate)?;
            if !replacement_wins(existing.as_ref(), &pack.version) {
                return Ok(false);
            }
            let cover_json = pack
                .cover
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|err| StorageError::Serialization(err.to_string()))?;
            conn.execute(
                "INSERT INTO app_sticker_packs (
                    coordinate, author_pubkey_hex, identifier, event_id_hex,
                    created_at, title, description, cover_json, license
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(coordinate) DO UPDATE SET
                    author_pubkey_hex = excluded.author_pubkey_hex,
                    identifier = excluded.identifier,
                    event_id_hex = excluded.event_id_hex,
                    created_at = excluded.created_at,
                    title = excluded.title,
                    description = excluded.description,
                    cover_json = excluded.cover_json,
                    license = excluded.license",
                params![
                    &pack.coordinate,
                    &pack.author_pubkey_hex,
                    &pack.identifier,
                    &pack.version.event_id_hex,
                    u64_to_i64(pack.version.created_at)?,
                    &pack.title,
                    pack.description.as_deref(),
                    cover_json.as_deref(),
                    pack.license.as_deref(),
                ],
            )
            .storage()?;
            conn.execute(
                "DELETE FROM app_stickers WHERE pack_coordinate = ?1",
                params![&pack.coordinate],
            )
            .storage()?;
            for (position, sticker) in pack.stickers.iter().enumerate() {
                conn.execute(
                    "INSERT INTO app_stickers (
                        pack_coordinate, shortcode, url, sha256, mime, width,
                        height, alt, emoji, position
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        &pack.coordinate,
                        &sticker.shortcode,
                        &sticker.url,
                        &sticker.sha256,
                        &sticker.mime,
                        sticker.width.map(i64::from),
                        sticker.height.map(i64::from),
                        sticker.alt.as_deref(),
                        sticker.emoji.as_deref(),
                        usize_to_i64(position)?,
                    ],
                )
                .storage()?;
            }
            Ok(true)
        })
    }

    pub fn sticker_pack(&self, coordinate: &str) -> StorageResult<Option<StoredStickerPack>> {
        let conn = self.lock()?;
        sticker_pack_tx(&conn, coordinate)
    }

    /// Return pre-shaped packs. `installed_only` filters through the committed
    /// installed-list projection with pending local operations rebased over it;
    /// search is bounded and matches only non-secret public metadata.
    pub fn sticker_packs(
        &self,
        installed_only: bool,
        search: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<StoredStickerPack>> {
        let conn = self.lock()?;
        let limit = limit.clamp(1, 200);
        let search = search
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_ascii_lowercase);
        if installed_only {
            let mut packs = Vec::new();
            for coordinate in desired_installed_sticker_packs_tx(&conn)? {
                let Some(pack) = sticker_pack_tx(&conn, &coordinate)? else {
                    continue;
                };
                if search.as_ref().is_some_and(|needle| {
                    !pack.title.to_ascii_lowercase().contains(needle)
                        && !pack
                            .description
                            .as_deref()
                            .unwrap_or_default()
                            .to_ascii_lowercase()
                            .contains(needle)
                }) {
                    continue;
                }
                packs.push(pack);
                if packs.len() == limit {
                    break;
                }
            }
            return Ok(packs);
        }
        let coordinates = match search {
            Some(search) => {
                let pattern = format!("%{}%", search.to_ascii_lowercase());
                let mut stmt = conn
                    .prepare(
                        "SELECT coordinate FROM app_sticker_packs
                         WHERE lower(title) LIKE ?1
                            OR lower(COALESCE(description, '')) LIKE ?1
                         ORDER BY created_at DESC, event_id_hex ASC
                         LIMIT ?2",
                    )
                    .storage()?;
                stmt.query_map(params![pattern, usize_to_i64(limit)?], |row| row.get(0))
                    .storage()?
                    .collect::<Result<Vec<String>, _>>()
                    .storage()?
            }
            None => {
                let mut stmt = conn
                    .prepare(
                        "SELECT coordinate FROM app_sticker_packs
                         ORDER BY created_at DESC, event_id_hex ASC
                         LIMIT ?1",
                    )
                    .storage()?;
                stmt.query_map(params![usize_to_i64(limit)?], |row| row.get(0))
                    .storage()?
                    .collect::<Result<Vec<String>, _>>()
                    .storage()?
            }
        };
        coordinates
            .into_iter()
            .map(|coordinate| sticker_pack_tx(&conn, &coordinate)?.ok_or(StorageError::NotFound))
            .collect()
    }

    /// Resolve a historical message reference against the currently validated
    /// addressable pack. The plaintext hash is part of the lookup: replacing a
    /// shortcode with different bytes can never silently substitute the new
    /// sticker into an old message.
    pub fn sticker_for_ref(
        &self,
        coordinate: &str,
        shortcode: &str,
        plaintext_sha256: &str,
    ) -> StorageResult<Option<StoredSticker>> {
        self.lock()?
            .query_row(
                "SELECT shortcode, url, sha256, mime, width, height, alt, emoji
                 FROM app_stickers
                 WHERE pack_coordinate = ?1 AND shortcode = ?2 AND sha256 = ?3",
                params![coordinate, shortcode, plaintext_sha256],
                sticker_from_row,
            )
            .optional()
            .storage()
    }

    pub fn installed_sticker_state(&self) -> StorageResult<StoredInstalledStickerState> {
        let conn = self.lock()?;
        installed_sticker_state_tx(&conn)
    }

    /// Apply a remote kind-10031 winner while preserving local pending
    /// operations. The caller can then rebase those operations over this base
    /// with [`desired_installed_sticker_packs`](Self::desired_installed_sticker_packs).
    pub fn replace_installed_sticker_packs_if_newer(
        &self,
        version: &StoredStickerPackVersion,
        packs: &[String],
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            replace_installed_sticker_packs_tx(&conn, version, packs)
        })
    }

    /// Queue the user's latest intent for a pack. One row per coordinate makes
    /// repeated taps idempotent while `requested_at` preserves deterministic
    /// cross-pack ordering for rebase.
    pub fn enqueue_sticker_install_operation(
        &self,
        pack_coordinate: &str,
        installed: bool,
        requested_at: u64,
    ) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO app_sticker_install_operations (
                    pack_coordinate, installed, requested_at
                 ) VALUES (?1, ?2, ?3)
                 ON CONFLICT(pack_coordinate) DO UPDATE SET
                    installed = excluded.installed,
                    requested_at = excluded.requested_at",
                params![
                    pack_coordinate,
                    bool_i64(installed),
                    u64_to_i64(requested_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn sticker_install_operations(&self) -> StorageResult<Vec<StoredStickerInstallOperation>> {
        let conn = self.lock()?;
        sticker_install_operations_tx(&conn)
    }

    /// Resolve a cross-device cap race by dropping the oldest pending local
    /// installs that add packs outside the refreshed remote base. Uninstalls
    /// and re-installs of base packs do not increase cardinality and are kept.
    pub fn trim_sticker_install_operations_to_capacity(
        &self,
        max_packs: usize,
    ) -> StorageResult<Vec<String>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let base = installed_sticker_state_tx(&conn)?
                .packs
                .into_iter()
                .collect::<HashSet<_>>();
            let mut excess = desired_installed_sticker_packs_tx(&conn)?
                .len()
                .saturating_sub(max_packs);
            if excess == 0 {
                return Ok(Vec::new());
            }
            let mut dropped = Vec::with_capacity(excess);
            for operation in sticker_install_operations_tx(&conn)? {
                if excess == 0 {
                    break;
                }
                if !operation.installed || base.contains(&operation.pack_coordinate) {
                    continue;
                }
                conn.execute(
                    "DELETE FROM app_sticker_install_operations WHERE pack_coordinate = ?1",
                    params![&operation.pack_coordinate],
                )
                .storage()?;
                dropped.push(operation.pack_coordinate);
                excess -= 1;
            }
            if excess != 0 {
                return Err(StorageError::Backend(
                    "installed sticker base exceeds capacity".to_owned(),
                ));
            }
            Ok(dropped)
        })
    }

    pub fn desired_installed_sticker_packs(&self) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        desired_installed_sticker_packs_tx(&conn)
    }

    /// Commit a successfully published installed-list event and clear the local
    /// operations it represents in the same SQL transaction.
    pub fn commit_installed_sticker_publication(
        &self,
        version: &StoredStickerPackVersion,
        packs: &[String],
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let replaced = replace_installed_sticker_packs_tx(&conn, version, packs)?;
            if replaced {
                conn.execute("DELETE FROM app_sticker_install_operations", [])
                    .storage()?;
            }
            Ok(replaced)
        })
    }

    pub fn put_sticker_outbox_event(&self, event: &StoredStickerOutboxEvent) -> StorageResult<()> {
        self.lock()?
            .execute(
                "INSERT INTO app_sticker_outbox_events (
                    event_id_hex, kind, event_json, created_at
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(event_id_hex) DO UPDATE SET
                    kind = excluded.kind,
                    event_json = excluded.event_json,
                    created_at = excluded.created_at",
                params![
                    &event.event_id_hex,
                    u64_to_i64(event.kind)?,
                    &event.event_json,
                    u64_to_i64(event.created_at)?
                ],
            )
            .storage()?;
        Ok(())
    }

    pub fn sticker_outbox_events(&self) -> StorageResult<Vec<StoredStickerOutboxEvent>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT event_id_hex, kind, event_json, created_at
                 FROM app_sticker_outbox_events
                 ORDER BY created_at ASC, event_id_hex ASC",
            )
            .storage()?;
        stmt.query_map([], |row| {
            Ok(StoredStickerOutboxEvent {
                event_id_hex: row.get(0)?,
                kind: nonnegative_u64(row.get(1)?, 1)?,
                event_json: row.get(2)?,
                created_at: nonnegative_u64(row.get(3)?, 3)?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    pub fn clear_sticker_outbox_event(&self, event_id_hex: &str) -> StorageResult<()> {
        self.lock()?
            .execute(
                "DELETE FROM app_sticker_outbox_events WHERE event_id_hex = ?1",
                params![event_id_hex],
            )
            .storage()?;
        Ok(())
    }
}

fn replacement_wins(
    existing: Option<&StoredStickerPackVersion>,
    incoming: &StoredStickerPackVersion,
) -> bool {
    match existing {
        None => true,
        Some(existing) if incoming.created_at != existing.created_at => {
            incoming.created_at > existing.created_at
        }
        Some(existing) => incoming.event_id_hex < existing.event_id_hex,
    }
}

fn sticker_pack_version_tx(
    conn: &Connection,
    coordinate: &str,
) -> StorageResult<Option<StoredStickerPackVersion>> {
    conn.query_row(
        "SELECT event_id_hex, created_at FROM app_sticker_packs WHERE coordinate = ?1",
        params![coordinate],
        |row| {
            Ok(StoredStickerPackVersion {
                event_id_hex: row.get(0)?,
                created_at: nonnegative_u64(row.get(1)?, 1)?,
            })
        },
    )
    .optional()
    .storage()
}

fn sticker_pack_tx(
    conn: &Connection,
    coordinate: &str,
) -> StorageResult<Option<StoredStickerPack>> {
    let row = conn
        .query_row(
            "SELECT coordinate, author_pubkey_hex, identifier, event_id_hex,
                    created_at, title, description, cover_json, license
             FROM app_sticker_packs WHERE coordinate = ?1",
            params![coordinate],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    nonnegative_u64(row.get(4)?, 4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .storage()?;
    let Some((
        coordinate,
        author_pubkey_hex,
        identifier,
        event_id_hex,
        created_at,
        title,
        description,
        cover_json,
        license,
    )) = row
    else {
        return Ok(None);
    };
    let cover = cover_json
        .map(|json| serde_json::from_str(&json))
        .transpose()
        .map_err(|err| StorageError::Serialization(err.to_string()))?;
    let mut stmt = conn
        .prepare(
            "SELECT shortcode, url, sha256, mime, width, height, alt, emoji
             FROM app_stickers WHERE pack_coordinate = ?1
             ORDER BY position ASC, shortcode ASC",
        )
        .storage()?;
    let stickers = stmt
        .query_map(params![&coordinate], sticker_from_row)
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    Ok(Some(StoredStickerPack {
        coordinate,
        author_pubkey_hex,
        identifier,
        version: StoredStickerPackVersion {
            event_id_hex,
            created_at,
        },
        title,
        description,
        cover,
        stickers,
        license,
    }))
}

fn sticker_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredSticker> {
    Ok(StoredSticker {
        shortcode: row.get(0)?,
        url: row.get(1)?,
        sha256: row.get(2)?,
        mime: row.get(3)?,
        width: optional_u32(row.get(4)?, 4)?,
        height: optional_u32(row.get(5)?, 5)?,
        alt: row.get(6)?,
        emoji: row.get(7)?,
    })
}

fn installed_sticker_state_tx(conn: &Connection) -> StorageResult<StoredInstalledStickerState> {
    let version = conn
        .query_row(
            "SELECT source_event_id_hex, created_at
             FROM app_sticker_install_state WHERE singleton = 1",
            [],
            |row| {
                Ok(StoredStickerPackVersion {
                    event_id_hex: row.get(0)?,
                    created_at: nonnegative_u64(row.get(1)?, 1)?,
                })
            },
        )
        .optional()
        .storage()?;
    let mut stmt = conn
        .prepare(
            "SELECT pack_coordinate FROM app_installed_sticker_packs
             ORDER BY position ASC, pack_coordinate ASC",
        )
        .storage()?;
    let packs = stmt
        .query_map([], |row| row.get(0))
        .storage()?
        .collect::<Result<Vec<String>, _>>()
        .storage()?;
    Ok(StoredInstalledStickerState { version, packs })
}

fn desired_installed_sticker_packs_tx(conn: &Connection) -> StorageResult<Vec<String>> {
    let mut packs = installed_sticker_state_tx(conn)?.packs;
    for operation in sticker_install_operations_tx(conn)? {
        packs.retain(|coordinate| coordinate != &operation.pack_coordinate);
        if operation.installed {
            packs.push(operation.pack_coordinate);
        }
    }
    Ok(deduplicated(packs))
}

fn replace_installed_sticker_packs_tx(
    conn: &Connection,
    version: &StoredStickerPackVersion,
    packs: &[String],
) -> StorageResult<bool> {
    let existing = installed_sticker_state_tx(conn)?.version;
    if !replacement_wins(existing.as_ref(), version) {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO app_sticker_install_state (
            singleton, source_event_id_hex, created_at
         ) VALUES (1, ?1, ?2)
         ON CONFLICT(singleton) DO UPDATE SET
            source_event_id_hex = excluded.source_event_id_hex,
            created_at = excluded.created_at",
        params![&version.event_id_hex, u64_to_i64(version.created_at)?],
    )
    .storage()?;
    conn.execute("DELETE FROM app_installed_sticker_packs", [])
        .storage()?;
    for (position, coordinate) in deduplicated(packs.to_vec()).iter().enumerate() {
        conn.execute(
            "INSERT INTO app_installed_sticker_packs (pack_coordinate, position)
             VALUES (?1, ?2)",
            params![coordinate, usize_to_i64(position)?],
        )
        .storage()?;
    }
    Ok(true)
}

fn sticker_install_operations_tx(
    conn: &Connection,
) -> StorageResult<Vec<StoredStickerInstallOperation>> {
    let mut stmt = conn
        .prepare(
            "SELECT pack_coordinate, installed, requested_at
             FROM app_sticker_install_operations
             ORDER BY requested_at ASC, pack_coordinate ASC",
        )
        .storage()?;
    stmt.query_map([], |row| {
        Ok(StoredStickerInstallOperation {
            pack_coordinate: row.get(0)?,
            installed: row.get::<_, i64>(1)? != 0,
            requested_at: nonnegative_u64(row.get(2)?, 2)?,
        })
    })
    .storage()?
    .collect::<Result<Vec<_>, _>>()
    .storage()
}

fn deduplicated(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn nonnegative_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn optional_u32(value: Option<i64>, column: usize) -> rusqlite::Result<Option<u32>> {
    value
        .map(|value| {
            value
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sticker(shortcode: &str, hash: &str) -> StoredSticker {
        StoredSticker {
            shortcode: shortcode.to_owned(),
            url: format!("https://example.com/{hash}.webp"),
            sha256: hash.to_owned(),
            mime: "image/webp".to_owned(),
            width: Some(512),
            height: Some(512),
            alt: Some(format!("{shortcode} sticker")),
            emoji: Some("🙂".to_owned()),
        }
    }

    fn pack(event_id: &str, created_at: u64, hash: &str) -> StoredStickerPack {
        StoredStickerPack {
            coordinate: format!("30031:{}:cats", "aa".repeat(32)),
            author_pubkey_hex: "aa".repeat(32),
            identifier: "cats".to_owned(),
            version: StoredStickerPackVersion {
                event_id_hex: event_id.to_owned(),
                created_at,
            },
            title: "Cats".to_owned(),
            description: Some("Cat stickers".to_owned()),
            cover: Some(sticker("cover", hash)),
            stickers: vec![sticker("wave", hash)],
            license: Some("CC0".to_owned()),
        }
    }

    #[test]
    fn pack_replacement_is_atomic_and_nip01_ordered() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let hash_a = "11".repeat(32);
        let hash_b = "22".repeat(32);
        let first = pack(&"bb".repeat(32), 10, &hash_a);
        assert!(store.replace_sticker_pack_if_newer(&first).unwrap());

        let older = pack(&"00".repeat(32), 9, &hash_b);
        assert!(!store.replace_sticker_pack_if_newer(&older).unwrap());
        assert!(
            store
                .sticker_for_ref(&first.coordinate, "wave", &hash_a)
                .unwrap()
                .is_some()
        );

        let tie_winner = pack(&"aa".repeat(32), 10, &hash_b);
        assert!(store.replace_sticker_pack_if_newer(&tie_winner).unwrap());
        assert!(
            store
                .sticker_for_ref(&first.coordinate, "wave", &hash_a)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .sticker_for_ref(&first.coordinate, "wave", &hash_b)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn installed_operations_rebase_without_losing_concurrent_intent() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let base = StoredStickerPackVersion {
            event_id_hex: "cc".repeat(32),
            created_at: 5,
        };
        store
            .replace_installed_sticker_packs_if_newer(&base, &["pack-a".to_owned()])
            .unwrap();
        store
            .enqueue_sticker_install_operation("pack-b", true, 6)
            .unwrap();

        let remote = StoredStickerPackVersion {
            event_id_hex: "dd".repeat(32),
            created_at: 7,
        };
        store
            .replace_installed_sticker_packs_if_newer(&remote, &["pack-c".to_owned()])
            .unwrap();
        assert_eq!(
            store.desired_installed_sticker_packs().unwrap(),
            vec!["pack-c".to_owned(), "pack-b".to_owned()]
        );

        let published = StoredStickerPackVersion {
            event_id_hex: "ee".repeat(32),
            created_at: 8,
        };
        assert!(
            store
                .commit_installed_sticker_publication(
                    &published,
                    &["pack-c".to_owned(), "pack-b".to_owned()],
                )
                .unwrap()
        );
        assert!(store.sticker_install_operations().unwrap().is_empty());
    }

    #[test]
    fn installed_only_listing_reflects_pending_local_operations() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let stored_pack = pack(&"bb".repeat(32), 10, &"11".repeat(32));
        store.replace_sticker_pack_if_newer(&stored_pack).unwrap();

        store
            .enqueue_sticker_install_operation(&stored_pack.coordinate, true, 11)
            .unwrap();
        assert_eq!(
            store
                .sticker_packs(true, None, 100)
                .unwrap()
                .into_iter()
                .map(|pack| pack.coordinate)
                .collect::<Vec<_>>(),
            vec![stored_pack.coordinate.clone()]
        );

        store
            .enqueue_sticker_install_operation(&stored_pack.coordinate, false, 12)
            .unwrap();
        assert!(store.sticker_packs(true, None, 100).unwrap().is_empty());
    }

    #[test]
    fn stale_outbox_commit_cannot_clear_operations_rebased_over_newer_remote() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let base = StoredStickerPackVersion {
            event_id_hex: "cc".repeat(32),
            created_at: 5,
        };
        store
            .replace_installed_sticker_packs_if_newer(&base, &["pack-a".to_owned()])
            .unwrap();
        store
            .enqueue_sticker_install_operation("pack-b", true, 6)
            .unwrap();

        let remote = StoredStickerPackVersion {
            event_id_hex: "dd".repeat(32),
            created_at: 8,
        };
        store
            .replace_installed_sticker_packs_if_newer(&remote, &["pack-c".to_owned()])
            .unwrap();

        let stale_outbox = StoredStickerPackVersion {
            event_id_hex: "ee".repeat(32),
            created_at: 7,
        };
        assert!(
            !store
                .commit_installed_sticker_publication(
                    &stale_outbox,
                    &["pack-a".to_owned(), "pack-b".to_owned()],
                )
                .unwrap()
        );
        assert_eq!(
            store.desired_installed_sticker_packs().unwrap(),
            vec!["pack-c".to_owned(), "pack-b".to_owned()]
        );
        assert_eq!(store.sticker_install_operations().unwrap().len(), 1);
    }

    #[test]
    fn cross_device_capacity_race_drops_oldest_excess_local_install() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let initial = (0..99)
            .map(|index| format!("pack-{index}"))
            .collect::<Vec<_>>();
        store
            .replace_installed_sticker_packs_if_newer(
                &StoredStickerPackVersion {
                    event_id_hex: "cc".repeat(32),
                    created_at: 5,
                },
                &initial,
            )
            .unwrap();
        store
            .enqueue_sticker_install_operation("local-pack", true, 6)
            .unwrap();
        assert_eq!(store.desired_installed_sticker_packs().unwrap().len(), 100);

        let remote = (0..100)
            .map(|index| format!("remote-pack-{index}"))
            .collect::<Vec<_>>();
        store
            .replace_installed_sticker_packs_if_newer(
                &StoredStickerPackVersion {
                    event_id_hex: "dd".repeat(32),
                    created_at: 7,
                },
                &remote,
            )
            .unwrap();
        assert_eq!(store.desired_installed_sticker_packs().unwrap().len(), 101);

        assert_eq!(
            store
                .trim_sticker_install_operations_to_capacity(100)
                .unwrap(),
            vec!["local-pack".to_owned()]
        );
        assert_eq!(store.desired_installed_sticker_packs().unwrap(), remote);
        assert!(store.sticker_install_operations().unwrap().is_empty());
    }

    #[test]
    fn outbox_roundtrips_without_secret_side_channel() {
        let store = SqliteAccountStorage::in_memory().unwrap();
        let event = StoredStickerOutboxEvent {
            event_id_hex: "aa".repeat(32),
            kind: 30_031,
            event_json: "{\"kind\":30031}".to_owned(),
            created_at: 12,
        };
        store.put_sticker_outbox_event(&event).unwrap();
        assert_eq!(store.sticker_outbox_events().unwrap(), vec![event.clone()]);
        store
            .clear_sticker_outbox_event(&event.event_id_hex)
            .unwrap();
        assert!(store.sticker_outbox_events().unwrap().is_empty());
    }
}
