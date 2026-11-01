//! A chat's history moved between an account's devices (mdk#2628 4.2a).
//!
//! The sending device reads its app events in chat order (epoch, `created_at`,
//! id), each with what a history bundle carries or nothing for a row that
//! stays out. The receiving device's import only adds rows. A row it already
//! holds, from live delivery or an earlier import, stays as it is, so an import
//! never undoes a newer live update. Each new row is marked with the roster
//! slot of the device that sent it, and the unread projection skips marked
//! rows.
use super::*;
use crate::SqliteAppStorage;
use cgka_traits::MarmotAppEvent;
use cgka_traits::app_components::DeviceSlotId;
use zeroize::Zeroizing;

/// The device a chat history was imported from (mdk#2628 4.2d).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryImportSource {
    /// The device's roster slot, 64 lowercase hex characters.
    pub device_slot_id_hex: String,
    /// The device's name as [`SqliteAppStorage::set_device_labels`] last gave
    /// it: empty when it has none, is no longer on the roster, or none was
    /// given since the database opened.
    pub device_label: String,
}

impl HistoryImportSource {
    pub(crate) fn new(slot: &[u8], label: Option<String>) -> Self {
        Self {
            device_slot_id_hex: hex::encode(slot),
            device_label: label.unwrap_or_default(),
        }
    }
}

/// The name of an imported row's source, or NULL for a row that arrived
/// live or a source no name was given for. Reads `timeline`.
pub(crate) const TIMELINE_IMPORT_LABEL_SQL: &str = "(SELECT label.label FROM app_event_imports imported JOIN temp.device_labels label ON label.slot = imported.source_slot WHERE imported.group_id_hex=timeline.group_id_hex AND imported.message_id_hex=timeline.message_id_hex)";

/// The latest history import into one chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LatestHistoryImport {
    pub group_id_hex: String,
    pub source: HistoryImportSource,
    pub imported_at: u64,
}

/// One app event of a chat in chat order, as a history bundle sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryExportRow {
    pub source_epoch: u64,
    pub created_at: u64,
    pub message_id_hex: String,
    /// What a bundle carries for the row, or none for a row that stays out.
    /// A row that stays out still lies in the stretch a bundle vouches for.
    pub event: Option<HistoryExportEvent>,
}

/// An app event as a history bundle carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryExportEvent {
    pub event: MarmotAppEvent,
    pub retention_seconds: Option<u64>,
    /// This device's authority verdict for a review label or an admin removal,
    /// when it has settled one.
    pub moderation_grant: Option<bool>,
}

/// One app event from a sibling's history. It carries no transport id: this
/// device can never fetch or open the relay copy, and an id it cannot check
/// must not take the unique slot a live row needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportedAppEvent {
    pub message_id_hex: String,
    /// The MLS epoch the event was sent in, which orders it among live rows.
    pub source_epoch: u64,
    pub sender: String,
    pub plaintext: String,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub created_at: u64,
    pub retention: Option<AppMessageRetentionDecision>,
    /// The sending device's authority verdict for a review label or an admin
    /// removal, taken as this row's. Without one the row has no authority.
    pub moderation_grant: Option<bool>,
    /// Per-file keys for the chat message's attachments, which this device
    /// cannot derive: it was never in the epoch the message was sent in.
    pub file_keys: Vec<ImportedFileKey>,
}

/// One attachment's key, named by the `ciphertext_sha256` of the media
/// reference it opens.
#[derive(Clone, PartialEq, Eq)]
pub struct ImportedFileKey {
    pub ciphertext_sha256: String,
    pub key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ImportedFileKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedFileKey").finish_non_exhaustive()
    }
}

/// What one import changed.
#[derive(Clone, Debug)]
pub struct AppEventImport {
    /// How many events became new rows.
    pub imported: usize,
    /// Every timeline row the import changed, at its final state.
    pub update: TimelineProjectionUpdate,
}

impl SqliteAppStorage {
    /// Records, in one transaction, each event this device does not hold yet,
    /// marked as imported from `source_slot`. Skips an event already stored,
    /// one whose retention expired by `now`, and one whose target retention
    /// erased.
    pub fn import_app_events(
        &self,
        group_id_hex: &str,
        source_slot: &DeviceSlotId,
        events: &[ImportedAppEvent],
        now: u64,
    ) -> StorageResult<AppEventImport> {
        self.connection.with_transaction(|| {
            let mut imported = 0;
            let mut changed = BTreeSet::new();
            for event in events {
                let expired = event
                    .retention
                    .and_then(|retention| retention.expires_at)
                    .is_some_and(|expires_at| expires_at <= now);
                if expired || self.holds_app_event(group_id_hex, &event.message_id_hex)? {
                    continue;
                }
                let update = self.record_app_event_with_source(
                    &StoredAppEvent {
                        group_id_hex: group_id_hex.to_owned(),
                        message_id_hex: event.message_id_hex.clone(),
                        source_message_id_hex: None,
                        source_epoch: Some(event.source_epoch),
                        direction: "received".to_owned(),
                        sender: event.sender.clone(),
                        plaintext: event.plaintext.clone(),
                        kind: event.kind,
                        tags: event.tags.clone(),
                        recorded_at: event.created_at,
                        received_at: now,
                        origin_commit_id: None,
                        moderation_grant: false,
                    },
                    event.retention,
                    None,
                )?;
                changed.extend(
                    update
                        .messages
                        .into_iter()
                        .map(|message| message.message_id_hex),
                );
                let conn = self.lock()?;
                // An event whose target retention erased records nothing, so
                // it gets no mark either.
                let marked = conn
                    .execute_cached(
                        "INSERT INTO app_event_imports (group_id_hex, message_id_hex, source_slot, imported_at)
                         SELECT ?1, ?2, ?3, ?4
                         WHERE EXISTS (
                             SELECT 1 FROM app_events WHERE group_id_hex = ?1 AND message_id_hex = ?2
                         )",
                        params![
                            group_id_hex,
                            event.message_id_hex,
                            source_slot.as_slice(),
                            u64_to_i64(now)?,
                        ],
                    )
                    .storage()?;
                imported += marked;
                if marked == 1 {
                    // The timeline insert's trigger ran before the mark existed,
                    // so the imported message's attachment slots go in now.
                    conn.execute_cached(
                        "INSERT OR IGNORE INTO attachment_history(group_id_hex,message_id_hex,
                            attachment_index,source_message_id_hex,source_epoch,sender,timeline_at,
                            received_at,order_class,order_primary,order_phase,order_at,slot_json,visible)
                         SELECT * FROM attachment_history_source
                         WHERE group_id_hex = ?1 AND message_id_hex = ?2",
                        params![group_id_hex, event.message_id_hex],
                    )
                    .storage()?;
                    // Only one key opens a ciphertext, so a key that differs
                    // from one the chat already holds for it is not stored.
                    for file_key in &event.file_keys {
                        conn.execute_cached(
                            "INSERT OR IGNORE INTO imported_media_file_keys
                                (group_id_hex, message_id_hex, ciphertext_sha256, file_key)
                             SELECT ?1, ?2, ?3, ?4
                             WHERE NOT EXISTS (
                                 SELECT 1 FROM imported_media_file_keys
                                 WHERE group_id_hex = ?1 AND ciphertext_sha256 = ?3
                                   AND file_key != ?4
                             )",
                            params![
                                group_id_hex,
                                event.message_id_hex,
                                file_key.ciphertext_sha256,
                                file_key.key.as_slice(),
                            ],
                        )
                        .storage()?;
                    }
                }
                if marked == 1
                    && let Some(grant) = event.moderation_grant
                {
                    changed.extend(grant_imported_authority_tx(
                        &conn,
                        group_id_hex,
                        &event.message_id_hex,
                        grant,
                    )?);
                }
            }
            let conn = self.lock()?;
            let messages = timeline_records_by_ids_tx(&conn, group_id_hex, changed)?;
            let changes = messages
                .iter()
                .cloned()
                .map(|message| TimelineMessageChange::Upsert {
                    trigger: TimelineUpdateTrigger::SnapshotRefresh,
                    message: Box::new(message),
                })
                .collect();
            Ok(AppEventImport {
                imported,
                update: TimelineProjectionUpdate {
                    group_id_hex: group_id_hex.to_owned(),
                    messages,
                    changes,
                },
            })
        })
    }

    /// Up to `limit` of the chat's app events after `after`, in chat order.
    /// Only rows with an MLS epoch have a place in chat order.
    ///
    /// A row stays out when branch selection withdrew it, its retention
    /// expired by `now`, it is local to this device (group-system rows, and
    /// this device's sends no relay accepted), its content no longer matches
    /// its id (a scrubbed control), or it is a deleted or removed message or
    /// targets one. A deletion or removal itself goes in.
    pub fn history_export_page(
        &self,
        group_id_hex: &str,
        after: Option<(u64, u64, &str)>,
        now: u64,
        limit: usize,
    ) -> StorageResult<Vec<HistoryExportRow>> {
        let (after_epoch, after_at, after_id) = match after {
            Some((epoch, at, id)) => (Some(u64_to_i64(epoch)?), Some(u64_to_i64(at)?), Some(id)),
            None => (None, None, None),
        };
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT event.message_id_hex, event.source_epoch, event.recorded_at, event.sender,
                        event.plaintext, event.kind, event.tags_json, event.retention_seconds,
                        CASE WHEN event.kind IN (1985, 4891) AND event.authority_state = 2
                             THEN event.moderation_grant END,
                        event.invalidated != 0
                        OR ifnull(event.retention_expires_at <= ?5, 0)
                        OR event.kind = 1210
                        OR (event.direction = 'sent' AND event.source_message_id_hex IS NULL)
                        OR EXISTS (
                            SELECT 1 FROM message_timeline AS message
                            WHERE message.group_id_hex = event.group_id_hex
                              AND message.message_id_hex = event.message_id_hex
                              AND message.deleted != 0
                        )
                        OR (event.kind NOT IN (5, 4891) AND EXISTS (
                            SELECT 1 FROM message_modifier_edges AS edge
                            JOIN message_timeline AS target
                              ON target.group_id_hex = edge.group_id_hex
                             AND target.message_id_hex = edge.target_message_id_hex
                            WHERE edge.group_id_hex = event.group_id_hex
                              AND edge.modifier_message_id_hex = event.message_id_hex
                              AND target.deleted != 0
                        ))
                 FROM app_events AS event
                 WHERE event.group_id_hex = ?1
                   AND event.source_epoch IS NOT NULL
                   AND (?2 IS NULL
                        OR (event.source_epoch, event.recorded_at, event.message_id_hex) > (?2, ?3, ?4))
                 ORDER BY event.source_epoch, event.recorded_at, event.message_id_hex
                 LIMIT ?6",
            )
            .storage()?;
        let rows = stmt
            .query_map(
                params![
                    group_id_hex,
                    after_epoch,
                    after_at,
                    after_id,
                    u64_to_i64(now)?,
                    i64::try_from(limit).unwrap_or(i64::MAX),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<bool>>(8)?,
                        row.get::<_, bool>(9)?,
                    ))
                },
            )
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(
                |(id, epoch, at, sender, plaintext, kind, tags, retention, grant, left_out)| {
                    let created_at = i64_to_u64(at)?;
                    let event = MarmotAppEvent::new(
                        sender,
                        created_at,
                        i64_to_u64(kind)?,
                        tags_from_json(tags)
                            .map_err(|err| StorageError::Backend(err.to_string()))?,
                        plaintext,
                    );
                    let event = (!left_out && event.id == id).then(|| -> StorageResult<_> {
                        Ok(HistoryExportEvent {
                            event,
                            retention_seconds: retention.map(i64_to_u64).transpose()?,
                            moderation_grant: grant,
                        })
                    });
                    Ok(HistoryExportRow {
                        source_epoch: i64_to_u64(epoch)?,
                        created_at,
                        message_id_hex: id,
                        event: event.transpose()?,
                    })
                },
            )
            .collect()
    }

    /// Replace the device names imported rows resolve their source against
    /// with `labels`, by roster slot. Kept in memory for this connection
    /// only, so every open starts with none.
    pub fn set_device_labels(&self, labels: &[(DeviceSlotId, String)]) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached("DELETE FROM temp.device_labels", [])
                .storage()?;
            for (slot, label) in labels {
                conn.execute_cached(
                    "INSERT OR REPLACE INTO temp.device_labels (slot, label) VALUES (?1, ?2)",
                    params![slot.as_slice(), label],
                )
                .storage()?;
            }
            Ok(())
        })
    }

    /// Each chat's latest history import: when it landed and the device it
    /// came from.
    pub fn latest_history_imports(&self) -> StorageResult<Vec<LatestHistoryImport>> {
        let conn = self.lock()?;
        // SQLite takes the bare columns from the row holding the maximum.
        let mut stmt = conn
            .prepare_cached(
                "SELECT imported.group_id_hex, imported.source_slot, label.label,
                        MAX(imported.imported_at)
                 FROM app_event_imports imported
                 LEFT JOIN temp.device_labels label ON label.slot = imported.source_slot
                 GROUP BY imported.group_id_hex ORDER BY imported.group_id_hex",
            )
            .storage()?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(group_id_hex, slot, label, imported_at)| {
                Ok(LatestHistoryImport {
                    group_id_hex,
                    source: HistoryImportSource::new(&slot, label),
                    imported_at: i64_to_u64(imported_at)?,
                })
            })
            .collect()
    }

    /// The roster slot of the device an app event was imported from, or none
    /// for a row that arrived live.
    pub fn app_event_import_source(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Option<DeviceSlotId>> {
        let slot = self
            .lock()?
            .query_row_cached(
                "SELECT source_slot FROM app_event_imports
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2",
                params![group_id_hex, message_id_hex],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .storage()?;
        slot.map(|slot| {
            DeviceSlotId::try_from(slot).map_err(|_| {
                StorageError::Backend("imported app event source slot is not 32 bytes".to_owned())
            })
        })
        .transpose()
    }

    /// The key a sibling sent with the imported chat message `message_id_hex`
    /// for its media reference with `ciphertext_sha256`. A message this device
    /// received itself has none.
    pub fn imported_media_file_key(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
        ciphertext_sha256: &str,
    ) -> StorageResult<Option<Zeroizing<[u8; 32]>>> {
        let key = self
            .lock()?
            .query_row_cached(
                "SELECT file_key FROM imported_media_file_keys
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND ciphertext_sha256 = ?3",
                params![group_id_hex, message_id_hex, ciphertext_sha256],
                |row| row.get::<_, Vec<u8>>(0).map(Zeroizing::new),
            )
            .optional()
            .storage()?;
        key.map(|key| file_key_bytes(&key)).transpose()
    }

    /// The imported key for the chat's media reference with
    /// `ciphertext_sha256`, for a caller that cannot name the message. Import
    /// refuses a second, different key for a held ciphertext, so the chat has
    /// at most one.
    pub fn imported_media_file_key_for_ciphertext(
        &self,
        group_id_hex: &str,
        ciphertext_sha256: &str,
    ) -> StorageResult<Option<Zeroizing<[u8; 32]>>> {
        let key = self
            .lock()?
            .query_row_cached(
                "SELECT file_key FROM imported_media_file_keys
                 WHERE group_id_hex = ?1 AND ciphertext_sha256 = ?2
                 LIMIT 1",
                params![group_id_hex, ciphertext_sha256],
                |row| row.get::<_, Vec<u8>>(0).map(Zeroizing::new),
            )
            .optional()
            .storage()?;
        key.map(|key| file_key_bytes(&key)).transpose()
    }

    /// Every imported key for the chat message `message_id_hex`, so a device
    /// that imported a message can pass its keys on.
    pub fn imported_media_file_keys(
        &self,
        group_id_hex: &str,
        message_id_hex: &str,
    ) -> StorageResult<Vec<ImportedFileKey>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(
                "SELECT ciphertext_sha256, file_key FROM imported_media_file_keys
                 WHERE group_id_hex = ?1 AND message_id_hex = ?2
                 ORDER BY ciphertext_sha256",
            )
            .storage()?;
        let rows = statement
            .query_map(params![group_id_hex, message_id_hex], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(1)?),
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        rows.into_iter()
            .map(|(ciphertext_sha256, key)| {
                Ok(ImportedFileKey {
                    ciphertext_sha256,
                    key: file_key_bytes(&key)?,
                })
            })
            .collect()
    }

    fn holds_app_event(&self, group_id_hex: &str, message_id_hex: &str) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM app_events WHERE group_id_hex = ?1 AND message_id_hex = ?2)",
                params![group_id_hex, message_id_hex],
                |row| row.get::<_, bool>(0),
            )
            .storage()
    }
}

/// Gives an imported review label or admin removal the sender's verdict, and
/// re-projects the rows it touches. The row was recorded with no authority, and
/// the verdict has no MLS state to bind it to, so it keeps no source context.
fn grant_imported_authority_tx(
    conn: &Connection,
    group_id_hex: &str,
    message_id_hex: &str,
    grant: bool,
) -> StorageResult<BTreeSet<String>> {
    let changed = conn
        .execute_cached(
            "UPDATE app_events SET authority_state = 2, authority_context = NULL, moderation_grant = ?3
             WHERE group_id_hex = ?1 AND message_id_hex = ?2 AND kind IN (1985, 4891)",
            params![group_id_hex, message_id_hex, grant],
        )
        .storage()?;
    if changed == 0 {
        return Ok(BTreeSet::new());
    }
    let Some((kind, tags)) = app_event_projection_parts_tx(conn, group_id_hex, message_id_hex)?
    else {
        return Ok(BTreeSet::new());
    };
    let ids = affected_timeline_message_ids_for_parts_tx(
        conn,
        group_id_hex,
        message_id_hex,
        kind,
        &tags,
    )?;
    for id in &ids {
        upsert_message_timeline_projection_for_message_tx(conn, group_id_hex, id)?;
    }
    Ok(ids)
}

fn file_key_bytes(key: &[u8]) -> StorageResult<Zeroizing<[u8; 32]>> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    if key.len() != bytes.len() {
        return Err(StorageError::Backend(
            "imported media file key is not 32 bytes".to_owned(),
        ));
    }
    bytes.copy_from_slice(key);
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteAccountStorage;
    use cgka_traits::app_event::{
        AppMessageAuthority, AppMessageRetentionDecision, MARMOT_APP_EVENT_KIND_CHAT,
        MARMOT_APP_EVENT_KIND_DELETE, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM,
        MARMOT_APP_EVENT_KIND_REACTION, MARMOT_APP_EVENT_KIND_REMOVE,
    };

    const GROUP: &str = "6767676767676767";
    const NOW: u64 = 100;

    fn author(n: u8) -> String {
        hex::encode([n; 32])
    }

    fn row(
        sender: u8,
        epoch: u64,
        at: u64,
        kind: u64,
        target: Option<&str>,
        text: &str,
    ) -> StoredAppEvent {
        let tags = target
            .map(|target| vec![vec!["e".to_owned(), target.to_owned()]])
            .unwrap_or_default();
        let event = MarmotAppEvent::new(author(sender), at, kind, tags.clone(), text);
        StoredAppEvent {
            group_id_hex: GROUP.to_owned(),
            source_message_id_hex: Some(format!("source-{}", event.id)),
            message_id_hex: event.id,
            source_epoch: Some(epoch),
            direction: "received".to_owned(),
            sender: author(sender),
            plaintext: text.to_owned(),
            kind,
            tags,
            recorded_at: at,
            received_at: at,
            origin_commit_id: None,
            moderation_grant: false,
        }
    }

    fn chat(sender: u8, epoch: u64, at: u64, text: &str) -> StoredAppEvent {
        row(sender, epoch, at, MARMOT_APP_EVENT_KIND_CHAT, None, text)
    }

    /// Each row's id with whether a bundle carries it.
    fn carried(rows: &[HistoryExportRow]) -> Vec<(String, bool)> {
        rows.iter()
            .map(|row| (row.message_id_hex.clone(), row.event.is_some()))
            .collect()
    }

    #[test]
    fn history_export_reads_chat_order_and_leaves_out_what_a_bundle_must_not_carry() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        // Chat order is epoch first, so `kept` sorts after `removed`.
        let kept = chat(1, 1, 10, "kept");
        let removed = chat(2, 1, 5, "removed by an admin");
        let deleted = chat(1, 2, 1, "deleted by its author");
        let reaction = row(
            2,
            2,
            2,
            MARMOT_APP_EVENT_KIND_REACTION,
            Some(&deleted.message_id_hex),
            "+",
        );
        let deletion = row(
            1,
            2,
            3,
            MARMOT_APP_EVENT_KIND_DELETE,
            Some(&deleted.message_id_hex),
            "",
        );
        let expired = chat(2, 2, 4, "expired");
        let withdrawn = chat(2, 2, 5, "withdrawn");
        let mut unsent = chat(1, 2, 6, "never accepted");
        unsent.direction = "sent".to_owned();
        unsent.source_message_id_hex = None;
        let system = row(1, 2, 7, MARMOT_APP_EVENT_KIND_GROUP_SYSTEM, None, "{}");
        let removal = row(
            1,
            3,
            1,
            MARMOT_APP_EVENT_KIND_REMOVE,
            Some(&removed.message_id_hex),
            r#"{"v":1,"action":"remove"}"#,
        );
        let scrubbed = chat(2, 3, 2, "scrubbed");
        let mut no_epoch = chat(2, 0, 3, "no epoch");
        no_epoch.source_epoch = None;

        s.record_app_event_with_source(
            &kept,
            Some(AppMessageRetentionDecision::new(10, 1_000)),
            None,
        )
        .unwrap();
        s.record_app_event_with_source(
            &expired,
            Some(AppMessageRetentionDecision::new(4, 10)),
            None,
        )
        .unwrap();
        for event in [
            &removed, &deleted, &reaction, &deletion, &withdrawn, &unsent, &system, &scrubbed,
            &no_epoch,
        ] {
            s.record_app_event(event).unwrap();
        }
        s.record_app_event_with_source(
            &removal,
            None,
            Some(AppMessageAuthority {
                source_context: [1; 32],
                moderation_grant: true,
            }),
        )
        .unwrap();
        s.invalidate_app_event_by_source(
            withdrawn.source_message_id_hex.as_deref().unwrap(),
            "withdrawn",
        )
        .unwrap();
        s.lock()
            .unwrap()
            .execute(
                "UPDATE app_events SET plaintext = '' WHERE message_id_hex = ?1",
                params![scrubbed.message_id_hex],
            )
            .unwrap();

        let rows = s.history_export_page(GROUP, None, NOW, 100).unwrap();
        assert_eq!(
            carried(&rows),
            [
                (&removed, false),
                (&kept, true),
                (&deleted, false),
                (&reaction, false),
                (&deletion, true),
                (&expired, false),
                (&withdrawn, false),
                (&unsent, false),
                (&system, false),
                (&removal, true),
                (&scrubbed, false),
            ]
            .map(|(event, carried)| (event.message_id_hex.clone(), carried))
        );
        let kept_row = rows[1].event.as_ref().unwrap();
        assert_eq!(kept_row.event.content, "kept");
        assert_eq!(kept_row.retention_seconds, Some(1_000));
        assert_eq!(kept_row.moderation_grant, None);
        assert_eq!(rows[9].event.as_ref().unwrap().moderation_grant, Some(true));
        assert_eq!((rows[9].source_epoch, rows[9].created_at), (3, 1));

        // Paging resumes after the last row it returned.
        let first = s.history_export_page(GROUP, None, NOW, 4).unwrap();
        let last = first.last().unwrap();
        let rest = s
            .history_export_page(
                GROUP,
                Some((last.source_epoch, last.created_at, &last.message_id_hex)),
                NOW,
                100,
            )
            .unwrap();
        assert_eq!([first, rest].concat(), rows);
    }

    #[test]
    fn an_unsettled_moderation_verdict_is_not_exported() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let target = chat(2, 1, 1, "target");
        let removal = row(
            1,
            1,
            2,
            MARMOT_APP_EVENT_KIND_REMOVE,
            Some(&target.message_id_hex),
            r#"{"v":1,"action":"remove"}"#,
        );
        s.record_app_event(&target).unwrap();
        s.record_app_event_with_source(&removal, None, None)
            .unwrap();
        let rows = s.history_export_page(GROUP, None, NOW, 100).unwrap();
        assert_eq!(rows[1].event.as_ref().unwrap().moderation_grant, None);
    }

    fn imported(event: &StoredAppEvent, file_keys: Vec<ImportedFileKey>) -> ImportedAppEvent {
        ImportedAppEvent {
            message_id_hex: event.message_id_hex.clone(),
            source_epoch: event.source_epoch.unwrap(),
            sender: event.sender.clone(),
            plaintext: event.plaintext.clone(),
            kind: event.kind,
            tags: event.tags.clone(),
            created_at: event.recorded_at,
            retention: None,
            moderation_grant: None,
            file_keys,
        }
    }

    fn file_key(ciphertext: u8, key: u8) -> ImportedFileKey {
        ImportedFileKey {
            ciphertext_sha256: hex::encode([ciphertext; 32]),
            key: Zeroizing::new([key; 32]),
        }
    }

    // mdk#2628 4.2a: a key is stored only with a row the import adds, and it
    // is zeroed and removed with that row.
    #[test]
    fn imported_file_keys_stay_with_the_rows_an_import_adds() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let held = chat(1, 1, 10, "held");
        let new = chat(1, 1, 11, "new");
        s.record_app_event(&held).unwrap();
        let slot = DeviceSlotId::from([0x11; 32]);
        s.import_app_events(
            GROUP,
            &slot,
            &[
                imported(&held, vec![file_key(0xaa, 1)]),
                imported(&new, vec![file_key(0xbb, 2)]),
            ],
            NOW,
        )
        .unwrap();

        assert!(
            s.imported_media_file_keys(GROUP, &held.message_id_hex)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.imported_media_file_keys(GROUP, &new.message_id_hex)
                .unwrap(),
            vec![file_key(0xbb, 2)]
        );
        assert_eq!(
            s.imported_media_file_key(GROUP, &new.message_id_hex, &hex::encode([0xbb; 32]))
                .unwrap()
                .map(|key| *key),
            Some([2; 32])
        );
        // A key belongs to its message: another message naming the same
        // ciphertext does not get it.
        assert!(
            s.imported_media_file_key(GROUP, &held.message_id_hex, &hex::encode([0xbb; 32]))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            s.imported_media_file_key_for_ciphertext(GROUP, &hex::encode([0xbb; 32]))
                .unwrap()
                .map(|key| *key),
            Some([2; 32])
        );
        assert!(
            s.imported_media_file_key_for_ciphertext(GROUP, &hex::encode([0xaa; 32]))
                .unwrap()
                .is_none()
        );

        let conn = s.lock().unwrap();
        conn.execute_batch(
            "CREATE TEMP TABLE removed_keys (file_key BLOB);
             CREATE TEMP TRIGGER record_removed_key AFTER DELETE ON imported_media_file_keys
             BEGIN INSERT INTO removed_keys VALUES (OLD.file_key); END;",
        )
        .unwrap();
        conn.execute(
            "DELETE FROM app_events WHERE group_id_hex = ?1 AND message_id_hex = ?2",
            params![GROUP, new.message_id_hex],
        )
        .unwrap();
        let removed: Vec<Vec<u8>> = conn
            .prepare("SELECT file_key FROM removed_keys")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        drop(conn);
        assert_eq!(removed, vec![vec![0; 32]]);
        assert!(
            s.imported_media_file_keys(GROUP, &new.message_id_hex)
                .unwrap()
                .is_empty()
        );
    }

    fn attachment_slots(s: &SqliteAppStorage) -> Vec<(String, String)> {
        s.lock()
            .unwrap()
            .prepare(
                "SELECT message_id_hex, source_message_id_hex FROM attachment_history ORDER BY 1",
            )
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    // mdk#2628 4.2a: an imported chat message gets attachment slots, under its
    // app event id, and keeps them when the chat's timeline is rebuilt.
    #[test]
    fn an_imported_attachment_keeps_its_slot_through_a_timeline_rebuild() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let tags = vec![vec![
            "imeta".to_owned(),
            "url https://blossom.example/aa".to_owned(),
        ]];
        let event =
            MarmotAppEvent::new(author(1), 10, MARMOT_APP_EVENT_KIND_CHAT, tags.clone(), "");
        let photo = StoredAppEvent {
            message_id_hex: event.id.clone(),
            tags,
            plaintext: String::new(),
            ..chat(1, 1, 10, "")
        };
        // A received row without a transport id that no import marks gets no
        // slot, as before.
        let unmarked = chat(2, 1, 11, "unmarked");
        s.record_app_event(&StoredAppEvent {
            source_message_id_hex: None,
            tags: photo.tags.clone(),
            ..unmarked
        })
        .unwrap();
        s.import_app_events(
            GROUP,
            &DeviceSlotId::from([0x11; 32]),
            &[imported(&photo, Vec::new())],
            NOW,
        )
        .unwrap();
        let expected = vec![(photo.message_id_hex.clone(), photo.message_id_hex.clone())];
        assert_eq!(attachment_slots(&s), expected);

        s.rebuild_message_timeline_for_group(GROUP).unwrap();
        assert_eq!(attachment_slots(&s), expected);
    }

    // mdk#2628 4.2a: only one key opens a ciphertext, so the chat keeps the
    // first key it imported for one and refuses a different one.
    #[test]
    fn a_different_key_for_a_held_ciphertext_is_not_stored() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let first = chat(1, 1, 10, "first");
        let same = chat(1, 1, 11, "same key");
        let other = chat(1, 2, 12, "other key");
        s.import_app_events(
            GROUP,
            &DeviceSlotId::from([0x11; 32]),
            &[
                imported(&first, vec![file_key(0xaa, 1)]),
                imported(&same, vec![file_key(0xaa, 1)]),
                imported(&other, vec![file_key(0xaa, 2)]),
            ],
            NOW,
        )
        .unwrap();
        assert_eq!(
            s.imported_media_file_keys(GROUP, &first.message_id_hex)
                .unwrap(),
            vec![file_key(0xaa, 1)]
        );
        assert_eq!(
            s.imported_media_file_keys(GROUP, &same.message_id_hex)
                .unwrap(),
            vec![file_key(0xaa, 1)]
        );
        assert!(
            s.imported_media_file_keys(GROUP, &other.message_id_hex)
                .unwrap()
                .is_empty()
        );
    }

    // mdk#2628 4.2a: an import skips a row this device holds, a repeat within
    // the batch, and a row whose retention expired; it marks what it adds with
    // its source and keeps that row's retention decision.
    #[test]
    fn an_import_adds_only_the_rows_this_device_lacks() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let source = DeviceSlotId::from([7; 32]);
        let held = chat(1, 3, 30, "live");
        let old = chat(2, 1, 10, "imported");
        let expired = chat(2, 2, 20, "expired");
        s.record_app_event(&held).unwrap();
        let retained = |event: &StoredAppEvent, seconds| ImportedAppEvent {
            retention: Some(AppMessageRetentionDecision::new(event.recorded_at, seconds)),
            ..imported(event, Vec::new())
        };

        let outcome = s
            .import_app_events(
                GROUP,
                &source,
                &[
                    ImportedAppEvent {
                        plaintext: "imported".to_owned(),
                        ..imported(&held, Vec::new())
                    },
                    retained(&old, 500),
                    imported(&old, Vec::new()),
                    retained(&expired, 5),
                ],
                NOW,
            )
            .unwrap();

        assert_eq!(outcome.imported, 1);
        let changed = outcome
            .update
            .changes
            .iter()
            .map(|change| match change {
                TimelineMessageChange::Upsert { trigger, message } => {
                    (message.message_id_hex.clone(), trigger.clone())
                }
                TimelineMessageChange::Remove { .. } => panic!("an import removes nothing"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            changed,
            [(
                old.message_id_hex.clone(),
                TimelineUpdateTrigger::SnapshotRefresh
            )]
        );

        let kept = s
            .timeline_message(GROUP, &held.message_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(kept.plaintext, "live");
        assert_eq!(kept.source_message_id_hex, held.source_message_id_hex);
        assert_eq!(
            s.app_event_import_source(GROUP, &held.message_id_hex)
                .unwrap(),
            None
        );

        let added = s
            .timeline_message(GROUP, &old.message_id_hex)
            .unwrap()
            .unwrap();
        assert_eq!(added.plaintext, "imported");
        assert_eq!(added.direction, "received");
        assert_eq!(added.source_message_id_hex, None);
        assert_eq!(added.source_epoch, Some(1));
        assert_eq!(added.retention_expires_at, Some(510));
        assert_eq!(
            s.app_event_import_source(GROUP, &old.message_id_hex)
                .unwrap(),
            Some(source)
        );
        assert!(
            s.timeline_message(GROUP, &expired.message_id_hex)
                .unwrap()
                .is_none()
        );
    }
    // mdk#2628 4.2d: an imported row names its source by the name last given
    // for it on this connection, and a live row names none. Each chat's
    // latest import reads the same way.
    #[test]
    fn an_imported_row_names_its_source_by_the_name_last_given() {
        let s = SqliteAccountStorage::in_memory().unwrap().app_storage();
        let (phone, laptop) = (DeviceSlotId::from([7; 32]), DeviceSlotId::from([8; 32]));
        let live = chat(1, 3, 30, "live");
        let first = chat(2, 1, 10, "first");
        let second = chat(2, 2, 20, "second");
        s.record_app_event(&live).unwrap();
        let named = |slot: DeviceSlotId, label: &str| HistoryImportSource {
            device_slot_id_hex: hex::encode(slot),
            device_label: label.to_owned(),
        };
        let source = |id: &str| {
            s.timeline_message(GROUP, id)
                .unwrap()
                .unwrap()
                .imported_from
        };
        let latest = || s.latest_history_imports().unwrap();

        s.set_device_labels(&[(phone, "Phone".to_owned())]).unwrap();
        let outcome = s
            .import_app_events(GROUP, &phone, &[imported(&first, Vec::new())], NOW)
            .unwrap();
        let [TimelineMessageChange::Upsert { message, .. }] = outcome.update.changes.as_slice()
        else {
            panic!("one upsert");
        };
        assert_eq!(message.imported_from, Some(named(phone, "Phone")));
        s.import_app_events(GROUP, &laptop, &[imported(&second, Vec::new())], NOW + 1)
            .unwrap();

        assert_eq!(source(&live.message_id_hex), None);
        assert_eq!(source(&second.message_id_hex), Some(named(laptop, "")));
        let page = s
            .message_timeline(TimelineMessageQuery {
                group_id_hex: Some(GROUP.to_owned()),
                ..TimelineMessageQuery::default()
            })
            .unwrap();
        assert_eq!(
            page.messages
                .iter()
                .map(|message| message.imported_from.clone())
                .collect::<Vec<_>>(),
            [Some(named(phone, "Phone")), Some(named(laptop, "")), None]
        );
        assert_eq!(
            latest(),
            [LatestHistoryImport {
                group_id_hex: GROUP.to_owned(),
                source: named(laptop, ""),
                imported_at: NOW + 1,
            }]
        );

        // The names given next replace them all.
        s.set_device_labels(&[(laptop, "Laptop".to_owned())])
            .unwrap();
        assert_eq!(source(&first.message_id_hex), Some(named(phone, "")));
        assert_eq!(latest()[0].source, named(laptop, "Laptop"));
    }
}
