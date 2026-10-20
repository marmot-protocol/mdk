//! Manage storage (mdk#2314 step 5): what retained attachments hold on the
//! device, across both layouts (media-store files and legacy SQLCipher
//! bodies), and bulk removal.
//!
//! A retained attachment is a slot whose acquisition is complete, whose body
//! is readable and whose source is still current: the same rule as
//! [`SqliteAppStorage::retained_attachment_asset`]. Removal is the existing
//! explicit `Remove` (suppression plus the acquisition row, with body rows
//! and references cascading), and it reports the media files whose keys it
//! deleted so the caller can unlink them at once.
use super::*;
use media_store::FileId;

/// Account-wide storage held by retained attachments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttachmentStorageUsage {
    /// Ready retained media-store files, each counted once however many
    /// attachments share it.
    pub media_bytes: u64,
    /// Bodies still in the database (the legacy layout), as the retained-byte
    /// counter keeps them.
    pub legacy_bytes: u64,
    /// Retained attachments that read locally now.
    pub attachment_count: u64,
    /// The account database file, and the part of it that is free pages.
    pub database_bytes: u64,
    pub database_free_bytes: u64,
    /// The avatar and group-image cache: images still in the database plus
    /// each cache file once, however many owners share it. Unlike retained
    /// media it can be cleared and fetched again.
    pub cache_bytes: u64,
    /// Moving legacy bodies into the media store. From the database this is
    /// `NotNeeded` or `Running`; the app runtime adds what its batches saw.
    pub migration: AttachmentMigrationState,
}

/// Retained attachment bytes in one chat: each stored body once, however
/// many of the chat's attachments share it. Content shared with other chats
/// counts in each of them. `attachment_count` counts attachments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatAttachmentUsage {
    pub group_id_hex: String,
    pub bytes: u64,
    pub attachment_count: u64,
}

/// Where the next page of [`ChatAttachmentUsage`] starts (largest first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatUsageCursor {
    bytes: u64,
    group_id_hex: String,
}

/// One retained attachment, for a largest-first listing.
#[derive(Clone, PartialEq, Eq)]
pub struct RetainedAttachmentEntry {
    pub group_id_hex: String,
    pub message_id_hex: String,
    pub source_message_id_hex: String,
    pub attachment_index: u32,
    pub byte_count: u64,
    /// The published `imeta` tag, as stored JSON.
    pub slot_json: String,
    pub received_at: u64,
}

impl std::fmt::Debug for RetainedAttachmentEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedAttachmentEntry")
            .field("byte_count", &self.byte_count)
            .finish_non_exhaustive()
    }
}

/// Where the next page of [`RetainedAttachmentEntry`] starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSizeCursor {
    byte_count: u64,
    group_id_hex: String,
    message_id_hex: String,
    attachment_index: u32,
}

impl RetainedAttachmentEntry {
    /// The cursor that resumes a listing after this entry.
    pub fn cursor(&self) -> RetainedSizeCursor {
        RetainedSizeCursor {
            byte_count: self.byte_count,
            group_id_hex: self.group_id_hex.clone(),
            message_id_hex: self.message_id_hex.clone(),
            attachment_index: self.attachment_index,
        }
    }
}

impl ChatAttachmentUsage {
    /// The cursor that resumes a listing after this chat.
    pub fn cursor(&self) -> ChatUsageCursor {
        ChatUsageCursor {
            bytes: self.bytes,
            group_id_hex: self.group_id_hex.clone(),
        }
    }
}

/// The outcome of one bounded removal batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttachmentRemoval {
    /// Attachments removed in this batch.
    pub removed: usize,
    /// Media files whose keys this batch deleted; unlink them now.
    pub released_files: Vec<FileId>,
    /// Matching retained attachments remain; call again.
    pub more: bool,
}

/// The most attachments one removal batch touches.
pub const ATTACHMENT_REMOVAL_BATCH: usize = 64;

/// SQL for "`q` is a retained attachment at `now` (parameter `now_param`)".
fn retained(now_param: &str) -> String {
    format!(
        "q.state=3 AND {RETAINED_BODY} AND {SOURCE_MATCH}
         AND (q.expires_at IS NULL OR q.expires_at>{now_param})"
    )
}

fn page_limit(limit: usize) -> StorageResult<i64> {
    if limit == 0 || limit > 256 {
        return Err(StorageError::Backend(
            "invalid attachment storage page limit".into(),
        ));
    }
    Ok(limit as i64)
}

/// Removes one slot as explicit `Remove` does: records suppression and
/// deletes its acquisition, whose body rows and media reference cascade.
/// `None` when the slot is unknown. Otherwise the media files whose last
/// reference (and so whose key) went with it, for an immediate unlink.
pub(super) fn remove_slot(
    conn: &Connection,
    group: &str,
    message: &str,
    index: u32,
) -> StorageResult<Option<Vec<FileId>>> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM attachment_history
             WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)
             OR EXISTS(SELECT 1 FROM attachment_acquisition
             WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)
             OR EXISTS(SELECT 1 FROM attachment_removal_suppression
             WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3)",
            params![group, message, index],
            |r| r.get(0),
        )
        .storage()?;
    if !exists {
        return Ok(None);
    }
    let candidates = {
        let mut stmt = conn
            .prepare(
                "SELECT mr.file_id FROM media_file_refs mr
                 JOIN attachment_acquisition q ON q.token=mr.token
                 WHERE q.group_id_hex=?1 AND q.message_id_hex=?2 AND q.attachment_index=?3",
            )
            .storage()?;
        stmt.query_map(params![group, message, index], |r| r.get::<_, Vec<u8>>(0))
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?
    };
    conn.execute(
        "INSERT INTO attachment_removal_suppression VALUES(?1,?2,?3) ON CONFLICT DO NOTHING",
        params![group, message, index],
    )
    .storage()?;
    conn.execute(
        "DELETE FROM attachment_acquisition
         WHERE group_id_hex=?1 AND message_id_hex=?2 AND attachment_index=?3",
        params![group, message, index],
    )
    .storage()?;
    // The last reference's trigger deleted a file's row (its key); those
    // files are released and safe to unlink.
    let mut released = Vec::new();
    for id in candidates {
        let gone: bool = conn
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM media_files WHERE id=?1)",
                [&id],
                |r| r.get(0),
            )
            .storage()?;
        if gone && let Some(id) = FileId::from_slice(&id) {
            released.push(id);
        }
    }
    Ok(Some(released))
}

impl SqliteAppStorage {
    /// Account-wide usage across both layouts. Reads no bodies.
    pub fn attachment_storage_usage(&self, now: u64) -> StorageResult<AttachmentStorageUsage> {
        let conn = self.lock()?;
        let media_bytes: i64 = conn
            .query_row(
                "SELECT coalesce(sum(byte_len),0) FROM media_files WHERE state=1 AND category=1",
                [],
                |r| r.get(0),
            )
            .storage()?;
        let legacy_bytes: i64 = conn
            .query_row(
                "SELECT coalesce((SELECT byte_count FROM attachment_retention_usage WHERE id=1),0)",
                [],
                |r| r.get(0),
            )
            .storage()?;
        let attachment_count: i64 = conn
            .query_row(
                &format!(
                    "SELECT count(*) FROM attachment_acquisition q WHERE {}",
                    retained("?1")
                ),
                [u64_to_i64(now)?],
                |r| r.get(0),
            )
            .storage()?;
        let cache_bytes = crate::app::avatar_cache::usage(&conn)?.byte_count;
        let space = crate::app::storage_compaction::database_space_in(&conn)?;
        let remaining = super::legacy_migration::legacy_attachment_bytes_in(&conn)?;
        let unsigned = |value: i64| u64::try_from(value).unwrap_or(0);
        Ok(AttachmentStorageUsage {
            media_bytes: unsigned(media_bytes),
            legacy_bytes: unsigned(legacy_bytes),
            attachment_count: unsigned(attachment_count),
            database_bytes: space.file_bytes(),
            database_free_bytes: space.free_bytes(),
            cache_bytes,
            migration: if remaining == 0 {
                AttachmentMigrationState::NotNeeded
            } else {
                AttachmentMigrationState::Running {
                    remaining_bytes: remaining,
                }
            },
        })
    }

    /// Up to `limit` (1..=256) chats by retained attachment bytes, largest
    /// first, after `after`.
    pub fn attachment_storage_by_chat(
        &self,
        now: u64,
        after: Option<&ChatUsageCursor>,
        limit: usize,
    ) -> StorageResult<Vec<ChatAttachmentUsage>> {
        let limit = page_limit(limit)?;
        let (bytes, group) = after.map_or((i64::MAX, ""), |cursor| {
            (
                i64::try_from(cursor.bytes).unwrap_or(i64::MAX),
                cursor.group_id_hex.as_str(),
            )
        });
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                // One row per stored body within a chat: a media file is
                // counted once however many of the chat's attachments share
                // it, while each legacy body is its own stored copy.
                "SELECT group_id_hex,bytes,attachments FROM (
                   SELECT group_id_hex,sum(len) AS bytes,sum(slots) AS attachments FROM (
                     SELECT q.group_id_hex AS group_id_hex,max({RETAINED_BYTE_LEN}) AS len,
                            count(*) AS slots
                     FROM attachment_acquisition q WHERE {}
                     GROUP BY q.group_id_hex,coalesce(
                       'f'||(SELECT hex(mr.file_id) FROM media_file_refs mr
                             JOIN media_files mf ON mf.id=mr.file_id
                             WHERE mr.token=q.token AND mf.state=1),
                       't'||hex(q.token)))
                   GROUP BY group_id_hex)
                 WHERE bytes<?2 OR (bytes=?2 AND group_id_hex>?3)
                 ORDER BY bytes DESC,group_id_hex LIMIT ?4",
                retained("?1")
            ))
            .storage()?;
        stmt.query_map(params![u64_to_i64(now)?, bytes, group, limit], |r| {
            Ok(ChatAttachmentUsage {
                group_id_hex: r.get(0)?,
                bytes: nonnegative(r, 1)?,
                attachment_count: nonnegative(r, 2)?,
            })
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    /// Up to `limit` (1..=256) retained attachments, largest first, after
    /// `after`; optionally within one chat.
    pub fn largest_retained_attachments(
        &self,
        now: u64,
        group: Option<&str>,
        after: Option<&RetainedSizeCursor>,
        limit: usize,
    ) -> StorageResult<Vec<RetainedAttachmentEntry>> {
        let limit = page_limit(limit)?;
        let (bytes, cursor_group, cursor_message, cursor_index) =
            after.map_or((i64::MAX, "", "", -1i64), |cursor| {
                (
                    i64::try_from(cursor.byte_count).unwrap_or(i64::MAX),
                    cursor.group_id_hex.as_str(),
                    cursor.message_id_hex.as_str(),
                    i64::from(cursor.attachment_index),
                )
            });
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT g,m,s,i,len,slot,received FROM (
                   SELECT q.group_id_hex AS g,q.message_id_hex AS m,q.source_message_id_hex AS s,
                          q.attachment_index AS i,{RETAINED_BYTE_LEN} AS len,q.slot_json AS slot,
                          (SELECT h.received_at FROM attachment_history h
                           WHERE h.group_id_hex=q.group_id_hex AND h.message_id_hex=q.message_id_hex
                             AND h.attachment_index=q.attachment_index) AS received
                   FROM attachment_acquisition q
                   WHERE {} AND (?2 IS NULL OR q.group_id_hex=?2))
                 WHERE len<?3 OR (len=?3 AND (g,m,i)>(?4,?5,?6))
                 ORDER BY len DESC,g,m,i LIMIT ?7",
                retained("?1")
            ))
            .storage()?;
        stmt.query_map(
            params![
                u64_to_i64(now)?,
                group,
                bytes,
                cursor_group,
                cursor_message,
                cursor_index,
                limit
            ],
            |r| {
                Ok(RetainedAttachmentEntry {
                    group_id_hex: r.get(0)?,
                    message_id_hex: r.get(1)?,
                    source_message_id_hex: r.get(2)?,
                    attachment_index: r.get(3)?,
                    byte_count: nonnegative(r, 4)?,
                    slot_json: r.get(5)?,
                    received_at: r.get::<_, Option<i64>>(6)?.map_or(0, |v| v.max(0) as u64),
                })
            },
        )
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()
    }

    /// Removes up to [`ATTACHMENT_REMOVAL_BATCH`] retained attachments, as
    /// explicit `Remove` does, in one transaction: those of chat `group` (or
    /// every chat), received before `received_before` when given. Unlink the
    /// returned files, then call again while `more`.
    pub fn remove_retained_attachments(
        &self,
        now: u64,
        group: Option<&str>,
        received_before: Option<u64>,
    ) -> StorageResult<AttachmentRemoval> {
        // A bound past SQLite's integer range is later than every stored
        // received time, so it filters nothing.
        let before = received_before.and_then(|before| i64::try_from(before).ok());
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let slots = {
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT q.group_id_hex,q.message_id_hex,q.attachment_index
                         FROM attachment_acquisition q
                         WHERE {} AND (?2 IS NULL OR q.group_id_hex=?2)
                           AND (?3 IS NULL OR EXISTS(SELECT 1 FROM attachment_history h
                               WHERE h.group_id_hex=q.group_id_hex
                                 AND h.message_id_hex=q.message_id_hex
                                 AND h.attachment_index=q.attachment_index
                                 AND h.received_at<?3))
                         ORDER BY q.group_id_hex,q.message_id_hex,q.attachment_index
                         LIMIT ?4",
                        retained("?1")
                    ))
                    .storage()?;
                stmt.query_map(
                    params![
                        u64_to_i64(now)?,
                        group,
                        before,
                        (ATTACHMENT_REMOVAL_BATCH + 1) as i64
                    ],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, u32>(2)?,
                        ))
                    },
                )
                .storage()?
                .collect::<Result<Vec<_>, _>>()
                .storage()?
            };
            let more = slots.len() > ATTACHMENT_REMOVAL_BATCH;
            let mut removal = AttachmentRemoval {
                more,
                ..Default::default()
            };
            for (group, message, index) in slots.into_iter().take(ATTACHMENT_REMOVAL_BATCH) {
                if let Some(released) = remove_slot(&conn, &group, &message, index)? {
                    removal.removed += 1;
                    removal.released_files.extend(released);
                }
            }
            Ok(removal)
        })
    }
}
