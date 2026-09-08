//! Internal durable selected-presentation foundation. Runtime orchestration owns hydration.
use crate::{ChatListAvatar, SqliteAccountStorage, SqliteResultExt, serialize, u64_to_i64};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub const CHAT_PRESENTATION_BATCH_LIMIT: usize = 50;
const FORMAT: u32 = 1;
const MAX_BYTES: usize = 65536;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresentationText {
    Literal(String),
    UnnamedGroup { member_count: Option<u64> },
    UnavailableConversation,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresentationSource {
    Group,
    PeerProfile,
    PeerFallback,
    GroupFallback,
    UnknownFallback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresentationResolution {
    Cached,
    LastKnown,
    Fallback,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectedAvatar {
    RemoteImage {
        url: String,
        cache_key: String,
    },
    EncryptedGroupImage {
        image: ChatListAvatar,
        cache_key: String,
    },
    Placeholder {
        stable_seed: String,
        source: PresentationSource,
    },
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationPresentation {
    pub title: PresentationText,
    pub avatar: SelectedAvatar,
    pub title_source: PresentationSource,
    pub avatar_source: PresentationSource,
    pub peer_id: Option<String>,
    pub resolution: PresentationResolution,
}
impl std::fmt::Debug for ConversationPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationPresentation")
            .field("title_source", &self.title_source)
            .field("avatar_source", &self.avatar_source)
            .field("resolution", &self.resolution)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChatPresentation {
    pub presentation: ConversationPresentation,
    pub profile_version: Option<ChatPresentationVersion>,
}
impl std::fmt::Debug for StoredChatPresentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredChatPresentation")
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatPresentationVersion {
    pub store_epoch: Vec<u8>,
    pub revision: u64,
}
impl std::fmt::Debug for ChatPresentationVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatPresentationVersion")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}
/// Captured under the account lock. Binds a prepared value to this store and source generation.
#[derive(Clone)]
pub struct ChatPresentationInput {
    pub group_id_hex: String,
    pub source_version: ChatPresentationVersion,
    pub row_epoch: Vec<u8>,
    pub group_name: String,
    pub member_count: Option<u64>,
    pub members: Vec<String>,
    pub avatar_url: Option<String>,
    pub avatar: Option<ChatListAvatar>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatPresentationRead {
    Missing,
    Pending,
    Ready(Box<StoredChatPresentation>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatPresentationWrite {
    Applied,
    Unchanged,
    Stale,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    format: u32,
    value: StoredChatPresentation,
}
fn nonnegative(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}
fn decode_envelope(bytes: &[u8]) -> StorageResult<Envelope> {
    if bytes.len() > MAX_BYTES {
        return Err(invalid("oversized chat presentation"));
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid chat presentation encoding"))?;
    if envelope.format != FORMAT {
        return Err(invalid("unsupported chat presentation format"));
    }
    Ok(envelope)
}
fn invalid(detail: &str) -> StorageError {
    StorageError::Serialization(detail.to_owned())
}

impl SqliteAccountStorage {
    pub fn chat_presentation_version(&self) -> StorageResult<ChatPresentationVersion> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT store_epoch, revision FROM chat_presentation_meta WHERE id = 1",
            [],
            |r| {
                Ok(ChatPresentationVersion {
                    store_epoch: r.get(0)?,
                    revision: nonnegative(r, 1)?,
                })
            },
        )
        .storage()
    }
    /// Missing/pending are explicit; this read never writes or hydrates.
    pub fn chat_presentation(&self, group: &str) -> StorageResult<ChatPresentationRead> {
        let conn = self.lock()?;
        let bytes: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT presentation_json FROM chat_list_rows WHERE group_id_hex = ?1",
                [group],
                |r| r.get(0),
            )
            .optional()
            .storage()?;
        match bytes {
            None => Ok(ChatPresentationRead::Missing),
            Some(None) => Ok(ChatPresentationRead::Pending),
            Some(Some(bytes)) => {
                let envelope = decode_envelope(&bytes)?;
                Ok(ChatPresentationRead::Ready(Box::new(envelope.value)))
            }
        }
    }
    /// The pending partial index is the durable backfill worklist. Committed rows leave it;
    /// interruption or a later invalidation makes precisely that row available again.
    pub fn pending_chat_presentation_inputs(&self) -> StorageResult<Vec<ChatPresentationInput>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut query = conn
                .prepare_cached(
                    "SELECT group_id_hex FROM chat_list_rows INDEXED BY chat_presentation_pending
                 WHERE presentation_json IS NULL ORDER BY group_id_hex LIMIT ?1",
                )
                .storage()?;
            let groups = query
                .query_map([CHAT_PRESENTATION_BATCH_LIMIT as i64], |r| {
                    r.get::<_, String>(0)
                })
                .storage()?
                .collect::<rusqlite::Result<Vec<_>>>()
                .storage()?;
            drop(query);
            drop(conn);
            groups
                .iter()
                .map(|g| {
                    self.chat_presentation_input(g)?
                        .ok_or_else(|| invalid("presentation row disappeared"))
                })
                .collect()
        })
    }
    pub fn chat_presentation_input(
        &self,
        group: &str,
    ) -> StorageResult<Option<ChatPresentationInput>> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let input = conn.query_row(
                "SELECT m.store_epoch, r.presentation_source_revision, a.profile_name, a.member_count,
                        a.image_hash_hex, a.image_key_hex, a.image_nonce_hex, a.image_upload_key_hex,
                        a.image_media_type,
                        (SELECT component_data_hex FROM account_group_app_components c
                         WHERE c.group_id_hex = a.group_id_hex AND c.component_id = 32775), r.presentation_row_epoch
                 FROM chat_list_rows r JOIN account_groups a ON a.group_id_hex = r.group_id_hex
                 CROSS JOIN chat_presentation_meta m WHERE r.group_id_hex = ?1 AND m.id = 1", [group], |r| {
                    let hash: String = r.get(4)?;
                    Ok(ChatPresentationInput {
                        group_id_hex: group.to_owned(),
                        row_epoch: r.get(10)?,
                        source_version: ChatPresentationVersion { store_epoch: r.get(0)?, revision: nonnegative(r, 1)? },
                        group_name: r.get(2)?, member_count: r.get::<_, Option<i64>>(3)?.and_then(|n| u64::try_from(n).ok()), members: Vec::new(),
                        avatar_url: crate::chat_list::decoded_avatar_url(r.get::<_, Option<String>>(9)?.as_deref()),
                        avatar: if hash.is_empty() { None } else { Some(ChatListAvatar {
                            image_hash_hex: hash, image_key_hex: r.get(5)?, image_nonce_hex: r.get(6)?,
                            image_upload_key_hex: r.get(7)?, media_type: r.get(8)?,
                        }) },
                    })
                }
            ).optional().storage()?;
            let Some(mut input) = input else { return Ok(None); };
            let mut query = conn.prepare_cached("SELECT member_id_hex FROM chat_presentation_members WHERE group_id_hex = ?1 ORDER BY member_id_hex LIMIT 3").storage()?;
            let members = query.query_map([group], |r| r.get::<_, String>(0)).storage()?
                .collect::<rusqlite::Result<Vec<_>>>().storage()?;
            input.members = members;
            Ok(Some(input))
        })
    }
    /// Account orchestration supplies the complete authoritative two-member roster, including named groups.
    /// Other roster sizes/unknown membership clear peer evidence. Does not alter direct-chat reuse policy.
    pub fn set_chat_presentation_members(
        &self,
        group: &str,
        members: &[String],
    ) -> StorageResult<()> {
        let mut normalized: Vec<_> = members
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .collect();
        normalized.sort();
        normalized.dedup();
        if normalized.len() != 2
            || normalized
                .iter()
                .any(|s| s.is_empty() || hex::decode(s).is_err())
        {
            normalized.clear();
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let mut query = conn.prepare_cached("SELECT member_id_hex FROM chat_presentation_members WHERE group_id_hex = ?1 ORDER BY member_id_hex LIMIT 3").storage()?;
            let previous = query.query_map([group], |r| r.get::<_, String>(0)).storage()?
                .collect::<rusqlite::Result<Vec<_>>>().storage()?;
            drop(query);
            if previous == normalized { return Ok(()); }
            conn.execute("DELETE FROM chat_presentation_members WHERE group_id_hex = ?1", [group]).storage()?;
            for member in normalized { conn.execute("INSERT INTO chat_presentation_members VALUES (?1, ?2)", params![group, member]).storage()?; }
            conn.execute("UPDATE chat_list_rows SET presentation_json = NULL, presentation_source_revision = presentation_source_revision + 1 WHERE group_id_hex = ?1", [group]).storage()?;
            conn.execute("DELETE FROM chat_presentation_dependencies WHERE group_id_hex = ?1", [group]).storage()?;
            Ok(())
        })
    }
    /// Compare-and-store also makes batched backfill restart-safe. A failed write rolls back its dependencies.
    pub fn store_chat_presentation(
        &self,
        input: &ChatPresentationInput,
        value: &StoredChatPresentation,
    ) -> StorageResult<ChatPresentationWrite> {
        let bytes = serialize(&Envelope {
            format: FORMAT,
            value: value.clone(),
        })?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("oversized chat presentation"));
        }
        if let Some(peer) = &value.presentation.peer_id
            && (input.member_count != Some(2)
                || input.members.len() != 2
                || !input.members.contains(peer))
        {
            return Err(invalid("presentation peer is not in captured roster"));
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let existing: Option<Option<Vec<u8>>> = conn.query_row(
                "SELECT r.presentation_json FROM chat_list_rows r CROSS JOIN chat_presentation_meta m
                 WHERE r.group_id_hex = ?1 AND r.presentation_source_revision = ?2 AND m.id = 1 AND m.store_epoch = ?3 AND r.presentation_row_epoch = ?4",
                params![input.group_id_hex, u64_to_i64(input.source_version.revision)?, input.source_version.store_epoch, input.row_epoch], |r| r.get(0),
            ).optional().storage()?;
            let Some(existing) = existing else { return Ok(ChatPresentationWrite::Stale); };
            if existing.as_ref() == Some(&bytes) { return Ok(ChatPresentationWrite::Unchanged); }
            let old = existing.as_deref().map(decode_envelope).transpose()?;
            // A deletion is versioned too. An absent cache read must not undo accepted profile evidence.
            if let Some(old_version) = old.as_ref().and_then(|old| old.value.profile_version.as_ref()) {
                let Some(new_version) = &value.profile_version else { return Ok(ChatPresentationWrite::Stale); };
                if old_version.store_epoch == new_version.store_epoch && old_version.revision > new_version.revision {
                    return Ok(ChatPresentationWrite::Stale);
                }
            }
            let changed = old.as_ref().is_none_or(|old| old.value.presentation != value.presentation);
            conn.execute("UPDATE chat_list_rows SET presentation_json = ?2 WHERE group_id_hex = ?1", params![input.group_id_hex, bytes]).storage()?;
            if changed {
                conn.execute("UPDATE chat_presentation_meta SET revision = revision + 1 WHERE id = 1", []).storage()?;
            }
            conn.execute("DELETE FROM chat_presentation_dependencies WHERE group_id_hex = ?1", [&input.group_id_hex]).storage()?;
            let p = &value.presentation;
            let title = matches!(p.title_source, PresentationSource::PeerProfile | PresentationSource::PeerFallback);
            let avatar = matches!(p.avatar_source, PresentationSource::PeerProfile | PresentationSource::PeerFallback);
            if let Some(peer) = &p.peer_id && (title || avatar) {
                conn.execute("INSERT INTO chat_presentation_dependencies VALUES (?1, ?2, ?3)", params![input.group_id_hex, peer, i64::from(title) + 2 * i64::from(avatar)]).storage()?;
            }
            Ok(ChatPresentationWrite::Applied)
        })
    }
    pub fn chat_presentation_dependents(
        &self,
        member: &str,
        after: Option<&str>,
    ) -> StorageResult<Vec<String>> {
        let conn = self.lock()?;
        let mut query = conn.prepare_cached("SELECT group_id_hex FROM chat_presentation_dependencies WHERE member_id_hex = ?1 AND group_id_hex > ?2 ORDER BY group_id_hex LIMIT ?3").storage()?;
        query
            .query_map(
                params![
                    member,
                    after.unwrap_or(""),
                    CHAT_PRESENTATION_BATCH_LIMIT as i64
                ],
                |r| r.get::<_, String>(0),
            )
            .storage()?
            .collect::<rusqlite::Result<Vec<_>>>()
            .storage()
    }
}

#[cfg(test)]
mod tests;
