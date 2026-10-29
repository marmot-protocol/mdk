//! Small state shared with this account's other devices (mdk#2628 item 4.3):
//! each chat's read position, pin, mute and archive state. See migration 0142
//! for the columns.
//!
//! Items hold the account's winning value; this device's own chat state stays
//! in its usual tables. [`SqliteAppStorage::sync_small_state`] keeps the two
//! together in one transaction:
//!
//! - A local state that differs from what this device last observed is a
//!   change its user made here: it becomes the item's new value, one version
//!   higher, and is owed to the siblings. Nothing hooks the setters, so every
//!   path that changes local state is covered, and a chat that disappears is
//!   never taken for a change.
//! - Received items are merged under the caller's [`SmallStateRule`].
//! - A winning value not yet applied to a chat this device holds is applied:
//!   pins, mutes and read positions here, archives by the caller, which owns
//!   the in-memory account state.
//!
//! Nothing happens before [`SqliteAppStorage::start_small_state`].

use super::{
    ChatPinError, MentionClassifier, pinned_chat_order_tx, read_state_tx, refresh_chat_list_row_tx,
    rewrite_pinned_chat_order_tx,
};
use crate::base::connection::CachedSql;
use crate::{
    SqliteAppStorage, SqliteResultExt, i64_to_u64, u64_to_i64, unix_now_ms, unix_now_seconds,
};
use cgka_traits::storage::{StorageError, StorageResult};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{BTreeMap, BTreeSet};

/// The largest number an item carries, as a version, epoch or time: the
/// largest integer every JSON reader holds exactly.
pub const MAX_SMALL_STATE_NUMBER: u64 = (1 << 53) - 1;

/// Which setting of a chat an item holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SmallStateItemName {
    Read,
    Pin,
    Mute,
    Archive,
}

impl SmallStateItemName {
    pub const ALL: [Self; 4] = [Self::Read, Self::Pin, Self::Mute, Self::Archive];
    const VERSIONED: [Self; 3] = [Self::Pin, Self::Mute, Self::Archive];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Pin => "pin",
            Self::Mute => "mute",
            Self::Archive => "archive",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|name| name.as_str() == value)
    }
}

/// A message's place in its chat: the epoch it was sent in, its
/// `created_at` and its app event id. Positions compare in that order, the
/// same on every device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReadPosition {
    pub epoch: u64,
    pub at: u64,
    /// 64 lowercase hex characters, so string order is byte order.
    pub message_id_hex: String,
}

/// Whether a chat is muted, and until when.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MuteSetting {
    Unmuted,
    /// Until unmuted.
    Muted,
    /// Until this time, in seconds.
    MutedUntil(u64),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SmallStateValue {
    Read(ReadPosition),
    Pin(bool),
    Mute(MuteSetting),
    Archive(bool),
}

impl SmallStateValue {
    pub const fn name(&self) -> SmallStateItemName {
        match self {
            Self::Read(_) => SmallStateItemName::Read,
            Self::Pin(_) => SmallStateItemName::Pin,
            Self::Mute(_) => SmallStateItemName::Mute,
            Self::Archive(_) => SmallStateItemName::Archive,
        }
    }
}

/// The version and change id of a pin, mute or archive value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SmallStateVersion {
    pub version: u64,
    pub change_id: [u8; 16],
}

/// One chat's value of one item.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SmallStateItem {
    pub group_id_hex: String,
    pub value: SmallStateValue,
    /// `None` for a read position, `Some` for every other item.
    pub version: Option<SmallStateVersion>,
}

impl SmallStateItem {
    pub const fn name(&self) -> SmallStateItemName {
        self.value.name()
    }

    /// Whether the item keeps the rules every device holds it to: a chat as
    /// lowercase hex, a version on every item but a read position, and every
    /// number at most [`MAX_SMALL_STATE_NUMBER`]. Storage skips one that
    /// does not.
    pub fn is_valid(&self) -> bool {
        let number = |value: u64| value <= MAX_SMALL_STATE_NUMBER;
        let chat = !self.group_id_hex.is_empty()
            && self.group_id_hex.len().is_multiple_of(2)
            && is_lower_hex(&self.group_id_hex);
        let value = match &self.value {
            SmallStateValue::Read(position) => {
                self.version.is_none()
                    && number(position.epoch)
                    && number(position.at)
                    && position.message_id_hex.len() == 64
                    && is_lower_hex(&position.message_id_hex)
            }
            SmallStateValue::Mute(MuteSetting::MutedUntil(until)) => number(*until),
            SmallStateValue::Pin(_) | SmallStateValue::Mute(_) | SmallStateValue::Archive(_) => {
                true
            }
        };
        let version = match (&self.value, self.version) {
            (SmallStateValue::Read(_), version) => version.is_none(),
            (_, Some(version)) => version.version >= 1 && number(version.version),
            (_, None) => false,
        };
        chat && value && version
    }
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// How received values merge; the app owns it.
pub trait SmallStateRule {
    /// Whether `incoming` beats `held`, two values of the same chat and item.
    fn wins(&self, incoming: &SmallStateItem, held: &SmallStateItem) -> bool;
    /// A fresh change id for a change this device's user made.
    fn new_change_id(&self) -> [u8; 16];
    /// Where a chat that becomes pinned through small state goes among
    /// `pinned`, this device's pinned chats in order. Clamped to the end.
    fn pin_index(&self, pinned: &[String]) -> usize;
}

/// What one [`SqliteAppStorage::sync_small_state`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SmallStateSync {
    /// Chats whose local pin, mute or read state this call changed.
    pub applied: BTreeMap<String, BTreeSet<SmallStateItemName>>,
    /// Winning archive states the caller still has to apply. The next call
    /// records them as applied once the chat's state matches.
    pub archive_to_apply: Vec<(String, bool)>,
    /// Local changes this call recorded; they are owed to the siblings.
    pub recorded: usize,
}

/// A sibling whose whole snapshot this device still needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmallStateSnapshotRequest {
    /// The sibling's slot.
    pub to: [u8; 32],
    /// The latest request to it; `None` before the first.
    pub request: Option<[u8; 16]>,
    /// When that request was sent, in seconds; `None` to ask at once.
    pub asked_at: Option<u64>,
}

impl SqliteAppStorage {
    /// Start taking part in small state, owing a snapshot request. `true`
    /// when this call started it.
    pub fn start_small_state(&self) -> StorageResult<bool> {
        let inserted = self
            .lock()?
            .execute_cached(
                "INSERT OR IGNORE INTO small_state_sync (id, started_at, snapshot_owed)
                 VALUES (1, ?1, 1)",
                params![u64_to_i64(unix_now_seconds())?],
            )
            .storage()?;
        Ok(inserted == 1)
    }

    pub fn small_state_started(&self) -> StorageResult<bool> {
        small_state_started_tx(&*self.lock()?)
    }

    /// Whether this device still has to ask a sibling for a snapshot.
    pub fn small_state_snapshot_owed(&self) -> StorageResult<bool> {
        self.lock()?
            .query_row_cached(
                "SELECT EXISTS(SELECT 1 FROM small_state_sync WHERE id = 1 AND snapshot_owed = 1)",
                [],
                |row| row.get(0),
            )
            .storage()
    }

    /// Owe snapshot requests: this device may have lost messages its
    /// siblings sent. Does nothing before [`Self::start_small_state`].
    pub fn owe_small_state_snapshots(&self) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "UPDATE small_state_sync SET snapshot_owed = 1 WHERE id = 1",
                [],
            )
            .storage()?;
        Ok(())
    }

    /// Begin owed snapshot requests at the device group's tip epoch `tip`:
    /// this device needs a whole snapshot from each sibling in `to`, and owes
    /// its siblings every item it holds. Earlier requests are forgotten. Does
    /// nothing unless requests are owed.
    pub fn begin_small_state_snapshots(&self, to: &[[u8; 32]], tip: u64) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let begun = conn
                .execute_cached(
                    "UPDATE small_state_sync SET snapshot_owed = 0, snapshot_round_tip = ?1
                     WHERE id = 1 AND snapshot_owed = 1",
                    params![u64_to_i64(tip)?],
                )
                .storage()?;
            if begun == 0 {
                return Ok(());
            }
            conn.execute_cached("DELETE FROM small_state_snapshot_requests", [])
                .storage()?;
            for slot in to {
                conn.execute_cached(
                    "INSERT OR IGNORE INTO small_state_snapshot_requests (to_slot) VALUES (?1)",
                    params![slot.as_slice()],
                )
                .storage()?;
            }
            conn.execute_cached(
                "UPDATE small_state_items SET unsent = 1 WHERE unsent = 0",
                [],
            )
            .storage()?;
            Ok(())
        })
    }

    /// The device group's tip epoch when this device last began asking for
    /// snapshots; `None` before the first time.
    pub fn small_state_snapshot_round_tip(&self) -> StorageResult<Option<u64>> {
        self.lock()?
            .query_row_cached(
                "SELECT snapshot_round_tip FROM small_state_sync WHERE id = 1",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .storage()?
            .flatten()
            .map(i64_to_u64)
            .transpose()
    }

    /// The siblings whose whole snapshot this device still needs, in slot
    /// order.
    pub fn small_state_snapshot_requests(&self) -> StorageResult<Vec<SmallStateSnapshotRequest>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(
                "SELECT to_slot, request, asked_at FROM small_state_snapshot_requests
                 ORDER BY to_slot",
            )
            .storage()?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            })
            .storage()?
            .collect::<Result<Vec<_>, _>>()
            .storage()?;
        let corrupt = || StorageError::Backend("corrupt small-state snapshot request".into());
        rows.into_iter()
            .map(|(to, request, asked_at)| {
                Ok(SmallStateSnapshotRequest {
                    to: to.try_into().map_err(|_| corrupt())?,
                    request: request
                        .map(|request| request.try_into().map_err(|_| corrupt()))
                        .transpose()?,
                    asked_at: asked_at.map(i64_to_u64).transpose()?,
                })
            })
            .collect()
    }

    /// Record a request sent to `to` with id `request`. The parts of an
    /// earlier request's answer no longer count.
    pub fn record_small_state_snapshot_asked(
        &self,
        to: &[u8; 32],
        request: &[u8; 16],
        asked_at: u64,
    ) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            conn.execute_cached(
                "DELETE FROM small_state_snapshot_parts
                 WHERE request = (SELECT request FROM small_state_snapshot_requests
                                  WHERE to_slot = ?1)",
                params![to.as_slice()],
            )
            .storage()?;
            conn.execute_cached(
                "UPDATE small_state_snapshot_requests SET request = ?2, asked_at = ?3
                 WHERE to_slot = ?1",
                params![to.as_slice(), request.as_slice(), u64_to_i64(asked_at)?],
            )
            .storage()?;
            Ok(())
        })
    }

    /// Stop needing `to`'s snapshot: it is no longer an active sibling.
    pub fn drop_small_state_snapshot_request(&self, to: &[u8; 32]) -> StorageResult<()> {
        self.lock()?
            .execute_cached(
                "DELETE FROM small_state_snapshot_requests WHERE to_slot = ?1",
                params![to.as_slice()],
            )
            .storage()?;
        Ok(())
    }

    /// Ask again at once for the request `request`, which branch selection
    /// withdrew. `false` when no sibling's latest request has that id.
    pub fn withdraw_small_state_snapshot_request(&self, request: &[u8; 16]) -> StorageResult<bool> {
        Ok(self
            .lock()?
            .execute_cached(
                "UPDATE small_state_snapshot_requests SET asked_at = NULL WHERE request = ?1",
                params![request.as_slice()],
            )
            .storage()?
            == 1)
    }

    /// Record that part `part` of `parts` of the answer to `request` was
    /// merged. `true` when that makes the answer whole: the sibling's snapshot
    /// is no longer needed.
    pub fn record_small_state_snapshot_part(
        &self,
        request: &[u8; 16],
        part: u64,
        parts: u64,
    ) -> StorageResult<bool> {
        if part == 0 || part > parts || parts > MAX_SMALL_STATE_NUMBER {
            return Ok(false);
        }
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            let inserted = conn
                .execute_cached(
                    "INSERT OR IGNORE INTO small_state_snapshot_parts (request, parts, part)
                     SELECT request, ?2, ?3 FROM small_state_snapshot_requests
                     WHERE request = ?1",
                    params![request.as_slice(), u64_to_i64(parts)?, u64_to_i64(part)?],
                )
                .storage()?;
            if inserted == 0 {
                return Ok(false);
            }
            let merged: i64 = conn
                .query_row_cached(
                    "SELECT COUNT(*) FROM small_state_snapshot_parts
                     WHERE request = ?1 AND parts = ?2",
                    params![request.as_slice(), u64_to_i64(parts)?],
                    |row| row.get(0),
                )
                .storage()?;
            if i64_to_u64(merged)? < parts {
                return Ok(false);
            }
            conn.execute_cached(
                "DELETE FROM small_state_snapshot_requests WHERE request = ?1",
                params![request.as_slice()],
            )
            .storage()?;
            Ok(true)
        })
    }

    /// Record local changes, merge `incoming`, and apply winning values, in
    /// one transaction. Does nothing before [`Self::start_small_state`].
    pub fn sync_small_state(
        &self,
        local_account_id_hex: &str,
        incoming: &[SmallStateItem],
        rule: &dyn SmallStateRule,
        mention_classifier: &MentionClassifier<'_>,
    ) -> StorageResult<SmallStateSync> {
        self.connection.with_transaction(|| {
            let mut conn = self.lock()?;
            let mut outcome = SmallStateSync::default();
            if !small_state_started_tx(&conn)? {
                return Ok(outcome);
            }
            let now = unix_now_seconds();
            forget_left_chats_tx(&conn)?;
            let chats = held_chats_tx(&conn)?;
            outcome.recorded = record_local_changes_tx(&conn, &chats, rule, now)?;
            for item in incoming.iter().filter(|item| item.is_valid()) {
                merge_item_tx(&conn, item, rule, now)?;
            }
            apply_winners_tx(&mut conn, &chats, rule, &mut outcome)?;
            for (group_id_hex, names) in &outcome.applied {
                if names.contains(&SmallStateItemName::Read) {
                    refresh_chat_list_row_tx(
                        &conn,
                        local_account_id_hex,
                        group_id_hex,
                        mention_classifier,
                    )?;
                }
            }
            Ok(outcome)
        })
    }

    /// Every item this device holds, for a snapshot.
    pub fn small_state_items(&self) -> StorageResult<Vec<SmallStateItem>> {
        items_tx(&*self.lock()?, false)
    }

    /// The items this device still owes its siblings.
    pub fn unsent_small_state_items(&self) -> StorageResult<Vec<SmallStateItem>> {
        items_tx(&*self.lock()?, true)
    }

    /// Mark `items` sent, where each still holds the value that was sent. A
    /// newer local change made since stays owed.
    pub fn mark_small_state_sent(&self, items: &[SmallStateItem]) -> StorageResult<()> {
        self.connection.with_transaction(|| {
            let conn = self.lock()?;
            for item in items {
                if held_item_tx(&conn, &item.group_id_hex, item.name())?.as_ref() == Some(item) {
                    conn.execute_cached(
                        "UPDATE small_state_items SET unsent = 0
                         WHERE group_id_hex = ?1 AND item = ?2",
                        params![item.group_id_hex, item.name().as_str()],
                    )
                    .storage()?;
                }
            }
            Ok(())
        })
    }

    /// Owe the siblings every item this device holds, with its version and
    /// change id: a small-state message it sent or merged was withdrawn, or it
    /// may have lost messages its siblings need. Returns how many are owed
    /// again.
    pub fn owe_all_small_state_items(&self) -> StorageResult<usize> {
        self.lock()?
            .execute_cached(
                "UPDATE small_state_items SET unsent = 1 WHERE unsent = 0",
                [],
            )
            .storage()
    }
}

fn small_state_started_tx(conn: &Connection) -> StorageResult<bool> {
    conn.query_row_cached(
        "SELECT EXISTS(SELECT 1 FROM small_state_sync WHERE id = 1)",
        [],
        |row| row.get(0),
    )
    .storage()
}

/// One chat this device holds, with its own state of each item.
struct HeldChat {
    pinned: bool,
    archived: bool,
    /// `muted_until_ms` as stored: `None` without a row, `Some(None)` muted
    /// until unmuted.
    mute: Option<Option<i64>>,
    /// The read marker's position, when it names a delivered message.
    read: Option<ReadPosition>,
    /// The read marker's canonical order key, to compare a position with.
    read_key: Option<(u8, u64, u8, u64, String)>,
}

impl HeldChat {
    fn observed(&self, name: SmallStateItemName) -> String {
        match name {
            SmallStateItemName::Pin => flag_text(self.pinned),
            SmallStateItemName::Archive => flag_text(self.archived),
            SmallStateItemName::Mute => mute_text(self.mute),
            SmallStateItemName::Read => String::new(),
        }
    }

    fn value(&self, name: SmallStateItemName) -> Option<SmallStateValue> {
        match name {
            SmallStateItemName::Pin => Some(SmallStateValue::Pin(self.pinned)),
            SmallStateItemName::Archive => Some(SmallStateValue::Archive(self.archived)),
            SmallStateItemName::Mute => Some(SmallStateValue::Mute(match self.mute {
                None => MuteSetting::Unmuted,
                Some(None) => MuteSetting::Muted,
                Some(Some(until_ms)) => MuteSetting::MutedUntil(
                    u64::try_from(until_ms)
                        .unwrap_or_default()
                        .div_ceil(1000)
                        .min(MAX_SMALL_STATE_NUMBER),
                ),
            })),
            SmallStateItemName::Read => self.read.clone().map(SmallStateValue::Read),
        }
    }

    fn is_default(&self, name: SmallStateItemName) -> bool {
        match name {
            SmallStateItemName::Pin => !self.pinned,
            SmallStateItemName::Archive => !self.archived,
            SmallStateItemName::Mute => self.mute.is_none(),
            SmallStateItemName::Read => self.read.is_none(),
        }
    }
}

fn flag_text(flag: bool) -> String {
    if flag { "1" } else { "0" }.to_owned()
}

fn mute_text(mute: Option<Option<i64>>) -> String {
    match mute {
        None => "off".to_owned(),
        Some(None) => "on".to_owned(),
        Some(Some(until_ms)) => format!("until:{until_ms}"),
    }
}

fn held_chats_tx(conn: &Connection) -> StorageResult<BTreeMap<String, HeldChat>> {
    let mut statement = conn
        .prepare_cached(
            "SELECT ag.group_id_hex, ag.archived,
                    EXISTS(SELECT 1 FROM chat_pin_positions AS pin
                           WHERE pin.group_id_hex = ag.group_id_hex),
                    mute.group_id_hex IS NOT NULL, mute.muted_until_ms
             FROM account_groups AS ag
             LEFT JOIN chat_notification_settings AS mute
                ON mute.group_id_hex = ag.group_id_hex",
        )
        .storage()?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? != 0,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut chats = BTreeMap::new();
    for (group_id_hex, archived, pinned, muted_row, muted_until_ms) in rows {
        let read_key = read_state_tx(conn, &group_id_hex)?.and_then(|state| {
            state
                .canonical_order_key()
                .map(|(class, primary, phase, at, id)| (class, primary, phase, at, id.to_owned()))
        });
        let read = read_key
            .as_ref()
            .filter(|(class, _, phase, _, _)| *class == 1 && *phase == 1)
            .map(|(_, epoch, _, at, id)| ReadPosition {
                epoch: *epoch,
                at: *at,
                message_id_hex: id.clone(),
            });
        chats.insert(
            group_id_hex,
            HeldChat {
                pinned,
                archived,
                mute: muted_row.then_some(muted_until_ms),
                read,
                read_key,
            },
        );
    }
    Ok(chats)
}

/// A chat this device left keeps its items but no longer has its own state of
/// them: when it comes back, its items are applied again, never taken for a
/// change.
fn forget_left_chats_tx(conn: &Connection) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE small_state_items SET observed = NULL
         WHERE observed IS NOT NULL
           AND group_id_hex NOT IN (SELECT group_id_hex FROM account_groups)",
        [],
    )
    .storage()?;
    Ok(())
}

/// A held row: the winning item and what this device last observed.
struct HeldRow {
    item: SmallStateItem,
    observed: Option<String>,
}

fn held_row_tx(
    conn: &Connection,
    group_id_hex: &str,
    name: SmallStateItemName,
) -> StorageResult<Option<HeldRow>> {
    conn.query_row_cached(
        "SELECT version, change_id, flag, mute_until, read_epoch, read_at,
                read_message_id_hex, observed
         FROM small_state_items WHERE group_id_hex = ?1 AND item = ?2",
        params![group_id_hex, name.as_str()],
        |row| {
            Ok((
                row.get::<_, Option<i64>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        },
    )
    .optional()
    .storage()?
    .map(
        |(version, change_id, flag, mute_until, epoch, at, message_id_hex, observed)| {
            let item = decode_item(
                group_id_hex,
                name,
                version,
                change_id,
                flag,
                mute_until,
                epoch.zip(at).zip(message_id_hex),
            )?;
            Ok(HeldRow { item, observed })
        },
    )
    .transpose()
}

fn held_item_tx(
    conn: &Connection,
    group_id_hex: &str,
    name: SmallStateItemName,
) -> StorageResult<Option<SmallStateItem>> {
    Ok(held_row_tx(conn, group_id_hex, name)?.map(|row| row.item))
}

#[allow(clippy::too_many_arguments)]
fn decode_item(
    group_id_hex: &str,
    name: SmallStateItemName,
    version: Option<i64>,
    change_id: Option<Vec<u8>>,
    flag: Option<i64>,
    mute_until: Option<i64>,
    read: Option<((i64, i64), String)>,
) -> StorageResult<SmallStateItem> {
    let corrupt = || StorageError::Backend("corrupt small-state item".into());
    let value = match name {
        SmallStateItemName::Read => {
            let ((epoch, at), message_id_hex) = read.ok_or_else(corrupt)?;
            SmallStateValue::Read(ReadPosition {
                epoch: i64_to_u64(epoch)?,
                at: i64_to_u64(at)?,
                message_id_hex,
            })
        }
        SmallStateItemName::Pin => SmallStateValue::Pin(flag.ok_or_else(corrupt)? != 0),
        SmallStateItemName::Archive => SmallStateValue::Archive(flag.ok_or_else(corrupt)? != 0),
        SmallStateItemName::Mute => SmallStateValue::Mute(match (flag, mute_until) {
            (Some(0), _) => MuteSetting::Unmuted,
            (Some(_), None) => MuteSetting::Muted,
            (Some(_), Some(until)) => MuteSetting::MutedUntil(i64_to_u64(until)?),
            (None, _) => return Err(corrupt()),
        }),
    };
    let version = match name {
        SmallStateItemName::Read => None,
        _ => Some(SmallStateVersion {
            version: i64_to_u64(version.ok_or_else(corrupt)?)?,
            change_id: change_id
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                .ok_or_else(corrupt)?,
        }),
    };
    Ok(SmallStateItem {
        group_id_hex: group_id_hex.to_owned(),
        value,
        version,
    })
}

fn items_tx(conn: &Connection, unsent_only: bool) -> StorageResult<Vec<SmallStateItem>> {
    let mut statement = conn
        .prepare_cached(
            "SELECT group_id_hex, item FROM small_state_items
             WHERE ?1 = 0 OR unsent = 1
             ORDER BY group_id_hex, item",
        )
        .storage()?;
    let keys = statement
        .query_map(params![i64::from(unsent_only)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .storage()?
        .collect::<Result<Vec<_>, _>>()
        .storage()?;
    let mut items = Vec::with_capacity(keys.len());
    for (group_id_hex, name) in keys {
        let name = SmallStateItemName::parse(&name)
            .ok_or_else(|| StorageError::Backend("corrupt small-state item".into()))?;
        if let Some(item) = held_item_tx(conn, &group_id_hex, name)? {
            items.push(item);
        }
    }
    Ok(items)
}

/// Write `item` as the held value: this device's user's change, owed to the
/// siblings (`unsent`), or a sibling's that won.
fn write_item_tx(
    conn: &Connection,
    item: &SmallStateItem,
    observed: Option<&str>,
    unsent: bool,
    now: u64,
) -> StorageResult<()> {
    let (flag, mute_until, read) = match &item.value {
        SmallStateValue::Read(position) => (None, None, Some(position)),
        SmallStateValue::Pin(flag) | SmallStateValue::Archive(flag) => {
            (Some(i64::from(*flag)), None, None)
        }
        SmallStateValue::Mute(MuteSetting::Unmuted) => (Some(0), None, None),
        SmallStateValue::Mute(MuteSetting::Muted) => (Some(1), None, None),
        SmallStateValue::Mute(MuteSetting::MutedUntil(until)) => {
            (Some(1), Some(u64_to_i64(*until)?), None)
        }
    };
    conn.execute_cached(
        "INSERT INTO small_state_items (
            group_id_hex, item, version, change_id, flag, mute_until,
            read_epoch, read_at, read_message_id_hex, observed, unsent, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(group_id_hex, item) DO UPDATE SET
            version = excluded.version,
            change_id = excluded.change_id,
            flag = excluded.flag,
            mute_until = excluded.mute_until,
            read_epoch = excluded.read_epoch,
            read_at = excluded.read_at,
            read_message_id_hex = excluded.read_message_id_hex,
            observed = excluded.observed,
            unsent = excluded.unsent,
            updated_at = excluded.updated_at",
        params![
            item.group_id_hex,
            item.name().as_str(),
            item.version
                .map(|version| u64_to_i64(version.version))
                .transpose()?,
            item.version.map(|version| version.change_id.to_vec()),
            flag,
            mute_until,
            read.map(|position| u64_to_i64(position.epoch))
                .transpose()?,
            read.map(|position| u64_to_i64(position.at)).transpose()?,
            read.map(|position| position.message_id_hex.as_str()),
            observed,
            i64::from(unsent),
            u64_to_i64(now)?,
        ],
    )
    .storage()?;
    Ok(())
}

/// Forget what this device observed of an item, so its held value is applied
/// again.
fn clear_observed_tx(
    conn: &Connection,
    group_id_hex: &str,
    name: SmallStateItemName,
) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE small_state_items SET observed = NULL WHERE group_id_hex = ?1 AND item = ?2",
        params![group_id_hex, name.as_str()],
    )
    .storage()?;
    Ok(())
}

fn set_observed_tx(
    conn: &Connection,
    group_id_hex: &str,
    name: SmallStateItemName,
    observed: &str,
) -> StorageResult<()> {
    conn.execute_cached(
        "UPDATE small_state_items SET observed = ?3 WHERE group_id_hex = ?1 AND item = ?2",
        params![group_id_hex, name.as_str(), observed],
    )
    .storage()?;
    Ok(())
}

/// Turn every local state that differs from what this device last observed
/// into a new value, owed to the siblings. A read position counts only when
/// it moved past the held one.
fn record_local_changes_tx(
    conn: &Connection,
    chats: &BTreeMap<String, HeldChat>,
    rule: &dyn SmallStateRule,
    now: u64,
) -> StorageResult<usize> {
    let mut recorded = 0;
    for (group_id_hex, chat) in chats {
        if let Some(local) = chat.read.clone() {
            let held = held_item_tx(conn, group_id_hex, SmallStateItemName::Read)?;
            let further = match held.map(|item| item.value) {
                Some(SmallStateValue::Read(held)) => local > held,
                _ => true,
            };
            let item = SmallStateItem {
                group_id_hex: group_id_hex.clone(),
                value: SmallStateValue::Read(local),
                version: None,
            };
            if further && item.is_valid() {
                write_item_tx(conn, &item, None, true, now)?;
                recorded += 1;
            }
        }
        for name in SmallStateItemName::VERSIONED {
            let observed = chat.observed(name);
            let version = match held_row_tx(conn, group_id_hex, name)? {
                // Not applied yet: the winner is applied below, not replaced.
                Some(HeldRow { observed: None, .. }) => continue,
                Some(HeldRow {
                    observed: Some(seen),
                    ..
                }) if seen == observed => continue,
                Some(HeldRow { item, .. }) => match item.version {
                    // No change can beat the highest version: put the held
                    // value back.
                    Some(held) if held.version >= MAX_SMALL_STATE_NUMBER => {
                        clear_observed_tx(conn, group_id_hex, name)?;
                        continue;
                    }
                    held => held.map_or(1, |held| held.version + 1),
                },
                None if chat.is_default(name) => continue,
                None => 1,
            };
            let Some(value) = chat.value(name) else {
                continue;
            };
            let item = SmallStateItem {
                group_id_hex: group_id_hex.clone(),
                value,
                version: Some(SmallStateVersion {
                    version,
                    change_id: rule.new_change_id(),
                }),
            };
            if item.is_valid() {
                write_item_tx(conn, &item, Some(&observed), true, now)?;
                recorded += 1;
            }
        }
    }
    Ok(recorded)
}

/// Keep `incoming` when it beats the held value. A value that wins is not
/// applied yet, and is not owed: its sender has it.
fn merge_item_tx(
    conn: &Connection,
    incoming: &SmallStateItem,
    rule: &dyn SmallStateRule,
    now: u64,
) -> StorageResult<()> {
    let held = held_item_tx(conn, &incoming.group_id_hex, incoming.name())?;
    if held
        .as_ref()
        .is_none_or(|held| held != incoming && rule.wins(incoming, held))
    {
        write_item_tx(conn, incoming, None, false, now)?;
    }
    Ok(())
}

/// Apply every winning value this device holds a chat for and has not
/// applied: pins and mutes once, read positions whenever they are further than
/// the chat's marker.
fn apply_winners_tx(
    conn: &mut Connection,
    chats: &BTreeMap<String, HeldChat>,
    rule: &dyn SmallStateRule,
    outcome: &mut SmallStateSync,
) -> StorageResult<()> {
    for (group_id_hex, chat) in chats {
        if let Some(SmallStateValue::Read(position)) =
            held_item_tx(conn, group_id_hex, SmallStateItemName::Read)?.map(|item| item.value)
        {
            let key = (
                1,
                position.epoch,
                1,
                position.at,
                position.message_id_hex.clone(),
            );
            if chat.read_key.as_ref().is_none_or(|current| key > *current) {
                advance_read_marker_tx(conn, group_id_hex, &position)?;
                note_applied(outcome, group_id_hex, SmallStateItemName::Read);
            }
        }
        let mut pinned = chat.pinned;
        for name in SmallStateItemName::VERSIONED {
            let Some(HeldRow {
                item,
                observed: None,
            }) = held_row_tx(conn, group_id_hex, name)?
            else {
                continue;
            };
            let observed = match item.value {
                SmallStateValue::Pin(pin) => {
                    // An archived chat is never pinned here.
                    let pin = pin && !chat.archived;
                    if pin != pinned {
                        set_pinned_tx(conn, group_id_hex, pin, rule)?;
                        pinned = pin;
                        note_applied(outcome, group_id_hex, name);
                    }
                    flag_text(pinned)
                }
                SmallStateValue::Mute(setting) => {
                    let mute = match setting {
                        MuteSetting::Unmuted => None,
                        MuteSetting::Muted => Some(None),
                        MuteSetting::MutedUntil(until) => {
                            Some(Some(u64_to_i64(until.saturating_mul(1000))?))
                        }
                    };
                    if mute != chat.mute {
                        set_mute_tx(conn, group_id_hex, mute)?;
                        note_applied(outcome, group_id_hex, name);
                    }
                    mute_text(mute)
                }
                SmallStateValue::Archive(archived) => {
                    if archived != chat.archived {
                        outcome
                            .archive_to_apply
                            .push((group_id_hex.clone(), archived));
                        continue;
                    }
                    flag_text(archived)
                }
                SmallStateValue::Read(_) => continue,
            };
            set_observed_tx(conn, group_id_hex, name, &observed)?;
        }
    }
    Ok(())
}

fn note_applied(outcome: &mut SmallStateSync, group_id_hex: &str, name: SmallStateItemName) {
    outcome
        .applied
        .entry(group_id_hex.to_owned())
        .or_default()
        .insert(name);
}

fn advance_read_marker_tx(
    conn: &Connection,
    group_id_hex: &str,
    position: &ReadPosition,
) -> StorageResult<()> {
    let now = u64_to_i64(unix_now_seconds())?;
    // A sibling's read never clears this device's manual-unread reminder.
    conn.execute_cached(
        "INSERT INTO conversation_read_state (
            group_id_hex, last_read_message_id_hex, last_read_timeline_at,
            last_read_order_class, last_read_order_primary,
            last_read_order_phase, last_read_order_at,
            initialized_at, updated_at, manually_marked_unread
         )
         VALUES (?1, ?2, ?3, 1, ?4, 1, ?3, ?5, ?5, 0)
         ON CONFLICT(group_id_hex) DO UPDATE SET
            last_read_message_id_hex = excluded.last_read_message_id_hex,
            last_read_timeline_at = excluded.last_read_timeline_at,
            last_read_order_class = excluded.last_read_order_class,
            last_read_order_primary = excluded.last_read_order_primary,
            last_read_order_phase = excluded.last_read_order_phase,
            last_read_order_at = excluded.last_read_order_at,
            updated_at = excluded.updated_at",
        params![
            group_id_hex,
            position.message_id_hex,
            u64_to_i64(position.at)?,
            u64_to_i64(position.epoch)?,
            now,
        ],
    )
    .storage()?;
    Ok(())
}

/// Pin or unpin. A newly pinned chat goes where the rule places it.
fn set_pinned_tx(
    conn: &mut Connection,
    group_id_hex: &str,
    pinned: bool,
    rule: &dyn SmallStateRule,
) -> StorageResult<()> {
    let pin_error = |error: ChatPinError| match error {
        ChatPinError::Storage(error) => error,
        other => StorageError::Backend(other.to_string()),
    };
    let mut order = pinned_chat_order_tx(conn).map_err(pin_error)?;
    let existing = order.iter().position(|candidate| candidate == group_id_hex);
    match (pinned, existing) {
        (true, None) => {
            let index = rule.pin_index(&order).min(order.len());
            order.insert(index, group_id_hex.to_owned());
        }
        (false, Some(position)) => {
            order.remove(position);
        }
        _ => return Ok(()),
    }
    rewrite_pinned_chat_order_tx(conn, &order).map_err(pin_error)
}

fn set_mute_tx(
    conn: &Connection,
    group_id_hex: &str,
    mute: Option<Option<i64>>,
) -> StorageResult<()> {
    match mute {
        None => conn.execute_cached(
            "DELETE FROM chat_notification_settings WHERE group_id_hex = ?1",
            params![group_id_hex],
        ),
        Some(muted_until_ms) => conn.execute_cached(
            "INSERT INTO chat_notification_settings (group_id_hex, muted_until_ms, updated_at_ms)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id_hex) DO UPDATE SET
                muted_until_ms = excluded.muted_until_ms,
                updated_at_ms = excluded.updated_at_ms",
            params![group_id_hex, muted_until_ms, unix_now_ms()],
        ),
    }
    .storage()?;
    Ok(())
}

#[cfg(test)]
mod tests;
