//! Durable source authority and progress for one authenticated device-group
//! move. Native intent/fanout and retained Welcome material are not copied here.

use crate::base::connection::CachedSql;
use crate::{SqliteAppStorage, SqliteResultExt, deserialize, i64_to_u64, serialize, u64_to_i64};
use cgka_traits::GroupId;
use cgka_traits::storage::{DeviceGroupWelcomeExpectation, StorageError, StorageResult};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

/// The single move transition's durable outcome. Made never restores old trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
pub enum DeviceGroupMovePhase {
    Waiting = 0,
    Joined = 1,
    Made = 2,
    Finished = 3,
}

impl DeviceGroupMovePhase {
    fn parse(value: i64) -> StorageResult<Self> {
        match value {
            0 => Ok(Self::Waiting),
            1 => Ok(Self::Joined),
            2 => Ok(Self::Made),
            3 => Ok(Self::Finished),
            _ => Err(StorageError::Backend(
                "invalid device group move phase".into(),
            )),
        }
    }
}

/// Old sibling guidance is a label, not identity or authority to link it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveSibling {
    pub slot: [u8; 32],
    pub label: String,
    #[serde(default)]
    pub ended: bool,
}

/// Original rejected-slot facts captured only when this move becomes made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRejectedSlot {
    pub slot: [u8; 32],
    pub removed: bool,
    pub rejected_at: u64,
    pub tag_signature_key: Option<Vec<u8>>,
    /// Unsettled, imported, destination-device collision, destination rejection,
    /// or expired. This is local carry progress, not another roster authority.
    pub outcome: Option<MoveCarryOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveCarryOutcome {
    Imported,
    DeviceCollision,
    DestinationRejected,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceGroupMoveRecord {
    pub move_id: i64,
    pub destination_id: GroupId,
    pub original_id: GroupId,
    pub original_trust: crate::DeviceGroupTrust,
    pub original_key_package_ref_hex: String,
    pub original_recorded_at: u64,
    pub expectation: DeviceGroupWelcomeExpectation,
    pub own_slot: [u8; 32],
    pub siblings: Vec<MoveSibling>,
    pub phase: DeviceGroupMovePhase,
    pub rejected_slots: Option<Vec<MoveRejectedSlot>>,
}

const COLUMNS: &str = "destination_id, original_id, original_trust,
    original_key_package_ref_hex, original_recorded_at, sender_signature_key,
    key_package_ref, expires_at, own_slot, siblings, phase, rejected_slots, move_id";

fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<StorageResult<DeviceGroupMoveRecord>> {
    let destination: Vec<u8> = row.get(0)?;
    let original: Vec<u8> = row.get(1)?;
    let trust: String = row.get(2)?;
    let reference: String = row.get(3)?;
    let recorded: i64 = row.get(4)?;
    let sender: Vec<u8> = row.get(5)?;
    let key_package_ref: Vec<u8> = row.get(6)?;
    let expires: i64 = row.get(7)?;
    let own_slot: Vec<u8> = row.get(8)?;
    let siblings: Vec<u8> = row.get(9)?;
    let phase: i64 = row.get(10)?;
    let rejected: Option<Vec<u8>> = row.get(11)?;
    let move_id: i64 = row.get(12)?;
    Ok((|| {
        let destination_id = GroupId::new(destination);
        Ok(DeviceGroupMoveRecord {
            move_id,
            expectation: DeviceGroupWelcomeExpectation {
                group_id: destination_id.clone(),
                sender_signature_key: sender,
                key_package_ref,
                expires_at: i64_to_u64(expires)?,
            },
            destination_id,
            original_id: GroupId::new(original),
            original_trust: match trust.as_str() {
                "created" => crate::DeviceGroupTrust::Created,
                "linked" => crate::DeviceGroupTrust::Linked,
                _ => {
                    return Err(StorageError::Backend(
                        "invalid original device group trust".into(),
                    ));
                }
            },
            original_key_package_ref_hex: reference,
            original_recorded_at: i64_to_u64(recorded)?,
            own_slot: own_slot
                .try_into()
                .map_err(|_| StorageError::Backend("invalid move own slot".into()))?,
            siblings: deserialize(&siblings)?,
            phase: DeviceGroupMovePhase::parse(phase)?,
            rejected_slots: rejected.as_deref().map(deserialize).transpose()?,
        })
    })())
}

impl SqliteAppStorage {
    /// Retained move progress, including completed private sibling guidance.
    pub fn device_group_moves(&self) -> StorageResult<Vec<DeviceGroupMoveRecord>> {
        let conn = self.lock()?;
        let mut statement = conn
            .prepare_cached(&format!(
                "SELECT {COLUMNS} FROM device_group_moves ORDER BY move_id"
            ))
            .storage()?;
        statement
            .query_map([], read)
            .storage()?
            .map(|row| row.storage()?)
            .collect()
    }

    pub fn device_group_move(
        &self,
        destination: &GroupId,
    ) -> StorageResult<Option<DeviceGroupMoveRecord>> {
        self.lock()?.query_row_cached(&format!("SELECT {COLUMNS} FROM device_group_moves WHERE destination_id = ?1 ORDER BY move_id DESC LIMIT 1"), params![destination.as_slice()], read).optional().storage()?.transpose()
    }

    /// Pin only this authenticated original and confirmed pending destination.
    /// This is the sole exception to the ordinary one-claiming-row insertion;
    /// neither row's trust changes here.
    pub fn prepare_device_group_move(
        &self,
        expectation: &DeviceGroupWelcomeExpectation,
        own_slot: &[u8; 32],
        now: u64,
    ) -> StorageResult<bool> {
        self.connection.with_transaction(|| {
            let originals = self.device_groups()?.into_iter().filter(|row| row.trust.is_trusted()).collect::<Vec<_>>();
            let [original] = originals.as_slice() else {
                return Err(StorageError::Backend("move requires one authenticated original".into()));
            };
            let original_id = hex::decode(&original.group_id_hex).map_err(|_| StorageError::Backend("invalid original device group id".into()))?;
            let Some(reference) = &original.key_package_ref_hex else {
                return Err(StorageError::Backend("original device group lacks confirmed provenance".into()));
            };
            if original_id == expectation.group_id.as_slice() || expectation.sender_signature_key.is_empty() || expectation.key_package_ref.is_empty() {
                return Err(StorageError::Backend("invalid move destination expectation".into()));
            }
            let conn = self.lock()?;
            let blocked: bool = conn.query_row_cached("SELECT EXISTS(SELECT 1 FROM device_group_moves WHERE phase IN (0, 1)) OR EXISTS(SELECT 1 FROM device_groups WHERE group_id_hex = ?1 OR trust IN ('creating', 'awaiting_welcome'))", params![hex::encode(expectation.group_id.as_slice())], |row| row.get(0)).storage()?;
            if blocked { return Ok(false); }
            conn.execute_cached("INSERT INTO device_group_moves (destination_id, original_id, original_trust, original_key_package_ref_hex, original_recorded_at, sender_signature_key, key_package_ref, expires_at, own_slot, siblings, phase) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0)", params![expectation.group_id.as_slice(), original_id, if original.trust == crate::DeviceGroupTrust::Created {"created"} else {"linked"}, reference, u64_to_i64(original.recorded_at)?, expectation.sender_signature_key, expectation.key_package_ref, u64_to_i64(expectation.expires_at)?, own_slot.as_slice(), serialize(&Vec::<MoveSibling>::new())?]).storage()?;
            conn.execute_cached("INSERT INTO device_groups(group_id_hex,trust,key_package_ref_hex,recorded_at) VALUES(?1,'awaiting_welcome',?2,?3)", params![hex::encode(expectation.group_id.as_slice()),hex::encode(&expectation.key_package_ref),u64_to_i64(now)?]).storage()?;
            Ok(true)
        })
    }
}
