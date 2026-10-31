//! `marmot.account.device-roster.v1` state, update operations and codec.
//!
//! The roster is the GroupContext state of an account's device group
//! (mdk#2628 D16, D32). It holds the key that seals the account's device
//! tags and two kinds of keyed entry: devices keyed by their KeyPackage
//! publication slot, and rejected slots. One account-wide entry holds stage
//! 4's reserved fields. Nothing in it is about
//! the other groups the devices are in: each leaf's own device tag says which
//! device holds it.
//!
//! Unlike every other v1 GroupContext component, an update is a diff: a
//! sorted list of operations, each setting or removing one entry. The
//! resulting state is the prior state with the operations applied
//! ([`apply_device_roster_update_v1`]). The wire format is unreleased: the
//! engine advertises the component only in test-policy builds until its spec
//! lands.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::MAX_LEAVES_PER_ACCOUNT;
use super::codec::{decode_var_bytes, encode_var_bytes};

/// A KeyPackage publication slot id. On the Nostr binding it is the 32 bytes
/// of the KeyPackage event's `d` value.
pub type DeviceSlotId = [u8; 32];

/// A rename id: 16 random bytes that every entry is created with and every
/// rename of a device writes next to its label, so a device can tell its own
/// rename from another one after a fork. No other update changes it.
pub type DeviceRenameId = [u8; 16];

/// Largest label, client name or platform string, in UTF-8 bytes.
pub const DEVICE_ROSTER_TEXT_MAX_LEN: usize = 64;
/// Largest `KeyPackageRef`, in bytes. Marmot's ciphersuite makes it 32.
pub const DEVICE_ROSTER_KEY_PACKAGE_REF_MAX_LEN: usize = 64;
/// Largest tag signature public key, in bytes.
pub const DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN: usize = 255;
/// Largest reserved stage 4 key value, in bytes.
pub const DEVICE_ROSTER_RESERVED_KEY_MAX_LEN: usize = 255;

/// The whole roster. Maps keep entries sorted and unique by key, which is
/// the canonical order on the wire.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceRosterV1 {
    /// The key that seals the account's device tags. The creating device
    /// draws it at random; no update changes it.
    pub leaf_tag_key: [u8; 32],
    pub devices: BTreeMap<DeviceSlotId, DeviceEntryV1>,
    pub rejected_slots: BTreeMap<DeviceSlotId, RejectedSlotV1>,
    pub account: AccountEntryV1,
}

/// One linked device, keyed by its slot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEntryV1 {
    /// The name the user gave the device. UTF-8.
    pub label: String,
    /// The id the entry was created with or its latest rename wrote. Every
    /// entry is created with one; the field stays optional in the encoding.
    pub rename_id: Option<DeviceRenameId>,
    /// The device's client name. UTF-8.
    pub client: String,
    /// The device's platform, shared once it is linked. UTF-8.
    pub platform: String,
    /// When the device was linked, in Unix seconds, as its linker wrote it.
    pub linked_at: u64,
    /// The slot of the device that linked it; absent for the founder.
    pub linked_by: Option<DeviceSlotId>,
    pub settings: DeviceSettingsV1,
    pub status: DeviceStatusV1,
    /// The `KeyPackageRef` the device announced for its slot.
    pub announced_key_package: Option<Vec<u8>>,
    /// The public key the device signs its device tags with, absent until
    /// the device sets it.
    pub tag_signature_key: Option<Vec<u8>>,
    /// Reserved for account sync: the device's history key. Opaque here.
    pub history_key: Option<Vec<u8>>,
}

/// A device's settings, one bit each on the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSettingsV1 {
    pub add_to_all_chats: bool,
    pub bring_history: bool,
    pub keep_while_inactive: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceStatusV1 {
    #[default]
    Active,
    /// Marked inactive by its siblings.
    Inactive,
    /// Recorded that it is signing out.
    Leaving,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedSlotV1 {
    pub reason: RejectedSlotReasonV1,
    pub rejected_at: u64,
    /// A removed device's tag signature key, kept so its tags still read
    /// as its slot's. A `NotMe` slot never had an entry and has none.
    pub tag_signature_key: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectedSlotReasonV1 {
    /// The user said a sign-in in this slot was not theirs.
    NotMe,
    /// A device in this slot was removed.
    Removed,
}

/// Account-wide fields for backups (mdk#2628 4.4): the device that writes
/// them, by slot, and the recovery key's public half. Opaque to the codec,
/// which checks only their bounds. Serializable because a queued
/// `SendIntent::ReplaceAccountEntry` carries it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntryV1 {
    pub backup_writer: Option<DeviceSlotId>,
    pub recovery_public_key: Option<Vec<u8>>,
}

/// One roster operation. Each names one entry. Types 4 and 5 belonged to
/// the removed rejected-KeyPackage operations and are never reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceRosterOperationV1 {
    SetDevice(DeviceSlotId, DeviceEntryV1),
    RemoveDevice(DeviceSlotId),
    SetRejectedSlot(DeviceSlotId, RejectedSlotV1),
    RemoveRejectedSlot(DeviceSlotId),
    SetAccount(AccountEntryV1),
}

impl DeviceRosterOperationV1 {
    const fn op_type(&self) -> u8 {
        match self {
            Self::SetDevice(..) => 0,
            Self::RemoveDevice(..) => 1,
            Self::SetRejectedSlot(..) => 2,
            Self::RemoveRejectedSlot(..) => 3,
            Self::SetAccount(..) => 6,
        }
    }

    /// The entry this operation names: its kind, then its key bytes. The
    /// canonical order of an update's operations is this order.
    fn entry(&self) -> (u8, &[u8]) {
        match self {
            Self::SetDevice(slot, _) | Self::RemoveDevice(slot) => (0, slot),
            Self::SetRejectedSlot(slot, _) | Self::RemoveRejectedSlot(slot) => (1, slot),
            Self::SetAccount(_) => (2, &[]),
        }
    }
}

/// An AppDataUpdate's bytes for the roster: one or more operations, at most
/// one per entry, in canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRosterUpdateV1 {
    operations: Vec<DeviceRosterOperationV1>,
}

impl DeviceRosterUpdateV1 {
    /// Sort `operations` into canonical order. Refuses an empty list and two
    /// operations on one entry.
    pub fn new(mut operations: Vec<DeviceRosterOperationV1>) -> Result<Self, String> {
        operations.sort_by(|a, b| a.entry().cmp(&b.entry()));
        let update = Self { operations };
        update.validate()?;
        Ok(update)
    }

    pub fn operations(&self) -> &[DeviceRosterOperationV1] {
        &self.operations
    }

    fn validate(&self) -> Result<(), String> {
        if self.operations.is_empty() {
            return Err("device roster update has no operations".into());
        }
        for pair in self.operations.windows(2) {
            if pair[0].entry() >= pair[1].entry() {
                return Err(
                    "device roster update operations must be sorted with one per entry".into(),
                );
            }
        }
        for operation in &self.operations {
            match operation {
                DeviceRosterOperationV1::SetDevice(_, device) => validate_device(device)?,
                DeviceRosterOperationV1::SetRejectedSlot(_, rejected) => {
                    validate_rejected_slot(rejected)?;
                }
                DeviceRosterOperationV1::SetAccount(account) => validate_account(account)?,
                DeviceRosterOperationV1::RemoveDevice(_)
                | DeviceRosterOperationV1::RemoveRejectedSlot(_) => {}
            }
        }
        Ok(())
    }
}

impl DeviceRosterV1 {
    /// The roster's own invariants: field bounds, at most
    /// [`MAX_LEAVES_PER_ACCOUNT`] devices, no two devices with one tag
    /// signature key, no tag signature key on a `NotMe` slot, and no slot
    /// both a device and rejected.
    pub fn validate(&self) -> Result<(), String> {
        if self.devices.len() > MAX_LEAVES_PER_ACCOUNT {
            return Err(format!(
                "device roster holds more than {MAX_LEAVES_PER_ACCOUNT} devices"
            ));
        }
        let mut tag_signature_keys = std::collections::BTreeSet::new();
        for device in self.devices.values() {
            validate_device(device)?;
            if let Some(key) = &device.tag_signature_key
                && !tag_signature_keys.insert(key)
            {
                return Err("device roster gives two devices one tag signature key".into());
            }
        }
        if self
            .devices
            .keys()
            .any(|slot| self.rejected_slots.contains_key(slot))
        {
            return Err("device roster lists a slot as both a device and rejected".into());
        }
        for rejected in self.rejected_slots.values() {
            validate_rejected_slot(rejected)?;
            if rejected.reason == RejectedSlotReasonV1::NotMe
                && rejected.tag_signature_key.is_some()
            {
                return Err("device roster gives a not-me slot a tag signature key".into());
            }
        }
        validate_account(&self.account)
    }

    /// Apply `update` to this roster. Setting an entry inserts or replaces
    /// it; removing an entry the roster lacks is invalid. No operation
    /// touches `leaf_tag_key`. The result must satisfy [`Self::validate`].
    pub fn apply(&self, update: &DeviceRosterUpdateV1) -> Result<Self, String> {
        let mut next = self.clone();
        for operation in update.operations() {
            match operation {
                DeviceRosterOperationV1::SetDevice(slot, device) => {
                    next.devices.insert(*slot, device.clone());
                }
                DeviceRosterOperationV1::RemoveDevice(slot) => {
                    next.devices
                        .remove(slot)
                        .ok_or("device roster update removes a device it does not hold")?;
                }
                DeviceRosterOperationV1::SetRejectedSlot(slot, rejected) => {
                    next.rejected_slots.insert(*slot, rejected.clone());
                }
                DeviceRosterOperationV1::RemoveRejectedSlot(slot) => {
                    next.rejected_slots
                        .remove(slot)
                        .ok_or("device roster update removes a rejected slot it does not hold")?;
                }
                DeviceRosterOperationV1::SetAccount(account) => {
                    next.account = account.clone();
                }
            }
        }
        next.validate()?;
        Ok(next)
    }
}

/// Apply encoded update bytes to encoded state bytes and return the
/// resulting state bytes. Both inputs must be canonical.
pub fn apply_device_roster_update_v1(prior: &[u8], update: &[u8]) -> Result<Vec<u8>, String> {
    let roster = decode_device_roster_v1(prior)?;
    let update = decode_device_roster_update_v1(update)?;
    encode_device_roster_v1(&roster.apply(&update)?)
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.len() > DEVICE_ROSTER_TEXT_MAX_LEN {
        return Err(format!(
            "device roster {label} exceeds {DEVICE_ROSTER_TEXT_MAX_LEN} bytes"
        ));
    }
    Ok(())
}

fn validate_bounded(value: &[u8], max_len: usize, label: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!(
            "device roster {label} must be 1 to {max_len} bytes"
        ));
    }
    Ok(())
}

fn validate_key_package_ref(value: &[u8]) -> Result<(), String> {
    validate_bounded(
        value,
        DEVICE_ROSTER_KEY_PACKAGE_REF_MAX_LEN,
        "KeyPackageRef",
    )
}

fn validate_device(device: &DeviceEntryV1) -> Result<(), String> {
    validate_text(&device.label, "label")?;
    validate_text(&device.client, "client")?;
    validate_text(&device.platform, "platform")?;
    if let Some(key_package_ref) = &device.announced_key_package {
        validate_key_package_ref(key_package_ref)?;
    }
    if let Some(tag_signature_key) = &device.tag_signature_key {
        validate_bounded(
            tag_signature_key,
            DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN,
            "tag signature key",
        )?;
    }
    if let Some(history_key) = &device.history_key {
        validate_bounded(
            history_key,
            DEVICE_ROSTER_RESERVED_KEY_MAX_LEN,
            "history key",
        )?;
    }
    Ok(())
}

fn validate_rejected_slot(rejected: &RejectedSlotV1) -> Result<(), String> {
    match &rejected.tag_signature_key {
        Some(tag_signature_key) => validate_bounded(
            tag_signature_key,
            DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN,
            "tag signature key",
        ),
        None => Ok(()),
    }
}

fn validate_account(account: &AccountEntryV1) -> Result<(), String> {
    if let Some(key) = &account.recovery_public_key {
        validate_bounded(key, DEVICE_ROSTER_RESERVED_KEY_MAX_LEN, "recovery key")?;
    }
    Ok(())
}

// ── Encoding ────────────────────────────────────────────────────────────────

pub fn encode_device_roster_v1(roster: &DeviceRosterV1) -> Result<Vec<u8>, String> {
    roster.validate()?;
    let mut devices = Vec::new();
    for (slot, device) in &roster.devices {
        devices.extend_from_slice(slot);
        encode_device(device, &mut devices);
    }
    let mut rejected_slots = Vec::new();
    for (slot, rejected) in &roster.rejected_slots {
        rejected_slots.extend_from_slice(slot);
        encode_rejected_slot(rejected, &mut rejected_slots);
    }
    let mut out = roster.leaf_tag_key.to_vec();
    encode_var_bytes(&devices, &mut out);
    encode_var_bytes(&rejected_slots, &mut out);
    encode_account(&roster.account, &mut out);
    Ok(out)
}

pub fn encode_device_roster_update_v1(update: &DeviceRosterUpdateV1) -> Result<Vec<u8>, String> {
    update.validate()?;
    let mut operations = Vec::new();
    for operation in update.operations() {
        operations.push(operation.op_type());
        match operation {
            DeviceRosterOperationV1::SetDevice(slot, device) => {
                operations.extend_from_slice(slot);
                encode_device(device, &mut operations);
            }
            DeviceRosterOperationV1::RemoveDevice(slot)
            | DeviceRosterOperationV1::RemoveRejectedSlot(slot) => {
                operations.extend_from_slice(slot);
            }
            DeviceRosterOperationV1::SetRejectedSlot(slot, rejected) => {
                operations.extend_from_slice(slot);
                encode_rejected_slot(rejected, &mut operations);
            }
            DeviceRosterOperationV1::SetAccount(account) => {
                encode_account(account, &mut operations);
            }
        }
    }
    let mut out = Vec::new();
    encode_var_bytes(&operations, &mut out);
    Ok(out)
}

fn encode_device(device: &DeviceEntryV1, out: &mut Vec<u8>) {
    encode_var_bytes(device.label.as_bytes(), out);
    match &device.rename_id {
        None => out.push(0),
        Some(rename_id) => {
            out.push(1);
            out.extend_from_slice(rename_id);
        }
    }
    encode_var_bytes(device.client.as_bytes(), out);
    encode_var_bytes(device.platform.as_bytes(), out);
    out.extend_from_slice(&device.linked_at.to_be_bytes());
    encode_optional_slot(device.linked_by.as_ref(), out);
    let settings = device.settings;
    out.push(
        u8::from(settings.add_to_all_chats)
            | (u8::from(settings.bring_history) << 1)
            | (u8::from(settings.keep_while_inactive) << 2),
    );
    out.push(match device.status {
        DeviceStatusV1::Active => 0,
        DeviceStatusV1::Inactive => 1,
        DeviceStatusV1::Leaving => 2,
    });
    encode_optional_bytes(device.announced_key_package.as_deref(), out);
    encode_optional_bytes(device.tag_signature_key.as_deref(), out);
    encode_optional_bytes(device.history_key.as_deref(), out);
}

fn encode_rejected_slot(rejected: &RejectedSlotV1, out: &mut Vec<u8>) {
    out.push(match rejected.reason {
        RejectedSlotReasonV1::NotMe => 0,
        RejectedSlotReasonV1::Removed => 1,
    });
    out.extend_from_slice(&rejected.rejected_at.to_be_bytes());
    encode_optional_bytes(rejected.tag_signature_key.as_deref(), out);
}

fn encode_account(account: &AccountEntryV1, out: &mut Vec<u8>) {
    encode_optional_slot(account.backup_writer.as_ref(), out);
    encode_optional_bytes(account.recovery_public_key.as_deref(), out);
}

fn encode_optional_slot(slot: Option<&DeviceSlotId>, out: &mut Vec<u8>) {
    match slot {
        None => out.push(0),
        Some(slot) => {
            out.push(1);
            out.extend_from_slice(slot);
        }
    }
}

fn encode_optional_bytes(bytes: Option<&[u8]>, out: &mut Vec<u8>) {
    match bytes {
        None => out.push(0),
        Some(bytes) => {
            out.push(1);
            encode_var_bytes(bytes, out);
        }
    }
}

// ── Decoding ────────────────────────────────────────────────────────────────

/// Decode canonical roster state bytes. Entries must be sorted and unique,
/// and the state must satisfy [`DeviceRosterV1::validate`].
pub fn decode_device_roster_v1(bytes: &[u8]) -> Result<DeviceRosterV1, String> {
    let mut cursor = bytes;
    let leaf_tag_key = decode_slot(&mut cursor, "leaf tag key")?;
    let devices_bytes = decode_vector(&mut cursor, "devices")?;
    let rejected_slots_bytes = decode_vector(&mut cursor, "rejected slots")?;
    let account = decode_account(&mut cursor)?;
    if !cursor.is_empty() {
        return Err("device roster has trailing bytes".into());
    }

    let mut roster = DeviceRosterV1 {
        leaf_tag_key,
        account,
        ..DeviceRosterV1::default()
    };
    let mut items = devices_bytes.as_slice();
    while !items.is_empty() {
        let slot = decode_slot(&mut items, "device slot")?;
        let device = decode_device(&mut items)?;
        insert_sorted(&mut roster.devices, slot, device, "devices")?;
    }
    let mut items = rejected_slots_bytes.as_slice();
    while !items.is_empty() {
        let slot = decode_slot(&mut items, "rejected slot")?;
        let rejected = decode_rejected_slot(&mut items)?;
        insert_sorted(&mut roster.rejected_slots, slot, rejected, "rejected slots")?;
    }
    roster.validate()?;
    Ok(roster)
}

/// Decode canonical update bytes: one or more operations, sorted, one per
/// entry.
pub fn decode_device_roster_update_v1(bytes: &[u8]) -> Result<DeviceRosterUpdateV1, String> {
    let mut cursor = bytes;
    let operations_bytes = decode_vector(&mut cursor, "operations")?;
    if !cursor.is_empty() {
        return Err("device roster update has trailing bytes".into());
    }
    let mut items = operations_bytes.as_slice();
    let mut operations = Vec::new();
    while !items.is_empty() {
        let op_type = take_u8(&mut items, "operation type")?;
        let operation = match op_type {
            0 => {
                let slot = decode_slot(&mut items, "device slot")?;
                DeviceRosterOperationV1::SetDevice(slot, decode_device(&mut items)?)
            }
            1 => DeviceRosterOperationV1::RemoveDevice(decode_slot(&mut items, "device slot")?),
            2 => {
                let slot = decode_slot(&mut items, "rejected slot")?;
                DeviceRosterOperationV1::SetRejectedSlot(slot, decode_rejected_slot(&mut items)?)
            }
            3 => DeviceRosterOperationV1::RemoveRejectedSlot(decode_slot(
                &mut items,
                "rejected slot",
            )?),
            6 => DeviceRosterOperationV1::SetAccount(decode_account(&mut items)?),
            _ => return Err("device roster update has an unknown operation type".into()),
        };
        operations.push(operation);
    }
    let update = DeviceRosterUpdateV1 { operations };
    update.validate()?;
    Ok(update)
}

fn insert_sorted<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    label: &str,
) -> Result<(), String> {
    if map.last_key_value().is_some_and(|(last, _)| *last >= key) {
        return Err(format!("device roster {label} must be sorted and unique"));
    }
    map.insert(key, value);
    Ok(())
}

fn decode_vector(cursor: &mut &[u8], label: &str) -> Result<Vec<u8>, String> {
    decode_var_bytes(cursor, usize::MAX, &format!("device roster {label}"))
}

fn decode_device(cursor: &mut &[u8]) -> Result<DeviceEntryV1, String> {
    let label = decode_text(cursor, "label")?;
    let rename_id = decode_optional(cursor, "rename id", |cursor| {
        let (bytes, rest) = cursor
            .split_first_chunk::<16>()
            .ok_or_else(|| "device roster rename id is truncated".to_owned())?;
        *cursor = rest;
        Ok(*bytes)
    })?;
    let client = decode_text(cursor, "client")?;
    let platform = decode_text(cursor, "platform")?;
    let linked_at = take_u64(cursor, "linked_at")?;
    let linked_by = decode_optional_slot(cursor, "linked_by")?;
    let flags = take_u8(cursor, "settings")?;
    if flags & !0b111 != 0 {
        return Err("device roster settings set a reserved bit".into());
    }
    let settings = DeviceSettingsV1 {
        add_to_all_chats: flags & 0b001 != 0,
        bring_history: flags & 0b010 != 0,
        keep_while_inactive: flags & 0b100 != 0,
    };
    let status = match take_u8(cursor, "status")? {
        0 => DeviceStatusV1::Active,
        1 => DeviceStatusV1::Inactive,
        2 => DeviceStatusV1::Leaving,
        _ => return Err("device roster status is unknown".into()),
    };
    let announced_key_package = decode_optional(cursor, "announced KeyPackageRef", |cursor| {
        decode_key_package_ref(cursor)
    })?;
    let tag_signature_key = decode_optional(cursor, "tag signature key", |cursor| {
        decode_bounded(
            cursor,
            DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN,
            "tag signature key",
        )
    })?;
    let history_key = decode_optional(cursor, "history key", |cursor| {
        decode_bounded(cursor, DEVICE_ROSTER_RESERVED_KEY_MAX_LEN, "history key")
    })?;
    Ok(DeviceEntryV1 {
        label,
        rename_id,
        client,
        platform,
        linked_at,
        linked_by,
        settings,
        status,
        announced_key_package,
        tag_signature_key,
        history_key,
    })
}

fn decode_rejected_slot(cursor: &mut &[u8]) -> Result<RejectedSlotV1, String> {
    let reason = match take_u8(cursor, "rejection reason")? {
        0 => RejectedSlotReasonV1::NotMe,
        1 => RejectedSlotReasonV1::Removed,
        _ => return Err("device roster rejection reason is unknown".into()),
    };
    let rejected_at = take_u64(cursor, "rejected_at")?;
    let tag_signature_key = decode_optional(cursor, "tag signature key", |cursor| {
        decode_bounded(
            cursor,
            DEVICE_ROSTER_TAG_SIGNATURE_KEY_MAX_LEN,
            "tag signature key",
        )
    })?;
    Ok(RejectedSlotV1 {
        reason,
        rejected_at,
        tag_signature_key,
    })
}

fn decode_account(cursor: &mut &[u8]) -> Result<AccountEntryV1, String> {
    let backup_writer = decode_optional_slot(cursor, "backup writer")?;
    let recovery_public_key = decode_optional(cursor, "recovery key", |cursor| {
        decode_bounded(cursor, DEVICE_ROSTER_RESERVED_KEY_MAX_LEN, "recovery key")
    })?;
    Ok(AccountEntryV1 {
        backup_writer,
        recovery_public_key,
    })
}

fn decode_text(cursor: &mut &[u8], label: &str) -> Result<String, String> {
    let bytes = decode_var_bytes(
        cursor,
        DEVICE_ROSTER_TEXT_MAX_LEN,
        &format!("device roster {label}"),
    )?;
    String::from_utf8(bytes).map_err(|_| format!("device roster {label} is not UTF-8"))
}

fn decode_key_package_ref(cursor: &mut &[u8]) -> Result<Vec<u8>, String> {
    decode_bounded(
        cursor,
        DEVICE_ROSTER_KEY_PACKAGE_REF_MAX_LEN,
        "KeyPackageRef",
    )
}

fn decode_bounded(cursor: &mut &[u8], max_len: usize, label: &str) -> Result<Vec<u8>, String> {
    let bytes = decode_var_bytes(cursor, max_len, &format!("device roster {label}"))?;
    if bytes.is_empty() {
        return Err(format!("device roster {label} must not be empty"));
    }
    Ok(bytes)
}

fn decode_optional<T>(
    cursor: &mut &[u8],
    label: &str,
    decode: impl FnOnce(&mut &[u8]) -> Result<T, String>,
) -> Result<Option<T>, String> {
    match take_u8(cursor, label)? {
        0 => Ok(None),
        1 => decode(cursor).map(Some),
        _ => Err(format!(
            "device roster {label} has an invalid presence byte"
        )),
    }
}

fn decode_optional_slot(cursor: &mut &[u8], label: &str) -> Result<Option<DeviceSlotId>, String> {
    decode_optional(cursor, label, |cursor| decode_slot(cursor, label))
}

fn decode_slot(cursor: &mut &[u8], label: &str) -> Result<DeviceSlotId, String> {
    let (bytes, rest) = cursor
        .split_first_chunk::<32>()
        .ok_or_else(|| format!("device roster {label} is truncated"))?;
    *cursor = rest;
    Ok(*bytes)
}

fn take_u8(cursor: &mut &[u8], label: &str) -> Result<u8, String> {
    let (byte, rest) = cursor
        .split_first()
        .ok_or_else(|| format!("device roster {label} is truncated"))?;
    *cursor = rest;
    Ok(*byte)
}

fn take_u64(cursor: &mut &[u8], label: &str) -> Result<u64, String> {
    let (bytes, rest) = cursor
        .split_first_chunk::<8>()
        .ok_or_else(|| format!("device roster {label} is truncated"))?;
    *cursor = rest;
    Ok(u64::from_be_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(n: u8) -> DeviceSlotId {
        [n; 32]
    }

    fn device(label: &str) -> DeviceEntryV1 {
        DeviceEntryV1 {
            label: label.into(),
            ..DeviceEntryV1::default()
        }
    }

    fn removed() -> RejectedSlotV1 {
        RejectedSlotV1 {
            reason: RejectedSlotReasonV1::Removed,
            rejected_at: 1_700_001_000,
            tag_signature_key: Some(vec![0x06; 32]),
        }
    }

    /// One of everything: a leaf tag key, two devices, one with every
    /// optional field, a rejected slot and the reserved account fields.
    fn full_roster() -> DeviceRosterV1 {
        let phone = DeviceEntryV1 {
            label: "Phone".into(),
            rename_id: Some([0x06; 16]),
            client: "wn".into(),
            platform: "ios".into(),
            linked_at: 1_700_000_000,
            linked_by: None,
            settings: DeviceSettingsV1 {
                add_to_all_chats: true,
                bring_history: true,
                keep_while_inactive: false,
            },
            status: DeviceStatusV1::Active,
            announced_key_package: Some(vec![0xaa; 32]),
            tag_signature_key: Some(vec![0x05; 32]),
            history_key: None,
        };
        let laptop = DeviceEntryV1 {
            label: "Laptop".into(),
            linked_at: 1_700_000_600,
            linked_by: Some(slot(1)),
            status: DeviceStatusV1::Leaving,
            history_key: Some(vec![0x03; 32]),
            ..DeviceEntryV1::default()
        };
        DeviceRosterV1 {
            leaf_tag_key: [0x33; 32],
            devices: [(slot(1), phone), (slot(2), laptop)].into_iter().collect(),
            rejected_slots: [(slot(9), removed())].into_iter().collect(),
            account: AccountEntryV1 {
                backup_writer: Some(slot(1)),
                recovery_public_key: Some(vec![0x04; 33]),
            },
        }
    }

    #[test]
    fn empty_roster_is_its_leaf_tag_key_two_empty_vectors_and_an_empty_account_entry() {
        let bytes = encode_device_roster_v1(&DeviceRosterV1::default()).unwrap();
        let mut expected = vec![0; 32];
        expected.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(bytes, expected);
        assert_eq!(
            decode_device_roster_v1(&bytes).unwrap(),
            DeviceRosterV1::default()
        );
        assert!(decode_device_roster_v1(&bytes[..31]).is_err());
    }

    #[test]
    fn roster_round_trips_canonically() {
        let roster = full_roster();
        let bytes = encode_device_roster_v1(&roster).unwrap();
        assert_eq!(decode_device_roster_v1(&bytes).unwrap(), roster);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_device_roster_v1(&trailing).is_err());
    }

    /// The vectors in the component's spec, so independent implementations
    /// can check their encoding.
    #[test]
    fn spec_vectors() {
        let roster = DeviceRosterV1 {
            leaf_tag_key: [0x33; 32],
            devices: [(
                slot(0x11),
                DeviceEntryV1 {
                    label: "Phone".into(),
                    rename_id: Some([0x55; 16]),
                    client: "wn".into(),
                    platform: String::new(),
                    linked_at: 0x6553_f100,
                    linked_by: None,
                    settings: DeviceSettingsV1 {
                        add_to_all_chats: true,
                        bring_history: false,
                        keep_while_inactive: true,
                    },
                    status: DeviceStatusV1::Active,
                    announced_key_package: None,
                    tag_signature_key: Some(vec![0x44; 32]),
                    history_key: None,
                },
            )]
            .into_iter()
            .collect(),
            ..DeviceRosterV1::default()
        };
        let expected = concat!(
            "3333333333333333333333333333333333333333333333333333333333333333", // leaf_tag_key
            "406a", // devices<V>: 106 bytes
            "1111111111111111111111111111111111111111111111111111111111111111", // slot
            "0550686f6e65", // label "Phone"
            "0155555555555555555555555555555555", // rename id
            "02776e", // client "wn"
            "00",   // platform ""
            "000000006553f100", // linked_at
            "00",   // linked_by absent
            "05",   // settings
            "00",   // status active
            "00",   // no KeyPackageRef
            "01",   // tag signature key
            "204444444444444444444444444444444444444444444444444444444444444444",
            "00",   // no history key
            "00",   // rejected_slots<V>
            "0000", // account entry
        );
        let bytes = encode_device_roster_v1(&roster).unwrap();
        assert_eq!(hex::encode(&bytes), expected);
        assert_eq!(decode_device_roster_v1(&bytes).unwrap(), roster);

        let removal = DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::SetRejectedSlot(
                slot(0x11),
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::Removed,
                    rejected_at: 0x6553_f200,
                    tag_signature_key: Some(vec![0x44; 32]),
                },
            ),
            DeviceRosterOperationV1::RemoveDevice(slot(0x11)),
        ])
        .unwrap();
        let removal_bytes = encode_device_roster_update_v1(&removal).unwrap();
        assert_eq!(
            hex::encode(&removal_bytes),
            concat!(
                "406d",                                                             // operations<V>: 109 bytes
                "01",                                                               // remove_device
                "1111111111111111111111111111111111111111111111111111111111111111", // slot
                "02", // set_rejected_slot
                "1111111111111111111111111111111111111111111111111111111111111111", // slot
                "01", // reason removed
                "000000006553f200", // rejected_at
                "01", // tag_signature_key present
                "20",
                "4444444444444444444444444444444444444444444444444444444444444444", // tag_signature_key
            )
        );
        let next = roster.apply(&removal).unwrap();
        assert!(next.devices.is_empty());
        assert_eq!(next.leaf_tag_key, roster.leaf_tag_key);
        assert_eq!(
            apply_device_roster_update_v1(&bytes, &removal_bytes).unwrap(),
            encode_device_roster_v1(&next).unwrap()
        );

        let mut announcing = roster.devices[&slot(0x11)].clone();
        announcing.announced_key_package = Some(vec![0x66; 32]);
        let announcement = DeviceRosterUpdateV1::new(vec![DeviceRosterOperationV1::SetDevice(
            slot(0x11),
            announcing,
        )])
        .unwrap();
        let entry = concat!(
            "1111111111111111111111111111111111111111111111111111111111111111", // slot
            "0550686f6e65",                                                     // label "Phone"
            "0155555555555555555555555555555555",                               // rename id
            "02776e",                                                           // client "wn"
            "00",                                                               // platform ""
            "000000006553f100",                                                 // linked_at
            "00",                                                               // linked_by absent
            "05",                                                               // settings
            "00",                                                               // status active
            "01", // announced_key_package present
            "206666666666666666666666666666666666666666666666666666666666666666",
            "01", // tag signature key
            "204444444444444444444444444444444444444444444444444444444444444444",
            "00", // no history key
        );
        let announcement_bytes = encode_device_roster_update_v1(&announcement).unwrap();
        assert_eq!(
            hex::encode(&announcement_bytes),
            format!("408c00{entry}") // operations<V>: 140 bytes; set_device
        );
        let announced = apply_device_roster_update_v1(&bytes, &announcement_bytes).unwrap();
        assert_eq!(
            hex::encode(&announced),
            format!(
                "{}408b{entry}000000",
                "3333333333333333333333333333333333333333333333333333333333333333"
            )
        );
    }

    #[test]
    fn decoding_rejects_non_canonical_rosters() {
        let two = DeviceRosterV1 {
            devices: [(slot(1), device("A")), (slot(2), device("B"))]
                .into_iter()
                .collect(),
            ..DeviceRosterV1::default()
        };
        let bytes = encode_device_roster_v1(&two).unwrap();
        // Swap the two device entries, which have the same length. The leaf
        // tag key comes first; the devices' 102-byte vector takes a two-byte
        // length prefix; the empty rejected-slot vector and the empty
        // account entry, three bytes, follow.
        let devices_at = 32 + 2;
        let entry_len = (bytes.len() - devices_at - 3) / 2;
        let mut swapped = bytes[..devices_at].to_vec();
        swapped.extend_from_slice(&bytes[devices_at + entry_len..devices_at + 2 * entry_len]);
        swapped.extend_from_slice(&bytes[devices_at..devices_at + entry_len]);
        swapped.extend_from_slice(&bytes[devices_at + 2 * entry_len..]);
        assert!(
            decode_device_roster_v1(&swapped)
                .unwrap_err()
                .contains("sorted and unique")
        );

        let one = encode_device_roster_v1(&DeviceRosterV1 {
            devices: [(slot(1), device("A"))].into_iter().collect(),
            ..DeviceRosterV1::default()
        })
        .unwrap();
        // Layout: leaf tag key, devices len, slot, label (2), rename id,
        // client, platform, linked_at, linked_by, settings, status,
        // KeyPackageRef, tag signature key, history key, ...
        let rename_id_at = 32 + 1 + 32 + 2;
        let mut bad_rename_presence = one.clone();
        bad_rename_presence[rename_id_at] = 2;
        assert!(decode_device_roster_v1(&bad_rename_presence).is_err());
        let settings_at = rename_id_at + 1 + 1 + 1 + 8 + 1;
        let mut reserved_bit = one.clone();
        reserved_bit[settings_at] = 0b1000;
        assert!(decode_device_roster_v1(&reserved_bit).is_err());
        let mut unknown_status = one.clone();
        unknown_status[settings_at + 1] = 3;
        assert!(decode_device_roster_v1(&unknown_status).is_err());
        let mut bad_presence = one.clone();
        bad_presence[settings_at - 1] = 2;
        assert!(decode_device_roster_v1(&bad_presence).is_err());
        let mut bad_tag_key_presence = one.clone();
        bad_tag_key_presence[settings_at + 3] = 2;
        assert!(decode_device_roster_v1(&bad_tag_key_presence).is_err());
        let mut bad_utf8 = one;
        bad_utf8[32 + 1 + 32 + 1] = 0xff;
        assert!(decode_device_roster_v1(&bad_utf8).is_err());
    }

    #[test]
    fn the_roster_keeps_its_invariants() {
        let too_many = DeviceRosterV1 {
            devices: (0..=MAX_LEAVES_PER_ACCOUNT as u8)
                .map(|n| (slot(n), device("Spare")))
                .collect(),
            ..DeviceRosterV1::default()
        };
        assert!(encode_device_roster_v1(&too_many).is_err());

        let mut both = DeviceRosterV1 {
            devices: [(slot(1), device("A"))].into_iter().collect(),
            ..DeviceRosterV1::default()
        };
        both.rejected_slots.insert(
            slot(1),
            RejectedSlotV1 {
                reason: RejectedSlotReasonV1::NotMe,
                rejected_at: 0,
                tag_signature_key: None,
            },
        );
        assert!(encode_device_roster_v1(&both).is_err());

        let long_label = DeviceRosterV1 {
            devices: [(slot(1), device(&"x".repeat(65)))].into_iter().collect(),
            ..DeviceRosterV1::default()
        };
        assert!(encode_device_roster_v1(&long_label).is_err());

        // Each device signs its tags with a key of its own.
        let signing = |key: Vec<u8>| DeviceEntryV1 {
            tag_signature_key: Some(key),
            ..device("A")
        };
        let mut shared = DeviceRosterV1 {
            devices: [
                (slot(1), signing(vec![0x0a; 32])),
                (slot(2), signing(vec![0x0b; 32])),
            ]
            .into_iter()
            .collect(),
            ..DeviceRosterV1::default()
        };
        assert!(encode_device_roster_v1(&shared).is_ok());
        shared.devices.insert(slot(2), signing(vec![0x0a; 32]));
        assert!(
            encode_device_roster_v1(&shared)
                .unwrap_err()
                .contains("one tag signature key")
        );
        for bad_key in [Vec::new(), vec![0x0c; 256]] {
            let roster = DeviceRosterV1 {
                devices: [(slot(1), signing(bad_key.clone()))].into_iter().collect(),
                ..DeviceRosterV1::default()
            };
            assert!(encode_device_roster_v1(&roster).is_err());
            let roster = DeviceRosterV1 {
                rejected_slots: [(
                    slot(1),
                    RejectedSlotV1 {
                        tag_signature_key: Some(bad_key),
                        ..removed()
                    },
                )]
                .into_iter()
                .collect(),
                ..DeviceRosterV1::default()
            };
            assert!(encode_device_roster_v1(&roster).is_err());
        }

        // A removed slot keeps its device's key; a not-me slot never had
        // one. A removed slot's key may match a device's: the signature
        // covers the slot it names.
        let rejected = |reason| DeviceRosterV1 {
            devices: [(slot(1), signing(vec![0x06; 32]))].into_iter().collect(),
            rejected_slots: [(
                slot(2),
                RejectedSlotV1 {
                    reason,
                    ..removed()
                },
            )]
            .into_iter()
            .collect(),
            ..DeviceRosterV1::default()
        };
        assert!(encode_device_roster_v1(&rejected(RejectedSlotReasonV1::Removed)).is_ok());
        assert!(
            encode_device_roster_v1(&rejected(RejectedSlotReasonV1::NotMe))
                .unwrap_err()
                .contains("not-me slot")
        );
    }

    #[test]
    fn an_update_is_sorted_with_one_operation_per_entry() {
        assert!(DeviceRosterUpdateV1::new(vec![]).is_err());
        assert!(
            DeviceRosterUpdateV1::new(vec![
                DeviceRosterOperationV1::SetDevice(slot(1), device("A")),
                DeviceRosterOperationV1::RemoveDevice(slot(1)),
            ])
            .is_err()
        );
        // A device and a rejected slot with the same slot are different
        // entries. Kinds sort devices, rejected slots, then the account
        // entry.
        let update = DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::SetAccount(AccountEntryV1::default()),
            DeviceRosterOperationV1::RemoveRejectedSlot(slot(1)),
            DeviceRosterOperationV1::RemoveDevice(slot(2)),
            DeviceRosterOperationV1::RemoveDevice(slot(1)),
        ])
        .unwrap();
        assert!(matches!(
            update.operations(),
            [
                DeviceRosterOperationV1::RemoveDevice(first),
                DeviceRosterOperationV1::RemoveDevice(second),
                DeviceRosterOperationV1::RemoveRejectedSlot(_),
                DeviceRosterOperationV1::SetAccount(_),
            ] if *first == slot(1) && *second == slot(2)
        ));
        let bytes = encode_device_roster_update_v1(&update).unwrap();
        assert_eq!(decode_device_roster_update_v1(&bytes).unwrap(), update);

        // Out of order on the wire.
        let in_order = encode_device_roster_update_v1(
            &DeviceRosterUpdateV1::new(vec![
                DeviceRosterOperationV1::RemoveDevice(slot(1)),
                DeviceRosterOperationV1::RemoveDevice(slot(2)),
            ])
            .unwrap(),
        )
        .unwrap();
        let mut reversed = vec![in_order[0]];
        reversed.extend_from_slice(&in_order[34..]);
        reversed.extend_from_slice(&in_order[1..34]);
        assert!(decode_device_roster_update_v1(&reversed).is_err());
        // 4 and 5 were the removed rejected-KeyPackage operations.
        for op_type in [4, 5, 7] {
            let mut unknown_op = in_order.clone();
            unknown_op[1] = op_type;
            assert!(decode_device_roster_update_v1(&unknown_op).is_err());
        }
        assert!(decode_device_roster_update_v1(&[0]).is_err());
    }

    #[test]
    fn applying_an_update_sets_and_removes_entries() {
        let prior = full_roster();
        let update = DeviceRosterUpdateV1::new(vec![
            DeviceRosterOperationV1::SetDevice(slot(2), device("Work laptop")),
            DeviceRosterOperationV1::SetDevice(slot(3), device("Tablet")),
            DeviceRosterOperationV1::RemoveRejectedSlot(slot(9)),
        ])
        .unwrap();
        let next = prior.apply(&update).unwrap();
        assert_eq!(next.devices[&slot(2)], device("Work laptop"));
        assert_eq!(next.devices[&slot(3)], device("Tablet"));
        assert!(next.rejected_slots.is_empty());
        assert_eq!(next.account, prior.account);
        assert_eq!(next.leaf_tag_key, prior.leaf_tag_key);
        assert_eq!(
            apply_device_roster_update_v1(
                &encode_device_roster_v1(&prior).unwrap(),
                &encode_device_roster_update_v1(&update).unwrap(),
            )
            .unwrap(),
            encode_device_roster_v1(&next).unwrap()
        );

        for invalid in [
            DeviceRosterOperationV1::RemoveDevice(slot(7)),
            DeviceRosterOperationV1::RemoveRejectedSlot(slot(7)),
            DeviceRosterOperationV1::SetRejectedSlot(
                slot(1),
                RejectedSlotV1 {
                    reason: RejectedSlotReasonV1::NotMe,
                    rejected_at: 0,
                    tag_signature_key: None,
                },
            ),
            // The laptop takes the phone's tag signature key.
            DeviceRosterOperationV1::SetDevice(
                slot(2),
                DeviceEntryV1 {
                    tag_signature_key: Some(vec![0x05; 32]),
                    ..device("Laptop")
                },
            ),
        ] {
            let update = DeviceRosterUpdateV1::new(vec![invalid.clone()]).unwrap();
            assert!(prior.apply(&update).is_err(), "{invalid:?}");
        }
    }
}
