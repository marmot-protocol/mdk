//! The receiver rules of device-roster-v1.md, "Key binding" (marmot#521).
//!
//! A `tag_signature_key` in a device group's roster is the signature key of
//! the device whose entry or record holds it. The Commit that adds a device
//! binds the key to the leaf it adds, and no later Commit changes it. Each
//! rule is decided from the Commit and its candidate parent state alone, so
//! every member reaches the same answer:
//!
//! - every added leaf has a new entry, set inline, with its key, and an entry
//!   for a slot the parent does not list is set only that way;
//! - a key never changes;
//! - a keyed entry is removed only inline, with every leaf that signs with
//!   its key;
//! - a `removed` record keeps only its slot's key;
//! - a leaf keeps its signature key.
//!
//! [`validate_commit`] runs at the shared staged-Commit checkpoint
//! ([`crate::app_components::validate_current_profile_invariants_for_staged_commit`]),
//! so local sends, inbound Commits, convergence replay and fork recovery all
//! decide the same way. [`validate_standalone_update`] applies the same
//! rules to a standalone roster proposal, which can carry no Add and is
//! never inline. Neither reads stored state, so a device group whose roster
//! was written before these rules keeps working: only new Commits are held
//! to them.

use std::collections::BTreeSet;

use cgka_traits::app_components::{
    DEVICE_ROSTER_COMPONENT_ID, DeviceRosterOperationV1, DeviceRosterV1, RejectedSlotReasonV1,
    decode_device_roster_update_v1,
};
use cgka_traits::error::EngineError;
use openmls::group::{MlsGroup, StagedCommit};
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{LeafNode, LeafNodeIndex, ProposalOrRefType, Sender};

/// Check a Commit whose candidate parent is `parent` against the rules.
/// `resulting_leaves` is the Commit's complete resulting leaf set.
pub(crate) fn validate_commit(
    parent: &MlsGroup,
    staged: &StagedCommit,
    committer_index: LeafNodeIndex,
    resulting_leaves: &[LeafNode],
) -> Result<(), EngineError> {
    if !crate::app_components::group_requires_device_roster(parent)? {
        return Ok(());
    }
    let roster = parent_roster(parent)?;

    // A leaf keeps its signature key.
    for update in staged.update_proposals() {
        let Sender::Member(index) = update.sender() else {
            continue;
        };
        keeps_signature_key(parent, *index, update.update_proposal().leaf_node())?;
    }
    if let Some(path_leaf) = staged.update_path_leaf_node() {
        keeps_signature_key(parent, committer_index, path_leaf)?;
    }

    let mut operations = Vec::new();
    for queued in staged.queued_proposals() {
        if let Proposal::AppDataUpdate(update) = queued.proposal()
            && let Some(ops) = roster_operations(update)?
        {
            let inline = queued.proposal_or_ref_type() == ProposalOrRefType::Proposal;
            operations.extend(ops.into_iter().map(|op| (op, inline)));
        }
    }
    let added: BTreeSet<Vec<u8>> = staged
        .add_proposals()
        .map(|add| {
            add.add_proposal()
                .key_package()
                .leaf_node()
                .signature_key()
                .as_slice()
                .to_vec()
        })
        .collect();
    let resulting: BTreeSet<&[u8]> = resulting_leaves
        .iter()
        .map(|leaf| leaf.signature_key().as_slice())
        .collect();
    validate_operations(&roster, &operations, &added, &resulting)
}

/// Check a standalone roster proposal against the rules, on the state it
/// was proposed in. It carries no Add and is not inline, so it can neither
/// set an entry for a new slot nor remove a keyed entry.
pub(crate) fn validate_standalone_update(
    group: &MlsGroup,
    update: &AppDataUpdateProposal,
) -> Result<(), EngineError> {
    if !crate::app_components::group_requires_device_roster(group)? {
        return Ok(());
    }
    let Some(operations) = roster_operations(update)? else {
        return Ok(());
    };
    let operations: Vec<_> = operations.into_iter().map(|op| (op, false)).collect();
    validate_operations(
        &parent_roster(group)?,
        &operations,
        &BTreeSet::new(),
        &BTreeSet::new(),
    )
}

/// Check a standalone Update proposal: the leaf it proposes keeps the
/// sender's signature key.
pub(crate) fn validate_standalone_leaf_update(
    group: &MlsGroup,
    sender: LeafNodeIndex,
    leaf: &LeafNode,
) -> Result<(), EngineError> {
    if !crate::app_components::group_requires_device_roster(group)? {
        return Ok(());
    }
    keeps_signature_key(group, sender, leaf)
}

fn parent_roster(group: &MlsGroup) -> Result<DeviceRosterV1, EngineError> {
    crate::app_components::device_roster_of_group(group).ok_or_else(|| {
        EngineError::Other(
            "invalid device roster state: the required roster has no GroupContext state".into(),
        )
    })
}

fn roster_operations(
    update: &AppDataUpdateProposal,
) -> Result<Option<Vec<DeviceRosterOperationV1>>, EngineError> {
    if update.component_id() != DEVICE_ROSTER_COMPONENT_ID {
        return Ok(None);
    }
    let AppDataUpdateOperation::Update(data) = update.operation() else {
        return Ok(None);
    };
    decode_device_roster_update_v1(data.as_slice())
        .map(|update| Some(update.operations().to_vec()))
        .map_err(|error| EngineError::Serialize(format!("invalid device roster update: {error}")))
}

fn keeps_signature_key(
    parent: &MlsGroup,
    index: LeafNodeIndex,
    leaf: &LeafNode,
) -> Result<(), EngineError> {
    let Some(member) = parent.member_at(index) else {
        return Ok(());
    };
    if member.signature_key != leaf.signature_key().as_slice() {
        return Err(refused("a device group's leaf keeps its signature key"));
    }
    Ok(())
}

/// The roster rules over one Commit's or proposal's roster operations, each
/// with whether it is inline. `added` holds the signature keys of the leaves
/// the Commit adds, `resulting` those of its resulting state.
fn validate_operations(
    parent: &DeviceRosterV1,
    operations: &[(DeviceRosterOperationV1, bool)],
    added: &BTreeSet<Vec<u8>>,
    resulting: &BTreeSet<&[u8]>,
) -> Result<(), EngineError> {
    let mut new_entry_keys = BTreeSet::new();
    for (operation, inline) in operations {
        match operation {
            DeviceRosterOperationV1::SetDevice(slot, entry) => match parent.devices.get(slot) {
                Some(current) => {
                    if entry.tag_signature_key != current.tag_signature_key {
                        return Err(refused("a device's tag signature key never changes"));
                    }
                }
                None => {
                    let Some(key) = entry.tag_signature_key.as_deref() else {
                        return Err(refused(ADDED_LEAF_ENTRY));
                    };
                    if !inline {
                        return Err(refused(ADDED_LEAF_ENTRY));
                    }
                    new_entry_keys.insert(key.to_vec());
                }
            },
            DeviceRosterOperationV1::RemoveDevice(slot) => {
                let Some(key) = parent
                    .devices
                    .get(slot)
                    .and_then(|entry| entry.tag_signature_key.as_deref())
                else {
                    continue;
                };
                if !inline || resulting.contains(key) {
                    return Err(refused(
                        "a keyed device entry is removed only inline, with its leaf",
                    ));
                }
            }
            DeviceRosterOperationV1::SetRejectedSlot(slot, record) => {
                let Some(key) = record.tag_signature_key.as_deref() else {
                    continue;
                };
                let slot_key = parent
                    .devices
                    .get(slot)
                    .and_then(|entry| entry.tag_signature_key.as_deref())
                    == Some(key);
                let record_key = parent.rejected_slots.get(slot).is_some_and(|current| {
                    current.reason == RejectedSlotReasonV1::Removed
                        && current.tag_signature_key.as_deref() == Some(key)
                });
                if record.reason != RejectedSlotReasonV1::Removed || !(slot_key || record_key) {
                    return Err(refused("a removed record keeps only its slot's key"));
                }
            }
            DeviceRosterOperationV1::RemoveRejectedSlot(_)
            | DeviceRosterOperationV1::SetAccount(_) => {}
        }
    }
    if new_entry_keys != *added {
        return Err(refused(ADDED_LEAF_ENTRY));
    }
    Ok(())
}

const ADDED_LEAF_ENTRY: &str =
    "every leaf a device group's Commit adds has a new entry, set inline, with its key";

fn refused(rule: &str) -> EngineError {
    EngineError::Other(format!(
        "commit is invalid: device roster key binding: {rule}"
    ))
}
