//! Canonical device effects are independent of renderable account activity.

use crate::Engine;
use cgka_traits::{
    EngineError, GroupId, MemberId,
    engine::{GroupEvent, GroupMemberLeaf},
    storage::StorageProvider,
};
use openmls::prelude::{BasicCredential, MlsGroup};

/// Durable membership work prepared inside its caller's transaction. Native
/// notifications and derived engine bookkeeping are released only after commit.
pub(crate) struct CanonicalMembershipEffects {
    events: Vec<GroupEvent>,
    termination: Option<crate::message_processor::LocalGroupTermination>,
    announce_termination: bool,
}

/// Retain leaf keys privately so reuse of an index by the same account is a real transition.
/// Keys never leave the engine or enter diagnostics.
pub(crate) struct MembershipSnapshot {
    leaves: Vec<(GroupMemberLeaf, Vec<u8>)>,
    local_active: bool,
    record_removed: bool,
}

impl MembershipSnapshot {
    pub(crate) fn capture(group: &MlsGroup, identity: &MemberId, record_removed: bool) -> Self {
        Self {
            leaves: group
                .members()
                .filter_map(|member| {
                    BasicCredential::try_from(member.credential)
                        .ok()
                        .map(|credential| {
                            (
                                GroupMemberLeaf {
                                    member: MemberId::new(credential.identity().to_vec()),
                                    leaf_index: member.index.u32(),
                                },
                                member.signature_key,
                            )
                        })
                })
                .collect(),
            local_active: crate::identity::local_leaf_is_active(group, identity),
            record_removed,
        }
    }
    /// Derive a leaf notification from immutable trees; this performs no writes.
    fn departed_leaf_event(
        &self,
        after: &Self,
        group_id: &GroupId,
        epoch: cgka_traits::EpochId,
    ) -> Option<GroupEvent> {
        let leaves: Vec<_> = self
            .leaves
            .iter()
            .filter(|leaf| !after.leaves.contains(leaf))
            .map(|(leaf, _)| leaf.clone())
            .collect();
        let mut departed_members = Vec::new();
        for leaf in &leaves {
            if !after
                .leaves
                .iter()
                .any(|(active, _)| active.member == leaf.member)
                && !departed_members.contains(&leaf.member)
            {
                departed_members.push(leaf.member.clone());
            }
        }
        if !leaves.is_empty() {
            return Some(GroupEvent::GroupMemberLeavesRemoved {
                group_id: group_id.clone(),
                epoch,
                leaves,
                departed_members,
            });
        }
        None
    }
}

/// Current trusted tag namespace, pinned before historical reconstruction.
/// A leaf must authenticate both this account and the exact tagged slot.
/// No roster that cannot be read can make a leaf read as a sibling.
pub(crate) struct SiblingSelfRemovalContext {
    account: MemberId,
    roster: cgka_traits::app_components::DeviceRosterV1,
}

impl SiblingSelfRemovalContext {
    pub(crate) fn staged_slots(
        &self,
        group: &MlsGroup,
        staged: &openmls::group::StagedCommit,
    ) -> std::collections::BTreeSet<cgka_traits::app_components::DeviceSlotId> {
        use openmls::prelude::{Proposal, Sender};
        staged
            .queued_proposals()
            .filter_map(|proposal| {
                if !matches!(proposal.proposal(), Proposal::SelfRemove) {
                    return None;
                }
                let Sender::Member(index) = proposal.sender() else {
                    return None;
                };
                if *index == group.own_leaf_index() {
                    return None;
                }
                self.leaf_slot(group.public_group().leaf(*index)?)
            })
            .collect()
    }

    fn leaf_slot(
        &self,
        leaf: &openmls::prelude::LeafNode,
    ) -> Option<cgka_traits::app_components::DeviceSlotId> {
        use cgka_traits::app_components::DeviceTagClaim;
        if !crate::identity::validated_member_id_of_leaf(leaf)
            .is_ok_and(|account| account == self.account)
        {
            return None;
        }
        match crate::device_tag::device_tag_claim(leaf, &self.roster) {
            DeviceTagClaim::Device(slot) => Some(slot),
            _ => None,
        }
    }

    /// Only the final selected tree can end a current-membership hold.
    pub(crate) fn clear_present(&self, group: &MlsGroup, record: &mut cgka_traits::Group) {
        for member in group.members() {
            if let Some(slot) = group
                .public_group()
                .leaf(member.index)
                .and_then(|leaf| self.leaf_slot(leaf))
            {
                record.self_removed_sibling_slots.remove(&slot);
            }
        }
    }
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn sibling_self_removal_context(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<SiblingSelfRemovalContext>, EngineError> {
        let Some(trusted) = self
            .device_tag_group
            .as_ref()
            .filter(|trusted| *trusted != group_id)
        else {
            return Ok(None);
        };
        match self.ensure_group_live(trusted) {
            Ok(()) => {}
            Err(EngineError::UnknownGroup(_) | EngineError::GroupNotHydrated(_)) => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
        // Reading another leaf's tag does not require this observer's own
        // entry to have announced its tag key. Reuse the same trusted live
        // roster, but preserve real load/storage errors for transaction retry.
        let Some(device_group) = MlsGroup::load(
            self.storage.mls_storage(),
            &openmls::group::GroupId::from_slice(trusted.as_slice()),
        )
        .map_err(|error| EngineError::Backend(format!("load device group: {error:?}")))?
        else {
            return Ok(None);
        };
        if !device_group.is_active()
            || !crate::app_components::group_requires_device_roster(&device_group)?
        {
            return Ok(None);
        }
        Ok(
            crate::app_components::device_roster_of_group(&device_group).map(|roster| {
                SiblingSelfRemovalContext {
                    account: self.identity.self_id().clone(),
                    roster,
                }
            }),
        )
    }

    pub(crate) fn canonical_membership_snapshot(
        &self,
        group_id: &GroupId,
    ) -> Result<MembershipSnapshot, EngineError> {
        let removed = self.storage.get_group(group_id)?.removed;
        self.with_mls_group(group_id, |group| {
            Ok(MembershipSnapshot::capture(
                group,
                self.identity.self_id(),
                removed,
            ))
        })
    }

    /// Compare the actual pre-apply and selected trees once. Replayed common-prefix
    /// removals must not delete a replacement device's newer registration.
    #[cfg(test)]
    pub(crate) fn emit_canonical_membership_effects(
        &mut self,
        group_id: &GroupId,
        before: &MembershipSnapshot,
    ) -> Result<(), EngineError> {
        let after = self.canonical_membership_snapshot(group_id)?;
        let effects = self.storage.with_transaction(|storage| {
            self.prepare_canonical_membership_effects_on_storage(storage, group_id, before, &after)
        })?;
        self.finish_canonical_membership_effects(group_id, effects);
        Ok(())
    }

    /// Prepare all fallible storage work before a merge consumes its pending
    /// slot. The supplied snapshots describe the actual pre/post-merge trees.
    pub(crate) fn prepare_canonical_membership_effects_on_storage(
        &self,
        storage: &S,
        group_id: &GroupId,
        before: &MembershipSnapshot,
        after: &MembershipSnapshot,
    ) -> Result<CanonicalMembershipEffects, EngineError> {
        let mut record = storage.get_group(group_id)?;
        let mut events = Vec::new();
        if let Some(event) = before.departed_leaf_event(after, group_id, record.epoch) {
            events.push(event);
        }
        let mut termination = None;
        if record.disbanded.is_none() {
            if !after.local_active {
                termination = Some(crate::message_processor::prepare_local_group_termination(
                    storage, group_id,
                )?);
            } else {
                // Historical selection can restore an old removed marker even
                // when the source copy was already live. Normalize the selected
                // record independently of whether membership actually changed.
                if record.removed {
                    record.removed = false;
                    storage.put_group(&record)?;
                }
                if before.record_removed || !before.local_active {
                    events.push(GroupEvent::LocalGroupCopyRestored {
                        group_id: group_id.clone(),
                    });
                }
            }
        }
        Ok(CanonicalMembershipEffects {
            events,
            termination,
            announce_termination: before.local_active || !before.record_removed,
        })
    }

    /// Publish a successfully committed membership plan without reading storage.
    pub(crate) fn finish_canonical_membership_effects(
        &mut self,
        group_id: &GroupId,
        prepared: CanonicalMembershipEffects,
    ) {
        self.events_buf.extend(prepared.events);
        if let Some(termination) = prepared.termination {
            self.finish_local_group_termination(
                group_id,
                termination,
                prepared.announce_termination,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_convergence::tests::test_engine;
    use cgka_traits::GroupStorage;
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};

    /// Selected historical metadata must agree with the authenticated live leaf,
    /// without inventing restoration when the source copy was already active.
    #[tokio::test]
    async fn active_selection_normalizes_removed_metadata_without_false_restoration() {
        let mut engine = test_engine();
        let (group, created) = engine
            .create_group(CreateGroupRequest {
                name: "selected membership".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated { pending, .. } = created else {
            panic!("legacy creation");
        };
        engine.confirm_published(pending).await.unwrap();
        engine.drain_events();
        for source_removed in [false, true] {
            for selected_removed in [false, true] {
                let mut record = engine.storage.get_group(&group).unwrap();
                record.removed = source_removed;
                engine.storage.put_group(&record).unwrap();
                let before = engine.canonical_membership_snapshot(&group).unwrap();
                // Model historical selection replacing only device-local record
                // metadata; the authenticated MLS leaf remains active.
                record.removed = selected_removed;
                engine.storage.put_group(&record).unwrap();
                engine
                    .emit_canonical_membership_effects(&group, &before)
                    .unwrap();
                assert!(!engine.storage.get_group(&group).unwrap().removed);
                let events = engine.drain_events();
                assert_eq!(events.len(), usize::from(source_removed));
                assert!(events.iter().all(|event| matches!(event,
                    GroupEvent::LocalGroupCopyRestored { group_id } if group_id == &group)));
                let current = engine.canonical_membership_snapshot(&group).unwrap();
                engine
                    .emit_canonical_membership_effects(&group, &current)
                    .unwrap();
                assert!(engine.drain_events().is_empty());
            }
        }
    }

    /// A reused slot and account still represent a different device when its
    /// authenticated leaf key changes. Replayed unchanged prefixes stay silent.
    #[tokio::test]
    async fn membership_effects_distinguish_reused_leaf_keys_and_suppress_common_prefix() {
        let mut engine = test_engine();
        let (group, created) = engine
            .create_group(CreateGroupRequest {
                name: "device effects".into(),
                description: String::new(),
                members: vec![],
                required_features: vec![],
                app_components: vec![],
                initial_admins: vec![],
            })
            .await
            .unwrap();
        let SendResult::GroupCreated { pending, .. } = created else {
            panic!("legacy creation");
        };
        engine.confirm_published(pending).await.unwrap();
        engine.drain_events();
        let unchanged = engine.canonical_membership_snapshot(&group).unwrap();
        engine
            .emit_canonical_membership_effects(&group, &unchanged)
            .unwrap();
        assert!(engine.drain_events().is_empty());
        // Pure diff control: model a different key in the immutable snapshot.
        // This does not assert that an inbound tree authenticated that key.
        let mut replaced = engine.canonical_membership_snapshot(&group).unwrap();
        replaced.leaves[0].1[0] ^= 0xff;
        engine
            .emit_canonical_membership_effects(&group, &replaced)
            .unwrap();
        let events = engine.drain_events();
        assert_eq!(
            events,
            vec![GroupEvent::GroupMemberLeavesRemoved {
                group_id: group.clone(),
                epoch: engine.epoch(&group).unwrap(),
                leaves: vec![replaced.leaves[0].0.clone()],
                departed_members: vec![],
            }]
        );
        let current = engine.canonical_membership_snapshot(&group).unwrap();
        engine
            .emit_canonical_membership_effects(&group, &current)
            .unwrap();
        assert!(
            engine.drain_events().is_empty(),
            "a common-prefix replay must preserve newer destinations"
        );
    }
}
