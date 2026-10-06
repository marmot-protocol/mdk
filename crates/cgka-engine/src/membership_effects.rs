//! Canonical device effects are independent of renderable account activity.

use crate::Engine;
use cgka_traits::{
    EngineError, GroupId, MemberId,
    engine::{GroupEvent, GroupMemberLeaf},
    storage::StorageProvider,
};
use openmls::prelude::{BasicCredential, MlsGroup};

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
}

impl<S: StorageProvider> Engine<S> {
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
    pub(crate) fn emit_canonical_membership_effects(
        &mut self,
        group_id: &GroupId,
        before: &MembershipSnapshot,
    ) -> Result<(), EngineError> {
        let after = self.canonical_membership_snapshot(group_id)?;
        let leaves: Vec<_> = before
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
            self.events_buf
                .push_back(GroupEvent::GroupMemberLeavesRemoved {
                    group_id: group_id.clone(),
                    epoch: self.storage.get_group(group_id)?.epoch,
                    leaves,
                    departed_members,
                });
        }
        if !after.local_active {
            let record = self.storage.get_group(group_id)?;
            if record.disbanded.is_none() {
                self.discard_queued_outbound_intents_with_termination(
                    group_id,
                    before.local_active || !before.record_removed,
                )?;
                self.retire_deferred_peel_rows_for_terminal_group(group_id)?;
                self.clear_leave_request_state(group_id)?;
            }
        } else if before.record_removed || !before.local_active {
            let mut record = self.storage.get_group(group_id)?;
            if record.disbanded.is_none() {
                record.removed = false;
                self.storage.put_group(&record)?;
                self.events_buf
                    .push_back(GroupEvent::LocalGroupCopyRestored {
                        group_id: group_id.clone(),
                    });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_convergence::tests::test_engine;
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};

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
        // Model the previous authenticated tree's different leaf key. Index and
        // account alone would miss this transition and retain the old token.
        let mut replaced = engine.canonical_membership_snapshot(&group).unwrap();
        replaced.leaves[0].1[0] ^= 0xff;
        engine
            .emit_canonical_membership_effects(&group, &replaced)
            .unwrap();
        let events = engine.drain_events();
        assert!(
            matches!(&events[..], [GroupEvent::GroupMemberLeavesRemoved { leaves, departed_members, .. }] if leaves.len() == 1 && departed_members.is_empty())
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
