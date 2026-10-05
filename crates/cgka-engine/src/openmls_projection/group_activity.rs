//! Per-commit presentation deltas captured during authenticated canonical apply.

use std::collections::HashSet;

use cgka_traits::{MemberId, engine::GroupStateChange};
use openmls::prelude::{MlsGroup, Proposal, StagedCommit};

use super::marmot_members;

pub(super) struct GroupActivitySnapshot {
    name: String,
    admins: Vec<[u8; 32]>,
    avatar: [Option<Vec<u8>>; 2],
    retention: Option<u64>,
    members: Vec<MemberId>,
}

impl GroupActivitySnapshot {
    /// Decode the presentation state from one authenticated MLS tree; malformed components fail apply.
    pub(super) fn capture(group: &MlsGroup) -> Result<Self, super::OpenMlsProjectionError> {
        let map_error = |error: cgka_traits::EngineError| {
            super::OpenMlsProjectionError::Replay(error.to_string())
        };
        Ok(Self {
            name: crate::app_components::group_profile_of_group(group)
                .map_err(map_error)?
                .map(|profile| profile.0)
                .unwrap_or_default(),
            admins: crate::app_components::admins_of_group(group).map_err(map_error)?,
            avatar: crate::message_processor::avatar_component_snapshot(group),
            retention: crate::app_components::message_retention_seconds_of_group(group)
                .map_err(map_error)?,
            members: marmot_members(group)
                .into_iter()
                .map(|member| member.id)
                .collect(),
        })
    }

    /// Derive this commit's activity from its source and result trees.
    /// Only validated SelfRemove senders override the committer as departure actors.
    pub(super) fn changes(
        &self,
        after: &Self,
        committer: &MemberId,
        leavers: &[MemberId],
    ) -> Vec<(MemberId, GroupStateChange)> {
        let before_members: HashSet<_> = self.members.iter().collect();
        let after_members: HashSet<_> = after.members.iter().collect();
        let mut changes = crate::group_state_changes::admin_changes(&self.admins, &after.admins);
        changes.extend(crate::group_state_changes::profile_changes(
            Some(&self.name),
            Some(&after.name),
            &self.avatar,
            &after.avatar,
        ));
        changes.extend(crate::group_state_changes::message_retention_changes(
            self.retention,
            after.retention,
        ));
        changes.extend(
            after
                .members
                .iter()
                .filter(|member| !before_members.contains(member))
                .cloned()
                .map(|member| GroupStateChange::MemberAdded { member }),
        );
        let mut attributed: Vec<_> = changes
            .into_iter()
            .map(|change| (committer.clone(), change))
            .collect();
        for member in self
            .members
            .iter()
            .filter(|member| !after_members.contains(member))
        {
            attributed.push(if leavers.contains(member) {
                (
                    member.clone(),
                    GroupStateChange::MemberLeft {
                        member: member.clone(),
                    },
                )
            } else {
                (
                    committer.clone(),
                    GroupStateChange::MemberRemoved {
                        member: member.clone(),
                    },
                )
            });
        }
        attributed
    }
}

/// Only a validated SelfRemove proposal authenticates voluntary departure.
pub(super) fn staged_leavers(group: &MlsGroup, staged: &StagedCommit) -> Vec<MemberId> {
    staged
        .queued_proposals()
        .filter(|proposal| matches!(proposal.proposal(), Proposal::SelfRemove))
        .filter_map(|proposal| crate::identity::member_id_of_sender(proposal.sender(), group))
        .collect()
}
