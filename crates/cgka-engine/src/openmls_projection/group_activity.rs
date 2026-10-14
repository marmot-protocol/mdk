//! Per-commit presentation deltas captured during authenticated canonical apply.

use std::collections::HashSet;

use cgka_traits::{MemberId, engine::GroupStateChange};
use openmls::prelude::{MlsGroup, Proposal, StagedCommit};

pub(crate) struct GroupActivitySnapshot {
    name: Option<String>,
    admins: Option<Vec<[u8; 32]>>,
    avatar: [Option<Vec<u8>>; 2],
    retention: Option<Option<u64>>,
    members: Vec<MemberId>,
}

impl GroupActivitySnapshot {
    /// Read display components independently. Unknown encodings never veto protocol apply;
    /// the shared derivation can still render a later authenticated repair of those components.
    pub(crate) fn capture(group: &MlsGroup) -> Self {
        Self {
            name: crate::app_components::group_profile_of_group(group)
                .ok()
                .map(|profile| profile.map(|p| p.0).unwrap_or_default()),
            admins: crate::app_components::admins_of_group(group).ok(),
            avatar: crate::message_processor::avatar_component_snapshot(group),
            retention: crate::app_components::message_retention_seconds_of_group(group).ok(),
            members: group
                .members()
                .filter_map(|member| {
                    openmls::prelude::BasicCredential::try_from(member.credential)
                        .ok()
                        .map(|credential| MemberId::new(credential.identity().to_vec()))
                })
                .collect(),
        }
    }

    /// Render account transitions, while sibling-device changes stay out of account history.
    /// All producers use this derivation so author and recipient targets agree.
    pub(crate) fn changes(
        &self,
        after: &Self,
        committer: &MemberId,
        additions: &[MemberId],
        leavers: &[MemberId],
    ) -> Vec<(MemberId, GroupStateChange)> {
        let after_members: HashSet<_> = after.members.iter().collect();
        let mut changes = Vec::new();
        // Unknown before-state uses the historical author fallback. An unknown
        // after-state cannot support a display claim, so omit only that delta.
        if let Some(after) = &after.admins {
            changes.extend(crate::group_state_changes::admin_changes(
                self.admins.as_deref().unwrap_or_default(),
                after,
            ));
        }
        if let Some(after_name) = &after.name {
            changes.extend(crate::group_state_changes::profile_changes(
                self.name.as_deref(),
                Some(after_name),
                &self.avatar,
                &after.avatar,
            ));
        } else if self.avatar != after.avatar {
            changes.push(GroupStateChange::GroupAvatarChanged);
        }
        if let (Some(before), Some(after)) = (self.retention, after.retention) {
            changes.extend(crate::group_state_changes::message_retention_changes(
                before, after,
            ));
        }
        let mut seen_additions = HashSet::new();
        changes.extend(
            additions
                .iter()
                .filter(|member| !self.members.contains(member) && seen_additions.insert(*member))
                .cloned()
                .map(|member| GroupStateChange::MemberAdded { member }),
        );
        let mut attributed: Vec<_> = changes
            .into_iter()
            .map(|change| (committer.clone(), change))
            .collect();
        let mut seen_leavers = HashSet::new();
        attributed.extend(
            leavers
                .iter()
                .filter(|member| !after_members.contains(member) && seen_leavers.insert(*member))
                .cloned()
                .map(|member| (member.clone(), GroupStateChange::MemberLeft { member })),
        );
        let mut removed_accounts = HashSet::new();
        for member in &self.members {
            if !after_members.contains(member)
                && !leavers.contains(member)
                && removed_accounts.insert(member)
            {
                attributed.push((
                    committer.clone(),
                    GroupStateChange::MemberRemoved {
                        member: member.clone(),
                    },
                ));
            }
        }
        attributed
    }
}

/// Read authenticated account identities from the staged Add leaves.
pub(crate) fn staged_additions(
    staged: &StagedCommit,
) -> Result<Vec<MemberId>, super::OpenMlsProjectionError> {
    staged
        .add_proposals()
        .map(|proposal| {
            crate::identity::validated_member_id_of_leaf(
                proposal.add_proposal().key_package().leaf_node(),
            )
        })
        .collect::<Result<_, _>>()
        .map_err(|error| super::OpenMlsProjectionError::Replay(error.to_string()))
}

/// Only a validated SelfRemove proposal authenticates voluntary departure.
pub(crate) fn staged_leavers(group: &MlsGroup, staged: &StagedCommit) -> Vec<MemberId> {
    staged
        .queued_proposals()
        .filter(|proposal| matches!(proposal.proposal(), Proposal::SelfRemove))
        .filter_map(|proposal| crate::identity::member_id_of_sender(proposal.sender(), group))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed_convergence::tests::test_engine;
    use cgka_traits::app_components::{
        GROUP_MESSAGE_RETENTION_COMPONENT_ID, GROUP_PROFILE_COMPONENT_ID,
    };
    use cgka_traits::engine::{CgkaEngine, CreateGroupRequest, SendResult};
    use cgka_traits::storage::StorageProvider;

    /// A valid repair has the same author/recipient target even when its old
    /// display state is undecodable. Unknown resulting state never invents rows.
    #[test]
    fn shared_decoder_preserves_authenticated_display_repairs() {
        let actor = MemberId::new(vec![1; 32]);
        let before = GroupActivitySnapshot {
            name: None,
            admins: None,
            avatar: [None, None],
            retention: None,
            members: vec![actor.clone()],
        };
        let after = GroupActivitySnapshot {
            name: Some("repaired".into()),
            admins: Some(vec![[2; 32]]),
            avatar: [None, None],
            retention: Some(Some(60)),
            members: vec![actor.clone()],
        };
        assert_eq!(
            before.changes(&after, &actor, &[], &[]),
            vec![
                (
                    actor.clone(),
                    GroupStateChange::AdminAdded {
                        member: MemberId::new(vec![2; 32])
                    }
                ),
                (
                    actor.clone(),
                    GroupStateChange::GroupRenamed {
                        name: "repaired".into(),
                        previous_name: None
                    }
                ),
            ]
        );
        // Retention activity requires a numeric old value; do not invent zero
        // when only the previous encoding is unknown.
        assert!(after.changes(&before, &actor, &[], &[]).is_empty());
    }

    /// Existing legacy state can contain unknown display encodings even though
    /// its next MLS self-update is valid. Capture must not veto that update.
    #[tokio::test]
    async fn malformed_legacy_display_components_do_not_block_valid_mls_evolution() {
        use cgka_traits::group::ProtocolProfile;
        use openmls::extensions::{AppDataDictionaryExtension, Extension, Extensions};
        use openmls::group::{MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY};
        use openmls::prelude::LeafNodeParameters;
        let mut engine = test_engine();
        let (id, created) = engine
            .create_group(CreateGroupRequest {
                name: "legacy template".into(),
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
        let extensions = engine
            .with_mls_group(&id, |group| Ok(group.extensions().clone()))
            .unwrap();
        let mut dictionary = extensions
            .app_data_dictionary()
            .unwrap()
            .dictionary()
            .clone();
        dictionary.insert(GROUP_PROFILE_COMPONENT_ID, vec![0xff]);
        dictionary.insert(GROUP_MESSAGE_RETENTION_COMPONENT_ID, vec![0xff]);
        let mut values = extensions
            .iter()
            .filter(|extension| !matches!(extension, Extension::AppDataDictionary(_)))
            .cloned()
            .collect::<Vec<_>>();
        values.push(Extension::AppDataDictionary(
            AppDataDictionaryExtension::new(dictionary),
        ));
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(engine.ciphersuite)
            .capabilities(crate::capabilities::leaf_capabilities(
                &engine.registry,
                engine.ciphersuite,
                ProtocolProfile::Legacy,
            ))
            .with_leaf_node_extensions(
                engine
                    .identity
                    .leaf_extensions(&engine.supported_app_components)
                    .unwrap(),
            )
            .unwrap()
            .with_group_context_extensions(Extensions::from_vec(values).unwrap())
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let provider =
            crate::provider::EngineOpenMlsProvider::<storage_sqlite::SqliteAccountStorage>::new(
                &engine.crypto,
                engine.storage.mls_storage(),
            );
        let mut group = MlsGroup::new(
            &provider,
            &engine.identity.signer,
            &config,
            engine.identity.credential_with_key.clone(),
        )
        .unwrap();
        let before = GroupActivitySnapshot::capture(&group);
        assert_eq!(before.name, None);
        assert_eq!(before.retention, None);
        group
            .self_update(
                &provider,
                &engine.identity.signer,
                LeafNodeParameters::default(),
            )
            .unwrap();
        let staged = group.pending_commit().unwrap();
        crate::app_components::validate_current_profile_invariants_for_staged_commit(
            &group,
            staged,
            group.own_leaf_index(),
        )
        .unwrap();
        group.merge_pending_commit(&provider).unwrap();
        let after = GroupActivitySnapshot::capture(&group);
        assert_eq!(group.epoch().as_u64(), 1);
        assert!(
            before
                .changes(&after, engine.identity.self_id(), &[], &[])
                .is_empty()
        );
        // A valid membership delta survives both unknown display components.
        let added = MemberId::new(vec![0x42; 32]);
        assert_eq!(
            before.changes(
                &after,
                engine.identity.self_id(),
                std::slice::from_ref(&added),
                &[]
            ),
            vec![(
                engine.identity.self_id().clone(),
                GroupStateChange::MemberAdded { member: added }
            )]
        );

        // Drive a real validated AppDataUpdate repairing the legacy profile.
        // This is the same staging helper the author uses, rather than a
        // fabricated before/after name pair.
        engine
            .stage_commit_with_app_data_updates(
                &mut group,
                &provider,
                vec![],
                vec![],
                vec![Proposal::AppDataUpdate(Box::new(
                    openmls::prelude::AppDataUpdateProposal::update(
                        GROUP_PROFILE_COMPONENT_ID,
                        crate::app_components::encode_group_profile("repaired", "").unwrap(),
                    ),
                ))],
                "legacy_profile_repair_test",
            )
            .unwrap();
        group.merge_pending_commit(&provider).unwrap();
        assert_eq!(
            after.changes(
                &GroupActivitySnapshot::capture(&group),
                engine.identity.self_id(),
                &[],
                &[],
            ),
            vec![(
                engine.identity.self_id().clone(),
                GroupStateChange::GroupRenamed {
                    name: "repaired".into(),
                    previous_name: None,
                },
            )]
        );
    }
}
