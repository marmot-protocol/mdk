//! `SendIntent::UpdateGroupData` — issues an `AppDataUpdate` commit for
//! `marmot.group.profile.v1`.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{AppComponentData, GROUP_PROFILE_COMPONENT_ID};
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId};
use openmls::component::ComponentData;
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use std::collections::BTreeSet;
use tls_codec::Serialize as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_send_update_group_data(
        &mut self,
        group_id: GroupId,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<SendResult, EngineError> {
        if name.is_none() && description.is_none() {
            return Err(EngineError::Other(
                "UpdateGroupData with no fields to change".into(),
            ));
        }

        let current_profile = self
            .storage
            .get_group(&group_id)
            .ok()
            .map(|g| (g.name, g.description))
            .unwrap_or_default();
        let projected_name = name.unwrap_or(current_profile.0);
        let projected_description = description.unwrap_or(current_profile.1);
        let profile_bytes =
            crate::app_components::encode_group_profile(&projected_name, &projected_description)?;

        self.do_send_update_app_components(
            group_id,
            vec![AppComponentData {
                component_id: GROUP_PROFILE_COMPONENT_ID,
                data: profile_bytes,
            }],
        )
        .await
    }

    pub(crate) async fn do_send_update_app_components(
        &mut self,
        group_id: GroupId,
        updates: Vec<AppComponentData>,
    ) -> Result<SendResult, EngineError> {
        if updates.is_empty() {
            return Err(EngineError::Other(
                "UpdateAppComponents requires at least one component update".into(),
            ));
        }

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "UpdateAppComponents",
                    reason: "update_app_components requires Stable",
                },
            ));
        }

        let mut seen = BTreeSet::new();
        for update in &updates {
            if !seen.insert(update.component_id) {
                return Err(EngineError::Other(
                    "UpdateAppComponents contains duplicate component ids".into(),
                ));
            }
            crate::app_components::validate_app_component_update(update)?;
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        // Fork-detection bookkeeping (pre-stage epoch is the commit
        // origin).
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, &group_id, pre_commit_epoch)?;
        self.epoch_manager
            .record_committed_from(&group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Stage the AppDataUpdate commit. Don't merge — confirm path does that.
        let proposals = updates
            .iter()
            .map(|update| {
                Proposal::AppDataUpdate(Box::new(AppDataUpdateProposal::update(
                    update.component_id,
                    update.data.clone(),
                )))
            })
            .collect::<Vec<_>>();
        let mut builder = mls_group
            .commit_builder()
            .add_proposals(proposals)
            .load_psks(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
            )
            .map_err(|e| EngineError::Backend(format!("load_psks: {e:?}")))?;
        let mut app_data = builder.app_data_dictionary_updater();
        for proposal in builder.app_data_update_proposals() {
            if let AppDataUpdateOperation::Update(data) = proposal.operation() {
                app_data.set(ComponentData::from_parts(
                    proposal.component_id(),
                    data.clone(),
                ));
            }
        }
        builder.with_app_data_dictionary_updates(app_data.changes());
        let commit_bundle = builder
            .build(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::rand(&provider),
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::crypto(
                    &provider,
                ),
                &self.identity.signer,
                |_| true,
            )
            .map_err(|e| EngineError::Backend(format!("app_data_update build: {e:?}")))?
            .stage_commit(&provider)
            .map_err(|e| EngineError::Backend(format!("app_data_update stage: {e:?}")))?;
        let (commit_out, _welcome_opt, _gi) = commit_bundle.into_contents();
        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| EngineError::Serialize(format!("{e:?}")))?;

        let wrapped = self
            .peeler
            .wrap_group_message(
                &EncryptedPayload {
                    ciphertext: commit_bytes.clone(),
                    aad: vec![],
                },
                &pre_commit_ctx,
            )
            .await
            .map_err(EngineError::Peeler)?;
        let wrapped = TransportMessage {
            envelope: TransportEnvelope::GroupMessage {
                transport_group_id: pre_commit_ctx
                    .transport_group_id()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| group_id.as_slice().to_vec()),
            },
            ..wrapped
        };
        self.record_sent_openmls_message(
            &wrapped,
            commit_bytes.as_slice(),
            &group_id,
            pre_commit_epoch,
        )?;

        // Mirror projected app-facing fields at send time. Rollback
        // re-derives from the unmerged MLS app component.
        if let Ok(mut g) = self.storage.get_group(&group_id) {
            for update in &updates {
                if update.component_id == GROUP_PROFILE_COMPONENT_ID {
                    let (name, description) =
                        crate::app_components::decode_group_profile(&update.data)?;
                    g.name = name;
                    g.description = description;
                }
            }
            self.storage.put_group(&g)?;
        }

        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged = StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
        )?;
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            pre_commit_epoch,
            wrapped.id.clone(),
            &commit_bytes,
            recovery_snapshot,
        );

        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending: pending_ref,
        })
    }
}
