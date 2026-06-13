//! `upgrade_group_capabilities` — produces a commit that promotes every
//! currently-upgradeable capability into the group's required set.
//!
//! Mirrors `do_send_invite`'s shape (parse, stage commit, wrap with
//! pre-stage exporter, transition to `PendingPublish`, return
//! `GroupEvolution`). Publish-before-apply defers merge and Marmot record
//! updates to `do_confirm_published`.

use crate::engine::Engine;
use crate::pending_commit_guard::PendingCommitCleanupGuard;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId};
use openmls::component::ComponentData;
use openmls::extensions::{Extension, Extensions, RequiredCapabilitiesExtension};
use openmls::group::MlsGroup;
use openmls::messages::proposals::{AppDataUpdateOperation, AppDataUpdateProposal, Proposal};
use openmls::prelude::{ExtensionType, ProposalType};
use tls_codec::Serialize as _;

impl<S: StorageProvider> Engine<S> {
    pub(crate) async fn do_upgrade_group_capabilities(
        &mut self,
        group_id: &GroupId,
    ) -> Result<SendResult, EngineError> {
        // Must be Stable to upgrade.
        if let Some(state) = self.epoch_manager.state(group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "Upgrade",
                    reason: "upgrade requires Stable",
                },
            ));
        }

        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mut mls_group = MlsGroup::load(
            <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(&provider),
            &mls_gid,
        )
        .map_err(|e| EngineError::Backend(format!("load: {e:?}")))?
        .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::app_components::require_admin(&mls_group, group_id, self.identity.self_id())?;

        // Compute upgradeable capabilities only after the admin gate so
        // non-admin callers get the policy error instead of a cache-shaped
        // "nothing to upgrade" result.
        let upgradeable = self.do_upgradeable_capabilities(group_id)?;
        if upgradeable.is_empty() {
            return Err(EngineError::Other(
                "no upgradeable capabilities to apply".into(),
            ));
        }

        // Build new RequiredCapabilities = existing ∪ upgradeable MLS
        // primitives. App components are negotiated in the upstream
        // `app_components` component, not in MLS RequiredCapabilities.
        let mut req_exts: Vec<u16> = Vec::new();
        let mut req_props: Vec<u16> = Vec::new();
        for ext in mls_group.extensions().iter() {
            if let Extension::RequiredCapabilities(rc) = ext {
                for t in rc.extension_types() {
                    req_exts.push(u16::from(*t));
                }
                for t in rc.proposal_types() {
                    req_props.push(u16::from(*t));
                }
            }
        }
        for e in &upgradeable.extensions {
            if !req_exts.contains(e) {
                req_exts.push(*e);
            }
        }
        for p in &upgradeable.proposals {
            if !req_props.contains(p) {
                req_props.push(*p);
            }
        }
        req_exts.sort();
        req_exts.dedup();
        req_props.sort();
        req_props.dedup();
        let upgrades_required_capabilities =
            !upgradeable.extensions.is_empty() || !upgradeable.proposals.is_empty();
        let new_extensions = if upgrades_required_capabilities {
            let new_rc = RequiredCapabilitiesExtension::new(
                &req_exts
                    .iter()
                    .copied()
                    .map(ExtensionType::from)
                    .collect::<Vec<_>>(),
                &req_props
                    .iter()
                    .copied()
                    .map(ProposalType::from)
                    .collect::<Vec<_>>(),
                &[],
            );

            let mut new_ext_vec: Vec<Extension> = mls_group
                .extensions()
                .iter()
                .filter(|e| !matches!(e, Extension::RequiredCapabilities(_)))
                .cloned()
                .collect();
            new_ext_vec.push(Extension::RequiredCapabilities(new_rc));
            Some(
                Extensions::from_vec(new_ext_vec)
                    .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?,
            )
        } else {
            None
        };

        let mut app_component_updates = Vec::new();
        if !upgradeable.app_components.is_empty() {
            let mut required_components =
                crate::app_components::required_app_components_of_group(&mls_group)?;
            let before = required_components.clone();
            for component_id in &upgradeable.app_components.ids {
                required_components.insert(*component_id);
            }
            if required_components != before {
                app_component_updates.push(Proposal::AppDataUpdate(Box::new(
                    AppDataUpdateProposal::update(
                        cgka_traits::app_components::APP_COMPONENTS_COMPONENT_ID,
                        cgka_traits::app_components::encode_components_list(
                            &required_components.ids,
                        ),
                    ),
                )));
            }
        }

        // Fork-detection bookkeeping.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, group_id, pre_commit_epoch)?;
        self.audit_snapshot_created(
            group_id,
            &recovery_snapshot,
            pre_commit_epoch,
            "pre_upgrade_commit",
        );
        self.epoch_manager
            .record_committed_from(group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Produce + stage the upgrade commit. Under publish-before-apply we
        // do NOT call `merge_pending_commit` here — the merge + Marmot
        // record's required capability update both defer to
        // `do_confirm_published` (which reads the post-merge group state).
        let mut commit_builder = mls_group.commit_builder();
        if let Some(new_extensions) = new_extensions {
            commit_builder = commit_builder
                .propose_group_context_extensions(new_extensions)
                .map_err(|e| EngineError::Backend(format!("upgrade_gce: {e:?}")))?;
        }
        if !app_component_updates.is_empty() {
            commit_builder = commit_builder.add_proposals(app_component_updates);
        }
        let mut builder = commit_builder
            .load_psks(
                <EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                    &provider,
                ),
            )
            .map_err(|e| EngineError::Backend(format!("upgrade load_psks: {e:?}")))?;
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
            .map_err(|e| EngineError::Backend(format!("upgrade build: {e:?}")))?
            .stage_commit(&provider)
            .map_err(|e| EngineError::Backend(format!("upgrade stage: {e:?}")))?;
        let pending_commit_guard = PendingCommitCleanupGuard::arm(&provider, group_id.clone());
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
            group_id,
            pre_commit_epoch,
        )?;

        // State: PendingPublish at the projected post-merge epoch (+1).
        let new_epoch = EpochId(pre_commit_epoch.0.saturating_add(1));
        let commit_priority = mls_group
            .pending_commit()
            .map(crate::app_components::commit_ordering_priority_for_staged)
            .ok_or_else(|| EngineError::Backend("upgrade produced no pending commit".into()))?;
        let pending_ref = self.epoch_manager.next_pending_ref();
        let staged = StagedCommitHandle::from_bytes(group_id.as_slice().to_vec());
        self.epoch_manager.begin_pending(
            group_id.clone(),
            pre_commit_epoch,
            new_epoch,
            staged,
            pending_ref,
            crate::epoch_manager::PendingKind::GroupEvolution,
            self.current_audit_context.clone(),
        )?;
        self.track_pending_commit_for_recovery(
            pending_ref,
            group_id.clone(),
            pre_commit_epoch,
            wrapped.id.clone(),
            cgka_traits::engine::CommitOrderingKey::from_commit_bytes(
                pre_commit_epoch,
                commit_priority,
                self.identity.self_id().clone(),
                &commit_bytes,
            ),
            recovery_snapshot,
        );
        pending_commit_guard.disarm();

        let _ = upgradeable;
        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending: pending_ref,
        })
    }
}
