//! `upgrade_group_capabilities` — produces a `GroupContextExtensions`
//! commit that promotes every currently-upgradeable capability into the
//! group's `RequiredCapabilities`.
//!
//! Mirrors `do_send_invite`'s shape (parse, stage GCE commit, wrap with
//! pre-stage exporter, transition to `PendingPublish`, return
//! `GroupEvolution`). Publish-before-apply defers merge and Marmot record
//! updates to `do_confirm_published`.

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId};
use openmls::extensions::{Extension, Extensions, RequiredCapabilitiesExtension};
use openmls::group::MlsGroup;
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
        crate::group_data::require_admin(&mls_group, group_id, self.identity.self_id())?;

        // Compute upgradeable capabilities only after the admin gate so
        // non-admin callers get the policy error instead of a cache-shaped
        // "nothing to upgrade" result.
        let upgradeable = self.do_upgradeable_capabilities(group_id)?;
        if upgradeable.is_empty() {
            return Err(EngineError::Other(
                "no upgradeable capabilities to apply".into(),
            ));
        }

        // Build new RequiredCapabilities = existing ∪ upgradeable.
        let mut req_exts: Vec<u16> = Vec::new();
        let mut req_props: Vec<u16> = Vec::new();
        for ext in mls_group.extensions().iter() {
            if let Extension::RequiredCapabilities(rc) = ext {
                for t in rc.extension_types() {
                    if let ExtensionType::Unknown(n) = t {
                        req_exts.push(*n);
                    }
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
        let new_rc = RequiredCapabilitiesExtension::new(
            &req_exts
                .iter()
                .copied()
                .map(ExtensionType::Unknown)
                .collect::<Vec<_>>(),
            &req_props
                .iter()
                .copied()
                .map(ProposalType::from)
                .collect::<Vec<_>>(),
            &[],
        );

        // Replace the RequiredCapabilities ext in the existing extension set.
        let mut new_ext_vec: Vec<Extension> = mls_group
            .extensions()
            .iter()
            .filter(|e| !matches!(e, Extension::RequiredCapabilities(_)))
            .cloned()
            .collect();
        new_ext_vec.push(Extension::RequiredCapabilities(new_rc));
        let new_extensions = Extensions::from_vec(new_ext_vec)
            .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?;

        // Fork-detection bookkeeping.
        let pre_commit_epoch = EpochId(mls_group.epoch().as_u64());
        let recovery_snapshot =
            self.fork_recovery
                .create_snapshot(&self.storage, group_id, pre_commit_epoch)?;
        self.epoch_manager
            .record_committed_from(group_id, pre_commit_epoch);
        let pre_commit_ctx =
            crate::group_lifecycle::build_group_context_snapshot(&mls_group, &provider)?;

        // Produce + stage the GCE commit. Under publish-before-apply we
        // do NOT call `merge_pending_commit` here — the merge + Marmot
        // record's `required_capabilities` update both defer to
        // `do_confirm_published` (which reads the new RequiredCapabilities
        // off the post-merge group context and mirrors it).
        let (commit_out, _welcome_opt, _gi) = mls_group
            .update_group_context_extensions(&provider, new_extensions, &self.identity.signer)
            .map_err(|e| EngineError::Backend(format!("update_gce: {e:?}")))?;
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
                transport_group_id: group_id.as_slice().to_vec(),
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
        let new_epoch = EpochId(pre_commit_epoch.0 + 1);
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

        let _ = upgradeable;
        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending: pending_ref,
        })
    }
}
