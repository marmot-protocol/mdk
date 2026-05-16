//! `SendIntent::UpdateGroupData` — issues a `GroupContextExtensions` commit
//! that replaces the `marmot_group_data` extension with one whose `name` /
//! `description` fields have been overwritten by the caller's request.
//!
//! Other `marmot_group_data` fields (admins, relays, image_*, etc.) are
//! preserved as-is. Admin set updates and relay updates are out of scope
//! for this intent; admin promotion lives in a follow-on plan and relay
//! configuration is transport-adapter territory.
//!
//! The send path stages a GCE commit with the pre-stage exporter context,
//! enters `PendingPublish`, and defers merge until `do_confirm_published`.
//! Rollback via `do_publish_failed` discards the staged GCE.

use crate::engine::Engine;
use crate::group_data::{NostrGroupData, read_from_group};
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::engine::SendResult;
use cgka_traits::engine_state::{EpochState, StagedCommitHandle};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::transport::{EncryptedPayload, TransportEnvelope, TransportMessage};
use cgka_traits::types::{EpochId, GroupId};
use openmls::extensions::{Extension, Extensions};
use openmls::group::MlsGroup;
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

        if let Some(state) = self.epoch_manager.state(&group_id)
            && !matches!(state, EpochState::Stable { .. })
        {
            return Err(EngineError::InvalidTransition(
                cgka_traits::engine_state::InvalidTransition {
                    from: state.name(),
                    to: "UpdateGroupData",
                    reason: "update_group_data requires Stable",
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
        crate::group_data::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        // Read the existing marmot_group_data extension and overwrite only
        // the requested fields. Everything else (admins, relays, image_*,
        // disappearing_message_secs, version, nostr_group_id) is
        // preserved verbatim.
        let mut data: NostrGroupData = read_from_group(&mls_group)?.ok_or_else(|| {
            EngineError::Backend(
                "UpdateGroupData on a group with no marmot_group_data extension".into(),
            )
        })?;
        if let Some(n) = name {
            data.name = tls_codec::VLBytes::new(n.into_bytes());
        }
        if let Some(d) = description {
            data.description = tls_codec::VLBytes::new(d.into_bytes());
        }
        let new_marmot_ext = data.to_extension()?;

        // Replace ONLY the marmot_group_data extension; preserve every
        // other extension (RequiredCapabilities especially).
        let mut new_ext_vec: Vec<Extension> = mls_group
            .extensions()
            .iter()
            .filter(|e| !is_marmot_group_data(e))
            .cloned()
            .collect();
        new_ext_vec.push(new_marmot_ext);
        let new_extensions = Extensions::from_vec(new_ext_vec)
            .map_err(|e| EngineError::Backend(format!("extensions: {e:?}")))?;

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

        // Stage the GCE commit. Don't merge — confirm path does that.
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
            &group_id,
            pre_commit_epoch,
        )?;

        // Mirror the projected name/description in the Marmot record at
        // send time (rolled back on publish_failed via the stored data
        // re-derive from MLS). The Marmot record's name/description are
        // user-visible fields; they should reflect "what the user just
        // asked for" during PendingPublish.
        if let Ok(mut g) = self.storage.get_group(&group_id) {
            g.name = String::from_utf8_lossy(data.name.as_slice()).into_owned();
            g.description = String::from_utf8_lossy(data.description.as_slice()).into_owned();
            self.storage.put_group(&g)?;
        }

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

        Ok(SendResult::GroupEvolution {
            msg: wrapped,
            welcomes: vec![],
            pending: pending_ref,
        })
    }
}

fn is_marmot_group_data(ext: &Extension) -> bool {
    matches!(
        ext,
        Extension::Unknown(crate::group_data::MARMOT_GROUP_DATA_EXT_TYPE, _)
    )
}
