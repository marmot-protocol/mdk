//! Explicit activation of the negotiated, irreversible view-once profile.

use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentData, GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID,
    VIEW_ONCE_COMPONENT_ID, encode_components_list,
};
use cgka_traits::error::{EngineError, ViewOnceActivationRefusal};
use cgka_traits::{GroupId, MemberId, StorageProvider};
use openmls::group::MlsGroup;

use crate::engine::Engine;

fn activation_refusal(
    group: &MlsGroup,
    self_id: &MemberId,
) -> Result<Option<ViewOnceActivationRefusal>, EngineError> {
    use ViewOnceActivationRefusal as Refusal;
    let account = crate::app_components::admin_pubkey_from_member_id(self_id)?;
    if !crate::app_components::admins_of_group(group)?.contains(&account) {
        return Ok(Some(Refusal::NotAdmin));
    }
    if crate::account_identity_proof::protocol_profile_of_group(group)?
        == cgka_traits::group::ProtocolProfile::Legacy
    {
        return Ok(Some(Refusal::LegacyProfile));
    }
    let required = crate::app_components::required_app_components_of_group(group)?;
    if required.contains(VIEW_ONCE_COMPONENT_ID) {
        return Ok(Some(Refusal::AlreadyRequired));
    }
    if !required.contains(GROUP_ENCRYPTED_MEDIA_V2_COMPONENT_ID) {
        return Ok(Some(Refusal::EncryptedMediaV2NotRequired));
    }
    for leaf in crate::app_components::ratchet_tree_leaves(group.export_ratchet_tree())? {
        if crate::app_components::carries_view_once_data(leaf.extensions().app_data_dictionary()) {
            return Ok(Some(Refusal::CarriesData));
        }
        if !crate::app_components::app_components_of_leaf(&leaf)?.contains(VIEW_ONCE_COMPONENT_ID) {
            return Ok(Some(Refusal::UnsupportedLeaf));
        }
    }
    Ok(None)
}

fn refusal_error(group_id: GroupId, reason: ViewOnceActivationRefusal) -> EngineError {
    match reason {
        ViewOnceActivationRefusal::NotAdmin => EngineError::NotGroupAdmin { group_id },
        reason => EngineError::ViewOnceActivationRefused { group_id, reason },
    }
}

impl<S: StorageProvider> Engine<S> {
    /// Read only the named authenticated epoch; missing retained state denies access.
    pub fn view_once_required_at(
        &self,
        group_id: &GroupId,
        epoch: cgka_traits::EpochId,
    ) -> Result<bool, EngineError> {
        self.ensure_group_live(group_id)?;
        self.with_mls_group(group_id, |group| {
            Ok(
                source_policy(&self.storage, &self.rewinds, &self.crypto, group, epoch)?
                    .is_some_and(|(required, _)| required),
            )
        })
    }

    /// Advisory eligibility; staging repeats it on the actual parent state.
    pub fn view_once_activation_refusal(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ViewOnceActivationRefusal>, EngineError> {
        self.ensure_group_live(group_id)?;
        self.with_mls_group(group_id, |group| {
            activation_refusal(group, self.identity.self_id())
        })
    }

    pub(crate) fn check_view_once_activation(&self, group_id: &GroupId) -> Result<(), EngineError> {
        match self.view_once_activation_refusal(group_id)? {
            None => Ok(()),
            Some(reason) => Err(refusal_error(group_id.clone(), reason)),
        }
    }

    pub(crate) async fn do_enable_view_once(
        &mut self,
        group_id: GroupId,
    ) -> Result<cgka_traits::SendResult, EngineError> {
        let group = self.load_mls_group(&group_id)?;
        if let Some(reason) = activation_refusal(&group, self.identity.self_id())? {
            return Err(refusal_error(group_id, reason));
        }
        let mut required = crate::app_components::required_app_components_of_group(&group)?;
        required.insert(VIEW_ONCE_COMPONENT_ID);
        let update = AppComponentData {
            component_id: APP_COMPONENTS_COMPONENT_ID,
            data: encode_components_list(&required.ids),
        };
        let removals = if crate::app_components::carries_view_once_data(
            group.extensions().app_data_dictionary(),
        ) {
            vec![VIEW_ONCE_COMPONENT_ID]
        } else {
            Vec::new()
        };
        drop(group);
        self.do_send_app_data_updates(group_id, vec![update], removals)
            .await
    }
}

/// Read negotiation and timer from the same authenticated source-epoch
/// state, restoring the caller's current replay state before returning.
pub(crate) fn source_policy<S: StorageProvider>(
    storage: &S,
    rewinds: &crate::snapshot_guard::Rewinds,
    crypto: &openmls_rust_crypto::RustCrypto,
    group: &MlsGroup,
    source_epoch: cgka_traits::EpochId,
) -> Result<Option<(bool, u64)>, EngineError> {
    let read = |source: &MlsGroup| -> Result<Option<(bool, u64)>, EngineError> {
        Ok(Some((
            crate::app_components::group_requires_view_once(source)?,
            crate::app_components::message_retention_seconds_of_group(source)?.unwrap_or(0),
        )))
    };
    if group.epoch().as_u64() == source_epoch.0 {
        return read(group);
    }
    let group_id = GroupId::new(group.group_id().as_slice().to_vec());
    crate::openmls_projection::with_retained_anchor_group(
        storage,
        rewinds,
        crypto,
        &group_id,
        source_epoch,
        crate::snapshot_guard::RewindSite::RetentionSource,
        &format!("view-once-{}", source_epoch.0),
        |source, _| read(source),
    )
}
