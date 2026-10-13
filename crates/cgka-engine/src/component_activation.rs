//! Enabling an app component in a group that predates it.
//!
//! Spec: `app-components/README.md`, "Enabling a Component in an Existing
//! Group". The process has three steps, and this module owns the engine side
//! of each:
//!
//! 1. **Advertise.** A self-update re-advertises every component this device
//!    supports in its own leaf ([`own_leaf_refresh_extensions`]). KeyPackage
//!    replacement on a changed supported set lives above the engine.
//! 2. **Eligible.** Every leaf in the current state advertises the component
//!    ([`crate::app_components::app_component_support_blockers`]).
//! 3. **Activate.** One admin Commit installs the component's initial state and
//!    adds it to the required `app_components` list
//!    ([`Engine::do_activate_app_components`]). The required list is computed
//!    here, at preparation time, so a queued activation can never drop a
//!    requirement another Commit added meanwhile.
//!
//! Scheduling (the randomized refresh window, when an admin device commits an
//! automatic activation) belongs to account maintenance, not the engine.

use std::collections::BTreeSet;

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, ActivatableAppComponent, AppComponentData, AppComponentId,
    AppComponentSet, ComponentActivationMode, encode_components_list,
};
use cgka_traits::engine::SendResult;
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::extensions::{AppDataDictionaryExtension, Extension, Extensions};
use openmls::group::MlsGroup;
use openmls::prelude::LeafNode;
use openmls_traits::OpenMlsProvider as _;

/// Replacement extensions for this device's own leaf when it advertises fewer
/// component ids than the device supports, or `None` when nothing is missing.
///
/// Every extension and every other dictionary entry, including the account
/// identity proof, is copied unchanged; only the `app_components` support list
/// grows. The list is the union of what the leaf already advertises and the
/// supported set, so a refresh never withdraws support the group may require.
pub(crate) fn own_leaf_refresh_extensions(
    leaf: &LeafNode,
    supported: &AppComponentSet,
) -> Result<Option<Extensions<LeafNode>>, EngineError> {
    let advertised = crate::app_components::app_components_of_leaf(leaf)?;
    if supported.missing_from(&advertised).is_empty() {
        return Ok(None);
    }
    let mut merged: BTreeSet<AppComponentId> = advertised.ids;
    merged.extend(supported.ids.iter().copied());
    merged.insert(APP_COMPONENTS_COMPONENT_ID);

    let mut saw_dictionary = false;
    let mut extensions = Vec::new();
    for extension in leaf.extensions().iter() {
        match extension {
            Extension::AppDataDictionary(existing) => {
                saw_dictionary = true;
                let mut dictionary = existing.dictionary().clone();
                dictionary.insert(APP_COMPONENTS_COMPONENT_ID, encode_components_list(&merged));
                extensions.push(Extension::AppDataDictionary(
                    AppDataDictionaryExtension::new(dictionary),
                ));
            }
            other => extensions.push(other.clone()),
        }
    }
    if !saw_dictionary {
        // A leaf with no dictionary cannot carry the identity proof, so it is
        // not a current-profile leaf; leave it for the profile checks.
        return Ok(None);
    }
    Extensions::from_vec(extensions)
        .map(Some)
        .map_err(|error| EngineError::Backend(format!("refreshed leaf extensions: {error:?}")))
}

impl<S: StorageProvider> Engine<S> {
    fn load_live_mls_group(&self, group_id: &GroupId) -> Result<MlsGroup, EngineError> {
        self.ensure_group_live(group_id)?;
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))
    }

    /// Component ids this device supports that its own leaf in `group_id` does
    /// not advertise yet. Non-empty means a self-update would refresh the leaf.
    pub fn own_leaf_missing_app_components(
        &self,
        group_id: &GroupId,
    ) -> Result<AppComponentSet, EngineError> {
        let mls_group = self.load_live_mls_group(group_id)?;
        let leaf = mls_group
            .own_leaf_node()
            .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?;
        let advertised = crate::app_components::app_components_of_leaf(leaf)?;
        Ok(self.supported_app_components.missing_from(&advertised))
    }

    /// Automatic-mode components this device may activate in `group_id` now:
    /// configured, not yet required, advertised by every current leaf, and
    /// this device is an active admin. Advisory; activation re-checks all of
    /// it when the Commit is prepared.
    pub fn auto_activatable_app_components(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<AppComponentId>, EngineError> {
        if !self
            .activatable_app_components
            .iter()
            .any(|component| component.mode == ComponentActivationMode::Automatic)
        {
            return Ok(Vec::new());
        }
        let mls_group = self.load_live_mls_group(group_id)?;
        if crate::app_components::require_admin(&mls_group, group_id, self.identity.self_id())
            .is_err()
        {
            return Ok(Vec::new());
        }
        let required = crate::app_components::required_app_components_of_group(&mls_group)?;
        let mut eligible = Vec::new();
        for component in &self.activatable_app_components {
            if component.mode != ComponentActivationMode::Automatic
                || required.contains(component.component_id)
            {
                continue;
            }
            if crate::app_components::app_component_support_blockers(
                &mls_group,
                component.component_id,
            )?
            .is_empty()
            {
                eligible.push(component.component_id);
            }
        }
        Ok(eligible)
    }

    /// Account identifiers whose leaves do not advertise `component_id` yet.
    /// Empty means the group is eligible to require it.
    pub fn app_component_support_blockers(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<Vec<cgka_traits::MemberId>, EngineError> {
        let mls_group = self.load_live_mls_group(group_id)?;
        crate::app_components::app_component_support_blockers(&mls_group, component_id)
    }

    fn activatable_component(
        &self,
        group_id: &GroupId,
        component_id: AppComponentId,
    ) -> Result<&ActivatableAppComponent, EngineError> {
        self.activatable_app_components
            .iter()
            .find(|component| component.component_id == component_id)
            .ok_or_else(|| EngineError::AppComponentNotActivatable {
                group_id: group_id.clone(),
                component_id,
            })
    }

    pub(crate) async fn do_activate_app_components(
        &mut self,
        group_id: GroupId,
        component_ids: Vec<AppComponentId>,
    ) -> Result<SendResult, EngineError> {
        let provider = EngineOpenMlsProvider::<S>::new(&self.crypto, self.storage.mls_storage());
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = MlsGroup::load(provider.storage(), &mls_gid)
            .map_err(|error| EngineError::Backend(format!("load: {error:?}")))?
            .ok_or_else(|| EngineError::UnknownGroup(group_id.clone()))?;
        crate::app_components::require_admin(&mls_group, &group_id, self.identity.self_id())?;

        let mut required = crate::app_components::required_app_components_of_group(&mls_group)?;
        let mut state_updates = Vec::new();
        let mut activated = false;
        for component_id in component_ids.into_iter().collect::<BTreeSet<_>>() {
            if required.contains(component_id) {
                continue;
            }
            let component = self.activatable_component(&group_id, component_id)?;
            let members =
                crate::app_components::app_component_support_blockers(&mls_group, component_id)?;
            if !members.is_empty() {
                return Err(EngineError::AppComponentUnsupportedMembers {
                    group_id,
                    component_id,
                    members,
                });
            }
            if crate::app_components::app_component_data_of_group(&mls_group, component_id)
                .is_none()
            {
                state_updates.push(AppComponentData {
                    component_id,
                    data: component.initial_state.clone(),
                });
            }
            required.insert(component_id);
            activated = true;
        }
        if !activated {
            return Ok(SendResult::NoChange { group_id });
        }

        let mut updates = vec![AppComponentData {
            component_id: APP_COMPONENTS_COMPONENT_ID,
            data: encode_components_list(&required.ids),
        }];
        updates.extend(state_updates);
        self.do_send_update_app_components(group_id, updates).await
    }
}
