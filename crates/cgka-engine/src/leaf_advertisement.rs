//! What this device's own leaf advertises, and refreshing it.
//!
//! A LeafNode's `app_components` support list only changes when the member
//! replaces its leaf, so a leaf keeps whatever its KeyPackage advertised unless
//! something refreshes it. Without a refresh, an existing group can never
//! become eligible to require a component added after the member joined (spec
//! `app-components/README.md`, "Enabling a Component in an Existing Group").
//!
//! - [`own_leaf_refresh_extensions`]: the replacement extensions a self-update
//!   uses to re-advertise every supported component.
//! - [`Engine::own_leaf_missing_app_components`]: whether a self-update would
//!   refresh the leaf. Account maintenance schedules the randomized refresh.
//! - [`Engine::app_component_support_blockers`]: which members' leaves do not
//!   advertise a component yet, i.e. what keeps a group from being eligible.
//!
//! Activating a component (requiring it in GroupContext) is not here; it lands
//! with its first caller.

use std::collections::BTreeSet;

use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentId, AppComponentSet, encode_components_list,
};
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
    /// not advertise yet. Non-empty exactly when a self-update would change the
    /// leaf: a leaf [`own_leaf_refresh_extensions`] cannot refresh (no
    /// `app_data_dictionary`) reports nothing missing, so maintenance never
    /// schedules a refresh that would leave it stale again.
    pub fn own_leaf_missing_app_components(
        &self,
        group_id: &GroupId,
    ) -> Result<AppComponentSet, EngineError> {
        let mls_group = self.load_live_mls_group(group_id)?;
        let leaf = mls_group
            .own_leaf_node()
            .ok_or_else(|| EngineError::Backend("group has no local leaf".into()))?;
        if own_leaf_refresh_extensions(leaf, &self.supported_app_components)?.is_none() {
            return Ok(AppComponentSet::default());
        }
        let advertised = crate::app_components::app_components_of_leaf(leaf)?;
        Ok(self.supported_app_components.missing_from(&advertised))
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
}
