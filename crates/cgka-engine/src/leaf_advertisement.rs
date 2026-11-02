//! What this device's own leaf advertises, and refreshing it.
//!
//! A LeafNode's `app_components` support list only changes when the member
//! replaces its leaf, so a leaf keeps whatever its KeyPackage advertised unless
//! something refreshes it. Without a refresh, an existing group can never
//! become eligible to require a component added after the member joined (spec
//! `app-components/README.md`, "Enabling a Component in an Existing Group").
//!
//! - [`own_leaf_refresh_extensions`]: the replacement extensions a self-update
//!   uses to re-advertise every supported component and, once this device
//!   can tag, to carry a device tag that reads as its own.
//! - [`Engine::own_leaf_missing_app_components`]: whether a self-update would
//!   refresh the leaf. Account maintenance schedules the randomized refresh.
//! - [`Engine::own_commit_leaf_parameters`]: the UpdatePath leaf of every
//!   other own Commit, which needs a tag the same way (device-tag-v1.md,
//!   "Producing tags").
//! - [`Engine::app_component_support_blockers`]: which members' leaves do not
//!   advertise a component yet, i.e. what keeps a group from being eligible.
//!
//! Activating a component (requiring it in GroupContext) is not here:
//! account-devices activation is `crate::account_devices_activation`.

use std::collections::BTreeSet;

use crate::device_tag::OwnDeviceTag;
use crate::engine::Engine;
use crate::provider::EngineOpenMlsProvider;
use cgka_traits::app_components::{
    APP_COMPONENTS_COMPONENT_ID, AppComponentId, AppComponentSet, DEVICE_TAG_COMPONENT_ID,
    encode_components_list,
};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::GroupId;
use openmls::extensions::{AppDataDictionaryExtension, Extension, Extensions};
use openmls::group::MlsGroup;
use openmls::messages::proposals::Proposal;
use openmls::prelude::{LeafNode, LeafNodeParameters};
use openmls_traits::OpenMlsProvider as _;

/// Replacement extensions for this device's own leaf when it advertises fewer
/// component ids than the device supports or `device_tag` is a tag it needs,
/// or `None` when neither holds.
///
/// Every extension and every other dictionary entry, including the account
/// identity proof, is copied unchanged; only the `app_components` support list
/// grows, and the `0x800f` entry becomes `device_tag`. The list is the union
/// of what the leaf already advertises and the supported set, plus `0x800f`
/// for a tagged leaf, so a refresh never withdraws support the group may
/// require.
pub(crate) fn own_leaf_refresh_extensions(
    leaf: &LeafNode,
    supported: &AppComponentSet,
    device_tag: Option<Vec<u8>>,
) -> Result<Option<Extensions<LeafNode>>, EngineError> {
    let advertised = crate::app_components::app_components_of_leaf(leaf)?;
    if supported.missing_from(&advertised).is_empty() && device_tag.is_none() {
        return Ok(None);
    }
    let mut merged: BTreeSet<AppComponentId> = advertised.ids;
    merged.extend(supported.ids.iter().copied());
    merged.insert(APP_COMPONENTS_COMPONENT_ID);
    if device_tag.is_some() {
        merged.insert(DEVICE_TAG_COMPONENT_ID);
    }

    let mut saw_dictionary = false;
    let mut extensions = Vec::new();
    for extension in leaf.extensions().iter() {
        match extension {
            Extension::AppDataDictionary(existing) => {
                saw_dictionary = true;
                let mut dictionary = existing.dictionary().clone();
                dictionary.insert(APP_COMPONENTS_COMPONENT_ID, encode_components_list(&merged));
                if let Some(tag) = &device_tag {
                    dictionary.insert(DEVICE_TAG_COMPONENT_ID, tag.clone());
                }
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
    /// not advertise yet, plus `0x800f` while the leaf needs a device tag that
    /// reads as its own. Non-empty exactly when a self-update would change the
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
        // An empty stand-in tag is enough to ask whether the leaf can take one.
        let tag_due = self.device_tag_due(&mls_group, &[]).is_some();
        if own_leaf_refresh_extensions(
            leaf,
            &self.supported_app_components,
            tag_due.then(Vec::new),
        )?
        .is_none()
        {
            return Ok(AppComponentSet::default());
        }
        let advertised = crate::app_components::app_components_of_leaf(leaf)?;
        let mut missing = self.supported_app_components.missing_from(&advertised);
        if tag_due {
            missing.insert(DEVICE_TAG_COMPONENT_ID);
        }
        Ok(missing)
    }

    /// The replacement extensions a self-update gives this device's leaf in
    /// `mls_group`, or `None` when the leaf needs nothing.
    pub(crate) fn own_leaf_replacement(
        &self,
        mls_group: &MlsGroup,
    ) -> Result<Option<Extensions<LeafNode>>, EngineError> {
        let due = self.device_tag_due(mls_group, &[]);
        self.replace_own_leaf(mls_group, due)
    }

    /// The UpdatePath leaf parameters of an own Commit other than a
    /// self-update that carries `proposals`. Once this device can tag,
    /// "every LeafNode it creates for its own leaf" carries a tag
    /// (device-tag-v1.md, "Producing tags"). The parameters stay empty, so the
    /// UpdatePath keeps the leaf's extensions and its tag, unless the leaf
    /// needs one. Then they replace the leaf as a self-update would, and force
    /// an UpdatePath into a Commit that would otherwise omit it.
    pub(crate) fn own_commit_leaf_parameters(
        &self,
        mls_group: &MlsGroup,
        proposals: &[Proposal],
    ) -> Result<LeafNodeParameters, EngineError> {
        let Some(due) = self.device_tag_due(mls_group, proposals) else {
            return Ok(LeafNodeParameters::default());
        };
        Ok(self
            .replace_own_leaf(mls_group, Some(due))?
            .map(|extensions| {
                LeafNodeParameters::builder()
                    .with_extensions(extensions)
                    .build()
            })
            .unwrap_or_default())
    }

    fn replace_own_leaf(
        &self,
        mls_group: &MlsGroup,
        due: Option<OwnDeviceTag>,
    ) -> Result<Option<Extensions<LeafNode>>, EngineError> {
        let Some(leaf) = mls_group.own_leaf_node() else {
            return Ok(None);
        };
        let device_tag = due
            .map(|own| own.seal(&self.crypto, &self.identity.signer))
            .transpose()?;
        own_leaf_refresh_extensions(leaf, &self.supported_app_components, device_tag)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_identity_proof::{
        AccountIdentityProofMaterial, account_identity_proof_capability,
    };
    use crate::engine::DEFAULT_CIPHERSUITE;
    use openmls::extensions::{AppDataDictionary, ExtensionType, UnknownExtension};
    use openmls::prelude::{Capabilities, KeyPackage};

    #[test]
    fn refresh_unions_support_and_preserves_every_other_leaf_byte() {
        let engine = crate::distributed_convergence::tests::test_engine();
        let AccountIdentityProofMaterial::LegacyExtension(proof) =
            &engine.identity.account_identity_proof
        else {
            panic!("legacy fixture");
        };
        let old = 0x9101;
        let new = 0x9102;
        let opaque_id = 0x9201;
        let opaque = vec![0, 255, 7, 0];
        let other = Extension::Unknown(0xf123, UnknownExtension(vec![0, 3, 0xff]));
        let mut dictionary = AppDataDictionary::new();
        dictionary.insert(
            APP_COMPONENTS_COMPONENT_ID,
            encode_components_list(&BTreeSet::from([APP_COMPONENTS_COMPONENT_ID, old])),
        );
        dictionary.insert(opaque_id, opaque.clone());
        let make_leaf = |with_dictionary| {
            let mut extensions = vec![proof.clone(), other.clone()];
            if with_dictionary {
                extensions.push(Extension::AppDataDictionary(
                    AppDataDictionaryExtension::new(dictionary.clone()),
                ));
            }
            KeyPackage::builder()
                .leaf_node_capabilities(Capabilities::new(
                    None,
                    Some(&[DEFAULT_CIPHERSUITE]),
                    Some(&[
                        account_identity_proof_capability(),
                        ExtensionType::Unknown(0xf123),
                        ExtensionType::AppDataDictionary,
                    ]),
                    None,
                    None,
                ))
                .leaf_node_extensions(Extensions::from_vec(extensions).unwrap())
                .build(
                    DEFAULT_CIPHERSUITE,
                    &openmls_rust_crypto::OpenMlsRustCrypto::default(),
                    &engine.identity.signer,
                    engine.identity.credential_with_key.clone(),
                )
                .unwrap()
                .key_package()
                .leaf_node()
                .clone()
        };
        let leaf = make_leaf(true);
        crate::account_identity_proof::validate_leaf_account_identity_proof(
            &leaf,
            DEFAULT_CIPHERSUITE,
        )
        .unwrap();
        let tag = vec![4, 0, 0xfe];
        let refreshed =
            own_leaf_refresh_extensions(&leaf, &AppComponentSet::new([new]), Some(tag.clone()))
                .unwrap()
                .unwrap();
        assert_eq!(refreshed.unknown(0xf123), leaf.extensions().unknown(0xf123));
        assert_eq!(refreshed.unknown(0xf2f1), leaf.extensions().unknown(0xf2f1));
        assert_eq!(refreshed.iter().count(), leaf.extensions().iter().count());
        let result = refreshed.app_data_dictionary().unwrap().dictionary();
        assert_eq!(result.len(), 3);
        assert_eq!(result.get(&opaque_id), Some(opaque.as_slice()));
        assert_eq!(result.get(&DEVICE_TAG_COMPONENT_ID), Some(tag.as_slice()));
        assert_eq!(
            result.get(&APP_COMPONENTS_COMPONENT_ID),
            Some(
                encode_components_list(&BTreeSet::from([
                    APP_COMPONENTS_COMPONENT_ID,
                    old,
                    new,
                    DEVICE_TAG_COMPONENT_ID
                ]))
                .as_slice()
            )
        );
        let no_dictionary = make_leaf(false);
        crate::account_identity_proof::validate_leaf_account_identity_proof(
            &no_dictionary,
            DEFAULT_CIPHERSUITE,
        )
        .unwrap();
        assert!(
            own_leaf_refresh_extensions(&no_dictionary, &AppComponentSet::new([new]), Some(tag))
                .unwrap()
                .is_none()
        );
    }
}
