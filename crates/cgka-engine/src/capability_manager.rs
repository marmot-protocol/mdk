//! CapabilityManager — `feature_status` + per-member capability cache.
//!
//! ## How this cache is populated
//!
//! `LeafNode::capabilities()` has been public since OpenMLS 0.7, but
//! `MlsGroup::public_group()` itself is `pub(crate)` in OpenMLS 0.8.1.
//! `MlsGroup::members()` returns `Member` records that omit capabilities.
//! The engine therefore cannot read another member's capabilities from a live
//! `MlsGroup` via public API. The cache is required for correctness, not just
//! speed.
//!
//! Cache population uses only public APIs:
//!
//! - **Self** via [`MlsGroup::own_leaf_node`] — call after create / join /
//!   any commit that updates our leaf.
//! - **Other members added by us (create_group, invite)** — we already
//!   parsed their KeyPackages for the capability-enforcement check, so we
//!   cache from `capabilities_of_key_package` on that path.
//! - **Other members added by someone else (we ingested their commit)** —
//!   the commit's `StagedCommit::add_proposals()` carries each new member's
//!   KeyPackage; we cache from there during `ingest_group_message`.
//!
//! Self-welcome recipients get **self** only until subsequent commits bring
//! them reads of other KeyPackages. For "is feature Required" queries, MLS's
//! own RequiredCapabilities invariant is authoritative regardless.

use crate::capabilities::{capabilities_of_key_package, capabilities_of_leaf};
use crate::engine::Engine;
use cgka_traits::capabilities::{Feature, FeatureStatus, GroupCapabilities, RequirementLevel};
use cgka_traits::error::EngineError;
use cgka_traits::group::Member as MarmotMember;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{GroupId, MemberId};
use openmls::extensions::Extension;
use openmls::group::{MlsGroup, StagedCommit};
use openmls::prelude::{BasicCredential, KeyPackage};
use openmls_traits::types::Ciphersuite;

/// Cache self's capabilities from the local `MlsGroup`. Called after any
/// membership change since our own leaf might get updated (e.g. on
/// `add_members` with `force_self_update=true`).
///
/// Cross-checks the OpenMLS-reported leaf credential against the engine's
/// declared `self_id`. A mismatch is a structural bug (the engine and
/// OpenMLS disagree about who "we" are inside the group) and is surfaced
/// as `EngineError::Backend` rather than silently caching under a wrong
/// member id.
pub(crate) fn cache_self_capabilities<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    mls_group: &MlsGroup,
    self_id: &MemberId,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    if let Some(leaf) = mls_group.own_leaf_node() {
        crate::account_identity_proof::validate_leaf_account_identity_proof(leaf, ciphersuite)?;
        let caps = capabilities_of_leaf(leaf);
        let bc = BasicCredential::try_from(leaf.credential().clone())
            .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
        let leaf_id = MemberId::new(bc.identity().to_vec());
        if &leaf_id != self_id {
            return Err(EngineError::Backend(
                "own_leaf_node identity does not match engine self_id".into(),
            ));
        }
        let member = MarmotMember {
            id: leaf_id,
            credential: vec![],
        };
        storage.save_member_capabilities(group_id, &member, caps)?;
    }
    Ok(())
}

/// Cache capabilities extracted from a validated invitee's KeyPackage.
/// Called from create_group / invite paths after capability-check passes.
pub(crate) fn cache_from_key_packages<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    kps: &[KeyPackage],
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    for kp in kps {
        crate::account_identity_proof::validate_leaf_account_identity_proof(
            kp.leaf_node(),
            ciphersuite,
        )?;
        let caps = capabilities_of_key_package(kp);
        let bc = BasicCredential::try_from(kp.leaf_node().credential().clone())
            .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
        let member = MarmotMember {
            id: MemberId::new(bc.identity().to_vec()),
            credential: vec![],
        };
        storage.save_member_capabilities(group_id, &member, caps)?;
    }
    Ok(())
}

/// Cache capabilities for members added by an ingested commit. The
/// `StagedCommit::add_proposals()` path exposes each new member's KeyPackage
/// before merge_staged_commit consumes the staged commit.
pub(crate) fn cache_from_staged_commit<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    staged: &StagedCommit,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    for add in staged.add_proposals() {
        let kp = add.add_proposal().key_package();
        crate::account_identity_proof::validate_leaf_account_identity_proof(
            kp.leaf_node(),
            ciphersuite,
        )?;
        let caps = capabilities_of_key_package(kp);
        let bc = BasicCredential::try_from(kp.leaf_node().credential().clone())
            .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
        let member = MarmotMember {
            id: MemberId::new(bc.identity().to_vec()),
            credential: vec![],
        };
        storage.save_member_capabilities(group_id, &member, caps)?;
    }
    Ok(())
}

/// Read `RequiredCapabilities` from the MLS group's extensions and convert
/// to a Marmot `GroupCapabilities`. Returns default (empty) if no RC ext is
/// set.
pub(crate) fn required_capabilities_from_group(mls_group: &MlsGroup) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for ext in mls_group.extensions().iter() {
        if let Extension::RequiredCapabilities(rc) = ext {
            for t in rc.extension_types() {
                out.extensions.insert(u16::from(*t));
            }
            for t in rc.proposal_types() {
                out.proposals.insert(u16::from(*t));
            }
        }
    }
    if let Ok(components) = crate::app_components::required_app_components_of_group(mls_group) {
        out.app_components = components;
    }
    out
}

impl<S: StorageProvider> Engine<S> {
    pub(crate) fn do_feature_status(
        &self,
        group_id: &GroupId,
        feature: &Feature,
    ) -> Result<FeatureStatus, EngineError> {
        let req = self
            .registry
            .get(feature)
            .ok_or_else(|| EngineError::Other(format!("unknown feature {feature}")))?;
        let required_cap = req.requires;

        // Load the MLS group to read live RequiredCapabilities.
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = match MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                &provider,
            ),
            &mls_gid,
        ) {
            Ok(Some(g)) => g,
            Ok(None) => return Err(EngineError::UnknownGroup(group_id.clone())),
            Err(e) => return Err(EngineError::Backend(format!("load: {e:?}"))),
        };

        // If the capability is in the group's RequiredCapabilities, MLS
        // guarantees every current member supports it. Available.
        let required = required_capabilities_from_group(&mls_group);
        if required.contains(&required_cap) {
            return Ok(FeatureStatus::Available);
        }

        // Non-required: walk members via cache. If every member supports the
        // capability, the group could be upgraded to require it. If any
        // member is missing, the feature is unavailable and we name the
        // gap.
        let group_record = self.storage.get_group(group_id)?;
        let mut any_missing = false;
        for member in &group_record.members {
            let caps = self
                .storage
                .member_capabilities(group_id, &member.id)?
                .unwrap_or_default();
            if !caps.contains(&required_cap) {
                any_missing = true;
                break;
            }
        }

        if any_missing {
            let mut missing = GroupCapabilities::default();
            missing.insert(required_cap);
            Ok(FeatureStatus::Unavailable { missing })
        } else {
            Ok(FeatureStatus::Upgradeable)
        }
    }

    pub(crate) fn do_upgradeable_capabilities(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupCapabilities, EngineError> {
        let provider = crate::provider::EngineOpenMlsProvider::<S>::new(
            &self.crypto,
            self.storage.mls_storage(),
        );
        let mls_gid = openmls::group::GroupId::from_slice(group_id.as_slice());
        let mls_group = match MlsGroup::load(
            <crate::provider::EngineOpenMlsProvider<'_, S> as openmls_traits::OpenMlsProvider>::storage(
                &provider,
            ),
            &mls_gid,
        ) {
            Ok(Some(g)) => g,
            Ok(None) => return Err(EngineError::UnknownGroup(group_id.clone())),
            Err(e) => return Err(EngineError::Backend(format!("load: {e:?}"))),
        };
        let already_required = required_capabilities_from_group(&mls_group);
        let group_record = self.storage.get_group(group_id)?;

        let mut upgradeable = GroupCapabilities::default();
        for (_feat, spec) in self.registry.iter() {
            let cap = spec.requires;
            // Skip transport-required and already-required capabilities.
            if let RequirementLevel::TransportRequired { .. } = spec.level {
                continue;
            }
            if already_required.contains(&cap) {
                continue;
            }
            // Check every member supports.
            let mut all_ok = true;
            for member in &group_record.members {
                let caps = self
                    .storage
                    .member_capabilities(group_id, &member.id)?
                    .unwrap_or_default();
                if !caps.contains(&cap) {
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                upgradeable.insert(cap);
            }
        }
        Ok(upgradeable)
    }
}
