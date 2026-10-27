//! CapabilityManager — `feature_status` and `upgradeable_capabilities`.
//!
//! Both answers read every current leaf's capabilities from the MLS tree
//! (`MlsGroup::export_ratchet_tree`). Members support a capability only when
//! every leaf advertises it, so each device of an account counts on its own,
//! and every member computes the same answer from authenticated state
//! (app-components/README.md, "Eligibility"). While an own commit is pending,
//! the leaves it adds count too, as in the projected roster `members()`
//! reports.
//!
//! The module also holds the own-leaf and added-leaf profile checks that the
//! create, invite, join and apply paths run before they persist state.

use crate::capabilities::capabilities_of_leaf;
use crate::engine::Engine;
use cgka_traits::capabilities::{
    Capability, Feature, FeatureStatus, GroupCapabilities, RequirementLevel,
};
use cgka_traits::error::EngineError;
use cgka_traits::storage::StorageProvider;
use cgka_traits::types::{GroupId, MemberId};
use openmls::extensions::Extension;
use openmls::group::{MlsGroup, StagedCommit};
use openmls::prelude::{BasicCredential, KeyPackage};
use openmls_traits::types::Ciphersuite;

/// Check the own leaf after create, join or any commit that may replace it
/// (e.g. `add_members` with `force_self_update=true`): its proof profile
/// must match the group's.
///
/// Also cross-checks the OpenMLS-reported leaf credential against the
/// engine's declared `self_id`. A mismatch is a structural bug (the engine
/// and OpenMLS disagree about who "we" are inside the group) and is surfaced
/// as `EngineError::Backend`.
pub(crate) fn check_own_leaf(
    mls_group: &MlsGroup,
    self_id: &MemberId,
    ciphersuite: Ciphersuite,
) -> Result<(), EngineError> {
    if let Some(leaf) = mls_group.own_leaf_node() {
        let leaf_profile =
            crate::account_identity_proof::validate_leaf_account_identity_proof(leaf, ciphersuite)?;
        let group_profile = crate::account_identity_proof::protocol_profile_of_group(mls_group)?;
        if leaf_profile != group_profile {
            return Err(EngineError::InvalidAccountIdentityProof(
                "own leaf proof profile does not match group profile".into(),
            ));
        }
        let bc = BasicCredential::try_from(leaf.credential().clone())
            .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
        if &MemberId::new(bc.identity().to_vec()) != self_id {
            return Err(EngineError::Backend(
                "own_leaf_node identity does not match engine self_id".into(),
            ));
        }
    }
    Ok(())
}

/// Replay-side own-leaf check when the caller has only the materialized
/// OpenMLS group, not the engine's declared identity.
///
/// The own leaf still carries the authenticated Marmot credential identity;
/// derive that identity and route through [`check_own_leaf`] so replay
/// performs the same proof/profile validation as direct ingest.
pub(crate) fn check_own_leaf_of_group(mls_group: &MlsGroup) -> Result<(), EngineError> {
    let Some(leaf) = mls_group.own_leaf_node() else {
        return Ok(());
    };
    let credential = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|e| EngineError::Backend(format!("credential: {e:?}")))?;
    let self_id = MemberId::new(credential.identity().to_vec());
    check_own_leaf(mls_group, &self_id, mls_group.ciphersuite())
}

/// Check that every validated invitee KeyPackage carries a proof of the
/// persisted group's profile. Called from create_group / invite paths after
/// the capability check passes.
pub(crate) fn check_key_package_profiles<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    kps: &[KeyPackage],
) -> Result<(), EngineError> {
    let group_profile = storage.get_group(group_id)?.protocol_profile;
    for kp in kps {
        let leaf_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
            kp.leaf_node(),
            kp.ciphersuite(),
        )?;
        if leaf_profile != group_profile {
            return Err(EngineError::InvalidAccountIdentityProof(
                "KeyPackage proof profile does not match group profile".into(),
            ));
        }
    }
    Ok(())
}

/// Check that every leaf a staged commit adds carries a proof of the
/// persisted group's profile, before `merge_staged_commit` consumes it.
pub(crate) fn check_added_leaf_profiles<S: StorageProvider>(
    storage: &S,
    group_id: &GroupId,
    staged: &StagedCommit,
) -> Result<(), EngineError> {
    let group_profile = storage.get_group(group_id)?.protocol_profile;
    for add in staged.add_proposals() {
        let kp = add.add_proposal().key_package();
        let leaf_profile = crate::account_identity_proof::validate_leaf_account_identity_proof(
            kp.leaf_node(),
            kp.ciphersuite(),
        )?;
        if leaf_profile != group_profile {
            return Err(EngineError::InvalidAccountIdentityProof(
                "added leaf proof profile does not match group profile".into(),
            ));
        }
    }
    Ok(())
}

/// The capabilities of every leaf the answers below count: each current leaf
/// of the tree, then each leaf a pending own commit adds. Leaves the pending
/// commit removes still count, as they do in `members()` until it merges.
fn leaf_capabilities_of_group(mls_group: &MlsGroup) -> Result<Vec<GroupCapabilities>, EngineError> {
    let mut leaves = crate::app_components::ratchet_tree_leaves(mls_group.export_ratchet_tree())?
        .iter()
        .map(capabilities_of_leaf)
        .collect::<Vec<_>>();
    if let Some(staged) = mls_group.pending_commit() {
        leaves.extend(
            staged
                .add_proposals()
                .map(|add| capabilities_of_leaf(add.add_proposal().key_package().leaf_node())),
        );
    }
    Ok(leaves)
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

/// Per-member role capabilities a group requires because it carries the
/// agent-text-stream-QUIC (`0x8006`) component with a non-empty
/// `required_member_roles` mask.
///
/// `spec/app-components/agent-text-stream-quic-v1.md` requires every member to
/// advertise each role capability named by `required_member_roles`. This reads
/// the component bytes from the live group and maps the mask to its role
/// capabilities (`cgka_traits::agent_text_stream::required_role_capabilities`).
/// Empty when the component is absent or the mask requires no roles. Returns
/// `GroupCapabilities` so callers reuse the same `missing_from` check used for
/// required components.
pub(crate) fn required_role_capabilities_from_group(mls_group: &MlsGroup) -> GroupCapabilities {
    let Some(bytes) = crate::app_components::app_component_data_of_group(
        mls_group,
        cgka_traits::app_components::AGENT_TEXT_STREAM_QUIC_COMPONENT_ID,
    ) else {
        return GroupCapabilities::default();
    };
    let Ok(policy) =
        cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1::decode_component_state(&bytes)
    else {
        // A malformed component is rejected elsewhere (component validation);
        // surface no role requirement here rather than guessing a mask.
        return GroupCapabilities::default();
    };
    cgka_traits::agent_text_stream::required_role_capabilities(policy.required_member_roles)
}

/// Per-member role capabilities demanded by an agent-text-stream-QUIC (`0x8006`)
/// component supplied in a `create_group` request, before the group exists.
/// Mirrors [`required_role_capabilities_from_group`] but reads the policy bytes
/// from the request's component list (#177). Empty when the component is absent.
pub(crate) fn required_role_capabilities_from_request_components(
    components: &[cgka_traits::app_components::AppComponentData],
) -> GroupCapabilities {
    let Some(component) = components.iter().find(|component| {
        component.component_id == cgka_traits::app_components::AGENT_TEXT_STREAM_QUIC_COMPONENT_ID
    }) else {
        return GroupCapabilities::default();
    };
    let Ok(policy) =
        cgka_traits::agent_text_stream::AgentTextStreamQuicPolicyV1::decode_component_state(
            &component.data,
        )
    else {
        return GroupCapabilities::default();
    };
    cgka_traits::agent_text_stream::required_role_capabilities(policy.required_member_roles)
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

        // Non-required: if every leaf supports the capability, the group
        // could be upgraded to require it. If any leaf lacks it, the feature
        // is unavailable and we name the gap.
        let leaves = leaf_capabilities_of_group(&mls_group)?;
        if leaves.iter().all(|caps| caps.contains(&required_cap)) {
            Ok(FeatureStatus::Upgradeable)
        } else {
            let mut missing = GroupCapabilities::default();
            missing.insert(required_cap);
            Ok(FeatureStatus::Unavailable { missing })
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
        let leaves = leaf_capabilities_of_group(&mls_group)?;

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
            // Requiring account-devices is an explicit admin decision that a
            // group can never undo (account-devices-v1.md, "Activation in an
            // existing group"), so an upgrade never adds it by itself.
            if cap
                == Capability::AppComponent(
                    cgka_traits::app_components::ACCOUNT_DEVICES_COMPONENT_ID,
                )
            {
                continue;
            }
            if leaves.iter().all(|caps| caps.contains(&cap)) {
                upgradeable.insert(cap);
            }
        }
        Ok(upgradeable)
    }
}

/// Fold every capability in `extra` into `required` (set union). Used to add the
/// agent-stream `required_member_roles` role capabilities to a group's required
/// capability set before the per-KeyPackage invite check and the join-time
/// self-check (#177).
pub(crate) fn merge_capabilities(
    required: &mut cgka_traits::capabilities::GroupCapabilities,
    extra: &cgka_traits::capabilities::GroupCapabilities,
) {
    required.proposals.extend(extra.proposals.iter().copied());
    required.extensions.extend(extra.extensions.iter().copied());
    for id in &extra.app_components.ids {
        required.app_components.insert(*id);
    }
}
