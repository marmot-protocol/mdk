//! Capability derivation from the [`FeatureRegistry`] into OpenMLS
//! [`Capabilities`] / [`RequiredCapabilitiesExtension`] shapes.
//!
//! The engine is the one place that speaks both Marmot-capability vocabulary
//! (Feature / Capability / RequirementLevel) AND OpenMLS vocabulary
//! (ExtensionType / ProposalType). This module is the translator.

use crate::feature_registry::FeatureRegistry;
use cgka_traits::app_components::AppComponentSet;
use cgka_traits::capabilities::{
    Capability as CTCapability, Feature, GroupCapabilities, RequirementLevel, TransportKind,
};
use cgka_traits::error::EngineError;
use openmls::extensions::RequiredCapabilitiesExtension;
use openmls::prelude::{Capabilities, ExtensionType, ProposalType};
use openmls_traits::types::Ciphersuite;

/// Derive the per-leaf `Capabilities` this client advertises. Includes every
/// feature in the registry regardless of level — that's what "I support this"
/// means at the leaf.
pub(crate) fn leaf_capabilities(
    registry: &FeatureRegistry,
    ciphersuite: Ciphersuite,
) -> Capabilities {
    let mut ext_types: Vec<ExtensionType> = vec![
        ExtensionType::RequiredCapabilities,
        ExtensionType::AppDataDictionary,
        ExtensionType::LastResort,
        crate::account_identity_proof::account_identity_proof_capability(),
    ];
    let mut proposal_types: Vec<ProposalType> = vec![ProposalType::AppDataUpdate];

    for (_feat, req) in registry.iter() {
        match req.requires {
            CTCapability::Extension(t) => ext_types.push(ExtensionType::from(t)),
            CTCapability::Proposal(t) => proposal_types.push(ProposalType::from(t)),
            CTCapability::AppComponent(_) => {}
        }
    }
    ext_types.sort();
    ext_types.dedup();
    proposal_types.sort();
    proposal_types.dedup();

    Capabilities::new(
        None,
        Some(&[ciphersuite]),
        Some(&ext_types),
        Some(&proposal_types),
        None,
    )
}

/// Derive the `RequiredCapabilities` extension for a new group. Includes
/// every `Required` feature + every `TransportRequired` feature whose
/// transport is listed in `active_transports`.
pub(crate) fn required_capabilities_extension(
    registry: &FeatureRegistry,
    active_transports: &[TransportKind],
) -> (GroupCapabilities, RequiredCapabilitiesExtension) {
    let mut caps = GroupCapabilities::default();
    caps.insert(CTCapability::Extension(u16::from(
        ExtensionType::AppDataDictionary,
    )));
    caps.insert(CTCapability::Extension(
        crate::account_identity_proof::ACCOUNT_IDENTITY_PROOF_EXTENSION_TYPE,
    ));
    caps.insert(CTCapability::Proposal(u16::from(
        ProposalType::AppDataUpdate,
    )));
    for (_f, req) in registry.iter() {
        match &req.level {
            RequirementLevel::Required => caps.insert(req.requires),
            RequirementLevel::TransportRequired { transport }
                if active_transports.contains(transport) =>
            {
                caps.insert(req.requires);
            }
            _ => {}
        }
    }

    let ext_types: Vec<ExtensionType> = caps
        .extensions
        .iter()
        .map(|t| ExtensionType::from(*t))
        .collect();
    let proposal_types: Vec<ProposalType> = caps
        .proposals
        .iter()
        .map(|t| ProposalType::from(*t))
        .collect();

    let ext = RequiredCapabilitiesExtension::new(&ext_types, &proposal_types, &[]);
    (caps, ext)
}

/// Derive RequiredCapabilities and additionally force specific caller-
/// requested features to be required for this group, even when their registry
/// level is `Optional`.
pub(crate) fn required_capabilities_extension_for_features(
    registry: &FeatureRegistry,
    active_transports: &[TransportKind],
    requested: &[Feature],
) -> Result<(GroupCapabilities, RequiredCapabilitiesExtension), EngineError> {
    let (mut caps, _) = required_capabilities_extension(registry, active_transports);
    for feature in requested {
        let req = registry
            .get(feature)
            .ok_or_else(|| EngineError::Other(format!("unknown feature {feature}")))?;
        caps.insert(req.requires);
    }
    Ok((caps.clone(), extension_from_group_capabilities(&caps)))
}

pub(crate) fn extension_from_group_capabilities(
    caps: &GroupCapabilities,
) -> RequiredCapabilitiesExtension {
    let ext_types: Vec<ExtensionType> = caps
        .extensions
        .iter()
        .map(|t| ExtensionType::from(*t))
        .collect();
    let proposal_types: Vec<ProposalType> = caps
        .proposals
        .iter()
        .map(|t| ProposalType::from(*t))
        .collect();
    RequiredCapabilitiesExtension::new(&ext_types, &proposal_types, &[])
}

/// Read a KeyPackage's advertised capabilities into a Marmot
/// [`GroupCapabilities`]. Used by `constructable_capabilities` and by the
/// invite-validation path.
pub(crate) fn capabilities_of_key_package(kp: &openmls::prelude::KeyPackage) -> GroupCapabilities {
    capabilities_of_leaf(kp.leaf_node())
}

/// Read a LeafNode's advertised capabilities for constructability checks and
/// cache-on-ingest updates.
pub(crate) fn capabilities_of_leaf(leaf: &openmls::prelude::LeafNode) -> GroupCapabilities {
    let mut out = group_capabilities_from_caps(leaf.capabilities());
    out.app_components = crate::app_components::app_components_of_leaf(leaf)
        .unwrap_or_else(|_| AppComponentSet::default());
    out
}

/// Convert OpenMLS [`Capabilities`] into Marmot [`GroupCapabilities`]
/// (extensions + proposals only; app components are carried separately).
fn group_capabilities_from_caps(caps: &Capabilities) -> GroupCapabilities {
    let mut out = GroupCapabilities::default();
    for ext in caps.extensions() {
        if !ext.is_grease() {
            out.extensions.insert(u16::from(*ext));
        }
    }
    for prop in caps.proposals() {
        out.proposals.insert(u16::from(*prop));
    }
    out
}

/// The full set of capabilities this client supports at runtime: the MLS
/// extensions/proposals it advertises (derived from the feature registry, same
/// as [`leaf_capabilities`]) plus the app components it supports. Used by the
/// join path to reject a Welcome whose group requires capabilities this client
/// cannot apply (joining.md:65, convergence.md:19), independent of what the
/// consumed KeyPackage's leaf happened to advertise.
pub(crate) fn self_supported_capabilities(
    registry: &FeatureRegistry,
    ciphersuite: Ciphersuite,
    supported_app_components: &AppComponentSet,
) -> GroupCapabilities {
    let mut out = group_capabilities_from_caps(&leaf_capabilities(registry, ciphersuite));
    out.app_components = supported_app_components.clone();
    out
}
