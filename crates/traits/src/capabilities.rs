//! Capability negotiation types.
//!
//! A `Feature` (user-facing concept, e.g. `SelfRemove`) maps to exactly one
//! `Capability` (MLS primitive — a proposal type or extension type). The
//! `FeatureRegistry` is a flat map of features to specs; a group's
//! `RequiredCapabilities` is the union of its active features' capabilities.
//!
//! See `docs/marmot-architecture/further-context/capability-negotiation.md`
//! for the full design rationale. The one-capability-per-feature rule is
//! deliberate: it avoids dependency graphs and keeps `feature_status()` a
//! flat lookup.

use crate::app_components::{AppComponentId, AppComponentSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// One MLS primitive required by a feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    /// A custom proposal type (`ProposalType::Custom(u16)`).
    Proposal(u16),
    /// A custom extension type (`ExtensionType::Unknown(u16)`).
    Extension(u16),
    /// A Marmot MLS app component id carried in `app_data_dictionary`.
    AppComponent(AppComponentId),
}

/// Stable, opaque identifier for a feature. Callers construct these as
/// constants at registry population time.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Feature(pub &'static str);

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// How strictly a feature is required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequirementLevel {
    /// Must be in `RequiredCapabilities` for all group members. New members
    /// cannot join without advertising the backing capability.
    Required,
    /// Group uses the feature if all current members happen to support it.
    /// New members who don't support it can still join (feature degrades to
    /// unavailable for them; see `FeatureStatus`).
    Optional,
    /// Required if and only if a specific transport is active. A group using
    /// Nostr transport requires the Nostr-transport-metadata extension; a
    /// group using both Nostr and FIPS requires both extensions.
    TransportRequired { transport: TransportKind },
}

/// Which transport a `TransportRequired` feature binds to. Named rather than
/// untyped strings so the type system catches typos.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransportKind {
    Nostr,
    Fips,
}

/// What the registry knows about a feature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub requires: Capability,
    pub level: RequirementLevel,
    pub description: &'static str,
}

/// Set of MLS primitives a member or group supports. Sorted sets so equality
/// is order-independent and `Debug` output is deterministic for snapshot tests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupCapabilities {
    pub proposals: BTreeSet<u16>,
    pub extensions: BTreeSet<u16>,
    #[serde(default)]
    pub app_components: AppComponentSet,
}

impl GroupCapabilities {
    pub fn insert(&mut self, cap: Capability) {
        match cap {
            Capability::Proposal(p) => {
                self.proposals.insert(p);
            }
            Capability::Extension(e) => {
                self.extensions.insert(e);
            }
            Capability::AppComponent(id) => {
                self.app_components.insert(id);
            }
        }
    }

    pub fn contains(&self, cap: &Capability) -> bool {
        match cap {
            Capability::Proposal(p) => self.proposals.contains(p),
            Capability::Extension(e) => self.extensions.contains(e),
            Capability::AppComponent(id) => self.app_components.contains(*id),
        }
    }

    /// Capabilities present in `self` but missing from `other`.
    pub fn missing_from(&self, other: &Self) -> Self {
        Self {
            proposals: self
                .proposals
                .difference(&other.proposals)
                .copied()
                .collect(),
            extensions: self
                .extensions
                .difference(&other.extensions)
                .copied()
                .collect(),
            app_components: self.app_components.missing_from(&other.app_components),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.proposals.is_empty() && self.extensions.is_empty() && self.app_components.is_empty()
    }
}

/// Per-group, per-feature status. Consumed by `CgkaEngine::feature_status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeatureStatus {
    /// Feature is in the group's `RequiredCapabilities` — MLS guarantees every
    /// member supports it.
    Available,
    /// Every current member's KeyPackage advertises the capability, but it is
    /// not yet in `RequiredCapabilities`. Can be upgraded via
    /// `upgrade_group_capabilities`.
    Upgradeable,
    /// At least one current member does not advertise the capability. Names
    /// the missing pieces so the UI can show "waiting on member X".
    Unavailable { missing: GroupCapabilities },
}
