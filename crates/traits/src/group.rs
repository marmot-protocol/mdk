//! `Group` and `Member` records as seen by storage.
//!
//! **Invariant (enforced at trait-definition time):** neither [`Group`] nor
//! [`Member`] contains any transport-layer types. No `nostr_group_id`, no
//! relay URLs, no FIPS mesh ids. That mapping lives in the transport adapter
//! (see `docs/marmot-architecture/further-context/cgka-engine-design.md:247-268`).

use crate::capabilities::GroupCapabilities;
use crate::types::{EpochId, GroupId, MemberId};
use serde::{Deserialize, Serialize};

/// Marmot application-profile generation for a group or KeyPackage.
///
/// This is the strict-cutover classification used for decisions that differ
/// between the deployed legacy application profile and the adopted current
/// profile, including the account-identity-proof carrier, encrypted-media
/// component, and mixed-profile rejection. It does **not** identify which MLS
/// extension carrier encodes application data: legacy-classified state may
/// already use the current `app_data_dictionary` carrier.
///
/// Existing persisted records predate profile classification and therefore
/// deserialize as [`ProtocolProfile::Legacy`]. Current-profile state is always
/// explicit; code must not infer a hybrid profile independently for each
/// application component.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolProfile {
    #[default]
    Legacy,
    Current,
}

/// A group, as storage sees it. Mirrors the engine's view of the group's
/// metadata — not the MLS tree (OpenMLS owns that).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub name: String,
    pub description: String,
    pub epoch: EpochId,
    pub members: Vec<Member>,
    pub required_capabilities: GroupCapabilities,
    /// Persisted application-profile generation for this group. Records
    /// written before profile classification existed are deterministically
    /// legacy, regardless of the MLS carrier used by their latest state.
    #[serde(default)]
    pub protocol_profile: ProtocolProfile,
    /// The local copy of this group is marked removed: retained canonical
    /// state records the local member's own removal (spec
    /// `protocol-core/member-departure.md`, "Realizing removal"). The record
    /// is retained inactive — history may be kept, but the group must not be
    /// presented as active and nothing may be sent or published to it. This
    /// flag is the idempotence marker for the realization obligation: it is
    /// set together with the self-removed state notification, so later input
    /// classified `SelfEvicted` does not re-emit the notification. Terminal
    /// for the group on this client while the removal stays canonical; it
    /// clears on an authenticated re-join, or when branch selection
    /// supersedes the removal that set it — the selected canonical branch
    /// then records the local member's membership, so the removal "is treated
    /// as not having happened" (spec `protocol-core/convergence.md`,
    /// "Applying the selected branch"). Defaults to `false` for records
    /// persisted before this field existed.
    #[serde(default)]
    pub removed: bool,
    /// Epoch at which this device's membership began (welcome-join or group
    /// creation), refreshed on an authenticated re-join. Post-peel
    /// classification lower bound: an application message whose MLS epoch
    /// precedes it is pre-membership — permanently undecryptable by design
    /// and never worth retrying. `EpochId(0)` (the default for records
    /// persisted before this field existed) means "unknown — no bound".
    #[serde(default)]
    pub join_epoch: EpochId,
}

/// One member of a group, as storage sees it.
///
/// `id` is the stable cross-epoch identifier (signature public key). The MLS
/// leaf index is **not** stored here — it changes as the tree mutates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub id: MemberId,
    pub credential: Vec<u8>,
}
