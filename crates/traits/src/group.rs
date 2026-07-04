//! `Group` and `Member` records as seen by storage.
//!
//! **Invariant (enforced at trait-definition time):** neither [`Group`] nor
//! [`Member`] contains any transport-layer types. No `nostr_group_id`, no
//! relay URLs, no FIPS mesh ids. That mapping lives in the transport adapter
//! (see `docs/marmot-architecture/further-context/cgka-engine-design.md:247-268`).

use crate::capabilities::GroupCapabilities;
use crate::types::{EpochId, GroupId, MemberId};
use serde::{Deserialize, Serialize};

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
