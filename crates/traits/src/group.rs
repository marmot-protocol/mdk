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
    /// Local copy cannot safely select a canonical branch from retained
    /// material (e.g. `MissingRetainedAnchor` inside the rollback horizon).
    /// Canonical state is frozen; the client MUST stop applying and ingesting
    /// group-state changes until a verified repair path
    /// (`spec/protocol-core/group-state.md:54-66`). Persisted so process
    /// restart cannot silently clear the halt (mdk#971). Clears only through
    /// an authenticated re-join welcome (or another verified repair that
    /// rebuilds the group record). Defaults to `false` for records persisted
    /// before this field existed.
    #[serde(default)]
    pub unrecoverable: bool,
    /// Authenticated terminal tombstone. When present, live OpenMLS state has
    /// been deleted and the group must never hydrate, route, send, converge, or
    /// rejoin under this group id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disbanded: Option<DisbandTombstone>,
    /// Epoch at which this device's first known membership began
    /// (welcome-join or group creation). Post-peel
    /// classification lower bound: an application message whose MLS epoch
    /// precedes it is pre-membership — permanently undecryptable by design
    /// and never worth retrying. `EpochId(0)` (the default for records
    /// persisted before this field existed) means "unknown — no bound".
    /// Authenticated rejoin/repair resets this to zero because a single lower
    /// bound cannot represent multiple membership intervals; classifying all
    /// earlier epochs as absent would incorrectly reject prior-membership
    /// traffic.
    #[serde(default)]
    pub join_epoch: EpochId,
    /// Epoch at which this device's CURRENT local copy of the group was
    /// installed — group creation, a first welcome-join, or the replacement
    /// welcome that discarded the previous copy.
    ///
    /// Distinct from [`Group::join_epoch`], which is a membership lower bound
    /// for application messages and is deliberately reset to zero by a
    /// replacement welcome so prior-interval messages stay decryptable from
    /// retained anchors. This field is the copy's own start: below it no
    /// commit can be a rival, because this copy holds no state at that epoch
    /// to rewind to and never will. It is the live-ingest counterpart of the
    /// bound `retire_commits_superseded_by_replacement_welcome` already
    /// applies to retained rows.
    ///
    /// `EpochId(0)` (the default for records persisted before this field
    /// existed) means "unknown" and applies no floor, exactly like
    /// `join_epoch`.
    #[serde(default)]
    pub local_copy_install_epoch: EpochId,
    /// When the Welcome that installed this local copy was created, in Unix
    /// seconds, clamped at join to no later than the joining device's own
    /// clock. `None` on a copy this device created itself, on transports that
    /// cannot establish the value, and on records persisted before this field
    /// existed.
    ///
    /// A **soft** signal, and only ever that. The epoch fields above are the
    /// post-peel floor: they can classify only a message the device managed to
    /// open, and the traffic published while a removed device was away never
    /// peels at all, so it never reaches them. This is the one thing known
    /// about such a message before decryption — but it is not enough to refuse
    /// it, because pre-peel a commit and an application message are
    /// indistinguishable and their envelope times mean different things: a
    /// commit carries wrap time, while an application message carries the
    /// sender's compose time (`peeler::GroupMessageMetadata::outer_created_at`).
    /// The offline outbox holds plaintext and re-encrypts at drain, so a
    /// message composed hours before it was sent is ordinary live traffic
    /// wearing an old timestamp. Anything terminal keyed on this value would
    /// eventually lose one of those for good.
    ///
    /// Use it only where being wrong is free: see
    /// [`Group::transport_message_predates_local_copy`].
    ///
    /// The clamp is why the inviter's clock cannot become this device's
    /// problem. The value is the NIP-59 welcome rumor's `created_at`, which no
    /// relay validates, so an inviter running fast — or lying — would otherwise
    /// place the floor in the future and make every later message look like
    /// history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_copy_welcome_created_at: Option<crate::transport::Timestamp>,
}

impl Group {
    /// Is this local copy of the group terminal — nothing may be routed, sent,
    /// or ingested for it any more?
    ///
    /// Two distinct reasons, both terminal here and neither implying the
    /// other: [`Group::removed`] means this device is out of a group that goes
    /// on without it, and [`Group::disbanded`] means the group itself is gone
    /// for everyone. [`Group::unrecoverable`] is deliberately excluded: that
    /// copy is halted pending a verified repair, not finished.
    pub fn is_terminal(&self) -> bool {
        self.removed || self.disbanded.is_some()
    }

    /// Does `timestamp` sit far enough before this copy's Welcome that traffic
    /// carrying it is more likely the group's history than this copy's?
    ///
    /// This copy's epochs begin at the commit that minted its Welcome, so a
    /// message genuinely published before then can never be opened here. But
    /// the converse does not hold — an application message carries its
    /// sender's compose time, which the offline outbox can leave hours behind
    /// the moment the message actually went out — so a `true` here is a guess,
    /// not a verdict.
    ///
    /// Every caller must therefore be one for which a wrong guess costs
    /// nothing in either direction. Today that is two: dropping one piece of
    /// stall evidence, and suppressing a refusal notification for a release
    /// that happens either way. Never gate persistence, decryption, retry, or
    /// any terminal classification on it.
    pub fn transport_message_predates_local_copy(
        &self,
        timestamp: crate::transport::Timestamp,
    ) -> bool {
        self.local_copy_welcome_created_at.is_some_and(|welcome| {
            timestamp.0.saturating_add(PRE_WELCOME_CLOCK_SKEW_SECS) < welcome.0
        })
    }
}

/// Clock-skew tolerance for [`Group::transport_message_predates_local_copy`].
///
/// Both decisions this margin gates are reversible, which sets its size from a
/// direction opposite to the usual one. A margin that is too *wide* leaves more
/// false stall arms and more refusal notifications for expected traffic —
/// exactly what the signal exists to reduce. A margin that is too *narrow*
/// costs one piece of stall evidence from a sender whose clock trails the
/// inviter's, or from a message composed offline; every other message that
/// device receives still arms, so the detector still fires on a real stall.
/// The cheap direction is therefore the tight one.
///
/// Five minutes is the sender-clock tolerance this project already assumes
/// elsewhere — `marmot-app`'s transport cursor allows the same drift. That
/// constant is deliberately not imported: it bounds a different quantity and
/// lives above the transport boundary, while this one must stay
/// transport-agnostic. Only the shared assumption about real clocks is reused.
pub const PRE_WELCOME_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Durable evidence and read-only projection material retained after a
/// selected disband Commit deletes live MLS state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisbandTombstone {
    pub epoch: EpochId,
    pub actor: MemberId,
    pub origin_commit_id: Option<crate::types::MessageId>,
    pub commit_digest: [u8; 32],
    /// True only on the exact account-device leaf that authored the selected
    /// Commit. Sibling leaves for the same account are removed.
    pub local_was_committer_leaf: bool,
    /// Deduplicated account roster captured immediately before disbanding.
    pub former_members: Vec<Member>,
    /// Whether hydration has already replayed this guard's terminal
    /// `GroupDisbanded` to the application.
    ///
    /// The guard itself is immortal — nothing may consume or clear it — so
    /// suppressing the *replay* is the only thing this marker does. Rows
    /// written before the marker existed carry no field and default to
    /// unannounced, which replays them exactly once more and then marks them.
    ///
    /// The failure direction is deliberate: losing the marker costs one
    /// redundant replay (the application's terminal projection is replay-safe
    /// by construction), while a marker set too early would suppress an
    /// announcement the application never received. Only
    /// `Engine::restore_disband_tombstone` sets it, and only after it has
    /// produced the replay.
    #[serde(default)]
    pub announced: bool,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::GroupCapabilities;
    use crate::transport::Timestamp;

    fn copy_installed_at(welcome: Option<u64>) -> Group {
        Group {
            id: GroupId::new(vec![7; 16]),
            name: String::new(),
            description: String::new(),
            epoch: EpochId(4),
            members: Vec::new(),
            required_capabilities: GroupCapabilities::default(),
            protocol_profile: ProtocolProfile::Current,
            removed: false,
            unrecoverable: false,
            disbanded: None,
            join_epoch: EpochId(4),
            local_copy_install_epoch: EpochId(4),
            local_copy_welcome_created_at: welcome.map(Timestamp),
        }
    }

    const WELCOME: u64 = 1_700_000_000;

    #[test]
    fn a_copy_this_device_created_never_predates_itself() {
        let created_here = copy_installed_at(None);

        assert!(!created_here.transport_message_predates_local_copy(Timestamp(0)));
        assert!(!created_here.transport_message_predates_local_copy(Timestamp(WELCOME - 99_999)));
    }

    #[test]
    fn the_tolerance_band_ends_one_second_before_the_margin() {
        let joined = copy_installed_at(Some(WELCOME));
        let margin = PRE_WELCOME_CLOCK_SKEW_SECS;

        // Inside the band, including its exact edge: not old enough to say.
        assert!(!joined.transport_message_predates_local_copy(Timestamp(WELCOME)));
        assert!(!joined.transport_message_predates_local_copy(Timestamp(WELCOME - margin)));
        // One second beyond it.
        assert!(joined.transport_message_predates_local_copy(Timestamp(WELCOME - margin - 1)));
    }

    #[test]
    fn a_message_newer_than_the_welcome_never_predates_it() {
        let joined = copy_installed_at(Some(WELCOME));

        assert!(!joined.transport_message_predates_local_copy(Timestamp(WELCOME + 1)));
        assert!(!joined.transport_message_predates_local_copy(Timestamp(u64::MAX)));
    }
}
