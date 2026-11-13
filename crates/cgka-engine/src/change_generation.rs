//! Per-group change generations (mdk#3273): a value that moves whenever an
//! input of a group's published answers may have changed, so a layer that
//! publishes those answers rebuilds a group only when its generation moved.
//!
//! The durable half is the backend's write count for the group
//! ([`StorageProvider::group_write_generation`]). The memory half is the engine state those answers read
//! besides storage, held by value: availability (live, unhydrated,
//! quarantined, a failed rewind restore) and the group's lifecycle state.
//! Holding memory facts by value means no engine mutation site has to
//! remember to bump anything. Application-message ratchet steps move neither
//! half.

use crate::engine::Engine;
use cgka_traits::engine::GroupHydrationQuarantineReason;
use cgka_traits::engine_state::EpochState;
use cgka_traits::storage::{GroupWriteGeneration, StorageProvider};
use cgka_traits::types::GroupId;

/// Whether the engine serves a group's gated reads, as its memory says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Availability {
    /// Not quarantined and not waiting for hydration: live if stored.
    Open,
    /// Seeded at session open; gated reads fail with `GroupNotHydrated`.
    Unhydrated,
    /// Gated reads answer `UnknownGroup`.
    Quarantined(GroupHydrationQuarantineReason),
}

/// One scope of a [`GroupChangeGeneration`]. Two stamps are
/// [`Self::unchanged_since`] each other only when the backend counts writes;
/// without a count every stamp differs, so nothing is reused.
#[derive(Clone, Debug)]
pub struct ChangeStamp {
    /// This group's writes in the stamp's scope.
    durable: Option<u64>,
    availability: Availability,
    /// `None` for the hydrated scope, which no lifecycle state feeds.
    lifecycle: Option<Option<EpochState>>,
}

impl ChangeStamp {
    /// Whether no input this stamp covers has changed since `earlier` was
    /// taken.
    pub fn unchanged_since(&self, earlier: &Self) -> bool {
        self.durable.is_some()
            && self.durable == earlier.durable
            && self.availability == earlier.availability
            && self.lifecycle == earlier.lifecycle
    }
}

/// Where one group's published answers stand.
#[derive(Clone, Debug)]
pub struct GroupChangeGeneration {
    /// Moves on every input of the group's published answers: engine
    /// record writes, lifecycle and commit-derived MLS state, the
    /// convergence-pass row, fanouts, maintenance rows and evolutions,
    /// withdrawn-commit message states, the app's device-group and
    /// self-membership rows, and availability (hydration, quarantine
    /// entered or cleared, forget).
    pub state: ChangeStamp,
    /// Moves on commit-derived and availability changes: the inputs of
    /// answers read from a loaded group, such as app components.
    pub hydrated: ChangeStamp,
}

impl<S: StorageProvider> Engine<S> {
    /// The change generation of each group in `group_ids`, in order.
    pub fn group_change_generations<'a>(
        &self,
        group_ids: impl IntoIterator<Item = &'a GroupId>,
    ) -> Vec<GroupChangeGeneration> {
        group_ids
            .into_iter()
            .map(|group_id| {
                let writes = self.storage.group_write_generation(group_id);
                let durable = |scope: fn(&GroupWriteGeneration) -> u64| writes.as_ref().map(scope);
                let availability = match self.quarantined_reason(group_id) {
                    Some(reason) => Availability::Quarantined(reason),
                    None if self.unhydrated_groups.contains(group_id) => Availability::Unhydrated,
                    None => Availability::Open,
                };
                GroupChangeGeneration {
                    state: ChangeStamp {
                        durable: durable(|writes| writes.state),
                        availability,
                        lifecycle: Some(self.epoch_manager.state(group_id).cloned()),
                    },
                    hydrated: ChangeStamp {
                        durable: durable(|writes| writes.committed),
                        availability,
                        lifecycle: None,
                    },
                }
            })
            .collect()
    }
}
