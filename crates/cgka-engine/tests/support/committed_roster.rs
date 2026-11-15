//! Checks a group's committed roster (mdk#3273 B) against the engine's
//! merged membership at the public boundary.

// Shared by every engine test binary; only some check rosters.
#![allow(dead_code)]

use cgka_engine::Engine;
use cgka_traits::storage::{CommittedMembers, CommittedRoster, StorageProvider};
use cgka_traits::types::GroupId;

/// `group_id`'s committed roster, after checking it holds exactly the
/// distinct account ids of the engine's merged MLS membership, which leaves
/// out a pending commit's changes.
pub fn checked_committed_roster<S: StorageProvider>(
    engine: &Engine<S>,
    storage: &S,
    group_id: &GroupId,
) -> CommittedRoster {
    let merged = engine
        .canonical_group_membership(group_id)
        .expect("merged membership");
    let expected =
        CommittedMembers::from_ids(merged.member_leaves.into_iter().map(|leaf| leaf.member));
    let roster = storage
        .committed_roster(group_id)
        .expect("read committed roster")
        .expect("group has a committed roster");
    assert_eq!(
        roster.members, expected,
        "committed roster holds the merged membership"
    );
    roster
}
