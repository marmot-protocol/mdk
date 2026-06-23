//! Pure before/after diff helpers that turn an applied commit's effect on
//! canonical group state into [`GroupStateChange`] values.
//!
//! These are deliberately side-effect free and MLS-free: the caller captures
//! before/after snapshots of the admin set, profile name, and avatar component
//! bytes around `merge_staged_commit` (or a confirmed own-commit) and asks this
//! module for the renderable deltas. Member add/remove/leave classification
//! stays in `message_processor` because it needs live `MlsGroup` + staged-commit
//! proposal access to distinguish an admin removal from a self-leave.
//!
//! Each [`GroupStateChange`] is later surfaced as a `GroupEvent::GroupStateChanged`
//! and synthesized by the app layer into a durable kind-1210 group system row.

use cgka_traits::engine::GroupStateChange;
use cgka_traits::types::MemberId;
use std::collections::HashSet;

/// Admin grants/revocations between two admin-policy snapshots. Iterates the
/// ordered input slices (not a set) so the output is deterministic for a given
/// before/after pair, which the conformance vectors rely on.
pub(crate) fn admin_changes(before: &[[u8; 32]], after: &[[u8; 32]]) -> Vec<GroupStateChange> {
    let before_set: HashSet<[u8; 32]> = before.iter().copied().collect();
    let after_set: HashSet<[u8; 32]> = after.iter().copied().collect();
    let mut changes = Vec::new();
    for admin in after {
        if !before_set.contains(admin) {
            changes.push(GroupStateChange::AdminAdded {
                member: MemberId::new(admin.to_vec()),
            });
        }
    }
    for admin in before {
        if !after_set.contains(admin) {
            changes.push(GroupStateChange::AdminRemoved {
                member: MemberId::new(admin.to_vec()),
            });
        }
    }
    changes
}

/// Profile changes between two snapshots: a rename when the display name moved,
/// and an avatar change when either avatar component's bytes moved. `None`
/// snapshots are treated as absent (empty name / no avatar bytes).
pub(crate) fn profile_changes(
    before_name: Option<&str>,
    after_name: Option<&str>,
    before_avatar: &[Option<Vec<u8>>],
    after_avatar: &[Option<Vec<u8>>],
) -> Vec<GroupStateChange> {
    let mut changes = Vec::new();
    let before_name = before_name.unwrap_or("");
    let after_name = after_name.unwrap_or("");
    if before_name != after_name {
        changes.push(GroupStateChange::GroupRenamed {
            name: after_name.to_owned(),
        });
    }
    if before_avatar != after_avatar {
        changes.push(GroupStateChange::GroupAvatarChanged);
    }
    changes
}

/// Disappearing-message retention changes between two snapshots. `None` and
/// `Some(0)` are both normalized to disabled (`0`) before comparing so missing
/// legacy component bytes and an explicit off value do not synthesize a row.
pub(crate) fn message_retention_changes(
    before: Option<u64>,
    after: Option<u64>,
) -> Vec<GroupStateChange> {
    let old_seconds = before.unwrap_or(0);
    let new_seconds = after.unwrap_or(0);
    if old_seconds == new_seconds {
        return Vec::new();
    }
    vec![GroupStateChange::MessageRetentionChanged {
        old_seconds,
        new_seconds,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn admin_changes_reports_grants_then_revocations() {
        let before = [id(1), id(2)];
        let after = [id(2), id(3)];
        let changes = admin_changes(&before, &after);
        assert_eq!(
            changes,
            vec![
                GroupStateChange::AdminAdded {
                    member: MemberId::new(id(3).to_vec())
                },
                GroupStateChange::AdminRemoved {
                    member: MemberId::new(id(1).to_vec())
                },
            ]
        );
    }

    #[test]
    fn admin_changes_empty_when_equal() {
        let admins = [id(1), id(2)];
        assert!(admin_changes(&admins, &admins).is_empty());
    }

    #[test]
    fn profile_changes_detects_rename_and_avatar() {
        let changes = profile_changes(
            Some("old"),
            Some("new"),
            &[Some(vec![1]), None],
            &[Some(vec![2]), None],
        );
        assert_eq!(
            changes,
            vec![
                GroupStateChange::GroupRenamed {
                    name: "new".to_owned()
                },
                GroupStateChange::GroupAvatarChanged,
            ]
        );
    }

    #[test]
    fn profile_changes_empty_when_unchanged() {
        assert!(profile_changes(Some("x"), Some("x"), &[None], &[None]).is_empty());
    }

    #[test]
    fn message_retention_changes_report_old_and_new_seconds() {
        assert_eq!(
            message_retention_changes(None, Some(60)),
            vec![GroupStateChange::MessageRetentionChanged {
                old_seconds: 0,
                new_seconds: 60,
            }]
        );
        assert_eq!(
            message_retention_changes(Some(60), None),
            vec![GroupStateChange::MessageRetentionChanged {
                old_seconds: 60,
                new_seconds: 0,
            }]
        );
        assert_eq!(
            message_retention_changes(Some(60), Some(120)),
            vec![GroupStateChange::MessageRetentionChanged {
                old_seconds: 60,
                new_seconds: 120,
            }]
        );
        assert!(message_retention_changes(None, None).is_empty());
        assert!(message_retention_changes(Some(60), Some(60)).is_empty());
    }
}
