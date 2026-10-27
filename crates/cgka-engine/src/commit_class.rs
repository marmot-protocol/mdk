//! The one test that decides a Commit's authority and its branch priority.
//!
//! [`classify_staged_commit`] reads a Commit and its candidate parent state and
//! returns exactly one [`CommitClass`]:
//!
//! - **self-update**: no proposals, only the committer's update path;
//! - **SelfRemove-only**: at least one SelfRemove and nothing else;
//! - **same-account**: the parent requires `marmot.group.account-devices.v1`
//!   and every proposal, carried by value, adds a KeyPackage of the
//!   committer's account or removes another current leaf of it;
//! - **admin-required**: everything else.
//!
//! The first three are the Commits a non-admin may make
//! (group-messaging.md, "Commit authorization"; account-devices-v1.md,
//! "Authorization"). They are `ordinary` in branch selection whoever commits
//! them, and admin-required Commits are `privileged` (convergence.md,
//! `tip_priority`; account-devices-v1.md, "Branch priority").
//!
//! Replay (which normal apply, candidate probes and recovery share), the
//! committer's checks before it publishes, and the stamp it records at publish
//! all call [`classify_staged_commit`] on the same parent state. A stamp that
//! disagreed with replay would make the committer resolve forks differently
//! from every other member.
//!
//! For a parent that does not require account-devices the answers are those
//! of the earlier shape-only rule: the requirement is read only for a Commit
//! made entirely of same-account operations, and such a Commit is otherwise
//! admin-required. `tests::groups_without_account_devices_keep_the_shape_only_answers`
//! checks this for every shape.

use cgka_traits::engine::CommitOrderingPriority;
use cgka_traits::error::EngineError;
use cgka_traits::ingest::ProposalRejectionCategory;
use cgka_traits::types::{GroupId, MemberId};
use openmls::group::{MlsGroup, StagedCommit};
use openmls::messages::proposals::Proposal;
use openmls::prelude::{LeafNodeIndex, ProposalOrRefType, QueuedProposal};

/// The one class a Commit has in its candidate parent state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommitClass {
    /// Updates only the committer's own LeafNode.
    SelfUpdate,
    /// Commits pending SelfRemove proposals and nothing else.
    SelfRemoveOnly,
    /// Adds and removes leaves of the committer's own account, by value, in a
    /// parent that requires account-devices.
    SameAccount,
    /// Needs an active admin committer.
    AdminRequired,
}

impl CommitClass {
    /// Whether only an active admin may commit it.
    pub fn requires_admin(self) -> bool {
        self == Self::AdminRequired
    }

    /// Its branch-selection class: `privileged` exactly when it needs an
    /// admin, whoever commits it.
    pub fn priority(self) -> CommitOrderingPriority {
        if self.requires_admin() {
            CommitOrderingPriority::Privileged
        } else {
            CommitOrderingPriority::Ordinary
        }
    }
}

/// Classify `staged` against `parent`, the candidate parent state it was
/// staged from. `committer` is the committer's leaf in `parent`; a Commit
/// without a member committer is never same-account.
pub fn classify_staged_commit(
    parent: &MlsGroup,
    staged: &StagedCommit,
    committer: Option<LeafNodeIndex>,
) -> Result<CommitClass, EngineError> {
    CommitShape::of(parent, staged, committer)
        .class(|| crate::app_components::group_requires_account_devices(parent))
}

/// Why [`authorize_staged_commit`] refuses a Commit.
#[derive(Debug)]
pub enum CommitAuthorityError {
    /// The parent state the class depends on cannot be read.
    ParentState(EngineError),
    /// A proposal the Commit carries fails its own rules, for example a
    /// membership change by a non-admin outside a same-account Commit.
    Proposal(ProposalRejectionCategory),
    /// The Commit is admin-required and its committer is not an active admin.
    NotAdmin,
    /// Any other failure of the admin check, including an active admin's own
    /// SelfRemove.
    Other(EngineError),
}

/// Authorize `staged` against `parent` and return its class.
///
/// Replay and the committer's own checks call this one function, so a
/// committer refuses locally exactly the Commits every member rejects on
/// replay. `committer_leaf` and `committer_id` are the committer's leaf in
/// `parent` and its authenticated member id.
pub fn authorize_staged_commit(
    parent: &MlsGroup,
    group_id: &GroupId,
    committer_leaf: Option<LeafNodeIndex>,
    committer_id: Option<&MemberId>,
    staged: &StagedCommit,
) -> Result<CommitClass, CommitAuthorityError> {
    let class = classify_staged_commit(parent, staged, committer_leaf)
        .map_err(CommitAuthorityError::ParentState)?;
    crate::app_components::authorize_staged_commit_proposals(parent, staged, class)
        .map_err(|rejection| CommitAuthorityError::Proposal(rejection.category))?;
    crate::app_components::require_admin_for_staged_commit(
        parent,
        group_id,
        committer_id,
        staged,
        class,
    )
    .map_err(|error| match error {
        EngineError::NotGroupAdmin { .. } => CommitAuthorityError::NotAdmin,
        other => CommitAuthorityError::Other(other),
    })?;
    Ok(class)
}

/// [`authorize_staged_commit`] for a Commit this device staged and is about to
/// publish, with its refusals as the errors its send paths report.
pub(crate) fn authorize_own_staged_commit(
    parent: &MlsGroup,
    group_id: &GroupId,
    self_id: &MemberId,
    staged: &StagedCommit,
) -> Result<CommitClass, EngineError> {
    authorize_staged_commit(
        parent,
        group_id,
        Some(parent.own_leaf_index()),
        Some(self_id),
        staged,
    )
    .map_err(|error| match error {
        CommitAuthorityError::Proposal(ProposalRejectionCategory::AuthorizationFailed)
        | CommitAuthorityError::NotAdmin => EngineError::NotGroupAdmin {
            group_id: group_id.clone(),
        },
        CommitAuthorityError::Proposal(category) => EngineError::Other(format!(
            "commit is invalid: {}",
            crate::app_components::proposal_rejection_category_tag(category)
        )),
        CommitAuthorityError::ParentState(error) | CommitAuthorityError::Other(error) => error,
    })
}

/// What the classifier reads from a Commit: how many proposals it carries,
/// how many of them are SelfRemoves (by value or by reference, as the
/// shape-only rule counted them) and how many are same-account operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitShape {
    has_update_path: bool,
    proposals: usize,
    self_removes: usize,
    same_account: usize,
}

impl CommitShape {
    fn of(parent: &MlsGroup, staged: &StagedCommit, committer: Option<LeafNodeIndex>) -> Self {
        let committer_account = committer.and_then(|leaf| {
            parent.member_at(leaf).and_then(|member| {
                crate::app_components::credential_account_pubkey(member.credential)
            })
        });
        let mut shape = Self {
            has_update_path: staged.update_path_leaf_node().is_some(),
            proposals: 0,
            self_removes: 0,
            same_account: 0,
        };
        for queued in staged.queued_proposals() {
            shape.proposals += 1;
            if matches!(queued.proposal(), Proposal::SelfRemove) {
                shape.self_removes += 1;
            } else if let (Some(leaf), Some(account)) = (committer, committer_account)
                && is_same_account_operation(parent, leaf, &account, queued)
            {
                shape.same_account += 1;
            }
        }
        shape
    }

    /// The class of a Commit with this shape. `parent_requires_account_devices`
    /// is asked only for a Commit made entirely of same-account operations,
    /// the one case whose answer depends on it.
    fn class<E>(
        self,
        parent_requires_account_devices: impl FnOnce() -> Result<bool, E>,
    ) -> Result<CommitClass, E> {
        if self.proposals == 0 {
            return Ok(if self.has_update_path {
                CommitClass::SelfUpdate
            } else {
                CommitClass::AdminRequired
            });
        }
        if self.self_removes == self.proposals {
            return Ok(CommitClass::SelfRemoveOnly);
        }
        if self.same_account == self.proposals && parent_requires_account_devices()? {
            return Ok(CommitClass::SameAccount);
        }
        Ok(CommitClass::AdminRequired)
    }
}

/// account-devices-v1.md, "Same-account operations": an Add, by value, of a
/// KeyPackage whose credential identity is the committer's account, or a
/// Remove, by value, of a current leaf other than the committer's own whose
/// credential identity is the committer's account.
fn is_same_account_operation(
    parent: &MlsGroup,
    committer: LeafNodeIndex,
    account: &[u8; 32],
    queued: &QueuedProposal,
) -> bool {
    if queued.proposal_or_ref_type() != ProposalOrRefType::Proposal {
        return false;
    }
    let identity = match queued.proposal() {
        Proposal::Add(add) => crate::app_components::credential_account_pubkey(
            add.key_package().leaf_node().credential().clone(),
        ),
        Proposal::Remove(remove) if remove.removed() != committer => parent
            .member_at(remove.removed())
            .and_then(|member| crate::app_components::credential_account_pubkey(member.credential)),
        _ => None,
    };
    identity.as_ref() == Some(account)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape-only rule this classifier replaced, transcribed unchanged:
    /// a non-admin may make a self-update (no proposals, an update path) or a
    /// SelfRemove-only Commit (at least one proposal, every one a SelfRemove),
    /// never both and nothing else.
    fn shape_only_requires_admin(shape: CommitShape) -> bool {
        let is_self_update_only = shape.proposals == 0 && shape.has_update_path;
        let is_self_remove_only = shape.self_removes > 0 && shape.self_removes == shape.proposals;
        !(is_self_update_only ^ is_self_remove_only)
    }

    fn shape_only_priority(shape: CommitShape) -> CommitOrderingPriority {
        if shape_only_requires_admin(shape) {
            CommitOrderingPriority::Privileged
        } else {
            CommitOrderingPriority::Ordinary
        }
    }

    /// Every shape with up to `MAX_PROPOSALS` proposals. The class depends on
    /// a Commit only through these counts, so this covers every Commit with at
    /// most that many proposals.
    fn every_shape() -> impl Iterator<Item = CommitShape> {
        const MAX_PROPOSALS: usize = 8;
        (0..=MAX_PROPOSALS).flat_map(|proposals| {
            (0..=proposals).flat_map(move |self_removes| {
                (0..=proposals - self_removes).flat_map(move |same_account| {
                    [false, true].map(|has_update_path| CommitShape {
                        has_update_path,
                        proposals,
                        self_removes,
                        same_account,
                    })
                })
            })
        })
    }

    #[test]
    fn groups_without_account_devices_keep_the_shape_only_answers() {
        for shape in every_shape() {
            let class = shape.class(|| Ok::<_, ()>(false)).unwrap();
            assert_eq!(
                class.requires_admin(),
                shape_only_requires_admin(shape),
                "{shape:?} -> {class:?}"
            );
            assert_eq!(
                class.priority(),
                shape_only_priority(shape),
                "{shape:?} -> {class:?}"
            );
        }
    }

    #[test]
    fn account_devices_changes_only_same_account_commits() {
        for shape in every_shape() {
            let mut asked = false;
            let class = shape
                .class(|| {
                    asked = true;
                    Ok::<_, ()>(true)
                })
                .unwrap();
            let same_account = shape.proposals > 0 && shape.same_account == shape.proposals;
            assert_eq!(asked, same_account, "{shape:?}");
            if same_account {
                assert_eq!(class, CommitClass::SameAccount, "{shape:?}");
                assert_eq!(class.priority(), CommitOrderingPriority::Ordinary);
            } else {
                assert_eq!(
                    class.requires_admin(),
                    shape_only_requires_admin(shape),
                    "{shape:?} -> {class:?}"
                );
            }
        }
    }

    #[test]
    fn a_requirement_that_cannot_be_read_fails_only_same_account_commits() {
        for shape in every_shape() {
            let result = shape.class(|| Err("unreadable parent"));
            let same_account = shape.proposals > 0 && shape.same_account == shape.proposals;
            assert_eq!(result.is_err(), same_account, "{shape:?}");
        }
    }

    #[test]
    fn exactly_admin_required_commits_are_privileged() {
        for class in [
            CommitClass::SelfUpdate,
            CommitClass::SelfRemoveOnly,
            CommitClass::SameAccount,
            CommitClass::AdminRequired,
        ] {
            assert_eq!(
                class.priority() == CommitOrderingPriority::Privileged,
                class == CommitClass::AdminRequired
            );
        }
    }
}
