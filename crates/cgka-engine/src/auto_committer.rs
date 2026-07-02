//! SelfRemove auto-commit policy.
//!
//! Per MIP-03 §144+§147 and RFC 9420 §12.2: when a SelfRemove proposal lands
//! in the pending queue, the committer MUST NOT be the leaver. Marmot lets any
//! remaining authorized member attempt the SelfRemove-only commit; competing
//! commits are ordinary same-epoch races for convergence to resolve.
//!
//! ## Scope
//!
//! For 0.1.0 we handle only SelfRemove auto-commit. Other proposal types
//! (Update, PreSharedKey, …) that land in the pending queue require user-
//! or engine-level commit decisions that we don't automate yet.
//!
//! ## Auto-publish lifecycle
//!
//! Auto-commit follows the same publish-before-apply lifecycle as explicit
//! group evolution. It stages an OpenMLS pending commit, pushes
//! `(TransportMessage, PendingStateRef)` onto `auto_publish_buf`, and defers
//! `merge_pending_commit` until `do_confirm_published`. If publication fails,
//! the application calls `publish_failed` with the pending ref and the engine
//! clears the staged commit.

use openmls::framing::Sender;
use openmls::group::MlsGroup;
use openmls::prelude::{LeafNodeIndex, Proposal, QueuedProposal};

/// Decision returned by the policy.
pub(crate) enum AutoCommitDecision {
    /// This client should commit the named proposal.
    Commit,
    /// We are not allowed to commit this proposal.
    Observe,
}

pub(crate) struct AutoCommitDecisionReport {
    pub decision: AutoCommitDecision,
    pub reason: &'static str,
}

/// Inspect a QueuedProposal and decide whether we should auto-commit.
///
/// Criteria:
///
/// 1. The proposal is a SelfRemove.
/// 2. **Committer-MUST-NOT-be-leaver (RFC 9420 §12.2).** We are not the
///    target — if we were, we'd produce an invalid commit and OpenMLS
///    would reject it. Enforcing here gives a clean typed early exit
///    instead of an opaque MLS error.
/// 3. Admin checks are partly enforced by send-time guards and partly here:
///    if the leaver is the only admin, this policy observes instead of
///    committing.
///
/// Not enforced here:
/// - **§151 remove-beats-self-remove**: a precedence rule when both a
///   Remove and a SelfRemove target the same leaf in the same pending
///   queue. The engine does not produce Remove proposals yet.
pub(crate) fn decide_with_reason(
    mls_group: &MlsGroup,
    proposal: &QueuedProposal,
) -> AutoCommitDecisionReport {
    // (1) SelfRemove only.
    match proposal.proposal() {
        Proposal::SelfRemove => {}
        _ => {
            return AutoCommitDecisionReport {
                decision: AutoCommitDecision::Observe,
                reason: "proposal_not_self_remove",
            };
        }
    }

    // Identify the leaver.
    let leaver_idx: LeafNodeIndex = match proposal.sender() {
        Sender::Member(i) => *i,
        _ => {
            return AutoCommitDecisionReport {
                decision: AutoCommitDecision::Observe,
                reason: "sender_not_member",
            };
        }
    };

    let own = mls_group.own_leaf_index();

    // (2) We are not the target.
    if own == leaver_idx {
        return AutoCommitDecisionReport {
            decision: AutoCommitDecision::Observe,
            reason: "we_are_target",
        };
    }

    // (3) member-departure.md:23-26 — an admin must leave the admin set before
    //     SelfRemove. Refuse to auto-commit any SelfRemove whose sender is
    //     still an active admin in the prior epoch.
    //
    // Fail-closed: if we cannot read the admin set or the leaver's
    // pubkey (e.g. malformed admin extension, non-32-byte credential),
    // we do NOT commit. A corrupted group is not a state the auto-
    // committer should advance on best-effort.
    let Ok(admins) = crate::app_components::admins_of_group(mls_group) else {
        return AutoCommitDecisionReport {
            decision: AutoCommitDecision::Observe,
            reason: "admin_set_unreadable",
        };
    };
    let leaver_pubkey = match pubkey_at_leaf_index(mls_group, leaver_idx) {
        PubkeyResult::Ok(p) => Some(p),
        PubkeyResult::MalformedIdentity => {
            return AutoCommitDecisionReport {
                decision: AutoCommitDecision::Observe,
                reason: "leaver_identity_malformed",
            };
        }
        PubkeyResult::LeafMissing => None,
    };
    if let Some(leaver_pubkey) = leaver_pubkey
        && admins.iter().any(|admin| admin == &leaver_pubkey)
    {
        return AutoCommitDecisionReport {
            decision: AutoCommitDecision::Observe,
            reason: "leaver_still_admin",
        };
    }

    AutoCommitDecisionReport {
        decision: AutoCommitDecision::Commit,
        reason: "self_remove_remaining_member",
    }
}

enum PubkeyResult {
    Ok([u8; 32]),
    LeafMissing,
    MalformedIdentity,
}

/// Look up the 32-byte identity (admin pubkey form) at a given leaf index.
///
/// Returns three distinct outcomes so the auto-committer can fail-closed
/// on malformed identities (which violate MIP-01) instead of treating
/// them as "no leaver pubkey to compare against."
fn pubkey_at_leaf_index(
    mls_group: &MlsGroup,
    idx: openmls::prelude::LeafNodeIndex,
) -> PubkeyResult {
    let Some(m) = mls_group.members().find(|m| m.index == idx) else {
        return PubkeyResult::LeafMissing;
    };
    let Ok(bc) = openmls::prelude::BasicCredential::try_from(m.credential) else {
        return PubkeyResult::MalformedIdentity;
    };
    let id = bc.identity();
    if id.len() != 32 {
        return PubkeyResult::MalformedIdentity;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(id);
    PubkeyResult::Ok(out)
}

// The commit-staging work happens in `message_processor::ingest_group_message`
// directly so the freshly processed proposal can be stored and committed on
// the same OpenMLS group instance. Applying the staged commit still waits for
// `confirm_published`.
