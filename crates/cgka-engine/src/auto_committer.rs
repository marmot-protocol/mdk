//! Lowest-index auto-committer policy.
//!
//! Per MIP-03 §144+§147 and RFC 9420 §12.2: when a SelfRemove proposal lands
//! in the pending queue, the committer MUST NOT be the leaver. To avoid
//! forks from multiple remaining members concurrently committing, Marmot
//! picks a deterministic committer: the **lowest-index remaining member
//! that isn't the target of the SelfRemove**.
//!
//! This deterministic policy has a known liveness tradeoff: if the
//! lowest-index eligible member is offline, the commit waits. A later
//! randomized-delay policy can replace this module without changing ingest.
//!
//! ## Scope
//!
//! For 0.1.0 we handle only SelfRemove auto-commit. Other proposal types
//! (Update, PreSharedKey, …) that land in the pending queue require user-
//! or engine-level commit decisions that we don't automate yet.
//!
//! ## Auto-publish lifecycle
//!
//! Explicit `send` paths defer their `merge_pending_commit` to
//! `do_confirm_published`. The auto-commit path merges immediately, then
//! pushes the wrapped commit onto `auto_publish_buf` for
//! `drain_auto_publish`. There is no per-message confirm callback for
//! auto-publish yet. A later API can return `(TransportMessage,
//! PendingStateRef)` from the auto-publish drain and add an
//! `auto_publish_failed` callback.

use openmls::framing::Sender;
use openmls::group::MlsGroup;
use openmls::prelude::{LeafNodeIndex, Proposal, QueuedProposal};

/// Decision returned by the policy.
pub(crate) enum AutoCommitDecision {
    /// This client should commit the named proposal.
    Commit,
    /// Some other client is responsible (or we're the target).
    Observe,
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
/// 3. We are the lowest-index remaining non-target member.
///
/// Admin checks are partly enforced by send-time guards and partly here:
/// if the leaver is the only admin, this policy observes instead of
/// committing.
///
/// Not enforced here:
/// - **§151 remove-beats-self-remove**: a precedence rule when both a
///   Remove and a SelfRemove target the same leaf in the same pending
///   queue. The engine does not produce Remove proposals yet.
pub(crate) fn decide(mls_group: &MlsGroup, proposal: &QueuedProposal) -> AutoCommitDecision {
    // (1) SelfRemove only.
    match proposal.proposal() {
        Proposal::SelfRemove => {}
        _ => return AutoCommitDecision::Observe,
    }

    // Identify the leaver.
    let leaver_idx: LeafNodeIndex = match proposal.sender() {
        Sender::Member(i) => *i,
        _ => return AutoCommitDecision::Observe,
    };

    let own = mls_group.own_leaf_index();

    // (2) We are not the target.
    if own == leaver_idx {
        return AutoCommitDecision::Observe;
    }

    // (3) We are the lowest-index remaining non-target member.
    let lowest = mls_group
        .members()
        .map(|m| m.index)
        .filter(|i| *i != leaver_idx)
        .min();
    if lowest != Some(own) {
        return AutoCommitDecision::Observe;
    }

    // (4) MIP-03 §150 admin-depletion guard. If the leaver is the only
    //     admin, committing this SelfRemove would deplete admins. Refuse.
    if let Ok(admins) = crate::group_data::admins_of_group(mls_group)
        && let Some(leaver_pubkey) = pubkey_at_leaf_index(mls_group, leaver_idx)
        && admins.len() == 1
        && admins[0] == leaver_pubkey
    {
        return AutoCommitDecision::Observe;
    }

    AutoCommitDecision::Commit
}

/// Look up the 32-byte identity (admin pubkey form) at a given leaf index.
fn pubkey_at_leaf_index(
    mls_group: &MlsGroup,
    idx: openmls::prelude::LeafNodeIndex,
) -> Option<[u8; 32]> {
    let m = mls_group.members().find(|m| m.index == idx)?;
    let bc = openmls::prelude::BasicCredential::try_from(m.credential).ok()?;
    let id = bc.identity();
    if id.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(id);
    Some(out)
}

// The commit-and-apply work happens in `message_processor::ingest_group_message`
// directly — the `MlsGroup` holding the pending proposal must be the same
// instance, and reloading from storage loses the in-memory proposal queue.
