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
    //
    // Fail-closed: if we cannot read the admin set or the leaver's
    // pubkey (e.g. malformed admin extension, non-32-byte credential),
    // we do NOT commit. A corrupted group is not a state the auto-
    // committer should advance on best-effort.
    let Ok(admins) = crate::app_components::admins_of_group(mls_group) else {
        return AutoCommitDecision::Observe;
    };
    let leaver_pubkey = match pubkey_at_leaf_index(mls_group, leaver_idx) {
        PubkeyResult::Ok(p) => Some(p),
        PubkeyResult::MalformedIdentity => return AutoCommitDecision::Observe,
        PubkeyResult::LeafMissing => None,
    };
    if let Some(leaver_pubkey) = leaver_pubkey
        && admins.len() == 1
        && admins[0] == leaver_pubkey
    {
        return AutoCommitDecision::Observe;
    }

    AutoCommitDecision::Commit
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
