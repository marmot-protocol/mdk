//! Lowest-index auto-committer policy.
//!
//! Per MIP-03 §144+§147 and RFC 9420 §12.2: when a SelfRemove proposal lands
//! in the pending queue, the committer MUST NOT be the leaver. To avoid
//! forks from multiple remaining members concurrently committing, Marmot
//! picks a deterministic committer: the **lowest-index remaining member
//! that isn't the target of the SelfRemove**.
//!
//! This is a known shortcut (flagged in `docs/learnings.md:141`): if that
//! lowest-index member is offline, the commit never happens. A future
//! randomized-delay + observe-others strategy can replace this policy
//! object without touching the ingest pipeline — which is why the policy
//! is named + isolated in this module.
//!
//! ## Scope
//!
//! For 0.1.0 we handle only SelfRemove auto-commit. Other proposal types
//! (Update, PreSharedKey, …) that land in the pending queue require user-
//! or engine-level commit decisions that we don't automate yet.
//!
//! ## Deviation from publish-before-apply (Task 4.13)
//!
//! Explicit `send` paths defer their `merge_pending_commit` to
//! `do_confirm_published` (Task 4.13, landed). The auto-commit path here
//! intentionally does NOT — it merges immediately, then pushes the wrapped
//! commit onto `auto_publish_buf` for the application to drain via
//! `drain_auto_publish`. There's no per-message `confirm_published`
//! callback for auto-publish, so the engine has to choose between
//! (a) advancing optimistically (current behavior) or (b) leaving the
//! group stuck in `PendingPublish` until something un-pends it. (a) is
//! the lesser evil: a failed auto-commit publish causes divergence from
//! peers but the engine remains usable; (b) would block all subsequent
//! sends with no recovery. A future iteration could extend
//! `drain_auto_publish` to return `(TransportMessage, PendingStateRef)`
//! tuples and add an `auto_publish_failed` callback — that's a trait
//! API change and not in scope for 0.1.0.

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
/// Criteria — these implement two of the four MIP-03 / RFC-9420 guards
/// listed in Task 4.9 of the production refactor plan:
///
/// 1. The proposal is a SelfRemove.
/// 2. **Committer-MUST-NOT-be-leaver (RFC 9420 §12.2).** We are not the
///    target — if we were, we'd produce an invalid commit and OpenMLS
///    would reject it. Enforcing here gives a clean typed early exit
///    instead of an opaque MLS error.
/// 3. We are the lowest-index remaining non-target member (Marmot
///    fork-avoidance — `docs/learnings.md:112`).
///
/// **Not enforced here (admin-related Task 4.9 guards):**
/// - **§149 admin-cannot-self-remove**: requires the engine to know who is
///   admin. Marmot's admin model lives in the `MARMOT_ADMINS` extension
///   (transport-adapter-owned in our split). The engine layer has no
///   admin concept today.
/// - **§150 admin-depletion-before-commit**: same blocker — the engine
///   would need an admin set to detect "this commit leaves zero admins."
/// - **§151 remove-beats-self-remove**: a precedence rule when both a
///   Remove and a SelfRemove target the same leaf in the same pending
///   queue. Currently moot because the engine never produces Remove
///   proposals; only SelfRemove. Wire this in when invite-with-implicit-
///   remove or admin-driven removal lands.
///
/// See `plans/2026-04-22-cgka-engine-production-refactor-v1.md` Task 4.9.
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
