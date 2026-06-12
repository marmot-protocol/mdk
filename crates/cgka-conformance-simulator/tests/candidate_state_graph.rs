use cgka_conformance_simulator::convergence::{
    AppWitness, BranchCandidate, ConvergencePolicy, is_branch_eligible, select_canonical_branch,
};
use cgka_traits::CommitOrderingPriority;

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn witness(epoch: u64, sender: &str) -> AppWitness {
    AppWitness {
        epoch,
        sender: sender.as_bytes().to_vec(),
    }
}

#[test]
fn equal_depth_fork_uses_app_witnesses_before_digest_tiebreak() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 10,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let heavily_witnessed = BranchCandidate {
        id: "heavily-witnessed".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![
            witness(2, "alice"),
            witness(2, "bob"),
            witness(2, "bob"),
            witness(3, "carol"),
        ],
    };
    let lower_digest = BranchCandidate {
        id: "lower-digest".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(2, "alice")],
    };

    let candidates = [heavily_witnessed.clone(), lower_digest];
    let winner = select_canonical_branch(3, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, heavily_witnessed.id);
    assert_eq!(heavily_witnessed.score(&policy).valid_commit_depth, 2);
    assert_eq!(heavily_witnessed.score(&policy).app_witness_score, 3);
}

#[test]
fn witness_quorum_can_override_small_commit_depth_lead() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 3,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let live_branch = BranchCandidate {
        id: "live".into(),
        fork_epoch: 1,
        tip_epoch: 4,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![
            witness(2, "alice"),
            witness(2, "bob"),
            witness(2, "carol"),
            witness(3, "alice"),
            witness(3, "bob"),
            witness(3, "carol"),
        ],
    };
    let withheld_branch = BranchCandidate {
        id: "withheld".into(),
        fork_epoch: 1,
        tip_epoch: 6,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(2, "mallory")],
    };
    let candidates = [live_branch.clone(), withheld_branch];

    let winner = select_canonical_branch(6, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, live_branch.id);
    assert!(live_branch.score(&policy).witness_quorum_met);
}

#[test]
fn witness_quorum_does_not_override_large_commit_depth_lead() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 8,
        witness_quorum_senders_per_epoch: 3,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let live_branch = BranchCandidate {
        id: "live".into(),
        fork_epoch: 1,
        tip_epoch: 4,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![
            witness(2, "alice"),
            witness(2, "bob"),
            witness(2, "carol"),
            witness(3, "alice"),
            witness(3, "bob"),
            witness(3, "carol"),
        ],
    };
    let much_longer_branch = BranchCandidate {
        id: "much-longer".into(),
        fork_epoch: 1,
        tip_epoch: 7,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![],
    };
    let candidates = [live_branch, much_longer_branch.clone()];

    let winner = select_canonical_branch(7, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, much_longer_branch.id);
}

#[test]
fn app_witnesses_count_distinct_senders_per_epoch() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 2,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let branch = BranchCandidate {
        id: "witnessed".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x01),
        app_witnesses: vec![
            witness(2, "alice"),
            witness(2, "alice"),
            witness(2, "bob"),
            witness(2, "carol"),
            witness(3, "alice"),
            witness(3, "bob"),
        ],
    };

    assert_eq!(branch.score(&policy).app_witness_score, 4);
    assert!(branch.score(&policy).witness_quorum_met);
}

#[test]
fn stale_branch_is_ineligible_beyond_rewind_horizon() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 10,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let stale = BranchCandidate {
        id: "stale".into(),
        fork_epoch: 4,
        tip_epoch: 7,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(5, "alice")],
    };
    let fresh = BranchCandidate {
        id: "fresh".into(),
        fork_epoch: 6,
        tip_epoch: 8,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![],
    };
    let candidates = [stale.clone(), fresh.clone()];

    assert!(!is_branch_eligible(10, &stale, &policy));
    assert!(is_branch_eligible(10, &fresh, &policy));
    let winner =
        select_canonical_branch(10, &candidates, &policy).expect("fresh branch should win");
    assert_eq!(winner.id, fresh.id);
}

#[test]
fn digest_tiebreak_picks_lower_digest_after_commit_and_witness_ties() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 10,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let higher_digest = BranchCandidate {
        id: "higher-digest".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![witness(2, "alice")],
    };
    let lower_digest = BranchCandidate {
        id: "lower-digest".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(2, "alice")],
    };
    let candidates = [higher_digest, lower_digest.clone()];

    let winner = select_canonical_branch(3, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, lower_digest.id);
}

#[test]
fn privileged_tiebreak_beats_digest_after_depth_and_witness_ties() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 10,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let ordinary_lower_digest = BranchCandidate {
        id: "ordinary".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(2, "alice")],
    };
    let privileged_higher_digest = BranchCandidate {
        id: "privileged".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Privileged,
        tip_committer: b"z".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![witness(2, "alice")],
    };
    let candidates = [ordinary_lower_digest, privileged_higher_digest.clone()];

    let winner = select_canonical_branch(3, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, privileged_higher_digest.id);
}

#[test]
fn committer_tiebreak_beats_digest_after_priority_tie() {
    let policy = ConvergencePolicy {
        max_rewind_commits: 5,
        witness_quorum_senders_per_epoch: 10,
        witness_quorum_epochs: 2,
        max_witness_override_depth: 2,
    };
    let higher_committer_lower_digest = BranchCandidate {
        id: "higher-committer".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"z".to_vec(),
        tip_digest: digest(0x00),
        app_witnesses: vec![witness(2, "alice")],
    };
    let lower_committer_higher_digest = BranchCandidate {
        id: "lower-committer".into(),
        fork_epoch: 1,
        tip_epoch: 3,
        tip_priority: CommitOrderingPriority::Ordinary,
        tip_committer: b"a".to_vec(),
        tip_digest: digest(0xff),
        app_witnesses: vec![witness(2, "alice")],
    };
    let candidates = [
        higher_committer_lower_digest,
        lower_committer_higher_digest.clone(),
    ];

    let winner = select_canonical_branch(3, &candidates, &policy).expect("one branch should win");

    assert_eq!(winner.id, lower_committer_higher_digest.id);
}
