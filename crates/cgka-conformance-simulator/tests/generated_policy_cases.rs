use cgka_conformance_simulator::convergence::{
    BranchCandidate, ConvergencePolicy, select_canonical_branch,
};
use cgka_conformance_simulator::policy_cases::{parse_policy_cases, reason_against};

const POLICY_CASES_JSON: &str = include_str!("../../../formal/tamarin/policy_cases.json");

#[test]
fn generated_policy_cases_match_selector() {
    for case in parse_policy_cases(POLICY_CASES_JSON) {
        let policy = ConvergencePolicy::from(&case.policy);
        let candidates: Vec<BranchCandidate> = case
            .branches
            .iter()
            .map(|branch| branch.to_candidate())
            .collect();

        for ordered_candidates in candidate_orders(&candidates) {
            let winner =
                select_canonical_branch(case.current_tip_epoch, &ordered_candidates, &policy)
                    .unwrap_or_else(|| panic!("case {:?} should select a branch", case.name));

            assert_eq!(
                winner.id,
                case.expected.branch,
                "case {:?} selected wrong branch for candidate order {:?}",
                case.name,
                candidate_ids(&ordered_candidates)
            );

            let winner_score = winner.score(&policy);
            let observed_reason = ordered_candidates
                .iter()
                .filter(|branch| branch.id != winner.id)
                .map(|branch| reason_against(&winner_score, &branch.score(&policy)))
                .find(|reason| *reason == case.expected.reason)
                .unwrap_or("not_winner");
            assert_eq!(
                observed_reason,
                case.expected.reason,
                "case {:?} selected with wrong reason for candidate order {:?}",
                case.name,
                candidate_ids(&ordered_candidates)
            );
        }
    }
}

#[test]
fn generated_priority_tie_matches_selector_before_digest() {
    assert_named_pre_digest_case("priority_tie", "privileged", "priority_tie");
}

#[test]
fn generated_committer_tie_matches_selector_before_digest() {
    assert_named_pre_digest_case("committer_tie", "lower_committer", "committer_tie");
}

fn assert_named_pre_digest_case(name: &str, expected_branch: &str, expected_reason: &str) {
    let case = parse_policy_cases(POLICY_CASES_JSON)
        .into_iter()
        .find(|case| case.name == name)
        .unwrap_or_else(|| panic!("missing generated policy case {name:?}"));
    let policy = ConvergencePolicy::from(&case.policy);
    let candidates: Vec<BranchCandidate> = case
        .branches
        .iter()
        .map(|branch| branch.to_candidate())
        .collect();
    let winner = select_canonical_branch(case.current_tip_epoch, &candidates, &policy)
        .expect("named case selects a branch");
    let loser = candidates
        .iter()
        .find(|candidate| candidate.id != winner.id)
        .expect("named case has a loser");

    assert_eq!(winner.id, expected_branch);
    assert_eq!(
        reason_against(&winner.score(&policy), &loser.score(&policy)),
        expected_reason
    );
    assert!(
        winner.tip_digest > loser.tip_digest,
        "digest must favor the loser so the preceding rule is proven decisive"
    );
}

fn candidate_orders(candidates: &[BranchCandidate]) -> Vec<Vec<BranchCandidate>> {
    let mut orders = vec![candidates.to_vec()];
    let mut reversed = candidates.to_vec();
    reversed.reverse();
    if reversed != orders[0] {
        orders.push(reversed);
    }
    if candidates.len() > 2 {
        let mut rotated = candidates.to_vec();
        rotated.rotate_left(1);
        if !orders.contains(&rotated) {
            orders.push(rotated);
        }
    }
    orders
}

fn candidate_ids(candidates: &[BranchCandidate]) -> Vec<&str> {
    candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect()
}
