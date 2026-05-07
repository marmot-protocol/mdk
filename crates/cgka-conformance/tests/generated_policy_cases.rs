use cgka_conformance::convergence::{ConvergencePolicy, select_canonical_branch};
use cgka_conformance::policy_cases::{parse_policy_cases, reason_against};

const POLICY_CASES_JSON: &str = include_str!("../../../formal/tamarin/policy_cases.json");

#[test]
fn generated_policy_cases_match_selector() {
    for case in parse_policy_cases(POLICY_CASES_JSON) {
        let policy = ConvergencePolicy::from(&case.policy);
        let candidates: Vec<_> = case
            .branches
            .iter()
            .map(|branch| branch.to_candidate())
            .collect();

        let winner = select_canonical_branch(case.current_tip_epoch, &candidates, &policy)
            .unwrap_or_else(|| panic!("case {:?} should select a branch", case.name));

        assert_eq!(
            winner.id, case.expected.branch,
            "case {:?} selected wrong branch",
            case.name
        );

        let winner_score = winner.score(&policy);
        let observed_reason = candidates
            .iter()
            .filter(|branch| branch.id != winner.id)
            .map(|branch| reason_against(&winner_score, &branch.score(&policy)))
            .find(|reason| *reason == case.expected.reason)
            .unwrap_or("not_winner");
        assert_eq!(
            observed_reason, case.expected.reason,
            "case {:?} selected with wrong reason",
            case.name
        );
    }
}
