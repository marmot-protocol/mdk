use std::env;
use std::fs;

use cgka_conformance_simulator::convergence::ConvergencePolicy;
use cgka_conformance_simulator::policy_cases::{
    PolicyCase, digest_rank, parse_policy_cases, reason_against,
};

fn main() {
    let mut format = "tamarin";
    let mut path = "formal/tamarin/policy_cases.json";
    let args: Vec<_> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                format = args.get(i).map(String::as_str).unwrap_or_else(|| {
                    eprintln!("missing value for --format");
                    std::process::exit(2);
                });
            }
            value => path = value,
        }
        i += 1;
    }

    let contents = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!("failed to read {path}: {err}");
        std::process::exit(1);
    });
    let cases = parse_policy_cases(&contents);

    match format {
        "tamarin" => print_tamarin(&cases),
        "rust-test" => print_rust_test(),
        other => {
            eprintln!("unsupported format {other:?}; expected tamarin or rust-test");
            std::process::exit(2);
        }
    }
}

fn print_tamarin(cases: &[PolicyCase]) {
    println!("/* Generated from formal/tamarin/policy_cases.json. */");
    for case in cases {
        let policy = ConvergencePolicy::from(&case.policy);
        let candidates: Vec<_> = case
            .branches
            .iter()
            .map(|branch| branch.to_candidate())
            .collect();
        let winner = candidates
            .iter()
            .find(|branch| branch.id == case.expected.branch)
            .unwrap_or_else(|| panic!("case {:?} expected branch missing", case.name));
        let loser = candidates
            .iter()
            .find(|branch| branch.id != case.expected.branch)
            .unwrap_or_else(|| panic!("case {:?} needs a loser branch", case.name));
        let winner_score = winner.score(&policy);
        let loser_score = loser.score(&policy);
        let reason = reason_against(&winner_score, &loser_score);
        assert_eq!(
            reason, case.expected.reason,
            "case {:?} expected reason mismatch",
            case.name
        );

        println!();
        println!("rule Init_Generated_Family_{}:", pascal(&case.name));
        println!("  [ Fr(~run) ]");
        println!("--[");
        println!("    Scenario(~run, '{}'),", case.scenario);
        println!("    GeneratedBoundedCase(~run, '{}'),", case.name);
        println!(
            "    GeneratedExpectedSelection(~run, '{}', '{}'),",
            case.expected.branch, case.expected.reason
        );
        println!("    SameInputSet(~run, 'alice'),");
        println!("    SameInputSet(~run, 'bob'),");
        println!("    PolicyLoaded(~run, 'group', 'generated_policy'),");
        for candidate in &candidates {
            println!("    Eligible(~run, '{}'),", candidate.id);
        }
        if reason == "quorum_tie" {
            println!("    QuorumMet(~run, '{}'),", winner.id);
            println!("    BoostAllowed(~run, '{}'),", winner.id);
        }
        for candidate in &candidates {
            let score = candidate.score(&policy);
            println!(
                "    Score(~run, '{}', '{}', '{}', '{}', '{}', '{}'),",
                candidate.id,
                depth(score.valid_commit_depth),
                depth(score.effective_commit_depth),
                quorum(score.witness_quorum_met),
                witness(score.app_witness_score),
                digest_rank(&score.tip_digest)
            );
        }
        match reason {
            "digest_tie" => println!(
                "    DigestLower(~run, '{}', '{}')",
                digest_rank(&winner_score.tip_digest),
                digest_rank(&loser_score.tip_digest)
            ),
            "quorum_tie" => println!("    QuorumTieCase(~run, '{}', '{}')", winner.id, loser.id),
            "witness_score_tie" => println!(
                "    ScoreGreater(~run, '{}', '{}')",
                witness(winner_score.app_witness_score),
                witness(loser_score.app_witness_score)
            ),
            _ => println!(
                "    ScoreGreater(~run, '{}', '{}')",
                depth(winner_score.effective_commit_depth),
                depth(loser_score.effective_commit_depth)
            ),
        }
        println!("  ]->");
        println!("  [");
        println!("    Compare(~run, '{}', '{}'),", winner.id, loser.id);
        println!("    Compare(~run, '{}', '{}'),", loser.id, winner.id);
        println!("    View(~run, 'alice', '{}', '{}'),", winner.id, loser.id);
        println!("    View(~run, 'bob', '{}', '{}'),", loser.id, winner.id);
        println!("    !PolicyLoadedState(~run),");
        for candidate in &candidates {
            println!("    !EligibleState(~run, '{}'),", candidate.id);
        }
        if reason == "quorum_tie" {
            println!("    !BoostAllowedState(~run, '{}'),", winner.id);
        }
        for candidate in &candidates {
            let score = candidate.score(&policy);
            println!(
                "    !ScoreState(~run, '{}', '{}', '{}', '{}', '{}', '{}'),",
                candidate.id,
                depth(score.valid_commit_depth),
                depth(score.effective_commit_depth),
                quorum(score.witness_quorum_met),
                witness(score.app_witness_score),
                digest_rank(&score.tip_digest)
            );
        }
        match reason {
            "digest_tie" => println!(
                "    !DigestLtState(~run, '{}', '{}')",
                digest_rank(&winner_score.tip_digest),
                digest_rank(&loser_score.tip_digest)
            ),
            "quorum_tie" => println!(
                "    !QuorumTieCaseState(~run, '{}', '{}')",
                winner.id, loser.id
            ),
            "witness_score_tie" => println!(
                "    !GtState(~run, '{}', '{}')",
                witness(winner_score.app_witness_score),
                witness(loser_score.app_witness_score)
            ),
            _ => println!(
                "    !GtState(~run, '{}', '{}')",
                depth(winner_score.effective_commit_depth),
                depth(loser_score.effective_commit_depth)
            ),
        }
        println!("  ]");
    }

    for case in cases {
        println!();
        println!("lemma generated_{}_executable:", case.name);
        println!("  exists-trace");
        println!("  \"Ex run #i #j.");
        println!("      GeneratedBoundedCase(run, '{}') @ #i", case.name);
        println!(
            "    & Selected(run, 'alice', '{}', '{}') @ #j\"",
            case.expected.branch, case.expected.reason
        );
    }
}

fn print_rust_test() {
    println!(
        "use cgka_conformance_simulator::convergence::{{ConvergencePolicy, select_canonical_branch}};"
    );
    println!(
        "use cgka_conformance_simulator::policy_cases::{{parse_policy_cases, reason_against}};"
    );
    println!();
    println!(
        "const POLICY_CASES_JSON: &str = include_str!(\"../../../formal/tamarin/policy_cases.json\");"
    );
    println!();
    println!("#[test]");
    println!("fn generated_policy_cases_match_selector() {{");
    println!("    for case in parse_policy_cases(POLICY_CASES_JSON) {{");
    println!("        let policy = ConvergencePolicy::from(&case.policy);");
    println!(
        "        let candidates: Vec<_> = case.branches.iter().map(|b| b.to_candidate()).collect();"
    );
    println!(
        "        let winner = select_canonical_branch(case.current_tip_epoch, &candidates, &policy).expect(\"case should select a branch\");"
    );
    println!("        assert_eq!(winner.id, case.expected.branch);");
    println!("        let winner_score = winner.score(&policy);");
    println!(
        "        let observed_reason = candidates.iter().filter(|b| b.id != winner.id).map(|b| reason_against(&winner_score, &b.score(&policy))).find(|r| *r == case.expected.reason).unwrap_or(\"not_winner\");"
    );
    println!("        assert_eq!(observed_reason, case.expected.reason);");
    println!("    }}");
    println!("}}");
}

fn pascal(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn depth(value: u64) -> String {
    format!("d{value}")
}

fn witness(value: usize) -> String {
    format!("w{value}")
}

fn quorum(value: bool) -> &'static str {
    if value { "qyes" } else { "qno" }
}
