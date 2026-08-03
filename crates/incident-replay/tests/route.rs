//! Route composition: the verdict picks an incident route, and a route whose
//! recovery fails closed falls through to the remaining lower-precedence ones
//! rather than discarding a reproducible incident that shares the export.

use incident_replay::{
    IncidentSourceFormatV1, MEMBERSHIP_INCIDENT_NAME, Outcome, Routing, parse, route,
};

/// Route the named `agent-state.json` fixture. Every fixture here is a document
/// export, so the source format is fixed.
fn routed(name: &str) -> Routing {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let json =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read fixture {path}: {err}"));
    let export = parse(&json).unwrap_or_else(|err| panic!("parse fixture {name}: {err}"));
    route(&export, IncidentSourceFormatV1::AgentStateDocument)
}

#[test]
fn a_fail_closed_convergence_falls_through_to_a_clean_fork() {
    // The real 26a9f546 shape: one export carries a contested convergence *and* a
    // membership fork at the same epoch. Convergence outranks the fork for
    // classification, but its recovery fail-closes here (the witness boost is not
    // provably decisive), and committing to that single route threw away a
    // membership fork the simulator reproduces perfectly. Rule precedence is
    // unchanged — only a *failed* recovery falls through.
    let routing = routed("convergence-failclosed-with-clean-fork.json");

    let Outcome::Accepted(artifact) = &routing.outcome else {
        panic!("expected the fork fallback to be accepted, got {routing:?}");
    };
    assert_eq!(artifact.vector.scenario_name, MEMBERSHIP_INCIDENT_NAME);

    // The discarded higher-precedence incident is still reported: an accepted
    // fork plus a note beats a bare quarantine, but it must not hide that the
    // convergence could not be replayed.
    let labels: Vec<&str> = routing
        .advisories
        .iter()
        .map(|advisory| advisory.label)
        .collect();
    assert_eq!(labels, ["superseded route"]);
    assert!(
        routing.advisories[0]
            .detail
            .contains("quorum boost is not provably decisive"),
        "advisory should carry the convergence quarantine reason, got {:?}",
        routing.advisories[0].detail
    );
}

#[test]
fn a_fallback_that_also_fails_leaves_the_higher_quarantine_primary() {
    // Fall-through may only upgrade the outcome. When the fork route fails too,
    // the convergence quarantine stays primary — it is the higher-precedence
    // incident, and letting the fallback's reason take the headline would
    // misreport which incident the export is about. The fallback's own reason is
    // still disclosed.
    let routing = routed("convergence-failclosed-with-unusable-fork.json");

    let Outcome::Quarantine { reason } = &routing.outcome else {
        panic!("expected the convergence quarantine to stand, got {routing:?}");
    };
    assert!(
        reason.contains("quorum boost is not provably decisive"),
        "primary must stay the convergence reason, got {reason:?}"
    );
    assert_eq!(routing.advisories.len(), 1);
    assert_eq!(routing.advisories[0].label, "fallback route");
    assert!(
        routing.advisories[0]
            .detail
            .contains("snapshot was missing"),
        "advisory should name why the fork route failed, got {:?}",
        routing.advisories[0].detail
    );
}

#[test]
fn a_fail_closed_convergence_with_no_fork_reports_no_fallback() {
    // There is no lower route to enter, so "we also tried the fork route and
    // found no fork" is noise, not a finding. One primary line, nothing else.
    let routing = routed("convergence-failclosed-without-fork.json");

    assert!(matches!(routing.outcome, Outcome::Quarantine { .. }));
    assert_eq!(routing.advisories, []);
}

#[test]
fn an_accepted_vector_does_not_mask_a_halted_engine() {
    // The fork reproduces, so the primary line is the accepted vector — but
    // engine-b recorded an unrecoverable halt, and a single verdict would have
    // buried it. Rules 5 and 6 are verdict-independent for exactly this case.
    let routing = routed("fork-accepted-with-halted-engine.json");

    assert!(matches!(routing.outcome, Outcome::Accepted(_)));
    assert_eq!(routing.advisories.len(), 1);
    assert_eq!(routing.advisories[0].label, "halt");
    assert!(
        routing.advisories[0]
            .detail
            .contains("hydrate_unrecoverable_group"),
        "advisory should name the halt reason, got {:?}",
        routing.advisories[0].detail
    );
}

#[test]
fn a_repaired_halt_is_not_reported_as_an_advisory() {
    // The halt advisory is verdict-independent, so a cleared halt has to vanish
    // from the advisory path too — suppressing it only from the verdict would
    // leave the CLI printing `advisory (halt)` under a healthy primary line,
    // sending the operator after a device that already repaired itself.
    let routing = routed("healthy-halt-cleared-by-repair.json");

    assert!(matches!(routing.outcome, Outcome::Healthy));
    assert_eq!(routing.advisories, []);
}

#[test]
fn a_halt_verdict_is_not_also_reported_as_its_own_advisory() {
    // When the halt *is* the primary outcome, printing it again as an advisory
    // would just duplicate the line.
    let routing = routed("quarantine-hydrate-unrecoverable.json");

    assert!(matches!(routing.outcome, Outcome::Quarantine { .. }));
    assert_eq!(routing.advisories, []);
}
