//! The CLI's printed output is the operator-facing contract, so it is pinned
//! here against the real binary rather than against an in-process rendering.
//!
//! Every primary line the CLI can print is covered, because the outcome an
//! export routes to decides *which* line the operator reads: `healthy:` and
//! `quarantine:` are rendered from the outcome alone, while `accepted` is
//! rendered from facts only the CLI has (whether an out-dir was given, and what
//! it wrote there). Pinning all of them keeps the rendering honest — a line that
//! no code path can actually produce is worse than no line at all, because it
//! reads as documentation of what the CLI does.
//!
//! End-to-end coverage for fail-closed format detection lives here for the same
//! reason: what an undetectable export must *not* print is as much a part of the
//! contract as what a classified one does.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use tempfile::NamedTempFile;

/// Run the CLI against a fixture, returning `(stdout, stderr, exit code)`.
fn run(fixture: &str) -> (String, String, i32) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture);
    let output = Command::new(env!("CARGO_BIN_EXE_incident-replay"))
        .arg(&path)
        .output()
        .unwrap_or_else(|err| panic!("run the CLI on {}: {err}", path.display()));
    (
        String::from_utf8(output.stdout).expect("stdout is utf-8"),
        String::from_utf8(output.stderr).expect("stderr is utf-8"),
        output.status.code().expect("the CLI exited normally"),
    )
}

#[test]
fn a_healthy_export_prints_the_healthy_line_and_nothing_else() {
    // A cleared halt leaves nothing to report, so this is the whole of stdout:
    // one primary line, no advisories.
    let (stdout, stderr, code) = run("healthy-halt-cleared-by-repair.json");

    assert_eq!(stdout, "healthy: 0 vectors\n");
    assert_eq!(stderr, "");
    assert_eq!(code, 0);
}

#[test]
fn a_quarantined_export_prints_the_reason_and_still_exits_zero() {
    // Producing no vector is a valid classification, not a failure, so the exit
    // code stays 0 and the reason goes to stdout with the verdict.
    let (stdout, stderr, code) = run("quarantine-hydrate-unrecoverable.json");

    assert!(
        stdout.starts_with("quarantine: "),
        "expected a quarantine primary line, got {stdout:?}"
    );
    assert!(
        stdout.contains("hydrate_unrecoverable_group"),
        "the halt reason belongs in the line the operator reads first, got {stdout:?}"
    );
    assert_eq!(stderr, "");
    assert_eq!(code, 0);
}

#[test]
fn an_accepted_export_prints_its_fidelity_not_a_bare_scenario_name() {
    // The accepted line is the one an outcome cannot render on its own: what the
    // operator needs is the artifact's fidelity and sensitivity plus what the run
    // could not cover, and with no out-dir there are no written paths to name.
    // A bare `accepted: <scenario-name>` is specifically *not* what this prints,
    // and an unreachable rendering claiming otherwise misdescribes the CLI.
    let (stdout, stderr, code) = run("replayable-membership-fork.json");

    assert!(
        stdout.starts_with("accepted ("),
        "expected the fidelity-carrying accepted line, got {stdout:?}"
    );
    assert!(
        !stdout.contains("accepted: "),
        "the CLI never prints a bare `accepted:` line, got {stdout:?}"
    );
    assert!(
        stdout.contains("pass an out-dir to persist"),
        "an accepted run with no out-dir should say how to persist it, got {stdout:?}"
    );
    assert_eq!(stderr, "");
    assert_eq!(code, 0);
}

#[test]
fn a_manifest_less_error_remnant_never_classifies_as_healthy() {
    let mut input = NamedTempFile::new().expect("create export");
    input
        .write_all(br#"{"t":"error","complete":false}"#)
        .expect("write export");
    let output = Command::new(env!("CARGO_BIN_EXE_incident-replay"))
        .arg(input.path())
        .output()
        .expect("run incident-replay");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert_eq!(output.status.code(), Some(2));
    assert!(!stdout.contains("healthy:"));
}
