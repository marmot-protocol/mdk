//! `incident-replay` CLI: classify a Goggles export — either an
//! `agent-state.json` document or a streamed NDJSON group export — and, for a
//! fork-recovery or convergence incident, synthesize and verify a conformance
//! vector. The format is recognised from the content: a stream leads with its
//! `manifest` line (the `goggles-group-export/v1` contract), anything else is
//! parsed as `agent-state.json`.
//!
//! Prints a human-readable outcome and exits 0 for any successful classification
//! (healthy, quarantine, and accepted are all valid outcomes). Exits 2 on usage,
//! I/O, or parse failure.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cgka_conformance_simulator::VectorFixture;
use incident_replay::{
    AgentStateExport, ForkCommitKind, QuarantineReason, Verdict, accept, accept_convergence,
    classify, is_stream, liveness_advisory, parse, parse_stream, recover_convergence, recover_fork,
};

/// Vector name for a group-metadata fork-recovery incident.
const INCIDENT_NAME: &str = "fork-recovery-incident/v1";
/// Vector name for a membership/admin fork-recovery incident (a distinct shape,
/// so a distinct name and file — it must not overwrite the group-data vector).
const MEMBERSHIP_INCIDENT_NAME: &str = "membership-fork-recovery-incident/v1";
/// Vector name for a convergence incident.
const CONVERGENCE_NAME: &str = "convergence-incident/v1";
/// Match the workspace's audit-artifact ceiling and reject oversized forensic
/// input before parsing can allocate from attacker-controlled JSON/NDJSON.
const MAX_INCIDENT_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: incident-replay <agent-state.json | group-export.ndjson> [out-dir]");
        return ExitCode::from(2);
    };
    let out_dir = args.next().map(PathBuf::from);

    let json = match read_incident_export(Path::new(&path)) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", path.to_string_lossy());
            return ExitCode::from(2);
        }
    };
    let export = if is_stream(&json) {
        match parse_stream(&json) {
            Ok(export) => export,
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::from(2);
            }
        }
    } else {
        match parse(&json) {
            Ok(export) => export,
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::from(2);
            }
        }
    };

    let verdict = classify(&export);
    // A co-occurring liveness incident (rule 5) loses the single verdict to any
    // higher-precedence incident, so surface it as a secondary advisory — unless
    // it *is* the primary verdict, where it is already printed.
    let liveness_is_primary = matches!(
        &verdict,
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence { .. }
        }
    );
    let code = match verdict {
        Verdict::ForkRecovery => run_fork_recovery(&export, out_dir.as_deref()),
        Verdict::Healthy => {
            println!("healthy: 0 vectors");
            ExitCode::SUCCESS
        }
        Verdict::ConvergenceSelected => run_convergence(&export, out_dir.as_deref()),
        Verdict::Quarantine { reason } => quarantine(&reason),
    };
    if !liveness_is_primary && let Some(reason) = liveness_advisory(&export) {
        println!("advisory (liveness): {reason}");
    }
    code
}

fn read_incident_export(path: &Path) -> io::Result<String> {
    read_utf8_limited(std::fs::File::open(path)?, MAX_INCIDENT_EXPORT_BYTES)
}

fn read_utf8_limited(reader: impl Read, max_bytes: u64) -> io::Result<String> {
    let mut bytes = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("incident export exceeds {max_bytes} bytes"),
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn run_fork_recovery(export: &AgentStateExport, out_dir: Option<&Path>) -> ExitCode {
    let fork = match recover_fork(export) {
        Ok(fork) => fork,
        Err(err) => return quarantine(&err),
    };
    let name = match fork.commit {
        ForkCommitKind::GroupData => INCIDENT_NAME,
        ForkCommitKind::Membership => MEMBERSHIP_INCIDENT_NAME,
    };
    match accept(&fork, name) {
        Ok(vector) => persist_or_report(&vector, out_dir),
        Err(err) => quarantine(&err),
    }
}

fn run_convergence(export: &AgentStateExport, out_dir: Option<&Path>) -> ExitCode {
    let conv = match recover_convergence(export) {
        Ok(conv) => conv,
        Err(err) => return quarantine(&err),
    };
    match accept_convergence(&conv, CONVERGENCE_NAME) {
        Ok(vector) => persist_or_report(&vector, out_dir),
        Err(err) => quarantine(&err),
    }
}

/// Report a fail-closed quarantine and exit cleanly: producing no vector is a
/// valid outcome, so it is not an error exit.
fn quarantine(reason: &dyn std::fmt::Display) -> ExitCode {
    println!("quarantine: {reason}");
    ExitCode::SUCCESS
}

/// Write the accepted vector to `out_dir`, or print it when no dir was given.
fn persist_or_report(vector: &VectorFixture, out_dir: Option<&Path>) -> ExitCode {
    match out_dir {
        Some(dir) => match write_vector(vector, dir) {
            Ok(path) => {
                println!("accepted: wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: cannot write vector: {err}");
                ExitCode::from(2)
            }
        },
        None => {
            println!(
                "accepted: {} (pass an out-dir to persist)",
                vector.scenario_name
            );
            ExitCode::SUCCESS
        }
    }
}

/// Write a vector as `<dir>/<name>.v1.json` (creating `dir`), returning the path.
fn write_vector(vector: &VectorFixture, dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let stem = vector
        .scenario_name
        .rsplit_once('/')
        .map_or(vector.scenario_name.as_str(), |(stem, _version)| stem);
    let path = dir.join(format!("{stem}.v1.json"));
    let json = serde_json::to_string_pretty(vector).expect("vector serializes");
    std::fs::write(&path, format!("{json}\n"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_input_past_the_limit() {
        let error = read_utf8_limited(io::Cursor::new(b"0123456789"), 8).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 8 bytes"));
    }

    #[test]
    fn bounded_reader_accepts_utf8_at_the_limit() {
        assert_eq!(
            read_utf8_limited(io::Cursor::new("ciao".as_bytes()), 4).unwrap(),
            "ciao"
        );
    }
}
