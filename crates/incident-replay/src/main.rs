//! `incident-replay` CLI: classify a Goggles `agent-state.json` export and, for a
//! fork-recovery incident, synthesize and verify a conformance vector.
//!
//! Prints a human-readable outcome and exits 0 for any successful classification
//! (healthy, quarantine, and accepted are all valid outcomes). Exits 2 on usage,
//! I/O, or parse failure.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cgka_conformance_simulator::VectorFixture;
use incident_replay::{
    AgentStateExport, Verdict, accept, accept_convergence, classify, parse, recover_convergence,
    recover_fork,
};

/// Vector name for a fork-recovery incident (one incident per export today).
const INCIDENT_NAME: &str = "fork-recovery-incident/v1";
/// Vector name for a convergence incident.
const CONVERGENCE_NAME: &str = "convergence-incident/v1";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: incident-replay <agent-state.json> [out-dir]");
        return ExitCode::from(2);
    };
    let out_dir = args.next().map(PathBuf::from);

    let json = match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", path.to_string_lossy());
            return ExitCode::from(2);
        }
    };
    let export = match parse(&json) {
        Ok(export) => export,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    match classify(&export) {
        Verdict::ForkRecovery => run_fork_recovery(&export, out_dir.as_deref()),
        Verdict::Healthy => {
            println!("healthy: 0 vectors");
            ExitCode::SUCCESS
        }
        Verdict::ConvergenceSelected => run_convergence(&export, out_dir.as_deref()),
        Verdict::Quarantine { reason } => {
            println!("quarantine: {reason:?}");
            ExitCode::SUCCESS
        }
    }
}

fn run_fork_recovery(export: &AgentStateExport, out_dir: Option<&Path>) -> ExitCode {
    let fork = match recover_fork(export) {
        Ok(fork) => fork,
        Err(err) => return quarantine(&err),
    };
    match accept(&fork, INCIDENT_NAME) {
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
