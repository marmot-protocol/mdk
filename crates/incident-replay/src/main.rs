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

use incident_replay::{
    AgentStateExport, ForkCommitKind, IncidentScenarioArtifactV1, IncidentSourceFormatV1,
    QuarantineReason, Verdict, accept, accept_convergence, accept_exact_history,
    archetype_artifact, classify, import_exact_history, is_stream, liveness_advisory, parse,
    parse_stream, recover_convergence, recover_fork,
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
    let stream = is_stream(&json);
    let source_format = if stream {
        IncidentSourceFormatV1::GogglesGroupExportStream
    } else {
        IncidentSourceFormatV1::AgentStateDocument
    };
    let export = if stream {
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
        Verdict::ForkRecovery => run_fork_recovery(&export, source_format, out_dir.as_deref()),
        Verdict::Healthy => {
            println!("healthy: 0 vectors");
            ExitCode::SUCCESS
        }
        Verdict::ConvergenceSelected => run_convergence(&export, source_format, out_dir.as_deref()),
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

fn run_fork_recovery(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    out_dir: Option<&Path>,
) -> ExitCode {
    match import_exact_history(export, source_format) {
        Ok(Some(artifact)) => {
            return match accept_exact_history(artifact) {
                Ok(artifact) => persist_or_report(&artifact, out_dir),
                Err(error) => quarantine(&error),
            };
        }
        Ok(None) => {}
        Err(error) => return quarantine(&error),
    }
    let fork = match recover_fork(export) {
        Ok(fork) => fork,
        Err(err) => return quarantine(&err),
    };
    let name = match fork.commit {
        ForkCommitKind::GroupData => INCIDENT_NAME,
        ForkCommitKind::Membership => MEMBERSHIP_INCIDENT_NAME,
    };
    match accept(&fork, name) {
        Ok(vector) => match archetype_artifact(export, source_format, vector) {
            Ok(artifact) => persist_or_report(&artifact, out_dir),
            Err(error) => quarantine(&error),
        },
        Err(err) => quarantine(&err),
    }
}

fn run_convergence(
    export: &AgentStateExport,
    source_format: IncidentSourceFormatV1,
    out_dir: Option<&Path>,
) -> ExitCode {
    match import_exact_history(export, source_format) {
        Ok(Some(artifact)) => {
            return match accept_exact_history(artifact) {
                Ok(artifact) => persist_or_report(&artifact, out_dir),
                Err(error) => quarantine(&error),
            };
        }
        Ok(None) => {}
        Err(error) => return quarantine(&error),
    }
    let conv = match recover_convergence(export) {
        Ok(conv) => conv,
        Err(err) => return quarantine(&err),
    };
    match accept_convergence(&conv, CONVERGENCE_NAME) {
        Ok(vector) => match archetype_artifact(export, source_format, vector) {
            Ok(artifact) => persist_or_report(&artifact, out_dir),
            Err(error) => quarantine(&error),
        },
        Err(err) => quarantine(&err),
    }
}

/// Report a fail-closed quarantine and exit cleanly: producing no vector is a
/// valid outcome, so it is not an error exit.
fn quarantine(reason: &dyn std::fmt::Display) -> ExitCode {
    println!("quarantine: {reason}");
    ExitCode::SUCCESS
}

/// Write the accepted vector plus evidence artifact to `out_dir`, or describe
/// its fidelity when no directory was given.
fn persist_or_report(artifact: &IncidentScenarioArtifactV1, out_dir: Option<&Path>) -> ExitCode {
    match out_dir {
        Some(dir) => match write_artifact(artifact, dir) {
            Ok((vector_path, artifact_path)) => {
                println!(
                    "accepted ({:?}): wrote {} and {}",
                    artifact.replay_fidelity,
                    vector_path.display(),
                    artifact_path.display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("error: cannot write incident artifacts: {err}");
                ExitCode::from(2)
            }
        },
        None => {
            println!(
                "accepted ({:?}): {}; exact byte replay unavailable without sensitive local state; unavailable fields: {} (pass an out-dir to persist)",
                artifact.replay_fidelity,
                artifact.vector.scenario_name,
                artifact
                    .unavailable_fields
                    .iter()
                    .map(|field| field.field.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            ExitCode::SUCCESS
        }
    }
}

/// Write a shareable vector and its evidence envelope owner-only. No source
/// export, transport bytes, or MLS checkpoint is copied into either file.
fn write_artifact(
    artifact: &IncidentScenarioArtifactV1,
    dir: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    fs_private::create_dir_all_private(dir)?;
    let stem = artifact_stem(&artifact.vector.scenario_name);
    let vector_path = dir.join(format!("{stem}.v1.json"));
    let artifact_path = dir.join(format!("{stem}.incident.v1.json"));
    let vector_json = serde_json::to_string_pretty(&artifact.vector).expect("vector serializes");
    let artifact_json = serde_json::to_string_pretty(artifact).expect("artifact serializes");
    fs_private::write_private(&vector_path, format!("{vector_json}\n").as_bytes())?;
    fs_private::write_private(&artifact_path, format!("{artifact_json}\n").as_bytes())?;
    Ok((vector_path, artifact_path))
}

fn artifact_stem(scenario_name: &str) -> String {
    let raw_stem = scenario_name
        .rsplit_once('/')
        .map_or(scenario_name, |(stem, _version)| stem);
    let mut stem = raw_stem
        .chars()
        .take(96)
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => character,
            _ => '-',
        })
        .collect::<String>();
    if stem.is_empty() || stem == "." || stem == ".." {
        stem = "incident".into();
    }
    stem
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

    #[test]
    fn artifact_stem_is_one_safe_path_component() {
        let stem = artifact_stem("../../outside/incident/v1");
        assert!(!stem.contains('/'));
        assert!(!stem.contains('\\'));
        assert_ne!(stem, ".");
        assert_ne!(stem, "..");
    }
}
