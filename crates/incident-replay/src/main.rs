//! `incident-replay` CLI: classify a Goggles export — either an
//! `agent-state.json` document or a streamed NDJSON group export — and, for a
//! fork-recovery or convergence incident, synthesize and verify a conformance
//! vector. The format is recognised from the content: a stream leads with its
//! `manifest` line (the `goggles-group-export/v1` contract), anything else is
//! parsed as `agent-state.json`.
//!
//! Reading, format detection, and printing live here; everything about *which*
//! route an export takes is [`incident_replay::route`].
//!
//! Output is one primary line — `healthy:`, `quarantine:`, or `accepted:` — plus
//! an `advisory (<label>):` line for every co-occurring finding that line does
//! not itself report. An accepted incident is written owner-only as the portable
//! vector next to its `incident-scenario-artifact.v1` evidence envelope; the
//! source export, transport ciphertext, and MLS checkpoints are never copied.
//!
//! Exits 0 for any successful classification (healthy, quarantine, and accepted
//! are all valid outcomes). Exits 2 on usage, I/O, parse, or write failure, and
//! on a simulator infrastructure failure that left the export unclassified.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use incident_replay::{
    IncidentReplayFidelityV1, IncidentReproductionStatusV1, IncidentScenarioArtifactV1,
    IncidentSourceFormatV1, Outcome, is_stream, parse, parse_stream, route,
};

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

    // One primary line, then every co-occurring finding it does not itself
    // report. Routing policy — including which route runs, whether the export's
    // attested history supersedes an archetype, and what happens when a route
    // fails closed — lives in the library; this is presentation only.
    let routing = route(&export, source_format);
    let code = match &routing.outcome {
        // Producing no vector is a valid outcome, so a quarantine is not an
        // error exit.
        Outcome::Healthy | Outcome::Quarantine { .. } => {
            println!("{}", routing.outcome);
            ExitCode::SUCCESS
        }
        Outcome::Accepted(artifact) => persist_or_report(artifact, out_dir.as_deref()),
        // The pipeline reached no verdict, so this one *is* an error exit.
        Outcome::InfrastructureFailure { reason } => {
            eprintln!("error: {reason}");
            ExitCode::from(2)
        }
    };
    for advisory in &routing.advisories {
        println!("{advisory}");
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

/// Write the accepted vector plus evidence artifact to `out_dir`, or describe
/// its fidelity when no directory was given.
fn persist_or_report(artifact: &IncidentScenarioArtifactV1, out_dir: Option<&Path>) -> ExitCode {
    if artifact.replay_fidelity == IncidentReplayFidelityV1::ProducerAttestedNormalizedHistory
        && artifact.reproduction_status != IncidentReproductionStatusV1::Reproduced
    {
        eprintln!("error: refusing to persist an unreproduced normalized-history artifact");
        return ExitCode::from(2);
    }
    match out_dir {
        Some(dir) => match write_artifact(artifact, dir) {
            Ok((vector_path, artifact_path)) => {
                println!(
                    "accepted ({:?}, {:?}): wrote {} and {}",
                    artifact.replay_fidelity,
                    artifact.sensitivity,
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
                "accepted ({:?}, {:?}); byte replay unavailable without sensitive local state; unavailable fields: {} (pass an out-dir to persist)",
                artifact.replay_fidelity,
                artifact.sensitivity,
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

/// Write a vector and evidence envelope owner-only. Producer-attested Scenario
/// IR may contain unredacted labels and payloads and remains confidential.
fn write_artifact(
    artifact: &IncidentScenarioArtifactV1,
    dir: &Path,
) -> std::io::Result<(PathBuf, PathBuf)> {
    fs_private::create_dir_all_private(dir)?;
    let stem = if artifact.sensitivity
        == incident_replay::IncidentArtifactSensitivityV1::ConfidentialUnredactedScenario
    {
        "confidential-normalized-incident".to_owned()
    } else {
        artifact_stem(&artifact.vector.scenario_name)
    };
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
