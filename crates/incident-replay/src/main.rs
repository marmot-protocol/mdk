//! `incident-replay` CLI: classify a Goggles export — either an
//! `agent-state.json` document or a streamed NDJSON group export — and, for a
//! fork-recovery or convergence incident, synthesize and verify a conformance
//! vector. The format is recognised from the content: any first line carrying
//! the stream's `t` discriminator is parsed under the fail-closed
//! `goggles-group-export/v1` contract; anything else is parsed as
//! `agent-state.json`. A document is read whole, so it is capped at
//! [`MAX_DOCUMENT_EXPORT_BYTES`]; a stream is parsed line by line under the
//! parser's per-line and line-count bounds, so its total size is not capped.
//!
//! Reading, format detection, and printing live here; everything about *which*
//! route an export takes is [`incident_replay::route`].
//!
//! Output is one primary line — `healthy:`, `quarantine:`, or
//! `accepted (<fidelity>, <sensitivity>)` — plus an `advisory (<label>):` line
//! for every co-occurring finding that line does not itself report. An
//! accepted incident is written owner-only as the portable vector next to its
//! `incident-scenario-artifact.v1` evidence envelope; the source export,
//! transport ciphertext, and MLS checkpoints are never copied.
//!
//! Exits 0 for any successful classification (healthy, quarantine, and accepted
//! are all valid outcomes). Exits 2 on usage, I/O, parse, or write failure, and
//! on a simulator infrastructure failure that left the export unclassified.

use std::io::{self, BufRead, BufReader, Read, Seek};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use incident_replay::{
    AgentStateExport, IncidentReplayFidelityV1, IncidentReproductionStatusV1,
    IncidentScenarioArtifactV1, IncidentSourceFormatV1, Outcome, ParseError, StreamParseError,
    parse, parse_stream, route, starts_as_stream,
};

/// Bound the in-memory `String` an `agent-state.json` document is read into,
/// and reject an oversized document before parsing can allocate from
/// attacker-controlled JSON. Streams are not held to it: they are never read
/// whole, and the stream parser bounds each line and the line count instead.
///
/// Sized from observed fleet exports — the largest was 72.9 MB as of
/// 2026-09-03 — with room left for groups to age. Deliberately not tied to the
/// audit upload ceiling: a Goggles group export is a server-side concatenation
/// of many uploads, so nothing bounds it by what one upload may be.
const MAX_DOCUMENT_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: incident-replay <agent-state.json | group-export.ndjson> [out-dir]");
        return ExitCode::from(2);
    };
    let out_dir = args.next().map(PathBuf::from);

    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", path.to_string_lossy());
            return ExitCode::from(2);
        }
    };
    let (source_format, export) = match load_export(BufReader::new(file), MAX_DOCUMENT_EXPORT_BYTES)
    {
        Ok(loaded) => loaded,
        Err(LoadError::Read(err)) => {
            eprintln!("error: cannot read {}: {err}", path.to_string_lossy());
            return ExitCode::from(2);
        }
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };

    // One primary line, then every co-occurring finding it does not itself
    // report. Routing policy — including which route runs, whether the export's
    // attested history supersedes an archetype, and what happens when a route
    // fails closed — lives in the library; this is presentation only.
    let routing = route(&export, source_format);
    // Every primary line is rendered here, so this match is the single source of
    // truth for what an operator reads. Two of the four need facts only this
    // binary has — the accepted line depends on what was written where, and an
    // infrastructure failure is a stderr line, not a verdict — so `Outcome`
    // deliberately renders none of them itself.
    let code = match &routing.outcome {
        // Producing no vector is a valid outcome, so neither of these is an
        // error exit.
        Outcome::Healthy => {
            println!("healthy: 0 vectors");
            ExitCode::SUCCESS
        }
        Outcome::Quarantine { reason } => {
            println!("quarantine: {reason}");
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

/// Parse an export in the format its first non-empty line declares. A stream
/// is parsed line by line under its own bounds; only a document is read whole,
/// so only a document is held to `max_document_bytes`.
fn load_export(
    mut reader: impl BufRead + Seek,
    max_document_bytes: u64,
) -> Result<(IncidentSourceFormatV1, AgentStateExport), LoadError> {
    let stream = starts_as_stream(&mut reader).map_err(LoadError::Read)?;
    reader.rewind().map_err(LoadError::Read)?;
    if stream {
        Ok((
            IncidentSourceFormatV1::GogglesGroupExportStream,
            parse_stream(reader)?,
        ))
    } else {
        let json = read_utf8_limited(reader, max_document_bytes).map_err(LoadError::Read)?;
        Ok((IncidentSourceFormatV1::AgentStateDocument, parse(&json)?))
    }
}

/// Why an export could not be loaded. `Read` is reported against the path by
/// the caller; the parse failures carry their own context.
#[derive(Debug, thiserror::Error)]
enum LoadError {
    #[error("{0}")]
    Read(io::Error),
    #[error(transparent)]
    Stream(#[from] StreamParseError),
    #[error(transparent)]
    Document(#[from] ParseError),
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
    use incident_replay::MAX_STREAM_LINE_BYTES;

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

    const STREAM: &str = concat!(
        r#"{"t":"manifest","schema_version":"goggles-group-export/v1"}"#,
        "\n",
        r#"{"t":"event","kind":{"type":"epoch_state_changed","epoch":2,"new_state":"stable"}}"#,
        "\n",
        r#"{"t":"eof","complete":true,"counts":{"event":1}}"#,
        "\n",
    );

    /// The document cap bounds only the document shape: a stream is bounded
    /// line by line while it is read, so its total size is not capped.
    #[test]
    fn a_stream_larger_than_the_document_cap_is_parsed() {
        let (format, export) =
            load_export(io::Cursor::new(STREAM), 16).expect("the stream is parsed");

        assert_eq!(format, IncidentSourceFormatV1::GogglesGroupExportStream);
        assert_eq!(export.events.len(), 1);
    }

    #[test]
    fn a_document_larger_than_the_document_cap_is_rejected() {
        let document = r#"{"events":[]}"#;

        let error = load_export(io::Cursor::new(document), 8).unwrap_err();

        let LoadError::Read(error) = error else {
            panic!("expected the document cap to reject the read, got {error:?}");
        };
        assert!(error.to_string().contains("exceeds 8 bytes"));
    }

    /// A first line too long to be a stream line is read as a document, and the
    /// document parser still refuses it for carrying the stream discriminator.
    #[test]
    fn a_first_line_over_the_stream_line_bound_is_read_as_a_document() {
        let mut line = br#"{"t":"manifest","pad":""#.to_vec();
        line.resize(line.len() + MAX_STREAM_LINE_BYTES as usize, b'x');
        line.extend_from_slice(b"\"}");

        let error = load_export(io::Cursor::new(line), MAX_DOCUMENT_EXPORT_BYTES).unwrap_err();

        assert!(
            matches!(error, LoadError::Document(ParseError::StreamDiscriminator)),
            "got {error:?}"
        );
    }

    /// A group export is a server-side concatenation of many uploads, so a
    /// document legitimately exceeds any single upload's ceiling. Sparse:
    /// `set_len` reserves the size without writing, and the NUL bytes it reads
    /// back are valid UTF-8.
    #[test]
    fn a_document_larger_than_one_upload_is_read() {
        let over_one_upload = 64 * 1024 * 1024 + 1;
        let file = tempfile::NamedTempFile::new().expect("temp file");
        file.as_file().set_len(over_one_upload).expect("sparse len");

        let export = read_utf8_limited(file.reopen().expect("reopen"), MAX_DOCUMENT_EXPORT_BYTES)
            .expect("export is read");

        assert_eq!(export.len() as u64, over_one_upload);
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
