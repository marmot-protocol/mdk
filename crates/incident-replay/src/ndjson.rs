//! Parser for the Goggles streaming NDJSON group export
//! (`goggles-group-export/v1`).
//!
//! The stream is a sequence of JSON lines discriminated by a `t` field: a
//! leading `manifest`, data sections (`event`, `source`, `delivery_artifact`,
//! …), and a terminal `eof` that carries `complete` plus per-section counts.
//! Completeness is enforced here, fail-closed: the parse succeeds only when the
//! stream ends with `eof`, the server marked it `complete`, every section
//! count matches what was actually received, and no in-band `error` line (the
//! server's only failure surface once the HTTP status is committed) appeared.
//! That replaces the `derived_projections.has_more` truncation signal of the
//! `agent-state.json` shape — the stream is uncapped, so the parsed export
//! carries empty projections and the classifier's truncation gate is vacuously
//! satisfied.
//!
//! Like [`crate::export`], the line model is lenient to growth: unknown `t`
//! sections and unknown fields are tolerated (they still participate in the
//! count check), so the parser survives Goggles adding data without a schema
//! bump.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::export::{AgentStateExport, AuditEvent};

/// The `t` discriminator of the leading manifest line.
const MANIFEST: &str = "manifest";
/// The `t` discriminator of the terminal completeness line.
const EOF: &str = "eof";
/// The `t` discriminator of forensic event lines.
const EVENT: &str = "event";
/// The `t` discriminator of the in-band failure line: once the HTTP status is
/// committed the server can only signal a mid-stream failure in-band, as a
/// terminal `{"t":"error","complete":false}` line with no `eof`.
const ERROR: &str = "error";

/// Whether `input` is a Goggles NDJSON group-export stream. The v1 contract
/// requires the first line to be the manifest, so this checks exactly that; an
/// `agent-state.json` document (one JSON object, no `t` discriminator) is never
/// mistaken for a stream.
pub fn is_stream(input: &str) -> bool {
    let Some(first_line) = input.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    matches!(
        serde_json::from_str::<TagProbe>(first_line),
        Ok(TagProbe { t }) if t == MANIFEST
    )
}

/// Parse a streamed group export into the same [`AgentStateExport`] the rest of
/// the pipeline consumes. Fails closed on any break of the streaming contract.
pub fn parse_stream(input: &str) -> Result<AgentStateExport, StreamParseError> {
    let mut events = Vec::new();
    let mut received: BTreeMap<String, u64> = BTreeMap::new();
    let mut eof: Option<EofLine> = None;
    let mut saw_manifest = false;

    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        if eof.is_some() {
            return Err(StreamParseError::LineAfterEof { line: number });
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|source| StreamParseError::Line {
                line: number,
                source,
            })?;
        let TagProbe { t } =
            TagProbe::deserialize(&value).map_err(|source| StreamParseError::Line {
                line: number,
                source,
            })?;

        if !saw_manifest {
            if t != MANIFEST {
                return Err(StreamParseError::MissingManifest);
            }
            saw_manifest = true;
            continue;
        }
        match t.as_str() {
            MANIFEST => return Err(StreamParseError::DuplicateManifest { line: number }),
            ERROR => return Err(StreamParseError::ServerReportedError { line: number }),
            EOF => {
                eof = Some(EofLine::deserialize(&value).map_err(|source| {
                    StreamParseError::Line {
                        line: number,
                        source,
                    }
                })?);
            }
            EVENT => {
                events.push(AuditEvent::deserialize(&value).map_err(|source| {
                    StreamParseError::Line {
                        line: number,
                        source,
                    }
                })?);
                *received.entry(t).or_default() += 1;
            }
            _ => *received.entry(t).or_default() += 1,
        }
    }

    if !saw_manifest {
        return Err(StreamParseError::MissingManifest);
    }
    let eof = eof.ok_or(StreamParseError::MissingEof)?;
    if !eof.complete {
        return Err(StreamParseError::MarkedIncomplete);
    }
    verify_counts(&eof.counts, &received)?;

    Ok(AgentStateExport {
        events,
        derived_projections: Default::default(),
    })
}

/// Compare the server's per-section counts against what actually arrived, in
/// both directions: a recorded section that fell short *and* a received
/// section the server never counted both mean the stream cannot be trusted.
fn verify_counts(
    recorded: &BTreeMap<String, u64>,
    received: &BTreeMap<String, u64>,
) -> Result<(), StreamParseError> {
    let sections = recorded.keys().chain(received.keys());
    for section in sections {
        let want = recorded.get(section).copied().unwrap_or(0);
        let got = received.get(section).copied().unwrap_or(0);
        if want != got {
            return Err(StreamParseError::SectionCountMismatch {
                section: section.clone(),
                recorded: want,
                received: got,
            });
        }
    }
    Ok(())
}

/// The `t` discriminator of one stream line.
#[derive(Deserialize)]
struct TagProbe {
    t: String,
}

/// The terminal completeness line. `complete` and `counts` are contractual, so
/// their absence fails the parse rather than defaulting.
#[derive(Deserialize)]
struct EofLine {
    complete: bool,
    counts: BTreeMap<String, u64>,
}

/// Why a streamed export could not be parsed. Every variant means the stream
/// broke the `goggles-group-export/v1` contract; none of them may be classified
/// around, because a short stream would otherwise read as a healthy group.
#[derive(Debug, thiserror::Error)]
pub enum StreamParseError {
    #[error("line {line} is not valid stream JSON: {source}")]
    Line {
        line: usize,
        source: serde_json::Error,
    },
    #[error("stream does not begin with the manifest line")]
    MissingManifest,
    #[error("line {line} is a second manifest")]
    DuplicateManifest { line: usize },
    #[error("stream ended without the terminal eof line")]
    MissingEof,
    #[error("line {line}: the server reported a mid-stream failure (in-band error line)")]
    ServerReportedError { line: usize },
    #[error("line {line} follows the terminal eof line")]
    LineAfterEof { line: usize },
    #[error("server marked the stream incomplete (eof.complete = false)")]
    MarkedIncomplete,
    #[error("section `{section}` count mismatch: server recorded {recorded}, received {received}")]
    SectionCountMismatch {
        section: String,
        recorded: u64,
        received: u64,
    },
}
