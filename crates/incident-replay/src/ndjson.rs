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
//! The stream is read line by line from a [`BufRead`], never whole, so its
//! size is not capped. Hostile input is bounded instead, fail-closed: no line
//! may exceed [`MAX_STREAM_LINE_BYTES`] (enforced while reading, before the
//! line is buffered in full) and the stream may not exceed
//! [`MAX_STREAM_LINES`], which bounds the parsed events and section counts.
//!
//! Like [`crate::export`], the line model is lenient to growth: unknown `t`
//! sections and unknown fields are tolerated (they still participate in the
//! count check), so the parser survives Goggles adding data without a schema
//! bump.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Read};

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

/// The longest stream line accepted, in bytes, excluding its `\n` terminator.
/// Bounds what one attacker-controlled line can allocate before it is parsed.
/// About 4x the longest line observed in a real export (3.7 MB, in a 741 MB
/// export), so a legitimately large line is never rejected.
pub const MAX_STREAM_LINE_BYTES: u64 = 16 * 1024 * 1024;

/// The most lines a stream may carry, blank lines included. Every parsed event
/// and every attacker-named section counted from an unknown `t` takes a line,
/// so this bounds both. About 60x the line count of the largest real export
/// (269k lines in 741 MB).
pub const MAX_STREAM_LINES: usize = 16 * 1024 * 1024;

/// Whether `input` is a Goggles NDJSON group-export stream. A stream line is
/// discriminated by a `t` field; checking whether the first non-empty line
/// carries a `t` discriminator prevents a manifest-less or corrupt stream from
/// falling back to the document parser and fail-opening as a healthy export.
pub fn is_stream(input: &str) -> bool {
    let Some(first_line) = input.lines().find(|line| !line.trim().is_empty()) else {
        return false;
    };
    serde_json::from_str::<BTreeMap<String, serde::de::IgnoredAny>>(first_line)
        .is_ok_and(|object| object.contains_key("t"))
}

/// [`is_stream`] for a reader: whether its first non-empty line carries the
/// stream's `t` discriminator, reading at most [`MAX_STREAM_LINE_BYTES`] of any
/// line and at most [`MAX_STREAM_LINES`] lines. Input that exceeds either bound,
/// or is not UTF-8, cannot open a stream, so the answer is `false` and the
/// caller's document parser, bounded by its own cap, rejects what it cannot
/// adopt.
pub fn starts_as_stream(input: &mut impl BufRead) -> io::Result<bool> {
    let mut buffer = Vec::new();
    for _ in 0..MAX_STREAM_LINES {
        if !read_bounded_line(input, &mut buffer)? {
            break;
        }
        if buffer.len() as u64 > MAX_STREAM_LINE_BYTES {
            return Ok(false);
        }
        let Ok(line) = std::str::from_utf8(&buffer) else {
            return Ok(false);
        };
        if !line.trim().is_empty() {
            return Ok(is_stream(line));
        }
    }
    Ok(false)
}

/// Parse a streamed group export into the same [`AgentStateExport`] the rest of
/// the pipeline consumes. Fails closed on any break of the streaming contract.
pub fn parse_stream(mut input: impl BufRead) -> Result<AgentStateExport, StreamParseError> {
    let mut events = Vec::new();
    let mut received: BTreeMap<String, u64> = BTreeMap::new();
    let mut eof: Option<EofLine> = None;
    let mut saw_manifest = false;
    let mut buffer = Vec::new();
    let mut number = 0;

    while read_bounded_line(&mut input, &mut buffer).map_err(|source| StreamParseError::Read {
        line: number + 1,
        source,
    })? {
        number += 1;
        if number > MAX_STREAM_LINES {
            return Err(StreamParseError::TooManyLines {
                limit: MAX_STREAM_LINES,
            });
        }
        if buffer.len() as u64 > MAX_STREAM_LINE_BYTES {
            return Err(StreamParseError::LineTooLong {
                line: number,
                limit: MAX_STREAM_LINE_BYTES,
            });
        }
        let line = std::str::from_utf8(&buffer).map_err(|error| StreamParseError::Read {
            line: number,
            source: io::Error::new(io::ErrorKind::InvalidData, error),
        })?;
        if line.trim().is_empty() {
            continue;
        }
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
            if t == ERROR {
                return Err(StreamParseError::ServerReportedError { line: number });
            }
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
        normalized_scenario_history: None,
    })
}

/// Read the next line into `buffer` without its `\n` or `\r\n` terminator,
/// matching [`str::lines`]; `false` at end of input. The read stops just past
/// [`MAX_STREAM_LINE_BYTES`] plus room for a `\r\n`, so an oversized line shows
/// as a longer buffer, never by holding the whole line.
fn read_bounded_line(input: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<bool> {
    buffer.clear();
    if input
        .by_ref()
        .take(MAX_STREAM_LINE_BYTES + 2)
        .read_until(b'\n', buffer)?
        == 0
    {
        return Ok(false);
    }
    if buffer.ends_with(b"\n") {
        buffer.pop();
        if buffer.ends_with(b"\r") {
            buffer.pop();
        }
    }
    Ok(true)
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
    /// The stream could not be read, or a line is not UTF-8.
    #[error("line {line} could not be read: {source}")]
    Read { line: usize, source: io::Error },
    #[error("line {line} is not valid stream JSON: {source}")]
    Line {
        line: usize,
        source: serde_json::Error,
    },
    #[error("line {line} exceeds {limit} bytes")]
    LineTooLong { line: usize, limit: u64 },
    #[error("stream exceeds {limit} lines")]
    TooManyLines { limit: usize },
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
