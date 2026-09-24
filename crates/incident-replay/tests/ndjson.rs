//! Streaming NDJSON export parsing: format detection, the fail-closed
//! completeness contract, and end-to-end classification of a parsed stream.

use incident_replay::{
    BehindEngine, BehindMode, MAX_STREAM_LINE_BYTES, MAX_STREAM_LINES, QuarantineReason,
    StreamParseError, Verdict, classify, is_stream, parse_stream,
};

fn load(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read fixture {path}: {err}"))
}

#[test]
fn a_complete_stream_parses_and_classifies_healthy() {
    let input = load("group-export.ndjson");
    assert!(is_stream(&input));
    let export = parse_stream(input.as_bytes()).expect("complete stream parses");
    assert_eq!(export.events.len(), 3);
    assert_eq!(classify(&export), Verdict::Healthy);
}

#[test]
fn an_agent_state_document_is_not_detected_as_a_stream() {
    assert!(!is_stream(&load("healthy.json")));
}

#[test]
fn a_stream_carrying_an_engine_left_behind_quarantines() {
    // The envelope fields the liveness gate reads (engine_id, wall_time_ms)
    // survive the stream parse: an engine the group advanced two epochs past
    // quarantines instead of reading as healthy.
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "event", "engine_id": "engine-a", "wall_time_ms": 1000000000000, "kind": {"type": "epoch_state_changed", "epoch": 4}}"#,
        "\n",
        r#"{"t": "event", "engine_id": "engine-b", "wall_time_ms": 1000007200000, "kind": {"type": "epoch_state_changed", "epoch": 6}}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {"event": 2}}"#,
        "\n",
    );
    let export = parse_stream(input.as_bytes()).expect("stream parses");
    assert_eq!(
        classify(&export),
        Verdict::Quarantine {
            reason: QuarantineReason::EpochDivergence {
                group_epoch: 6,
                engines: vec![BehindEngine {
                    engine_id: "engine-a".into(),
                    epoch: 4,
                    mode: BehindMode::WentDark,
                }],
            }
        }
    );
}

#[test]
fn a_stream_reporting_a_mid_stream_failure_is_rejected() {
    // Once the HTTP status is committed the server can only fail in-band: a
    // terminal error line with no eof. The parse must name that surface
    // precisely — an operator retries the export, not their network.
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#,
        "\n",
        r#"{"t": "error", "complete": false}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::ServerReportedError { line: 3 })
    ));
}

#[test]
fn a_stream_without_a_leading_manifest_is_rejected() {
    let input = r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#;
    assert!(is_stream(input));
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::MissingManifest)
    ));
}

#[test]
fn a_manifest_less_error_remnant_is_detected_as_a_stream_and_rejected() {
    // A stream truncated to just its terminal in-band error line (e.g. after an
    // immediate server abort) carries a `t` discriminator and must be classified
    // as a stream so it fail-closes with ServerReportedError instead of reading
    // as a healthy document.
    let input = r#"{"t": "error", "complete": false}"#;
    assert!(is_stream(input));
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::ServerReportedError { line: 1 })
    ));
}

#[test]
fn malformed_stream_discriminators_never_fall_back_to_the_document_parser() {
    for input in [
        r#"{"t": null}"#,
        r#"{"t": 0}"#,
        r#"{"t": {}}"#,
        r#"{"t": []}"#,
        r#"{"t": "error", "t": null}"#,
    ] {
        assert!(is_stream(input), "stream-shaped input was missed: {input}");
        assert!(
            parse_stream(input.as_bytes()).is_err(),
            "malformed stream unexpectedly parsed: {input}"
        );
    }
}

#[test]
fn a_stream_without_a_terminal_eof_is_rejected() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::MissingEof)
    ));
}

#[test]
fn a_stream_the_server_marked_incomplete_is_rejected() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "eof", "complete": false, "counts": {}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::MarkedIncomplete)
    ));
}

#[test]
fn a_section_count_shortfall_is_rejected() {
    // The server recorded two events but only one arrived: a silently short
    // stream must never read as a healthy group.
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {"event": 2}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::SectionCountMismatch { ref section, recorded: 2, received: 1 })
            if section == "event"
    ));
}

#[test]
fn a_section_the_server_never_counted_is_rejected() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "source", "id": 1}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::SectionCountMismatch { ref section, recorded: 0, received: 1 })
            if section == "source"
    ));
}

#[test]
fn unknown_sections_are_tolerated_but_still_counted() {
    // A future Goggles section type must not fail the parse — and must still
    // reconcile against the eof counts.
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "some_future_section", "detail": 7}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {"some_future_section": 1}}"#,
        "\n",
    );
    let export = parse_stream(input.as_bytes()).expect("unknown sections parse");
    assert!(export.events.is_empty());
}

#[test]
fn data_after_the_terminal_eof_is_rejected() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {}}"#,
        "\n",
        r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::LineAfterEof { line: 3 })
    ));
}

#[test]
fn a_second_manifest_is_rejected() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        r#"{"t": "eof", "complete": true, "counts": {}}"#,
        "\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::DuplicateManifest { line: 2 })
    ));
}

#[test]
fn an_invalid_line_is_rejected_with_its_line_number() {
    let input = concat!(
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        "\n",
        "not json\n",
    );
    assert!(matches!(
        parse_stream(input.as_bytes()),
        Err(StreamParseError::Line { line: 2, .. })
    ));
}

const MANIFEST_LINE: &str = "{\"t\":\"manifest\"}\n";

#[test]
fn a_line_over_the_line_bound_fails_closed() {
    let mut input = MANIFEST_LINE.as_bytes().to_vec();
    input.resize(input.len() + MAX_STREAM_LINE_BYTES as usize + 1, b' ');
    input.extend_from_slice(b"\n");

    assert!(matches!(
        parse_stream(input.as_slice()),
        Err(StreamParseError::LineTooLong { line: 2, .. })
    ));
}

/// An endless line terminates the parse only if the bound is enforced while
/// reading: buffering the whole line first would never return.
#[test]
fn an_endless_line_fails_closed_without_being_buffered() {
    let endless = std::io::Read::chain(MANIFEST_LINE.as_bytes(), std::io::repeat(b' '));

    assert!(matches!(
        parse_stream(std::io::BufReader::new(endless)),
        Err(StreamParseError::LineTooLong { line: 2, .. })
    ));
}

#[test]
fn a_line_at_the_line_bound_is_accepted() {
    let mut input = br#"{"t":"manifest"}"#.to_vec();
    input.resize(MAX_STREAM_LINE_BYTES as usize, b' ');
    input.extend_from_slice(b"\n{\"t\":\"eof\",\"complete\":true,\"counts\":{}}\n");

    parse_stream(input.as_slice()).expect("a line at the bound parses");
}

#[test]
fn a_line_that_is_not_utf8_fails_closed() {
    let mut input = MANIFEST_LINE.as_bytes().to_vec();
    input.extend_from_slice(b"{\"t\":\"source\",\"x\":\"\xff\"}\n");

    let Err(StreamParseError::Read { line, source }) = parse_stream(input.as_slice()) else {
        panic!("a non-UTF-8 line must fail as a read error");
    };
    assert_eq!(line, 2);
    assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
}

/// Blank lines are the cheapest lines to send, so they count toward the bound
/// like any other.
#[test]
fn a_stream_over_the_line_bound_fails_closed() {
    let mut input = MANIFEST_LINE.as_bytes().to_vec();
    input.resize(input.len() + MAX_STREAM_LINES, b'\n');

    assert!(matches!(
        parse_stream(input.as_slice()),
        Err(StreamParseError::TooManyLines { .. })
    ));
}
