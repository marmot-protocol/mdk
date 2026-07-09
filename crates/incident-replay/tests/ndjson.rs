//! Streaming NDJSON export parsing: format detection, the fail-closed
//! completeness contract, and end-to-end classification of a parsed stream.

use incident_replay::{
    BehindEngine, BehindMode, QuarantineReason, StreamParseError, Verdict, classify, is_stream,
    parse_stream,
};

fn load(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read fixture {path}: {err}"))
}

#[test]
fn a_complete_stream_parses_and_classifies_healthy() {
    let input = load("group-export.ndjson");
    assert!(is_stream(&input));
    let export = parse_stream(&input).expect("complete stream parses");
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
    let export = parse_stream(input).expect("stream parses");
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
        parse_stream(input),
        Err(StreamParseError::ServerReportedError { line: 3 })
    ));
}

#[test]
fn a_stream_without_a_leading_manifest_is_rejected() {
    let input = r#"{"t": "event", "kind": {"type": "epoch_confirmed", "epoch": 1}}"#;
    assert!(!is_stream(input));
    assert!(matches!(
        parse_stream(input),
        Err(StreamParseError::MissingManifest)
    ));
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
        parse_stream(input),
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
        parse_stream(input),
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
        parse_stream(input),
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
        parse_stream(input),
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
    let export = parse_stream(input).expect("unknown sections parse");
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
        parse_stream(input),
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
        parse_stream(input),
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
        parse_stream(input),
        Err(StreamParseError::Line { line: 2, .. })
    ));
}
