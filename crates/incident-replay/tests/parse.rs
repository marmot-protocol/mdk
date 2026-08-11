//! Parser behaviour: lenient to unknown shapes, loud on invalid input.

use incident_replay::{ParseError, Verdict, classify, parse};

#[test]
fn invalid_json_is_a_parse_error() {
    assert!(parse("not json at all").is_err());
}

#[test]
fn unknown_event_kinds_and_absent_projections_are_tolerated() {
    // Real exports carry ~40 event kinds and many fields this adapter ignores;
    // unknown kinds map to a no-op and an absent derived_projections defaults
    // cleanly rather than failing the parse.
    let export =
        parse(r#"{ "events": [ { "kind": { "type": "some_future_kind", "detail": 7 } } ] }"#)
            .expect("unknown kinds and absent derived_projections parse");
    assert_eq!(classify(&export), Verdict::Healthy);
}

#[test]
fn stream_shaped_lines_are_rejected_as_documents() {
    // A stream line carrying a `t` discriminator must never be adopted by the
    // document parser as an empty (healthy) export.
    for input in [
        r#"{"t": "error", "complete": false}"#,
        r#"{"t": "manifest", "schema_version": "goggles-group-export/v1"}"#,
        r#"{"t": null}"#,
        r#"{"t": 0}"#,
        r#"{"t": {}}"#,
        r#"{"t": []}"#,
        r#"{"t": "error", "t": null}"#,
    ] {
        assert!(
            matches!(parse(input), Err(ParseError::StreamDiscriminator)),
            "stream-shaped input was not rejected: {input}"
        );
    }
}
