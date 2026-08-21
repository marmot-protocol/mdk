//! Parser behaviour: lenient to unknown shapes, loud on invalid input.

use incident_replay::{ParseError, Verdict, classify, parse};

#[test]
fn invalid_json_is_a_parse_error() {
    assert!(parse("not json at all").is_err());
}

#[test]
fn invalid_document_errors_keep_the_source_position() {
    let Err(ParseError::Json(source)) = parse("{\n  \"events\": [\n}") else {
        panic!("invalid document did not return its JSON error");
    };
    assert_eq!(source.line(), 3);
    assert_eq!(source.column(), 1);
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
        // The discriminator is decisive even beside recognized export fields:
        // a stream line must never be read as a document.
        r#"{"t": "event", "events": []}"#,
    ] {
        assert!(
            matches!(parse(input), Err(ParseError::StreamDiscriminator)),
            "stream-shaped input was not rejected: {input}"
        );
    }
}

#[test]
fn documents_with_no_recognized_field_are_rejected() {
    // Every modelled field defaults, so without this gate any JSON object at all
    // would deserialize into an empty export and print a healthy verdict — the
    // worst failure a forensic tool has, a clean bill of health for a document
    // that was never an export.
    for input in [
        "{}",
        r#"{"name": "mdk", "version": "0.1.0", "dependencies": {}}"#,
        // A version string is not evidence of contents: an export that carries
        // no modelled section carries nothing to classify.
        r#"{"schema_version": "marmot-agent-state/v1"}"#,
    ] {
        assert!(
            matches!(parse(input), Err(ParseError::UnrecognizedDocument)),
            "unrecognized document was not rejected: {input}"
        );
    }
}

#[test]
fn the_rejection_message_names_what_was_expected_and_quotes_nothing() {
    // The rejected document is operator-supplied forensic input; the error tells
    // the operator what an export looks like without echoing a byte of it.
    let error = parse(r#"{"relay": "wss://relay.example"}"#)
        .expect_err("an unrecognized document is rejected")
        .to_string();

    assert!(error.contains("events"), "unhelpful message: {error}");
    assert!(
        !error.contains("relay"),
        "message echoed the document: {error}"
    );
}

#[test]
fn any_single_recognized_field_is_enough_to_parse() {
    // Sparse exports are legitimate: the marker proves the document is an
    // export, not that it is a complete one.
    for input in [
        r#"{"events": []}"#,
        r#"{"derived_projections": {}}"#,
        r#"{"normalized_scenario_history": null}"#,
    ] {
        let export = parse(input).unwrap_or_else(|err| panic!("sparse export {input}: {err}"));
        assert_eq!(classify(&export), Verdict::Healthy);
    }
}

#[test]
fn unknown_top_level_fields_stay_tolerated() {
    // Forward compatibility is the whole point of the lenient model: a newer
    // Goggles export growing sections this adapter does not read must still
    // parse, and the marker gate must not turn into a schema check.
    let export = parse(
        r#"{
            "schema_version": "marmot-agent-state/v1",
            "events": [],
            "derived_projections": {},
            "normalized_scenario_history": null,
            "some_future_section": { "rows": [1, 2, 3] }
        }"#,
    )
    .expect("an export with unknown extra fields parses");

    assert_eq!(classify(&export), Verdict::Healthy);
}

#[test]
fn documents_that_are_not_json_objects_are_rejected() {
    // An export is an object. `[]` is the sharp case: serde accepts a struct in
    // its sequence form too, so an empty array deserialized into exactly the
    // same empty, healthy export an empty object did.
    for input in ["[]", "[[], {}, null]", r#""agent-state""#, "7", "null"] {
        assert!(
            matches!(parse(input), Err(ParseError::UnrecognizedDocument)),
            "non-object document was not rejected: {input}"
        );
    }
}
