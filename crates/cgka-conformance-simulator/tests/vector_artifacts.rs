use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::Value;

#[test]
fn vector_manifest_artifacts_exist_and_byte_fixtures_are_well_formed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vectors = root.join("vectors");
    let manifest_path = vectors.join("manifest.v1.json");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest exists"))
            .expect("manifest JSON parses");

    assert_eq!(manifest["manifest_version"], "1");
    let entries = manifest["entries"].as_array().expect("entries is an array");
    assert!(!entries.is_empty(), "manifest should name current vectors");

    let mut manifest_artifacts = BTreeSet::new();
    for entry in entries {
        if let Some(artifact) = entry.get("artifact").and_then(Value::as_str) {
            manifest_artifacts.insert(artifact.to_string());
            assert!(
                vectors.join(artifact).exists(),
                "manifest artifact {artifact} should exist"
            );
        }
    }

    for entry in fs::read_dir(&vectors).expect("vectors dir exists") {
        let path = entry.expect("vector dir entry").path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !file_name.ends_with(".v1.json") || file_name == "manifest.v1.json" {
            continue;
        }
        assert!(
            manifest_artifacts.contains(file_name),
            "manifest should list top-level vector fixture {file_name}"
        );
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("fixture exists"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        assert!(
            fixture.get("expected_trace").is_some()
                || fixture
                    .get("expected_outcomes")
                    .and_then(Value::as_array)
                    .is_some_and(|outcomes| !outcomes.is_empty()),
            "{} should define expected_trace or expected_outcomes",
            path.display()
        );
    }

    let schema_path = vectors.join("byte-fixtures/schema.v1.json");
    let schema: Value =
        serde_json::from_str(&fs::read_to_string(schema_path).expect("byte schema exists"))
            .expect("byte schema JSON parses");
    assert_eq!(schema["title"], "Marmot byte-level vector fixture v1");

    let byte_fixture_dir = vectors.join("byte-fixtures");
    let mut byte_fixture_count = 0usize;
    for entry in fs::read_dir(&byte_fixture_dir).expect("byte fixture dir exists") {
        let entry = entry.expect("byte fixture dir entry");
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !file_name.ends_with(".v1.json") || file_name == "schema.v1.json" {
            continue;
        }
        byte_fixture_count += 1;
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("byte fixture exists"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        assert_eq!(
            fixture["fixture_version"],
            "1",
            "{} has fixture_version 1",
            path.display()
        );
        assert_eq!(
            fixture["component"]["name"],
            "marmot.transport.nostr.routing.v1",
            "{} should cover the first app-component byte vectors",
            path.display()
        );
        let hex = fixture["bytes"]["hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has bytes.hex", path.display()));
        assert_even_hex(hex, &path);
    }

    assert!(
        byte_fixture_count >= 2,
        "expected state and update byte fixtures"
    );
}

fn assert_even_hex(hex: &str, path: &Path) {
    assert!(
        hex.len().is_multiple_of(2),
        "{} hex length should be even",
        path.display()
    );
    assert!(
        hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{} hex should contain only hex digits",
        path.display()
    );
}

/// The byte fixtures are portable cross-implementation vectors, so they MUST
/// round-trip through the reference Marmot codec — not merely be well-formed hex
/// (closes the gap that let the fixtures drift to a TLS layout the codec rejects).
#[test]
fn nostr_routing_byte_fixtures_round_trip_through_reference_codec() {
    use cgka_traits::app_components::{decode_nostr_routing_v1, encode_nostr_routing_v1};

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("vectors/byte-fixtures");
    let mut checked = 0usize;
    for entry in fs::read_dir(&dir).expect("byte fixture dir exists") {
        let path = entry.expect("byte fixture entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.ends_with(".v1.json") || name == "schema.v1.json" {
            continue;
        }
        let fixture: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read fixture"))
                .unwrap_or_else(|e| panic!("{} parses: {e}", path.display()));
        if fixture["component"]["name"] != "marmot.transport.nostr.routing.v1" {
            continue;
        }
        let hex = fixture["bytes"]["hex"]
            .as_str()
            .unwrap_or_else(|| panic!("{} has bytes.hex", path.display()));
        let bytes =
            hex::decode(hex).unwrap_or_else(|e| panic!("{} hex decodes: {e}", path.display()));
        let decoded = decode_nostr_routing_v1(&bytes);
        let expected_valid = fixture["expected"]["valid"]
            .as_bool()
            .unwrap_or_else(|| panic!("{} has expected.valid", path.display()));
        if expected_valid {
            let routing = decoded.unwrap_or_else(|e| {
                panic!(
                    "{} must decode via the reference codec: {e}",
                    path.display()
                )
            });
            let expected_id = fixture["expected"]["fields"]["nostr_group_id_hex"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has nostr_group_id_hex", path.display()));
            assert_eq!(
                hex::encode(routing.nostr_group_id),
                expected_id,
                "{} nostr_group_id",
                path.display()
            );
            let expected_relays: Vec<String> = fixture["expected"]["fields"]["relays"]
                .as_array()
                .unwrap_or_else(|| panic!("{} has relays", path.display()))
                .iter()
                .map(|r| r.as_str().expect("relay string").to_owned())
                .collect();
            assert_eq!(routing.relays, expected_relays, "{} relays", path.display());
            // The fixture bytes are canonical: re-encoding the decoded value
            // reproduces bytes.hex exactly.
            let reencoded = encode_nostr_routing_v1(&routing).expect("re-encode");
            assert_eq!(
                hex::encode(&reencoded),
                hex,
                "{} bytes.hex must be the canonical encoding",
                path.display()
            );
        } else {
            assert!(
                decoded.is_err(),
                "{} must be rejected by the reference codec",
                path.display()
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 3,
        "expected to round-trip the state, update, and invalid fixtures"
    );
}
