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

    for entry in entries {
        if let Some(artifact) = entry.get("artifact").and_then(Value::as_str) {
            assert!(
                vectors.join(artifact).exists(),
                "manifest artifact {artifact} should exist"
            );
        }
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
