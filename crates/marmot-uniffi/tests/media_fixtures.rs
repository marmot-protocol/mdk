//! Shared golden imeta fixture agreement across the UniFFI media boundary.
//!
//! The same fixture files drive marmot-app's parser tests and wn-cli's
//! validation test, so every Rust layer reaches identical verdicts for
//! identical wire input. This suite proves the FFI boundary specifically:
//!
//! - `parse_media_imeta_tag` returns the typed wire version and the complete
//!   reference for golden V1 and V2 fixtures independently;
//! - absent (`null`) versus present-empty (`""`) optional fields survive the
//!   FFI conversion unchanged;
//! - malformed, noncanonical, and unknown-version tags surface as the typed
//!   `MarmotKitError::InvalidMediaReference` error, never a panic;
//! - converting the FFI record back to the app-layer reference and rebuilding
//!   through the checked outbound builder reproduces the fixture tag exactly,
//!   so the conversion drops no field.

use marmot_app::{EncryptedMediaVersion, MediaAttachmentReference};
use marmot_uniffi::{
    EncryptedMediaVersionFfi, MarmotKitError, MessageTagFfi, parse_media_imeta_tag,
};

fn fixture_cases(file: &str) -> Vec<serde_json::Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/encrypted-media")
        .join(file);
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read media fixture {}: {err}", path.display())),
    )
    .expect("media fixture file is valid JSON");
    doc["cases"].as_array().expect("fixture cases").clone()
}

fn fixture_tag(case: &serde_json::Value) -> Vec<String> {
    case["tag"]
        .as_array()
        .expect("fixture tag")
        .iter()
        .map(|field| field.as_str().expect("fixture tag field").to_owned())
        .collect()
}

/// `null`/absent means the optional wire field is absent; a string (including
/// `""`) means present with exactly that value.
fn fixture_optional(value: &serde_json::Value, key: &str) -> Option<String> {
    match &value[key] {
        serde_json::Value::Null => None,
        serde_json::Value::String(text) => Some(text.clone()),
        other => panic!("fixture optional field {key} must be null or string, got {other}"),
    }
}

fn expected_version_ffi(expected: &serde_json::Value) -> EncryptedMediaVersionFfi {
    match expected["version"].as_str().unwrap() {
        "encrypted-media-v1" => EncryptedMediaVersionFfi::V1,
        "encrypted-media-v2" => EncryptedMediaVersionFfi::V2,
        other => panic!("fixture version {other} is not a supported FFI version"),
    }
}

fn assert_fixture_file(file: &str) {
    let cases = fixture_cases(file);
    assert!(!cases.is_empty(), "{file} must contain cases");
    for case in cases {
        let name = case["name"].as_str().expect("fixture case name");
        let tag = fixture_tag(&case);
        let source_epoch = case["source_epoch"].as_u64().expect("fixture source_epoch");
        let result = parse_media_imeta_tag(
            MessageTagFfi {
                values: tag.clone(),
            },
            source_epoch,
        );
        if case["valid"].as_bool().expect("fixture valid flag") {
            let reference =
                result.unwrap_or_else(|err| panic!("{file}/{name} must parse over FFI: {err}"));
            let expected = &case["expected"];
            assert_eq!(
                reference.version,
                expected_version_ffi(expected),
                "{file}/{name} typed wire version"
            );
            assert_eq!(
                reference.locators.len(),
                expected["locators"].as_array().unwrap().len(),
                "{file}/{name} locator count"
            );
            for (locator, expected_locator) in reference
                .locators
                .iter()
                .zip(expected["locators"].as_array().unwrap())
            {
                assert_eq!(
                    locator.kind,
                    expected_locator["kind"].as_str().unwrap(),
                    "{file}/{name} locator kind"
                );
                assert_eq!(
                    locator.value,
                    expected_locator["value"].as_str().unwrap(),
                    "{file}/{name} locator value"
                );
            }
            assert_eq!(
                reference.ciphertext_sha256,
                expected["ciphertext_sha256"].as_str().unwrap(),
                "{file}/{name} ciphertext_sha256"
            );
            assert_eq!(
                reference.plaintext_sha256,
                expected["plaintext_sha256"].as_str().unwrap(),
                "{file}/{name} plaintext_sha256"
            );
            assert_eq!(
                reference.nonce_hex,
                expected["nonce_hex"].as_str().unwrap(),
                "{file}/{name} nonce_hex"
            );
            assert_eq!(
                reference.media_type,
                expected["media_type"].as_str().unwrap(),
                "{file}/{name} media_type"
            );
            assert_eq!(
                reference.file_name,
                expected["file_name"].as_str().unwrap(),
                "{file}/{name} file_name"
            );
            assert_eq!(
                reference.source_epoch, source_epoch,
                "{file}/{name} source_epoch"
            );
            assert_eq!(
                reference.dim,
                fixture_optional(expected, "dim"),
                "{file}/{name} dim absent-vs-present-empty"
            );
            assert_eq!(
                reference.thumbhash,
                fixture_optional(expected, "thumbhash"),
                "{file}/{name} thumbhash absent-vs-present-empty"
            );
            // Convert the FFI record back to the app-layer reference and rebuild
            // the wire tag through the checked outbound builder: byte-identical
            // output proves the FFI conversion dropped nothing.
            let app_reference = MediaAttachmentReference::from(reference);
            let version = EncryptedMediaVersion::parse(&app_reference.version).unwrap();
            let allowed: Vec<String> = app_reference
                .locators
                .iter()
                .map(|locator| locator.kind.clone())
                .collect();
            let rebuilt = app_reference
                .build_imeta_tag(version, &allowed, false)
                .unwrap_or_else(|err| panic!("{file}/{name} must rebuild after FFI: {err}"));
            assert_eq!(rebuilt, tag, "{file}/{name} exact round-trip through FFI");
        } else {
            let err = result.expect_err(&format!("{file}/{name} must be rejected over FFI"));
            let needle = case["error_contains"].as_str().expect("error_contains");
            match &err {
                MarmotKitError::InvalidMediaReference { details } => assert!(
                    details.contains(needle),
                    "{file}/{name} typed error must mention {needle:?}, got: {details}"
                ),
                other => panic!(
                    "{file}/{name} must surface as typed InvalidMediaReference, got {other:?}"
                ),
            }
        }
    }
}

#[test]
fn shared_golden_v1_fixtures_cross_ffi_with_typed_version_and_errors() {
    assert_fixture_file("imeta-v1.json");
}

#[test]
fn shared_golden_v2_fixtures_cross_ffi_with_typed_version_and_errors() {
    assert_fixture_file("imeta-v2.json");
}
