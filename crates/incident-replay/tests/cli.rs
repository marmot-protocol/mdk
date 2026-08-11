//! End-to-end CLI coverage for fail-closed format detection.

use std::io::Write;
use std::process::Command;

use tempfile::NamedTempFile;

#[test]
fn a_manifest_less_error_remnant_never_classifies_as_healthy() {
    let mut input = NamedTempFile::new().expect("create export");
    input
        .write_all(br#"{"t":"error","complete":false}"#)
        .expect("write export");
    let output = Command::new(env!("CARGO_BIN_EXE_incident-replay"))
        .arg(input.path())
        .output()
        .expect("run incident-replay");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    assert_eq!(output.status.code(), Some(2));
    assert!(!stdout.contains("healthy:"));
}
