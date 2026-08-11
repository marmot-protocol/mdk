//! End-to-end CLI coverage for fail-closed format detection.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn malformed_stream_discriminators_never_classify_as_healthy() {
    for input in [
        r#"{"t": null}"#,
        r#"{"t": 0}"#,
        r#"{"t": {}}"#,
        r#"{"t": []}"#,
        r#"{"t": "error", "t": null}"#,
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_incident-replay"))
            .arg("/dev/stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch incident-replay");
        child
            .stdin
            .take()
            .expect("capture stdin")
            .write_all(input.as_bytes())
            .expect("write export");
        let output = child.wait_with_output().expect("wait for incident-replay");
        let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

        assert_eq!(output.status.code(), Some(2), "input: {input}");
        assert!(!stdout.contains("healthy:"), "input: {input}");
    }
}
