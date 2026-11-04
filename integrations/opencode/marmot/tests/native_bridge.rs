//! Run the native transport's deterministic protocol regressions in ordinary crate CI.
#[cfg(target_os = "linux")]
#[test]
fn native_transport_protocol_regressions() {
    let status = std::process::Command::new("python3")
        .args([
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
            "-p",
            "test_native_bridge.py",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("Python 3 is required for native OpenCode transport tests");
    assert!(
        status.success(),
        "native transport protocol regressions failed"
    );
}
