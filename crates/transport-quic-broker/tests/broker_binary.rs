use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BROKER_BIN: &str = env!("CARGO_BIN_EXE_marmot-quic-broker");

#[test]
fn plain_startup_log_reports_certificate_fingerprint_not_der() {
    let mut child = Command::new(BROKER_BIN)
        .args(["--bind", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn broker");

    let stderr = child.stderr.take().expect("stderr pipe");
    let output = read_lines_with_timeout(stderr, 3);
    let _ = child.kill();
    let _ = child.wait();
    let output = output.expect("broker startup stderr");

    assert!(!output.contains("server_cert_der_hex"));
    let fingerprint = output
        .lines()
        .find_map(|line| line.strip_prefix("server_cert_sha256_fingerprint="))
        .expect("certificate fingerprint line");
    assert_sha256_fingerprint(fingerprint);
}

#[test]
fn json_startup_log_reports_certificate_fingerprint_not_der() {
    let mut child = Command::new(BROKER_BIN)
        .args(["--bind", "127.0.0.1:0", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn broker");

    let stdout = child.stdout.take().expect("stdout pipe");
    let output = read_lines_with_timeout(stdout, 1);
    let _ = child.kill();
    let _ = child.wait();
    let output = output.expect("broker startup json");

    assert!(!output.contains("server_cert_der_hex"));
    let payload: serde_json::Value = serde_json::from_str(&output).expect("startup json");
    let result = payload.get("result").expect("result object");
    assert!(result.get("server_cert_der_hex").is_none());
    let fingerprint = result
        .get("server_cert_sha256_fingerprint")
        .and_then(|value| value.as_str())
        .expect("certificate fingerprint");
    assert_sha256_fingerprint(fingerprint);
}

fn read_lines_with_timeout<R: Read + Send + 'static>(
    reader: R,
    line_count: usize,
) -> Result<String, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut output = String::new();
        for _ in 0..line_count {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => output.push_str(&line),
                Err(err) => {
                    let _ = tx.send(Err(err.to_string()));
                    return;
                }
            }
        }
        let _ = tx.send(Ok(output));
    });
    rx.recv_timeout(Duration::from_secs(5))
        .map_err(|err| format!("timed out reading broker output: {err}"))?
}

fn assert_sha256_fingerprint(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(
        value.chars().all(|ch| matches!(ch, '0'..='9' | 'a'..='f')),
        "fingerprint should be lowercase hex"
    );
}
