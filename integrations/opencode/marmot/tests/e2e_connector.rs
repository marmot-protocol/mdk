#![cfg(unix)]

use std::env;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use agent_control::{
    AgentControlAccount, AgentControlDebugFinalSend, AgentControlEnvelope, AgentControlRequest,
    AgentControlResponse, read_envelope, write_frame,
};
use tempfile::TempDir;
use tokio::io::BufReader;
use tokio::net::UnixStream;
use tokio::time::sleep;

const GROUP_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const MESSAGE_ID_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const SENDER_ACCOUNT_ID_HEX: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const INBOUND_TEXT: &str = "ping from connector";
const MAX_REPLY_BYTES: usize = 64;
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test]
#[ignore = "spawns real wn-agent and wn-opencode processes"]
async fn debug_inbound_reaches_fake_opencode_and_records_chunked_finals() {
    let temp = TempDir::new().expect("temp dir");
    let marmot_home = temp.path().join("marmot-home");
    let socket = temp.path().join("a.sock");
    let state_path = temp.path().join("wn-opencode-state").join("sessions.json");
    let fake_opencode = write_fake_opencode(temp.path());

    let agent = ChildGuard::new(spawn_wn_agent(&marmot_home, &socket, temp.path()));

    wait_for_agent(&socket).await;
    let account = create_account(&socket).await;

    let harness = ChildGuard::new(spawn_wn_opencode(
        &socket,
        &state_path,
        &fake_opencode,
        &account.account_id_hex,
        temp.path(),
    ));

    let expected_text = expected_reply_text();
    let finals =
        inject_until_recorded_finals(&socket, &account.account_id_hex, expected_text.as_str())
            .await;
    assert!(
        finals.len() >= 2,
        "expected chunked final sends, got {}",
        finals.len()
    );
    assert_eq!(
        finals
            .iter()
            .map(|send| send.text.as_str())
            .collect::<String>(),
        expected_text
    );
    for (index, send) in finals.iter().enumerate() {
        assert_eq!(send.account_id_hex, account.account_id_hex);
        assert_eq!(send.group_id_hex, GROUP_ID_HEX);
        assert_eq!(
            send.reply_to_message_id_hex.as_deref(),
            Some(MESSAGE_ID_HEX)
        );
        assert!(
            send.text.len() <= MAX_REPLY_BYTES,
            "chunk {index} exceeded max reply bytes"
        );
        assert_eq!(send.message_ids_hex, vec![format!("{:064x}", index + 1)]);
    }

    drop(harness);
    drop(agent);
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("repo root")
}

struct SpawnedChild {
    name: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

fn spawn_wn_agent(home: &Path, socket: &Path, log_root: &Path) -> SpawnedChild {
    let stdout_path = log_root.join("wn-agent.out.log");
    let stderr_path = log_root.join("wn-agent.err.log");
    let stdout = File::create(&stdout_path).expect("create wn-agent stdout log");
    let stderr = File::create(&stderr_path).expect("create wn-agent stderr log");
    let child = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
        .args([
            "run",
            "-q",
            "-p",
            "agent-connector",
            "--bin",
            "wn-agent",
            "--",
            "--home",
        ])
        .arg(home)
        .arg("--socket")
        .arg(socket)
        .arg("--debug-controls")
        .current_dir(repo_root())
        .env(
            "RUST_LOG",
            env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_owned()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn wn-agent");
    SpawnedChild {
        name: "wn-agent",
        child,
        stdout_path,
        stderr_path,
    }
}

fn spawn_wn_opencode(
    socket: &Path,
    state_path: &Path,
    fake_opencode: &Path,
    account_id_hex: &str,
    log_root: &Path,
) -> SpawnedChild {
    let stdout_path = log_root.join("wn-opencode.out.log");
    let stderr_path = log_root.join("wn-opencode.err.log");
    let stdout = File::create(&stdout_path).expect("create wn-opencode stdout log");
    let stderr = File::create(&stderr_path).expect("create wn-opencode stderr log");
    let child = Command::new(env!("CARGO_BIN_EXE_wn-opencode"))
        .env("MARMOT_AGENT_SOCKET", socket)
        .env("WN_OPENCODE_ACCOUNT_ID_HEX", account_id_hex)
        .env("WN_OPENCODE_ALLOWED_SENDERS_HEX", SENDER_ACCOUNT_ID_HEX)
        .env("WN_OPENCODE_BIN", fake_opencode)
        .env("WN_OPENCODE_STATE_PATH", state_path)
        .env("WN_OPENCODE_MAX_REPLY_BYTES", MAX_REPLY_BYTES.to_string())
        .env("WN_OPENCODE_TIMEOUT_SECS", "5")
        .env("WN_OPENCODE_REQUEST_TIMEOUT_SECS", "5")
        .env("RUST_LOG", "warn,wn_opencode=info")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn wn-opencode");
    SpawnedChild {
        name: "wn-opencode",
        child,
        stdout_path,
        stderr_path,
    }
}

fn write_fake_opencode(root: &Path) -> std::path::PathBuf {
    let script = root.join("fake-opencode");
    fs::write(
        &script,
        r#"#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" != "run" ] || [ "${2:-}" != "--format" ] || [ "${3:-}" != "json" ]; then
  echo "unexpected opencode args: $*" >&2
  exit 64
fi
found_delimiter=0
prompt=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--" ]; then
    found_delimiter=1
    shift
    prompt="${1:-}"
    break
  fi
  shift
done
if [ "$found_delimiter" -ne 1 ]; then
  echo "missing prompt delimiter: $*" >&2
  exit 64
fi
tail=""
for _ in $(seq 1 40); do
  tail="${tail}chunk "
done
printf '%s\n' '{"type":"step_start","sessionID":"ses_e2e"}'
printf '{"type":"text","part":{"text":"marmot-e2e-ok: %s %s"}}\n' "$prompt" "$tail"
"#,
    )
    .expect("write fake opencode");
    let mut permissions = fs::metadata(&script)
        .expect("fake opencode metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&script, permissions).expect("chmod fake opencode");
    script
}

fn expected_reply_text() -> String {
    format!("marmot-e2e-ok: {INBOUND_TEXT} {}", "chunk ".repeat(40))
}

async fn wait_for_agent(socket: &Path) {
    wait_for(
        || async {
            matches!(
                send_control_request(
                    socket,
                    "req-ready",
                    AgentControlRequest::DebugRecordedFinals,
                )
                .await,
                Ok(AgentControlResponse::DebugRecordedFinals { .. })
            )
        },
        "wn-agent debug control socket",
        AGENT_READY_TIMEOUT,
    )
    .await;
}

async fn create_account(socket: &Path) -> AgentControlAccount {
    let response = send_control_request(
        socket,
        "req-create-account",
        AgentControlRequest::AccountCreate {
            label: Some("wn-opencode-e2e".to_owned()),
            publish_key_package: false,
        },
    )
    .await
    .expect("create account");
    let AgentControlResponse::AccountCreated { account } = response else {
        panic!("expected account_created response, got {response:?}");
    };
    account
}

async fn inject_until_recorded_finals(
    socket: &Path,
    account_id_hex: &str,
    expected_text: &str,
) -> Vec<AgentControlDebugFinalSend> {
    wait_for(
        || async {
            let _ = send_control_request(
                socket,
                "req-debug-inject",
                AgentControlRequest::DebugInjectInbound {
                    account_id_hex: account_id_hex.to_owned(),
                    group_id_hex: GROUP_ID_HEX.to_owned(),
                    message_id_hex: MESSAGE_ID_HEX.to_owned(),
                    sender_account_id_hex: SENDER_ACCOUNT_ID_HEX.to_owned(),
                    text: INBOUND_TEXT.to_owned(),
                },
            )
            .await;
            let recorded = match send_control_request(
                socket,
                "req-debug-finals",
                AgentControlRequest::DebugRecordedFinals,
            )
            .await
            {
                Ok(AgentControlResponse::DebugRecordedFinals { sends }) => sends,
                _ => return None,
            };
            if recorded
                .iter()
                .map(|send| send.text.as_str())
                .collect::<String>()
                == expected_text
            {
                Some(recorded)
            } else {
                None
            }
        },
        "recorded wn-opencode final sends",
        Duration::from_secs(30),
    )
    .await
    .expect("recorded final sends")
}

async fn send_control_request(
    socket: &Path,
    id: &str,
    request: AgentControlRequest,
) -> Result<AgentControlResponse, Box<dyn std::error::Error + Send + Sync>> {
    let stream = UnixStream::connect(socket).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let envelope = AgentControlEnvelope::request(Some(id.to_owned()), request);
    write_frame(&mut write_half, &envelope).await?;
    let response: AgentControlEnvelope<AgentControlResponse> = read_envelope(&mut reader)
        .await?
        .ok_or("control socket closed")?;
    if response.id.as_deref() != Some(id) {
        return Err("control response id mismatch".into());
    }
    match response.payload {
        AgentControlResponse::Error { code, message } => {
            Err(format!("control request rejected: {code}: {message}").into())
        }
        payload => Ok(payload),
    }
}

async fn wait_for<T, Fut, F>(mut probe: F, label: &str, timeout: Duration) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = T>,
    T: WaitValue,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let value = probe().await;
        if value.is_ready() {
            return value;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {label}");
}

trait WaitValue {
    fn is_ready(&self) -> bool;
}

impl WaitValue for bool {
    fn is_ready(&self) -> bool {
        *self
    }
}

impl<T> WaitValue for Option<T> {
    fn is_ready(&self) -> bool {
        self.is_some()
    }
}

fn stop_process(child: &mut Child) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    let _ = child.kill();
    let _ = child.wait();
}

struct ChildGuard {
    name: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl ChildGuard {
    fn new(spawned: SpawnedChild) -> Self {
        Self {
            name: spawned.name,
            child: spawned.child,
            stdout_path: spawned.stdout_path,
            stderr_path: spawned.stderr_path,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        stop_process(&mut self.child);
        if std::thread::panicking() {
            dump_child_log(self.name, "stdout", &self.stdout_path);
            dump_child_log(self.name, "stderr", &self.stderr_path);
        }
    }
}

fn dump_child_log(process: &str, stream: &str, path: &Path) {
    match fs::read_to_string(path) {
        Ok(contents) if !contents.trim().is_empty() => {
            eprintln!(
                "----- {process} {stream}: {} -----\n{contents}",
                path.display()
            );
        }
        _ => {}
    }
}
