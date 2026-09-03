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

/// Stable synthetic group id used by connector e2e tests.
const GROUP_ID_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// Stable synthetic message id used by connector e2e tests.
const MESSAGE_ID_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";
/// Stable synthetic follow-up message id used by resume connector e2e tests.
const RESUME_MESSAGE_ID_HEX: &str =
    "5555555555555555555555555555555555555555555555555555555555555555";
/// Stable synthetic sender id permitted by connector e2e tests.
pub const SENDER_ACCOUNT_ID_HEX: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
/// Prompt injected through the debug control socket.
const INBOUND_TEXT: &str = "ping from connector";
/// Follow-up prompt injected after the first backend session is persisted.
const RESUME_INBOUND_TEXT: &str = "followup from connector";
/// Small reply cap that forces chunking in connector e2e tests.
pub const MAX_REPLY_BYTES: usize = 64;
const AGENT_READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Paths and account identity supplied to a backend-specific process factory.
pub struct HarnessContext<'a> {
    /// Private temporary root for the test.
    pub root: &'a Path,
    /// Debug `wn-agent` control socket.
    pub socket: &'a Path,
    /// Local account created for the test.
    pub account_id_hex: &'a str,
}

/// Runs the shared real-process connector scenario around a backend factory.
pub async fn run_connector_e2e(
    harness_name: &'static str,
    spawn_harness: impl FnOnce(HarnessContext<'_>) -> SpawnedChild,
) {
    run_connector_e2e_scenario(harness_name, spawn_harness, false).await;
}

/// Runs the shared connector scenario and then verifies a same-group resume.
pub async fn run_connector_resume_e2e(
    harness_name: &'static str,
    spawn_harness: impl FnOnce(HarnessContext<'_>) -> SpawnedChild,
) {
    run_connector_e2e_scenario(harness_name, spawn_harness, true).await;
}

async fn run_connector_e2e_scenario(
    harness_name: &'static str,
    spawn_harness: impl FnOnce(HarnessContext<'_>) -> SpawnedChild,
    exercise_resume: bool,
) {
    let temp = TempDir::new().expect("temp dir");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("make temp root private");
    let marmot_home = temp.path().join("marmot-home");
    let socket = temp.path().join("a.sock");

    let agent = ChildGuard::new(spawn_wn_agent(&marmot_home, &socket, temp.path()));
    wait_for_agent(&socket).await;
    let account = create_account(&socket, harness_name).await;
    let harness = ChildGuard::new(spawn_harness(HarnessContext {
        root: temp.path(),
        socket: &socket,
        account_id_hex: &account.account_id_hex,
    }));

    let expected_text = expected_reply_text();
    let finals = inject_until_recorded_finals(
        &socket,
        &account.account_id_hex,
        MESSAGE_ID_HEX,
        INBOUND_TEXT,
        &expected_text,
        harness_name,
    )
    .await;
    assert_final_sends(
        &finals,
        &account.account_id_hex,
        MESSAGE_ID_HEX,
        &expected_text,
        0,
        2,
    );

    if exercise_resume {
        let resumed_text = expected_resume_reply_text();
        let all_expected_text = format!("{expected_text}{resumed_text}");
        let all_finals = inject_until_recorded_finals(
            &socket,
            &account.account_id_hex,
            RESUME_MESSAGE_ID_HEX,
            RESUME_INBOUND_TEXT,
            &all_expected_text,
            harness_name,
        )
        .await;
        assert!(
            all_finals.len() > finals.len(),
            "expected resumed final sends"
        );
        assert_final_sends(
            &all_finals[finals.len()..],
            &account.account_id_hex,
            RESUME_MESSAGE_ID_HEX,
            &resumed_text,
            finals.len(),
            1,
        );
    }

    drop(harness);
    drop(agent);
}

/// Spawned child and its captured log paths.
pub struct SpawnedChild {
    name: &'static str,
    child: Child,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl SpawnedChild {
    /// Spawns a child with stdout and stderr captured under `log_root`.
    pub fn spawn(name: &'static str, command: &mut Command, log_root: &Path) -> Self {
        let stdout_path = log_root.join(format!("{name}.out.log"));
        let stderr_path = log_root.join(format!("{name}.err.log"));
        let stdout = File::create(&stdout_path).expect("create child stdout log");
        let stderr = File::create(&stderr_path).expect("create child stderr log");
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn connector child");
        Self {
            name,
            child,
            stdout_path,
            stderr_path,
        }
    }
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
}

fn spawn_wn_agent(home: &Path, socket: &Path, log_root: &Path) -> SpawnedChild {
    let mut command = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
    command
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
        );
    SpawnedChild::spawn("wn-agent", &mut command, log_root)
}

fn expected_reply_text() -> String {
    format!("marmot-e2e-ok: {INBOUND_TEXT} {}", "chunk ".repeat(40))
}

fn expected_resume_reply_text() -> String {
    format!("marmot-e2e-resume-ok: {RESUME_INBOUND_TEXT}")
}

fn assert_final_sends(
    finals: &[AgentControlDebugFinalSend],
    account_id_hex: &str,
    reply_to_message_id_hex: &str,
    expected_text: &str,
    prior_send_count: usize,
    minimum_chunks: usize,
) {
    assert!(
        finals.len() >= minimum_chunks,
        "expected at least {minimum_chunks} final sends, got {}",
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
        assert_eq!(send.account_id_hex, account_id_hex);
        assert_eq!(send.group_id_hex, GROUP_ID_HEX);
        assert_eq!(
            send.reply_to_message_id_hex.as_deref(),
            Some(reply_to_message_id_hex)
        );
        assert!(send.text.len() <= MAX_REPLY_BYTES);
        assert_eq!(
            send.message_ids_hex,
            vec![format!("{:064x}", prior_send_count + index + 1)]
        );
    }
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

async fn create_account(socket: &Path, harness_name: &str) -> AgentControlAccount {
    let response = send_control_request(
        socket,
        "req-create-account",
        AgentControlRequest::AccountCreate {
            label: Some(format!("{harness_name}-e2e")),
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
    message_id_hex: &str,
    inbound_text: &str,
    expected_text: &str,
    harness_name: &str,
) -> Vec<AgentControlDebugFinalSend> {
    wait_for(
        || async {
            let _ = send_control_request(
                socket,
                "req-debug-inject",
                AgentControlRequest::DebugInjectInbound {
                    account_id_hex: account_id_hex.to_owned(),
                    group_id_hex: GROUP_ID_HEX.to_owned(),
                    message_id_hex: message_id_hex.to_owned(),
                    sender_account_id_hex: SENDER_ACCOUNT_ID_HEX.to_owned(),
                    text: inbound_text.to_owned(),
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
            (recorded
                .iter()
                .map(|send| send.text.as_str())
                .collect::<String>()
                == expected_text)
                .then_some(recorded)
        },
        &format!("recorded {harness_name} final sends"),
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
        AgentControlResponse::Error { code, message, .. } => {
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
    if let Ok(contents) = fs::read_to_string(path)
        && !contents.trim().is_empty()
    {
        eprintln!(
            "----- {process} {stream}: {} -----\n{contents}",
            path.display()
        );
    }
}
