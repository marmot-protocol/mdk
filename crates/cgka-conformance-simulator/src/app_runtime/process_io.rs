//! Bounded, versioned private stdio RPC and owned child lifecycle.
//!
//! Children inherit the campaign process group so the campaign's outer watchdog
//! also reaches participants. Every normal owner drop kills and reaps its child.
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use marmot_app::AppError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{SubjectError, SubjectFailureCategory};

pub const PROTOCOL: &str = "marmot-app-harness-process/v1";
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    pub code: String,
    pub message: String,
    pub category: SubjectFailureCategory,
    pub kind: String,
    pub retryable: bool,
}
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for WireError {}
impl WireError {
    pub fn environment(code: &str) -> Self {
        Self {
            code: code.into(),
            message: "app scenario child protocol or lifecycle failed".into(),
            category: SubjectFailureCategory::Environment,
            kind: "app_process".into(),
            retryable: false,
        }
    }
    pub fn subject(&self) -> SubjectError {
        SubjectError::classified(self.category, &self.code, &self.message)
    }
    pub fn app(self) -> AppError {
        match self.kind.as_str() {
            "account_worker_busy" => AppError::AccountWorkerBusy,
            "account_session_busy" => AppError::AccountSessionBusy,
            "runtime_busy" => AppError::RuntimeBusy,
            "unknown_group" => AppError::UnknownGroup(String::new()),
            _ => AppError::Io(std::io::Error::other(self)),
        }
    }
}
impl From<AppError> for WireError {
    fn from(error: AppError) -> Self {
        let kind = super::app_error_kind(&error).to_owned();
        let retryable = super::app_error_retryable(&error);
        let error = super::app_error(error);
        Self {
            code: error.code,
            message: error.message,
            category: error.category,
            kind,
            retryable,
        }
    }
}
impl From<SubjectError> for WireError {
    fn from(error: SubjectError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            category: error.category,
            kind: "app_process".into(),
            retryable: false,
        }
    }
}
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub protocol: String,
    pub id: u64,
    pub method: String,
    pub args: Value,
}
#[derive(Serialize, Deserialize)]
pub struct Response {
    pub protocol: String,
    pub id: u64,
    pub result: Result<Value, WireError>,
}

struct Job {
    method: String,
    args: Value,
    response: mpsc::Sender<Result<Value, WireError>>,
}
struct Inner {
    child: Arc<Mutex<Child>>,
    sender: Mutex<Option<mpsc::Sender<Job>>>,
    io_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    pid: u32,
    executable: PathBuf,
}
impl Inner {
    fn terminate(&self) {
        if let Ok(mut child) = self.child.lock() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.terminate();
        self.sender
            .get_mut()
            .expect("process sender mutex poisoned")
            .take();
        if let Some(thread) = self
            .io_thread
            .get_mut()
            .expect("process IO mutex poisoned")
            .take()
        {
            let _ = thread.join();
        }
    }
}
#[derive(Clone)]
pub struct ProcessClient(Arc<Inner>);
impl ProcessClient {
    pub fn spawn(role: &str, root: &Path) -> Result<Self, WireError> {
        let executable = resolve_node().map_err(|_| {
            let mut error = WireError::environment("app_process_binary_missing");
            error.message = "build cgka-conformance-node alongside the runner, or set MDK_APP_PROCESS_NODE to the matching binary".into();
            error
        })?;
        Self::spawn_executable(role, root, executable)
    }
    fn spawn_executable(role: &str, root: &Path, executable: PathBuf) -> Result<Self, WireError> {
        let stderr = fs_private::open_private_append(&root.join("process-stderr.log"))
            .map_err(|_| WireError::environment("app_process_log_failed"))?;
        let mut child = Command::new(&executable)
            .args(["--app-harness", role])
            .env("RUST_MIN_STACK", "4194304")
            .env("MDK_APP_PROCESS_PARENT_PID", std::process::id().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|_| WireError::environment("app_process_spawn_failed"))?;
        let pid = child.id();
        let mut stdin = child.stdin.take().expect("piped child stdin");
        let stdout = child.stdout.take().expect("piped child stdout");
        let child = Arc::new(Mutex::new(child));
        let (sender, jobs) = mpsc::channel::<Job>();
        let io_thread = std::thread::Builder::new()
            .name("app-scenario-stdio".into())
            .spawn(move || {
                let mut reader = BufReader::new(stdout);
                for (index, job) in jobs.into_iter().enumerate() {
                    let id = index as u64;
                    let result = (|| {
                        let request = Request {
                            protocol: PROTOCOL.into(),
                            id,
                            method: job.method,
                            args: job.args,
                        };
                        let bytes = serde_json::to_vec(&request)
                            .map_err(|_| WireError::environment("app_process_request_encode"))?;
                        if bytes.len() >= MAX_FRAME_BYTES {
                            return Err(WireError::environment("app_process_frame_too_large"));
                        }
                        stdin
                            .write_all(&bytes)
                            .and_then(|_| stdin.write_all(b"\n"))
                            .and_then(|_| stdin.flush())
                            .map_err(|_| WireError::environment("app_process_write_failed"))?;
                        let bytes = read_frame(&mut reader)?;
                        decode_response(&bytes, id)
                    })();
                    let broken = result.is_err();
                    let _ = job
                        .response
                        .send(result.and_then(|application| application));
                    if broken {
                        break;
                    }
                }
            })
            .map_err(|_| {
                if let Ok(mut child) = child.lock() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                WireError::environment("app_process_io_thread_failed")
            })?;
        let client = Self(Arc::new(Inner {
            child,
            sender: Mutex::new(Some(sender)),
            io_thread: Mutex::new(Some(io_thread)),
            pid,
            executable,
        }));
        let hello: Value = client.call("hello", serde_json::json!({}))?;
        if hello["protocol"] != PROTOCOL
            || hello["policy_overrides"] != cfg!(feature = "test-policy-overrides")
            || hello["worker_threads"] != 4
        {
            return Err(WireError::environment("app_process_build_mismatch"));
        }
        let manifest = serde_json::json!({
            "schema_version": "1", "pid": pid, "role": role,
            "executable": client.0.executable, "protocol": PROTOCOL,
            "worker_threads": 4, "policy_overrides": cfg!(feature = "test-policy-overrides"),
        });
        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| WireError::environment("app_process_manifest_failed"))?;
        fs_private::write_private(&root.join("process.json"), &bytes)
            .map_err(|_| WireError::environment("app_process_manifest_failed"))?;
        Ok(client)
    }
    pub fn pid(&self) -> u32 {
        self.0.pid
    }
    pub fn call<T: DeserializeOwned>(&self, method: &str, args: Value) -> Result<T, WireError> {
        self.call_with_timeout(method, args, RESPONSE_TIMEOUT)
    }
    fn call_with_timeout<T: DeserializeOwned>(
        &self,
        method: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<T, WireError> {
        let (tx, rx) = mpsc::channel();
        self.0
            .sender
            .lock()
            .map_err(|_| WireError::environment("app_process_lock_failed"))?
            .as_ref()
            .ok_or_else(|| WireError::environment("app_process_closed"))?
            .send(Job {
                method: method.into(),
                args,
                response: tx,
            })
            .map_err(|_| WireError::environment("app_process_closed"))?;
        let value = match rx.recv_timeout(timeout) {
            Ok(result) => result?,
            Err(_) => {
                self.0.terminate();
                return Err(WireError::environment("app_process_response_timeout"));
            }
        };
        serde_json::from_value(value)
            .map_err(|_| WireError::environment("app_process_invalid_result"))
    }
    pub async fn call_async<T: DeserializeOwned + Send + 'static>(
        &self,
        method: &str,
        args: Value,
    ) -> Result<T, WireError> {
        // A cancelled setup/action future must stop the child before its private
        // root can drop, even though spawn_blocking retains a client clone.
        struct Cancel<'a> {
            client: &'a ProcessClient,
            armed: bool,
        }
        impl Drop for Cancel<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.client.0.terminate();
                }
            }
        }
        let mut cancel = Cancel {
            client: self,
            armed: true,
        };
        let client = self.clone();
        let method = method.to_owned();
        let result = tokio::task::spawn_blocking(move || client.call(&method, args))
            .await
            .map_err(|_| WireError::environment("app_process_io_task_failed"))?;
        cancel.armed = false;
        result
    }
    pub fn reap(&self) -> Result<(), WireError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let status = loop {
            let status = self
                .0
                .child
                .lock()
                .map_err(|_| WireError::environment("app_process_lock_failed"))?
                .try_wait()
                .map_err(|_| WireError::environment("app_process_wait_failed"))?;
            if let Some(status) = status {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                self.0.terminate();
                return Err(WireError::environment("app_process_exit_timeout"));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        if !status.success() {
            return Err(WireError::environment("app_process_exit_failed"));
        }
        Ok(())
    }
}
pub fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| WireError::environment("app_process_read_failed"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(WireError::environment("app_process_frame_too_large"));
    }
    if !bytes.ends_with(b"\n") {
        return Err(WireError::environment("app_process_truncated_frame"));
    }
    Ok(bytes)
}
fn resolve_node() -> std::io::Result<PathBuf> {
    if let Some(path) = std::env::var_os("MDK_APP_PROCESS_NODE") {
        return std::fs::canonicalize(path);
    }
    let exe = std::env::current_exe()?;
    let mut parent = exe
        .parent()
        .ok_or_else(|| std::io::Error::other("executable has no parent"))?;
    if parent.file_name().is_some_and(|name| name == "deps") {
        parent = parent
            .parent()
            .ok_or_else(|| std::io::Error::other("deps has no parent"))?;
    }
    std::fs::canonicalize(parent.join(format!(
        "cgka-conformance-node{}",
        std::env::consts::EXE_SUFFIX
    )))
}

fn decode_response(bytes: &[u8], id: u64) -> Result<Result<Value, WireError>, WireError> {
    let response: Response = serde_json::from_slice(bytes)
        .map_err(|_| WireError::environment("app_process_invalid_response"))?;
    if response.protocol != PROTOCOL || response.id != id {
        return Err(WireError::environment("app_process_response_mismatch"));
    }
    Ok(response.result)
}
/// The case watchdog can SIGKILL the coordinator, bypassing Rust Drop. On Unix,
/// an independent OS thread makes every app child exit when its owner disappears,
/// including while a runtime command is blocked. It holds no database handles.
pub fn watch_parent() -> Result<(), WireError> {
    #[cfg(unix)]
    {
        let expected = std::env::var("MDK_APP_PROCESS_PARENT_PID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|pid| *pid > 1)
            .ok_or_else(|| WireError::environment("app_process_parent_missing"))?;
        std::thread::Builder::new()
            .name("app-scenario-owner".into())
            .spawn(move || {
                loop {
                    // SAFETY: getppid takes no pointers and has no preconditions.
                    if unsafe { libc::getppid() } as u32 != expected {
                        std::process::exit(1);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            .map_err(|_| WireError::environment("app_process_owner_watch_failed"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    fn fake_helper(root: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = root.join("fake-helper");
        fs_private::write_private(&path, format!("#!/bin/sh\n{body}\n").as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[cfg(unix)]
    fn fake_hello() -> String {
        let response = Response {
            protocol: PROTOCOL.into(),
            id: 0,
            result: Ok(
                serde_json::json!({"protocol":PROTOCOL,"policy_overrides":cfg!(feature="test-policy-overrides"),"worker_threads":4}),
            ),
        };
        format!(
            "read -r request\nprintf '%s\\n' '{}'",
            serde_json::to_string(&response).unwrap()
        )
    }
    #[cfg(unix)]
    #[test]
    fn unresponsive_child_is_killed_and_reaped_on_request_timeout() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_helper(
            root.path(),
            &format!("{}\nwhile read -r request; do :; done", fake_hello()),
        );
        let client =
            ProcessClient::spawn_executable("participant", root.path(), executable).unwrap();
        let result =
            client.call_with_timeout::<Value>("stuck", Value::Null, Duration::from_millis(25));
        assert_eq!(result.unwrap_err().code, "app_process_response_timeout");
        assert!(client.0.child.lock().unwrap().try_wait().unwrap().is_some());
    }
    #[cfg(unix)]
    #[test]
    fn mismatched_timing_build_is_rejected_and_partial_setup_is_reaped() {
        let root = tempfile::tempdir().unwrap();
        let response = Response {
            protocol: PROTOCOL.into(),
            id: 0,
            result: Ok(
                serde_json::json!({"protocol":PROTOCOL,"policy_overrides":!cfg!(feature="test-policy-overrides"),"worker_threads":4}),
            ),
        };
        let executable = fake_helper(
            root.path(),
            &format!(
                "printf '%s\\n' \"$$\" >&2\nread -r request\nprintf '%s\\n' '{}'\nwhile read -r request; do :; done",
                serde_json::to_string(&response).unwrap()
            ),
        );
        let error = ProcessClient::spawn_executable("participant", root.path(), executable)
            .err()
            .expect("mismatched build accepted");
        assert_eq!(error.code, "app_process_build_mismatch");
        let pid = std::fs::read_to_string(root.path().join("process-stderr.log")).unwrap();
        assert!(
            !Command::new("kill")
                .args(["-0", pid.trim()])
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        assert!(!root.path().join("process.json").exists());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_an_inflight_call_stops_the_child_before_the_root_is_released() {
        let root = tempfile::tempdir().unwrap();
        let executable = fake_helper(
            root.path(),
            &format!("{}\nwhile read -r request; do :; done", fake_hello()),
        );
        let client =
            ProcessClient::spawn_executable("participant", root.path(), executable).unwrap();
        let task_client = client.clone();
        let task =
            tokio::spawn(
                async move { task_client.call_async::<Value>("stuck", Value::Null).await },
            );
        tokio::time::sleep(Duration::from_millis(25)).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(client.0.child.lock().unwrap().try_wait().unwrap().is_some());
    }
    #[cfg(unix)]
    #[test]
    fn application_error_keeps_io_connection_usable() {
        let root = tempfile::tempdir().unwrap();
        let error = Response {
            protocol: PROTOCOL.into(),
            id: 1,
            result: Err(WireError::environment("expected_refusal")),
        };
        let success = Response {
            protocol: PROTOCOL.into(),
            id: 2,
            result: Ok(serde_json::json!(42)),
        };
        let executable = fake_helper(
            root.path(),
            &format!(
                "{}\nread -r request\nprintf '%s\\n' '{}'\nread -r request\nprintf '%s\\n' '{}'",
                fake_hello(),
                serde_json::to_string(&error).unwrap(),
                serde_json::to_string(&success).unwrap()
            ),
        );
        let client =
            ProcessClient::spawn_executable("participant", root.path(), executable).unwrap();
        assert_eq!(
            client
                .call::<Value>("refusal", Value::Null)
                .unwrap_err()
                .code,
            "expected_refusal"
        );
        assert_eq!(client.call::<u32>("after", Value::Null).unwrap(), 42);
        client.reap().unwrap();
    }
    #[test]
    fn framing_rejects_truncation_and_oversize_without_reading_unbounded_input() {
        assert_eq!(
            read_frame(&mut &b"{}"[..]).unwrap_err().code,
            "app_process_truncated_frame"
        );
        assert_eq!(
            read_frame(&mut &b""[..]).unwrap_err().code,
            "app_process_truncated_frame"
        );
        let oversized = vec![b'x'; MAX_FRAME_BYTES + 10];
        let mut reader = oversized.as_slice();
        assert_eq!(
            read_frame(&mut reader).unwrap_err().code,
            "app_process_frame_too_large"
        );
        assert_eq!(reader.len(), 9);
        assert_eq!(read_frame(&mut &b"{}\nnext"[..]).unwrap(), b"{}\n");
    }
    #[test]
    fn application_failure_is_valid_but_wrong_id_protocol_or_json_is_not() {
        let mut response = Response {
            protocol: PROTOCOL.into(),
            id: 7,
            result: Err(WireError::environment("expected_failure")),
        };
        let bytes = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            decode_response(&bytes, 7).unwrap().unwrap_err().code,
            "expected_failure"
        );
        assert_eq!(
            decode_response(&bytes, 8).unwrap_err().code,
            "app_process_response_mismatch"
        );
        response.protocol = "old".into();
        assert_eq!(
            decode_response(&serde_json::to_vec(&response).unwrap(), 7)
                .unwrap_err()
                .code,
            "app_process_response_mismatch"
        );
        assert_eq!(
            decode_response(b"bad json", 7).unwrap_err().code,
            "app_process_invalid_response"
        );
    }
    #[test]
    fn remote_errors_keep_retry_and_privacy_classification() {
        for error in [
            AppError::AccountWorkerBusy,
            AppError::AccountSessionBusy,
            AppError::RuntimeBusy,
            AppError::UnknownGroup("synthetic-secret".into()),
            AppError::GroupInviteNotPending,
        ] {
            let original = WireError::from(error);
            let restored = WireError::from(original.clone().app());
            assert_eq!(restored.kind, original.kind);
            assert_eq!(restored.retryable, original.retryable);
            assert_eq!(restored.category, original.category);
            assert_eq!(restored.code, original.code);
            assert!(
                !serde_json::to_string(&restored)
                    .unwrap()
                    .contains("synthetic-secret")
            );
        }
    }
}
