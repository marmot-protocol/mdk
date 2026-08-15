use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::{CampaignLaneObservationV1, RunnerError, load_manifest};

pub const CAMPAIGN_LANE_STEP_OBSERVATION_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignLaneStepObservationV1 {
    pub schema_version: String,
    pub name: String,
    pub wall_clock_us: u64,
    pub user_cpu_us: Option<u64>,
    pub system_cpu_us: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub filesystem_block_write_lower_bound_bytes: Option<u64>,
    pub executed_cases: u64,
    pub flaky_cases: u64,
    pub flake_retries: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable_process_fields: Vec<String>,
}

impl CampaignLaneStepObservationV1 {
    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != CAMPAIGN_LANE_STEP_OBSERVATION_VERSION {
            return Err(RunnerError::validation(
                "lane_step_observation_version",
                "unsupported lane step observation version",
            ));
        }
        if self.name.is_empty() {
            return Err(RunnerError::validation(
                "lane_step_observation_name",
                "lane step observation requires a name",
            ));
        }
        if self.flaky_cases > self.executed_cases {
            return Err(RunnerError::validation(
                "lane_step_observation_flakes",
                "flaky cases cannot exceed executed cases",
            ));
        }
        if self.flake_retries < self.flaky_cases {
            return Err(RunnerError::validation(
                "lane_step_observation_retries",
                "each flaky case must account for at least one retry",
            ));
        }
        if self.exit_code.is_some() && self.signal.is_some() {
            return Err(RunnerError::validation(
                "lane_step_observation_status",
                "lane step cannot have both an exit code and a signal",
            ));
        }
        Ok(())
    }

    pub fn succeeded(&self) -> bool {
        self.exit_code == Some(0) && self.signal.is_none()
    }

    pub fn write_private(&self, path: &Path) -> Result<(), RunnerError> {
        self.validate()?;
        create_private_parent(path)?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| RunnerError::environment("lane_step_serialize", error))?;
        fs_private::write_private(path, &bytes)
            .map_err(|error| RunnerError::environment("lane_step_write", error))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectedLaneObservationV1 {
    pub observation: CampaignLaneObservationV1,
    pub failed_steps: Vec<String>,
}

#[derive(Default)]
struct NextestStats {
    executed_cases: u64,
    retry_attempts: BTreeMap<String, u64>,
}

impl NextestStats {
    fn record_line(&mut self, line: &str) -> bool {
        let structured = self.record_structured_line(line);
        self.record_retry_line(line);
        structured
    }

    fn record_structured_line(&mut self, line: &str) -> bool {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            return false;
        };
        let Some(kind) = value.get("type").and_then(serde_json::Value::as_str) else {
            return false;
        };
        if kind == "suite"
            && value.get("event").and_then(serde_json::Value::as_str) != Some("started")
        {
            let passed = value
                .get("passed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let failed = value
                .get("failed")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let measured = value
                .get("measured")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            self.executed_cases = self
                .executed_cases
                .saturating_add(passed)
                .saturating_add(failed)
                .saturating_add(measured);
        }
        matches!(kind, "suite" | "test")
    }

    fn record_retry_line(&mut self, line: &str) {
        let plain = strip_ansi(line);
        let Some(marker) = plain.find("TRY ") else {
            return;
        };
        let mut fields = plain[marker + 4..].split_whitespace();
        let Some(attempt) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            return;
        };
        let Some(status) = fields.next() else {
            return;
        };
        if !matches!(status, "PASS" | "FAIL") {
            return;
        }
        let remainder = fields.collect::<Vec<_>>().join(" ");
        let test_name = remainder
            .split_once(']')
            .map_or(remainder.as_str(), |(_, identity)| identity)
            .trim();
        if test_name.is_empty() {
            return;
        }
        self.retry_attempts
            .entry(test_name.to_owned())
            .and_modify(|current| *current = (*current).max(attempt))
            .or_insert(attempt);
    }

    fn flaky_cases(&self) -> u64 {
        u64::try_from(
            self.retry_attempts
                .values()
                .filter(|attempt| **attempt > 1)
                .count(),
        )
        .unwrap_or(u64::MAX)
    }

    fn flake_retries(&self) -> u64 {
        self.retry_attempts
            .values()
            .map(|attempt| attempt.saturating_sub(1))
            .fold(0_u64, u64::saturating_add)
    }
}

pub fn observe_lane_step(
    name: String,
    command: &[OsString],
) -> Result<CampaignLaneStepObservationV1, RunnerError> {
    if name.is_empty() {
        return Err(RunnerError::validation(
            "lane_step_observation_name",
            "lane step observation requires a name",
        ));
    }
    let Some((program, arguments)) = command.split_first() else {
        return Err(RunnerError::validation(
            "lane_step_command",
            "lane step observation requires a command argv",
        ));
    };
    let started = Instant::now();
    let mut child = Command::new(program);
    child
        .args(arguments)
        .env("NEXTEST_EXPERIMENTAL_LIBTEST_JSON", "1")
        .env("NEXTEST_MESSAGE_FORMAT", "libtest-json-plus")
        .env("NEXTEST_STATUS_LEVEL", "retry")
        .env("NEXTEST_FINAL_STATUS_LEVEL", "fail")
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = child
        .spawn()
        .map_err(|error| RunnerError::environment("lane_step_spawn", error))?;
    let stdout = child.stdout.take().ok_or_else(|| {
        RunnerError::validation("lane_step_stdout", "lane step stdout pipe is unavailable")
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        RunnerError::validation("lane_step_stderr", "lane step stderr pipe is unavailable")
    })?;
    let stats = Arc::new(Mutex::new(NextestStats::default()));
    let stdout_thread = relay_output(stdout, false, Arc::clone(&stats));
    let stderr_thread = relay_output(stderr, true, Arc::clone(&stats));
    let usage = wait_with_usage(child)?;
    join_output_thread(stdout_thread)?;
    join_output_thread(stderr_thread)?;
    let stats = Arc::try_unwrap(stats)
        .map_err(|_| {
            RunnerError::validation("lane_step_stats", "lane step stats are still shared")
        })?
        .into_inner()
        .map_err(|_| {
            RunnerError::validation("lane_step_stats", "lane step stats lock is poisoned")
        })?;
    let observation = CampaignLaneStepObservationV1 {
        schema_version: CAMPAIGN_LANE_STEP_OBSERVATION_VERSION.into(),
        name,
        wall_clock_us: duration_us(started.elapsed()),
        user_cpu_us: usage.user_cpu_us,
        system_cpu_us: usage.system_cpu_us,
        peak_rss_bytes: usage.peak_rss_bytes,
        filesystem_block_write_lower_bound_bytes: usage.filesystem_block_write_lower_bound_bytes,
        executed_cases: stats.executed_cases,
        flaky_cases: stats.flaky_cases(),
        flake_retries: stats.flake_retries(),
        exit_code: usage.exit_code,
        signal: usage.signal,
        unavailable_process_fields: usage.unavailable_process_fields,
    };
    observation.validate()?;
    Ok(observation)
}

pub fn collect_lane_observation(
    step_dir: &Path,
    artifact_roots: &[PathBuf],
    disk_roots: &[PathBuf],
    campaign_manifests: &[PathBuf],
) -> Result<CollectedLaneObservationV1, RunnerError> {
    let steps = read_step_observations(step_dir)?;
    let mut artifact_roots = artifact_roots.to_vec();
    for manifest_path in campaign_manifests {
        let manifest = load_manifest(manifest_path)?;
        artifact_roots.push(manifest.output_dir);
    }
    if artifact_roots.is_empty() || disk_roots.is_empty() {
        return Err(RunnerError::validation(
            "lane_observation_roots",
            "lane observation requires artifact and disk roots",
        ));
    }

    let mut wall_clock_us = 0_u64;
    let mut cpu_us = 0_u64;
    let mut peak_rss_bytes = 0_u64;
    let mut executed_cases = 0_u64;
    let mut flaky_cases = 0_u64;
    let mut flake_retries = 0_u64;
    let mut failed_steps = Vec::new();
    for step in steps {
        step.validate()?;
        let (Some(user_cpu_us), Some(system_cpu_us), Some(step_peak_rss_bytes)) =
            (step.user_cpu_us, step.system_cpu_us, step.peak_rss_bytes)
        else {
            return Err(RunnerError::validation(
                "lane_observation_process_fields",
                format!("lane step {} lacks required CPU or RSS evidence", step.name),
            ));
        };
        wall_clock_us = wall_clock_us.saturating_add(step.wall_clock_us);
        cpu_us = cpu_us
            .saturating_add(user_cpu_us)
            .saturating_add(system_cpu_us);
        peak_rss_bytes = peak_rss_bytes.max(step_peak_rss_bytes);
        executed_cases = executed_cases.saturating_add(step.executed_cases);
        flaky_cases = flaky_cases.saturating_add(step.flaky_cases);
        flake_retries = flake_retries.saturating_add(step.flake_retries);
        if !step.succeeded() {
            failed_steps.push(step.name);
        }
    }

    Ok(CollectedLaneObservationV1 {
        observation: CampaignLaneObservationV1 {
            wall_clock_seconds: micros_to_seconds_ceil(wall_clock_us),
            cpu_seconds: micros_to_seconds_ceil(cpu_us),
            peak_rss_bytes,
            disk_bytes: measure_roots(disk_roots)?,
            artifact_bytes: measure_roots(&artifact_roots)?,
            executed_cases,
            flaky_cases,
            flake_retries,
        },
        failed_steps,
    })
}

pub fn write_lane_observation_private(
    observation: &CampaignLaneObservationV1,
    path: &Path,
) -> Result<(), RunnerError> {
    create_private_parent(path)?;
    let bytes = serde_json::to_vec_pretty(observation)
        .map_err(|error| RunnerError::environment("lane_observation_serialize", error))?;
    fs_private::write_private(path, &bytes)
        .map_err(|error| RunnerError::environment("lane_observation_write", error))
}

fn read_step_observations(
    step_dir: &Path,
) -> Result<Vec<CampaignLaneStepObservationV1>, RunnerError> {
    let mut paths = fs::read_dir(step_dir)
        .map_err(|error| RunnerError::environment("lane_step_directory", error))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| RunnerError::environment("lane_step_directory", error))?;
    paths.sort();
    let mut steps = Vec::new();
    let mut names = BTreeSet::new();
    for path in paths {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| RunnerError::environment("lane_step_metadata", error))?;
        if metadata.file_type().is_symlink() {
            return Err(RunnerError::validation(
                "lane_step_symlink",
                "lane step observation directory must not contain symlinks",
            ));
        }
        if !metadata.is_file() || path.extension() != Some(OsStr::new("json")) {
            continue;
        }
        let step: CampaignLaneStepObservationV1 = serde_json::from_slice(
            &fs::read(&path).map_err(|error| RunnerError::environment("lane_step_read", error))?,
        )
        .map_err(|error| RunnerError::environment("lane_step_parse", error))?;
        step.validate()?;
        if !names.insert(step.name.clone()) {
            return Err(RunnerError::validation(
                "lane_step_duplicate",
                "lane step observation names must be unique",
            ));
        }
        steps.push(step);
    }
    if steps.is_empty() {
        return Err(RunnerError::validation(
            "lane_step_empty",
            "lane observation requires at least one measured step",
        ));
    }
    Ok(steps)
}

fn measure_roots(roots: &[PathBuf]) -> Result<u64, RunnerError> {
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| RunnerError::environment("lane_observation_root", error))?;
        if metadata.file_type().is_symlink() {
            return Err(RunnerError::validation(
                "lane_observation_root_symlink",
                "lane observation roots must not be symlinks",
            ));
        }
        canonical.push(
            fs::canonicalize(root)
                .map_err(|error| RunnerError::environment("lane_observation_root", error))?,
        );
    }
    canonical.sort();
    canonical.dedup();
    for (index, root) in canonical.iter().enumerate() {
        if canonical
            .iter()
            .enumerate()
            .any(|(candidate_index, candidate)| {
                candidate_index != index && root.starts_with(candidate)
            })
        {
            return Err(RunnerError::validation(
                "lane_observation_overlapping_roots",
                "lane observation roots must not overlap",
            ));
        }
    }
    canonical.iter().try_fold(0_u64, |total, root| {
        Ok(total.saturating_add(measure_tree(root)?))
    })
}

fn measure_tree(path: &Path) -> Result<u64, RunnerError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| RunnerError::environment("lane_observation_metadata", error))?;
    if metadata.file_type().is_symlink() {
        // Do not follow links out of a workflow-owned measurement root. Cargo
        // and Docker may leave links in otherwise valid working directories;
        // linked bytes are outside this final-size lower bound.
        return Ok(0);
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }
    fs::read_dir(path)
        .map_err(|error| RunnerError::environment("lane_observation_directory", error))?
        .try_fold(0_u64, |total, entry| {
            let entry = entry
                .map_err(|error| RunnerError::environment("lane_observation_directory", error))?;
            Ok(total.saturating_add(measure_tree(&entry.path())?))
        })
}

fn relay_output<R: Read + Send + 'static>(
    reader: R,
    stderr: bool,
    stats: Arc<Mutex<NextestStats>>,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            let text = String::from_utf8_lossy(&line);
            let structured = stats
                .lock()
                .map_err(|_| io::Error::other("lane step stats lock is poisoned"))?
                .record_line(&text);
            if !structured {
                if stderr {
                    let mut output = io::stderr().lock();
                    output.write_all(&line)?;
                    output.flush()?;
                } else {
                    let mut output = io::stdout().lock();
                    output.write_all(&line)?;
                    output.flush()?;
                }
            }
        }
        Ok(())
    })
}

fn join_output_thread(thread: thread::JoinHandle<io::Result<()>>) -> Result<(), RunnerError> {
    thread
        .join()
        .map_err(|_| RunnerError::validation("lane_step_output", "lane output thread panicked"))?
        .map_err(|error| RunnerError::environment("lane_step_output", error))
}

struct ChildUsage {
    exit_code: Option<i32>,
    signal: Option<i32>,
    user_cpu_us: Option<u64>,
    system_cpu_us: Option<u64>,
    peak_rss_bytes: Option<u64>,
    filesystem_block_write_lower_bound_bytes: Option<u64>,
    unavailable_process_fields: Vec<String>,
}

#[cfg(unix)]
fn wait_with_usage(child: std::process::Child) -> Result<ChildUsage, RunnerError> {
    let pid = i32::try_from(child.id())
        .map_err(|error| RunnerError::environment("lane_step_pid", error))?;
    let mut status = 0;
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    loop {
        // SAFETY: `status` and `usage` are valid writable pointers for the
        // duration of the call, and `pid` names the live child we just spawned.
        let waited = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
        if waited == pid {
            break;
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(RunnerError::environment("lane_step_wait", error));
        }
    }
    // SAFETY: a successful `wait4` initialized the complete rusage value.
    let usage = unsafe { usage.assume_init() };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (filesystem_block_write_lower_bound_bytes, unavailable_process_fields) = (
        None,
        vec!["filesystem_block_write_lower_bound_bytes".to_owned()],
    );
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let (filesystem_block_write_lower_bound_bytes, unavailable_process_fields) = (
        Some(
            u64::try_from(usage.ru_oublock)
                .unwrap_or(0)
                .saturating_mul(512),
        ),
        Vec::new(),
    );
    Ok(ChildUsage {
        exit_code: libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)),
        signal: libc::WIFSIGNALED(status).then(|| libc::WTERMSIG(status)),
        user_cpu_us: Some(timeval_us(usage.ru_utime)),
        system_cpu_us: Some(timeval_us(usage.ru_stime)),
        peak_rss_bytes: Some(peak_rss_bytes(usage.ru_maxrss)),
        filesystem_block_write_lower_bound_bytes,
        unavailable_process_fields,
    })
}

#[cfg(not(unix))]
fn wait_with_usage(mut child: std::process::Child) -> Result<ChildUsage, RunnerError> {
    let status = child
        .wait()
        .map_err(|error| RunnerError::environment("lane_step_wait", error))?;
    Ok(ChildUsage {
        exit_code: status.code(),
        signal: None,
        user_cpu_us: None,
        system_cpu_us: None,
        peak_rss_bytes: None,
        filesystem_block_write_lower_bound_bytes: None,
        unavailable_process_fields: vec![
            "user_cpu_us".into(),
            "system_cpu_us".into(),
            "peak_rss_bytes".into(),
            "filesystem_block_write_lower_bound_bytes".into(),
        ],
    })
}

#[cfg(unix)]
fn timeval_us(value: libc::timeval) -> u64 {
    u64::try_from(value.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(value.tv_usec).unwrap_or(0))
}

#[cfg(all(unix, any(target_os = "macos", target_os = "ios")))]
fn peak_rss_bytes(value: libc::c_long) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
fn peak_rss_bytes(value: libc::c_long) -> u64 {
    u64::try_from(value).unwrap_or(0).saturating_mul(1024)
}

fn create_private_parent(path: &Path) -> Result<(), RunnerError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs_private::create_dir_all_private(parent)
            .map_err(|error| RunnerError::environment("lane_observation_directory", error))?;
    }
    Ok(())
}

fn micros_to_seconds_ceil(value: u64) -> u64 {
    value.div_ceil(1_000_000)
}

fn duration_us(value: std::time::Duration) -> u64 {
    u64::try_from(value.as_micros()).unwrap_or(u64::MAX)
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == 0x1b {
            if bytes.next() == Some(b'[') {
                for control in bytes.by_ref() {
                    if control.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        output.push(char::from(byte));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_suites_and_retry_statuses_produce_lane_counts() {
        let mut stats = NextestStats::default();
        assert!(stats.record_line(
            r#"{"type":"suite","event":"ok","passed":7,"failed":1,"ignored":2,"measured":0}"#
        ));
        stats.record_line("TRY 1 FAIL [ 0.1s] crate::tests flaky_case");
        stats.record_line("TRY 2 PASS [ 0.1s] crate::tests flaky_case");
        stats.record_line("TRY 2 PASS [ 0.1s] crate::tests flaky_case");
        stats.record_line("TRY 1 FAIL [ 0.1s] other::tests flaky_case");
        stats.record_line("TRY 3 PASS [ 0.1s] other::tests flaky_case");
        assert_eq!(stats.executed_cases, 8);
        assert_eq!(stats.flaky_cases(), 2);
        assert_eq!(stats.flake_retries(), 3);
    }

    #[test]
    fn aggregate_uses_sum_for_cpu_and_wall_but_max_for_rss() {
        let root = tempfile::tempdir().unwrap();
        let steps = root.path().join("steps");
        fs_private::create_dir_all_private(&steps).unwrap();
        let artifact = root.path().join("artifact");
        fs_private::create_dir_all_private(&artifact).unwrap();
        fs_private::write_private(&artifact.join("report.json"), b"1234").unwrap();
        for (name, wall, cpu, rss, cases) in [
            ("first", 1_500_000, 800_000, 12, 3),
            ("second", 500_001, 500_001, 20, 4),
        ] {
            CampaignLaneStepObservationV1 {
                schema_version: "1".into(),
                name: name.into(),
                wall_clock_us: wall,
                user_cpu_us: Some(cpu),
                system_cpu_us: Some(0),
                peak_rss_bytes: Some(rss),
                filesystem_block_write_lower_bound_bytes: Some(0),
                executed_cases: cases,
                flaky_cases: 0,
                flake_retries: 0,
                exit_code: Some(0),
                signal: None,
                unavailable_process_fields: Vec::new(),
            }
            .write_private(&steps.join(format!("{name}.json")))
            .unwrap();
        }
        let collected = collect_lane_observation(
            &steps,
            std::slice::from_ref(&artifact),
            std::slice::from_ref(&artifact),
            &[],
        )
        .unwrap();
        assert_eq!(collected.observation.wall_clock_seconds, 3);
        assert_eq!(collected.observation.cpu_seconds, 2);
        assert_eq!(collected.observation.peak_rss_bytes, 20);
        assert_eq!(collected.observation.executed_cases, 7);
        assert_eq!(collected.observation.artifact_bytes, 4);
        assert!(collected.failed_steps.is_empty());
    }
}
