use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::RunnerError;

pub const REGRESSION_CAMPAIGN_SCHEMA_VERSION: &str = "1";
pub const FOCUSED_CONVERGENCE_CAMPAIGN_ID: &str = "focused-convergence-regressions/v1";
pub const REGRESSION_CAMPAIGN_INPUT_FILE: &str = "campaign-input.v1.json";
pub const REGRESSION_CAMPAIGN_REPORT_FILE: &str = "campaign-report.v1.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCampaignInputV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub source_revision: String,
    pub cargo_lock_sha256: String,
    pub case_timeout_ms: u64,
    pub cases: Vec<RegressionCaseSpecV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCaseSpecV1 {
    pub case_id: String,
    pub assurance_claim: String,
    pub package: String,
    pub target: RegressionTestTargetV1,
    pub test_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegressionTestTargetV1 {
    Library,
    Integration { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCampaignReportV1 {
    pub schema_version: String,
    pub campaign_id: String,
    pub source_revision: String,
    pub input_manifest: PathBuf,
    pub input_sha256: String,
    pub passed: bool,
    pub cases: Vec<RegressionCaseResultV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionCaseResultV1 {
    pub case_id: String,
    pub command_argv: Vec<String>,
    pub stdout: RegressionArtifactV1,
    pub stderr: RegressionArtifactV1,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_error: Option<String>,
    pub wall_ms: u64,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionArtifactV1 {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

impl RegressionCampaignInputV1 {
    pub fn focused_convergence(
        source_revision: String,
        cargo_lock_sha256: String,
        case_timeout: Duration,
    ) -> Result<Self, RunnerError> {
        let case_timeout_ms = u64::try_from(case_timeout.as_millis()).map_err(|_| {
            RunnerError::validation(
                "regression_campaign_timeout",
                "case timeout does not fit in the versioned millisecond field",
            )
        })?;
        let input = Self {
            schema_version: REGRESSION_CAMPAIGN_SCHEMA_VERSION.into(),
            campaign_id: FOCUSED_CONVERGENCE_CAMPAIGN_ID.into(),
            source_revision,
            cargo_lock_sha256,
            case_timeout_ms,
            cases: focused_convergence_cases(),
        };
        input.validate()?;
        Ok(input)
    }

    pub fn validate(&self) -> Result<(), RunnerError> {
        if self.schema_version != REGRESSION_CAMPAIGN_SCHEMA_VERSION {
            return Err(RunnerError::validation(
                "regression_campaign_version",
                "unsupported regression campaign schema version",
            ));
        }
        if self.campaign_id.is_empty() || self.source_revision.is_empty() {
            return Err(RunnerError::validation(
                "regression_campaign_identity",
                "campaign id and source revision must be nonempty",
            ));
        }
        if !is_lower_sha256(&self.cargo_lock_sha256) {
            return Err(RunnerError::validation(
                "regression_campaign_lock_digest",
                "Cargo.lock digest must be a lowercase SHA-256 value",
            ));
        }
        if self.case_timeout_ms == 0 || self.cases.is_empty() {
            return Err(RunnerError::validation(
                "regression_campaign_cases",
                "campaign requires a nonzero timeout and at least one case",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for case in &self.cases {
            if case.case_id.is_empty()
                || case.assurance_claim.is_empty()
                || case.package.is_empty()
                || case.test_name.is_empty()
                || !case
                    .case_id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || matches!(&case.target, RegressionTestTargetV1::Integration { name } if name.is_empty())
                || case.features.iter().any(String::is_empty)
                || !ids.insert(case.case_id.as_str())
            {
                return Err(RunnerError::validation(
                    "regression_campaign_case",
                    "case ids must be unique and every case field must be nonempty",
                ));
            }
        }
        Ok(())
    }
}

impl RegressionCaseSpecV1 {
    pub fn cargo_args(&self) -> Vec<String> {
        let mut args = vec![
            "test".into(),
            "--locked".into(),
            "-p".into(),
            self.package.clone(),
        ];
        match &self.target {
            RegressionTestTargetV1::Library => args.push("--lib".into()),
            RegressionTestTargetV1::Integration { name } => {
                args.push("--test".into());
                args.push(name.clone());
            }
        }
        if !self.features.is_empty() {
            args.push("--features".into());
            args.push(self.features.join(","));
        }
        args.extend([
            self.test_name.clone(),
            "--".into(),
            "--exact".into(),
            "--nocapture".into(),
        ]);
        args
    }
}

impl RegressionCampaignReportV1 {
    pub fn validate_artifacts(&self, base_dir: &Path) -> Result<(), RunnerError> {
        if self.schema_version != REGRESSION_CAMPAIGN_SCHEMA_VERSION
            || self.campaign_id.is_empty()
            || self.source_revision.is_empty()
            || !is_lower_sha256(&self.input_sha256)
            || self.cases.is_empty()
            || self.passed != self.cases.iter().all(|case| case.passed)
        {
            return Err(RunnerError::validation(
                "regression_campaign_report",
                "regression campaign report is incomplete or inconsistent",
            ));
        }
        let input_bytes = read_artifact(base_dir, &self.input_manifest)?;
        validate_artifact(
            base_dir,
            &RegressionArtifactV1 {
                path: self.input_manifest.clone(),
                sha256: self.input_sha256.clone(),
                bytes: u64::try_from(input_bytes.len()).unwrap_or(u64::MAX),
            },
        )?;
        let input: RegressionCampaignInputV1 = serde_json::from_slice(&input_bytes)
            .map_err(|error| RunnerError::environment("regression_campaign_input_parse", error))?;
        input.validate()?;
        if input.campaign_id != self.campaign_id
            || input.source_revision != self.source_revision
            || input.cases.len() != self.cases.len()
        {
            return Err(RunnerError::validation(
                "regression_campaign_input_mismatch",
                "report identity and case coverage must match the preserved input",
            ));
        }
        for (planned, case) in input.cases.iter().zip(&self.cases) {
            if case.case_id != planned.case_id
                || case.command_argv.is_empty()
                || case.command_argv[1..] != planned.cargo_args()
                || case.passed
                    != (!case.timed_out
                        && case.launch_error.is_none()
                        && case.signal.is_none()
                        && case.exit_code == Some(0))
            {
                return Err(RunnerError::validation(
                    "regression_campaign_case_result",
                    "case result is incomplete or inconsistent",
                ));
            }
            validate_artifact(base_dir, &case.stdout)?;
            validate_artifact(base_dir, &case.stderr)?;
        }
        Ok(())
    }
}

pub fn focused_convergence_cases() -> Vec<RegressionCaseSpecV1> {
    vec![
        integration_case(
            "missing-anchor-halt",
            "A restarted committer without its retained source anchor fails closed through convergence without silently adjudicating the fork.",
            "cgka-engine",
            "fork_detection",
            "restarted_committer_without_source_anchor_halts_through_convergence",
        ),
        integration_case(
            "verified-welcome-repair",
            "An authenticated replacement Welcome repairs the fail-closed group and survives the next convergence drain.",
            "cgka-engine",
            "fork_detection",
            "verified_welcome_repair_survives_the_next_convergence_drain",
        ),
        integration_case(
            "atomic-self-remove-persistence",
            "Every injected write failure rolls back self-removal proposal, leave request, and dedup persistence and remains retryable after restart.",
            "cgka-engine",
            "auto_commit_atomicity",
            "leave_persistence_failure_rolls_back_every_transactional_write",
        ),
        RegressionCaseSpecV1 {
            case_id: "armed-backfill-after-catch-up".into(),
            assurance_claim: "An epoch-gap replay armed during explicit catch-up runs without later traffic, reaches the below-floor event, and coalesces to one full-history replay.".into(),
            package: "marmot-app".into(),
            target: RegressionTestTargetV1::Library,
            test_name: "tests::explicit_catch_up_arms_and_replays_without_later_traffic".into(),
            features: Vec::new(),
        },
        integration_case(
            "pinned-rewind-horizon",
            "A commit beyond the production-pinned rewind horizon is terminal stale in a normal build and never reported as recovered.",
            "cgka-engine",
            "fork_detection",
            "stale_commit_outside_rewind_horizon_is_not_treated_as_recoverable_fork",
        ),
    ]
}

pub async fn run_regression_campaign(
    workspace_root: &Path,
    output_dir: &Path,
    cargo_program: &Path,
    input: &RegressionCampaignInputV1,
) -> Result<RegressionCampaignReportV1, RunnerError> {
    input.validate()?;
    if output_dir.exists() {
        return Err(RunnerError::validation(
            "regression_campaign_output_exists",
            "campaign output directory already exists; evidence is never overwritten",
        ));
    }
    fs_private::create_dir_all_private(output_dir)
        .map_err(|error| RunnerError::environment("regression_campaign_output", error))?;

    let input_bytes = serde_json::to_vec_pretty(input)
        .map_err(|error| RunnerError::environment("regression_campaign_serialize", error))?;
    let input_path = output_dir.join(REGRESSION_CAMPAIGN_INPUT_FILE);
    fs_private::write_private(&input_path, &input_bytes)
        .map_err(|error| RunnerError::environment("regression_campaign_input_write", error))?;
    let input_sha256 = sha256(&input_bytes);

    let case_timeout = Duration::from_millis(input.case_timeout_ms);
    let mut results = Vec::with_capacity(input.cases.len());
    for case in &input.cases {
        let args = case.cargo_args();
        let started = Instant::now();
        let mut command = Command::new(cargo_program);
        command
            .current_dir(workspace_root)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.as_std_mut().process_group(0);
        }
        let (stdout, stderr, exit_code, signal, timed_out, launch_error) =
            execute_case(command, case_timeout, input.case_timeout_ms).await;
        let stdout_artifact = write_case_artifact(output_dir, case, "stdout", &stdout)?;
        let stderr_artifact = write_case_artifact(output_dir, case, "stderr", &stderr)?;
        let passed =
            !timed_out && launch_error.is_none() && signal.is_none() && exit_code == Some(0);
        results.push(RegressionCaseResultV1 {
            case_id: case.case_id.clone(),
            command_argv: std::iter::once(cargo_program.display().to_string())
                .chain(args)
                .collect(),
            stdout: stdout_artifact,
            stderr: stderr_artifact,
            exit_code,
            signal,
            timed_out,
            launch_error,
            wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            passed,
        });
    }

    let report = RegressionCampaignReportV1 {
        schema_version: REGRESSION_CAMPAIGN_SCHEMA_VERSION.into(),
        campaign_id: input.campaign_id.clone(),
        source_revision: input.source_revision.clone(),
        input_manifest: PathBuf::from(REGRESSION_CAMPAIGN_INPUT_FILE),
        input_sha256,
        passed: results.iter().all(|case| case.passed),
        cases: results,
    };
    report.validate_artifacts(output_dir)?;
    let report_bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| RunnerError::environment("regression_campaign_serialize", error))?;
    fs_private::write_private(
        &output_dir.join(REGRESSION_CAMPAIGN_REPORT_FILE),
        &report_bytes,
    )
    .map_err(|error| RunnerError::environment("regression_campaign_report_write", error))?;
    Ok(report)
}

fn integration_case(
    case_id: &str,
    assurance_claim: &str,
    package: &str,
    target: &str,
    test_name: &str,
) -> RegressionCaseSpecV1 {
    RegressionCaseSpecV1 {
        case_id: case_id.into(),
        assurance_claim: assurance_claim.into(),
        package: package.into(),
        target: RegressionTestTargetV1::Integration {
            name: target.into(),
        },
        test_name: test_name.into(),
        features: Vec::new(),
    }
}

fn write_case_artifact(
    output_dir: &Path,
    case: &RegressionCaseSpecV1,
    stream: &str,
    bytes: &[u8],
) -> Result<RegressionArtifactV1, RunnerError> {
    let path = PathBuf::from(format!("{}.{}.txt", case.case_id, stream));
    fs_private::write_private(&output_dir.join(&path), bytes)
        .map_err(|error| RunnerError::environment("regression_campaign_artifact_write", error))?;
    Ok(RegressionArtifactV1 {
        path,
        sha256: sha256(bytes),
        bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    })
}

fn validate_artifact(base_dir: &Path, artifact: &RegressionArtifactV1) -> Result<(), RunnerError> {
    if !is_lower_sha256(&artifact.sha256) {
        return Err(RunnerError::validation(
            "regression_campaign_artifact",
            "artifact digests must use the portable v1 form",
        ));
    }
    let bytes = read_artifact(base_dir, &artifact.path)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != artifact.bytes
        || sha256(&bytes) != artifact.sha256
    {
        return Err(RunnerError::validation(
            "regression_campaign_artifact_mismatch",
            "artifact bytes do not match the report",
        ));
    }
    Ok(())
}

fn read_artifact(base_dir: &Path, path: &Path) -> Result<Vec<u8>, RunnerError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(RunnerError::validation(
            "regression_campaign_artifact_path",
            "artifact paths must be nonempty relative paths without parent traversal",
        ));
    }
    let canonical_base = std::fs::canonicalize(base_dir)
        .map_err(|error| RunnerError::environment("regression_campaign_artifact_base", error))?;
    let canonical_path = std::fs::canonicalize(canonical_base.join(path))
        .map_err(|error| RunnerError::environment("regression_campaign_artifact_read", error))?;
    if !canonical_path.starts_with(&canonical_base) {
        return Err(RunnerError::validation(
            "regression_campaign_artifact_path",
            "artifact paths must remain within the campaign output directory",
        ));
    }
    std::fs::read(canonical_path)
        .map_err(|error| RunnerError::environment("regression_campaign_artifact_read", error))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn execute_case(
    mut command: Command,
    case_timeout: Duration,
    case_timeout_ms: u64,
) -> (
    Vec<u8>,
    Vec<u8>,
    Option<i32>,
    Option<i32>,
    bool,
    Option<String>,
) {
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return (
                Vec::new(),
                format!("failed to launch case: {error}\n").into_bytes(),
                None,
                None,
                false,
                Some(error.to_string()),
            );
        }
    };
    let stdout_task = tokio::spawn(read_pipe(child.stdout.take()));
    let stderr_task = tokio::spawn(read_pipe(child.stderr.take()));

    let (exit_code, signal, timed_out, mut execution_error) =
        match timeout(case_timeout, child.wait()).await {
            Ok(Ok(status)) => (status.code(), process_signal(&status), false, None),
            Ok(Err(error)) => (
                None,
                None,
                false,
                Some(format!("failed to wait for case: {error}")),
            ),
            Err(_) => {
                let kill_error = kill_process_group(&mut child).await.err();
                (
                    None,
                    None,
                    true,
                    kill_error.map(|error| format!("failed to reap timed-out case: {error}")),
                )
            }
        };

    let (mut stdout, stdout_error) = finish_pipe(stdout_task, "stdout").await;
    let (mut stderr, stderr_error) = finish_pipe(stderr_task, "stderr").await;
    if timed_out {
        stderr.extend_from_slice(
            format!("case exceeded timeout of {case_timeout_ms} ms\n").as_bytes(),
        );
    }
    for error in [stdout_error, stderr_error].into_iter().flatten() {
        if execution_error.is_none() {
            execution_error = Some(error.clone());
        }
        stderr.extend_from_slice(error.as_bytes());
        stderr.push(b'\n');
    }
    if let Some(error) = &execution_error
        && !stderr
            .windows(error.len())
            .any(|window| window == error.as_bytes())
    {
        stderr.extend_from_slice(error.as_bytes());
        stderr.push(b'\n');
    }
    stdout.shrink_to_fit();
    stderr.shrink_to_fit();
    (
        stdout,
        stderr,
        exit_code,
        signal,
        timed_out,
        execution_error,
    )
}

async fn read_pipe(pipe: Option<impl tokio::io::AsyncRead + Unpin>) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    if let Some(mut pipe) = pipe {
        pipe.read_to_end(&mut bytes).await?;
    }
    Ok(bytes)
}

async fn finish_pipe(
    task: tokio::task::JoinHandle<std::io::Result<Vec<u8>>>,
    stream: &str,
) -> (Vec<u8>, Option<String>) {
    match task.await {
        Ok(Ok(bytes)) => (bytes, None),
        Ok(Err(error)) => (
            Vec::new(),
            Some(format!("failed to read case {stream}: {error}")),
        ),
        Err(error) => (
            Vec::new(),
            Some(format!("case {stream} task failed: {error}")),
        ),
    }
}

async fn kill_process_group(child: &mut tokio::process::Child) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let pid = child
            .id()
            .ok_or_else(|| std::io::Error::other("child has no pid"))?;
        let pid = i32::try_from(pid).map_err(std::io::Error::other)?;
        // SAFETY: the child was spawned as the leader of a process group owned
        // by this campaign case. A negative pid targets only that group.
        if unsafe { libc::kill(-pid, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        let _ = child.wait().await?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        child.kill().await?;
        let _ = child.wait().await?;
        Ok(())
    }
}

#[cfg(unix)]
fn process_signal(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn process_signal(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use super::{
        REGRESSION_CAMPAIGN_INPUT_FILE, REGRESSION_CAMPAIGN_REPORT_FILE, RegressionCampaignInputV1,
        RegressionTestTargetV1, focused_convergence_cases, run_regression_campaign,
    };

    #[test]
    fn focused_catalog_pins_every_post_campaign_delta() {
        let cases = focused_convergence_cases();
        assert_eq!(
            cases
                .iter()
                .map(|case| case.case_id.as_str())
                .collect::<Vec<_>>(),
            [
                "missing-anchor-halt",
                "verified-welcome-repair",
                "atomic-self-remove-persistence",
                "armed-backfill-after-catch-up",
                "pinned-rewind-horizon",
            ]
        );
        assert!(cases.iter().all(|case| !case.assurance_claim.is_empty()));
    }

    #[test]
    fn cargo_arguments_are_exact_locked_and_target_specific() {
        let cases = focused_convergence_cases();
        let integration = cases[0].cargo_args();
        assert_eq!(
            integration,
            [
                "test",
                "--locked",
                "-p",
                "cgka-engine",
                "--test",
                "fork_detection",
                "restarted_committer_without_source_anchor_halts_through_convergence",
                "--",
                "--exact",
                "--nocapture",
            ]
        );
        assert!(matches!(cases[3].target, RegressionTestTargetV1::Library));
        assert!(cases[3].cargo_args().iter().any(|arg| arg == "--lib"));
    }

    #[test]
    fn input_validation_rejects_duplicate_cases_and_bad_lock_digest() {
        let mut input = RegressionCampaignInputV1::focused_convergence(
            "abc123".into(),
            "0".repeat(64),
            Duration::from_secs(5),
        )
        .unwrap();
        input.cases.push(input.cases[0].clone());
        assert_eq!(
            input.validate().unwrap_err().code,
            "regression_campaign_case"
        );
        input.cases.pop();
        input.cargo_lock_sha256 = "ABC".into();
        assert_eq!(
            input.validate().unwrap_err().code,
            "regression_campaign_lock_digest"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runner_preserves_exact_input_and_digest_bound_private_artifacts() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("fake-cargo");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o700);
        std::io::Write::write_all(
            &mut options.open(&program).unwrap(),
            b"#!/bin/sh\nprintf 'fake cargo: %s\\n' \"$*\"\nprintf 'diagnostic\\n' >&2\n",
        )
        .unwrap();
        let out = temp.path().join("evidence");
        let input = RegressionCampaignInputV1::focused_convergence(
            "0123456789abcdef".into(),
            "0".repeat(64),
            Duration::from_secs(2),
        )
        .unwrap();

        let report = run_regression_campaign(Path::new("."), &out, &program, &input)
            .await
            .unwrap();

        assert!(report.passed);
        assert_eq!(report.cases.len(), input.cases.len());
        report.validate_artifacts(&out).unwrap();
        assert!(out.join(REGRESSION_CAMPAIGN_INPUT_FILE).is_file());
        assert!(out.join(REGRESSION_CAMPAIGN_REPORT_FILE).is_file());
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for path in std::iter::once(out.join(REGRESSION_CAMPAIGN_INPUT_FILE))
            .chain(std::iter::once(out.join(REGRESSION_CAMPAIGN_REPORT_FILE)))
            .chain(
                report
                    .cases
                    .iter()
                    .flat_map(|case| [out.join(&case.stdout.path), out.join(&case.stderr.path)]),
            )
        {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            run_regression_campaign(Path::new("."), &out, &program, &input)
                .await
                .unwrap_err()
                .code,
            "regression_campaign_output_exists"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failing_case_still_writes_a_complete_report() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("failing-cargo");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o700);
        std::io::Write::write_all(
            &mut options.open(&program).unwrap(),
            b"#!/bin/sh\nprintf 'intentional failure\\n' >&2\nexit 7\n",
        )
        .unwrap();
        let out = temp.path().join("evidence");
        let mut input = RegressionCampaignInputV1::focused_convergence(
            "0123456789abcdef".into(),
            "0".repeat(64),
            Duration::from_secs(2),
        )
        .unwrap();
        input.cases.truncate(1);

        let report = run_regression_campaign(Path::new("."), &out, &program, &input)
            .await
            .unwrap();

        assert!(!report.passed);
        assert_eq!(report.cases[0].exit_code, Some(7));
        assert!(out.join(REGRESSION_CAMPAIGN_REPORT_FILE).is_file());
        report.validate_artifacts(&out).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_reaps_the_case_group_and_preserves_partial_output() {
        use std::os::unix::fs::OpenOptionsExt;

        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("slow-cargo");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o700);
        std::io::Write::write_all(
            &mut options.open(&program).unwrap(),
            b"#!/bin/sh\nprintf 'started before timeout\\n'\nsleep 30\n",
        )
        .unwrap();
        let out = temp.path().join("evidence");
        let mut input = RegressionCampaignInputV1::focused_convergence(
            "0123456789abcdef".into(),
            "0".repeat(64),
            Duration::from_millis(500),
        )
        .unwrap();
        input.cases.truncate(1);

        let report = run_regression_campaign(Path::new("."), &out, &program, &input)
            .await
            .unwrap();

        assert!(!report.passed);
        assert!(report.cases[0].timed_out);
        assert_eq!(report.cases[0].exit_code, None);
        let stdout = std::fs::read_to_string(out.join(&report.cases[0].stdout.path)).unwrap();
        let stderr = std::fs::read_to_string(out.join(&report.cases[0].stderr.path)).unwrap();
        assert!(stdout.contains("started before timeout"));
        assert!(stderr.contains("case exceeded timeout"));
        report.validate_artifacts(&out).unwrap();
    }
}
