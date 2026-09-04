use cgka_conformance_simulator::{
    GeneratedScenarioCase, GeneratedScenarioInputV1, GeneratedScenarioMinimizationBudget,
    GeneratedScenarioMinimizationStatus, HarnessStorageMode, ReportArgs, ReportInput,
    ScenarioReport, generate_family_case, resolve_scenario_input_bytes, run_report,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Args {
    family: String,
    seed: u64,
    cases: usize,
    out: PathBuf,
    storage: HarnessStorageMode,
    case_timeout: Duration,
    minimization_budget: GeneratedScenarioMinimizationBudget,
    input: Option<PathBuf>,
    capture_sensitive_replay: bool,
    worker: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessCampaignReportV1 {
    schema_version: String,
    family: String,
    seed: u64,
    storage: String,
    case_timeout_ms: u64,
    capture_sensitive_replay: bool,
    minimization_wall_time_ms: u64,
    minimization_max_trials: usize,
    minimization_trial_timeout_ms: u64,
    cases: Vec<ProcessCaseMeasurementV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessCaseMeasurementV1 {
    case_index: usize,
    generated_input: PathBuf,
    report: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fixture_candidate: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failure_capsule: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sensitive_replay_capsule: Option<PathBuf>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timeout_phase: Option<ProcessCaseTimeoutPhaseV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minimization_status: Option<GeneratedScenarioMinimizationStatus>,
    wall_us: u64,
    user_cpu_us: Option<u64>,
    system_cpu_us: Option<u64>,
    peak_rss_bytes: Option<u64>,
    database_bytes: Option<u64>,
    filesystem_block_write_lower_bound_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unavailable_process_fields: Vec<String>,
    #[serde(default)]
    artifact_integrity_errors: Vec<String>,
}

struct CaseArtifactPaths {
    generated_input: PathBuf,
    report: PathBuf,
    fixture_candidate: PathBuf,
    failure_capsule: PathBuf,
    sensitive_replay_capsule: PathBuf,
}

struct PlannedCase {
    case: GeneratedScenarioCase,
    paths: CaseArtifactPaths,
    generated_input_bytes: Vec<u8>,
}

struct CaseArtifactInspection {
    integrity_errors: Vec<String>,
    database_bytes: Option<u64>,
    timeout_phase: Option<ProcessCaseTimeoutPhaseV1>,
    minimization_status: Option<GeneratedScenarioMinimizationStatus>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessCaseTimeoutPhaseV1 {
    ScenarioExecution,
    Minimization,
    PostProcessing,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("cgka campaign: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode, Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.worker {
        return run_worker(&args).await;
    }
    let executable = std::env::current_exe()?;
    let (summary_path, planned_cases) = preflight_campaign(&args)?;
    #[cfg(unix)]
    let _output_dir_guard = fs_private::prepare_directory_path(
        &args.out,
        fs_private::PRIVATE_DIR_MODE,
        fs_private::ExistingDirectoryMode::Preserve,
    )?;
    #[cfg(not(unix))]
    fs_private::create_dir_all_private(&args.out)?;
    let mut observations = Vec::with_capacity(args.cases);
    for (case_index, planned) in planned_cases.into_iter().enumerate() {
        let PlannedCase {
            case,
            paths,
            generated_input_bytes,
        } = planned;
        fs_private::write_private(&paths.generated_input, &generated_input_bytes)?;
        let mut command = Command::new(&executable);
        command
            .arg("--worker")
            .arg("--input")
            .arg(&paths.generated_input)
            .arg("--out")
            .arg(&args.out)
            .arg("--storage")
            .arg(storage_label(args.storage))
            .arg("--minimization-wall-time-secs")
            .arg(args.minimization_budget.wall_clock.as_secs().to_string())
            .arg("--minimization-max-trials")
            .arg(args.minimization_budget.max_trials.to_string())
            .arg("--minimization-trial-timeout-secs")
            .arg(
                args.minimization_budget
                    .per_trial_timeout
                    .as_secs()
                    .to_string(),
            );
        if args.capture_sensitive_replay {
            command.arg("--capture-sensitive-replay");
        }
        let started = Instant::now();
        let child = command.spawn()?;
        let worker_pid = child.id();
        let usage = wait_with_usage(child, args.case_timeout)?;
        let mut inspection = inspect_case_artifacts(&case, &paths, &usage);
        inspection
            .integrity_errors
            .extend(cleanup_worker_temporary_artifacts(&paths, worker_pid));
        observations.push(build_case_measurement(
            case_index,
            paths,
            usage,
            inspection,
            started.elapsed(),
        ));
    }
    let failed = observations.iter().any(|case| {
        case.timed_out
            || case.exit_code != Some(0)
            || case.signal.is_some()
            || !case.artifact_integrity_errors.is_empty()
    });
    let summary = ProcessCampaignReportV1 {
        schema_version: "1".into(),
        family: args.family,
        seed: args.seed,
        storage: storage_label(args.storage).into(),
        case_timeout_ms: elapsed_ms(args.case_timeout),
        capture_sensitive_replay: args.capture_sensitive_replay,
        minimization_wall_time_ms: elapsed_ms(args.minimization_budget.wall_clock),
        minimization_max_trials: args.minimization_budget.max_trials,
        minimization_trial_timeout_ms: elapsed_ms(args.minimization_budget.per_trial_timeout),
        cases: observations,
    };
    fs_private::write_private(&summary_path, &serde_json::to_vec_pretty(&summary)?)?;
    println!("Process campaign report: {}", summary_path.display());
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn run_worker(args: &Args) -> Result<ExitCode, Box<dyn Error>> {
    let input = args.input.clone().ok_or("worker requires --input")?;
    let summary = run_report(&ReportArgs {
        input: ReportInput::GeneratedInputs {
            paths: vec![input],
            adapter: None,
        },
        out: args.out.clone(),
        strict_oracle: true,
        storage_mode: args.storage,
        capture_sensitive_replay: args.capture_sensitive_replay,
        minimization_budget: args.minimization_budget,
    })
    .await?;
    println!("{}", summary.to_human_text());
    let failed = summary.failed() > 0;
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn inspect_case_artifacts(
    case: &GeneratedScenarioCase,
    paths: &CaseArtifactPaths,
    usage: &ChildUsage,
) -> CaseArtifactInspection {
    let mut errors = Vec::new();
    let input_bytes = match std::fs::read(&paths.generated_input) {
        Ok(bytes) => bytes,
        Err(error) => {
            errors.push(format!("generated_input_unreadable:{error}"));
            Vec::new()
        }
    };
    let expected_source_sha256 = if input_bytes.is_empty() {
        None
    } else {
        match resolve_scenario_input_bytes(&input_bytes) {
            Ok(resolved) => {
                if resolved.generated_case.as_ref() != Some(case) {
                    errors.push("generated_input_case_mismatch".into());
                }
                Some(resolved.provenance.source_sha256)
            }
            Err(error) => {
                errors.push(format!("generated_input_invalid:{error}"));
                None
            }
        }
    };

    let normally_exited = !usage.timed_out && usage.signal.is_none();
    let report = match std::fs::read(&paths.report) {
        Ok(bytes) => match serde_json::from_slice::<ScenarioReport>(&bytes) {
            Ok(report) => Some(report),
            Err(error) => {
                if normally_exited {
                    errors.push(format!("report_invalid:{error}"));
                }
                None
            }
        },
        Err(error) => {
            if normally_exited {
                errors.push(format!("report_unreadable:{error}"));
            }
            None
        }
    };
    let database_bytes = report
        .as_ref()
        .and_then(|report| report.campaign_measurements.database_bytes);
    let minimization_status = report
        .as_ref()
        .and_then(|report| report.metadata.generated.as_ref())
        .map(|generated| generated.minimization.status);
    let timeout_phase = classify_timeout_phase(usage.timed_out, minimization_status);

    // A timeout or signal may interrupt the worker before it can publish a
    // report. A normally exiting worker, including a strict-oracle failure,
    // must leave a parseable report and fixture candidate.
    if normally_exited {
        if let Some(report) = report.as_ref() {
            let generated = report.metadata.generated.as_ref();
            if generated.map(|value| {
                (
                    value.family_name.as_str(),
                    value.generator_version.as_str(),
                    value.seed,
                    value.case_index,
                )
            }) != Some((
                case.family_name.as_str(),
                case.generator_version.as_str(),
                case.seed,
                case.case_index,
            )) {
                errors.push("report_generated_metadata_mismatch".into());
            }
            if report
                .metadata
                .input_provenance
                .as_ref()
                .map(|value| value.source_sha256.as_str())
                != expected_source_sha256.as_deref()
            {
                errors.push("report_input_digest_mismatch".into());
            }
        }
        if !paths.fixture_candidate.is_file() {
            errors.push("fixture_candidate_missing".into());
        }
        if usage.exit_code != Some(0) && paths.report.is_file() && !paths.failure_capsule.is_file()
        {
            errors.push("failure_capsule_missing".into());
        }
    }
    CaseArtifactInspection {
        integrity_errors: errors,
        database_bytes,
        timeout_phase,
        minimization_status,
    }
}

/// Removes same-process atomic-replacement files that can survive a forced
/// worker termination, returning integrity errors for anything not cleaned.
fn cleanup_worker_temporary_artifacts(paths: &CaseArtifactPaths, worker_pid: u32) -> Vec<String> {
    let Some(parent) = paths.report.parent() else {
        return vec!["temporary_artifact_parent_missing".into()];
    };
    let marker = format!(".tmp-{worker_pid}-");
    let prefixes = [
        &paths.report,
        &paths.failure_capsule,
        &paths.sensitive_replay_capsule,
    ]
    .into_iter()
    .filter_map(|path| path.file_name())
    .map(|name| {
        let mut prefix = name.as_encoded_bytes().to_vec();
        prefix.extend_from_slice(marker.as_bytes());
        prefix
    })
    .collect::<Vec<_>>();
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => return vec![format!("temporary_artifact_scan_failed:{error}")],
    };
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("temporary_artifact_scan_failed:{error}"));
                continue;
            }
        };
        let name = entry.file_name();
        if !prefixes
            .iter()
            .any(|prefix| name.as_encoded_bytes().starts_with(prefix))
        {
            continue;
        }
        let path = entry.path();
        if let Err(error) = std::fs::remove_file(&path) {
            errors.push(format!(
                "temporary_artifact_cleanup_failed:{}:{error}",
                path.display()
            ));
        }
    }
    errors
}

/// Maps reaped process usage and durable artifact inspection into the schema
/// written to the process-campaign summary.
fn build_case_measurement(
    case_index: usize,
    paths: CaseArtifactPaths,
    usage: ChildUsage,
    inspection: CaseArtifactInspection,
    elapsed: Duration,
) -> ProcessCaseMeasurementV1 {
    ProcessCaseMeasurementV1 {
        case_index,
        generated_input: paths.generated_input,
        report: paths.report,
        fixture_candidate: paths
            .fixture_candidate
            .exists()
            .then_some(paths.fixture_candidate),
        failure_capsule: paths
            .failure_capsule
            .exists()
            .then_some(paths.failure_capsule),
        sensitive_replay_capsule: paths
            .sensitive_replay_capsule
            .exists()
            .then_some(paths.sensitive_replay_capsule),
        exit_code: usage.exit_code,
        signal: usage.signal,
        timed_out: usage.timed_out,
        timeout_phase: inspection.timeout_phase,
        minimization_status: inspection.minimization_status,
        wall_us: elapsed_us(elapsed),
        user_cpu_us: usage.user_cpu_us,
        system_cpu_us: usage.system_cpu_us,
        peak_rss_bytes: usage.peak_rss_bytes,
        database_bytes: inspection.database_bytes,
        filesystem_block_write_lower_bound_bytes: usage.filesystem_block_write_lower_bound_bytes,
        unavailable_process_fields: usage.unavailable_process_fields,
        artifact_integrity_errors: inspection.integrity_errors,
    }
}

fn classify_timeout_phase(
    timed_out: bool,
    minimization_status: Option<GeneratedScenarioMinimizationStatus>,
) -> Option<ProcessCaseTimeoutPhaseV1> {
    timed_out.then_some(match minimization_status {
        Some(GeneratedScenarioMinimizationStatus::Pending) => {
            ProcessCaseTimeoutPhaseV1::Minimization
        }
        Some(_) => ProcessCaseTimeoutPhaseV1::PostProcessing,
        None => ProcessCaseTimeoutPhaseV1::ScenarioExecution,
    })
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, Box<dyn Error>> {
    let mut family = "adversarial-reliability/v1".to_owned();
    let mut seed = 7;
    let mut cases = 12;
    let mut out = PathBuf::from("target/cgka-adversarial-reliability-process-campaign");
    let mut storage = HarnessStorageMode::TempFileBackedSqlite;
    let mut case_timeout = Duration::from_secs(300);
    let mut minimization_budget = GeneratedScenarioMinimizationBudget::default();
    let mut input = None;
    let mut capture_sensitive_replay = false;
    let mut worker = false;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--worker" => worker = true,
            "--family" => family = args.next().ok_or("missing --family value")?,
            "--seed" => seed = args.next().ok_or("missing --seed value")?.parse()?,
            "--cases" => cases = args.next().ok_or("missing --cases value")?.parse()?,
            "--out" => out = PathBuf::from(args.next().ok_or("missing --out value")?),
            "--input" => input = Some(PathBuf::from(args.next().ok_or("missing --input value")?)),
            "--capture-sensitive-replay" => capture_sensitive_replay = true,
            "--storage" => {
                storage = match args.next().ok_or("missing --storage value")?.as_str() {
                    "memory" => HarnessStorageMode::InMemorySqlite,
                    "file" => HarnessStorageMode::TempFileBackedSqlite,
                    other => return Err(format!("invalid storage mode {other}").into()),
                }
            }
            "--case-timeout-secs" => {
                case_timeout = Duration::from_secs(
                    args.next()
                        .ok_or("missing --case-timeout-secs value")?
                        .parse()?,
                )
            }
            "--minimization-wall-time-secs" => {
                minimization_budget.wall_clock = Duration::from_secs(
                    args.next()
                        .ok_or("missing --minimization-wall-time-secs value")?
                        .parse()?,
                )
            }
            "--minimization-max-trials" => {
                minimization_budget.max_trials = args
                    .next()
                    .ok_or("missing --minimization-max-trials value")?
                    .parse()?
            }
            "--minimization-trial-timeout-secs" => {
                minimization_budget.per_trial_timeout = Duration::from_secs(
                    args.next()
                        .ok_or("missing --minimization-trial-timeout-secs value")?
                        .parse()?,
                )
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    if worker && input.is_none() {
        return Err("worker requires --input".into());
    }
    if !worker && input.is_some() {
        return Err("--input is reserved for campaign workers".into());
    }
    if !worker && cases == 0 {
        return Err("--cases must be greater than zero".into());
    }
    if !worker && case_timeout.is_zero() {
        return Err("--case-timeout-secs must be greater than zero".into());
    }
    minimization_budget = minimization_budget.validate()?;
    Ok(Args {
        family,
        seed,
        cases,
        out,
        storage,
        case_timeout,
        minimization_budget,
        input,
        capture_sensitive_replay,
        worker,
    })
}

fn preflight_campaign(args: &Args) -> Result<(PathBuf, Vec<PlannedCase>), Box<dyn Error>> {
    let summary_path = args.out.join("process-campaign.v1.json");
    ensure_path_absent(&summary_path)?;
    let mut planned_cases = Vec::with_capacity(args.cases);
    for case_index in 0..args.cases {
        let case = generate_family_case(&args.family, args.seed, u64::try_from(case_index)?)?;
        let paths = case_artifact_paths(&args.out, &case);
        for path in [
            &paths.generated_input,
            &paths.report,
            &paths.fixture_candidate,
            &paths.failure_capsule,
            &paths.sensitive_replay_capsule,
        ] {
            ensure_path_absent(path)?;
        }
        let generated_input_bytes =
            serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case.clone()))?;
        planned_cases.push(PlannedCase {
            case,
            paths,
            generated_input_bytes,
        });
    }
    Ok((summary_path, planned_cases))
}

fn case_artifact_paths(out: &Path, case: &GeneratedScenarioCase) -> CaseArtifactPaths {
    let stem = format!(
        "{}-seed-{}-case-{}",
        case.family_name.replace('/', "-"),
        case.seed,
        case.case_index
    );
    CaseArtifactPaths {
        generated_input: out.join(format!("{stem}-generated-input.json")),
        report: out.join(format!("{stem}.json")),
        fixture_candidate: out.join(format!("{stem}-fixture.v1.json")),
        failure_capsule: out.join(format!("{stem}-failure-capsule.v1.json")),
        sensitive_replay_capsule: out.join(format!("{stem}-sensitive-replay-capsule.v1.json")),
    }
}

fn ensure_path_absent(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing campaign artifact: {}",
            path.display()
        )
        .into());
    }
    Ok(())
}

fn storage_label(storage: HarnessStorageMode) -> &'static str {
    match storage {
        HarnessStorageMode::InMemorySqlite => "memory",
        HarnessStorageMode::TempFileBackedSqlite => "file",
    }
}

fn elapsed_us(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn elapsed_ms(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

struct ChildUsage {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    user_cpu_us: Option<u64>,
    system_cpu_us: Option<u64>,
    peak_rss_bytes: Option<u64>,
    filesystem_block_write_lower_bound_bytes: Option<u64>,
    unavailable_process_fields: Vec<String>,
}

#[cfg(unix)]
fn wait_with_usage(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<ChildUsage, Box<dyn Error>> {
    let pid = i32::try_from(child.id())?;
    let mut status = 0;
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("case timeout exceeds the host clock range")?;
    let timed_out = loop {
        // SAFETY: `pid` is the live direct child just spawned above; both output
        // pointers refer to writable storage for the duration of wait4.
        let waited = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, usage.as_mut_ptr()) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
        if waited == pid {
            break false;
        }
        if Instant::now() >= deadline {
            // Close the polling race: the worker may have exited successfully
            // after the check above but before the deadline comparison.
            let waited =
                unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, usage.as_mut_ptr()) };
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
            if waited == pid {
                break false;
            }
            if let Err(error) = child.kill() {
                if error.kind() == std::io::ErrorKind::InvalidInput {
                    let waited = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
                    if waited < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    break false;
                }
                let _ = child.wait();
                return Err(error.into());
            }
            // SAFETY: after killing the same direct child, blocking wait4 reaps
            // it and initializes both status and rusage.
            let waited = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
            if waited < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // SAFETY: either successful wait4 path initialized the complete rusage value.
    let usage = unsafe { usage.assume_init() };
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let (filesystem_block_write_lower_bound_bytes, unavailable_process_fields) = (
        None,
        vec!["filesystem_block_write_lower_bound_bytes".to_owned()],
    );
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    // `ru_oublock` counts real block-device output, so page-cache absorption
    // can only make this a lower bound for all child-process filesystem writes.
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
        timed_out,
        user_cpu_us: Some(timeval_us(usage.ru_utime)),
        system_cpu_us: Some(timeval_us(usage.ru_stime)),
        peak_rss_bytes: Some(peak_rss_bytes(usage.ru_maxrss)),
        filesystem_block_write_lower_bound_bytes,
        unavailable_process_fields,
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

#[cfg(not(unix))]
fn wait_with_usage(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<ChildUsage, Box<dyn Error>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("case timeout exceeds the host clock range")?;
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            if let Err(error) = child.kill()
                && error.kind() != std::io::ErrorKind::InvalidInput
            {
                return Err(error.into());
            }
            break (child.wait()?, true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Ok(ChildUsage {
        exit_code: status.code(),
        signal: None,
        timed_out,
        user_cpu_us: None,
        system_cpu_us: None,
        peak_rss_bytes: None,
        filesystem_block_write_lower_bound_bytes: None,
        unavailable_process_fields: vec![
            "user_cpu_us".to_owned(),
            "system_cpu_us".to_owned(),
            "peak_rss_bytes".to_owned(),
            "filesystem_block_write_lower_bound_bytes".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_per_case_timeout() {
        let args = parse_args(["--case-timeout-secs", "17"].into_iter().map(str::to_owned))
            .expect("arguments parse");
        assert_eq!(args.case_timeout, Duration::from_secs(17));
    }

    #[test]
    fn parses_minimization_budgets() {
        let args = parse_args(
            [
                "--minimization-wall-time-secs",
                "19",
                "--minimization-max-trials",
                "31",
                "--minimization-trial-timeout-secs",
                "4",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("arguments parse");
        assert_eq!(
            args.minimization_budget,
            GeneratedScenarioMinimizationBudget {
                wall_clock: Duration::from_secs(19),
                max_trials: 31,
                per_trial_timeout: Duration::from_secs(4),
            }
        );
    }

    #[test]
    fn timeout_phase_distinguishes_scenario_execution_from_minimization() {
        assert_eq!(
            classify_timeout_phase(true, None),
            Some(ProcessCaseTimeoutPhaseV1::ScenarioExecution)
        );
        assert_eq!(
            classify_timeout_phase(true, Some(GeneratedScenarioMinimizationStatus::Pending)),
            Some(ProcessCaseTimeoutPhaseV1::Minimization)
        );
        assert_eq!(
            classify_timeout_phase(
                true,
                Some(GeneratedScenarioMinimizationStatus::BudgetExhausted)
            ),
            Some(ProcessCaseTimeoutPhaseV1::PostProcessing)
        );
        assert_eq!(
            classify_timeout_phase(
                false,
                Some(GeneratedScenarioMinimizationStatus::BudgetExhausted)
            ),
            None
        );
    }

    #[test]
    fn parses_family_and_sensitive_capture() {
        let args = parse_args(
            ["--family", "chat-journey/v1", "--capture-sensitive-replay"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("arguments parse");
        assert_eq!(args.family, "chat-journey/v1");
        assert!(args.capture_sensitive_replay);
    }

    #[test]
    fn every_report_family_generates_an_exact_case() {
        for family in [
            "send-leave/v1",
            "convergence-e2e-delivery/v1",
            "convergence-chaos/v1",
            "admin-churn/v1",
            "adversarial-reliability/v1",
            "bounded-convergence-pressure/v1",
            "large-group-pressure/v1",
            "offline-catchup-pressure/v1",
            "membership-reentry/v1",
            "cross-route-exact-restart-permutations/v1",
            "cross-route-restart-permutations/v1",
            "chat-journey/v1",
        ] {
            let case = generate_family_case(family, 42, 3).expect("family case generates");
            assert_eq!(case.seed, 42);
            assert_eq!(case.case_index, 3);
            let legacy_prefix_case = match family {
                "send-leave/v1" => cgka_conformance_simulator::generate_send_leave_family(42, 4),
                "convergence-e2e-delivery/v1" => {
                    cgka_conformance_simulator::generate_convergence_e2e_delivery_family(42, 4)
                }
                "convergence-chaos/v1" => {
                    cgka_conformance_simulator::generate_convergence_chaos_family(42, 4)
                }
                "admin-churn/v1" => cgka_conformance_simulator::generate_admin_churn_family(42, 4),
                "adversarial-reliability/v1" => {
                    cgka_conformance_simulator::generate_adversarial_reliability_family(42, 4)
                }
                "bounded-convergence-pressure/v1" => {
                    cgka_conformance_simulator::generate_bounded_convergence_pressure_family(42, 4)
                }
                "large-group-pressure/v1" => {
                    cgka_conformance_simulator::generate_large_group_pressure_family(42, 4)
                }
                "offline-catchup-pressure/v1" => {
                    cgka_conformance_simulator::generate_offline_catchup_pressure_family(42, 4)
                }
                "membership-reentry/v1" => {
                    cgka_conformance_simulator::generate_membership_reentry_family(42, 4)
                }
                "cross-route-exact-restart-permutations/v1" => {
                    cgka_conformance_simulator::generate_cross_route_exact_restart_permutation_family(
                        42, 4,
                    )
                }
                "cross-route-restart-permutations/v1" => {
                    cgka_conformance_simulator::generate_cross_route_restart_permutation_family(
                        42, 4,
                    )
                }
                "chat-journey/v1" => {
                    cgka_conformance_simulator::generate_stateful_chat_journey_family(42, 4)
                }
                _ => unreachable!("family list is exhaustive"),
            }
            .pop()
            .expect("prefix contains requested case");
            assert_eq!(case, legacy_prefix_case);
        }
    }

    #[test]
    fn rejects_empty_or_worker_only_parent_inputs() {
        for args in [
            vec!["--cases", "0"],
            vec!["--case-timeout-secs", "0"],
            vec!["--minimization-wall-time-secs", "0"],
            vec!["--minimization-max-trials", "0"],
            vec!["--minimization-trial-timeout-secs", "0"],
            vec!["--input", "case.json"],
            vec!["--worker"],
        ] {
            let parsed = parse_args(args.iter().copied().map(str::to_owned));
            assert!(parsed.is_err(), "{args:?} must fail");
        }
    }

    #[test]
    fn case_artifacts_use_the_report_cli_stem() {
        let case = generate_family_case("convergence-chaos/v1", 42, 3).expect("case generates");
        let paths = case_artifact_paths(Path::new("out"), &case);
        let stem = "convergence-chaos-v1-seed-42-case-3";
        assert_eq!(
            paths.generated_input,
            Path::new("out").join(format!("{stem}-generated-input.json"))
        );
        assert_eq!(paths.report, Path::new("out").join(format!("{stem}.json")));
        assert_eq!(
            paths.fixture_candidate,
            Path::new("out").join(format!("{stem}-fixture.v1.json"))
        );
    }

    #[test]
    fn preflight_rejects_an_unknown_family_without_creating_output() {
        let temp = tempfile::tempdir().expect("temporary campaign root");
        let out = temp.path().join("not-created");
        let args = parse_args(
            [
                "--family",
                "unknown/v1",
                "--cases",
                "1",
                "--out",
                out.to_str().expect("UTF-8 test path"),
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("arguments parse");
        let error = preflight_campaign(&args)
            .err()
            .expect("unknown family must fail")
            .to_string();
        assert!(error.contains("unsupported family unknown/v1"));
        assert!(!out.exists());
    }

    #[test]
    fn cleanup_removes_only_temporaries_owned_by_the_reaped_worker() {
        let root = tempfile::tempdir().expect("temporary campaign root");
        let case = generate_family_case("send-leave/v1", 42, 0).expect("case generates");
        let paths = case_artifact_paths(root.path(), &case);
        let report_temporary = replacement_temporary_path(&paths.report, 4242, 0);
        let replay_temporary = replacement_temporary_path(&paths.sensitive_replay_capsule, 4242, 1);
        let unrelated_temporary = replacement_temporary_path(&paths.report, 7777, 0);
        for path in [&report_temporary, &replay_temporary, &unrelated_temporary] {
            fs_private::write_private(path, b"private temporary artifact")
                .expect("temporary artifact writes");
        }

        assert!(cleanup_worker_temporary_artifacts(&paths, 4242).is_empty());
        assert!(!report_temporary.exists());
        assert!(!replay_temporary.exists());
        assert!(unrelated_temporary.exists());
    }

    #[cfg(unix)]
    #[test]
    fn interrupted_minimization_preserves_original_artifacts_and_summary_phase() {
        let root = tempfile::tempdir().expect("temporary campaign root");
        let out = root.path().join("interrupted");
        fs_private::create_dir_all_private(&out).expect("private output directory");
        let case = interrupted_minimization_case();
        let paths = case_artifact_paths(&out, &case);
        fs_private::write_private(
            &paths.generated_input,
            &serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case.clone()))
                .expect("generated input serializes"),
        )
        .expect("generated input writes");

        let mut child = Command::new(std::env::current_exe().expect("test executable path"))
            .args([
                "--ignored",
                "--exact",
                "tests::interrupted_minimization_worker_fixture",
            ])
            .env("CGKA_INTERRUPTED_WORKER_INPUT", &paths.generated_input)
            .env("CGKA_INTERRUPTED_WORKER_OUT", &out)
            .spawn()
            .expect("worker fixture starts");
        let worker_pid = child.id();
        let deadline = Instant::now() + Duration::from_secs(30);
        let pending_report = loop {
            if let Ok(bytes) = std::fs::read(&paths.report)
                && let Ok(report) = serde_json::from_slice::<ScenarioReport>(&bytes)
                && report.metadata.generated.as_ref().map(|generated| {
                    generated.minimization.status == GeneratedScenarioMinimizationStatus::Pending
                }) == Some(true)
                && paths.fixture_candidate.is_file()
                && cgka_conformance_simulator::read_failure_capsule(&paths.failure_capsule).is_ok()
            {
                break report;
            }
            if let Some(status) = child.try_wait().expect("worker status reads") {
                panic!("worker exited before interruption evidence was durable: {status}");
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker did not publish pending minimization evidence");
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        assert!(
            pending_report
                .expectation_failures
                .iter()
                .any(|failure| failure.kind == "client_state_mismatch")
        );
        let usage = wait_with_usage(child, Duration::ZERO).expect("worker is killed and reaped");
        assert!(usage.timed_out);
        let mut inspection = inspect_case_artifacts(&case, &paths, &usage);
        inspection
            .integrity_errors
            .extend(cleanup_worker_temporary_artifacts(&paths, worker_pid));
        assert!(inspection.integrity_errors.is_empty());
        let measurement =
            build_case_measurement(0, paths, usage, inspection, Duration::from_millis(1));
        let summary = ProcessCampaignReportV1 {
            schema_version: "1".into(),
            family: case.family_name,
            seed: case.seed,
            storage: "memory".into(),
            case_timeout_ms: 1,
            capture_sensitive_replay: false,
            minimization_wall_time_ms: 300_000,
            minimization_max_trials: 10_000,
            minimization_trial_timeout_ms: 60_000,
            cases: vec![measurement],
        };
        let value = serde_json::to_value(summary).expect("campaign summary serializes");
        assert_eq!(value["cases"][0]["timed_out"], true);
        assert_eq!(value["cases"][0]["minimization_status"], "pending");
        assert_eq!(value["cases"][0]["timeout_phase"], "minimization");
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "process fixture launched by interrupted_minimization_preserves_original_artifacts_and_summary_phase"]
    async fn interrupted_minimization_worker_fixture() {
        let input = PathBuf::from(
            std::env::var_os("CGKA_INTERRUPTED_WORKER_INPUT").expect("worker fixture input path"),
        );
        let out = PathBuf::from(
            std::env::var_os("CGKA_INTERRUPTED_WORKER_OUT").expect("worker fixture output path"),
        );
        let result = run_worker(&Args {
            family: "interrupted-minimization/v1".into(),
            seed: 0,
            cases: 1,
            out,
            storage: HarnessStorageMode::InMemorySqlite,
            case_timeout: Duration::from_secs(300),
            minimization_budget: GeneratedScenarioMinimizationBudget {
                wall_clock: Duration::from_secs(300),
                max_trials: 10_000,
                per_trial_timeout: Duration::from_secs(60),
            },
            input: Some(input),
            capture_sensitive_replay: false,
            worker: true,
        })
        .await;
        panic!("worker fixture completed before being interrupted: {result:?}");
    }

    fn replacement_temporary_path(target: &Path, worker_pid: u32, id: u64) -> PathBuf {
        let mut name = target
            .file_name()
            .expect("artifact target names a file")
            .to_os_string();
        name.push(format!(".tmp-{worker_pid}-{id}"));
        target
            .parent()
            .expect("artifact target has a parent")
            .join(name)
    }

    fn interrupted_minimization_case() -> GeneratedScenarioCase {
        let mut scenario = cgka_conformance_simulator::ScenarioSpec {
            name: "interrupted-minimization/v1/case-0".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into(), "bob".into()],
            steps: vec![
                cgka_conformance_simulator::ScenarioStep::CreateGroup {
                    creator: "alice".into(),
                    name: "interrupted".into(),
                    invitees: vec!["bob".into()],
                    required_features: Vec::new(),
                    initial_admins: None,
                    pending: "create".into(),
                },
                cgka_conformance_simulator::ScenarioStep::accept_publication("alice", "create"),
                cgka_conformance_simulator::ScenarioStep::DeliverAll,
                cgka_conformance_simulator::ScenarioStep::Tick {
                    clients: vec!["bob".into()],
                },
                cgka_conformance_simulator::ScenarioStep::ClearEvents {
                    clients: vec!["alice".into(), "bob".into()],
                },
            ],
        };
        for index in 0..24 {
            scenario
                .steps
                .push(cgka_conformance_simulator::ScenarioStep::SendAppMessage {
                    sender: "bob".into(),
                    payload: format!("interruption noise {index}"),
                });
        }
        scenario.steps.extend([
            cgka_conformance_simulator::ScenarioStep::DeliverAll,
            cgka_conformance_simulator::ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
            cgka_conformance_simulator::ScenarioStep::Observe {
                clients: vec!["alice".into()],
            },
        ]);
        GeneratedScenarioCase {
            family_name: "interrupted-minimization/v1".into(),
            generator_version: "1".into(),
            seed: 17,
            case_index: 0,
            workload_profile: None,
            subject: cgka_conformance_simulator::GeneratedSubjectKind::Engine,
            scenario,
            expected_outcomes: vec![cgka_conformance_simulator::TraceExpectation::ClientState {
                client: "alice".into(),
                epoch: 1,
                member_count: 99,
                received_payloads: None,
                added_members: None,
                removed_members: None,
            }],
        }
    }

    #[cfg(unix)]
    #[test]
    fn kills_and_reaps_a_worker_that_exceeds_its_timeout() {
        let child = Command::new("sh")
            .args(["-c", "sleep 2"])
            .spawn()
            .expect("spawn sleeping child");
        let usage = wait_with_usage(child, Duration::from_millis(10)).expect("reap child");
        assert!(usage.timed_out);
        assert!(usage.signal.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_a_workers_nonzero_exit_code() {
        let child = Command::new("sh")
            .args(["-c", "exit 7"])
            .spawn()
            .expect("spawn failing child");
        let usage = wait_with_usage(child, Duration::from_secs(1)).expect("reap child");
        assert!(!usage.timed_out);
        assert_eq!(usage.exit_code, Some(7));
        assert_eq!(usage.signal, None);
    }
}
