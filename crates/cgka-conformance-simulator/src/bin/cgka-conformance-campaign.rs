use cgka_conformance_simulator::{
    GeneratedScenarioCase, GeneratedScenarioInputV1, HarnessStorageMode, ReportArgs, ReportInput,
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
            .arg(storage_label(args.storage));
        if args.capture_sensitive_replay {
            command.arg("--capture-sensitive-replay");
        }
        let started = Instant::now();
        let child = command.spawn()?;
        let usage = wait_with_usage(child, args.case_timeout)?;
        let inspection = inspect_case_artifacts(&case, &paths, &usage);
        observations.push(ProcessCaseMeasurementV1 {
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
            wall_us: elapsed_us(started.elapsed()),
            user_cpu_us: usage.user_cpu_us,
            system_cpu_us: usage.system_cpu_us,
            peak_rss_bytes: usage.peak_rss_bytes,
            database_bytes: inspection.database_bytes,
            filesystem_block_write_lower_bound_bytes: usage
                .filesystem_block_write_lower_bound_bytes,
            unavailable_process_fields: usage.unavailable_process_fields,
            artifact_integrity_errors: inspection.integrity_errors,
        });
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
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, Box<dyn Error>> {
    let mut family = "adversarial-reliability/v1".to_owned();
    let mut seed = 7;
    let mut cases = 12;
    let mut out = PathBuf::from("target/cgka-adversarial-reliability-process-campaign");
    let mut storage = HarnessStorageMode::TempFileBackedSqlite;
    let mut case_timeout = Duration::from_secs(300);
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
    Ok(Args {
        family,
        seed,
        cases,
        out,
        storage,
        case_timeout,
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
