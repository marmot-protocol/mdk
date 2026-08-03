use cgka_conformance_simulator::{
    HarnessStorageMode, ScenarioReport, generate_milestone3_adversarial_case,
    run_generated_case_report_with_storage_mode,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Args {
    seed: u64,
    cases: usize,
    case_index: Option<usize>,
    out: PathBuf,
    storage: HarnessStorageMode,
    case_timeout: Duration,
    worker: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessCampaignReportV1 {
    schema_version: String,
    seed: u64,
    cases: Vec<ProcessCaseMeasurementV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProcessCaseMeasurementV1 {
    case_index: usize,
    report: PathBuf,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    wall_us: u64,
    user_cpu_us: Option<u64>,
    system_cpu_us: Option<u64>,
    peak_rss_bytes: Option<u64>,
    database_bytes: Option<u64>,
    database_write_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unavailable_process_fields: Vec<String>,
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
    fs_private::create_dir_all_private(&args.out)?;

    let executable = std::env::current_exe()?;
    let mut observations = Vec::with_capacity(args.cases);
    for case_index in 0..args.cases {
        let report = args.out.join(format!("case-{case_index}.json"));
        let mut command = Command::new(&executable);
        command.args([
            "--worker",
            "--seed",
            &args.seed.to_string(),
            "--case-index",
            &case_index.to_string(),
            "--out",
            report.to_str().ok_or("non-UTF-8 report path")?,
            "--storage",
            storage_label(args.storage),
        ]);
        let started = Instant::now();
        let child = command.spawn()?;
        let usage = wait_with_usage(child, args.case_timeout)?;
        let database_bytes = read_database_bytes(&report);
        observations.push(ProcessCaseMeasurementV1 {
            case_index,
            report,
            exit_code: usage.exit_code,
            signal: usage.signal,
            timed_out: usage.timed_out,
            wall_us: elapsed_us(started.elapsed()),
            user_cpu_us: usage.user_cpu_us,
            system_cpu_us: usage.system_cpu_us,
            peak_rss_bytes: usage.peak_rss_bytes,
            database_bytes,
            database_write_bytes: usage.database_write_bytes,
            unavailable_process_fields: usage.unavailable_process_fields,
        });
    }
    let failed = observations
        .iter()
        .any(|case| case.timed_out || case.exit_code != Some(0) || case.signal.is_some());
    let summary = ProcessCampaignReportV1 {
        schema_version: "1".into(),
        seed: args.seed,
        cases: observations,
    };
    let summary_path = args.out.join("process-campaign.v1.json");
    fs_private::write_private(&summary_path, &serde_json::to_vec_pretty(&summary)?)?;
    println!("Process campaign report: {}", summary_path.display());
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

async fn run_worker(args: &Args) -> Result<ExitCode, Box<dyn Error>> {
    let case_index = args.case_index.ok_or("worker requires --case-index")?;
    let case = generate_milestone3_adversarial_case(args.seed, case_index as u64);
    let report = run_generated_case_report_with_storage_mode(&case, None, args.storage).await?;
    if let Some(parent) = args.out.parent() {
        fs_private::create_dir_all_private(parent)?;
    }
    fs_private::write_private(&args.out, &serde_json::to_vec_pretty(&report)?)?;
    let failed = !report.expectation_failures.is_empty() || !report.invariant_failures.is_empty();
    Ok(if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn read_database_bytes(path: &Path) -> Option<u64> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice::<ScenarioReport>(&bytes)
        .ok()?
        .campaign_measurements
        .database_bytes
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Args, Box<dyn Error>> {
    let mut seed = 7;
    let mut cases = 12;
    let mut case_index = None;
    let mut out = PathBuf::from("target/cgka-milestone3-process-campaign");
    let mut storage = HarnessStorageMode::TempFileBackedSqlite;
    let mut case_timeout = Duration::from_secs(300);
    let mut worker = false;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--worker" => worker = true,
            "--seed" => seed = args.next().ok_or("missing --seed value")?.parse()?,
            "--cases" => cases = args.next().ok_or("missing --cases value")?.parse()?,
            "--case-index" => {
                case_index = Some(args.next().ok_or("missing --case-index value")?.parse()?)
            }
            "--out" => out = PathBuf::from(args.next().ok_or("missing --out value")?),
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
    Ok(Args {
        seed,
        cases,
        case_index,
        out,
        storage,
        case_timeout,
        worker,
    })
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

struct ChildUsage {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    user_cpu_us: Option<u64>,
    system_cpu_us: Option<u64>,
    peak_rss_bytes: Option<u64>,
    database_write_bytes: Option<u64>,
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
            return Err(std::io::Error::last_os_error().into());
        }
        if waited == pid {
            break false;
        }
        if Instant::now() >= deadline {
            if let Err(error) = child.kill()
                && error.kind() != std::io::ErrorKind::InvalidInput
            {
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
    let (database_write_bytes, unavailable_process_fields) =
        (None, vec!["database_write_bytes".to_owned()]);
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    let (database_write_bytes, unavailable_process_fields) = (
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
        database_write_bytes,
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
        database_write_bytes: None,
        unavailable_process_fields: vec![
            "user_cpu_us".to_owned(),
            "system_cpu_us".to_owned(),
            "peak_rss_bytes".to_owned(),
            "database_write_bytes".to_owned(),
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
}
