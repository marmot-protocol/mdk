use std::error::Error;
use std::path::{Path, PathBuf};

use crate::{
    CoverageMatrixEntry, GeneratedScenarioCase, ScenarioReport, VectorFixture,
    coverage_matrix_entry, generate_convergence_chaos_family,
    generate_convergence_e2e_delivery_family, generate_send_leave_family,
    run_generated_case_report, run_vector_fixture_report,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportArgs {
    pub input: ReportInput,
    pub out: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportInput {
    GeneratedFamily {
        family: String,
        seed: u64,
        cases: usize,
    },
    VectorFixtures {
        paths: Vec<PathBuf>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportCommand {
    Run(ReportArgs),
    Help,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRunSummary {
    pub out: PathBuf,
    pub coverage_matrix: Vec<CoverageMatrixEntry>,
    pub scenarios: Vec<ScenarioReportSummary>,
}

impl ReportRunSummary {
    pub fn total(&self) -> usize {
        self.scenarios.len()
    }

    pub fn failed(&self) -> usize {
        self.scenarios
            .iter()
            .filter(|scenario| scenario.failure_count > 0)
            .count()
    }

    pub fn passed(&self) -> usize {
        self.total().saturating_sub(self.failed())
    }

    pub fn to_human_text(&self) -> String {
        let mut lines = Vec::new();
        let result = if self.failed() == 0 { "PASS" } else { "FAIL" };
        lines.push(format!(
            "CGKA conformance {result}: {} passed, {} failed, {} total",
            self.passed(),
            self.failed(),
            self.total()
        ));
        for scenario in &self.scenarios {
            let status = if scenario.failure_count == 0 {
                "PASS"
            } else {
                "FAIL"
            };
            let expectation_label = match scenario.expectation_count {
                0 => "no expectations".to_string(),
                1 => "1 expectation".to_string(),
                n => format!("{n} expectations"),
            };
            lines.push(format!(
                "{status} {} ({expectation_label}) -> {}",
                scenario.scenario_name,
                scenario.output.display()
            ));
            for failure in &scenario.failures {
                lines.push(format!("  - {}: {}", failure.kind, failure.message));
            }
        }
        lines.push(format!("Reports: {}", self.out.display()));
        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioReportSummary {
    pub scenario_name: String,
    pub source: String,
    pub output: PathBuf,
    pub expectation_count: usize,
    pub failure_count: usize,
    pub failures: Vec<ReportFailureSummary>,
    pub coverage: CoverageMatrixEntry,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportFailureSummary {
    pub kind: String,
    pub message: String,
}

pub async fn run_report(args: &ReportArgs) -> Result<ReportRunSummary, Box<dyn Error>> {
    std::fs::create_dir_all(&args.out)?;

    let scenarios = match &args.input {
        ReportInput::GeneratedFamily {
            family,
            seed,
            cases,
        } => run_generated_family_reports(family, *seed, *cases, &args.out).await?,
        ReportInput::VectorFixtures { paths } => {
            run_vector_fixture_reports(paths, &args.out).await?
        }
    };

    let coverage_matrix = scenarios
        .iter()
        .map(|scenario| scenario.coverage.clone())
        .collect();

    Ok(ReportRunSummary {
        out: args.out.clone(),
        coverage_matrix,
        scenarios,
    })
}

async fn run_generated_family_reports(
    family: &str,
    seed: u64,
    cases: usize,
    out: &Path,
) -> Result<Vec<ScenarioReportSummary>, Box<dyn Error>> {
    let cases = match family {
        "send-leave/v1" => generate_send_leave_family(seed, cases),
        "convergence-e2e-delivery/v1" => generate_convergence_e2e_delivery_family(seed, cases),
        "convergence-chaos/v1" => generate_convergence_chaos_family(seed, cases),
        other => return Err(format!("unsupported family {other}").into()),
    };

    let mut summaries = Vec::with_capacity(cases.len());
    for case in cases {
        let report = run_generated_case_report(&case, None).await?;
        let output = out.join(format!(
            "{}-seed-{}-case-{}.json",
            case.family_name.replace('/', "-"),
            case.seed,
            case.case_index
        ));
        std::fs::write(&output, serde_json::to_string_pretty(&report)?)?;
        let fixture_output = out.join(format!(
            "{}-seed-{}-case-{}-fixture.v1.json",
            case.family_name.replace('/', "-"),
            case.seed,
            case.case_index
        ));
        let fixture = generated_fixture_candidate(&case, &report);
        std::fs::write(&fixture_output, serde_json::to_string_pretty(&fixture)?)?;
        let source = case.family_name.clone();
        let coverage = coverage_matrix_entry(source.clone(), &report);
        summaries.push(ScenarioReportSummary {
            scenario_name: report.metadata.scenario_name.clone(),
            source,
            output,
            expectation_count: report.expected_trace.iter().count()
                + report.expected_outcomes.len(),
            failure_count: report.expectation_failures.len(),
            failures: report
                .expectation_failures
                .iter()
                .map(|failure| ReportFailureSummary {
                    kind: failure.kind.clone(),
                    message: failure.message.clone(),
                })
                .collect(),
            coverage,
        });
    }

    Ok(summaries)
}

fn generated_fixture_candidate(
    case: &GeneratedScenarioCase,
    report: &ScenarioReport,
) -> VectorFixture {
    let expected_trace = case
        .expected_outcomes
        .is_empty()
        .then(|| report.observed_trace.clone())
        .flatten();
    let mut fixture = case.to_vector_fixture(env!("CARGO_PKG_VERSION"), expected_trace);
    if let Some(minimized) = report
        .metadata
        .generated
        .as_ref()
        .and_then(|generated| generated.minimized_case.as_ref())
    {
        fixture.scenario_name = minimized.name.clone();
        fixture.scenario = minimized.clone();
    }
    fixture
}

async fn run_vector_fixture_reports(
    paths: &[PathBuf],
    out: &Path,
) -> Result<Vec<ScenarioReportSummary>, Box<dyn Error>> {
    let fixture_paths = collect_vector_fixture_paths(paths)?;
    let mut summaries = Vec::with_capacity(fixture_paths.len());
    for path in fixture_paths {
        let fixture: VectorFixture = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let report = run_vector_fixture_report(&fixture).await?;
        let output = out.join(format!(
            "{}-report.json",
            fixture.scenario_name.replace('/', "-")
        ));
        std::fs::write(&output, serde_json::to_string_pretty(&report)?)?;
        let source = path.display().to_string();
        let coverage = coverage_matrix_entry(source.clone(), &report);
        summaries.push(ScenarioReportSummary {
            scenario_name: fixture.scenario_name.clone(),
            source,
            output,
            expectation_count: fixture.expected_trace.iter().count()
                + fixture.expected_outcomes.len(),
            failure_count: report.expectation_failures.len(),
            failures: report
                .expectation_failures
                .iter()
                .map(|failure| ReportFailureSummary {
                    kind: failure.kind.clone(),
                    message: failure.message.clone(),
                })
                .collect(),
            coverage,
        });
    }
    Ok(summaries)
}

fn collect_vector_fixture_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    if paths.is_empty() {
        return Err("no vector fixture paths supplied".into());
    }

    let mut fixture_paths = Vec::new();
    for path in paths {
        if path.is_file() {
            fixture_paths.push(path.clone());
            continue;
        }
        if path.is_dir() {
            let mut entries = std::fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort();
            fixture_paths.extend(
                entries
                    .into_iter()
                    .filter(|path| is_vector_fixture_file(path)),
            );
            continue;
        }
        return Err(format!("vector fixture path does not exist: {}", path.display()).into());
    }
    fixture_paths.sort();
    fixture_paths.dedup();
    if fixture_paths.is_empty() {
        return Err("no vector fixture files found".into());
    }
    Ok(fixture_paths)
}

fn is_vector_fixture_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    file_name.ends_with(".v1.json") && file_name != "manifest.v1.json"
}

pub fn parse_report_command(
    args: impl IntoIterator<Item = String>,
) -> Result<ReportCommand, Box<dyn Error>> {
    let mut family = "send-leave/v1".to_string();
    let mut seed = 0u64;
    let mut cases = 1usize;
    let mut vectors = Vec::new();
    let mut out = PathBuf::from("target/cgka-conformance-simulator-reports");

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => family = next_value(&mut args, "--family")?,
            "--seed" => seed = next_value(&mut args, "--seed")?.parse()?,
            "--cases" => cases = next_value(&mut args, "--cases")?.parse()?,
            "--vectors" => vectors.push(PathBuf::from(next_value(&mut args, "--vectors")?)),
            "--out" => out = PathBuf::from(next_value(&mut args, "--out")?),
            "--help" | "-h" => return Ok(ReportCommand::Help),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let input = if vectors.is_empty() {
        ReportInput::GeneratedFamily {
            family,
            seed,
            cases,
        }
    } else {
        ReportInput::VectorFixtures { paths: vectors }
    };

    Ok(ReportCommand::Run(ReportArgs { input, out }))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}

pub fn report_usage() -> &'static str {
    "Usage: cgka-conformance-simulator-report [--vectors FILE_OR_DIR ... | --family send-leave/v1|convergence-e2e-delivery/v1|convergence-chaos/v1 --seed N --cases N] [--out DIR]"
}
