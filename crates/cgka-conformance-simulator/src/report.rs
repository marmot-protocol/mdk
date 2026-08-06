use std::error::Error;
use std::path::{Path, PathBuf};

use crate::scenario_input::generated_scenario_input_provenance;
use crate::{
    CoverageMatrixEntry, FailureCapsuleSensitivity, FailureCapsuleV1, GeneratedScenarioCase,
    GeneratedScenarioInputV1, HarnessStorageMode, ScenarioInputProvenanceV1, ScenarioReport,
    VectorFixture, coverage_matrix_entry, generate_adversarial_reliability_family,
    generate_convergence_chaos_family, generate_convergence_e2e_delivery_family,
    generate_send_leave_family, generate_stateful_chat_journey_family,
    resolve_scenario_input_bytes, run_vector_fixture_report_with_capture, write_failure_capsule,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportArgs {
    pub input: ReportInput,
    pub out: PathBuf,
    pub strict_oracle: bool,
    pub storage_mode: HarnessStorageMode,
    /// Explicit opt-in because replay checkpoints contain MLS key material.
    pub capture_sensitive_replay: bool,
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
    GeneratedInputs {
        paths: Vec<PathBuf>,
        /// Override the producer-recorded subject while preserving it in the
        /// saved input as provenance.
        adapter: Option<crate::GeneratedSubjectKind>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportCommand {
    Run(ReportArgs),
    ReplayCapsule(PathBuf),
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
            if let Some(capsule) = &scenario.failure_capsule {
                lines.push(format!("  capsule: {}", capsule.display()));
            }
            if let Some(capsule) = &scenario.replay_capsule {
                lines.push(format!("  sensitive replay: {}", capsule.display()));
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
    pub failure_capsule: Option<PathBuf>,
    pub replay_capsule: Option<PathBuf>,
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

fn scenario_report_failures(
    report: &ScenarioReport,
    strict_oracle: bool,
) -> Vec<ReportFailureSummary> {
    let mut failures = report
        .step_log
        .iter()
        .filter_map(|step| match &step.status {
            crate::ScenarioStepStatus::Completed => None,
            crate::ScenarioStepStatus::Failed { kind, message, .. } => Some(ReportFailureSummary {
                kind: format!("scenario_step_failed:{kind}"),
                message: format!("step {} ({}): {message}", step.step_index, step.step_type),
            }),
        })
        .chain(
            report
                .expectation_failures
                .iter()
                .map(|failure| ReportFailureSummary {
                    kind: failure.kind.clone(),
                    message: failure.message.clone(),
                }),
        )
        .collect::<Vec<_>>();

    if !strict_oracle {
        return failures;
    }

    failures.extend(report.oracle.weak_oracle_warnings.iter().map(|warning| {
        ReportFailureSummary {
            kind: "weak_oracle_warning".into(),
            message: format!(
                "{}; expected one of {:?}",
                warning.message, warning.expected_any_of
            ),
        }
    }));

    failures.extend(
        report
            .oracle
            .missing_observed_behaviors
            .iter()
            .map(|behavior| ReportFailureSummary {
                kind: "missing_observed_behavior".into(),
                message: format!("expected oracle behavior {behavior:?} was not observed"),
            }),
    );

    failures
}

pub async fn run_report(args: &ReportArgs) -> Result<ReportRunSummary, Box<dyn Error>> {
    #[cfg(unix)]
    let _output_dir_guard = fs_private::prepare_directory_path(
        &args.out,
        fs_private::PRIVATE_DIR_MODE,
        fs_private::ExistingDirectoryMode::Preserve,
    )?;
    #[cfg(not(unix))]
    fs_private::create_dir_all_private(&args.out)?;

    let scenarios = match &args.input {
        ReportInput::GeneratedFamily {
            family,
            seed,
            cases,
        } => {
            run_generated_family_reports(
                family,
                *seed,
                *cases,
                &args.out,
                args.strict_oracle,
                args.storage_mode,
                args.capture_sensitive_replay,
            )
            .await?
        }
        ReportInput::VectorFixtures { paths } => {
            run_vector_fixture_reports(
                paths,
                &args.out,
                args.strict_oracle,
                args.storage_mode,
                args.capture_sensitive_replay,
            )
            .await?
        }
        ReportInput::GeneratedInputs { paths, adapter } => {
            run_generated_input_reports(
                paths,
                *adapter,
                &args.out,
                args.strict_oracle,
                args.storage_mode,
                args.capture_sensitive_replay,
            )
            .await?
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
    strict_oracle: bool,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<Vec<ScenarioReportSummary>, Box<dyn Error>> {
    let cases = match family {
        "send-leave/v1" => generate_send_leave_family(seed, cases),
        "convergence-e2e-delivery/v1" => generate_convergence_e2e_delivery_family(seed, cases),
        "convergence-chaos/v1" => generate_convergence_chaos_family(seed, cases),
        "adversarial-reliability/v1" => generate_adversarial_reliability_family(seed, cases),
        "chat-journey/v1" => generate_stateful_chat_journey_family(seed, cases),
        other => return Err(format!("unsupported family {other}").into()),
    };

    let mut summaries = Vec::with_capacity(cases.len());
    for case in cases {
        let input_output = out.join(format!(
            "{}-seed-{}-case-{}-generated-input.json",
            case.family_name.replace('/', "-"),
            case.seed,
            case.case_index
        ));
        let source = case.family_name.clone();
        let input = GeneratedScenarioInputV1::new(case.clone());
        let input_bytes = serde_json::to_vec_pretty(&input)?;
        let provenance = generated_scenario_input_provenance(&input_bytes, &case)?;
        fs_private::write_private(&input_output, &input_bytes)?;
        summaries.push(
            run_generated_case_artifacts(
                &case,
                GeneratedCaseArtifactSource {
                    adapter: None,
                    provenance,
                    label: source,
                },
                out,
                strict_oracle,
                storage_mode,
                capture_sensitive_replay,
            )
            .await?,
        );
    }

    Ok(summaries)
}

async fn run_generated_input_reports(
    paths: &[PathBuf],
    adapter: Option<crate::GeneratedSubjectKind>,
    out: &Path,
    strict_oracle: bool,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<Vec<ScenarioReportSummary>, Box<dyn Error>> {
    if paths.is_empty() {
        return Err("no generated input paths supplied".into());
    }
    let mut summaries = Vec::with_capacity(paths.len());
    for path in paths {
        let input_bytes = std::fs::read(path)?;
        let resolved = resolve_scenario_input_bytes(&input_bytes)?;
        let case = resolved
            .generated_case
            .ok_or("--generated-input requires a GeneratedScenarioInputV1 envelope")?;
        summaries.push(
            run_generated_case_artifacts(
                &case,
                GeneratedCaseArtifactSource {
                    adapter,
                    provenance: resolved.provenance,
                    label: path.display().to_string(),
                },
                out,
                strict_oracle,
                storage_mode,
                capture_sensitive_replay,
            )
            .await?,
        );
    }
    Ok(summaries)
}

struct GeneratedCaseArtifactSource {
    adapter: Option<crate::GeneratedSubjectKind>,
    provenance: ScenarioInputProvenanceV1,
    label: String,
}

async fn run_generated_case_artifacts(
    case: &GeneratedScenarioCase,
    source: GeneratedCaseArtifactSource,
    out: &Path,
    strict_oracle: bool,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<ScenarioReportSummary, Box<dyn Error>> {
    let execution_subject = source.adapter.unwrap_or(case.subject);
    let adapter_overridden = execution_subject != case.subject;
    let (mut report, failure_capture) = crate::run_generated_case_report_with_capture_on_subject(
        case,
        execution_subject,
        None,
        storage_mode,
        capture_sensitive_replay,
    )
    .await?;
    report.metadata.input_provenance = Some(source.provenance);
    let artifact_stem = generated_artifact_stem(case, execution_subject);
    let output = out.join(format!("{artifact_stem}.json"));
    fs_private::write_private(&output, &serde_json::to_vec_pretty(&report)?)?;
    if !adapter_overridden {
        let fixture_output = out.join(format!("{artifact_stem}-fixture.v1.json"));
        let fixture = generated_fixture_candidate(case, &report);
        fs_private::write_private(&fixture_output, &serde_json::to_vec_pretty(&fixture)?)?;
    }
    let coverage = coverage_matrix_entry(source.label.clone(), &report);
    let failures = scenario_report_failures(&report, strict_oracle);
    let failure_count = failures.len();
    let failure_capsules = if failures.is_empty() {
        WrittenFailureCapsules::default()
    } else {
        let portable_path = out.join(format!("{artifact_stem}-failure-capsule.v1.json"));
        let replay_path = out.join(format!("{artifact_stem}-sensitive-replay-capsule.v1.json"));
        write_report_failure_capsules(
            &report,
            failure_capture_for(&failures, failure_capture),
            portable_path,
            replay_path,
        )?
    };
    Ok(ScenarioReportSummary {
        scenario_name: report.metadata.scenario_name.clone(),
        source: source.label,
        output,
        failure_capsule: failure_capsules.portable,
        replay_capsule: failure_capsules.replay,
        expectation_count: report.expected_trace.iter().count() + report.expected_outcomes.len(),
        failure_count,
        failures,
        coverage,
    })
}

fn generated_artifact_stem(
    case: &GeneratedScenarioCase,
    execution_subject: crate::GeneratedSubjectKind,
) -> String {
    let base = format!(
        "{}-seed-{}-case-{}",
        case.family_name.replace('/', "-"),
        case.seed,
        case.case_index
    );
    if execution_subject == case.subject {
        base
    } else {
        format!("{base}-{}", execution_subject.artifact_label())
    }
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
    strict_oracle: bool,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<Vec<ScenarioReportSummary>, Box<dyn Error>> {
    let fixture_paths = collect_vector_fixture_paths(paths)?;
    let mut summaries = Vec::with_capacity(fixture_paths.len());
    for path in fixture_paths {
        let fixture: VectorFixture = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        let (report, failure_capture) = run_vector_fixture_report_with_capture(
            &fixture,
            storage_mode,
            capture_sensitive_replay,
        )
        .await?;
        let output = out.join(format!(
            "{}-report.json",
            fixture.scenario_name.replace('/', "-")
        ));
        fs_private::write_private(&output, &serde_json::to_vec_pretty(&report)?)?;
        let source = path.display().to_string();
        let coverage = coverage_matrix_entry(source.clone(), &report);
        let failures = scenario_report_failures(&report, strict_oracle);
        let failure_count = failures.len();
        let failure_capsules = if failures.is_empty() {
            WrittenFailureCapsules::default()
        } else {
            let portable_path = out.join(format!(
                "{}-failure-capsule.v1.json",
                fixture.scenario_name.replace('/', "-")
            ));
            let replay_path = out.join(format!(
                "{}-sensitive-replay-capsule.v1.json",
                fixture.scenario_name.replace('/', "-")
            ));
            write_report_failure_capsules(
                &report,
                failure_capture_for(&failures, failure_capture),
                portable_path,
                replay_path,
            )?
        };
        summaries.push(ScenarioReportSummary {
            scenario_name: fixture.scenario_name.clone(),
            source,
            output,
            failure_capsule: failure_capsules.portable,
            replay_capsule: failure_capsules.replay,
            expectation_count: fixture.expected_trace.iter().count()
                + fixture.expected_outcomes.len(),
            failure_count,
            failures,
            coverage,
        });
    }
    Ok(summaries)
}

fn failure_capture_for(
    failures: &[ReportFailureSummary],
    capture: crate::ScenarioFailureCaptureV1,
) -> crate::ScenarioFailureCaptureV1 {
    if failures
        .iter()
        .all(|failure| failure.kind == "weak_oracle_warning")
    {
        crate::ScenarioFailureCaptureV1::default()
    } else {
        capture
    }
}

#[derive(Default)]
struct WrittenFailureCapsules {
    portable: Option<PathBuf>,
    replay: Option<PathBuf>,
}

fn write_report_failure_capsules(
    report: &ScenarioReport,
    capture: crate::ScenarioFailureCaptureV1,
    portable_path: PathBuf,
    replay_path: PathBuf,
) -> Result<WrittenFailureCapsules, Box<dyn Error>> {
    let portable_capsule = FailureCapsuleV1::from_report_capture(
        report.clone(),
        FailureCapsuleSensitivity::SyntheticShareable,
        capture.transport,
        None,
    )?;
    write_failure_capsule(&portable_path, &portable_capsule)?;

    let replay = if let Some(byte_replay) = capture.byte_replay {
        let replay_capsule = FailureCapsuleV1::from_report(
            report.clone(),
            FailureCapsuleSensitivity::SensitiveLocal,
            Vec::new(),
            Some(byte_replay),
        )?;
        write_failure_capsule(&replay_path, &replay_capsule)?;
        Some(replay_path)
    } else {
        None
    };

    Ok(WrittenFailureCapsules {
        portable: Some(portable_path),
        replay,
    })
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
            collect_vector_fixture_directory(path, &mut fixture_paths)?;
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

fn collect_vector_fixture_directory(
    directory: &Path,
    fixture_paths: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let mut entries = std::fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    for path in entries {
        if path.is_dir() {
            // Byte fixtures have their own schema/runner and deliberately use
            // the same `.v1.json` suffix. Every other vector subdirectory,
            // including `incidents/`, carries ordinary `VectorFixture`s.
            if path.file_name().and_then(|name| name.to_str()) != Some("byte-fixtures") {
                collect_vector_fixture_directory(&path, fixture_paths)?;
            }
        } else if is_vector_fixture_file(&path) {
            fixture_paths.push(path);
        }
    }
    Ok(())
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
    let mut generated_inputs = Vec::new();
    let mut generated_input_adapter = None;
    let mut out = PathBuf::from("target/cgka-conformance-simulator-reports");
    let mut strict_oracle = true;
    let mut storage_mode = None;
    let mut replay_capsule = None;
    let mut capture_sensitive_replay = false;
    let mut scenario_input_selected = false;
    let mut generated_family_selected = false;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => {
                scenario_input_selected = true;
                generated_family_selected = true;
                family = next_value(&mut args, "--family")?;
            }
            "--seed" => {
                scenario_input_selected = true;
                generated_family_selected = true;
                seed = next_value(&mut args, "--seed")?.parse()?;
            }
            "--cases" => {
                scenario_input_selected = true;
                generated_family_selected = true;
                cases = next_value(&mut args, "--cases")?.parse()?;
            }
            "--vectors" => {
                scenario_input_selected = true;
                vectors.push(PathBuf::from(next_value(&mut args, "--vectors")?));
            }
            "--generated-input" => {
                scenario_input_selected = true;
                generated_inputs.push(PathBuf::from(next_value(&mut args, "--generated-input")?));
            }
            "--adapter" => {
                scenario_input_selected = true;
                generated_input_adapter = Some(crate::GeneratedSubjectKind::parse(&next_value(
                    &mut args,
                    "--adapter",
                )?)?);
            }
            "--replay-capsule" => {
                replay_capsule = Some(PathBuf::from(next_value(&mut args, "--replay-capsule")?));
            }
            "--capture-sensitive-replay" => capture_sensitive_replay = true,
            "--out" => out = PathBuf::from(next_value(&mut args, "--out")?),
            "--storage" => {
                storage_mode = Some(HarnessStorageMode::parse(&next_value(
                    &mut args,
                    "--storage",
                )?)?)
            }
            "--strict-oracle" => strict_oracle = true,
            "--allow-weak-oracle" => strict_oracle = false,
            "--help" | "-h" => return Ok(ReportCommand::Help),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    if let Some(path) = replay_capsule {
        if scenario_input_selected || capture_sensitive_replay {
            return Err(
                "--replay-capsule cannot be combined with scenario or capture inputs".into(),
            );
        }
        return Ok(ReportCommand::ReplayCapsule(path));
    }

    if !generated_inputs.is_empty() && (!vectors.is_empty() || generated_family_selected) {
        return Err(
            "--generated-input cannot be combined with --vectors, --family, --seed, or --cases"
                .into(),
        );
    }
    if generated_input_adapter.is_some() && generated_inputs.is_empty() {
        return Err("--adapter requires at least one --generated-input".into());
    }

    let input = if !generated_inputs.is_empty() {
        ReportInput::GeneratedInputs {
            paths: generated_inputs,
            adapter: generated_input_adapter,
        }
    } else if vectors.is_empty() {
        ReportInput::GeneratedFamily {
            family,
            seed,
            cases,
        }
    } else {
        ReportInput::VectorFixtures { paths: vectors }
    };

    Ok(ReportCommand::Run(ReportArgs {
        input,
        out,
        strict_oracle,
        storage_mode: storage_mode.unwrap_or_else(HarnessStorageMode::from_env),
        capture_sensitive_replay,
    }))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}

pub fn report_usage() -> &'static str {
    "Usage: cgka-conformance-simulator-report [--replay-capsule FILE | --generated-input FILE ... [--adapter engine|retained-relay|app-runtime] | --vectors FILE_OR_DIR ... | --family send-leave/v1|convergence-e2e-delivery/v1|convergence-chaos/v1|adversarial-reliability/v1|chat-journey/v1 --seed N --cases N] [--out DIR] [--storage memory|file] [--strict-oracle|--allow-weak-oracle] [--capture-sensitive-replay]"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BehaviorEvidenceSummary, OracleBehavior, OracleCoverageWarning, ScenarioOracleReport,
        ScenarioReportMetadata, ScenarioSpec, ScenarioStimulus,
    };

    fn report_with_oracle(oracle: ScenarioOracleReport) -> ScenarioReport {
        ScenarioReport {
            metadata: ScenarioReportMetadata {
                scenario_name: "oracle-summary-test".into(),
                spec_version: "2".into(),
                step_count: 0,
                storage_backend: "in-memory-sqlite".into(),
                subject: None,
                generated: None,
                fixture: None,
                input_provenance: None,
            },
            scenario: ScenarioSpec {
                name: "oracle-summary-test".into(),
                spec_version: "2".into(),
                clients: Vec::new(),
                topology: Default::default(),
                steps: Vec::new(),
            },
            resolved_topology: Default::default(),
            expanded_schedule: Vec::new(),
            assertion_observations: Vec::new(),
            relay_sync_observations: Vec::new(),
            expected_trace: None,
            expected_outcomes: Vec::new(),
            observed_trace: None,
            oracle,
            step_log: Vec::new(),
            pending_resolution_observations: Vec::new(),
            quiescence_observations: Vec::new(),
            epoch_change_observations: Vec::new(),
            app_invalidation_observations: Vec::new(),
            expectation_failures: Vec::new(),
            invariant_failures: Vec::new(),
            campaign_measurements: Default::default(),
        }
    }

    #[test]
    fn scenario_report_failures_include_oracle_coverage_failures() {
        let report = report_with_oracle(ScenarioOracleReport {
            stimuli: vec![ScenarioStimulus::CommitStorm],
            oracle_behaviors: vec![OracleBehavior::ClientConvergence],
            observed_behaviors: Vec::new(),
            missing_observed_behaviors: vec![OracleBehavior::ClientConvergence],
            evidence: BehaviorEvidenceSummary::default(),
            weak_oracle_warnings: vec![OracleCoverageWarning {
                stimulus: ScenarioStimulus::CommitStorm,
                expected_any_of: vec![OracleBehavior::ClientConvergence],
                message:
                    "scenario includes CommitStorm but no expectation checks the matching behavior"
                        .into(),
            }],
        });

        let failures = scenario_report_failures(&report, true);

        assert_eq!(
            failures.len(),
            2,
            "oracle coverage failures should fail summaries"
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.kind == "weak_oracle_warning")
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.kind == "missing_observed_behavior")
        );
    }

    #[test]
    fn scenario_report_failures_include_subject_step_failures() {
        let mut report = report_with_oracle(ScenarioOracleReport {
            stimuli: Vec::new(),
            oracle_behaviors: Vec::new(),
            observed_behaviors: Vec::new(),
            missing_observed_behaviors: Vec::new(),
            evidence: BehaviorEvidenceSummary::default(),
            weak_oracle_warnings: Vec::new(),
        });
        report.step_log.push(crate::ScenarioStepLogEntry {
            step_index: 4,
            step_type: "tick".into(),
            status: crate::ScenarioStepStatus::Failed {
                kind: "backend".into(),
                category: crate::SubjectFailureCategory::Resource,
                message: "convergence replay budget exceeded".into(),
            },
            wall_us: 0,
        });

        let failures = scenario_report_failures(&report, false);
        let measurements =
            crate::CampaignMeasurementsV1::from_report(&report, 10, None, 0, None, None);

        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].kind, "scenario_step_failed:backend");
        assert!(failures[0].message.contains("replay budget exceeded"));
        assert_eq!(measurements.first_failing_action, Some(4));
        assert_eq!(measurements.convergence_latency_us, None);
        assert!(
            measurements
                .unavailable_process_fields
                .iter()
                .any(|field| field == "convergence_latency_us")
        );
        assert!(
            measurements
                .limiting_resource
                .as_deref()
                .is_some_and(|resource| resource.contains("replay budget exceeded"))
        );
    }
}
