//! Deterministic generated scenario families.
//!
//! Families produce ordinary [`ScenarioSpec`] values plus the metadata needed
//! to replay or promote a generated case into a fixed vector.

use crate::scenario::subject_setup_error;
use crate::{
    AppRuntimeHarness, GeneratedScenarioMetadata, HarnessStorageMode, RetainedRelaySubject,
    ScenarioFailureCaptureV1, ScenarioMessageSelectorV2, ScenarioOutboundSelection, ScenarioReport,
    ScenarioRunError, ScenarioSpec, ScenarioStep, ScenarioTrace, ScenarioTransportClass,
    SubjectFailureCategory, SubjectOutboundOutcome, TraceExpectation, VectorFixture,
    fingerprint_report_failure, run_scenario_report_with_outcomes_and_capture,
    run_scenario_report_with_outcomes_and_storage_mode, run_scenario_report_with_subject,
    stable_action_id,
};
use cgka_traits::group::ProtocolProfile;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const GENERATED_SCENARIO_INPUT_SCHEMA_VERSION: &str = "1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioCase {
    pub family_name: String,
    pub generator_version: String,
    pub seed: u64,
    pub case_index: u64,
    #[serde(default, skip_serializing_if = "GeneratedSubjectKind::is_engine")]
    pub subject: GeneratedSubjectKind,
    pub scenario: ScenarioSpec,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_outcomes: Vec<TraceExpectation>,
}

/// Versioned executable input for replaying one generated case with the same
/// subject adapter and expectations used by the original campaign run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedScenarioInputV1 {
    pub schema_version: String,
    pub case: GeneratedScenarioCase,
}

impl GeneratedScenarioInputV1 {
    pub fn new(case: GeneratedScenarioCase) -> Self {
        Self {
            schema_version: GENERATED_SCENARIO_INPUT_SCHEMA_VERSION.into(),
            case,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != GENERATED_SCENARIO_INPUT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported generated scenario input version {}",
                self.schema_version
            ));
        }
        Ok(())
    }
}

/// Adapter selected by a generated campaign case.
///
/// Keeping this in generated metadata prevents retained-history workloads from
/// silently running against the fast packet bus, where reconnect would merely
/// heal transient delivery rather than query durable relay history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedSubjectKind {
    #[default]
    Engine,
    RetainedRelay,
    AppRuntime,
}

impl GeneratedSubjectKind {
    fn is_engine(&self) -> bool {
        *self == Self::Engine
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "engine" => Ok(Self::Engine),
            "retained-relay" => Ok(Self::RetainedRelay),
            "app-runtime" => Ok(Self::AppRuntime),
            other => Err(format!("unsupported generated-case adapter {other}")),
        }
    }

    pub(crate) fn artifact_label(self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::RetainedRelay => "retained-relay",
            Self::AppRuntime => "app-runtime",
        }
    }
}

impl GeneratedScenarioCase {
    pub fn to_vector_fixture(
        &self,
        conformance_version: impl Into<String>,
        expected_trace: Option<ScenarioTrace>,
    ) -> VectorFixture {
        VectorFixture {
            scenario_name: self.scenario.name.clone(),
            vector_version: "1".into(),
            conformance_version: conformance_version.into(),
            seed: Some(self.seed),
            application_profile: None,
            scenario: self.scenario.clone(),
            expected_trace,
            expected_outcomes: self.expected_outcomes.clone(),
        }
    }
}

pub fn generate_send_leave_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ ((case_index as u64) << 32));
        let (mut scenario, mut expected_outcomes) = send_leave_case(&mut rng, case_index as u64);
        add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
        out.push(GeneratedScenarioCase {
            family_name: "send-leave/v1".into(),
            generator_version: "2".into(),
            seed,
            case_index: case_index as u64,
            subject: GeneratedSubjectKind::Engine,
            scenario,
            expected_outcomes,
        });
    }
    out
}

pub fn generate_convergence_e2e_delivery_family(
    seed: u64,
    cases: usize,
) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0A7_C0A7 ^ ((case_index as u64) << 32));
        out.push(GeneratedScenarioCase {
            family_name: "convergence-e2e-delivery/v1".into(),
            generator_version: "1".into(),
            seed,
            case_index: case_index as u64,
            subject: GeneratedSubjectKind::Engine,
            scenario: convergence_e2e_delivery_case(&mut rng, case_index as u64),
            expected_outcomes: vec![],
        });
    }
    out
}

pub fn generate_convergence_chaos_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0A7_1CE5 ^ ((case_index as u64) << 32));
        let (mut scenario, mut expected_outcomes) =
            convergence_chaos_case(&mut rng, case_index as u64);
        add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
        out.push(GeneratedScenarioCase {
            family_name: "convergence-chaos/v1".into(),
            generator_version: "6".into(),
            seed,
            case_index: case_index as u64,
            subject: GeneratedSubjectKind::Engine,
            scenario,
            expected_outcomes,
        });
    }
    out
}

/// Generate the admin-churn catalog ported from the external multi-VM harness
/// scenario catalog (cheeky, committy, crashy essences). Case indices rotate
/// through four arms: seeded sequential admin churn, competing same-epoch
/// admin-policy commits, restart during a commit burst, and a latecomer added
/// under commit pressure with a forward-secrecy check.
pub fn generate_admin_churn_family(seed: u64, cases: usize) -> Vec<GeneratedScenarioCase> {
    let mut out = Vec::with_capacity(cases);
    for case_index in 0..cases {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xAD41_C4B2 ^ ((case_index as u64) << 32));
        let (mut scenario, mut expected_outcomes) = admin_churn_case(&mut rng, case_index as u64);
        if case_index % 4 == 3 {
            // The latecomer arm scopes the pending-work oracle away from the
            // joiner: a welcome-joined member currently retains its own join
            // commit as a permanently deferred transport input, so the strict
            // whole-roster oracle would flag every latecomer scenario.
            add_scoped_reliability_oracle(
                &mut scenario,
                &mut expected_outcomes,
                labels(["alice", "bob", "carol"]),
            );
        } else {
            add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
        }
        out.push(GeneratedScenarioCase {
            family_name: "admin-churn/v1".into(),
            generator_version: "1".into(),
            seed,
            case_index: case_index as u64,
            subject: GeneratedSubjectKind::Engine,
            scenario,
            expected_outcomes,
        });
    }
    out
}

/// Generate the adversarial reliability catalog. Case indices rotate through
/// every required workload family; requesting more than twelve cases repeats
/// the catalog with a new deterministic case id and schedule seed.
pub fn generate_adversarial_reliability_family(
    seed: u64,
    cases: usize,
) -> Vec<GeneratedScenarioCase> {
    (0..cases)
        .map(|case_index| generate_adversarial_reliability_case(seed, case_index as u64))
        .collect()
}

/// Generate one catalog case without regenerating and discarding every prior
/// index. This is the process-runner entry point for deterministic isolation.
pub fn generate_adversarial_reliability_case(seed: u64, case_index: u64) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4d33_4144_5645_5253 ^ case_index.rotate_left(17));
    let (family_name, subject, mut scenario, mut expected_outcomes) =
        adversarial_reliability_case(&mut rng, case_index);
    add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
    GeneratedScenarioCase {
        family_name,
        generator_version: "2".into(),
        seed,
        case_index,
        subject,
        scenario,
        expected_outcomes,
    }
}

/// One-round form of the sustained mixed-traffic workload for normal
/// regression suites. The adversarial family retains the multi-round campaign.
pub fn generate_adversarial_reliability_sustained_regression(seed: u64) -> GeneratedScenarioCase {
    let case_index = 1_u64;
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4d33_4144_5645_5253 ^ case_index.rotate_left(17));
    let (family_name, subject, mut scenario, mut expected_outcomes) =
        adversarial_reliability_sustained_mixed_traffic_with_rounds(&mut rng, case_index, 1);
    scenario.name = "adversarial-reliability/sustained-mixed-traffic/regression".into();
    add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
    GeneratedScenarioCase {
        family_name,
        generator_version: "2-regression".into(),
        seed,
        case_index,
        subject,
        scenario,
        expected_outcomes,
    }
}

/// One-round offline catch-up form for normal regression suites. The catalog
/// case retains the multi-round retained-history flood.
pub fn generate_adversarial_reliability_offline_regression(seed: u64) -> GeneratedScenarioCase {
    adversarial_reliability_regression_case(seed, 0, |_, case_index| {
        adversarial_reliability_offline_retained_flood_with_rounds(case_index, 1)
    })
}

/// Two-update adversary for normal regression suites. The catalog case retains
/// the sustained self-update stream before the privileged removal race.
pub fn generate_adversarial_reliability_self_update_regression(seed: u64) -> GeneratedScenarioCase {
    adversarial_reliability_regression_case(seed, 2, |_, case_index| {
        adversarial_reliability_self_update_adversary_with_rounds(case_index, 2)
    })
}

/// Build a reduced catalog case while preserving its deterministic identity
/// and strict reliability oracle.
fn adversarial_reliability_regression_case(
    seed: u64,
    case_index: u64,
    build: impl FnOnce(
        &mut StdRng,
        u64,
    ) -> (
        String,
        GeneratedSubjectKind,
        ScenarioSpec,
        Vec<TraceExpectation>,
    ),
) -> GeneratedScenarioCase {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x4d33_4144_5645_5253 ^ case_index.rotate_left(17));
    let (family_name, subject, mut scenario, mut expected_outcomes) = build(&mut rng, case_index);
    scenario.name = format!("{family_name}/regression");
    add_strict_reliability_oracle(&mut scenario, &mut expected_outcomes);
    GeneratedScenarioCase {
        family_name,
        generator_version: "2-regression".into(),
        seed,
        case_index,
        subject,
        scenario,
        expected_outcomes,
    }
}

pub async fn run_generated_case_report(
    case: &GeneratedScenarioCase,
    expected_trace: Option<ScenarioTrace>,
) -> Result<ScenarioReport, ScenarioRunError> {
    run_generated_case_report_with_storage_mode(
        case,
        expected_trace,
        HarnessStorageMode::from_env(),
    )
    .await
}

pub async fn run_generated_case_report_with_storage_mode(
    case: &GeneratedScenarioCase,
    expected_trace: Option<ScenarioTrace>,
    storage_mode: HarnessStorageMode,
) -> Result<ScenarioReport, ScenarioRunError> {
    let mut report = run_generated_scenario(
        case.subject,
        &case.scenario,
        expected_trace.clone(),
        case.expected_outcomes.clone(),
        storage_mode,
    )
    .await?;
    add_generated_metadata(
        case,
        case.subject,
        expected_trace.as_ref(),
        &mut report,
        storage_mode,
    )
    .await;
    Ok(report)
}

/// Generated-case runner that retains exact wire artifacts for a failure
/// capsule while keeping the ordinary report API unchanged.
pub async fn run_generated_case_report_with_capture(
    case: &GeneratedScenarioCase,
    expected_trace: Option<ScenarioTrace>,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<(ScenarioReport, crate::ScenarioFailureCaptureV1), ScenarioRunError> {
    run_generated_case_report_with_capture_on_subject(
        case,
        case.subject,
        expected_trace,
        storage_mode,
        capture_sensitive_replay,
    )
    .await
}

pub async fn run_generated_case_report_with_capture_on_subject(
    case: &GeneratedScenarioCase,
    execution_subject: GeneratedSubjectKind,
    expected_trace: Option<ScenarioTrace>,
    storage_mode: HarnessStorageMode,
    capture_sensitive_replay: bool,
) -> Result<(ScenarioReport, crate::ScenarioFailureCaptureV1), ScenarioRunError> {
    let (mut report, failure_capture) = match execution_subject {
        GeneratedSubjectKind::Engine => {
            run_scenario_report_with_outcomes_and_capture(
                &case.scenario,
                expected_trace.clone(),
                case.expected_outcomes.clone(),
                storage_mode,
                capture_sensitive_replay,
            )
            .await?
        }
        GeneratedSubjectKind::RetainedRelay => {
            if capture_sensitive_replay {
                return Err(ScenarioRunError {
                    step_index: None,
                    kind: "sensitive_replay_capture_unsupported".into(),
                    category: SubjectFailureCategory::Environment,
                    message: "retained-relay generated cases cannot capture an engine checkpoint"
                        .into(),
                });
            }
            let mut subject = RetainedRelaySubject::new(
                &case.scenario.clients,
                &case.scenario.topology,
                ProtocolProfile::Legacy,
                storage_mode,
            )
            .map_err(subject_setup_error)?;
            let report = run_scenario_report_with_subject(
                &case.scenario,
                expected_trace.clone(),
                case.expected_outcomes.clone(),
                &mut subject,
            )
            .await?;
            (
                report,
                ScenarioFailureCaptureV1 {
                    transport: subject.captured_transport_window(),
                    byte_replay: None,
                },
            )
        }
        GeneratedSubjectKind::AppRuntime => {
            if capture_sensitive_replay {
                return Err(ScenarioRunError {
                    step_index: None,
                    kind: "sensitive_replay_capture_unsupported".into(),
                    category: SubjectFailureCategory::Environment,
                    message: "app-runtime generated cases cannot capture an engine checkpoint"
                        .into(),
                });
            }
            let mut subject = AppRuntimeHarness::new(&case.scenario.clients)
                .await
                .map_err(subject_setup_error)?;
            let result = run_scenario_report_with_subject(
                &case.scenario,
                expected_trace.clone(),
                case.expected_outcomes.clone(),
                &mut subject,
            )
            .await;
            subject.shutdown().await;
            (
                result?,
                ScenarioFailureCaptureV1 {
                    transport: Default::default(),
                    byte_replay: None,
                },
            )
        }
    };
    add_generated_metadata(
        case,
        execution_subject,
        expected_trace.as_ref(),
        &mut report,
        storage_mode,
    )
    .await;
    Ok((report, failure_capture))
}

async fn add_generated_metadata(
    case: &GeneratedScenarioCase,
    execution_subject: GeneratedSubjectKind,
    expected_trace: Option<&ScenarioTrace>,
    report: &mut ScenarioReport,
    storage_mode: HarnessStorageMode,
) {
    let minimized_case = if fingerprint_report_failure(report).is_ok() {
        minimize_failing_case(
            case,
            execution_subject,
            expected_trace,
            report,
            storage_mode,
        )
        .await
    } else {
        None
    };
    report.metadata.generated = Some(GeneratedScenarioMetadata {
        family_name: case.family_name.clone(),
        generator_version: case.generator_version.clone(),
        seed: case.seed,
        case_index: case.case_index,
        minimized_case,
    });
}

async fn minimize_failing_case(
    case: &GeneratedScenarioCase,
    execution_subject: GeneratedSubjectKind,
    expected_trace: Option<&ScenarioTrace>,
    failing_report: &ScenarioReport,
    storage_mode: HarnessStorageMode,
) -> Option<ScenarioSpec> {
    let target_identity = fingerprint_report_failure(failing_report)
        .ok()?
        .semantic_identity();
    minimize_scenario_with(case.scenario.clone(), |trial| {
        let expected_trace = expected_trace.cloned();
        let expected_outcomes = case.expected_outcomes.clone();
        let target_identity = target_identity.clone();
        async move {
            reproduces_failure(
                &trial,
                expected_trace,
                expected_outcomes,
                &target_identity,
                storage_mode,
                execution_subject,
            )
            .await
        }
    })
    .await
}

async fn minimize_scenario_with<F, Fut>(
    mut candidate: ScenarioSpec,
    mut reproduces: F,
) -> Option<ScenarioSpec>
where
    F: FnMut(ScenarioSpec) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut changed = false;
    loop {
        let mut reduced = false;
        for unit in semantic_minimization_units(&candidate.steps) {
            let mut trial = candidate.clone();
            remove_step_indices(&mut trial.steps, &unit);
            if reproduces(trial.clone()).await {
                candidate = trial;
                changed = true;
                reduced = true;
                break;
            }
        }
        if !reduced {
            break;
        }
    }
    changed.then_some(candidate)
}

/// Dependency-aware reduction units. Removing a fault arm without its release
/// (or a lifecycle stop without its restart) changes the scenario's meaning and
/// commonly produces a different terminal failure. These units are attempted
/// before individual noise steps.
pub fn semantic_reduction_units(steps: &[ScenarioStep]) -> Vec<Vec<usize>> {
    let mut open = std::collections::BTreeMap::<SemanticPairKey, Vec<usize>>::new();
    let mut units = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let Some((key, opens)) = semantic_pair_marker(step, &[]) else {
            continue;
        };
        if opens {
            open.entry(key).or_default().push(index);
        } else if let Some(mut starts) = open.remove(&key) {
            if let Some(start) = starts.pop() {
                units.push(vec![start, index]);
            }
            if !starts.is_empty() {
                open.insert(key, starts);
            }
        }
    }
    units
}

fn semantic_minimization_units(steps: &[ScenarioStep]) -> Vec<Vec<usize>> {
    let mut units = semantic_reduction_units(steps);
    let paired_indices = units.iter().flatten().copied().collect::<BTreeSet<_>>();
    units.extend(steps.iter().enumerate().filter_map(|(index, step)| {
        (!paired_indices.contains(&index) && is_minimizer_removable(step)).then_some(vec![index])
    }));
    units
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SemanticPairKey {
    group_path: Vec<String>,
    resource: SemanticPairResource,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SemanticPairResource {
    Withheld(String),
    Partition,
    Offline(String),
    Process(String),
    Storage(String),
}

fn semantic_pair_marker(
    step: &ScenarioStep,
    group_path: &[String],
) -> Option<(SemanticPairKey, bool)> {
    if let ScenarioStep::InGroup {
        group: nested_group,
        action,
    } = step
    {
        let mut nested_path = group_path.to_vec();
        nested_path.push(nested_group.clone());
        return semantic_pair_marker(action, &nested_path);
    }
    let (resource, opens) = match step {
        ScenarioStep::WithholdMessage { label, .. } => {
            (SemanticPairResource::Withheld(label.clone()), true)
        }
        ScenarioStep::ReleaseWithheld { label } => {
            (SemanticPairResource::Withheld(label.clone()), false)
        }
        ScenarioStep::SetPartition { .. } => (SemanticPairResource::Partition, true),
        ScenarioStep::ClearPartition => (SemanticPairResource::Partition, false),
        ScenarioStep::SetClientOffline { client } => {
            (SemanticPairResource::Offline(client.clone()), true)
        }
        ScenarioStep::ReconnectClient { client } => {
            (SemanticPairResource::Offline(client.clone()), false)
        }
        ScenarioStep::CrashProcess { process } => {
            (SemanticPairResource::Process(process.clone()), true)
        }
        ScenarioStep::RestartProcess { process } => {
            (SemanticPairResource::Process(process.clone()), false)
        }
        ScenarioStep::InjectStorageFault { fault } => {
            (SemanticPairResource::Storage(fault.target.clone()), true)
        }
        ScenarioStep::ClearStorageFault { target } => {
            (SemanticPairResource::Storage(target.clone()), false)
        }
        _ => return None,
    };
    Some((
        SemanticPairKey {
            group_path: group_path.to_vec(),
            resource,
        },
        opens,
    ))
}

fn remove_step_indices(steps: &mut Vec<ScenarioStep>, indices: &[usize]) {
    for index in indices.iter().rev() {
        steps.remove(*index);
    }
}

async fn reproduces_failure(
    scenario: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    target_identity: &crate::FailureIdentityV1,
    storage_mode: HarnessStorageMode,
    subject: GeneratedSubjectKind,
) -> bool {
    match run_generated_scenario(
        subject,
        scenario,
        expected_trace,
        expected_outcomes,
        storage_mode,
    )
    .await
    {
        Ok(report) => fingerprint_report_failure(&report)
            .is_ok_and(|fingerprint| fingerprint.semantic_identity() == *target_identity),
        Err(_) => false,
    }
}

async fn run_generated_scenario(
    subject: GeneratedSubjectKind,
    scenario: &ScenarioSpec,
    expected_trace: Option<ScenarioTrace>,
    expected_outcomes: Vec<TraceExpectation>,
    storage_mode: HarnessStorageMode,
) -> Result<ScenarioReport, ScenarioRunError> {
    match subject {
        GeneratedSubjectKind::Engine => {
            run_scenario_report_with_outcomes_and_storage_mode(
                scenario,
                expected_trace,
                expected_outcomes,
                storage_mode,
            )
            .await
        }
        GeneratedSubjectKind::RetainedRelay => {
            let mut retained = RetainedRelaySubject::new(
                &scenario.clients,
                &scenario.topology,
                ProtocolProfile::Legacy,
                storage_mode,
            )
            .map_err(subject_setup_error)?;
            run_scenario_report_with_subject(
                scenario,
                expected_trace,
                expected_outcomes,
                &mut retained,
            )
            .await
        }
        GeneratedSubjectKind::AppRuntime => {
            let mut app = AppRuntimeHarness::new(&scenario.clients)
                .await
                .map_err(subject_setup_error)?;
            let result = run_scenario_report_with_subject(
                scenario,
                expected_trace,
                expected_outcomes,
                &mut app,
            )
            .await;
            app.shutdown().await;
            result
        }
    }
}

fn is_minimizer_removable(step: &ScenarioStep) -> bool {
    matches!(
        step,
        ScenarioStep::SendAppMessage { .. }
            | ScenarioStep::ClearEvents { .. }
            | ScenarioStep::OmitMessage { .. }
            | ScenarioStep::DuplicateMessage { .. }
            | ScenarioStep::WithholdMessage { .. }
            | ScenarioStep::ReleaseWithheld { .. }
            | ScenarioStep::ReorderMessages { .. }
            | ScenarioStep::SetPartition { .. }
            | ScenarioStep::ClearPartition
    )
}

fn convergence_chaos_case(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    match case_index % 11 {
        0 => convergence_chaos_invite_fork(case_index),
        1 => convergence_chaos_group_data_fork(case_index),
        2 => convergence_chaos_rollback_queue_faults(rng, case_index),
        3 => convergence_chaos_partition_leave(case_index),
        4 => convergence_chaos_delayed_past_epoch_app(case_index),
        5 => convergence_chaos_stable_queue_faults(case_index),
        6 => convergence_chaos_large_message_storm(rng, case_index),
        7 => convergence_chaos_large_partitioned_storm(rng, case_index),
        8 => convergence_chaos_large_commit_storm(rng, case_index),
        9 => convergence_chaos_large_mixed_message_commit_storm(rng, case_index),
        _ => convergence_chaos_restart_delivery_faults(case_index),
    }
}

fn convergence_chaos_invite_fork(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob", "david", "eve"]),
        steps: vec![
            create_group(
                "alice",
                format!("invite-fork-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob", "david", "eve"]),
            ScenarioStep::SetPartition {
                allow: labels(["alice", "bob"]),
            },
            invite("alice", ["david"], "alice-invite"),
            invite("bob", ["eve"], "bob-invite"),
            confirmed_step("alice", "alice-invite"),
            confirmed_step("bob", "bob-invite"),
            ScenarioStep::DeliverAll,
            tick(["alice", "bob"]),
            observe(["alice", "bob"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(8, "alice", "alice-invite"),
        confirmed(9, "bob", "bob-invite"),
        clients_converged(["alice", "bob"], Some(2), Some(3)),
        client_state("alice", 2, 3, vec![]),
        client_state("bob", 2, 3, vec![]),
        recovery_summary(1, Some(1), Some(2)),
    ];
    (scenario, expected)
}

fn convergence_chaos_group_data_fork(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob"]),
        steps: vec![
            create_group(
                "alice",
                format!("group-data-fork-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob"]),
            ScenarioStep::UpdateGroupData {
                client: "alice".into(),
                name: format!("alice branch {case_index}"),
                pending: "alice-update".into(),
            },
            ScenarioStep::UpdateGroupData {
                client: "bob".into(),
                name: format!("bob branch {case_index}"),
                pending: "bob-update".into(),
            },
            confirmed_step("alice", "alice-update"),
            confirmed_step("bob", "bob-update"),
            ScenarioStep::DeliverAll,
            tick(["alice", "bob"]),
            observe(["alice", "bob"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(7, "alice", "alice-update"),
        confirmed(8, "bob", "bob-update"),
        clients_converged(["alice", "bob"], Some(2), Some(2)),
        recovery_summary(1, Some(1), Some(2)),
    ];
    (scenario, expected)
}

fn convergence_chaos_rollback_queue_faults(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    // A definite publish failure retracts alice's undelivered group-data commit
    // before rolling back local pending state. Bob then sends several app
    // messages. Drive their delivery schedule from the seed so distinct seeds
    // exercise distinct adversarial orderings, not just a different payload
    // string.
    // FIFO delivery makes the observed payload order the permuted queue order,
    // so recompute the expectation from the same permutation.
    let payloads = (0..6)
        .map(|index| format!("bob-after-rollback-{case_index}-{index}"))
        .collect::<Vec<_>>();
    let app_order = shuffled_order(rng, payloads.len());
    let expected_payloads = app_order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();
    let order = app_order.clone();

    let mut steps = vec![
        create_group(
            "alice",
            format!("rollback-faults-{case_index}"),
            ["bob"],
            "create",
        ),
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob"]),
        clear(["alice", "bob"]),
        ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("rolled back {case_index}"),
            pending: "update".into(),
        },
        acknowledged_step("alice", "update", SubjectOutboundOutcome::ReachedNoEndpoint),
    ];
    let mut app_selectors = Vec::with_capacity(payloads.len());
    for payload in &payloads {
        let step = ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: payload.clone(),
        };
        app_selectors.push(action_selector(
            steps.len(),
            &step,
            ScenarioTransportClass::Application,
        ));
        steps.push(step);
    }
    // Seed-driven delivery schedule for the post-rollback messages.
    let reordered = reorder_selectors(&app_selectors, &order);
    let duplicated = reordered[0].clone();
    steps.push(ScenarioStep::ReorderMessages { order: reordered });
    // The original reaches alice in the first delivery pass; the delayed copy
    // is released and ticked separately, so this shape exercises duplicate
    // app-message handling after a definite publish rollback.
    steps.push(ScenarioStep::DuplicateMessage {
        selector: duplicated.clone(),
    });
    steps.push(ScenarioStep::WithholdMessage {
        selector: with_occurrence(duplicated, 1),
        label: "duplicate-app".into(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick(["alice"]));
    steps.push(ScenarioStep::ReleaseWithheld {
        label: "duplicate-app".into(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick(["alice"]));
    steps.push(observe(["alice", "bob"]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob"]),
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        rolled_back(6, "alice", "update"),
        clients_converged(["alice", "bob"], Some(1), Some(2)),
        client_state("alice", 1, 2, expected_payloads),
        client_state("bob", 1, 2, vec![]),
    ];
    (scenario, expected)
}

fn convergence_chaos_stable_queue_faults(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let bob_payload = format!("bob-first-{case_index}");
    let carol_payload = format!("carol-second-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob", "carol"]),
        steps: vec![
            create_group(
                "alice",
                format!("stable-queue-faults-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: bob_payload.clone(),
            },
            ScenarioStep::SendAppMessage {
                sender: "carol".into(),
                payload: carol_payload.clone(),
            },
            ScenarioStep::DuplicateMessage {
                selector: application_selector("bob"),
            },
            ScenarioStep::WithholdMessage {
                selector: with_occurrence(application_selector("bob"), 1),
                label: "delayed-copy".into(),
            },
            ScenarioStep::ReorderMessages {
                order: vec![application_selector("carol"), application_selector("bob")],
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::ReleaseWithheld {
                label: "delayed-copy".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 3, vec![carol_payload, bob_payload]),
    ];
    (scenario, expected)
}

fn convergence_chaos_partition_leave(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let visible_payload = format!("bob-visible-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob"]),
        steps: vec![
            create_group(
                "alice",
                format!("partition-leave-{case_index}"),
                ["bob"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            clear(["alice", "bob"]),
            ScenarioStep::SetPartition {
                allow: labels(["bob"]),
            },
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: format!("bob-hidden-{case_index}"),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::ClearPartition,
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: visible_payload.clone(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            ScenarioStep::Leave {
                client: "bob".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            accept_all_outbound("alice"),
            ScenarioStep::DeliverAll,
            tick(["bob"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 2,
            member_count: 1,
            received_payloads: Some(vec![visible_payload]),
            added_members: None,
            removed_members: Some(vec!["bob".into()]),
        },
    ];
    (scenario, expected)
}

fn convergence_chaos_delayed_past_epoch_app(
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let payload = format!("epoch-one-delayed-{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob", "carol", "david"]),
        steps: vec![
            create_group(
                "alice",
                format!("delayed-past-epoch-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol", "david"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: payload.clone(),
            },
            ScenarioStep::WithholdMessage {
                selector: application_selector("bob"),
                label: "old-app".into(),
            },
            invite("alice", ["david"], "invite-david"),
            confirmed_step("alice", "invite-david"),
            ScenarioStep::DeliverAll,
            tick(["carol", "david"]),
            ScenarioStep::ReleaseWithheld {
                label: "old-app".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["carol", "david"]),
            ScenarioStep::AdvanceTime {
                delta_ms: 30 * 24 * 60 * 60 * 1_000 + 1,
            },
            tick(["david"]),
            observe(["carol", "david"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        confirmed(8, "alice", "invite-david"),
        client_state("carol", 2, 4, vec![payload]),
        // David joined after the application input was authored and therefore
        // does not claim historical delivery. Naming his state explicitly
        // also makes him part of the strict exact/pending-work boundary. His
        // opaque pre-join row is locally resource-released after the explicit
        // virtual-time residence deadline without claiming stale delivery.
        client_state("david", 2, 4, vec![]),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_message_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let payloads = senders
        .iter()
        .map(|sender| format!("{sender}:large-storm:{case_index}"))
        .collect::<Vec<_>>();
    // Drive the delivery schedule from the seed so distinct seeds exercise
    // distinct reorderings. FIFO delivery makes the observed payload order the
    // permuted queue order, so recompute the expectation from the same order.
    let order = shuffled_order(rng, senders.len());
    let expected_payloads = order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();

    let mut steps = large_group_setup(
        format!("large-message-storm-{case_index}"),
        clients.clone(),
        invitees.clone(),
    );
    for (sender, payload) in senders.iter().zip(payloads.iter()) {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
    }
    steps.push(ScenarioStep::ReorderMessages {
        order: order
            .iter()
            .map(|index| application_selector(&senders[*index]))
            .collect(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(vec!["alice".into()]));
    steps.push(observe_vec(vec!["alice".into()]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 21, expected_payloads),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_partitioned_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(25);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let payloads = senders
        .iter()
        .map(|sender| format!("{sender}:partitioned-storm:{case_index}"))
        .collect::<Vec<_>>();

    let mut steps = large_group_setup(
        format!("large-partitioned-storm-{case_index}"),
        clients.clone(),
        invitees.clone(),
    );
    steps.push(ScenarioStep::SetPartition {
        allow: vec!["alice".into()],
    });
    for (sender, payload) in senders.iter().zip(payloads.iter()) {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
    }
    // Vary the seeded delivery schedule. Only alice is un-partitioned, so it
    // receives every payload; FIFO delivery makes the observed order the
    // permuted queue order, so recompute the expectation from the same order.
    let order = shuffled_order(rng, senders.len());
    let expected_payloads = order
        .iter()
        .map(|index| payloads[*index].clone())
        .collect::<Vec<_>>();
    steps.push(ScenarioStep::ReorderMessages {
        order: order
            .iter()
            .map(|index| application_selector(&senders[*index]))
            .collect(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(vec!["alice".into()]));
    steps.push(ScenarioStep::ClearPartition);
    steps.push(observe_vec(vec!["alice".into()]));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 25, expected_payloads),
    ];
    (scenario, expected)
}

fn convergence_chaos_large_commit_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let committers = clients[..8].to_vec();
    let mut steps = large_group_setup(
        format!("large-commit-storm-{case_index}"),
        clients.clone(),
        invitees,
    );

    for committer in &committers {
        steps.push(ScenarioStep::UpdateGroupData {
            client: committer.clone(),
            name: format!("{committer} branch {case_index}"),
            pending: format!("{committer}-update"),
        });
    }
    for committer in &committers {
        steps.push(confirmed_step(committer, &format!("{committer}-update")));
    }
    // Vary which queued commit is duplicated and how the queue is reordered
    // from the seed. Convergence and per-committer confirmation are invariant
    // under delivery schedule, so the expectations stay fixed while distinct
    // seeds drive distinct adversarial commit-delivery orders.
    let duplicate_index = rng.gen_range(0..committers.len());
    let duplicate_selector = commit_selector(&committers[duplicate_index]);
    steps.push(ScenarioStep::DuplicateMessage {
        selector: duplicate_selector.clone(),
    });
    let mut queued = committers
        .iter()
        .map(|committer| commit_selector(committer))
        .collect::<Vec<_>>();
    queued.insert(duplicate_index + 1, with_occurrence(duplicate_selector, 1));
    steps.push(ScenarioStep::ReorderMessages {
        order: reorder_selectors(&queued, &shuffled_order(rng, queued.len())),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(committers.clone()));
    steps.push(observe_vec(committers.clone()));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    let mut expected = vec![
        confirmed(1, "alice", "create"),
        clients_converged_vec(committers.clone(), Some(2), Some(21)),
    ];
    for (offset, committer) in committers.iter().enumerate() {
        expected.push(confirmed(
            13 + offset,
            committer,
            &format!("{committer}-update"),
        ));
    }
    (scenario, expected)
}

fn convergence_chaos_large_mixed_message_commit_storm(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = large_clients(21);
    let invitees = clients[1..].to_vec();
    let senders = clients[1..].to_vec();
    let committers = clients[..8].to_vec();
    let sender_payloads = senders
        .iter()
        .map(|sender| (sender.clone(), format!("{sender}:mixed-storm:{case_index}")))
        .collect::<Vec<_>>();
    let mut steps = large_group_setup(
        format!("large-mixed-message-commit-storm-{case_index}"),
        clients.clone(),
        invitees,
    );

    for (sender, payload) in &sender_payloads {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        });
    }
    // Vary the message-phase schedule from the seed and preserve those events
    // through the commit storm so the oracle checks both workload phases.
    let message_order = shuffled_order(rng, senders.len());
    steps.push(ScenarioStep::ReorderMessages {
        order: message_order
            .iter()
            .map(|index| application_selector(&senders[*index]))
            .collect(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));

    for committer in &committers {
        steps.push(ScenarioStep::UpdateGroupData {
            client: committer.clone(),
            name: format!("{committer} mixed branch {case_index}"),
            pending: format!("{committer}-mixed-update"),
        });
    }
    for committer in &committers {
        steps.push(confirmed_step(
            committer,
            &format!("{committer}-mixed-update"),
        ));
    }
    // Vary the commit-storm duplicate target and reorder from the seed.
    // Convergence and per-committer confirmation are schedule-invariant.
    let duplicate_index = rng.gen_range(0..committers.len());
    let duplicate_selector = commit_selector(&committers[duplicate_index]);
    steps.push(ScenarioStep::DuplicateMessage {
        selector: duplicate_selector.clone(),
    });
    let mut queued = committers
        .iter()
        .map(|committer| commit_selector(committer))
        .collect::<Vec<_>>();
    queued.insert(duplicate_index + 1, with_occurrence(duplicate_selector, 1));
    steps.push(ScenarioStep::ReorderMessages {
        order: reorder_selectors(&queued, &shuffled_order(rng, queued.len())),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(committers.clone()));
    steps.push(observe_vec(committers.clone()));

    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    let mut expected = vec![
        confirmed(1, "alice", "create"),
        clients_converged_vec(committers.clone(), Some(2), Some(21)),
    ];
    for (offset, committer) in committers.iter().enumerate() {
        expected.push(confirmed(
            36 + offset,
            committer,
            &format!("{committer}-mixed-update"),
        ));
        let received_payloads = message_order
            .iter()
            .filter_map(|index| {
                let (sender, payload) = &sender_payloads[*index];
                (sender != committer).then(|| payload.clone())
            })
            .collect();
        expected.push(client_state(committer, 2, 21, received_payloads));
    }
    (scenario, expected)
}

fn convergence_chaos_restart_delivery_faults(
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let payload = format!("bob:restart-delivery:{case_index}");
    let scenario = ScenarioSpec {
        name: format!("convergence-chaos/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob", "carol"]),
        steps: vec![
            create_group(
                "alice",
                format!("restart-delivery-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            clear(["alice", "bob", "carol"]),
            ScenarioStep::SendAppMessage {
                sender: "bob".into(),
                payload: payload.clone(),
            },
            ScenarioStep::WithholdMessage {
                selector: application_selector("bob"),
                label: "restart-delayed".into(),
            },
            ScenarioStep::RestartClient {
                client: "alice".into(),
            },
            ScenarioStep::ReleaseWithheld {
                label: "restart-delayed".into(),
            },
            ScenarioStep::DuplicateMessage {
                selector: application_selector("bob"),
            },
            ScenarioStep::ReorderMessages {
                order: vec![
                    with_occurrence(application_selector("bob"), 1),
                    application_selector("bob"),
                ],
            },
            ScenarioStep::DeliverAll,
            tick(["alice"]),
            observe(["alice"]),
        ],
    };
    let expected = vec![
        confirmed(1, "alice", "create"),
        client_state("alice", 1, 3, vec![payload]),
    ];
    (scenario, expected)
}

/// Select one of the twelve adversarial workload shapes by stable case index.
fn admin_churn_case(rng: &mut StdRng, case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    match case_index % 4 {
        0 => admin_churn_seeded_churn(rng, case_index),
        1 => admin_churn_competing_admin_commits(rng, case_index),
        2 => admin_churn_restart_recovery(rng, case_index),
        _ => admin_churn_latecomer_under_pressure(case_index),
    }
}

fn admin_policy_step(client: &str, admins: Vec<String>, pending: &str) -> ScenarioStep {
    ScenarioStep::UpdateAdminPolicy {
        client: client.into(),
        admins,
        pending: pending.into(),
    }
}

fn payload_absent_assert(client: &str, payload: &str) -> ScenarioStep {
    ScenarioStep::Assert {
        assertion: crate::ScenarioAssertionV2::Exactly {
            predicate: crate::ScenarioPredicateV2::PayloadCount {
                client: client.into(),
                payload: payload.into(),
                count: 0,
            },
        },
    }
}

/// Push an acknowledge step for `pending` and record its confirmed
/// pending-resolution expectation at the acknowledge step's index.
fn push_confirmed(
    steps: &mut Vec<ScenarioStep>,
    expected: &mut Vec<TraceExpectation>,
    client: &str,
    pending: &str,
) {
    expected.push(confirmed(steps.len(), client, pending));
    steps.push(confirmed_step(client, pending));
}

/// Sequential admin churn: every commit settles before the next, but the
/// actor, action, and admin-set evolution are drawn from the seed
/// (cheeky essence without wall-clock randomness).
fn admin_churn_seeded_churn(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = labels(["alice", "bob", "carol", "dave"]);
    let rounds = 4_u64;
    let mut expected = Vec::new();
    let mut steps = vec![create_group_vec(
        "alice",
        format!("admin-churn-{case_index}"),
        clients[1..].to_vec(),
        "create",
    )];
    push_confirmed(&mut steps, &mut expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));
    steps.push(clear_vec(clients.clone()));

    steps.push(admin_policy_step("alice", clients.clone(), "promote-all"));
    push_confirmed(&mut steps, &mut expected, "alice", "promote-all");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));

    let mut admins: Vec<String> = clients.clone();
    for round in 0..rounds {
        let actor = admins[rng.gen_range(0..admins.len())].clone();
        let pending = format!("churn-{round}");
        if rng.gen_range(0..100_u32) < 50 || admins.len() == 1 {
            steps.push(ScenarioStep::UpdateGroupData {
                client: actor.clone(),
                name: format!("admin-churn-{case_index}-r{round}"),
                pending: pending.clone(),
            });
        } else {
            // Toggle a non-alice member in or out of the admin set so alice
            // always retains authority and the set never empties.
            let candidates: Vec<String> =
                clients.iter().filter(|c| *c != "alice").cloned().collect();
            let target = candidates[rng.gen_range(0..candidates.len())].clone();
            if admins.contains(&target) {
                admins.retain(|admin| admin != &target);
            } else {
                let position = clients.iter().position(|c| c == &target).unwrap_or(0);
                admins.insert(admins.len().min(position), target);
            }
            // The actor may have demoted itself; the commit is still issued
            // from its pre-commit authority.
            steps.push(admin_policy_step(&actor, admins.clone(), &pending));
        }
        push_confirmed(&mut steps, &mut expected, &actor, &pending);
        steps.push(ScenarioStep::DeliverAll);
        steps.push(tick_vec(clients.clone()));

        for sender in &clients {
            steps.push(ScenarioStep::SendAppMessage {
                sender: sender.clone(),
                payload: format!("admin-churn:{case_index}:r{round}:{sender}"),
            });
        }
        steps.push(ScenarioStep::DeliverAll);
        steps.push(tick_vec(clients.clone()));
    }
    steps.push(observe_vec(clients.clone()));

    let final_epoch = 2 + rounds;
    expected.push(clients_converged_vec(
        clients.clone(),
        Some(final_epoch),
        Some(clients.len()),
    ));
    for client in &clients {
        let received = (0..rounds)
            .flat_map(|round| {
                clients
                    .iter()
                    .filter(|sender| *sender != client)
                    .map(move |sender| format!("admin-churn:{case_index}:r{round}:{sender}"))
                    .collect::<Vec<_>>()
            })
            .collect();
        expected.push(client_state(client, final_epoch, clients.len(), received));
    }

    let scenario = ScenarioSpec {
        name: format!("admin-churn/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    (scenario, expected)
}

/// Two admins race admin-policy commits from the same epoch; delivery order is
/// drawn from the seed. Convergence and post-race usability are
/// schedule-invariant; the winning admin set is not asserted.
fn admin_churn_competing_admin_commits(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = labels(["alice", "bob", "carol", "dave"]);
    let mut expected = Vec::new();
    let mut steps = vec![create_group_vec(
        "alice",
        format!("admin-race-{case_index}"),
        clients[1..].to_vec(),
        "create",
    )];
    push_confirmed(&mut steps, &mut expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));

    steps.push(admin_policy_step(
        "alice",
        labels(["alice", "bob"]),
        "promote-core",
    ));
    push_confirmed(&mut steps, &mut expected, "alice", "promote-core");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));
    steps.push(clear_vec(clients.clone()));

    steps.push(admin_policy_step(
        "alice",
        labels(["alice", "bob", "carol"]),
        "alice-race",
    ));
    steps.push(admin_policy_step(
        "bob",
        labels(["alice", "bob", "dave"]),
        "bob-race",
    ));
    push_confirmed(&mut steps, &mut expected, "alice", "alice-race");
    push_confirmed(&mut steps, &mut expected, "bob", "bob-race");
    let racers = [commit_selector("alice"), commit_selector("bob")];
    steps.push(ScenarioStep::ReorderMessages {
        order: reorder_selectors(&racers, &shuffled_order(rng, racers.len())),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));

    for sender in &clients {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: format!("admin-churn:{case_index}:probe:{sender}"),
        });
    }
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));
    steps.push(observe_vec(clients.clone()));

    expected.push(clients_converged_vec(
        clients.clone(),
        Some(3),
        Some(clients.len()),
    ));
    for client in &clients {
        let received = clients
            .iter()
            .filter(|sender| *sender != client)
            .map(|sender| format!("admin-churn:{case_index}:probe:{sender}"))
            .collect();
        expected.push(client_state(client, 3, clients.len(), received));
    }

    let scenario = ScenarioSpec {
        name: format!("admin-churn/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    (scenario, expected)
}

/// A seeded victim restarts between publishing a rename commit and its
/// delivery, then must accept new traffic into the recovered group
/// (crashy essence).
fn admin_churn_restart_recovery(
    rng: &mut StdRng,
    case_index: u64,
) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = labels(["alice", "bob", "carol"]);
    let victim = clients[rng.gen_range(0..clients.len())].clone();
    let mut expected = Vec::new();
    let mut steps = vec![create_group_vec(
        "alice",
        format!("admin-restart-{case_index}"),
        clients[1..].to_vec(),
        "create",
    )];
    push_confirmed(&mut steps, &mut expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));
    steps.push(clear_vec(clients.clone()));

    steps.push(admin_policy_step("alice", clients.clone(), "promote-all"));
    push_confirmed(&mut steps, &mut expected, "alice", "promote-all");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));

    steps.push(ScenarioStep::UpdateGroupData {
        client: victim.clone(),
        name: format!("admin-restart-{case_index}-renamed"),
        pending: "victim-rename".into(),
    });
    push_confirmed(&mut steps, &mut expected, &victim, "victim-rename");
    steps.push(ScenarioStep::RestartClient {
        client: victim.clone(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));

    steps.push(ScenarioStep::SendAppMessage {
        sender: victim.clone(),
        payload: format!("admin-churn:{case_index}:recovered:{victim}"),
    });
    for sender in clients.iter().filter(|sender| **sender != victim) {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: format!("admin-churn:{case_index}:after:{sender}"),
        });
    }
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));
    steps.push(observe_vec(clients.clone()));

    expected.push(clients_converged_vec(
        clients.clone(),
        Some(3),
        Some(clients.len()),
    ));
    for client in &clients {
        let mut received = Vec::new();
        if *client != victim {
            received.push(format!("admin-churn:{case_index}:recovered:{victim}"));
        }
        for sender in clients.iter().filter(|sender| **sender != victim) {
            if sender != client {
                received.push(format!("admin-churn:{case_index}:after:{sender}"));
            }
        }
        expected.push(client_state(client, 3, clients.len(), received));
    }

    let scenario = ScenarioSpec {
        name: format!("admin-churn/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    (scenario, expected)
}

/// A latecomer joins while the founder keeps commit pressure up; the latecomer
/// must never observe pre-join plaintext (committy essence).
fn admin_churn_latecomer_under_pressure(case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = labels(["alice", "bob", "carol", "dave"]);
    let core = labels(["alice", "bob", "carol"]);
    let pre_payloads = [
        format!("admin-churn:{case_index}:pre:bob"),
        format!("admin-churn:{case_index}:pre:carol"),
    ];
    let mut expected = Vec::new();
    let mut steps = vec![create_group_vec(
        "alice",
        format!("admin-late-{case_index}"),
        core[1..].to_vec(),
        "create",
    )];
    push_confirmed(&mut steps, &mut expected, "alice", "create");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(core[1..].to_vec()));
    steps.push(clear_vec(clients.clone()));
    // The latecomer's process is not subscribed before its invite; pre-join
    // traffic must not accumulate in its mailbox. Ciphertext-exposure forward
    // secrecy is covered by the latecomer-forward-secrecy/v1 vector.
    steps.push(ScenarioStep::SetPartition {
        allow: core.clone(),
    });

    steps.push(ScenarioStep::SendAppMessage {
        sender: "bob".into(),
        payload: pre_payloads[0].clone(),
    });
    steps.push(ScenarioStep::SendAppMessage {
        sender: "carol".into(),
        payload: pre_payloads[1].clone(),
    });
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(core.clone()));

    for sprint in 0..2_u64 {
        let pending = format!("sprint-{sprint}");
        steps.push(ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("admin-late-{case_index}-s{sprint}"),
            pending: pending.clone(),
        });
        push_confirmed(&mut steps, &mut expected, "alice", &pending);
        steps.push(ScenarioStep::DeliverAll);
        steps.push(tick_vec(core[1..].to_vec()));
    }

    steps.push(ScenarioStep::ClearPartition);
    steps.push(invite("alice", ["dave"], "invite-late"));
    push_confirmed(&mut steps, &mut expected, "alice", "invite-late");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));

    steps.push(ScenarioStep::UpdateGroupData {
        client: "alice".into(),
        name: format!("admin-late-{case_index}-post"),
        pending: "post-invite-rename".into(),
    });
    push_confirmed(&mut steps, &mut expected, "alice", "post-invite-rename");
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients[1..].to_vec()));

    for sender in &clients {
        steps.push(ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: format!("admin-churn:{case_index}:post:{sender}"),
        });
    }
    steps.push(ScenarioStep::DeliverAll);
    steps.push(tick_vec(clients.clone()));
    for pre in &pre_payloads {
        steps.push(payload_absent_assert("dave", pre));
    }
    steps.push(observe_vec(clients.clone()));

    let final_epoch = 5;
    expected.push(clients_converged_vec(
        clients.clone(),
        Some(final_epoch),
        Some(clients.len()),
    ));
    let dave_received = clients
        .iter()
        .filter(|sender| *sender != "dave")
        .map(|sender| format!("admin-churn:{case_index}:post:{sender}"))
        .collect();
    expected.push(client_state(
        "dave",
        final_epoch,
        clients.len(),
        dave_received,
    ));
    let mut alice_received = pre_payloads.to_vec();
    alice_received.extend(
        clients
            .iter()
            .filter(|sender| *sender != "alice")
            .map(|sender| format!("admin-churn:{case_index}:post:{sender}")),
    );
    expected.push(client_state(
        "alice",
        final_epoch,
        clients.len(),
        alice_received,
    ));

    let scenario = ScenarioSpec {
        name: format!("admin-churn/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    };
    (scenario, expected)
}

fn adversarial_reliability_case(
    rng: &mut StdRng,
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    match case_index % 12 {
        0 => adversarial_reliability_offline_retained_flood(case_index),
        1 => adversarial_reliability_sustained_mixed_traffic(rng, case_index),
        2 => adversarial_reliability_self_update_adversary(case_index),
        3 => adversarial_reliability_losing_invite_outcome(case_index),
        4 => adversarial_reliability_unequal_relay_reconciliation(case_index),
        5 => adversarial_reliability_restart_boundaries(case_index),
        6 => adversarial_reliability_multi_group_noisy_neighbor(case_index),
        7 => {
            let (mut scenario, expected) = convergence_chaos_large_commit_storm(rng, case_index);
            scenario.name =
                format!("adversarial-reliability/candidate-replay-pressure/case-{case_index}");
            (
                "adversarial-reliability/candidate-replay-pressure/v1".into(),
                GeneratedSubjectKind::Engine,
                scenario,
                expected,
            )
        }
        8 => adversarial_reliability_multi_device_account(case_index),
        9 => adversarial_reliability_app_witness_value(case_index),
        10 => adversarial_reliability_mixed_binary_compatibility(case_index),
        _ => adversarial_reliability_clock_cursor_attack(case_index),
    }
}

/// Build the full retained-history flood, scaling its rounds by catalog cycle.
fn adversarial_reliability_offline_retained_flood(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let rounds = 3 + usize::try_from((case_index / 12) % 3).unwrap_or(0);
    adversarial_reliability_offline_retained_flood_with_rounds(case_index, rounds)
}

/// Build a retained-relay catch-up workload with an explicit flood duration.
fn adversarial_reliability_offline_retained_flood_with_rounds(
    case_index: u64,
    rounds: usize,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "carol", "david"]);
    let mut steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("offline-retained-{case_index}"),
            invitees: labels(["bob", "carol"]),
            required_features: vec![],
            initial_admins: Some(vec!["alice".into()]),
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob", "carol"]),
        ScenarioStep::SetClientOffline {
            client: "bob".into(),
        },
    ];
    for round in 0..rounds {
        steps.push(ScenarioStep::SendAppMessage {
            sender: "alice".into(),
            payload: format!("offline-flood-{case_index}-{round}"),
        });
        steps.push(accept_all_outbound("alice"));
        steps.push(ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("offline-state-{case_index}-{round}"),
            pending: format!("state-{round}"),
        });
        steps.push(confirmed_step("alice", &format!("state-{round}")));
        steps.push(ScenarioStep::DeliverAll);
        steps.push(tick(["carol"]));
    }
    steps.extend([
        invite("alice", ["david"], "invite-david"),
        confirmed_step("alice", "invite-david"),
        ScenarioStep::DeliverAll,
        tick(["carol", "david"]),
        ScenarioStep::SendAppMessage {
            sender: "david".into(),
            payload: format!("membership-window-{case_index}"),
        },
        accept_all_outbound("david"),
        ScenarioStep::DeliverAll,
        tick(["alice", "carol"]),
        ScenarioStep::RemoveMembers {
            remover: "alice".into(),
            members: vec!["david".into()],
            pending: "remove-david".into(),
        },
        confirmed_step("alice", "remove-david"),
        ScenarioStep::DeliverAll,
        tick(["carol", "david"]),
        ScenarioStep::ReconnectClient {
            client: "bob".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::FullHistory,
        },
        tick(["bob"]),
    ]);
    let expected = vec![clients_converged(["alice", "bob", "carol"], None, Some(3))];
    (
        "adversarial-reliability/offline-retained-history-flood/v1".into(),
        GeneratedSubjectKind::RetainedRelay,
        ScenarioSpec {
            name: format!(
                "adversarial-reliability/offline-retained-history-flood/case-{case_index}"
            ),
            spec_version: "2".into(),
            clients,
            topology: adversarial_reliability_single_relay_topology(&labels([
                "alice", "bob", "carol", "david",
            ])),
            steps,
        },
        expected,
    )
}

/// Build sustained mixed application, proposal, and commit traffic.
fn adversarial_reliability_sustained_mixed_traffic(
    rng: &mut StdRng,
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let rounds = 4 + usize::try_from((case_index / 12) % 4).unwrap_or(0);
    adversarial_reliability_sustained_mixed_traffic_with_rounds(rng, case_index, rounds)
}

/// Build mixed traffic with an explicit number of deterministic rounds.
fn adversarial_reliability_sustained_mixed_traffic_with_rounds(
    rng: &mut StdRng,
    case_index: u64,
    rounds: usize,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "carol", "david"]);
    let active = labels(["alice", "bob", "carol", "david"]);
    let mut steps = large_group_setup(
        format!("sustained-mixed-{case_index}"),
        clients.clone(),
        labels(["bob", "carol", "david"]),
    );
    for round in 0..rounds {
        let mut senders = labels(["alice", "bob", "carol", "david"]);
        let sender_count = senders.len();
        senders.rotate_left(rng.gen_range(0..sender_count));
        for sender in &senders {
            steps.push(ScenarioStep::SendAppMessage {
                sender: sender.clone(),
                payload: format!("mixed-{case_index}-{round}-{sender}"),
            });
            steps.push(accept_all_outbound(sender));
        }
        let committer = if round % 2 == 0 { "alice" } else { "bob" };
        steps.push(ScenarioStep::SelfUpdate {
            client: committer.into(),
            pending: format!("self-{round}"),
        });
        steps.push(confirmed_step(committer, &format!("self-{round}")));
        steps.push(ScenarioStep::DeliverAll);
        steps.push(tick_vec(active.clone()));
    }
    steps.extend([
        ScenarioStep::Leave {
            client: "david".into(),
        },
        ScenarioStep::DeliverAll,
        // Let the privileged admin produce the single auto-commit before the
        // remaining members observe the proposal. Ticking every member here
        // intentionally creates a separate multi-auto-committer adversary and
        // obscures this workload's sustained-traffic signal.
        tick(["alice"]),
        accept_all_outbound("alice"),
        ScenarioStep::DeliverAll,
        tick(["bob", "carol", "david"]),
    ]);
    (
        "adversarial-reliability/sustained-mixed-traffic/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/sustained-mixed-traffic/case-{case_index}"),
            spec_version: "2".into(),
            clients,
            topology: Default::default(),
            steps,
        },
        vec![clients_converged(["alice", "bob", "carol"], None, Some(3))],
    )
}

/// Build the full self-update stream followed by an administrative race.
fn adversarial_reliability_self_update_adversary(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    adversarial_reliability_self_update_adversary_with_rounds(case_index, 12)
}

/// Build a self-update/admin race with an explicit update count.
fn adversarial_reliability_self_update_adversary_with_rounds(
    case_index: u64,
    rounds: usize,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "carol"]);
    let mut steps = large_group_setup(
        format!("self-update-adversary-{case_index}"),
        clients.clone(),
        labels(["bob", "carol"]),
    );
    for round in 0..rounds {
        steps.extend([
            ScenarioStep::SelfUpdate {
                client: "bob".into(),
                pending: format!("grind-{round}"),
            },
            confirmed_step("bob", &format!("grind-{round}")),
            ScenarioStep::DeliverAll,
            tick(["alice", "carol"]),
        ]);
    }
    steps.extend([
        ScenarioStep::SelfUpdate {
            client: "bob".into(),
            pending: "racing-self-update".into(),
        },
        ScenarioStep::RemoveMembers {
            remover: "alice".into(),
            members: vec!["bob".into()],
            pending: "privileged-remove".into(),
        },
        confirmed_step("bob", "racing-self-update"),
        confirmed_step("alice", "privileged-remove"),
        ScenarioStep::DeliverAll,
        tick(["alice", "bob", "carol"]),
    ]);
    (
        "adversarial-reliability/self-update-admin-race/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/self-update-admin-race/case-{case_index}"),
            spec_version: "2".into(),
            clients,
            topology: Default::default(),
            steps,
        },
        vec![clients_converged(["alice", "carol"], None, Some(2))],
    )
}

/// Build an invite from a losing branch and require its named terminal outcome.
fn adversarial_reliability_losing_invite_outcome(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "david", "eve"]);
    let steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("losing-invite-repair-{case_index}"),
            invitees: vec!["bob".into()],
            required_features: vec![],
            initial_admins: Some(labels(["alice", "bob"])),
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob"]),
        invite("alice", ["david"], "winning-invite"),
        invite("bob", ["eve"], "losing-invite"),
        confirmed_step("alice", "winning-invite"),
        confirmed_step("bob", "losing-invite"),
        ScenarioStep::WithholdMessage {
            selector: commit_selector("alice"),
            label: "alice-commit".into(),
        },
        ScenarioStep::WithholdMessage {
            selector: commit_selector("bob"),
            label: "bob-commit".into(),
        },
        ScenarioStep::DeliverAll,
        tick(["david", "eve"]),
        ScenarioStep::ReleaseWithheld {
            label: "alice-commit".into(),
        },
        ScenarioStep::ReleaseWithheld {
            label: "bob-commit".into(),
        },
        ScenarioStep::DeliverAll,
        tick(["alice", "bob"]),
        // A same-device re-invite is not a valid repair here: both branch-only
        // devices have already consumed key packages with their signature
        // keys, and OpenMLS rejects reusing either key. Characterize the
        // current named outcome directly; repair requires an explicit local
        // reset/rejoin with fresh device state.
        ScenarioStep::AdvanceTime {
            delta_ms: 30 * 24 * 60 * 60 * 1_000 + 1,
        },
        tick(["alice", "bob", "david", "eve"]),
        ScenarioStep::ObserveExact {
            clients: labels(["david", "eve"]),
        },
    ];
    (
        "adversarial-reliability/losing-invite-unrecoverable/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/losing-invite-unrecoverable/case-{case_index}"),
            spec_version: "2".into(),
            clients: clients.clone(),
            topology: Default::default(),
            steps,
        },
        vec![
            clients_converged(["alice", "bob"], Some(2), Some(3)),
            TraceExpectation::ClientsNotEquivalent {
                clients: labels(["david", "eve"]),
                reason: "branch-only devices remain non-equivalent; the losing device requires explicit local reset/rejoin with fresh state".into(),
            },
        ],
    )
}

/// Build split relay histories that must reconcile after set equalization.
fn adversarial_reliability_unequal_relay_reconciliation(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob"]);
    let steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("unequal-relays-{case_index}"),
            invitees: vec!["bob".into()],
            required_features: vec![],
            initial_admins: Some(vec!["alice".into()]),
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::ReconcileRelayHistories {
            relays: labels(["relay:a", "relay:b"]),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::SetReconciliation,
        },
        tick(["bob"]),
        ScenarioStep::SetClientOffline {
            client: "bob".into(),
        },
        ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("unequal-relays-after-{case_index}"),
            pending: "rename".into(),
        },
        confirmed_step("alice", "rename"),
        ScenarioStep::ReconnectClient {
            client: "bob".into(),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::Incremental,
        },
        tick(["bob"]),
        ScenarioStep::ReconcileRelayHistories {
            relays: labels(["relay:a", "relay:b"]),
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::SetReconciliation,
        },
        tick(["bob"]),
    ];
    (
        "adversarial-reliability/unequal-relay-reconciliation/v1".into(),
        GeneratedSubjectKind::RetainedRelay,
        ScenarioSpec {
            name: format!("adversarial-reliability/unequal-relay-reconciliation/case-{case_index}"),
            spec_version: "2".into(),
            clients: clients.clone(),
            topology: adversarial_reliability_split_relay_topology(&clients),
            steps,
        },
        vec![clients_converged(["alice", "bob"], None, Some(2))],
    )
}

/// Build restart transitions around durable convergence-phase boundaries.
fn adversarial_reliability_restart_boundaries(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "carol"]);
    let steps = vec![
        create_group(
            "alice",
            format!("restart-boundaries-{case_index}"),
            ["bob", "carol"],
            "create",
        ),
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob", "carol"]),
        ScenarioStep::RestartClient {
            client: "bob".into(),
        },
        ScenarioStep::UpdateGroupData {
            client: "alice".into(),
            name: format!("restart-boundaries-after-{case_index}"),
            pending: "update".into(),
        },
        confirmed_step("alice", "update"),
        ScenarioStep::RestartClient {
            client: "carol".into(),
        },
        ScenarioStep::DeliverAll,
        tick(["bob", "carol"]),
        ScenarioStep::RestartClient {
            client: "alice".into(),
        },
    ];
    (
        "adversarial-reliability/restart-boundaries/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/restart-boundaries/case-{case_index}"),
            spec_version: "2".into(),
            clients,
            topology: Default::default(),
            steps,
        },
        vec![clients_converged(["alice", "bob", "carol"], None, Some(3))],
    )
}

/// Build concurrent groups to verify noisy-neighbor workload isolation.
fn adversarial_reliability_multi_group_noisy_neighbor(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob", "carol"]);
    let in_group = |group: &str, action: ScenarioStep| ScenarioStep::InGroup {
        group: group.into(),
        action: Box::new(action),
    };
    let mut steps = vec![
        in_group(
            "quiet",
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "quiet".into(),
                invitees: vec!["bob".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "quiet-create".into(),
            },
        ),
        confirmed_step("alice", "quiet-create"),
        ScenarioStep::DeliverAll,
        tick(["bob"]),
        in_group(
            "noisy",
            ScenarioStep::CreateGroup {
                creator: "alice".into(),
                name: "noisy".into(),
                invitees: vec!["carol".into()],
                required_features: vec![],
                initial_admins: Some(vec!["alice".into()]),
                pending: "noisy-create".into(),
            },
        ),
        confirmed_step("alice", "noisy-create"),
        ScenarioStep::DeliverAll,
        tick(["carol"]),
    ];
    for index in 0..10 {
        steps.push(in_group(
            "noisy",
            ScenarioStep::SendAppMessage {
                sender: "carol".into(),
                payload: format!("noise-{case_index}-{index}"),
            },
        ));
        steps.push(accept_all_outbound("carol"));
    }
    steps.extend([
        in_group(
            "quiet",
            ScenarioStep::SendAppMessage {
                sender: "alice".into(),
                payload: format!("quiet-progress-{case_index}"),
            },
        ),
        accept_all_outbound("alice"),
        ScenarioStep::DeliverAll,
        tick(["alice", "bob", "carol"]),
        in_group(
            "quiet",
            ScenarioStep::Observe {
                clients: labels(["alice", "bob"]),
            },
        ),
    ]);
    (
        "adversarial-reliability/multi-group-noisy-neighbor/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/multi-group-noisy-neighbor/case-{case_index}"),
            spec_version: "2".into(),
            clients,
            topology: Default::default(),
            steps,
        },
        vec![clients_converged(["alice", "bob"], Some(1), Some(2))],
    )
}

/// Build a shared-account, multi-device witness topology and workload.
fn adversarial_reliability_multi_device_account(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice-phone", "alice-laptop", "bob"]);
    let topology = adversarial_reliability_account_topology(&[
        ("alice-phone", "account:alice", "build-a"),
        ("alice-laptop", "account:alice", "build-a"),
        ("bob", "account:bob", "build-a"),
    ]);
    let steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice-phone".into(),
            name: format!("multi-device-{case_index}"),
            invitees: labels(["alice-laptop", "bob"]),
            required_features: vec![],
            initial_admins: Some(vec!["alice-phone".into()]),
            pending: "create".into(),
        },
        confirmed_step("alice-phone", "create"),
        ScenarioStep::DeliverAll,
        tick(["alice-laptop", "bob"]),
        ScenarioStep::SendAppMessage {
            sender: "alice-phone".into(),
            payload: format!("phone-{case_index}"),
        },
        accept_all_outbound("alice-phone"),
        ScenarioStep::SendAppMessage {
            sender: "alice-laptop".into(),
            payload: format!("laptop-{case_index}"),
        },
        accept_all_outbound("alice-laptop"),
        ScenarioStep::DeliverAll,
        tick(["alice-phone", "alice-laptop", "bob"]),
    ];
    (
        "adversarial-reliability/multi-device-account/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!("adversarial-reliability/multi-device-account/case-{case_index}"),
            spec_version: "2".into(),
            clients: clients.clone(),
            topology,
            steps,
        },
        vec![clients_converged_vec(clients, Some(1), Some(3))],
    )
}

/// Build competing branches whose selection depends on application witnesses.
fn adversarial_reliability_app_witness_value(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let scenario = ScenarioSpec {
        name: format!("adversarial-reliability/app-witness-value/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients: labels(["alice", "bob", "carol", "david", "eve", "frank"]),
        steps: vec![
            create_group(
                "alice",
                format!("witness-value-{case_index}"),
                ["bob", "carol"],
                "create",
            ),
            confirmed_step("alice", "create"),
            ScenarioStep::DeliverAll,
            tick(["bob", "carol"]),
            invite("alice", ["david"], "alice-branch"),
            invite("bob", ["eve", "frank"], "bob-branch"),
            confirmed_step("alice", "alice-branch"),
            confirmed_step("bob", "bob-branch"),
            ScenarioStep::WithholdMessage {
                selector: commit_selector("alice"),
                label: "alice-branch-commit".into(),
            },
            ScenarioStep::WithholdMessage {
                selector: commit_selector("bob"),
                label: "bob-branch-commit".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["david", "eve", "frank"]),
            ScenarioStep::SendAppMessage {
                sender: "david".into(),
                payload: format!("david-witness-{case_index}"),
            },
            accept_all_outbound("david"),
            ScenarioStep::SendAppMessage {
                sender: "eve".into(),
                payload: format!("eve-witness-{case_index}"),
            },
            accept_all_outbound("eve"),
            ScenarioStep::SendAppMessage {
                sender: "frank".into(),
                payload: format!("frank-witness-{case_index}"),
            },
            accept_all_outbound("frank"),
            ScenarioStep::ReleaseWithheld {
                label: "alice-branch-commit".into(),
            },
            ScenarioStep::ReleaseWithheld {
                label: "bob-branch-commit".into(),
            },
            ScenarioStep::DeliverAll,
            tick(["alice", "bob", "carol"]),
            ScenarioStep::AdvanceTime {
                delta_ms: 30 * 24 * 60 * 60 * 1_000 + 1,
            },
            tick(["alice", "bob", "carol", "david", "eve", "frank"]),
        ],
    };
    (
        "adversarial-reliability/app-witness-value/v1".into(),
        GeneratedSubjectKind::Engine,
        scenario,
        vec![clients_converged(["alice", "bob", "carol"], None, None)],
    )
}

/// Build a mixed-binary compatibility case with policy preflight constraints.
fn adversarial_reliability_mixed_binary_compatibility(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob"]);
    let topology = adversarial_reliability_account_topology(&[
        ("alice", "account:alice", "mdk-previous"),
        ("bob", "account:bob", "mdk-current"),
    ]);
    (
        "adversarial-reliability/mixed-binary-compatibility-preflight/v1".into(),
        GeneratedSubjectKind::Engine,
        ScenarioSpec {
            name: format!(
                "adversarial-reliability/mixed-binary-compatibility-preflight/case-{case_index}"
            ),
            spec_version: "2".into(),
            clients,
            topology,
            steps: vec![
                create_group(
                    "alice",
                    format!("mixed-binary-{case_index}"),
                    ["bob"],
                    "create",
                ),
                confirmed_step("alice", "create"),
                ScenarioStep::DeliverAll,
                tick(["bob"]),
            ],
        },
        vec![clients_converged(["alice", "bob"], Some(1), Some(2))],
    )
}

/// Build clock, scheduler, timestamp, and relay-cursor adversarial inputs.
fn adversarial_reliability_clock_cursor_attack(
    case_index: u64,
) -> (
    String,
    GeneratedSubjectKind,
    ScenarioSpec,
    Vec<TraceExpectation>,
) {
    let clients = labels(["alice", "bob"]);
    let steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("clock-cursor-{case_index}"),
            invitees: vec!["bob".into()],
            required_features: vec![],
            initial_admins: Some(vec!["alice".into()]),
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick(["bob"]),
        ScenarioStep::SetClientOffline {
            client: "bob".into(),
        },
        ScenarioStep::SendAppMessage {
            sender: "alice".into(),
            payload: format!("before-clock-jump-{case_index}"),
        },
        accept_all_outbound("alice"),
        ScenarioStep::AdvanceTime {
            delta_ms: 365 * 24 * 60 * 60 * 1_000,
        },
        ScenarioStep::ReconnectClient {
            client: "bob".into(),
        },
        ScenarioStep::ConfigureRelay {
            relay: "relay:default".into(),
            order: crate::ScenarioRelayOrderV2::Reverse,
            duplicate_copies: 2,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::Incremental,
        },
        ScenarioStep::SyncRelayHistory {
            clients: vec!["bob".into()],
            sync: crate::ScenarioRelaySyncModeV2::FullHistory,
        },
        tick(["bob"]),
    ];
    (
        "adversarial-reliability/clock-scheduler-cursor/v1".into(),
        GeneratedSubjectKind::RetainedRelay,
        ScenarioSpec {
            name: format!("adversarial-reliability/clock-scheduler-cursor/case-{case_index}"),
            spec_version: "2".into(),
            clients: clients.clone(),
            topology: adversarial_reliability_single_relay_topology(&clients),
            steps,
        },
        vec![clients_converged(["alice", "bob"], Some(1), Some(2))],
    )
}

/// Construct account, device, process, and client mappings for a workload.
fn adversarial_reliability_account_topology(
    clients: &[(&str, &str, &str)],
) -> crate::ScenarioTopologyV2 {
    let mut accounts = BTreeSet::new();
    crate::ScenarioTopologyV2 {
        accounts: clients
            .iter()
            .filter_map(|(_, account, _)| {
                if accounts.insert(*account) {
                    Some(crate::ScenarioAccountV2 {
                        id: (*account).into(),
                        roles: vec!["member".into()],
                    })
                } else {
                    None
                }
            })
            .collect(),
        devices: clients
            .iter()
            .map(|(client, account, _)| crate::ScenarioDeviceV2 {
                id: format!("device:{client}"),
                account: (*account).into(),
                process: format!("process:{client}"),
                client: (*client).into(),
            })
            .collect(),
        processes: clients
            .iter()
            .map(|(client, _, binary)| crate::ScenarioProcessV2 {
                id: format!("process:{client}"),
                binary_version: (*binary).into(),
                policy_version: "marmot-convergence-v1".into(),
                relays: vec![],
            })
            .collect(),
        groups: vec![],
        relays: vec![],
    }
}

/// Construct a topology in which every client reads from one retained relay.
fn adversarial_reliability_single_relay_topology(clients: &[String]) -> crate::ScenarioTopologyV2 {
    let mut topology = adversarial_reliability_account_topology(
        &clients
            .iter()
            .map(|client| (client.as_str(), client.as_str(), "mdk-current"))
            .collect::<Vec<_>>(),
    );
    topology.relays = vec![crate::ScenarioRelayV2 {
        id: "relay:default".into(),
        implementation_version: "memory/v1".into(),
        policy_version: "retain-all/v1".into(),
    }];
    for process in &mut topology.processes {
        process.relays = vec!["relay:default".into()];
    }
    topology
}

/// Construct unequal relay subscriptions for later history reconciliation.
fn adversarial_reliability_split_relay_topology(clients: &[String]) -> crate::ScenarioTopologyV2 {
    let mut topology = adversarial_reliability_single_relay_topology(clients);
    topology.relays = vec![
        crate::ScenarioRelayV2 {
            id: "relay:a".into(),
            implementation_version: "memory/v1".into(),
            policy_version: "retain-all/v1".into(),
        },
        crate::ScenarioRelayV2 {
            id: "relay:b".into(),
            implementation_version: "memory/v1".into(),
            policy_version: "retain-all/v1".into(),
        },
    ];
    for (index, process) in topology.processes.iter_mut().enumerate() {
        process.relays = vec![if index % 2 == 0 {
            "relay:a".into()
        } else {
            "relay:b".into()
        }];
    }
    topology
}

fn labels<const N: usize>(items: [&str; N]) -> Vec<String> {
    items.into_iter().map(String::from).collect()
}

fn application_selector(sender: &str) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        sender: Some(sender.into()),
        class: Some(ScenarioTransportClass::Application),
        ..Default::default()
    }
}

fn commit_selector(sender: &str) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        sender: Some(sender.into()),
        class: Some(ScenarioTransportClass::Commit),
        ..Default::default()
    }
}

fn action_selector(
    step_index: usize,
    step: &ScenarioStep,
    class: ScenarioTransportClass,
) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        action_id: Some(stable_action_id(step_index, step)),
        class: Some(class),
        ..Default::default()
    }
}

fn publication_selector(
    publication: &str,
    class: ScenarioTransportClass,
) -> ScenarioMessageSelectorV2 {
    ScenarioMessageSelectorV2 {
        publication: Some(publication.into()),
        class: Some(class),
        ..Default::default()
    }
}

fn with_occurrence(
    mut selector: ScenarioMessageSelectorV2,
    occurrence: usize,
) -> ScenarioMessageSelectorV2 {
    selector.occurrence = occurrence;
    selector
}

fn reorder_selectors(
    selectors: &[ScenarioMessageSelectorV2],
    order: &[usize],
) -> Vec<ScenarioMessageSelectorV2> {
    order
        .iter()
        .map(|index| selectors[*index].clone())
        .collect()
}

fn large_clients(count: usize) -> Vec<String> {
    let mut clients = Vec::with_capacity(count);
    clients.push("alice".into());
    for index in 1..count {
        clients.push(format!("member{index:02}"));
    }
    clients
}

fn large_group_setup(
    name: String,
    clients: Vec<String>,
    invitees: Vec<String>,
) -> Vec<ScenarioStep> {
    vec![
        create_group_vec("alice", name, invitees.clone(), "create"),
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        tick_vec(invitees),
        clear_vec(clients),
    ]
}

fn create_group<const N: usize>(
    creator: &str,
    name: String,
    invitees: [&str; N],
    pending: &str,
) -> ScenarioStep {
    ScenarioStep::CreateGroup {
        creator: creator.into(),
        name,
        invitees: labels(invitees),
        required_features: vec![],
        initial_admins: None,
        pending: pending.into(),
    }
}

fn create_group_vec(
    creator: &str,
    name: String,
    invitees: Vec<String>,
    pending: &str,
) -> ScenarioStep {
    ScenarioStep::CreateGroup {
        creator: creator.into(),
        name,
        invitees,
        required_features: vec![],
        initial_admins: None,
        pending: pending.into(),
    }
}

fn invite<const N: usize>(inviter: &str, invitees: [&str; N], pending: &str) -> ScenarioStep {
    ScenarioStep::InviteMembers {
        inviter: inviter.into(),
        invitees: labels(invitees),
        pending: pending.into(),
    }
}

fn confirmed_step(client: &str, pending: &str) -> ScenarioStep {
    acknowledged_step(client, pending, SubjectOutboundOutcome::Accepted)
}

fn acknowledged_step(
    client: &str,
    publication: &str,
    outcome: SubjectOutboundOutcome,
) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: Some(publication.into()),
        selection: ScenarioOutboundSelection::All,
        outcome,
    }
}

fn accept_all_outbound(client: &str) -> ScenarioStep {
    ScenarioStep::AcknowledgeOutbound {
        client: client.into(),
        publication: None,
        selection: ScenarioOutboundSelection::All,
        outcome: SubjectOutboundOutcome::Accepted,
    }
}

fn tick<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::Tick {
        clients: labels(clients),
    }
}

fn tick_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::Tick { clients }
}

fn clear<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::ClearEvents {
        clients: labels(clients),
    }
}

fn clear_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::ClearEvents { clients }
}

fn observe<const N: usize>(clients: [&str; N]) -> ScenarioStep {
    ScenarioStep::Observe {
        clients: labels(clients),
    }
}

fn observe_vec(clients: Vec<String>) -> ScenarioStep {
    ScenarioStep::Observe { clients }
}

fn confirmed(step_index: usize, client: &str, pending: &str) -> TraceExpectation {
    TraceExpectation::PendingResolution {
        step_index,
        client: client.into(),
        pending: pending.into(),
        resolution: "confirmed".into(),
    }
}

fn rolled_back(step_index: usize, client: &str, pending: &str) -> TraceExpectation {
    TraceExpectation::PendingResolution {
        step_index,
        client: client.into(),
        pending: pending.into(),
        resolution: "rolled_back".into(),
    }
}

fn clients_converged<const N: usize>(
    clients: [&str; N],
    epoch: Option<u64>,
    member_count: Option<usize>,
) -> TraceExpectation {
    TraceExpectation::ClientsConverged {
        clients: labels(clients),
        epoch,
        member_count,
    }
}

fn clients_converged_vec(
    clients: Vec<String>,
    epoch: Option<u64>,
    member_count: Option<usize>,
) -> TraceExpectation {
    TraceExpectation::ClientsConverged {
        clients,
        epoch,
        member_count,
    }
}

fn client_state(
    client: &str,
    epoch: u64,
    member_count: usize,
    received_payloads: Vec<String>,
) -> TraceExpectation {
    TraceExpectation::ClientState {
        client: client.into(),
        epoch,
        member_count,
        received_payloads: Some(received_payloads),
        added_members: None,
        removed_members: None,
    }
}

fn recovery_summary(
    count: usize,
    source_epoch: Option<u64>,
    recovered_epoch: Option<u64>,
) -> TraceExpectation {
    TraceExpectation::RecoverySummary {
        count,
        source_epoch,
        recovered_epoch,
        winner_differs_from_invalidated: true,
    }
}

fn convergence_e2e_delivery_case(rng: &mut StdRng, case_index: u64) -> ScenarioSpec {
    let clients = vec![
        "alice".to_string(),
        "bob".to_string(),
        "carol".to_string(),
        "frank".to_string(),
        "david".to_string(),
        "eve".to_string(),
        "grace".to_string(),
    ];
    let mut steps = convergence_e2e_prefix_steps(case_index);
    let mut queue = convergence_e2e_queue_selectors(&steps);
    let split_delivery = match rng.gen_range(0..=6) {
        0 => false,
        1 => {
            let order = reversed_order(queue.len());
            queue = reorder_selectors(&queue, &order);
            steps.push(ScenarioStep::ReorderMessages {
                order: queue.clone(),
            });
            false
        }
        2 => {
            let index = relevant_queue_index(rng, queue.len());
            let selector = queue[index].clone();
            steps.push(ScenarioStep::DuplicateMessage {
                selector: selector.clone(),
            });
            queue.insert(index + 1, with_occurrence(selector, 1));
            false
        }
        3 => {
            let index = relevant_queue_index(rng, queue.len());
            let selector = queue.remove(index);
            steps.push(ScenarioStep::WithholdMessage {
                selector: selector.clone(),
                label: "delayed-input".into(),
            });
            steps.push(ScenarioStep::ReleaseWithheld {
                label: "delayed-input".into(),
            });
            queue.push(with_occurrence(selector, 0));
            false
        }
        4 => {
            let index = relevant_queue_index(rng, queue.len());
            let selector = queue.remove(index);
            steps.push(ScenarioStep::WithholdMessage {
                selector,
                label: "delayed-input".into(),
            });
            true
        }
        5 => {
            let order = rotated_order(queue.len(), rng.gen_range(1..queue.len()));
            queue = reorder_selectors(&queue, &order);
            steps.push(ScenarioStep::ReorderMessages {
                order: queue.clone(),
            });
            false
        }
        _ => {
            let index = relevant_queue_index(rng, queue.len());
            let selector = queue[index].clone();
            steps.push(ScenarioStep::DuplicateMessage {
                selector: selector.clone(),
            });
            queue.insert(index + 1, with_occurrence(selector, 1));
            let order = reversed_order(queue.len());
            queue = reorder_selectors(&queue, &order);
            steps.push(ScenarioStep::ReorderMessages {
                order: queue.clone(),
            });
            false
        }
    };

    if split_delivery {
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::ReleaseWithheld {
            label: "delayed-input".into(),
        });
        steps.push(ScenarioStep::DeliverAll);
    } else {
        steps.push(ScenarioStep::DeliverAll);
    }
    steps.push(ScenarioStep::Tick {
        clients: vec!["carol".into(), "frank".into()],
    });
    steps.push(ScenarioStep::Observe {
        clients: vec!["carol".into(), "frank".into()],
    });

    ScenarioSpec {
        name: format!("convergence-e2e-delivery/v1/case-{case_index}"),
        spec_version: "2".into(),
        topology: Default::default(),
        clients,
        steps,
    }
}

fn convergence_e2e_prefix_steps(case_index: u64) -> Vec<ScenarioStep> {
    vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("convergence-e2e-delivery-{case_index}"),
            invitees: vec!["bob".into(), "carol".into(), "frank".into()],
            required_features: vec![],
            initial_admins: None,
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["bob".into(), "carol".into(), "frank".into()],
        },
        ScenarioStep::ClearEvents {
            clients: vec!["alice".into(), "bob".into(), "carol".into(), "frank".into()],
        },
        ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: vec!["david".into()],
            pending: "alice-invite-david".into(),
        },
        confirmed_step("alice", "alice-invite-david"),
        ScenarioStep::InviteMembers {
            inviter: "alice".into(),
            invitees: vec!["grace".into()],
            pending: "alice-invite-grace".into(),
        },
        confirmed_step("alice", "alice-invite-grace"),
        ScenarioStep::InviteMembers {
            inviter: "bob".into(),
            invitees: vec!["eve".into()],
            pending: "bob-invite-eve".into(),
        },
        confirmed_step("bob", "bob-invite-eve"),
        ScenarioStep::SendAppMessage {
            sender: "alice".into(),
            payload: "alice canonical payload".into(),
        },
        ScenarioStep::SendAppMessage {
            sender: "bob".into(),
            payload: "bob losing payload".into(),
        },
    ]
}

fn convergence_e2e_queue_selectors(steps: &[ScenarioStep]) -> Vec<ScenarioMessageSelectorV2> {
    let mut selectors = Vec::with_capacity(8);
    for publication in ["alice-invite-david", "alice-invite-grace", "bob-invite-eve"] {
        selectors.push(publication_selector(
            publication,
            ScenarioTransportClass::Welcome,
        ));
        selectors.push(publication_selector(
            publication,
            ScenarioTransportClass::Commit,
        ));
    }
    for (index, step) in steps.iter().enumerate() {
        if matches!(step, ScenarioStep::SendAppMessage { .. }) {
            selectors.push(action_selector(
                index,
                step,
                ScenarioTransportClass::Application,
            ));
        }
    }
    selectors
}

fn relevant_queue_index(rng: &mut StdRng, queue_len: usize) -> usize {
    const RELEVANT_BASE_INDICES: [usize; 5] = [1, 3, 5, 6, 7];
    let usable: Vec<usize> = RELEVANT_BASE_INDICES
        .into_iter()
        .filter(|index| *index < queue_len)
        .collect();
    usable[rng.gen_range(0..usable.len())]
}

fn reversed_order(len: usize) -> Vec<usize> {
    (0..len).rev().collect()
}

fn rotated_order(len: usize, left_by: usize) -> Vec<usize> {
    (0..len).map(|index| (index + left_by) % len).collect()
}

/// Seed-driven permutation of `0..len`. Distinct seeds produce distinct
/// delivery schedules, so the chaos family's queue-fault shapes vary real
/// behavior with the seed instead of re-running one fixed order. The result is
/// always a valid permutation consumed by semantic selector reordering.
fn shuffled_order(rng: &mut StdRng, len: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    // Fisher-Yates: deterministic for a fixed rng state.
    for i in (1..len).rev() {
        let j = rng.gen_range(0..=i);
        order.swap(i, j);
    }
    order
}

fn send_leave_case(rng: &mut StdRng, case_index: u64) -> (ScenarioSpec, Vec<TraceExpectation>) {
    let clients = vec!["alice".to_string(), "bob".to_string(), "carol".to_string()];
    let mut steps = vec![
        ScenarioStep::CreateGroup {
            creator: "alice".into(),
            name: format!("send-leave-{case_index}"),
            invitees: vec!["bob".into(), "carol".into()],
            required_features: vec![],
            initial_admins: None,
            pending: "create".into(),
        },
        confirmed_step("alice", "create"),
        ScenarioStep::DeliverAll,
        ScenarioStep::Tick {
            clients: vec!["bob".into(), "carol".into()],
        },
    ];

    let send_count = 2 + rng.gen_range(0..=2);
    let mut sends = Vec::with_capacity(send_count);
    let mut send_selectors = Vec::with_capacity(send_count);
    for send_index in 0..send_count {
        let sender = clients[rng.gen_range(0..clients.len())].clone();
        let marker: u16 = rng.r#gen();
        let payload = format!("case-{case_index}:send-{send_index}:{sender}:{marker}");
        let step = ScenarioStep::SendAppMessage {
            sender: sender.clone(),
            payload: payload.clone(),
        };
        send_selectors.push(action_selector(
            steps.len(),
            &step,
            ScenarioTransportClass::Application,
        ));
        steps.push(step);
        sends.push((sender, payload));
    }

    if send_count > 1 && rng.gen_bool(0.5) {
        steps.push(ScenarioStep::ReorderMessages {
            order: send_selectors.into_iter().rev().collect(),
        });
        sends.reverse();
    }
    steps.push(ScenarioStep::DeliverAll);
    steps.push(ScenarioStep::Tick {
        clients: clients.clone(),
    });

    let leaver = if rng.gen_bool(0.5) {
        Some(if rng.gen_bool(0.5) { "bob" } else { "carol" })
    } else {
        None
    };

    let observe_clients = if let Some(leaver) = leaver {
        steps.push(ScenarioStep::Leave {
            client: leaver.into(),
        });
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: vec!["alice".into()],
        });
        steps.push(accept_all_outbound("alice"));
        steps.push(ScenarioStep::DeliverAll);
        steps.push(ScenarioStep::Tick {
            clients: clients.clone(),
        });
        clients
            .iter()
            .filter(|client| client.as_str() != leaver)
            .cloned()
            .collect()
    } else {
        clients.clone()
    };

    steps.push(ScenarioStep::Observe {
        clients: observe_clients.clone(),
    });

    let epoch = u64::from(leaver.is_some()) + 1;
    let member_count = clients.len() - usize::from(leaver.is_some());
    let mut expected = vec![confirmed(1, "alice", "create")];
    for client in &observe_clients {
        expected.push(client_state(
            client,
            epoch,
            member_count,
            sends
                .iter()
                .filter(|(sender, _)| sender != client)
                .map(|(_, payload)| payload.clone())
                .collect(),
        ));
    }

    (
        ScenarioSpec {
            name: format!("send-leave/v1/case-{case_index}"),
            spec_version: "2".into(),
            topology: Default::default(),
            clients,
            steps,
        },
        expected,
    )
}

/// Turn a generated reliability scenario's claimed settled state into a
/// strict black-box assertion. The extra drain is deliberate: exact state and
/// quiescence are sampled only after every attached client has had a final
/// chance to consume retained transport.
fn add_strict_reliability_oracle(
    scenario: &mut ScenarioSpec,
    expected: &mut Vec<TraceExpectation>,
) {
    let exact_clients = expected
        .iter()
        .flat_map(|expectation| match expectation {
            TraceExpectation::ClientsConverged { clients, .. } => clients.clone(),
            TraceExpectation::ClientState { client, .. } => vec![client.clone()],
            _ => Vec::new(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if exact_clients.is_empty() {
        return;
    }

    assert!(
        scenario.steps.iter().any(|step| matches!(
            step,
            ScenarioStep::AcknowledgeOutbound {
                publication: Some(_),
                ..
            }
        )),
        "generated reliability scenario {} must exercise at least one labelled outbound acknowledgement",
        scenario.name
    );

    let final_group = scenario.steps.iter().rev().find_map(|step| match step {
        ScenarioStep::InGroup { group, .. } => Some(group.clone()),
        _ => None,
    });
    scenario.steps.push(ScenarioStep::DeliverAll);
    scenario.steps.push(ScenarioStep::Tick {
        clients: scenario.clients.clone(),
    });
    for client in &scenario.clients {
        scenario.steps.push(accept_all_outbound(client));
    }
    scenario.steps.push(ScenarioStep::DeliverAll);
    scenario.steps.push(ScenarioStep::Tick {
        clients: scenario.clients.clone(),
    });
    let observe = ScenarioStep::ObserveExact {
        clients: exact_clients.clone(),
    };
    scenario.steps.push(
        final_group.map_or(observe.clone(), |group| ScenarioStep::InGroup {
            group,
            action: Box::new(observe),
        }),
    );

    if exact_clients.len() >= 2 {
        expected.push(TraceExpectation::ClientsExactlyEquivalent {
            clients: exact_clients.clone(),
        });
    }
    expected.push(TraceExpectation::NoPendingWork {
        clients: exact_clients,
    });
}

/// Strict-oracle variant with an explicit pending-work scope. Appends the same
/// drain / acknowledge / exact-observation tail as
/// [`add_strict_reliability_oracle`], asserts exact equivalence across every
/// expectation-derived client, but limits the no-pending-work assertion to
/// `pending_scope`. Use only when a client is known to retain a documented
/// terminal input (for example a welcome-joined member's own join commit).
fn add_scoped_reliability_oracle(
    scenario: &mut ScenarioSpec,
    expected: &mut Vec<TraceExpectation>,
    pending_scope: Vec<String>,
) {
    let exact_clients = expected
        .iter()
        .flat_map(|expectation| match expectation {
            TraceExpectation::ClientsConverged { clients, .. } => clients.clone(),
            TraceExpectation::ClientState { client, .. } => vec![client.clone()],
            _ => Vec::new(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if exact_clients.is_empty() {
        return;
    }

    scenario.steps.push(ScenarioStep::DeliverAll);
    scenario.steps.push(ScenarioStep::Tick {
        clients: scenario.clients.clone(),
    });
    for client in &scenario.clients {
        scenario.steps.push(accept_all_outbound(client));
    }
    scenario.steps.push(ScenarioStep::DeliverAll);
    scenario.steps.push(ScenarioStep::Tick {
        clients: scenario.clients.clone(),
    });
    scenario.steps.push(ScenarioStep::ObserveExact {
        clients: exact_clients.clone(),
    });

    if exact_clients.len() >= 2 {
        expected.push(TraceExpectation::ClientsExactlyEquivalent {
            clients: exact_clients,
        });
    }
    expected.push(TraceExpectation::NoPendingWork {
        clients: pending_scope,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "must exercise at least one labelled outbound acknowledgement")]
    fn strict_oracle_rejects_family_without_outbound_lifecycle_coverage() {
        let mut scenario = ScenarioSpec {
            name: "missing-outbound-coverage".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![],
        };
        let mut expected = vec![TraceExpectation::ClientState {
            client: "alice".into(),
            epoch: 0,
            member_count: 1,
            received_payloads: None,
            added_members: None,
            removed_members: None,
        }];

        add_strict_reliability_oracle(&mut scenario, &mut expected);
    }

    #[tokio::test]
    async fn minimizer_never_splits_a_fault_and_recovery_pair() {
        let scenario = ScenarioSpec {
            name: "paired-reduction".into(),
            spec_version: "2".into(),
            topology: Default::default(),
            clients: vec!["alice".into()],
            steps: vec![
                ScenarioStep::SetPartition {
                    allow: vec!["alice".into()],
                },
                ScenarioStep::ClearEvents {
                    clients: vec!["alice".into()],
                },
                ScenarioStep::ClearPartition,
            ],
        };

        let minimized = minimize_scenario_with(scenario, |trial| async move {
            let has_partition = trial
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::SetPartition { .. }));
            let has_clear = trial
                .steps
                .iter()
                .any(|step| matches!(step, ScenarioStep::ClearPartition));
            has_partition || has_clear
        })
        .await
        .expect("independent noise should be removable");

        assert_eq!(minimized.steps.len(), 2);
        assert!(matches!(
            minimized.steps[0],
            ScenarioStep::SetPartition { .. }
        ));
        assert!(matches!(minimized.steps[1], ScenarioStep::ClearPartition));
    }

    #[test]
    fn minimization_units_include_orphans_without_splitting_complete_pairs() {
        let steps = vec![
            ScenarioStep::ClearPartition,
            ScenarioStep::SetPartition {
                allow: vec!["alice".into()],
            },
            ScenarioStep::SetPartition {
                allow: vec!["bob".into()],
            },
            ScenarioStep::ClearPartition,
        ];

        assert_eq!(
            semantic_minimization_units(&steps),
            vec![vec![2, 3], vec![0], vec![1]]
        );
    }
}
