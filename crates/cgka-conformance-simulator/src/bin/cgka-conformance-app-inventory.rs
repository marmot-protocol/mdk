//! Enumerate existing generated cases without rewriting their actions or assertions.
//! Save compatible inputs for explicit `--adapter app-runtime` report replay.

use std::{collections::BTreeSet, error::Error, path::PathBuf, process::ExitCode};

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedScenarioInputV1, ScenarioSpec,
    SubjectDescriptor, VectorFixture, compile_scenario, generate_family_case,
};
use serde_json::json;
use sha2::{Digest, Sha256};

// Bounded first inventory: small/catalog arms; pressure blocks remain opt-in.
const FAMILIES: &[(&str, u64)] = &[
    ("public-app-send-leave/v1", 6),
    ("public-app-membership-reentry/v1", 6),
    ("public-app-offline-recovery/v1", 6),
    ("public-app-admin-handoff/v1", 6),
    ("public-app-admin-churn/v1", 6),
    ("public-app-late-join/v1", 6),
    ("send-leave/v1", 12),
    ("convergence-e2e-delivery/v1", 12),
    ("convergence-chaos/v1", 12),
    ("admin-churn/v1", 12),
    ("adversarial-reliability/v1", 12),
    ("bounded-convergence-pressure/v1", 12),
    ("large-group-pressure/v1", 6),
    ("offline-catchup-pressure/v1", 12),
    ("membership-reentry/v1", 10),
    ("cross-route-restart-permutations/v1", 12),
    ("cross-route-exact-restart-permutations/v1", 12),
    ("chat-journey/v1", 12),
];

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("app inventory: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let out = PathBuf::from(
        args.next()
            .ok_or("usage: cgka-conformance-app-inventory OUT [SEED ...] [--vectors DIR]")?,
    );
    if out.exists() {
        return Err("output already exists; use a fresh evidence directory".into());
    }
    let mut seeds = Vec::new();
    let mut vector_dir = None;
    while let Some(arg) = args.next() {
        if arg == "--vectors" {
            if vector_dir.is_some() {
                return Err("--vectors may be supplied only once".into());
            }
            vector_dir = Some(PathBuf::from(
                args.next().ok_or("--vectors requires a directory")?,
            ));
        } else {
            seeds.push(arg.to_string_lossy().parse::<u64>()?);
        }
    }
    if seeds.is_empty() {
        seeds = vec![7, 42, 17001];
    }
    seeds.sort_unstable();
    seeds.dedup();
    fs_private::create_dir_all_private(&out)?;
    // Obtain the actual adapter descriptor. No participants or workload execute.
    let mut subject = AppRuntimeHarness::new(&[]).await?;
    let descriptor = subject.descriptor();
    subject.shutdown().await;
    drop(subject);
    let mut rows = Vec::new();
    for &(family, cases) in FAMILIES {
        for &seed in &seeds {
            for index in 0..cases {
                let case = generate_family_case(family, seed, index)?;
                let (missing, compile_error) = action_compatibility(&case.scenario, &descriptor);
                let compatible = missing.is_empty() && compile_error.is_none();
                let input = format!("{}-seed-{seed}-case-{index}.json", family.replace('/', "-"));
                let steps = case.scenario.steps.len();
                if compatible {
                    fs_private::write_private(
                        &out.join(&input),
                        &serde_json::to_vec_pretty(&GeneratedScenarioInputV1::new(case))?,
                    )?;
                }
                rows.push(json!({"family":family,"seed":seed,"case_index":index,
                    "action_preflight_compatible":compatible,"missing_capabilities":missing,
                    "compile_error":compile_error,"source_steps":steps,
                    "input":if compatible {Some(input)} else {None}}));
            }
        }
    }
    let mut vectors = Vec::new();
    let mut non_scenario_documents = Vec::new();
    if let Some(vector_dir) = vector_dir {
        let mut directories = vec![vector_dir.clone()];
        let mut paths = Vec::new();
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                if kind.is_dir() {
                    directories.push(entry.path());
                } else if kind.is_file()
                    && entry.path().extension().is_some_and(|ext| ext == "json")
                {
                    paths.push(entry.path());
                }
            }
        }
        paths.sort();
        for path in paths {
            let bytes = std::fs::read(&path)?;
            let document: serde_json::Value = serde_json::from_slice(&bytes)?;
            let file = path.strip_prefix(&vector_dir)?;
            let (name, scenario, has_expected_trace, outcome_count, input_kind) =
                if document.get("scenario_name").is_some() {
                    let fixture: VectorFixture = serde_json::from_value(document)?;
                    (
                        fixture.scenario_name,
                        fixture.scenario,
                        fixture.expected_trace.is_some(),
                        fixture.expected_outcomes.len(),
                        "vector_fixture",
                    )
                } else if document.get("schema_version").is_some() && document.get("case").is_some()
                {
                    let input: GeneratedScenarioInputV1 = serde_json::from_value(document)?;
                    input.validate()?;
                    (
                        input.case.scenario.name.clone(),
                        input.case.scenario,
                        false,
                        input.case.expected_outcomes.len(),
                        "generated_scenario_input",
                    )
                } else {
                    let kind = if document.get("manifest_version").is_some() {
                        "catalog_manifest"
                    } else if document.get("$schema").is_some() {
                        "schema"
                    } else if document.get("fixture_name").is_some() {
                        "byte_fixture"
                    } else {
                        "unrecognized_json"
                    };
                    non_scenario_documents.push(json!({"file": file, "kind": kind,
                        "source_sha256": hex::encode(Sha256::digest(&bytes))}));
                    continue;
                };
            let (missing, compile_error) = action_compatibility(&scenario, &descriptor);
            // Fixed engine traces can count only remote receive events, while
            // the app exposes persisted local and remote timeline rows. Keep
            // their entire oracle intact and inventory them for deliberate
            // companion design; action compatibility is not oracle equivalence.
            vectors.push(json!({
                "file": file, "scenario_name": name, "input_kind": input_kind,
                "source_sha256": hex::encode(Sha256::digest(&bytes)),
                "action_preflight_compatible": missing.is_empty() && compile_error.is_none(),
                "missing_capabilities": missing, "compile_error": compile_error,
                "source_steps": scenario.steps.len(),
                "has_expected_trace": has_expected_trace,
                "expected_outcome_count": outcome_count,
                "scope": "port planning only; original oracle unchanged and not executed"
            }));
        }
    }
    fs_private::write_private(
        &out.join("inventory.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema_version":"1", "descriptor":descriptor, "seeds":seeds, "cases":rows,
            "fixed_vectors": vectors,
            "non_scenario_documents": non_scenario_documents,
            "scope":"action preflight only; strict runtime oracles must still pass; no scenario rewritten"
        }))?,
    )?;
    println!("Saved app action-capability inventory to {}", out.display());
    Ok(())
}

fn action_compatibility(
    scenario: &ScenarioSpec,
    descriptor: &SubjectDescriptor,
) -> (BTreeSet<String>, Option<String>) {
    match compile_scenario(scenario) {
        Ok(compiled) => (
            compiled
                .actions
                .iter()
                .flat_map(|action| &action.schedule.required_capabilities)
                .filter(|capability| !descriptor.supports(**capability))
                .map(ToString::to_string)
                .collect(),
            None,
        ),
        Err(error) => (BTreeSet::new(), Some(error.to_string())),
    }
}
