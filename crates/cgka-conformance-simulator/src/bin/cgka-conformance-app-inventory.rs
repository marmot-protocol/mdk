//! Enumerate existing generated cases without rewriting their actions or assertions.
//! Save compatible inputs for explicit `--adapter app-runtime` report replay.

use std::{collections::BTreeSet, error::Error, path::PathBuf, process::ExitCode};

use cgka_conformance_simulator::{
    AppRuntimeHarness, ConvergenceSubject, GeneratedScenarioInputV1, compile_scenario,
    generate_family_case,
};
use serde_json::json;

// Bounded first inventory: small/catalog arms; pressure blocks remain opt-in.
const FAMILIES: &[(&str, u64)] = &[
    ("public-app-send-leave/v1", 6),
    ("public-app-membership-reentry/v1", 6),
    ("public-app-offline-recovery/v1", 6),
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
            .ok_or("usage: cgka-conformance-app-inventory OUT [SEED ...]")?,
    );
    if out.exists() {
        return Err("output already exists; use a fresh evidence directory".into());
    }
    let mut seeds = args
        .map(|s| s.to_string_lossy().parse::<u64>())
        .collect::<Result<Vec<_>, _>>()?;
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
                let (missing, compile_error) = match compile_scenario(&case.scenario) {
                    Ok(compiled) => (
                        compiled
                            .actions
                            .iter()
                            .flat_map(|a| &a.schedule.required_capabilities)
                            .filter(|c| !descriptor.supports(**c))
                            .map(ToString::to_string)
                            .collect::<BTreeSet<_>>(),
                        None,
                    ),
                    Err(error) => (BTreeSet::new(), Some(error.to_string())),
                };
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
    fs_private::write_private(
        &out.join("inventory.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema_version":"1", "descriptor":descriptor, "seeds":seeds, "cases":rows,
            "scope":"action preflight only; strict runtime oracles must still pass; no scenario rewritten"
        }))?,
    )?;
    println!("Saved app action-capability inventory to {}", out.display());
    Ok(())
}
