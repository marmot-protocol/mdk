use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cgka_conformance_simulator::{
    ScenarioSpec, ScenarioStep, VectorFixture, compile_scenario, run_scenario_report,
};

#[test]
fn schema_declares_every_executable_step_kind() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/scenario-ir.v2.schema.json"))
            .expect("scenario IR schema parses");
    assert_eq!(schema["properties"]["spec_version"]["const"], "2");
    let schema_kinds = schema["$defs"]["step"]["oneOf"]
        .as_array()
        .expect("step variants")
        .iter()
        .map(|variant| {
            variant["properties"]["type"]["const"]
                .as_str()
                .expect("step kind")
        })
        .collect::<BTreeSet<_>>();
    let executable_kinds = ScenarioStep::KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(schema_kinds, executable_kinds);
}

#[test]
fn every_repository_vector_compiles_to_stable_actions() {
    let vectors = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("vectors");
    let mut paths = Vec::new();
    collect_vector_paths(&vectors, &mut paths);
    assert!(!paths.is_empty());

    for path in paths {
        let fixture: VectorFixture = serde_json::from_slice(
            &fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
        )
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        let first = compile_scenario(&fixture.scenario)
            .unwrap_or_else(|error| panic!("compile {}: {error}", path.display()));
        let second = compile_scenario(&fixture.scenario)
            .unwrap_or_else(|error| panic!("recompile {}: {error}", path.display()));
        assert_eq!(
            first,
            second,
            "compiled schedule drifted for {}",
            path.display()
        );
        assert_eq!(first.actions.len(), fixture.scenario.steps.len());
    }
}

#[tokio::test]
async fn report_records_the_exact_schedule_consumed_by_execution() {
    let scenario = ScenarioSpec {
        name: "compiled-report/v2".into(),
        spec_version: "2".into(),
        clients: vec!["alice".into()],
        steps: vec![
            ScenarioStep::AdvanceTime { delta_ms: 10 },
            ScenarioStep::Tick {
                clients: vec!["alice".into()],
            },
        ],
    };
    let compiled = compile_scenario(&scenario).expect("compile scenario");
    let report = run_scenario_report(&scenario, None)
        .await
        .expect("execute compiled scenario");

    assert_eq!(report.expanded_schedule, compiled.expanded_schedule());
    assert_eq!(report.step_log.len(), compiled.actions.len());
}

fn collect_vector_paths(directory: &Path, paths: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().and_then(|name| name.to_str()) != Some("byte-fixtures") {
                collect_vector_paths(&path, paths);
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.ends_with(".v1.json") && name != "manifest.v1.json" {
            paths.push(path);
        }
    }
}
