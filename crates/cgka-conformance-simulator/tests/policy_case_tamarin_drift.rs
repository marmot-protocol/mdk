use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

fn generated_definitions(source: &str) -> BTreeMap<String, String> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut definitions = BTreeMap::new();
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let is_generated = line.starts_with("rule Init_Generated_Family_")
            || (line.starts_with("lemma generated_") && line.ends_with("_executable:"));
        if !is_generated {
            index += 1;
            continue;
        }

        let start = index;
        index += 1;
        while index < lines.len() && !is_top_level_definition(lines[index]) {
            index += 1;
        }
        let name = line.trim_end_matches(':').to_owned();
        let body = lines[start..index].join("\n").trim_end().to_owned();
        assert!(
            definitions.insert(name.clone(), body).is_none(),
            "duplicate {name}"
        );
    }
    definitions
}

fn is_top_level_definition(line: &str) -> bool {
    !line.starts_with([' ', '\t'])
        && (line.starts_with("rule ")
            || line.starts_with("lemma ")
            || line.starts_with("restriction ")
            || line.starts_with("/*")
            || line == "end")
}

#[test]
fn generated_policy_cases_match_committed_tamarin_definitions() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root exists");
    let policy_cases = workspace.join("formal/tamarin/policy_cases.json");
    let model_path = workspace.join("formal/tamarin/distributed_convergence_v0.spthy");
    let output = Command::new(env!("CARGO_BIN_EXE_cgka-policy-casegen"))
        .args(["--format", "tamarin"])
        .arg(&policy_cases)
        .output()
        .expect("policy-case generator runs");
    assert!(
        output.status.success(),
        "policy-case generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let expected = generated_definitions(
        std::str::from_utf8(&output.stdout).expect("generator output is UTF-8"),
    );
    let actual = generated_definitions(
        &std::fs::read_to_string(model_path).expect("Tamarin model is readable"),
    );

    assert!(
        !expected.is_empty(),
        "generator emitted no policy definitions"
    );
    assert_eq!(
        actual, expected,
        "policy_cases.json drifted from the committed Tamarin rules or executable lemmas; run `just policy-casegen` and update the model"
    );
}
