use std::fs;
use std::path::{Path, PathBuf};

const TRACING_MACROS: &[&str] = &[
    "tracing::trace!(",
    "tracing::debug!(",
    "tracing::info!(",
    "tracing::warn!(",
    "tracing::error!(",
    "trace!(",
    "debug!(",
    "info!(",
    "warn!(",
    "error!(",
];

const DIRECT_OUTPUT_MACROS: &[&str] = &["println!(", "eprintln!(", "dbg!("];

const FORBIDDEN_TRACE_TOKENS: &[&str] = &[
    "account_id",
    "member_id",
    "group_id",
    "message_id",
    "transport_group_id",
    "relay_url",
    "pubkey",
    "event_id",
    "subscription_id",
    "payload",
    "content",
    "plaintext",
    "ciphertext",
    "key_material",
    "private_key",
    "mls_bytes",
];

#[test]
fn production_tracing_calls_are_structured_and_privacy_safe() {
    let repo = workspace_root();
    let mut failures = Vec::new();

    for file in rust_source_files(&repo.join("crates")) {
        let Ok(contents) = fs::read_to_string(&file) else {
            continue;
        };

        for invocation in tracing_invocations(&contents) {
            if !invocation.body.contains("target:") {
                failures.push(format!(
                    "{}:{} tracing call is missing an explicit target",
                    file.display(),
                    invocation.line
                ));
            }
            if !invocation.body.contains("method =") {
                failures.push(format!(
                    "{}:{} tracing call is missing a method field",
                    file.display(),
                    invocation.line
                ));
            }
            for token in FORBIDDEN_TRACE_TOKENS {
                if invocation.body.contains(token) {
                    failures.push(format!(
                        "{}:{} tracing call contains forbidden token `{token}`",
                        file.display(),
                        invocation.line
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "tracing audit failed:\n{}",
        failures.join("\n")
    );
}

#[test]
fn production_library_sources_do_not_write_direct_output() {
    let repo = workspace_root();
    let mut failures = Vec::new();

    for file in rust_source_files(&repo.join("crates")) {
        if is_cli_binary(&file) {
            continue;
        }

        let Ok(contents) = fs::read_to_string(&file) else {
            continue;
        };

        for (index, line) in contents.lines().enumerate() {
            for output_macro in DIRECT_OUTPUT_MACROS {
                if line.contains(output_macro) {
                    failures.push(format!(
                        "{}:{} production library source writes direct output with `{output_macro}`",
                        file.display(),
                        index + 1
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "direct output audit failed:\n{}",
        failures.join("\n")
    );
}

#[derive(Debug)]
struct TraceInvocation {
    line: usize,
    body: String,
}

fn is_cli_binary(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component.as_os_str().to_str(), Some("bin")))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("conformance crate lives two levels below workspace root")
        .to_path_buf()
}

fn rust_source_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_source_files(root, &mut files);
    files
}

fn collect_rust_source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.components().any(|component| {
            matches!(
                component.as_os_str().to_str(),
                Some("target" | "tests" | "benches")
            )
        }) {
            continue;
        }

        if path.is_dir() {
            collect_rust_source_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}

fn tracing_invocations(contents: &str) -> Vec<TraceInvocation> {
    let lines = contents.lines().collect::<Vec<_>>();
    let mut invocations = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        if TRACING_MACROS
            .iter()
            .any(|needle| lines[index].contains(needle))
        {
            let start_line = index + 1;
            let mut body = String::new();
            let mut paren_depth = 0isize;

            loop {
                let line = lines[index];
                paren_depth += line.matches('(').count() as isize;
                paren_depth -= line.matches(')').count() as isize;
                body.push_str(line);
                body.push('\n');
                index += 1;

                if paren_depth <= 0 || index >= lines.len() {
                    break;
                }
            }

            invocations.push(TraceInvocation {
                line: start_line,
                body,
            });
        } else {
            index += 1;
        }
    }

    invocations
}
