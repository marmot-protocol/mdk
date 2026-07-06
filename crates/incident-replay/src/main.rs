//! `incident-replay` CLI: classify a Goggles `agent-state.json` export.
//!
//! Prints the machine-readable verdict as JSON and exits 0 for any successful
//! classification (a quarantine is a valid outcome, not an error). Exits 2 on
//! usage, I/O, or parse failure.

use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = std::env::args_os().nth(1) else {
        eprintln!("usage: incident-replay <agent-state.json>");
        return ExitCode::from(2);
    };
    let json = match std::fs::read_to_string(&path) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("error: cannot read {}: {err}", path.to_string_lossy());
            return ExitCode::from(2);
        }
    };
    let export = match incident_replay::parse(&json) {
        Ok(export) => export,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    let verdict = incident_replay::classify(&export);
    println!(
        "{}",
        serde_json::to_string_pretty(&verdict).expect("verdict serialises")
    );
    ExitCode::SUCCESS
}
