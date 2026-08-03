use std::path::PathBuf;
use std::process::ExitCode;

use cgka_conformance_simulator::{ScenarioSpec, process_orchestrator::ProcessOrchestrator};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conformance process orchestrator failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let scenario_path = PathBuf::from(
        args.next()
            .ok_or("usage: <scenario.json> <node-bin> <out.json>")?,
    );
    let node_bin = PathBuf::from(args.next().ok_or("missing node binary")?);
    let out = PathBuf::from(args.next().ok_or("missing output path")?);
    if args.next().is_some() {
        return Err("unexpected extra arguments".into());
    }
    let scenario: ScenarioSpec = serde_json::from_slice(&std::fs::read(scenario_path)?)?;
    let mut orchestrator = ProcessOrchestrator::launch(node_bin, &scenario).await?;
    let report = orchestrator.run(&scenario).await?;
    orchestrator.write_report_private(&report, &out)?;
    orchestrator.shutdown().await;
    if report.completed {
        Ok(())
    } else {
        Err("scenario did not complete; inspect the private report and capsule".into())
    }
}
