use std::path::PathBuf;
use std::process::ExitCode;

use cgka_conformance_simulator::{
    process_orchestrator::ProcessOrchestrator, resolve_scenario_input_bytes,
};

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
    let input = resolve_scenario_input_bytes(&std::fs::read(scenario_path)?)?;
    let artifact_name = format!(
        "{}.artifacts",
        out.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("conformance-process")
    );
    let artifact_directory = out
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(artifact_name);
    let mut orchestrator =
        ProcessOrchestrator::launch_resolved(node_bin, &input, artifact_directory).await?;
    let report_result = orchestrator.run().await.and_then(|report| {
        orchestrator.write_report_private(&report, &out)?;
        Ok(report)
    });
    orchestrator.shutdown().await;
    let report = report_result?;
    if report.completed {
        Ok(())
    } else {
        Err("scenario did not complete; inspect the private report and capsule".into())
    }
}
