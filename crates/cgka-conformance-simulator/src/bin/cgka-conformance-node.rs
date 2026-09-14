//! Public app participant and local relay child for scenario harnesses.
//! The default stdio mode retains the canonical process-orchestrator protocol;
//! `--app-harness` selects the shared public app harness service.

use std::process::ExitCode;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [mode, role] = args.as_slice()
        && mode == "--app-harness"
    {
        return match cgka_conformance_simulator::app_runtime::run_app_process_stdio(role).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    if !args.is_empty() {
        return ExitCode::FAILURE;
    }
    match cgka_conformance_simulator::node_protocol::run_node_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
