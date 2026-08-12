//! Stdio-only black-box node for deterministic process-orchestrator tests.
//!
//! Real relay sockets and container proxying belong to the distributed
//! campaign runner's executable of the same name.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match cgka_conformance_simulator::node_protocol::run_node_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
