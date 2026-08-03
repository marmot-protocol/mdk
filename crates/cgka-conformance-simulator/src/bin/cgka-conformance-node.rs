use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match cgka_conformance_simulator::node_protocol::run_node_stdio().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("conformance node I/O failed: {error}");
            ExitCode::FAILURE
        }
    }
}
