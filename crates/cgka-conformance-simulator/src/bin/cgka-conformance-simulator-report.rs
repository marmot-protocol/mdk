use std::error::Error;

use cgka_conformance_simulator::{
    ReportCommand, parse_report_command, read_failure_capsule, replay_engine_bytes, report_usage,
    run_report,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match parse_report_command(std::env::args().skip(1))? {
        ReportCommand::Run(args) => {
            let summary = run_report(&args).await?;
            println!("{}", summary.to_human_text());
            if summary.failed() > 0 {
                return Err("conformance failures".into());
            }
            Ok(())
        }
        ReportCommand::ReplayCapsule(path) => {
            let capsule = read_failure_capsule(&path)?;
            let replay = capsule
                .byte_replay
                .as_ref()
                .ok_or("failure capsule does not contain an engine byte-replay checkpoint")?;
            let observation = replay_engine_bytes(replay).await?;
            println!(
                "REPRODUCED {} at epoch {} ({})",
                observation.client_label, observation.epoch, observation.fingerprint.digest
            );
            Ok(())
        }
        ReportCommand::Help => {
            println!("{}", report_usage());
            Ok(())
        }
    }
}
