use std::error::Error;

use cgka_conformance_simulator::{ReportCommand, parse_report_command, report_usage, run_report};

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
        ReportCommand::Help => {
            println!("{}", report_usage());
            Ok(())
        }
    }
}
