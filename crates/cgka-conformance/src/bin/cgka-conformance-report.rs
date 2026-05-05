use std::error::Error;

use cgka_conformance::{ReportCommand, parse_report_command, report_usage, run_report};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    match parse_report_command(std::env::args().skip(1))? {
        ReportCommand::Run(args) => run_report(&args).await,
        ReportCommand::Help => {
            println!("{}", report_usage());
            Ok(())
        }
    }
}
