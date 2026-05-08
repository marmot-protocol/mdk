use std::error::Error;
use std::path::PathBuf;

use crate::{
    generate_convergence_e2e_delivery_family, generate_send_leave_family, run_generated_case_report,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportArgs {
    pub family: String,
    pub seed: u64,
    pub cases: usize,
    pub out: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportCommand {
    Run(ReportArgs),
    Help,
}

pub async fn run_report(args: &ReportArgs) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(&args.out)?;

    let cases = match args.family.as_str() {
        "send-leave/v1" => generate_send_leave_family(args.seed, args.cases),
        "convergence-e2e-delivery/v1" => {
            generate_convergence_e2e_delivery_family(args.seed, args.cases)
        }
        other => return Err(format!("unsupported family {other}").into()),
    };

    for case in cases {
        let report = run_generated_case_report(&case, None).await?;
        let path = args.out.join(format!(
            "{}-seed-{}-case-{}.json",
            case.family_name.replace('/', "-"),
            case.seed,
            case.case_index
        ));
        std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    }

    Ok(())
}

pub fn parse_report_command(
    args: impl IntoIterator<Item = String>,
) -> Result<ReportCommand, Box<dyn Error>> {
    let mut family = "send-leave/v1".to_string();
    let mut seed = 0u64;
    let mut cases = 1usize;
    let mut out = PathBuf::from("target/cgka-conformance-simulator-reports");

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => family = next_value(&mut args, "--family")?,
            "--seed" => seed = next_value(&mut args, "--seed")?.parse()?,
            "--cases" => cases = next_value(&mut args, "--cases")?.parse()?,
            "--out" => out = PathBuf::from(next_value(&mut args, "--out")?),
            "--help" | "-h" => return Ok(ReportCommand::Help),
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    Ok(ReportCommand::Run(ReportArgs {
        family,
        seed,
        cases,
        out,
    }))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    args.next()
        .ok_or_else(|| format!("missing value for {flag}").into())
}

pub fn report_usage() -> &'static str {
    "Usage: cgka-conformance-simulator-report [--family send-leave/v1|convergence-e2e-delivery/v1] [--seed N] [--cases N] [--out DIR]"
}
