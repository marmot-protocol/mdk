use std::{fs, path::PathBuf};

use clap::Parser;
use marmot_forensics::ForensicsBundle;
use marmot_forensics_analyzer::analyze_bundles;

#[derive(Debug, Parser)]
#[command(about = "Analyze Marmot forensic bundles")]
struct Args {
    #[arg(required = true)]
    bundles: Vec<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut bundles = Vec::with_capacity(args.bundles.len());
    for path in args.bundles {
        let bytes = fs::read(&path)?;
        bundles.push(serde_json::from_slice::<ForensicsBundle>(&bytes)?);
    }
    let report = analyze_bundles(&bundles);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
