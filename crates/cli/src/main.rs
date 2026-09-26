use std::io::Write;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // Bound the binary's async layout query at the CLI library boundary.
    let command: std::pin::Pin<Box<dyn std::future::Future<Output = wn_cli::CliOutput>>> =
        Box::pin(wn_cli::run_from(std::env::args_os()));
    let output = command.await;
    if let Err(err) = write_output(&output) {
        eprintln!("wn: failed to write command output: {err}");
        return ExitCode::FAILURE;
    }
    exit_code(output.code)
}

fn write_output(output: &wn_cli::CliOutput) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(output.stdout.as_bytes())?;
    stdout.flush()?;

    let mut stderr = std::io::stderr().lock();
    stderr.write_all(output.stderr.as_bytes())?;
    stderr.flush()
}

fn exit_code(code: i32) -> ExitCode {
    u8::try_from(code).map_or(ExitCode::FAILURE, ExitCode::from)
}
