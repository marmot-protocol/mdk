#[tokio::main]
async fn main() {
    let output = darkmatter_cli::run_from(std::env::args_os()).await;
    print!("{}", output.stdout);
    eprint!("{}", output.stderr);
    std::process::exit(output.code);
}
