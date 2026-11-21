use std::process::ExitCode;

use clap::Parser;
use dscan::cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match dscan::app::run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Błąd: {error}");
            ExitCode::FAILURE
        }
    }
}
