use std::process::ExitCode;

use clap::Parser;
use dscan::cli::Cli;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match dscan::app::run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        // Kody wyjścia (C7): 0 — brak zmian, 1 — błąd, 2 — wykryto zmiany.
        Err(dscan::error::CliError::ChangesDetected(_)) => ExitCode::from(2),
        Err(error) => {
            eprintln!("Błąd: {error}");
            ExitCode::FAILURE
        }
    }
}
