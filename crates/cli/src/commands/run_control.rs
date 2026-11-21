//! `dscan stop ID` i `dscan resume ID` — sterowanie skanem na serwerze (S9, C5).

use clap::Args;

use super::{Command, Context};
use crate::client::commands::control_scan;
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct RunIdArgs {
    /// Numer przebiegu.
    #[arg(value_name = "PRZEBIEG")]
    pub run_id: i64,
}

/// Wstrzymuje trwający skan (niedokończone podgrupy wracają do kolejki).
#[derive(Debug, Args)]
pub struct StopArgs {
    #[command(flatten)]
    pub run: RunIdArgs,
}

/// Wznawia wstrzymany skan od niedokończonych podgrup.
#[derive(Debug, Args)]
pub struct ResumeArgs {
    #[command(flatten)]
    pub run: RunIdArgs,
}

impl Command for StopArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        control_scan(self.run.run_id, "stop").await?;
        println!(
            "Wysłano polecenie wstrzymania przebiegu #{}.",
            self.run.run_id
        );
        Ok(())
    }
}

impl Command for ResumeArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        control_scan(self.run.run_id, "resume").await?;
        println!(
            "Wznowiono przebieg #{} (postęp: dashboard albo GET /api/v1/scans/{}).",
            self.run.run_id, self.run.run_id
        );
        Ok(())
    }
}
