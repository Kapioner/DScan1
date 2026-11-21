use crate::cli::Cli;
use crate::commands::{Command, Context};
use crate::error::CliError;

/// Wykonuje podkomendę wybraną przez użytkownika.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    let context = Context::new(cli.config);
    cli.command.execute(&context).await
}
