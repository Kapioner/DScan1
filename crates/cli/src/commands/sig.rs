use clap::{Args, Subcommand};

use super::{Command, Context};
use crate::client::commands::{signature_test_via_api, signatures_via_api};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct SigArgs {
    #[command(subcommand)]
    pub action: SigAction,
}

#[derive(Debug, Subcommand)]
pub enum SigAction {
    /// Wyświetla wbudowane sygnatury.
    List,
    /// Sprawdza sygnaturę na adresie usługi WWW (tylko w zakresie [scope]).
    Test {
        /// Nazwa sygnatury (np. WordPress); „*” = wszystkie.
        #[arg(value_name = "SYGNATURA")]
        signature: String,
        /// Adres usługi, np. http://10.0.0.5:80/ (host musi być adresem IP z [scope]).
        #[arg(long, value_name = "URL")]
        host: String,
    },
}

impl Command for SigArgs {
    /// Sygnatury przez API (C5) — lista z konfiguracji serwera, test wykonywany przez serwer
    /// (w jego zakresie `[scope]` i z jego limitami).
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        match &self.action {
            SigAction::List => signatures_via_api().await,
            SigAction::Test { signature, host } => signature_test_via_api(signature, host).await,
        }
    }
}
