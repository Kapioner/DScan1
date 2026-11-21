//! `dscan export` (I3, C5): eksport przez API z filtrami; uprawnienia według roli sprawdza serwer.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::{Command, Context};
use crate::client::commands::{ExportQuery, export_via_api};
use crate::error::CliError;

/// Format pliku eksportu.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Zakres eksportowanych danych.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportScope {
    /// Hosty z usługami (tylko JSON).
    Hosts,
    /// Jeden wiersz na usługę (JSON/CSV) — ten układ przyjmuje też import wyników.
    Services,
    /// Zmiany przebiegu względem poprzedniego.
    Changes,
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    /// Co eksportować.
    #[arg(value_enum, default_value_t = ExportScope::Hosts)]
    pub scope: ExportScope,
    /// Format pliku.
    #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
    pub format: ExportFormat,
    /// Plik wynikowy (domyślnie standardowe wyjście).
    #[arg(long, short, value_name = "PLIK")]
    pub output: Option<PathBuf>,
    /// Numer przebiegu (domyślnie ostatni zakończony).
    #[arg(long, value_name = "PRZEBIEG")]
    pub run: Option<i64>,
    /// Tylko usługi na tym porcie.
    #[arg(long)]
    pub port: Option<u16>,
    /// Tylko usługi w tym stanie (open, closed, filtered).
    #[arg(long)]
    pub state: Option<String>,
    /// Tylko usługi z technologią (fragment nazwy, np. wordpress).
    #[arg(long, value_name = "NAZWA")]
    pub technology: Option<String>,
    /// Tylko wyniki z ręcznymi poprawkami (wymaga roli z results:write).
    #[arg(long)]
    pub edited: bool,
}

impl ExportArgs {
    pub fn query(&self) -> ExportQuery {
        ExportQuery {
            kind: match self.scope {
                ExportScope::Hosts => "hosts",
                ExportScope::Services => "services",
                ExportScope::Changes => "changes",
            },
            format: match self.format {
                ExportFormat::Json => "json",
                ExportFormat::Csv => "csv",
            },
            run: self.run,
            port: self.port,
            state: self.state.clone(),
            technology: self.technology.clone(),
            edited: self.edited,
        }
    }
}

impl Command for ExportArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        let content = export_via_api(&self.query()).await?;
        match &self.output {
            Some(path) => {
                std::fs::write(path, &content).map_err(|source| CliError::File {
                    path: path.clone(),
                    source,
                })?;
                eprintln!("Zapisano {} bajtów do {}", content.len(), path.display());
            }
            None => print!("{content}"),
        }
        Ok(())
    }
}
