//! Podkomendy zdefiniowane w CLI (C2), których logika powstanie w kolejnych
//! zadaniach planu. Mają już docelowe argumenty i pomoc (`--help`), a uruchomione
//! zgłaszają czytelny błąd z numerem zadania.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::{Command, Context};
use crate::error::CliError;

fn not_implemented(command: &'static str, tasks: &'static str) -> Result<(), CliError> {
    Err(CliError::NotImplemented { command, tasks })
}

/// Format pliku eksportu.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Zakres eksportowanych danych.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportScope {
    Hosts,
    Services,
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
}

impl Command for ExportArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("export", "I3, C5")
    }
}
