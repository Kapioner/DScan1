//! Podkomendy zdefiniowane w CLI (C2), których logika powstanie w kolejnych
//! zadaniach planu. Mają już docelowe argumenty i pomoc (`--help`), a uruchomione
//! zgłaszają czytelny błąd z numerem zadania.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

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

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Numer starszego przebiegu.
    #[arg(value_name = "PRZEBIEG_A")]
    pub previous_run: i64,
    /// Numer nowszego przebiegu.
    #[arg(value_name = "PRZEBIEG_B")]
    pub current_run: i64,
}

impl Command for DiffArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("diff", "M1, C5")
    }
}

#[derive(Debug, Args)]
pub struct SigArgs {
    #[command(subcommand)]
    pub action: SigAction,
}

#[derive(Debug, Subcommand)]
pub enum SigAction {
    /// Wyświetla sygnatury.
    List,
    /// Testuje sygnaturę na wybranym hoście.
    Test {
        /// Nazwa sygnatury.
        #[arg(value_name = "SYGNATURA")]
        signature: String,
        /// Adres hosta do testu.
        #[arg(long, value_name = "HOST")]
        host: String,
    },
}

impl Command for SigArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("sig", "H5, C5")
    }
}
