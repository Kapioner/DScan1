//! Podkomendy zdefiniowane w CLI (C2), których logika powstanie w kolejnych
//! zadaniach planu. Mają już docelowe argumenty i pomoc (`--help`), a uruchomione
//! zgłaszają czytelny błąd z numerem zadania.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::{Command, Context, OverrideArgs};
use crate::error::CliError;

fn not_implemented(command: &'static str, tasks: &'static str) -> Result<(), CliError> {
    Err(CliError::NotImplemented { command, tasks })
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Cele: adresy IP, sieci CIDR lub domeny.
    #[arg(value_name = "CEL")]
    pub targets: Vec<String>,
    /// Nazwany profil skanu z konfiguracji.
    #[arg(long, value_name = "NAZWA")]
    pub profile: Option<String>,
    #[command(flatten)]
    pub overrides: OverrideArgs,
}

impl Command for ScanArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("scan", "S2, S3, S4, C5")
    }
}

#[derive(Debug, Args)]
pub struct TargetsArgs {
    #[command(subcommand)]
    pub action: TargetsAction,
}

#[derive(Debug, Subcommand)]
pub enum TargetsAction {
    /// Wyświetla zapisane cele.
    List,
    /// Dodaje cele (IP, CIDR, domeny).
    Add {
        #[arg(required = true, value_name = "CEL")]
        targets: Vec<String>,
        /// Grupa, do której trafią cele.
        #[arg(long, value_name = "NAZWA")]
        group: Option<String>,
    },
    /// Usuwa cele.
    Remove {
        #[arg(required = true, value_name = "CEL")]
        targets: Vec<String>,
    },
}

impl Command for TargetsArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("targets", "S2, A5, C5")
    }
}

/// Rodzaj importowanych danych.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ImportKind {
    /// Lista celów (CSV/JSON).
    Targets,
    /// Wyniki skanu (JSON/CSV, nmap XML).
    Results,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Plik do zaimportowania.
    #[arg(value_name = "PLIK")]
    pub file: PathBuf,
    /// Co zawiera plik.
    #[arg(long, value_enum, default_value_t = ImportKind::Targets)]
    pub kind: ImportKind,
}

impl Command for ImportArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("import", "I1, I2, C5")
    }
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

#[derive(Debug, Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub action: UserAction,
}

#[derive(Debug, Subcommand)]
pub enum UserAction {
    /// Tworzy konto administratora (bezpośrednio w bazie).
    CreateAdmin {
        #[arg(value_name = "LOGIN")]
        username: String,
    },
    /// Wyświetla użytkowników.
    List,
}

impl Command for UserArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("user", "A2, C6")
    }
}

#[derive(Debug, Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub action: KeysAction,
}

#[derive(Debug, Subcommand)]
pub enum KeysAction {
    /// Szyfruje dane wrażliwe nowym kluczem.
    Rotate,
}

impl Command for KeysArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        not_implemented("keys", "B6, C6")
    }
}
