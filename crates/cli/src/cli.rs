//! Definicja wiersza poleceń (clap derive). Każda podkomenda ma własny typ
//! argumentów w module [`crate::commands`].

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::commands::config::ConfigArgs;
use crate::commands::db::DbArgs;
use crate::commands::diff::DiffArgs;
use crate::commands::docs::{CompletionsArgs, DocsArgs};
use crate::commands::dojo::DojoArgs;
use crate::commands::evaluate::EvaluateArgs;
use crate::commands::export::ExportArgs;
use crate::commands::import::ImportArgs;
use crate::commands::keys::KeysArgs;
use crate::commands::run_control::{ResumeArgs, StopArgs};
use crate::commands::scan::ScanArgs;
use crate::commands::serve::ServeArgs;
use crate::commands::session::{LoginArgs, LogoutArgs};
use crate::commands::sig::SigArgs;
use crate::commands::targets::TargetsArgs;
use crate::commands::user::UserArgs;

/// DScan (Defect Scan): skanowanie i inwentaryzacja usług sieciowych.
#[derive(Debug, Parser)]
#[command(name = "dscan", version, propagate_version = true)]
pub struct Cli {
    /// Plik konfiguracji TOML (domyślnie ./dscan.toml, jeśli istnieje).
    #[arg(short, long, global = true, env = "DSCAN_CONFIG", value_name = "PLIK")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Wszystkie podkomendy `dscan`.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Uruchamia serwer API (wykonuje też migracje bazy).
    Serve(ServeArgs),
    /// Skanuje podane cele programem nmap (tylko cele z [scope]).
    Scan(ScanArgs),
    /// Zarządza listą celów skanowania.
    Targets(TargetsArgs),
    /// Importuje cele lub wyniki skanów z pliku.
    Import(ImportArgs),
    /// Eksportuje hosty, usługi lub zmiany do pliku.
    Export(ExportArgs),
    /// Porównuje dwa przebiegi skanu.
    Diff(DiffArgs),
    /// Zarządza sygnaturami technologii.
    Sig(SigArgs),
    /// Zarządza użytkownikami.
    User(UserArgs),
    /// Wyświetla i sprawdza konfigurację.
    Config(ConfigArgs),
    /// Zarządza bazą danych (migracje).
    Db(DbArgs),
    /// Zarządza kluczami szyfrowania.
    Keys(KeysArgs),
    /// Generuje dokumentację CLI (markdown albo strona man).
    Docs(DocsArgs),
    /// Wypisuje skrypt autouzupełniania dla powłoki (bash, zsh, fish…).
    Completions(CompletionsArgs),
    /// Wysyła wyniki i obserwacje do DefectDojo.
    Dojo(DojoArgs),
    /// Mierzy trafność wykrywania względem wyników referencyjnych.
    Evaluate(EvaluateArgs),
    /// Loguje do serwera API i zapisuje token w pliku użytkownika.
    Login(LoginArgs),
    /// Wylogowuje i usuwa zapisany token.
    Logout(LogoutArgs),
    /// Wstrzymuje trwający skan na serwerze.
    Stop(StopArgs),
    /// Wznawia wstrzymany skan na serwerze.
    Resume(ResumeArgs),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    const ALL_SUBCOMMANDS: [&str; 19] = [
        "serve",
        "scan",
        "targets",
        "import",
        "export",
        "diff",
        "sig",
        "user",
        "config",
        "db",
        "keys",
        "login",
        "logout",
        "stop",
        "resume",
        "evaluate",
        "dojo",
        "docs",
        "completions",
    ];

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn all_planned_subcommands_exist_with_help() {
        let command = Cli::command();
        for name in ALL_SUBCOMMANDS {
            let subcommand = command
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("brak podkomendy {name}"));
            assert!(subcommand.get_about().is_some(), "brak opisu dla {name}");
        }
    }

    #[test]
    fn nested_subcommands_have_help() {
        let command = Cli::command();
        for subcommand in command.get_subcommands() {
            for nested in subcommand.get_subcommands() {
                assert!(
                    nested.get_about().is_some(),
                    "brak opisu dla {} {}",
                    subcommand.get_name(),
                    nested.get_name()
                );
            }
        }
    }

    #[test]
    fn global_config_flag_works_after_subcommand() {
        let cli = Cli::try_parse_from(["dscan", "config", "show", "--config", "a.toml"]).unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("a.toml")));
    }

    #[test]
    fn missing_subcommand_is_an_error() {
        assert!(Cli::try_parse_from(["dscan"]).is_err());
    }
}
