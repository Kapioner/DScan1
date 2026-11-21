use std::fmt::Write;

use clap::{Args, Subcommand};
use dscan_config::{collect_warnings, render_effective_config};

use super::{Command, Context, OverrideArgs};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Wypisuje efektywną konfigurację (TOML) z ukrytymi sekretami.
    Show(OverrideArgs),
    /// Sprawdza konfigurację i wypisuje ostrzeżenia.
    Validate(OverrideArgs),
}

impl Command for ConfigArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        match &self.action {
            ConfigAction::Show(overrides) => {
                let config = context.load_config(overrides.to_overrides())?;
                println!("# Źródło: {}", context.config_source());
                print!("{}", render_effective_config(&config)?);
            }
            ConfigAction::Validate(overrides) => {
                let config = context.load_config(overrides.to_overrides())?;
                let warnings = collect_warnings(&config);
                print!(
                    "{}",
                    format_validation_report(&context.config_source(), &warnings)
                );
            }
        }
        Ok(())
    }
}

/// Raport `config validate`. Błędy kończą program wcześniej, więc tu konfiguracja jest poprawna.
pub fn format_validation_report(source: &str, warnings: &[String]) -> String {
    let mut report = format!("Konfiguracja poprawna (źródło: {source}).\n");
    if warnings.is_empty() {
        report.push_str("Brak ostrzeżeń.\n");
    }
    for warning in warnings {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(report, "Ostrzeżenie: {warning}");
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_without_warnings() {
        let report = format_validation_report("dscan.toml", &[]);
        assert!(report.contains("Konfiguracja poprawna (źródło: dscan.toml)"));
        assert!(report.contains("Brak ostrzeżeń"));
    }

    #[test]
    fn report_lists_each_warning() {
        let warnings = vec!["pierwsze".to_string(), "drugie".to_string()];

        let report = format_validation_report("x.toml", &warnings);

        assert!(report.contains("Ostrzeżenie: pierwsze"));
        assert!(report.contains("Ostrzeżenie: drugie"));
        assert!(!report.contains("Brak ostrzeżeń"));
    }
}
