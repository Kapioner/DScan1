use std::fmt::Write;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use dscan_config::CliOverrides;
use dscan_db::InsertSummary;
use dscan_integrations::{ImportFormat, TargetImport, detect_format, import_targets};

use super::{Command, Context, cipher_from_config, connect_database};
use crate::error::CliError;

/// Rodzaj importowanych danych.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportKind {
    /// Lista celów (CSV/JSON).
    Targets,
    /// Wyniki skanu (JSON/CSV, nmap XML).
    Results,
}

/// Format pliku (domyślnie wg rozszerzenia).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FileFormat {
    Csv,
    Json,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Plik do zaimportowania (CSV z kolumną `target` albo tablica JSON).
    #[arg(value_name = "PLIK")]
    pub file: PathBuf,
    /// Co zawiera plik.
    #[arg(long, value_enum, default_value_t = ImportKind::Targets)]
    pub kind: ImportKind,
    /// Format pliku, jeśli nie wynika z rozszerzenia.
    #[arg(long, value_enum)]
    pub format: Option<FileFormat>,
    /// Tylko sprawdza plik i pokazuje raport — nic nie zapisuje w bazie.
    #[arg(long)]
    pub dry_run: bool,
}

impl Command for ImportArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        if self.kind == ImportKind::Results {
            return Err(CliError::NotImplemented {
                command: "import --kind results",
                tasks: "I2",
            });
        }
        let format = match self.format {
            Some(FileFormat::Csv) => ImportFormat::Csv,
            Some(FileFormat::Json) => ImportFormat::Json,
            None => detect_format(&self.file)?,
        };
        let content = std::fs::read_to_string(&self.file).map_err(|source| CliError::File {
            path: self.file.clone(),
            source,
        })?;
        let import = import_targets(&content, format)?;
        print!("{}", format_import_report(&import));

        if self.dry_run {
            println!("Tryb próbny — nic nie zapisano.");
            return Ok(());
        }
        let config = context.load_config(CliOverrides::default())?;
        let cipher = cipher_from_config(&config)?;
        let pool = connect_database(&config).await?;
        let summary = dscan_db::insert_targets(&pool, &cipher, &import.accepted).await?;
        print!("{}", format_insert_summary(&summary));
        Ok(())
    }
}

/// Raport z walidacji pliku: liczby i lista odrzuconych wierszy z powodami.
pub fn format_import_report(import: &TargetImport) -> String {
    let mut text = format!(
        "Poprawne cele: {}, odrzucone wiersze: {}\n",
        import.accepted.len(),
        import.rejected.len()
    );
    for row in &import.rejected {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "  wiersz {}: '{}' — {}",
            row.row, row.value, row.reason
        );
    }
    text
}

pub fn format_insert_summary(summary: &InsertSummary) -> String {
    format!(
        "Zapisano w bazie: {} nowych, {} już istniało.\n",
        summary.inserted, summary.already_present
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_integrations::RejectedRow;

    #[test]
    fn report_lists_rejected_rows() {
        let import = TargetImport {
            accepted: Vec::new(),
            rejected: vec![RejectedRow {
                row: 3,
                value: "zły".into(),
                reason: "niepoprawny".into(),
            }],
        };

        let report = format_import_report(&import);

        assert!(report.starts_with("Poprawne cele: 0, odrzucone wiersze: 1"));
        assert!(report.contains("wiersz 3: 'zły' — niepoprawny"));
    }

    #[test]
    fn insert_summary_counts() {
        let summary = InsertSummary {
            inserted: 2,
            already_present: 1,
        };
        assert_eq!(
            format_insert_summary(&summary),
            "Zapisano w bazie: 2 nowych, 1 już istniało.\n"
        );
    }
}
