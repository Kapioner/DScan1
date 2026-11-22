use std::fmt::Write;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use dscan_config::CliOverrides;
use dscan_db::InsertSummary;
use dscan_engine::{ResultImport, import_results, split_by_scope};
use dscan_integrations::{
    ImportFormat, ResultFormat, TargetImport, detect_format, detect_result_format, import_targets,
    parse_result_format, parse_results,
};

use super::scan_report::format_summary;
use super::{Command, Context, cipher_from_config, connect_database};
use crate::client::commands::import_via_api;
use crate::error::CliError;

/// Rodzaj importowanych danych.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportKind {
    /// Lista celów (CSV/JSON).
    Targets,
    /// Wyniki skanu (JSON/CSV, nmap XML).
    Results,
}

/// Format pliku (domyślnie wg rozszerzenia: .csv, .json, .xml).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FileFormat {
    Csv,
    Json,
    /// Wynik nmap `-oX` (tylko `--kind results`).
    NmapXml,
    /// Źródło pasywne: eksport Shodana, JSON w liniach (I6).
    Shodan,
    /// Źródło pasywne: wynik masscan `-oJ` (I6).
    Masscan,
}

impl FileFormat {
    fn api_name(self) -> &'static str {
        match self {
            FileFormat::Csv => "csv",
            FileFormat::Json => "json",
            FileFormat::NmapXml => "nmap-xml",
            FileFormat::Shodan => "shodan",
            FileFormat::Masscan => "masscan",
        }
    }
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Plik do zaimportowania: cele (CSV z kolumną `target`, tablica JSON) albo wyniki
    /// (nmap XML, JSON z `dscan export hosts`, CSV z `dscan export services`).
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
    /// Zapis bezpośrednio do bazy (bez serwera i RBAC) — wymaga klucza szyfrowania.
    #[arg(long)]
    pub local: bool,
}

impl ImportArgs {
    /// Format z flagi albo z rozszerzenia pliku.
    pub fn format(&self) -> Result<FileFormat, CliError> {
        if let Some(format) = self.format {
            return Ok(format);
        }
        Ok(match self.kind {
            ImportKind::Targets => match detect_format(&self.file)? {
                ImportFormat::Csv => FileFormat::Csv,
                ImportFormat::Json => FileFormat::Json,
            },
            ImportKind::Results => match detect_result_format(&self.file)? {
                ResultFormat::NmapXml => FileFormat::NmapXml,
                ResultFormat::Json => FileFormat::Json,
                ResultFormat::Csv => FileFormat::Csv,
                ResultFormat::Shodan => FileFormat::Shodan,
                ResultFormat::Masscan => FileFormat::Masscan,
            },
        })
    }
}

impl Command for ImportArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let format = self.format()?;
        let content = std::fs::read_to_string(&self.file).map_err(|source| CliError::File {
            path: self.file.clone(),
            source,
        })?;
        let results = self.kind == ImportKind::Results;
        if !self.local {
            return import_via_api(results, format.api_name(), content, self.dry_run).await;
        }
        if results {
            return import_results_locally(context, format, &content, self.dry_run).await;
        }
        let import_format = match format {
            FileFormat::Csv => ImportFormat::Csv,
            FileFormat::Json => ImportFormat::Json,
            FileFormat::NmapXml | FileFormat::Shodan | FileFormat::Masscan => {
                return Err(CliError::Import(
                    dscan_integrations::ImportError::UnknownFormat("nmap-xml".into()),
                ));
            }
        };
        let import = import_targets(&content, import_format)?;
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

/// Import wyników bez serwera: to samo przetwarzanie co skan (I2).
async fn import_results_locally(
    context: &Context,
    format: FileFormat,
    content: &str,
    dry_run: bool,
) -> Result<(), CliError> {
    let result_format = parse_result_format(format.api_name())
        .ok_or_else(|| CliError::Http("nieznany format".into()))?;
    let parsed = parse_results(content, result_format)?;
    let config = context.load_config(CliOverrides::default())?;
    if dry_run {
        let (inside, outside) =
            split_by_scope(parsed.hosts, &config.settings.scope.allowed_networks);
        println!(
            "Tryb próbny: {} hostów w zakresie, {} poza zakresem — nic nie zapisano.",
            inside.len(),
            outside.len()
        );
        return Ok(());
    }
    let cipher = cipher_from_config(&config)?;
    let pool = connect_database(&config).await?;
    let import = ResultImport {
        hosts: parsed.hosts,
        raw_xml: parsed.raw_xml,
        profile: "import".into(),
        requested_by: None,
    };
    let outcome = import_results(&pool, &cipher, &config.settings, import).await?;
    if !outcome.out_of_scope.is_empty() {
        eprintln!(
            "Poza zakresem [scope] (pominięte): {}",
            outcome.out_of_scope.join(", ")
        );
    }
    eprint!("{}", format_summary(&outcome.summary));
    Ok(())
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
