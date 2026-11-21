//! Formaty wyjścia (`--output table|json|csv`) i kody wyjścia (C7): 0 — brak zmian,
//! 1 — błąd, 2 — wykryto zmiany. Pozwala używać `dscan scan` i `dscan diff` w skryptach i cronie.

use clap::ValueEnum;
use dscan_core::models::{Change, Host};
use dscan_integrations::{service_rows, to_csv};
use serde::Serialize;

use crate::client::types::ChangeView;
use crate::error::CliError;

/// Format wyniku na standardowym wyjściu.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Czytelna tabela (domyślnie).
    #[default]
    Table,
    Json,
    Csv,
}

impl From<&Change> for ChangeView {
    fn from(change: &Change) -> Self {
        ChangeView {
            ip: change.key.ip.to_string(),
            port: change.key.port,
            protocol: change.key.protocol.as_str().to_string(),
            kind: change.kind.as_str().to_string(),
            label: change.kind.label().to_string(),
        }
    }
}

/// Kod wyjścia 2, gdy są zmiany (komunikat o zmianach został już wypisany).
pub fn exit_for_changes(changes: usize) -> Result<(), CliError> {
    if changes > 0 {
        Err(CliError::ChangesDetected(changes))
    } else {
        Ok(())
    }
}

fn json<T: Serialize + ?Sized>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value)
        .map(|text| text + "\n")
        .map_err(|e| CliError::Http(e.to_string()))
}

/// Zmiany jako JSON albo CSV (dla `table` — `None`, wywołujący drukuje własny raport).
pub fn render_changes(
    changes: &[ChangeView],
    format: OutputFormat,
) -> Result<Option<String>, CliError> {
    match format {
        OutputFormat::Table => Ok(None),
        OutputFormat::Json => json(changes).map(Some),
        OutputFormat::Csv => to_csv(changes).map(Some).map_err(CliError::Http),
    }
}

/// Wynik skanu do JSON.
#[derive(Debug, Serialize)]
pub struct ScanOutput<'a> {
    pub run_id: i64,
    pub status: &'a str,
    pub changes: &'a [ChangeView],
    pub hosts: &'a [Host],
}

/// Wynik skanu: JSON (przebieg, zmiany, hosty) albo CSV (jeden wiersz na usługę).
pub fn render_scan(
    output: &ScanOutput<'_>,
    format: OutputFormat,
) -> Result<Option<String>, CliError> {
    match format {
        OutputFormat::Table => Ok(None),
        OutputFormat::Json => json(output).map(Some),
        OutputFormat::Csv => to_csv(&service_rows(output.hosts))
            .map(Some)
            .map_err(CliError::Http),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change() -> ChangeView {
        ChangeView {
            ip: "10.0.0.5".into(),
            port: 80,
            protocol: "tcp".into(),
            kind: "appeared".into(),
            label: "nowa".into(),
        }
    }

    #[test]
    fn formats_and_exit_codes() {
        assert!(
            render_changes(&[change()], OutputFormat::Table)
                .unwrap()
                .is_none()
        );
        let csv = render_changes(&[change()], OutputFormat::Csv)
            .unwrap()
            .unwrap();
        assert_eq!(csv.lines().next(), Some("ip,port,protocol,kind,label"));
        assert!(
            render_changes(&[change()], OutputFormat::Json)
                .unwrap()
                .unwrap()
                .contains("\"appeared\"")
        );
        assert!(exit_for_changes(0).is_ok());
        assert!(matches!(
            exit_for_changes(3),
            Err(CliError::ChangesDetected(3))
        ));
    }
}
