//! Import celów z CSV i JSON.
//!
//! CSV — nagłówek z kolumną `target` (opcjonalnie `group`, `note`; dopuszczalne polskie
//! nazwy `cel`, `grupa`, `notatka`):
//! ```text
//! target,group,note
//! 10.0.0.0/24,lab,sieć kontenerów
//! app.lab.local,lab,
//! ```
//! JSON — tablica napisów albo obiektów: `["10.0.0.1", {"target": "10.0.0.0/24", "group": "lab"}]`.

use std::collections::HashMap;
use std::path::Path;

use dscan_core::models::{Target, TargetKind};
use dscan_scanner::targets::parse_target;
use serde::Deserialize;

use crate::ImportError;

/// Format pliku z celami.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Csv,
    Json,
}

/// Odrzucony wiersz: numer (linia CSV lub pozycja w tablicy JSON), wartość i powód.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRow {
    pub row: usize,
    pub value: String,
    pub reason: String,
}

/// Wynik importu: poprawne cele i raport odrzuconych wierszy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetImport {
    pub accepted: Vec<Target>,
    pub rejected: Vec<RejectedRow>,
}

/// Jeden wiersz pliku przed walidacją.
#[derive(Debug, Clone, Deserialize)]
struct RawRow {
    #[serde(alias = "cel")]
    target: String,
    #[serde(default, alias = "grupa")]
    group: Option<String>,
    #[serde(default, alias = "notatka")]
    note: Option<String>,
}

/// Element tablicy JSON: sam napis albo obiekt z polami.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum JsonEntry {
    Text(String),
    Object(RawRow),
}

/// Format na podstawie rozszerzenia pliku.
pub fn detect_format(path: &Path) -> Result<ImportFormat, ImportError> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("csv") => Ok(ImportFormat::Csv),
        Some("json") => Ok(ImportFormat::Json),
        _ => Err(ImportError::UnknownFormat(path.display().to_string())),
    }
}

/// Wczytuje i waliduje cele z treści pliku.
pub fn import_targets(content: &str, format: ImportFormat) -> Result<TargetImport, ImportError> {
    let rows = match format {
        ImportFormat::Csv => read_csv_rows(content)?,
        ImportFormat::Json => read_json_rows(content)?,
    };
    Ok(validate_rows(rows))
}

/// Wiersz CSV albo powód, dla którego nie dało się go odczytać.
type NumberedRow = (usize, Result<RawRow, RejectedRow>);

fn read_csv_rows(content: &str) -> Result<Vec<NumberedRow>, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|error| ImportError::InvalidCsv(error.to_string()))?;
    let has_target = headers
        .iter()
        .any(|name| name.eq_ignore_ascii_case("target") || name.eq_ignore_ascii_case("cel"));
    if !has_target {
        return Err(ImportError::MissingTargetColumn);
    }

    let rows = reader
        .deserialize::<RawRow>()
        .enumerate()
        .map(|(index, result)| {
            // Linia 1 to nagłówek, więc pierwszy rekord jest w linii 2.
            let line = index + 2;
            let row = result.map_err(|error| RejectedRow {
                row: line,
                value: String::new(),
                reason: format!("nie można odczytać wiersza: {error}"),
            });
            (line, row)
        })
        .collect();
    Ok(rows)
}

fn read_json_rows(content: &str) -> Result<Vec<NumberedRow>, ImportError> {
    let entries: Vec<JsonEntry> = serde_json::from_str(content)
        .map_err(|error| ImportError::InvalidJson(error.to_string()))?;
    let rows = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let row = match entry {
                JsonEntry::Text(target) => RawRow {
                    target,
                    group: None,
                    note: None,
                },
                JsonEntry::Object(row) => row,
            };
            (index + 1, Ok(row))
        })
        .collect();
    Ok(rows)
}

/// Waliduje cele, odrzuca błędne i powtórzone (pierwsze wystąpienie wygrywa).
fn validate_rows(rows: Vec<NumberedRow>) -> TargetImport {
    let mut import = TargetImport::default();
    let mut first_seen: HashMap<TargetKind, usize> = HashMap::new();

    for (row_number, row) in rows {
        let raw = match row {
            Ok(raw) => raw,
            Err(rejected) => {
                import.rejected.push(rejected);
                continue;
            }
        };
        let reject = |reason: String| RejectedRow {
            row: row_number,
            value: raw.target.clone(),
            reason,
        };

        match parse_target(&raw.target) {
            Err(error) => import.rejected.push(reject(error.to_string())),
            Ok(kind) => match first_seen.get(&kind) {
                Some(first) => import
                    .rejected
                    .push(reject(format!("duplikat wiersza {first}"))),
                None => {
                    first_seen.insert(kind.clone(), row_number);
                    import.accepted.push(Target {
                        kind,
                        group: non_empty(raw.group),
                        note: non_empty(raw.note),
                    });
                }
            },
        }
    }
    import
}

/// Pusty napis (częsty w CSV) oznacza brak wartości.
fn non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_detected_from_extension() {
        assert_eq!(detect_format(Path::new("cele.CSV")), Ok(ImportFormat::Csv));
        assert_eq!(detect_format(Path::new("a/b.json")), Ok(ImportFormat::Json));
        assert!(detect_format(Path::new("cele.txt")).is_err());
    }

    #[test]
    fn csv_with_all_columns() {
        let csv = "target,group,note\n10.0.0.0/24,lab,sieć\napp.lab.local,,\n";

        let import = import_targets(csv, ImportFormat::Csv).unwrap();

        assert_eq!(import.accepted.len(), 2);
        assert_eq!(import.accepted[0].group.as_deref(), Some("lab"));
        assert_eq!(import.accepted[0].note.as_deref(), Some("sieć"));
        assert_eq!(import.accepted[1].group, None);
        assert!(import.rejected.is_empty());
    }

    #[test]
    fn csv_with_polish_headers_and_only_target_column() {
        let import = import_targets("cel\n10.0.0.1\n", ImportFormat::Csv).unwrap();
        assert_eq!(import.accepted.len(), 1);

        let import = import_targets("grupa,cel\nlab, 10.0.0.2 \n", ImportFormat::Csv).unwrap();
        assert_eq!(import.accepted[0].group.as_deref(), Some("lab"));
    }

    #[test]
    fn csv_without_target_column_is_rejected_entirely() {
        assert_eq!(
            import_targets("adres\n10.0.0.1\n", ImportFormat::Csv),
            Err(ImportError::MissingTargetColumn)
        );
    }

    #[test]
    fn invalid_and_duplicate_rows_are_reported_with_line_numbers() {
        let csv = "target\n10.0.0.1\nzły cel\n10.0.0.1\n10.0.0.0/33\n";

        let import = import_targets(csv, ImportFormat::Csv).unwrap();

        assert_eq!(import.accepted.len(), 1);
        let lines: Vec<usize> = import.rejected.iter().map(|row| row.row).collect();
        assert_eq!(lines, vec![3, 4, 5]);
        assert_eq!(import.rejected[1].reason, "duplikat wiersza 2");
        assert_eq!(import.rejected[0].value, "zły cel");
    }

    #[test]
    fn normalized_duplicates_are_detected() {
        // 10.0.0.7/24 to po normalizacji ta sama sieć co 10.0.0.0/24.
        let import =
            import_targets("target\n10.0.0.0/24\n10.0.0.7/24\n", ImportFormat::Csv).unwrap();
        assert_eq!(import.accepted.len(), 1);
        assert_eq!(import.rejected.len(), 1);
    }

    #[test]
    fn json_with_strings_and_objects() {
        let json = r#"["10.0.0.1", {"target": "10.0.0.0/24", "group": "lab", "note": "x"}, "???"]"#;

        let import = import_targets(json, ImportFormat::Json).unwrap();

        assert_eq!(import.accepted.len(), 2);
        assert_eq!(import.accepted[1].note.as_deref(), Some("x"));
        assert_eq!(import.rejected[0].row, 3);
    }

    #[test]
    fn json_that_is_not_an_array_is_rejected_entirely() {
        assert!(matches!(
            import_targets(r#"{"target": "10.0.0.1"}"#, ImportFormat::Json),
            Err(ImportError::InvalidJson(_))
        ));
    }

    #[test]
    fn empty_csv_gives_empty_import() {
        let import = import_targets("target\n", ImportFormat::Csv).unwrap();
        assert!(import.accepted.is_empty() && import.rejected.is_empty());
    }
}
