use std::fmt;

/// Błędy, przez które nie da się zaimportować pliku w ogóle
/// (błędne pojedyncze wiersze trafiają do raportu, a nie tutaj).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    UnknownFormat(String),
    MissingTargetColumn,
    InvalidCsv(String),
    InvalidJson(String),
    InvalidResults(String),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::UnknownFormat(name) => write!(
                f,
                "nie rozpoznano formatu pliku '{name}' — użyj rozszerzenia .csv/.json albo opcji --format"
            ),
            ImportError::MissingTargetColumn => {
                write!(
                    f,
                    "plik CSV musi mieć kolumnę 'target' (lub 'cel') w nagłówku"
                )
            }
            ImportError::InvalidCsv(reason) => write!(f, "niepoprawny plik CSV: {reason}"),
            ImportError::InvalidResults(reason) => write!(f, "niepoprawne wyniki skanu: {reason}"),
            ImportError::InvalidJson(reason) => write!(
                f,
                "niepoprawny plik JSON: {reason} (oczekiwano tablicy celów)"
            ),
        }
    }
}

impl std::error::Error for ImportError {}
