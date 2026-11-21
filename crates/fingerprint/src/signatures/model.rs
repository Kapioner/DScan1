use std::fmt;

use serde::Deserialize;

/// Sygnatura w postaci z pliku YAML.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureDef {
    pub name: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub condition: Condition,
    pub matchers: Vec<MatcherDef>,
    #[serde(default)]
    pub version: Option<VersionDef>,
}

/// Jak łączyć matchery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    /// Wystarczy jeden pasujący matcher (domyślnie).
    #[default]
    Any,
    /// Muszą pasować wszystkie.
    All,
}

/// Pojedynczy warunek. `weight` to wkład do pewności (0–100).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum MatcherDef {
    /// Nagłówek o nazwie `name`, którego wartość pasuje do `pattern` (brak wzorca = sam nagłówek).
    Header {
        name: String,
        #[serde(default)]
        pattern: Option<String>,
        weight: u8,
    },
    /// Ciasteczko o nazwie `name` (opcjonalnie wartość pasująca do `pattern`).
    Cookie {
        name: String,
        #[serde(default)]
        pattern: Option<String>,
        weight: u8,
    },
    /// Treść strony głównej pasująca do `pattern`.
    Body { pattern: String, weight: u8 },
    /// Hash favicony (mmh3, jak w Shodanie) — liczony od zadania H4.
    Favicon { hash: i32, weight: u8 },
    /// Ścieżka sondowana zapytaniem GET; pasuje, gdy odpowiedź ma `status` (domyślnie 200)
    /// i — jeśli podano — treść pasującą do `pattern`.
    Path {
        path: String,
        #[serde(default)]
        status: Option<u16>,
        #[serde(default)]
        pattern: Option<String>,
        weight: u8,
    },
}

/// Skąd odczytać wersję.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionSource {
    Header,
    Body,
}

/// Ekstrakcja wersji: pierwsza grupa przechwytująca wzorca.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionDef {
    pub source: VersionSource,
    /// Nazwa nagłówka (dla `source: header`).
    #[serde(default)]
    pub name: Option<String>,
    pub pattern: String,
}

/// Błąd w pliku sygnatur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    Yaml(String),
    InvalidPattern { signature: String, reason: String },
    Invalid { signature: String, reason: String },
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Yaml(reason) => write!(f, "niepoprawny plik sygnatur: {reason}"),
            SignatureError::InvalidPattern { signature, reason } => {
                write!(
                    f,
                    "sygnatura '{signature}': niepoprawne wyrażenie regularne: {reason}"
                )
            }
            SignatureError::Invalid { signature, reason } => {
                write!(f, "sygnatura '{signature}': {reason}")
            }
        }
    }
}

impl std::error::Error for SignatureError {}
