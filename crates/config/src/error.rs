use std::fmt;
use std::path::PathBuf;

use dscan_core::models::PortRangeError;

/// Błędy wczytywania i walidacji konfiguracji.
#[derive(Debug)]
pub enum ConfigError {
    /// Wskazany plik konfiguracyjny nie istnieje.
    FileNotFound(PathBuf),
    /// Błąd składni TOML, nieznane pole lub zły typ wartości.
    /// `Box`, bo `figment::Error` jest duży, a `Result` powinien być lekki.
    Parse(Box<figment::Error>),
    InvalidPortRange(PortRangeError),
    InvalidTime(String),
    /// Limit musi być większy od zera; pole zawiera nazwę ustawienia.
    ZeroLimit(&'static str),
    InvalidEncryptionKey(String),
    MissingEncryptionKey,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::FileNotFound(path) => {
                write!(f, "plik konfiguracyjny nie istnieje: {}", path.display())
            }
            ConfigError::Parse(error) => write!(f, "błąd konfiguracji: {error}"),
            ConfigError::InvalidPortRange(error) => write!(f, "{error}"),
            ConfigError::InvalidTime(text) => {
                write!(
                    f,
                    "niepoprawna godzina '{text}' (oczekiwano HH:MM, np. 22:00)"
                )
            }
            ConfigError::ZeroLimit(name) => {
                write!(f, "ustawienie '{name}' musi być większe od zera")
            }
            ConfigError::InvalidEncryptionKey(reason) => {
                write!(f, "niepoprawny klucz szyfrowania: {reason}")
            }
            ConfigError::MissingEncryptionKey => write!(
                f,
                "brak klucza szyfrowania — ustaw zmienną {}",
                crate::ENCRYPTION_KEY_ENV
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<figment::Error> for ConfigError {
    fn from(error: figment::Error) -> Self {
        ConfigError::Parse(Box::new(error))
    }
}

impl From<PortRangeError> for ConfigError {
    fn from(error: PortRangeError) -> Self {
        ConfigError::InvalidPortRange(error)
    }
}
