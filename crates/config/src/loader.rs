use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};

use crate::{ConfigError, ENCRYPTION_KEY_ENV, EncryptionKey, Settings, validate_settings};

/// Prefiks zmiennych środowiskowych, np. `SZTYGAR_LIMITS__NMAP_MAX_RATE`.
pub const ENV_PREFIX: &str = "SZTYGAR_";

/// Separator sekcji w nazwie zmiennej: `SZTYGAR_<SEKCJA>__<POLE>`.
const ENV_SECTION_SEPARATOR: &str = "__";

/// Zmienne z prefiksem `SZTYGAR_`, które nie są polami [`Settings`]
/// (bez prefiksu, bo tak porównuje je figment).
const ENV_KEYS_OUTSIDE_SETTINGS: [&str; 1] = ["ENCRYPTION_KEY"];

/// Gotowa, zwalidowana konfiguracja.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    /// `None`, gdy zmienna z kluczem nie jest ustawiona — nie każde polecenie go potrzebuje.
    pub encryption_key: Option<EncryptionKey>,
}

impl AppConfig {
    /// Klucz szyfrowania dla poleceń, które bez niego nie mogą działać.
    pub fn require_encryption_key(&self) -> Result<&EncryptionKey, ConfigError> {
        self.encryption_key
            .as_ref()
            .ok_or(ConfigError::MissingEncryptionKey)
    }
}

/// Wczytuje konfigurację z wybranych źródeł (wzorzec Builder).
///
/// ```no_run
/// use sztygar_config::ConfigLoader;
///
/// let config = ConfigLoader::new()
///     .optional_file("sztygar.toml")
///     .load()?;
/// # Ok::<(), sztygar_config::ConfigError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    file: Option<PathBuf>,
    file_required: bool,
    toml_text: Option<String>,
    use_env: bool,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigLoader {
    /// Domyślnie: tylko wartości domyślne + zmienne środowiskowe.
    pub fn new() -> Self {
        ConfigLoader {
            file: None,
            file_required: false,
            toml_text: None,
            use_env: true,
        }
    }

    /// Plik TOML, który musi istnieć (np. podany jawnie przez użytkownika).
    pub fn file(mut self, path: impl AsRef<Path>) -> Self {
        self.file = Some(path.as_ref().to_path_buf());
        self.file_required = true;
        self
    }

    /// Plik TOML, który jest pomijany, jeśli nie istnieje.
    pub fn optional_file(mut self, path: impl AsRef<Path>) -> Self {
        self.file = Some(path.as_ref().to_path_buf());
        self.file_required = false;
        self
    }

    /// Konfiguracja TOML podana jako tekst (przydatne w testach).
    pub fn toml_str(mut self, text: &str) -> Self {
        self.toml_text = Some(text.to_string());
        self
    }

    /// Wyłącza odczyt zmiennych środowiskowych (łącznie z kluczem szyfrowania).
    pub fn without_env(mut self) -> Self {
        self.use_env = false;
        self
    }

    /// Łączy źródła, waliduje wynik i odczytuje klucz szyfrowania.
    pub fn load(self) -> Result<AppConfig, ConfigError> {
        let settings: Settings = self.build_figment()?.extract()?;
        validate_settings(&settings)?;

        let encryption_key = if self.use_env {
            let value = std::env::var(ENCRYPTION_KEY_ENV).ok();
            encryption_key_from_value(value.as_deref())?
        } else {
            None
        };

        Ok(AppConfig {
            settings,
            encryption_key,
        })
    }

    fn build_figment(&self) -> Result<Figment, ConfigError> {
        let mut figment = Figment::from(Serialized::defaults(Settings::default()));

        if let Some(path) = &self.file {
            if self.file_required && !path.exists() {
                return Err(ConfigError::FileNotFound(path.clone()));
            }
            figment = figment.merge(Toml::file(path));
        }
        if let Some(text) = &self.toml_text {
            figment = figment.merge(Toml::string(text));
        }
        if self.use_env {
            let env = Env::prefixed(ENV_PREFIX)
                .ignore(&ENV_KEYS_OUTSIDE_SETTINGS)
                .split(ENV_SECTION_SEPARATOR);
            figment = figment.merge(env);
        }
        Ok(figment)
    }
}

/// Zamienia wartość zmiennej środowiskowej na klucz; pusta wartość = brak klucza.
fn encryption_key_from_value(value: Option<&str>) -> Result<Option<EncryptionKey>, ConfigError> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(hex) => EncryptionKey::from_hex(hex).map(Some),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn empty_key_value_means_no_key() {
        assert!(encryption_key_from_value(None).unwrap().is_none());
        assert!(encryption_key_from_value(Some("  ")).unwrap().is_none());
    }

    #[test]
    fn valid_key_value_is_decoded() {
        assert!(
            encryption_key_from_value(Some(VALID_KEY))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn invalid_key_value_is_an_error() {
        assert!(encryption_key_from_value(Some("xyz")).is_err());
    }

    #[test]
    fn without_sources_defaults_are_used() {
        let config = ConfigLoader::new().without_env().load().unwrap();
        assert_eq!(config.settings, Settings::default());
        assert!(config.encryption_key.is_none());
    }

    #[test]
    fn toml_overrides_defaults() {
        let config = ConfigLoader::new()
            .without_env()
            .toml_str("[limits]\nnmap_max_rate = 25")
            .load()
            .unwrap();

        assert_eq!(config.settings.limits.nmap_max_rate, 25);
        assert_eq!(config.settings.limits.max_parallel_nmap, 4);
    }

    #[test]
    fn encryption_key_cannot_be_set_in_toml() {
        let result = ConfigLoader::new()
            .without_env()
            .toml_str(&format!("encryption_key = \"{VALID_KEY}\""))
            .load();

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let result = ConfigLoader::new()
            .without_env()
            .toml_str("[limits]\nnmap_maxrate = 25")
            .load();

        assert!(matches!(result, Err(ConfigError::Parse(_))));
    }

    #[test]
    fn missing_required_file_is_reported() {
        let result = ConfigLoader::new()
            .without_env()
            .file("/nie/ma/takiego/pliku.toml")
            .load();

        assert!(matches!(result, Err(ConfigError::FileNotFound(_))));
    }

    #[test]
    fn missing_optional_file_is_skipped() {
        let config = ConfigLoader::new()
            .without_env()
            .optional_file("/nie/ma/takiego/pliku.toml")
            .load();

        assert!(config.is_ok());
    }

    #[test]
    fn require_encryption_key_fails_without_key() {
        let config = ConfigLoader::new().without_env().load().unwrap();
        assert!(matches!(
            config.require_encryption_key(),
            Err(ConfigError::MissingEncryptionKey)
        ));
    }
}
