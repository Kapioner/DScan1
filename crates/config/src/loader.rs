use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};

use crate::{
    ADMIN_PASSWORD_ENV, ADMIN_USERNAME_ENV, CliOverrides, ConfigError, DATABASE_URL_ENV,
    DatabaseUrl, ENCRYPTION_KEY_ENV, EncryptionKey, InitialAdmin, Settings, validate_settings,
};

/// Prefiks zmiennych środowiskowych, np. `DSCAN_LIMITS__NMAP_MAX_RATE`.
pub const ENV_PREFIX: &str = "DSCAN_";

/// Separator sekcji w nazwie zmiennej: `DSCAN_<SEKCJA>__<POLE>`.
const ENV_SECTION_SEPARATOR: &str = "__";

/// Sekcje [`Settings`]. Z env czytamy tylko zmienne `DSCAN_<SEKCJA>__<POLE>`,
/// więc inne zmienne z prefiksem (sekrety, `DSCAN_CONFIG`, `DSCAN_TEST_…`) nie psują
/// konfiguracji, a literówka w nazwie pola znanej sekcji nadal daje błąd.
const SETTINGS_SECTIONS: [&str; 9] = [
    "scope",
    "limits",
    "schedule",
    "stability",
    "server",
    "database",
    "http",
    "profiles",
    "defectdojo",
];

/// Gotowa, zwalidowana konfiguracja.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub settings: Settings,
    /// `None`, gdy zmienna z kluczem nie jest ustawiona — nie każde polecenie go potrzebuje.
    pub encryption_key: Option<EncryptionKey>,
    /// `None`, gdy zmienna z adresem bazy nie jest ustawiona.
    pub database_url: Option<DatabaseUrl>,
    /// Konto administratora tworzone przy pierwszym starcie (gdy w bazie nie ma użytkowników).
    pub initial_admin: Option<InitialAdmin>,
    /// Token DefectDojo (`DSCAN_DEFECTDOJO_TOKEN`).
    pub defectdojo_token: Option<crate::ApiToken>,
}

impl AppConfig {
    /// Klucz szyfrowania dla poleceń, które bez niego nie mogą działać.
    pub fn require_encryption_key(&self) -> Result<&EncryptionKey, ConfigError> {
        self.encryption_key
            .as_ref()
            .ok_or(ConfigError::MissingEncryptionKey)
    }

    /// Adres bazy dla poleceń, które z niej korzystają.
    pub fn require_database_url(&self) -> Result<&DatabaseUrl, ConfigError> {
        self.database_url
            .as_ref()
            .ok_or(ConfigError::MissingDatabaseUrl)
    }
}

/// Wczytuje konfigurację z wybranych źródeł (wzorzec Builder).
///
/// ```no_run
/// use dscan_config::ConfigLoader;
///
/// let config = ConfigLoader::new()
///     .optional_file("dscan.toml")
///     .load()?;
/// # Ok::<(), dscan_config::ConfigError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    file: Option<PathBuf>,
    file_required: bool,
    toml_text: Option<String>,
    use_env: bool,
    cli_overrides: CliOverrides,
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
            cli_overrides: CliOverrides::default(),
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

    /// Wartości z flag wiersza poleceń (najwyższy priorytet).
    pub fn cli_overrides(mut self, overrides: CliOverrides) -> Self {
        self.cli_overrides = overrides;
        self
    }

    /// Łączy źródła, waliduje wynik i odczytuje sekrety ze zmiennych środowiskowych.
    pub fn load(self) -> Result<AppConfig, ConfigError> {
        let settings: Settings = self.build_figment()?.extract()?;
        validate_settings(&settings)?;

        if !self.use_env {
            return Ok(AppConfig {
                settings,
                encryption_key: None,
                database_url: None,
                initial_admin: None,
                defectdojo_token: None,
            });
        }
        let key = std::env::var(ENCRYPTION_KEY_ENV).ok();
        let url = std::env::var(DATABASE_URL_ENV).ok();
        let admin_name = std::env::var(ADMIN_USERNAME_ENV).ok();
        let admin_password = std::env::var(ADMIN_PASSWORD_ENV).ok();
        Ok(AppConfig {
            settings,
            encryption_key: encryption_key_from_value(key.as_deref())?,
            database_url: database_url_from_value(url.as_deref()),
            initial_admin: InitialAdmin::from_values(
                admin_name.as_deref(),
                admin_password.as_deref(),
            ),
            defectdojo_token: crate::ApiToken::from_value(
                std::env::var(crate::DEFECTDOJO_TOKEN_ENV).ok().as_deref(),
            ),
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
                .filter(|key| is_settings_env_key(key.as_str()))
                .split(ENV_SECTION_SEPARATOR);
            figment = figment.merge(env);
        }
        Ok(self.cli_overrides.apply(figment))
    }
}

/// Zamienia wartość zmiennej środowiskowej na klucz; pusta wartość = brak klucza.
fn encryption_key_from_value(value: Option<&str>) -> Result<Option<EncryptionKey>, ConfigError> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(hex) => EncryptionKey::from_hex(hex).map(Some),
    }
}

/// Czy klucz zmiennej (bez prefiksu, np. `limits__nmap_max_rate`) należy do znanej sekcji.
fn is_settings_env_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SETTINGS_SECTIONS
        .iter()
        .any(|section| key.starts_with(&format!("{section}{ENV_SECTION_SEPARATOR}")))
}

/// Pusta wartość zmiennej oznacza brak adresu bazy.
fn database_url_from_value(value: Option<&str>) -> Option<DatabaseUrl> {
    match value.map(str::trim) {
        None | Some("") => None,
        Some(url) => Some(DatabaseUrl::new(url)),
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
    fn only_section_keys_are_read_from_env() {
        assert!(is_settings_env_key("limits__nmap_max_rate"));
        assert!(is_settings_env_key("SERVER__LISTEN"));
        assert!(!is_settings_env_key("encryption_key"));
        assert!(!is_settings_env_key("test_database_url"));
        assert!(!is_settings_env_key("limits"));
    }

    #[test]
    fn section_list_matches_settings_fields() {
        let table = toml::Table::try_from(Settings::default()).unwrap();
        let mut fields: Vec<&str> = table.keys().map(String::as_str).collect();
        let mut sections = SETTINGS_SECTIONS.to_vec();
        fields.sort_unstable();
        sections.sort_unstable();
        assert_eq!(fields, sections);
    }

    #[test]
    fn empty_database_url_means_none() {
        assert!(database_url_from_value(None).is_none());
        assert!(database_url_from_value(Some(" ")).is_none());
        assert!(database_url_from_value(Some("postgres://h/db")).is_some());
    }

    #[test]
    fn cli_overrides_beat_toml() {
        let overrides = CliOverrides {
            listen: Some("0.0.0.0:9000".parse().unwrap()),
            nmap_max_rate: Some(7),
            max_parallel_nmap: None,
        };

        let config = ConfigLoader::new()
            .without_env()
            .toml_str("[limits]\nnmap_max_rate = 25\nmax_parallel_nmap = 2")
            .cli_overrides(overrides)
            .load()
            .unwrap();

        assert_eq!(config.settings.limits.nmap_max_rate, 7);
        assert_eq!(config.settings.limits.max_parallel_nmap, 2);
        assert_eq!(config.settings.server.listen.port(), 9000);
    }

    #[test]
    fn cli_override_is_validated_too() {
        let overrides = CliOverrides {
            max_parallel_nmap: Some(0),
            ..CliOverrides::default()
        };

        let result = ConfigLoader::new()
            .without_env()
            .cli_overrides(overrides)
            .load();

        assert!(matches!(result, Err(ConfigError::ZeroLimit(_))));
    }

    #[test]
    fn require_database_url_fails_without_url() {
        let config = ConfigLoader::new().without_env().load().unwrap();
        assert!(matches!(
            config.require_database_url(),
            Err(ConfigError::MissingDatabaseUrl)
        ));
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
