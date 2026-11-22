//! Konfiguracja aplikacji DScan.
//!
//! Źródła (każde kolejne nadpisuje poprzednie):
//! 1. wartości domyślne ([`Settings::default`]),
//! 2. plik TOML (np. `dscan.toml`),
//! 3. zmienne środowiskowe `DSCAN_<SEKCJA>__<POLE>`, np. `DSCAN_LIMITS__NMAP_MAX_RATE=50`,
//! 4. flagi wiersza poleceń ([`CliOverrides`]).
//!
//! Sekrety — klucz szyfrowania ([`ENCRYPTION_KEY_ENV`]) i adres bazy
//! ([`DATABASE_URL_ENV`]) — są odczytywane **wyłącznie** ze zmiennych środowiskowych.

mod error;
mod loader;
mod overrides;
mod profiles;
mod schedule;
mod secret;
mod settings;
mod show;
mod validation;

pub use error::ConfigError;
pub use loader::{AppConfig, ConfigLoader, ENV_PREFIX};
pub use overrides::CliOverrides;
pub use profiles::{ResolvedProfile, ScanProfileSettings, profile_names, resolve_profile};
pub use schedule::{parse_clock_time, window_length_minutes};
pub use secret::{
    ADMIN_PASSWORD_ENV, ADMIN_USERNAME_ENV, ApiToken, DATABASE_URL_ENV, DEFECTDOJO_TOKEN_ENV,
    DatabaseUrl, ENCRYPTION_KEY_ENV, ENCRYPTION_KEY_LEN, EncryptionKey, InitialAdmin,
    NEW_ENCRYPTION_KEY_ENV, decode_hex_key, mask_url_password,
};
pub use settings::{
    DatabaseSettings, DefectDojoSettings, HttpSettings, RateLimitSettings, ScheduleSettings,
    ScopeSettings, ServerSettings, Settings, StabilitySettings, TimeWindow,
};
pub use show::render_effective_config;
pub use validation::{collect_warnings, validate_settings};
