//! Konfiguracja aplikacji Sztygar.
//!
//! Źródła (każde kolejne nadpisuje poprzednie):
//! 1. wartości domyślne ([`Settings::default`]),
//! 2. plik TOML (np. `sztygar.toml`),
//! 3. zmienne środowiskowe `SZTYGAR_<SEKCJA>__<POLE>`, np. `SZTYGAR_LIMITS__NMAP_MAX_RATE=50`.
//!
//! Klucz szyfrowania jest odczytywany **wyłącznie** ze zmiennej
//! [`ENCRYPTION_KEY_ENV`] — nie da się go wpisać do pliku TOML.

mod error;
mod loader;
mod schedule;
mod secret;
mod settings;
mod validation;

pub use error::ConfigError;
pub use loader::{AppConfig, ConfigLoader, ENV_PREFIX};
pub use schedule::{parse_clock_time, window_length_minutes};
pub use secret::{ENCRYPTION_KEY_ENV, ENCRYPTION_KEY_LEN, EncryptionKey, decode_hex_key};
pub use settings::{
    RateLimitSettings, ScheduleSettings, ScopeSettings, Settings, StabilitySettings, TimeWindow,
};
pub use validation::validate_settings;
