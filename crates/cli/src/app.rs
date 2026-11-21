use std::fmt::Write;
use std::path::Path;

use dscan_config::{AppConfig, ConfigError, ConfigLoader};

/// Plik wczytywany automatycznie, jeśli użytkownik nie poda innego.
pub const DEFAULT_CONFIG_FILE: &str = "dscan.toml";

/// Uruchamia aplikację: `dscan [PLIK_KONFIGURACJI]`.
/// Zwraca tekst do wypisania na standardowe wyjście.
///
/// Tymczasowo wypisuje efektywną konfigurację; podkomendy (clap) dojdą w zadaniu C2.
pub fn run(args: &[String]) -> Result<String, ConfigError> {
    let config_path = args.first().map(String::as_str);
    let config = build_loader(config_path).load()?;
    Ok(format_report(
        &config,
        config_path.unwrap_or(DEFAULT_CONFIG_FILE),
    ))
}

/// Jawnie podany plik musi istnieć; domyślny może nie istnieć.
fn build_loader(config_path: Option<&str>) -> ConfigLoader {
    match config_path {
        Some(path) => ConfigLoader::new().file(Path::new(path)),
        None => ConfigLoader::new().optional_file(DEFAULT_CONFIG_FILE),
    }
}

/// Raport z efektywną konfiguracją. Klucz szyfrowania nigdy nie jest wypisywany.
pub fn format_report(config: &AppConfig, source: &str) -> String {
    let key_status = match config.encryption_key {
        Some(_) => "ustawiony (wartość ukryta)",
        None => "brak",
    };

    let mut report = String::new();
    // Zapis do String nie może się nie udać, więc wynik write! jest pomijany.
    let _ = writeln!(report, "DScan v{}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(report, "Plik konfiguracji: {source}");
    let _ = writeln!(report, "Klucz szyfrowania: {key_status}");
    let _ = writeln!(report, "Efektywna konfiguracja:\n{:#?}", config.settings);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_config::EncryptionKey;

    const VALID_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn report_hides_encryption_key() {
        let mut config = ConfigLoader::new().without_env().load().unwrap();
        config.encryption_key = Some(EncryptionKey::from_hex(VALID_KEY).unwrap());

        let report = format_report(&config, "test.toml");

        assert!(report.contains("ustawiony (wartość ukryta)"));
        assert!(!report.contains(VALID_KEY));
        assert!(!report.contains("0a0b0c"));
    }

    #[test]
    fn report_shows_source_and_settings() {
        let config = ConfigLoader::new().without_env().load().unwrap();

        let report = format_report(&config, "test.toml");

        assert!(report.contains("Plik konfiguracji: test.toml"));
        assert!(report.contains("nmap_max_rate: 100"));
        assert!(report.contains("Klucz szyfrowania: brak"));
    }

    #[test]
    fn missing_explicit_file_is_an_error() {
        let args = vec!["/nie/ma/takiego/pliku.toml".to_string()];
        assert!(matches!(run(&args), Err(ConfigError::FileNotFound(_))));
    }
}
