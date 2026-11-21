use std::fmt::Write;

use crate::{AppConfig, ConfigError, DATABASE_URL_ENV, ENCRYPTION_KEY_ENV};

/// Efektywna konfiguracja w formacie TOML (do `config show`).
/// Sekrety są dopisane na końcu jako komentarze, bez ujawniania wartości.
pub fn render_effective_config(config: &AppConfig) -> Result<String, ConfigError> {
    let mut text = toml::to_string_pretty(&config.settings)
        .map_err(|error| ConfigError::Render(error.to_string()))?;

    let key_status = match config.encryption_key {
        Some(_) => "ustawiony (wartość ukryta)".to_string(),
        None => "brak".to_string(),
    };
    let database_status = match &config.database_url {
        Some(url) => url.masked(),
        None => "brak".to_string(),
    };

    // Zapis do String nie może się nie udać, więc wynik write! jest pomijany.
    let _ = writeln!(text, "\n# Sekrety (tylko ze zmiennych środowiskowych):");
    let _ = writeln!(text, "# {ENCRYPTION_KEY_ENV} = {key_status}");
    let _ = writeln!(text, "# {DATABASE_URL_ENV} = {database_status}");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigLoader, DatabaseUrl, EncryptionKey};

    const VALID_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn rendered_config_is_valid_toml_with_settings() {
        let config = ConfigLoader::new().without_env().load().unwrap();

        let text = render_effective_config(&config).unwrap();

        assert!(text.contains("[limits]"));
        assert!(text.contains("nmap_max_rate = 100"));
        assert!(text.contains(r#"listen = "127.0.0.1:8080""#));
        // Wynik da się wczytać z powrotem jako konfigurację.
        assert!(
            ConfigLoader::new()
                .without_env()
                .toml_str(&text)
                .load()
                .is_ok()
        );
    }

    #[test]
    fn rendered_config_hides_secrets() {
        let mut config = ConfigLoader::new().without_env().load().unwrap();
        config.encryption_key = Some(EncryptionKey::from_hex(VALID_KEY).unwrap());
        config.database_url = Some(DatabaseUrl::new("postgres://dscan:tajne@host/db"));

        let text = render_effective_config(&config).unwrap();

        assert!(!text.contains(VALID_KEY));
        assert!(!text.contains("tajne"));
        assert!(text.contains("DSCAN_ENCRYPTION_KEY = ustawiony (wartość ukryta)"));
        assert!(text.contains("postgres://dscan:***@host/db"));
    }
}
