//! Testy zmiennych środowiskowych. `figment::Jail` izoluje zmiany środowiska
//! i katalog roboczy na czas pojedynczego testu.
//!
//! Domknięcie `Jail::expect_with` musi zwracać `figment::Error` (API biblioteki),
//! stąd wyłączenie lintu o dużym typie błędu — tylko w tym pliku testowym.
#![allow(clippy::result_large_err)]

use dscan_config::{ConfigLoader, ENCRYPTION_KEY_ENV};
use figment::Jail;

const VALID_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn env_overrides_toml_file() {
    Jail::expect_with(|jail| {
        jail.create_file("dscan.toml", "[limits]\nnmap_max_rate = 25")?;
        jail.set_env("DSCAN_LIMITS__NMAP_MAX_RATE", "50");

        let config = ConfigLoader::new().file("dscan.toml").load().unwrap();

        assert_eq!(config.settings.limits.nmap_max_rate, 50);
        Ok(())
    });
}

#[test]
fn encryption_key_is_read_only_from_env() {
    Jail::expect_with(|jail| {
        jail.set_env(ENCRYPTION_KEY_ENV, VALID_KEY);

        let config = ConfigLoader::new().load().unwrap();

        let key = config.require_encryption_key().unwrap();
        assert_eq!(key.as_bytes()[31], 0x1f);
        Ok(())
    });
}

#[test]
fn invalid_encryption_key_in_env_is_an_error() {
    Jail::expect_with(|jail| {
        jail.set_env(ENCRYPTION_KEY_ENV, "za-krotki");

        assert!(ConfigLoader::new().load().is_err());
        Ok(())
    });
}

#[test]
fn unrelated_dscan_variables_are_ignored() {
    Jail::expect_with(|jail| {
        jail.set_env("DSCAN_TEST_DATABASE_URL", "postgres://x/y");
        jail.set_env("DSCAN_CONFIG", "inny.toml");

        assert!(ConfigLoader::new().load().is_ok());
        Ok(())
    });
}

#[test]
fn typo_in_env_field_name_is_an_error() {
    Jail::expect_with(|jail| {
        jail.set_env("DSCAN_LIMITS__NMAP_MAXRATE", "5");

        assert!(ConfigLoader::new().load().is_err());
        Ok(())
    });
}

#[test]
fn env_list_value_is_parsed() {
    Jail::expect_with(|jail| {
        jail.set_env("DSCAN_SCOPE__ALLOWED_PORTS", r#"["22","80-90"]"#);

        let config = ConfigLoader::new().load().unwrap();

        assert_eq!(config.settings.scope.allowed_ports, vec!["22", "80-90"]);
        Ok(())
    });
}
