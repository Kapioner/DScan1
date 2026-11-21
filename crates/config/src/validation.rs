use dscan_core::models::parse_port_range;

use crate::{
    AppConfig, ConfigError, DATABASE_URL_ENV, ENCRYPTION_KEY_ENV, Settings, parse_clock_time,
};

/// Sprawdza poprawność wartości, których nie wyrazi sam system typów
/// (zakresy portów, godziny, niezerowe limity).
pub fn validate_settings(settings: &Settings) -> Result<(), ConfigError> {
    validate_ports(&settings.scope.allowed_ports)?;
    validate_windows(settings)?;
    validate_limits(settings)?;
    validate_subgroup_size(settings.limits.subgroup_size)?;
    validate_probe_paths(&settings.http.probe_paths)?;
    if settings.http.min_confidence > 100 {
        return Err(ConfigError::ZeroLimit("http.min_confidence (0–100)"));
    }
    Ok(())
}

/// Sondowane ścieżki: tylko zwykłe ścieżki na skanowanym hoście (bez `..`, parametrów, innych hostów).
fn validate_probe_paths(paths: &[String]) -> Result<(), ConfigError> {
    let safe = |path: &str| {
        path.starts_with('/')
            && !path.starts_with("//")
            && !path.contains("..")
            && !path.contains(['?', '#'])
    };
    match paths.iter().find(|path| !safe(path)) {
        Some(path) => Err(ConfigError::InvalidProbePath(path.clone())),
        None => Ok(()),
    }
}

/// Największa dozwolona podgrupa — /16 dla IPv4.
const MAX_SUBGROUP_SIZE: u32 = 65_536;

/// Podgrupa musi być potęgą dwójki, żeby dało się ją wyrazić jako sieć CIDR (np. 256 = /24).
fn validate_subgroup_size(size: u32) -> Result<(), ConfigError> {
    if size.is_power_of_two() && size <= MAX_SUBGROUP_SIZE {
        Ok(())
    } else {
        Err(ConfigError::InvalidSubgroupSize(size))
    }
}

fn validate_ports(ports: &[String]) -> Result<(), ConfigError> {
    for text in ports {
        parse_port_range(text)?;
    }
    Ok(())
}

fn validate_windows(settings: &Settings) -> Result<(), ConfigError> {
    for window in &settings.schedule.windows {
        parse_clock_time(&window.start)?;
        parse_clock_time(&window.end)?;
    }
    Ok(())
}

fn validate_limits(settings: &Settings) -> Result<(), ConfigError> {
    let limits = &settings.limits;
    // (nazwa ustawienia, czy wartość jest zerem)
    let checks = [
        ("limits.nmap_max_rate", limits.nmap_max_rate == 0),
        ("limits.max_parallel_nmap", limits.max_parallel_nmap == 0),
        (
            "limits.http_requests_per_second",
            limits.http_requests_per_second == 0,
        ),
        (
            "limits.http_requests_per_host",
            limits.http_requests_per_host == 0,
        ),
        (
            "scope.max_bandwidth_kbps",
            settings.scope.max_bandwidth_kbps == 0,
        ),
        (
            "stability.inactive_after_missed_runs",
            settings.stability.inactive_after_missed_runs == 0,
        ),
        ("server.max_body_bytes", settings.server.max_body_bytes == 0),
        ("server.session_hours", settings.server.session_hours == 0),
        ("http.timeout_seconds", settings.http.timeout_seconds == 0),
        ("http.max_body_bytes", settings.http.max_body_bytes == 0),
        (
            "limits.max_addresses_per_scan",
            limits.max_addresses_per_scan == 0,
        ),
        (
            "database.max_connections",
            settings.database.max_connections == 0,
        ),
        (
            "database.connect_timeout_seconds",
            settings.database.connect_timeout_seconds == 0,
        ),
    ];

    match checks.iter().find(|(_, is_zero)| *is_zero) {
        Some((name, _)) => Err(ConfigError::ZeroLimit(name)),
        None => Ok(()),
    }
}

/// Ostrzeżenia o ustawieniach poprawnych, ale prawdopodobnie niezamierzonych
/// (do `config validate`). Nie blokują uruchomienia.
pub fn collect_warnings(config: &AppConfig) -> Vec<String> {
    let mut warnings = Vec::new();

    if config.settings.scope.allowed_networks.is_empty() {
        warnings.push("scope.allowed_networks jest puste — żaden cel nie będzie dozwolony".into());
    }
    if config.encryption_key.is_none() {
        warnings.push(format!(
            "brak {ENCRYPTION_KEY_ENV} — dane wrażliwe nie będą mogły być zapisane"
        ));
    }
    if config.database_url.is_none() {
        warnings.push(format!(
            "brak {DATABASE_URL_ENV} — polecenia serve i db nie zadziałają"
        ));
    }
    if !config.settings.server.listen.ip().is_loopback() {
        warnings.push(format!(
            "server.listen = {} — API będzie dostępne z sieci, nie tylko lokalnie",
            config.settings.server.listen
        ));
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimeWindow;

    #[test]
    fn default_settings_are_valid() {
        assert!(validate_settings(&Settings::default()).is_ok());
    }

    #[test]
    fn invalid_port_is_rejected() {
        let mut settings = Settings::default();
        settings.scope.allowed_ports = vec!["80".into(), "99999".into()];

        let error = validate_settings(&settings).unwrap_err();
        assert!(matches!(error, ConfigError::InvalidPortRange(_)));
    }

    #[test]
    fn invalid_window_time_is_rejected() {
        let mut settings = Settings::default();
        settings.schedule.windows = vec![TimeWindow {
            start: "22:00".into(),
            end: "25:00".into(),
        }];

        let error = validate_settings(&settings).unwrap_err();
        assert!(matches!(error, ConfigError::InvalidTime(_)));
    }

    #[test]
    fn default_config_without_secrets_has_warnings() {
        let config = crate::ConfigLoader::new().without_env().load().unwrap();

        let warnings = collect_warnings(&config);

        assert_eq!(warnings.len(), 3);
        assert!(warnings.iter().any(|w| w.contains("allowed_networks")));
        assert!(warnings.iter().any(|w| w.contains("DSCAN_ENCRYPTION_KEY")));
        assert!(warnings.iter().any(|w| w.contains("DSCAN_DATABASE_URL")));
    }

    #[test]
    fn public_listen_address_gives_warning() {
        let mut config = crate::ConfigLoader::new().without_env().load().unwrap();
        config.settings.server.listen = "0.0.0.0:8080".parse().unwrap();

        let warnings = collect_warnings(&config);

        assert!(warnings.iter().any(|w| w.contains("0.0.0.0:8080")));
    }

    #[test]
    fn unsafe_probe_paths_are_rejected() {
        let mut settings = Settings::default();
        for path in ["admin", "/../etc", "/login?x=1", "//evil.example"] {
            settings.http.probe_paths = vec![path.to_string()];
            assert!(
                matches!(
                    validate_settings(&settings),
                    Err(ConfigError::InvalidProbePath(_))
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn subgroup_size_must_be_power_of_two() {
        let mut settings = Settings::default();
        for (size, valid) in [
            (1, true),
            (256, true),
            (65_536, true),
            (0, false),
            (100, false),
            (131_072, false),
        ] {
            settings.limits.subgroup_size = size;
            assert_eq!(
                validate_settings(&settings).is_ok(),
                valid,
                "rozmiar {size}"
            );
        }
    }

    #[test]
    fn zero_limit_is_rejected_with_field_name() {
        let mut settings = Settings::default();
        settings.limits.max_parallel_nmap = 0;

        let error = validate_settings(&settings).unwrap_err();
        assert!(matches!(
            error,
            ConfigError::ZeroLimit("limits.max_parallel_nmap")
        ));
    }
}
