use sztygar_core::models::parse_port_range;

use crate::{ConfigError, Settings, parse_clock_time};

/// Sprawdza poprawność wartości, których nie wyrazi sam system typów
/// (zakresy portów, godziny, niezerowe limity).
pub fn validate_settings(settings: &Settings) -> Result<(), ConfigError> {
    validate_ports(&settings.scope.allowed_ports)?;
    validate_windows(settings)?;
    validate_limits(settings)?;
    Ok(())
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
    let checks = [
        ("limits.nmap_max_rate", limits.nmap_max_rate),
        ("limits.max_parallel_nmap", limits.max_parallel_nmap),
        (
            "limits.http_requests_per_second",
            limits.http_requests_per_second,
        ),
        (
            "limits.http_requests_per_host",
            limits.http_requests_per_host,
        ),
        (
            "scope.max_bandwidth_kbps",
            settings.scope.max_bandwidth_kbps,
        ),
        (
            "stability.inactive_after_missed_runs",
            settings.stability.inactive_after_missed_runs,
        ),
    ];

    match checks.iter().find(|(_, value)| *value == 0) {
        Some((name, _)) => Err(ConfigError::ZeroLimit(name)),
        None => Ok(()),
    }
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
