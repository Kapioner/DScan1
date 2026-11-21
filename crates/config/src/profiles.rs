//! Nazwane profile skanów (zadanie C4): sekcje `[profiles.NAZWA]` w `dscan.toml`.
//!
//! Profil zawiera tylko to, co zmienia względem ustawień głównych — pozostałe wartości
//! są brane z `[scope]`, `[limits]`, `[schedule]` i `[http]`.

use serde::{Deserialize, Serialize};

use crate::{ConfigError, Settings, TimeWindow, validate_settings};

/// Ustawienia jednego profilu (wszystkie opcjonalne).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanProfileSettings {
    /// `discovery` albo `services` (domyślnie `services`).
    pub mode: Option<String>,
    /// Porty zamiast `scope.allowed_ports` (muszą się w nich mieścić).
    pub ports: Option<Vec<String>>,
    pub max_rate: Option<u32>,
    pub parallel: Option<u32>,
    pub subgroup_size: Option<u32>,
    /// `nmap --host-timeout` w sekundach.
    pub host_timeout_seconds: Option<u64>,
    /// `nmap --max-retries`.
    pub max_retries: Option<u32>,
    pub windows: Option<Vec<TimeWindow>>,
    pub probe_paths: Option<Vec<String>>,
}

/// Ustawienia z nałożonym profilem i jego tryb skanu.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedProfile {
    pub name: String,
    pub mode: String,
    pub settings: Settings,
    pub host_timeout_seconds: Option<u64>,
    pub max_retries: Option<u32>,
}

const MODES: [&str; 2] = ["discovery", "services"];

/// Nakłada profil `name` na ustawienia i sprawdza wynik.
pub fn resolve_profile(settings: &Settings, name: &str) -> Result<ResolvedProfile, ConfigError> {
    let profile = settings
        .profiles
        .get(name)
        .ok_or_else(|| ConfigError::UnknownProfile {
            name: name.to_string(),
            available: profile_names(settings),
        })?;
    let mode = profile
        .mode
        .clone()
        .unwrap_or_else(|| "services".to_string());
    if !MODES.contains(&mode.as_str()) {
        return Err(ConfigError::InvalidProfile {
            name: name.to_string(),
            reason: format!("tryb '{mode}' (dozwolone: discovery, services)"),
        });
    }
    let mut merged = settings.clone();
    if let Some(ports) = &profile.ports {
        merged.scope.allowed_ports = ports.clone();
    }
    if let Some(rate) = profile.max_rate {
        merged.limits.nmap_max_rate = rate;
    }
    if let Some(parallel) = profile.parallel {
        merged.limits.max_parallel_nmap = parallel;
    }
    if let Some(size) = profile.subgroup_size {
        merged.limits.subgroup_size = size;
    }
    if let Some(windows) = &profile.windows {
        merged.schedule.windows = windows.clone();
    }
    if let Some(paths) = &profile.probe_paths {
        merged.http.probe_paths = paths.clone();
    }
    validate_settings(&merged).map_err(|error| ConfigError::InvalidProfile {
        name: name.to_string(),
        reason: error.to_string(),
    })?;
    Ok(ResolvedProfile {
        name: name.to_string(),
        mode,
        settings: merged,
        host_timeout_seconds: profile.host_timeout_seconds,
        max_retries: profile.max_retries,
    })
}

/// Nazwy zdefiniowanych profili (alfabetycznie).
pub fn profile_names(settings: &Settings) -> Vec<String> {
    settings.profiles.keys().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_with(name: &str, profile: ScanProfileSettings) -> Settings {
        let mut settings = Settings::default();
        settings.profiles.insert(name.to_string(), profile);
        settings
    }

    #[test]
    fn profile_overrides_only_given_values() {
        let settings = settings_with(
            "szybki",
            ScanProfileSettings {
                mode: Some("discovery".into()),
                max_rate: Some(300),
                ..Default::default()
            },
        );

        let resolved = resolve_profile(&settings, "szybki").unwrap();

        assert_eq!(resolved.mode, "discovery");
        assert_eq!(resolved.settings.limits.nmap_max_rate, 300);
        assert_eq!(
            resolved.settings.limits.max_parallel_nmap,
            Settings::default().limits.max_parallel_nmap
        );
    }

    #[test]
    fn unknown_profile_lists_available_ones() {
        let settings = settings_with("pelny", ScanProfileSettings::default());
        let error = resolve_profile(&settings, "nie-ma").unwrap_err();
        assert!(error.to_string().contains("pelny"), "{error}");
    }

    #[test]
    fn invalid_profile_values_are_rejected() {
        let bad_mode = settings_with(
            "x",
            ScanProfileSettings {
                mode: Some("full".into()),
                ..Default::default()
            },
        );
        assert!(resolve_profile(&bad_mode, "x").is_err());
        let bad_size = settings_with(
            "x",
            ScanProfileSettings {
                subgroup_size: Some(100),
                ..Default::default()
            },
        );
        assert!(resolve_profile(&bad_size, "x").is_err());
        let bad_port = settings_with(
            "x",
            ScanProfileSettings {
                ports: Some(vec!["99999".into()]),
                ..Default::default()
            },
        );
        assert!(resolve_profile(&bad_port, "x").is_err());
    }
}
