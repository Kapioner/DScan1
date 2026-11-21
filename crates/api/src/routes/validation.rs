//! Walidacja danych wejściowych API (cele, profile skanów).

use dscan_config::parse_clock_time;
use dscan_core::models::parse_port_range;
use dscan_db::{ProfileData, ProfileWindow};

use super::profiles::ProfileInput;
use crate::ApiError;

const MAX_GROUP_LEN: usize = 64;
const MAX_NOTE_LEN: usize = 2000;
const MAX_NAME_LEN: usize = 64;
const MIN_FREQUENCY_MINUTES: i32 = 5;
const MODES: [&str; 2] = ["discovery", "services"];

/// Nazwa grupy: przycięta, pusta = brak grupy, najwyżej 64 znaki.
pub fn clean_group(group: Option<String>) -> Result<Option<String>, ApiError> {
    clean_text(group, MAX_GROUP_LEN, "nazwa grupy")
}

/// Notatka: przycięta, pusta = brak notatki, najwyżej 2000 znaków.
pub fn clean_note(note: Option<String>) -> Result<Option<String>, ApiError> {
    clean_text(note, MAX_NOTE_LEN, "notatka")
}

fn clean_text(
    value: Option<String>,
    max_chars: usize,
    field: &str,
) -> Result<Option<String>, ApiError> {
    let Some(text) = value
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
    else {
        return Ok(None);
    };
    if text.chars().count() > max_chars {
        return Err(ApiError::BadRequest(format!(
            "{field} może mieć najwyżej {max_chars} znaków"
        )));
    }
    Ok(Some(text))
}

/// Sprawdza dane profilu i zamienia je na postać do zapisu.
pub fn validate_profile(input: ProfileInput) -> Result<ProfileData, ApiError> {
    let bad = |reason: String| ApiError::BadRequest(reason);
    let name = input.name.trim().to_string();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(bad(format!(
            "nazwa profilu musi mieć od 1 do {MAX_NAME_LEN} znaków"
        )));
    }
    if !MODES.contains(&input.mode.as_str()) {
        return Err(bad("tryb musi być 'discovery' albo 'services'".into()));
    }
    for port in &input.ports {
        parse_port_range(port).map_err(|error| bad(error.to_string()))?;
    }
    for window in &input.windows {
        parse_clock_time(&window.start).map_err(|error| bad(error.to_string()))?;
        parse_clock_time(&window.end).map_err(|error| bad(error.to_string()))?;
    }
    if input
        .frequency_minutes
        .is_some_and(|minutes| minutes < MIN_FREQUENCY_MINUTES)
    {
        return Err(bad(format!(
            "częstotliwość musi wynosić co najmniej {MIN_FREQUENCY_MINUTES} minut"
        )));
    }
    if input
        .max_rate
        .is_some_and(|rate| !(1..=100_000).contains(&rate))
    {
        return Err(bad(
            "limit tempa musi wynosić od 1 do 100000 pakietów/s".into()
        ));
    }
    Ok(ProfileData {
        name,
        mode: input.mode,
        target_group: clean_group(input.target_group)?,
        ports: input
            .ports
            .iter()
            .map(|port| port.trim().to_string())
            .collect(),
        windows: input
            .windows
            .into_iter()
            .map(|w| ProfileWindow {
                start: w.start,
                end: w.end,
            })
            .collect(),
        frequency_minutes: input.frequency_minutes,
        enabled: input.enabled,
        max_rate: input.max_rate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::profiles::WindowDto;

    #[test]
    fn group_is_trimmed_and_empty_means_none() {
        assert_eq!(
            clean_group(Some("  lab ".into())).unwrap().as_deref(),
            Some("lab")
        );
        assert_eq!(clean_group(Some("   ".into())).unwrap(), None);
        assert_eq!(clean_group(None).unwrap(), None);
    }

    #[test]
    fn too_long_values_are_rejected() {
        assert!(clean_group(Some("g".repeat(65))).is_err());
        assert!(clean_note(Some("n".repeat(2001))).is_err());
        assert!(clean_note(Some("n".repeat(2000))).is_ok());
    }

    fn input() -> ProfileInput {
        ProfileInput {
            name: " nocny ".into(),
            mode: "services".into(),
            target_group: Some("lab".into()),
            ports: vec!["22".into(), "8000-8100".into()],
            windows: vec![WindowDto {
                start: "22:00".into(),
                end: "06:00".into(),
            }],
            frequency_minutes: Some(60),
            enabled: true,
            max_rate: None,
        }
    }

    #[test]
    fn valid_profile_is_accepted_and_trimmed() {
        let data = validate_profile(input()).unwrap();
        assert_eq!(data.name, "nocny");
        assert_eq!(data.windows.len(), 1);
    }

    #[test]
    fn invalid_fields_are_rejected() {
        let cases: Vec<fn(&mut ProfileInput)> = vec![
            |p| p.name = "  ".into(),
            |p| p.mode = "full".into(),
            |p| p.ports = vec!["70000".into()],
            |p| {
                p.windows = vec![WindowDto {
                    start: "25:00".into(),
                    end: "06:00".into(),
                }]
            },
            |p| p.frequency_minutes = Some(1),
        ];
        for change in cases {
            let mut profile = input();
            change(&mut profile);
            assert!(matches!(
                validate_profile(profile),
                Err(ApiError::BadRequest(_))
            ));
        }
    }
}
