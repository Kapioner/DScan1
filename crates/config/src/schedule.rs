use chrono::NaiveTime;

use crate::ConfigError;

const MINUTES_PER_DAY: i64 = 24 * 60;

/// Parsuje godzinę w formacie `HH:MM`.
pub fn parse_clock_time(text: &str) -> Result<NaiveTime, ConfigError> {
    NaiveTime::parse_from_str(text.trim(), "%H:%M")
        .map_err(|_| ConfigError::InvalidTime(text.to_string()))
}

/// Długość okna w minutach. Gdy `end` jest wcześniej niż `start`,
/// okno przechodzi przez północ. Równe godziny oznaczają całą dobę.
pub fn window_length_minutes(start: NaiveTime, end: NaiveTime) -> i64 {
    let difference = (end - start).num_minutes();
    if difference > 0 {
        difference
    } else {
        difference + MINUTES_PER_DAY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(text: &str) -> NaiveTime {
        parse_clock_time(text).unwrap()
    }

    #[test]
    fn parses_valid_times() {
        assert_eq!(time("22:00"), NaiveTime::from_hms_opt(22, 0, 0).unwrap());
        assert_eq!(time(" 06:30 "), NaiveTime::from_hms_opt(6, 30, 0).unwrap());
    }

    #[test]
    fn rejects_invalid_times() {
        for text in ["", "24:00", "7", "12:60", "abc"] {
            assert!(parse_clock_time(text).is_err(), "powinno odrzucić: {text}");
        }
    }

    #[test]
    fn window_within_one_day() {
        assert_eq!(window_length_minutes(time("08:00"), time("16:30")), 510);
    }

    #[test]
    fn window_across_midnight() {
        assert_eq!(window_length_minutes(time("22:00"), time("06:00")), 480);
    }

    #[test]
    fn equal_start_and_end_means_whole_day() {
        assert_eq!(window_length_minutes(time("00:00"), time("00:00")), 1440);
    }
}
