//! Formatowanie wartości do wyświetlenia (wspólne dla CLI i interfejsu WWW).

use chrono::TimeDelta;

/// Czas w formacie `m:ss` albo `h:mm:ss` (wartości ujemne jako `0:00`).
pub fn format_duration(duration: TimeDelta) -> String {
    let total = duration.num_seconds().max(0);
    let (hours, minutes, seconds) = (total / 3600, total / 60 % 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_are_formatted() {
        assert_eq!(format_duration(TimeDelta::seconds(5)), "0:05");
        assert_eq!(format_duration(TimeDelta::seconds(125)), "2:05");
        assert_eq!(format_duration(TimeDelta::seconds(3725)), "1:02:05");
        assert_eq!(format_duration(TimeDelta::seconds(-3)), "0:00");
    }
}
