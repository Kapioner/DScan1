//! Okna czasowe skanowania (zadanie S8). Godziny `HH:MM` w czasie lokalnym serwera;
//! okno może przechodzić przez północ (np. 22:00–06:00), a `start == end` oznacza całą dobę.

use chrono::{DateTime, Duration, Local, NaiveTime, TimeZone, Utc};
use dscan_config::parse_clock_time;

/// Teraz nie ma żadnego otwartego okna.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutsideWindow;

/// Koniec okna, w którym jesteśmy: `Ok(None)` = bez ograniczeń (brak okien albo okno całodobowe),
/// `Ok(Some(t))` = skan trzeba zatrzymać o `t`, `Err` = teraz poza oknami.
/// Niepoprawne godziny są pomijane (walidacja odbywa się przy zapisie profilu).
pub fn window_stop(
    windows: &[(String, String)],
    now: DateTime<Local>,
) -> Result<Option<DateTime<Utc>>, OutsideWindow> {
    if windows.is_empty() {
        return Ok(None);
    }
    let parsed: Vec<(NaiveTime, NaiveTime)> = windows
        .iter()
        .filter_map(|(start, end)| {
            Some((parse_clock_time(start).ok()?, parse_clock_time(end).ok()?))
        })
        .collect();
    let mut stop: Option<DateTime<Local>> = None;
    for (start, end) in parsed {
        if start == end {
            return Ok(None);
        }
        if let Some(end_at) = current_window_end(start, end, now) {
            stop = Some(stop.map_or(end_at, |current: DateTime<Local>| current.max(end_at)));
        }
    }
    stop.map(|at| Some(at.with_timezone(&Utc)))
        .ok_or(OutsideWindow)
}

/// Czy chwila `now` należy do okna; jeśli tak — kiedy okno się kończy.
fn current_window_end(
    start: NaiveTime,
    end: NaiveTime,
    now: DateTime<Local>,
) -> Option<DateTime<Local>> {
    let time = now.time();
    let today = now.date_naive();
    let at = |date: chrono::NaiveDate, t: NaiveTime| {
        Local.from_local_datetime(&date.and_time(t)).earliest()
    };
    if start < end {
        return (time >= start && time < end)
            .then(|| at(today, end))
            .flatten();
    }
    // Okno przez północ, np. 22:00–06:00.
    if time >= start {
        return at(today + Duration::days(1), end);
    }
    (time < end).then(|| at(today, end)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(text: &str) -> DateTime<Local> {
        let naive = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M").unwrap();
        Local.from_local_datetime(&naive).unwrap()
    }

    fn windows(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    #[test]
    fn no_windows_means_no_limit() {
        assert_eq!(window_stop(&[], local("2026-11-21 12:00")), Ok(None));
        assert_eq!(
            window_stop(&windows(&[("00:00", "00:00")]), local("2026-11-21 12:00")),
            Ok(None)
        );
    }

    #[test]
    fn day_window() {
        let w = windows(&[("08:00", "16:00")]);
        assert_eq!(
            window_stop(&w, local("2026-11-21 10:00")),
            Ok(Some(local("2026-11-21 16:00").with_timezone(&Utc)))
        );
        assert_eq!(
            window_stop(&w, local("2026-11-21 16:00")),
            Err(OutsideWindow)
        );
        assert_eq!(
            window_stop(&w, local("2026-11-21 07:59")),
            Err(OutsideWindow)
        );
    }

    #[test]
    fn overnight_window() {
        let w = windows(&[("22:00", "06:00")]);
        assert_eq!(
            window_stop(&w, local("2026-11-21 23:00")),
            Ok(Some(local("2026-11-22 06:00").with_timezone(&Utc)))
        );
        assert_eq!(
            window_stop(&w, local("2026-11-22 05:30")),
            Ok(Some(local("2026-11-22 06:00").with_timezone(&Utc)))
        );
        assert_eq!(
            window_stop(&w, local("2026-11-21 12:00")),
            Err(OutsideWindow)
        );
    }

    #[test]
    fn several_windows() {
        let w = windows(&[("08:00", "09:00"), ("12:00", "13:00")]);
        assert_eq!(
            window_stop(&w, local("2026-11-21 12:30")),
            Ok(Some(local("2026-11-21 13:00").with_timezone(&Utc)))
        );
        assert_eq!(
            window_stop(&w, local("2026-11-21 10:00")),
            Err(OutsideWindow)
        );
    }
}
