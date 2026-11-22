//! Wzorce zależne od pory dnia (M2) i klasyfikacja stabilności hosta (M5) z historii
//! odpowiedzi w kolejnych przebiegach.

use chrono::{DateTime, Local, Timelike, Utc};

/// Odpowiedzi w jednej godzinie doby (czas lokalny serwera).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HourStat {
    pub responded: u32,
    pub total: u32,
}

impl HourStat {
    /// Odsetek odpowiedzi; `None` bez pomiarów.
    pub fn rate(&self) -> Option<f64> {
        (self.total > 0).then(|| f64::from(self.responded) / f64::from(self.total))
    }
}

/// Profil dostępności w 24 przedziałach godzinowych.
pub fn hourly_profile(history: &[(DateTime<Utc>, bool)]) -> [HourStat; 24] {
    let mut hours = [HourStat::default(); 24];
    for (at, responded) in history {
        let hour = at.with_timezone(&Local).hour() as usize;
        hours[hour].total += 1;
        hours[hour].responded += u32::from(*responded);
    }
    hours
}

/// Klasa stabilności hosta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stability {
    /// Za mało pomiarów do oceny.
    Insufficient,
    /// Odpowiada (prawie) zawsze.
    Stable,
    /// Prawie nigdy nie odpowiada.
    Silent,
    /// Odpowiada tylko w części doby — lista godzin z odpowiedziami.
    TimeDependent { active_hours: Vec<u32> },
    /// Odpowiada nieregularnie, bez wzorca godzinowego.
    Unstable,
}

impl Stability {
    pub fn label(&self) -> String {
        match self {
            Stability::Insufficient => "za mało pomiarów".into(),
            Stability::Stable => "stabilny".into(),
            Stability::Silent => "nie odpowiada".into(),
            Stability::TimeDependent { active_hours } => {
                format!(
                    "zależny od pory dnia (aktywny: {})",
                    format_hours(active_hours)
                )
            }
            Stability::Unstable => "niestabilny".into(),
        }
    }
}

/// Godziny jako zakresy, np. `8–17, 22`.
pub fn format_hours(hours: &[u32]) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < hours.len() {
        let start = hours[i];
        let mut end = start;
        while i + 1 < hours.len() && hours[i + 1] == end + 1 {
            i += 1;
            end = hours[i];
        }
        parts.push(if start == end {
            format!("{start}")
        } else {
            format!("{start}–{end}")
        });
        i += 1;
    }
    parts.join(", ")
}

/// Najmniej pomiarów do oceny.
pub const MIN_SAMPLES: u32 = 4;
/// Odsetek odpowiedzi uznawany za „zawsze” / „nigdy”.
const HIGH: f64 = 0.85;
const LOW: f64 = 0.15;

/// Klasyfikacja: stabilny / nie odpowiada / zależny od pory dnia / niestabilny.
pub fn classify_stability(history: &[(DateTime<Utc>, bool)]) -> Stability {
    let total = history.len() as u32;
    if total < MIN_SAMPLES {
        return Stability::Insufficient;
    }
    let responded = history.iter().filter(|(_, ok)| *ok).count() as f64;
    let rate = responded / f64::from(total);
    if rate >= HIGH {
        return Stability::Stable;
    }
    if rate <= LOW {
        return Stability::Silent;
    }
    let hours = hourly_profile(history);
    let measured: Vec<(u32, f64)> = hours
        .iter()
        .enumerate()
        .filter_map(|(h, s)| s.rate().map(|r| (h as u32, r)))
        .collect();
    let active: Vec<u32> = measured
        .iter()
        .filter(|(_, r)| *r >= HIGH)
        .map(|(h, _)| *h)
        .collect();
    let quiet = measured.iter().filter(|(_, r)| *r <= LOW).count();
    // Wzorzec godzinowy: każda zmierzona godzina jest wyraźnie „aktywna” albo „cicha”.
    if !active.is_empty() && quiet > 0 && active.len() + quiet == measured.len() {
        return Stability::TimeDependent {
            active_hours: active,
        };
    }
    Stability::Unstable
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32, hour: u32) -> DateTime<Utc> {
        Local
            .with_ymd_and_hms(2026, 11, day, hour, 0, 0)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn classes() {
        let stable: Vec<_> = (1..=6).map(|d| (at(d, 10), true)).collect();
        assert_eq!(classify_stability(&stable), Stability::Stable);
        assert_eq!(classify_stability(&stable[..2]), Stability::Insufficient);
        let silent: Vec<_> = (1..=6).map(|d| (at(d, 10), false)).collect();
        assert_eq!(classify_stability(&silent), Stability::Silent);

        // W dzień odpowiada, w nocy nie.
        let mut daily = Vec::new();
        for d in 1..=4 {
            daily.push((at(d, 10), true));
            daily.push((at(d, 2), false));
        }
        assert_eq!(
            classify_stability(&daily),
            Stability::TimeDependent {
                active_hours: vec![10]
            }
        );

        // Te same godziny, raz tak, raz nie.
        let flaky: Vec<_> = (1..=6).map(|d| (at(d, 10), d % 2 == 0)).collect();
        assert_eq!(classify_stability(&flaky), Stability::Unstable);
    }

    #[test]
    fn hours_are_grouped() {
        assert_eq!(format_hours(&[8, 9, 10, 17, 22, 23]), "8–10, 17, 22–23");
        let profile = hourly_profile(&[(at(1, 10), true), (at(2, 10), false)]);
        assert_eq!(
            profile[10],
            HourStat {
                responded: 1,
                total: 2
            }
        );
        assert_eq!(profile[10].rate(), Some(0.5));
    }
}
