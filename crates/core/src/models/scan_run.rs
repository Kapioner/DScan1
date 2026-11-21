use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

/// Etap życia przebiegu skanu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Pending,
    Running,
    /// Przerwany po końcu okna czasowego; zostanie wznowiony w kolejnym oknie.
    Paused,
    Completed,
    Failed,
}

impl ScanStatus {
    /// Nazwa zapisywana w bazie (kolumna `scan_runs.status`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStatus::Pending => "pending",
            ScanStatus::Running => "running",
            ScanStatus::Paused => "paused",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
        }
    }

    /// Odczyt nazwy z bazy; nieznana wartość daje `None`.
    pub fn parse(text: &str) -> Option<ScanStatus> {
        [
            ScanStatus::Pending,
            ScanStatus::Running,
            ScanStatus::Paused,
            ScanStatus::Completed,
            ScanStatus::Failed,
        ]
        .into_iter()
        .find(|status| status.as_str() == text)
    }
}

/// Jeden przebieg skanu (uruchomienie profilu na zbiorze celów).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: i64,
    pub profile: String,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub total_addresses: u64,
    pub completed_addresses: u64,
    pub total_subgroups: u32,
    pub completed_subgroups: u32,
}

impl ScanRun {
    /// Czas trwania zakończonego przebiegu (`None`, jeśli jeszcze trwa).
    pub fn duration(&self) -> Option<TimeDelta> {
        self.finished_at
            .map(|finished_at| finished_at - self.started_at)
    }

    /// Postęp w procentach na podstawie ukończonych podgrup.
    pub fn progress_percent(&self) -> f64 {
        calculate_progress_percent(self.completed_subgroups, self.total_subgroups)
    }

    /// Czas od startu do zakończenia albo — dla trwającego przebiegu — do chwili `now`.
    pub fn elapsed(&self, now: DateTime<Utc>) -> TimeDelta {
        self.finished_at.unwrap_or(now) - self.started_at
    }

    /// Prognoza czasu do końca trwającego przebiegu (`None` dla zakończonego
    /// albo gdy nie ukończono jeszcze żadnego adresu).
    pub fn estimated_remaining(&self, now: DateTime<Utc>) -> Option<TimeDelta> {
        if self.finished_at.is_some() {
            return None;
        }
        estimate_remaining(
            self.elapsed(now),
            self.completed_addresses,
            self.total_addresses,
        )
    }
}

/// Prognoza pozostałego czasu przy założeniu stałego tempa:
/// `pozostało = upłynęło × (wszystkie − ukończone) / ukończone`.
pub fn estimate_remaining(elapsed: TimeDelta, done: u64, total: u64) -> Option<TimeDelta> {
    if done == 0 || total == 0 {
        return None;
    }
    let remaining = total.saturating_sub(done);
    let millis = elapsed.num_milliseconds().max(0) as f64;
    let estimate = millis * remaining as f64 / done as f64;
    Some(TimeDelta::milliseconds(estimate.round() as i64))
}

/// Procent ukończenia `done` z `total`; dla `total == 0` zwraca 0.
pub fn calculate_progress_percent(done: u32, total: u32) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let ratio = f64::from(done.min(total)) / f64::from(total);
    ratio * 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_run() -> ScanRun {
        ScanRun {
            id: 1,
            profile: "default".to_string(),
            status: ScanStatus::Running,
            started_at: "2026-11-21T10:00:00Z".parse().unwrap(),
            finished_at: None,
            total_addresses: 1024,
            completed_addresses: 256,
            total_subgroups: 4,
            completed_subgroups: 1,
        }
    }

    #[test]
    fn duration_is_none_while_running() {
        assert_eq!(sample_run().duration(), None);
    }

    #[test]
    fn duration_is_difference_between_finish_and_start() {
        let mut run = sample_run();
        run.finished_at = Some("2026-11-21T10:15:30Z".parse().unwrap());

        assert_eq!(run.duration(), Some(TimeDelta::seconds(15 * 60 + 30)));
    }

    #[test]
    fn progress_percent_uses_subgroups() {
        assert_eq!(sample_run().progress_percent(), 25.0);
    }

    #[test]
    fn status_names_round_trip() {
        for status in [
            ScanStatus::Pending,
            ScanStatus::Running,
            ScanStatus::Paused,
            ScanStatus::Completed,
            ScanStatus::Failed,
        ] {
            assert_eq!(ScanStatus::parse(status.as_str()), Some(status));
        }
        assert_eq!(ScanStatus::parse("nieznany"), None);
    }

    #[test]
    fn estimate_scales_elapsed_time_by_remaining_work() {
        // 1/4 pracy w 60 s → zostały 3/4 → 180 s.
        assert_eq!(
            estimate_remaining(TimeDelta::seconds(60), 256, 1024),
            Some(TimeDelta::seconds(180))
        );
        assert_eq!(
            estimate_remaining(TimeDelta::seconds(60), 1024, 1024),
            Some(TimeDelta::zero())
        );
    }

    #[test]
    fn estimate_needs_some_progress() {
        assert_eq!(estimate_remaining(TimeDelta::seconds(60), 0, 1024), None);
        assert_eq!(estimate_remaining(TimeDelta::seconds(60), 0, 0), None);
    }

    #[test]
    fn running_scan_has_elapsed_and_eta() {
        let run = sample_run();
        let now = run.started_at + TimeDelta::seconds(30);

        assert_eq!(run.elapsed(now), TimeDelta::seconds(30));
        assert_eq!(run.estimated_remaining(now), Some(TimeDelta::seconds(90)));
    }

    #[test]
    fn finished_scan_has_no_eta() {
        let mut run = sample_run();
        run.finished_at = Some(run.started_at + TimeDelta::seconds(10));
        assert_eq!(run.estimated_remaining(Utc::now()), None);
        assert_eq!(run.elapsed(Utc::now()), TimeDelta::seconds(10));
    }

    #[test]
    fn calculate_progress_handles_edge_cases() {
        assert_eq!(calculate_progress_percent(0, 0), 0.0);
        assert_eq!(calculate_progress_percent(3, 3), 100.0);
        assert_eq!(calculate_progress_percent(5, 3), 100.0);
    }
}
