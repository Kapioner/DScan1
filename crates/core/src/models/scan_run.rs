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

/// Jeden przebieg skanu (uruchomienie profilu na zbiorze celów).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: i64,
    pub profile: String,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub total_addresses: u64,
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
    fn calculate_progress_handles_edge_cases() {
        assert_eq!(calculate_progress_percent(0, 0), 0.0);
        assert_eq!(calculate_progress_percent(3, 3), 100.0);
        assert_eq!(calculate_progress_percent(5, 3), 100.0);
    }
}
