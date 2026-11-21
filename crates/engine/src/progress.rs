//! Postęp przebiegu i jego obserwatorzy (wzorzec Observer): silnik informuje
//! o zdarzeniach, a obserwator decyduje, co z nimi zrobić (terminal, logi, testy).

use chrono::{DateTime, TimeDelta, Utc};
use dscan_core::models::estimate_remaining;

/// Stan przebiegu w trakcie skanowania.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    pub run_id: i64,
    pub started_at: DateTime<Utc>,
    pub total_subgroups: usize,
    pub finished_subgroups: usize,
    pub failed_subgroups: usize,
    pub total_addresses: u64,
    pub finished_addresses: u64,
}

impl ScanProgress {
    pub fn new(
        run_id: i64,
        started_at: DateTime<Utc>,
        total_subgroups: usize,
        total_addresses: u64,
    ) -> Self {
        ScanProgress {
            run_id,
            started_at,
            total_subgroups,
            finished_subgroups: 0,
            failed_subgroups: 0,
            total_addresses,
            finished_addresses: 0,
        }
    }

    /// Zalicza zakończoną (udaną lub nie) podgrupę.
    pub fn record(&mut self, addresses: u64, failed: bool) {
        self.finished_subgroups += 1;
        self.finished_addresses += addresses;
        if failed {
            self.failed_subgroups += 1;
        }
    }

    /// Postęp w procentach liczony po adresach.
    pub fn percent(&self) -> f64 {
        if self.total_addresses == 0 {
            return 0.0;
        }
        self.finished_addresses as f64 * 100.0 / self.total_addresses as f64
    }

    pub fn elapsed(&self, now: DateTime<Utc>) -> TimeDelta {
        now - self.started_at
    }

    /// Prognoza czasu do końca przy dotychczasowym tempie.
    pub fn estimated_remaining(&self, now: DateTime<Utc>) -> Option<TimeDelta> {
        estimate_remaining(
            self.elapsed(now),
            self.finished_addresses,
            self.total_addresses,
        )
    }
}

/// Wynik jednej podgrupy do wyświetlenia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubgroupReport {
    pub index: usize,
    pub addresses: u64,
    pub hosts: usize,
    pub open_ports: usize,
    pub duration: TimeDelta,
    /// `Some` z opisem błędu, gdy podgrupa się nie powiodła.
    pub error: Option<String>,
}

/// Obserwator postępu skanu. Metody mają domyślne (puste) implementacje,
/// więc obserwator implementuje tylko to, co go interesuje.
pub trait ScanObserver {
    fn scan_started(&self, _progress: &ScanProgress) {}
    fn subgroup_started(&self, _index: usize, _addresses: u64) {}
    fn subgroup_finished(&self, _report: &SubgroupReport, _progress: &ScanProgress) {}
}

/// Obserwator, który niczego nie robi.
pub struct SilentObserver;

impl ScanObserver for SilentObserver {}

/// Obserwator dla skanów w tle (serwer): postęp trafia do logów.
pub struct LogObserver;

impl ScanObserver for LogObserver {
    fn scan_started(&self, progress: &ScanProgress) {
        tracing::info!(
            "przebieg #{}: {} adresów w {} podgrupach (ukończone: {})",
            progress.run_id,
            progress.total_addresses,
            progress.total_subgroups,
            progress.finished_subgroups
        );
    }

    fn subgroup_finished(&self, report: &SubgroupReport, progress: &ScanProgress) {
        tracing::info!(
            "przebieg #{}: podgrupa {} — {} hostów, {:.0}%",
            progress.run_id,
            report.index + 1,
            report.hosts,
            progress.percent()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress() -> ScanProgress {
        ScanProgress::new(1, "2026-11-21T10:00:00Z".parse().unwrap(), 4, 1024)
    }

    #[test]
    fn recording_updates_counters() {
        let mut progress = progress();
        progress.record(256, false);
        progress.record(256, true);

        assert_eq!(progress.finished_subgroups, 2);
        assert_eq!(progress.failed_subgroups, 1);
        assert_eq!(progress.percent(), 50.0);
    }

    #[test]
    fn eta_follows_current_pace() {
        let mut progress = progress();
        progress.record(256, false);
        let now = progress.started_at + TimeDelta::seconds(20);

        assert_eq!(
            progress.estimated_remaining(now),
            Some(TimeDelta::seconds(60))
        );
    }

    #[test]
    fn no_eta_before_first_subgroup() {
        let progress = progress();
        assert_eq!(progress.estimated_remaining(Utc::now()), None);
        assert_eq!(progress.percent(), 0.0);
    }
}
