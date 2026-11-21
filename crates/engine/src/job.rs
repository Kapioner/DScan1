use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use dscan_core::models::{Host, ScanStatus};
use dscan_crypto::Cipher;
use dscan_db::{PgPool, SubgroupCompletion};
use dscan_scanner::pool::{PoolEvent, SubgroupResult, SubgroupScanner, run_pool};
use dscan_scanner::subgroups::split_into_subgroups;
use dscan_scanner::targets::count_addresses;
use ipnet::IpNet;

use crate::comparison::{Comparison, compare_with_previous};
use crate::{EngineError, ScanObserver, ScanProgress, SubgroupReport};

/// Ustawienia przebiegu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanJobSettings {
    /// Nazwa profilu zapisywana w przebiegu (np. `services`).
    pub profile: String,
    pub subgroup_size: u32,
    pub parallel: u32,
    pub max_addresses: u64,
}

/// Podsumowanie zakończonego przebiegu.
#[derive(Debug, Clone)]
pub struct ScanJobSummary {
    pub run_id: i64,
    /// Zmiany względem poprzedniego udanego przebiegu tego profilu (M1):
    /// `None`, gdy nie było z czym porównać albo przebieg się nie udał.
    pub comparison: Option<Comparison>,
    pub status: ScanStatus,
    pub duration: TimeDelta,
    pub subgroups: usize,
    pub failed_subgroups: usize,
    pub hosts: Vec<Host>,
}

/// Wykonuje przebieg skanu: dzieli sieci na podgrupy, skanuje je równolegle,
/// zapisuje wynik każdej podgrupy od razu po jej zakończeniu i powiadamia obserwatora.
/// Błąd zapisu w bazie przerywa przebieg i oznacza go jako nieudany.
pub async fn run_scan_job<S: SubgroupScanner>(
    pool: &PgPool,
    cipher: &Cipher,
    networks: &[IpNet],
    scanner: Arc<S>,
    settings: &ScanJobSettings,
    observer: &impl ScanObserver,
) -> Result<ScanJobSummary, EngineError> {
    let total = count_addresses(networks);
    if total == 0 {
        return Err(EngineError::NoTargets);
    }
    if total > u128::from(settings.max_addresses) {
        return Err(EngineError::TooManyAddresses {
            count: total,
            limit: settings.max_addresses,
        });
    }

    let subgroups = split_into_subgroups(networks, settings.subgroup_size);
    let texts: Vec<Vec<String>> = subgroups
        .iter()
        .map(|group| group.iter().map(ToString::to_string).collect())
        .collect();
    let created = dscan_db::create_scan_run(pool, &settings.profile, total as u64, &texts).await?;

    let mut job = RunningJob {
        pool,
        cipher,
        subgroup_ids: created.subgroup_ids,
        sizes: subgroups
            .iter()
            .map(|group| count_addresses(group) as u64)
            .collect(),
        progress: ScanProgress::new(created.run_id, Utc::now(), subgroups.len(), total as u64),
        hosts: Vec::new(),
    };
    observer.scan_started(&job.progress);

    let events = run_pool(scanner, subgroups, settings.parallel as usize);
    if let Err(error) = job.consume(events, observer).await {
        // Najlepsza próba oznaczenia przebiegu — pierwotny błąd jest ważniejszy.
        let _ = dscan_db::finish_scan_run(pool, created.run_id, ScanStatus::Failed).await;
        return Err(error);
    }
    job.finish(&settings.profile).await
}

/// Stan przebiegu w trakcie odbierania wyników z puli.
struct RunningJob<'a> {
    pool: &'a PgPool,
    cipher: &'a Cipher,
    subgroup_ids: Vec<i64>,
    sizes: Vec<u64>,
    progress: ScanProgress,
    hosts: Vec<Host>,
}

impl RunningJob<'_> {
    async fn consume(
        &mut self,
        mut events: tokio::sync::mpsc::Receiver<PoolEvent>,
        observer: &impl ScanObserver,
    ) -> Result<(), EngineError> {
        while let Some(event) = events.recv().await {
            match event {
                PoolEvent::Started { index, at } => {
                    dscan_db::mark_subgroup_running(self.pool, self.subgroup_ids[index], at)
                        .await?;
                    observer.subgroup_started(index, self.sizes[index]);
                }
                PoolEvent::Finished(result) => {
                    let report = self.save(result).await?;
                    self.progress
                        .record(report.addresses, report.error.is_some());
                    observer.subgroup_finished(&report, &self.progress);
                }
            }
        }
        Ok(())
    }

    /// Zapisuje wynik podgrupy w bazie i przygotowuje raport.
    async fn save(&mut self, result: SubgroupResult) -> Result<SubgroupReport, EngineError> {
        let (run_id, subgroup_id) = (self.progress.run_id, self.subgroup_ids[result.index]);
        let addresses = self.sizes[result.index];
        let mut report = SubgroupReport {
            index: result.index,
            addresses,
            hosts: 0,
            open_ports: 0,
            duration: result.finished_at - result.started_at,
            error: None,
        };
        match result.outcome {
            Ok(output) => {
                let completion = SubgroupCompletion {
                    run_id,
                    subgroup_id,
                    addresses,
                    started_at: result.started_at,
                    finished_at: result.finished_at,
                    hosts: &output.hosts,
                    raw_xml: &output.raw_xml,
                };
                dscan_db::complete_subgroup(self.pool, self.cipher, completion).await?;
                report.hosts = output.hosts.len();
                report.open_ports = output.hosts.iter().map(Host::open_port_count).sum();
                self.hosts.extend(output.hosts);
            }
            Err(error) => {
                let times = (result.started_at, result.finished_at);
                let message = error.to_string();
                dscan_db::fail_subgroup(self.pool, run_id, subgroup_id, addresses, times, &message)
                    .await?;
                report.error = Some(message);
            }
        }
        Ok(report)
    }

    async fn finish(self, profile: &str) -> Result<ScanJobSummary, EngineError> {
        let status = if self.progress.failed_subgroups == 0 {
            ScanStatus::Completed
        } else {
            ScanStatus::Failed
        };
        dscan_db::finish_scan_run(self.pool, self.progress.run_id, status).await?;
        // Niepełny (nieudany) przebieg dałby fałszywe „zniknięcia”, więc go nie porównujemy.
        let comparison = if status == ScanStatus::Completed {
            compare_with_previous(self.pool, self.progress.run_id, profile).await?
        } else {
            None
        };
        Ok(ScanJobSummary {
            run_id: self.progress.run_id,
            comparison,
            status,
            duration: self.progress.elapsed(Utc::now()),
            subgroups: self.progress.total_subgroups,
            failed_subgroups: self.progress.failed_subgroups,
            hosts: self.hosts,
        })
    }
}
