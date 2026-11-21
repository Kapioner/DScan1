//! Odbieranie wyników z puli i zakończenie przebiegu: zapis podgrup, wstrzymanie (S9),
//! obecność hostów (S11) i porównanie z poprzednim przebiegiem (M1).

use chrono::Utc;
use dscan_core::models::{Host, ScanStatus};
use dscan_crypto::Cipher;
use dscan_db::{PgPool, SubgroupCompletion};
use dscan_scanner::pool::{PoolEvent, SubgroupResult};
use ipnet::IpNet;

use crate::comparison::{Comparison, compare_with_previous};
use crate::{
    EngineError, ScanJobSettings, ScanJobSummary, ScanObserver, ScanProgress, SubgroupReport,
};

/// Wspólne zakończenie udanego przebiegu (skan i import I2): obecność hostów (S11)
/// i porównanie z poprzednim przebiegiem profilu (M1).
pub(crate) async fn finalize_run(
    pool: &PgPool,
    run_id: i64,
    settings: &ScanJobSettings,
    unstable: &[std::net::IpAddr],
) -> Result<(Option<Comparison>, dscan_db::PresenceUpdate), EngineError> {
    let networks: Vec<IpNet> = dscan_db::run_networks(pool, run_id)
        .await?
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    // Odpowiedzi z całego przebiegu (także sprzed wznowienia), nie tylko z tej sesji.
    let responded: Vec<_> = dscan_db::load_run_hosts(pool, run_id)
        .await?
        .iter()
        .map(|host| host.ip)
        .collect();
    let presence = dscan_db::update_presence(
        pool,
        run_id,
        &networks,
        &responded,
        settings.inactive_after_missed_runs,
    )
    .await?;
    let mut presence = presence;
    dscan_db::mark_unstable(pool, unstable).await?;
    presence.unstable = unstable.to_vec();
    let comparison = compare_with_previous(pool, run_id, &settings.profile).await?;
    Ok((comparison, presence))
}

/// Stan przebiegu w trakcie odbierania wyników z puli.
pub(crate) struct RunningJob<'a> {
    pub(crate) pool: &'a PgPool,
    pub(crate) cipher: &'a Cipher,
    pub(crate) subgroup_ids: Vec<i64>,
    pub(crate) sizes: Vec<u64>,
    pub(crate) progress: ScanProgress,
    pub(crate) hosts: Vec<Host>,
    pub(crate) interrupted: usize,
}

impl RunningJob<'_> {
    pub(crate) async fn consume(
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
                PoolEvent::Interrupted { index } => {
                    dscan_db::reset_subgroup(self.pool, self.subgroup_ids[index]).await?;
                    self.interrupted += 1;
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

    /// Koniec okna: przebieg wstrzymany, do wznowienia od niedokończonych podgrup.
    pub(crate) async fn pause(self) -> Result<ScanJobSummary, EngineError> {
        dscan_db::set_run_status(self.pool, self.progress.run_id, ScanStatus::Paused.as_str())
            .await?;
        Ok(self.summary(ScanStatus::Paused, None, None))
    }

    pub(crate) async fn finish(
        self,
        settings: &ScanJobSettings,
        unstable: &[std::net::IpAddr],
    ) -> Result<ScanJobSummary, EngineError> {
        let status = if self.progress.failed_subgroups == 0 {
            ScanStatus::Completed
        } else {
            ScanStatus::Failed
        };
        dscan_db::finish_scan_run(self.pool, self.progress.run_id, status).await?;
        // Niepełny (nieudany) przebieg dałby fałszywe „zniknięcia”, więc go nie porównujemy.
        if status != ScanStatus::Completed {
            return Ok(self.summary(status, None, None));
        }
        let (comparison, presence) =
            finalize_run(self.pool, self.progress.run_id, settings, unstable).await?;
        Ok(self.summary(status, comparison, Some(presence)))
    }

    fn summary(
        self,
        status: ScanStatus,
        comparison: Option<Comparison>,
        presence: Option<dscan_db::PresenceUpdate>,
    ) -> ScanJobSummary {
        ScanJobSummary {
            run_id: self.progress.run_id,
            comparison,
            presence,
            status,
            duration: self.progress.elapsed(Utc::now()),
            subgroups: self.progress.total_subgroups,
            failed_subgroups: self.progress.failed_subgroups,
            hosts: self.hosts,
        }
    }
}
