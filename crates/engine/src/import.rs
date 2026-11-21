//! Import wyników skanu (I2): zaimportowane hosty przechodzą to samo przetwarzanie co skan —
//! zapis jako przebieg z jedną podgrupą, obecność hostów (S11) i porównanie z poprzednim
//! przebiegiem tego samego profilu (M1). Hosty spoza `[scope]` są odrzucane.

use chrono::Utc;
use dscan_config::Settings;
use dscan_core::models::{Host, ScanStatus};
use dscan_crypto::Cipher;
use dscan_db::{NewRun, PgPool, SubgroupCompletion};
use dscan_scanner::targets::{is_in_scope, single_address_network};
use ipnet::IpNet;

use crate::running::finalize_run;
use crate::{EngineError, ScanJobSettings, ScanJobSummary, ScanRequest, job_settings};

/// Co zaimportować.
#[derive(Debug, Clone, Default)]
pub struct ResultImport {
    pub hosts: Vec<Host>,
    /// Surowy XML nmap (zachowywany do DefectDojo, jak przy skanie).
    pub raw_xml: Option<String>,
    /// Nazwa profilu przebiegu — porównanie idzie z poprzednim przebiegiem o tej nazwie.
    pub profile: String,
    pub requested_by: Option<i64>,
}

/// Wynik importu: podsumowanie przebiegu i adresy odrzucone (poza zakresem).
#[derive(Debug, Clone)]
pub struct ImportOutcome {
    pub summary: ScanJobSummary,
    pub out_of_scope: Vec<String>,
}

/// Dzieli hosty na te w zakresie `[scope]` i adresy spoza niego.
pub fn split_by_scope(hosts: Vec<Host>, allowed: &[IpNet]) -> (Vec<Host>, Vec<String>) {
    let (inside, outside): (Vec<Host>, Vec<Host>) = hosts
        .into_iter()
        .partition(|host| is_in_scope(&single_address_network(host.ip), allowed));
    (
        inside,
        outside.iter().map(|host| host.ip.to_string()).collect(),
    )
}

/// Zapisuje zaimportowane wyniki jako zakończony przebieg.
pub async fn import_results(
    pool: &PgPool,
    cipher: &Cipher,
    settings: &Settings,
    import: ResultImport,
) -> Result<ImportOutcome, EngineError> {
    let (hosts, out_of_scope) = split_by_scope(import.hosts, &settings.scope.allowed_networks);
    if hosts.is_empty() {
        return Err(EngineError::NoTargets);
    }
    let request = ScanRequest {
        requested_by: import.requested_by,
        ..ScanRequest::default()
    };
    let job: ScanJobSettings = job_settings(settings, "services", import.profile.clone(), &request);
    let addresses: Vec<String> = hosts
        .iter()
        .map(|host| single_address_network(host.ip).to_string())
        .collect();
    let run = NewRun {
        profile: job.profile.clone(),
        mode: job.mode.clone(),
        profile_id: None,
        requested_by: job.requested_by,
    };
    let created =
        dscan_db::create_scan_run_with(pool, &run, addresses.len() as u64, &[addresses]).await?;
    let (run_id, now) = (created.run_id, Utc::now());
    let subgroup_id = created
        .subgroup_ids
        .first()
        .copied()
        .ok_or(EngineError::NoTargets)?;
    let raw_xml = import.raw_xml.unwrap_or_default();
    let completion = SubgroupCompletion {
        run_id,
        subgroup_id,
        addresses: hosts.len() as u64,
        started_at: now,
        finished_at: now,
        hosts: &hosts,
        raw_xml: &raw_xml,
    };
    dscan_db::complete_subgroup(pool, cipher, completion).await?;
    dscan_db::finish_scan_run(pool, run_id, ScanStatus::Completed).await?;
    let (comparison, presence) = finalize_run(pool, run_id, &job, &[]).await?;
    let summary = ScanJobSummary {
        run_id,
        comparison,
        presence: Some(presence),
        status: ScanStatus::Completed,
        duration: chrono::TimeDelta::zero(),
        subgroups: 1,
        failed_subgroups: 0,
        hosts,
    };
    Ok(ImportOutcome {
        summary,
        out_of_scope,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_outside_scope_are_rejected() {
        let hosts = vec![
            Host::new("10.0.0.5".parse().unwrap(), Utc::now()),
            Host::new("8.8.8.8".parse().unwrap(), Utc::now()),
        ];
        let (inside, outside) = split_by_scope(hosts, &["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(inside.len(), 1);
        assert_eq!(outside, vec!["8.8.8.8"]);
    }
}
