//! Dane dashboardu (A8, F2): ostatni i trwające przebiegi, ważne znaleziska,
//! zmiany od poprzedniego skanu, statystyki technologii i obecność hostów.

use std::collections::{BTreeMap, HashMap};

use dscan_config::Settings;
use dscan_core::models::{Change, Host, HostStatus, ScanRun, ScanStatus};
use dscan_db::PgPool;
use dscan_fingerprint::environment::is_environment_finding;

use crate::{EngineError, load_signatures};

/// Kategorie sygnatur, które zawsze trafiają na listę ważnych znalezisk.
pub const IMPORTANT_CATEGORIES: [&str; 5] = [
    "panel-admina",
    "iot-kamera",
    "iot-drukarka",
    "ci-cd",
    "baza-danych",
];

/// Znalezisko wymagające uwagi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    /// Technologia albo opis (np. „Certyfikat TLS niezweryfikowany”).
    pub title: String,
    /// Kategoria sygnatury albo `środowisko`/`tls`.
    pub category: String,
}

/// Wszystko, co pokazuje dashboard.
#[derive(Debug, Clone, Default)]
pub struct Dashboard {
    /// Ostatni zakończony przebieg (do niego odnoszą się znaleziska i statystyki).
    pub latest: Option<ScanRun>,
    /// Przebiegi trwające i wstrzymane.
    pub active: Vec<ScanRun>,
    pub findings: Vec<Finding>,
    /// Najciekawsze usługi (M3), od najwyższego wyniku.
    pub interesting: Vec<crate::scoring::Interest>,
    /// Zmiany zapisane dla ostatniego przebiegu (względem poprzedniego tego profilu).
    pub changes: Vec<Change>,
    /// (technologia, liczba usług), malejąco.
    pub technologies: Vec<(String, usize)>,
    pub hosts: usize,
    pub open_services: usize,
    pub active_hosts: usize,
    pub inactive_hosts: usize,
}

/// Ważne znaleziska w hostach: heurystyki M6, ważne kategorie sygnatur i TLS bez weryfikacji.
pub fn important_findings(hosts: &[Host], categories: &HashMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for host in hosts {
        for service in &host.services {
            let finding = |title: String, category: String| Finding {
                ip: host.ip.to_string(),
                port: service.port,
                protocol: service.protocol.as_str().to_string(),
                title,
                category,
            };
            for detection in &service.detections {
                let category = categories.get(&detection.technology).map(String::as_str);
                if is_environment_finding(&detection.technology) {
                    findings.push(finding(detection.technology.clone(), "środowisko".into()));
                } else if let Some(category) = category.filter(|c| IMPORTANT_CATEGORIES.contains(c))
                {
                    findings.push(finding(detection.technology.clone(), category.to_string()));
                }
            }
            if service.http.as_ref().and_then(|http| http.tls_verified) == Some(false) {
                findings.push(finding(
                    "Certyfikat TLS niezweryfikowany".into(),
                    "tls".into(),
                ));
            }
        }
    }
    findings
}

/// Liczba usług z każdą technologią, od najczęstszej.
pub fn technology_stats(hosts: &[Host]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for detection in hosts
        .iter()
        .flat_map(|h| &h.services)
        .flat_map(|s| &s.detections)
    {
        *counts.entry(detection.technology.clone()).or_default() += 1;
    }
    let mut stats: Vec<_> = counts.into_iter().collect();
    stats.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    stats
}

/// Wczytuje dane dashboardu z bazy.
pub async fn load_dashboard(
    pool: &PgPool,
    cipher: &dscan_crypto::Cipher,
    settings: &Settings,
) -> Result<Dashboard, EngineError> {
    let runs = dscan_db::list_scan_runs(pool, 50).await?;
    let active = runs
        .iter()
        .filter(|run| {
            matches!(
                run.status,
                ScanStatus::Running | ScanStatus::Paused | ScanStatus::Pending
            )
        })
        .cloned()
        .collect();
    let latest = runs
        .into_iter()
        .find(|run| run.status == ScanStatus::Completed);
    let presence = dscan_db::load_presence(pool).await?;
    let mut dashboard = Dashboard {
        active,
        active_hosts: presence
            .iter()
            .filter(|p| p.status == HostStatus::Active)
            .count(),
        inactive_hosts: presence
            .iter()
            .filter(|p| p.status == HostStatus::Inactive)
            .count(),
        ..Dashboard::default()
    };
    if let Some(run) = &latest {
        // Z certyfikatami — ocena (M3) uwzględnia wygasłe i self-signed.
        let hosts = dscan_db::load_run_hosts_with_certificates(pool, cipher, run.id).await?;
        let categories: HashMap<String, String> = load_signatures(settings)?
            .summaries()
            .into_iter()
            .filter_map(|(name, category, _)| category.map(|category| (name, category)))
            .collect();
        dashboard.findings = important_findings(&hosts, &categories);
        dashboard.technologies = technology_stats(&hosts);
        dashboard.changes = dscan_db::list_changes(pool, run.id).await?;
        dashboard.interesting = crate::scoring::rank_interesting(
            &hosts,
            &settings.scoring,
            &categories,
            &dashboard.changes,
            chrono::Utc::now(),
        );
        dashboard.interesting.truncate(20);
        dashboard.hosts = hosts.len();
        dashboard.open_services = hosts.iter().map(Host::open_port_count).sum();
    }
    dashboard.latest = latest;
    Ok(dashboard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{Detection, HttpInfo, Protocol, Service, ServiceState};

    fn service(port: u16, technologies: &[&str]) -> Service {
        let mut service = Service::new(port, Protocol::Tcp, ServiceState::Open);
        service.detections = technologies
            .iter()
            .map(|t| Detection::from_evidence(t.to_string(), None, Vec::new()))
            .collect();
        service
    }

    fn hosts() -> Vec<Host> {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut tls = service(443, &["nginx"]);
        tls.http = Some(HttpInfo {
            url: "https://10.0.0.5/".into(),
            status_code: 200,
            title: None,
            headers: Vec::new(),
            cookies: Vec::new(),
            redirect_chain: Vec::new(),
            tls_verified: Some(false),
            certificate: None,
            favicon: None,
            simhash: None,
        });
        host.services = vec![
            service(80, &["Jenkins", "nginx"]),
            service(8080, &["Tryb debugowania"]),
            tls,
        ];
        vec![host]
    }

    #[test]
    fn findings_cover_categories_heuristics_and_tls() {
        let categories = HashMap::from([
            ("Jenkins".to_string(), "ci-cd".to_string()),
            ("nginx".into(), "serwer-www".into()),
        ]);
        let titles: Vec<String> = important_findings(&hosts(), &categories)
            .into_iter()
            .map(|f| f.title)
            .collect();
        assert_eq!(
            titles,
            vec![
                "Jenkins",
                "Tryb debugowania",
                "Certyfikat TLS niezweryfikowany"
            ]
        );
    }

    #[test]
    fn technologies_are_counted_descending() {
        let stats = technology_stats(&hosts());
        assert_eq!(stats[0], ("nginx".to_string(), 2));
        assert_eq!(stats.len(), 3);
    }
}
