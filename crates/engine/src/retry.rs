//! Powtórne pomiary hostów niestabilnych (S10): znany host z przeskanowanych sieci, który
//! tym razem nie odpowiedział, jest skanowany ponownie do N razy z odstępem. Jeśli odpowie
//! przy którejś próbie, jego wynik trafia do przebiegu, a host dostaje stan „niestabilny”.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use chrono::Utc;
use dscan_core::models::{HostStatus, Presence};
use dscan_crypto::Cipher;
use dscan_db::{PgPool, SubgroupCompletion};
use dscan_scanner::pool::{SubgroupScanner, wait_for_stop};
use dscan_scanner::targets::single_address_network;
use ipnet::IpNet;
use tokio::sync::watch;

use crate::{EngineError, ScanJobSettings};

/// Ustawienia powtórzeń.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub attempts: u32,
    pub delay: Duration,
}

/// Kandydaci do powtórki: znane, nie-nieaktywne hosty z przeskanowanych sieci bez odpowiedzi.
pub fn retry_candidates(
    known: &[Presence],
    scanned: &[IpNet],
    responded: &HashSet<IpAddr>,
) -> Vec<IpAddr> {
    known
        .iter()
        .filter(|p| p.status != HostStatus::Inactive)
        .filter(|p| !responded.contains(&p.ip))
        .filter(|p| scanned.iter().any(|net| net.contains(&p.ip)))
        .map(|p| p.ip)
        .collect()
}

/// Wykonuje powtórki i zwraca hosty, które odpowiedziały dopiero przy powtórce.
/// Sygnał `stop` przerywa czekanie i kolejne próby.
pub(crate) async fn remeasure<S: SubgroupScanner>(
    pool: &PgPool,
    cipher: &Cipher,
    run_id: i64,
    scanner: &S,
    mut pending: Vec<IpAddr>,
    policy: RetryPolicy,
    mut stop: watch::Receiver<bool>,
) -> Result<Vec<IpAddr>, EngineError> {
    let mut unstable = Vec::new();
    for attempt in 1..=policy.attempts {
        if pending.is_empty() || *stop.borrow() {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(policy.delay) => {}
            () = wait_for_stop(&mut stop) => break,
        }
        let networks: Vec<IpNet> = pending
            .iter()
            .map(|ip| single_address_network(*ip))
            .collect();
        let texts: Vec<String> = networks.iter().map(ToString::to_string).collect();
        let subgroup_id =
            dscan_db::add_retry_subgroup(pool, run_id, &texts, attempt as i32).await?;
        let started_at = Utc::now();
        // Błąd powtórki (np. nmap) nie psuje udanego przebiegu — kolejna próba albo koniec.
        let Ok(output) = scanner.scan(&networks).await else {
            let message = format!("powtórny pomiar {attempt} nieudany");
            let times = (started_at, Utc::now());
            dscan_db::fail_subgroup(
                pool,
                run_id,
                subgroup_id,
                texts.len() as u64,
                times,
                &message,
            )
            .await?;
            continue;
        };
        let completion = SubgroupCompletion {
            run_id,
            subgroup_id,
            addresses: texts.len() as u64,
            started_at,
            finished_at: Utc::now(),
            hosts: &output.hosts,
            raw_xml: &output.raw_xml,
        };
        dscan_db::complete_subgroup(pool, cipher, completion).await?;
        let answered: HashSet<IpAddr> = output.hosts.iter().map(|host| host.ip).collect();
        pending.retain(|ip| !answered.contains(ip));
        unstable.extend(answered);
    }
    Ok(unstable)
}

/// S10: znane hosty z przeskanowanych sieci, które nie odpowiedziały, skanujemy ponownie.
pub(crate) async fn remeasure_silent_hosts<S: SubgroupScanner>(
    pool: &PgPool,
    cipher: &Cipher,
    run_id: i64,
    scanner: &S,
    settings: &ScanJobSettings,
    stop: watch::Receiver<bool>,
) -> Result<Vec<IpAddr>, EngineError> {
    let networks: Vec<IpNet> = dscan_db::run_networks(pool, run_id)
        .await?
        .iter()
        .filter_map(|text| text.parse().ok())
        .collect();
    let responded = dscan_db::load_run_hosts(pool, run_id)
        .await?
        .iter()
        .map(|host| host.ip)
        .collect();
    let known = dscan_db::load_presence(pool).await?;
    let candidates = retry_candidates(&known, &networks, &responded);
    let policy = RetryPolicy {
        attempts: settings.unstable_retries,
        delay: std::time::Duration::from_secs(settings.retry_delay_seconds),
    };
    remeasure(pool, cipher, run_id, scanner, candidates, policy, stop).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presence(ip: &str, status: HostStatus) -> Presence {
        Presence {
            ip: ip.parse().unwrap(),
            status,
            consecutive_misses: 0,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn only_known_silent_hosts_in_scanned_networks_are_retried() {
        let known = vec![
            presence("10.0.0.1", HostStatus::Active), // odpowiedział — bez powtórki
            presence("10.0.0.2", HostStatus::Active), // milczy — powtórka
            presence("10.0.0.3", HostStatus::Inactive), // nieaktywny — bez powtórki
            presence("10.0.0.4", HostStatus::Unstable), // niestabilny — powtórka
            presence("10.9.0.1", HostStatus::Active), // poza skanowaną siecią
        ];
        let responded = HashSet::from(["10.0.0.1".parse().unwrap()]);
        let candidates = retry_candidates(&known, &["10.0.0.0/24".parse().unwrap()], &responded);
        let texts: Vec<String> = candidates.iter().map(ToString::to_string).collect();
        assert_eq!(texts, vec!["10.0.0.2", "10.0.0.4"]);
    }
}
