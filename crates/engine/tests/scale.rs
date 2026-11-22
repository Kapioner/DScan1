//! Test skali (Q2): przebieg na sieci /18 (16 384 adresów) z atrapą skanera, która „znajduje”
//! 10% hostów z dwiema usługami. Sprawdza czas, przyrost pamięci i brak zakleszczeń
//! (całość pod limitem czasu). Pomijany bez `DSCAN_TEST_DATABASE_URL`.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use dscan_core::models::{Host, Protocol, ScanStatus, Service, ServiceState};
use dscan_crypto::Cipher;
use dscan_engine::{ScanJobSettings, SilentObserver, run_scan_job};
use dscan_scanner::ScannerError;
use dscan_scanner::nmap::ScanOutput;
use dscan_scanner::pool::SubgroupScanner;
use ipnet::IpNet;
use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;

/// Atrapa: co dziesiąty adres podgrupy odpowiada (porty 22 i 80), skan trwa 5 ms.
struct ManyHostsScanner;

impl SubgroupScanner for ManyHostsScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let hosts = targets
            .iter()
            .flat_map(|net| net.hosts())
            .step_by(10)
            .map(|ip| {
                let mut host = Host::new(ip, Utc::now());
                host.services
                    .push(Service::new(22, Protocol::Tcp, ServiceState::Open));
                host.services
                    .push(Service::new(80, Protocol::Tcp, ServiceState::Open));
                host
            })
            .collect();
        Ok(ScanOutput {
            hosts,
            raw_xml: "<nmaprun/>".into(),
        })
    }
}

/// Szczytowe zużycie pamięci procesu (VmHWM, kB) — tylko Linux.
fn peak_memory_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn scan_of_sixteen_thousand_addresses() {
    let Ok(url) = std::env::var("DSCAN_TEST_DATABASE_URL") else {
        eprintln!("pomijam test: brak zmiennej DSCAN_TEST_DATABASE_URL");
        return;
    };
    let schema = format!("test_scale_{}", std::process::id());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    admin
        .execute(format!("CREATE SCHEMA {schema}").as_str())
        .await
        .unwrap();
    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .after_connect(move |connection, _| {
            let search_path = search_path.clone();
            Box::pin(async move {
                connection.execute(search_path.as_str()).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    dscan_db::run_migrations(&pool).await.unwrap();

    let settings = ScanJobSettings {
        profile: "skala".into(),
        mode: "services".into(),
        profile_id: None,
        requested_by: None,
        subgroup_size: 256,
        parallel: 8,
        max_addresses: 1 << 20,
        inactive_after_missed_runs: 3,
        unstable_retries: 0,
        retry_delay_seconds: 0,
    };
    let networks: Vec<IpNet> = vec!["10.64.0.0/18".parse().unwrap()];
    let memory_before = peak_memory_kb();
    let started = Instant::now();
    let summary = tokio::time::timeout(
        Duration::from_secs(300),
        run_scan_job(
            &pool,
            &Cipher::new(&[3; 32]),
            &networks,
            Arc::new(ManyHostsScanner),
            &settings,
            &SilentObserver,
        ),
    )
    .await
    .expect("przebieg nie zakończył się w 5 minut — możliwe zakleszczenie")
    .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(summary.status, ScanStatus::Completed);
    assert_eq!(summary.subgroups, 64);
    assert!(
        summary.hosts.len() > 1_500,
        "hosty: {}",
        summary.hosts.len()
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM services")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored as usize, summary.hosts.len() * 2);
    let memory_growth = peak_memory_kb()
        .zip(memory_before)
        .map(|(after, before)| after.saturating_sub(before));
    eprintln!(
        "Q2: 16384 adresów, {} hostów, {} usług — {:.1} s, przyrost pamięci {:?} kB",
        summary.hosts.len(),
        stored,
        elapsed.as_secs_f64(),
        memory_growth
    );
    assert!(
        memory_growth.is_none_or(|kb| kb < 512 * 1024),
        "za duży przyrost pamięci"
    );

    pool.close().await;
    admin
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await
        .unwrap();
}
