// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use chrono::{TimeDelta, Utc};
use common::TestDatabase;
use dscan_core::models::{Host, Protocol, ScanStatus, Service, ServiceState};
use dscan_crypto::Cipher;
use dscan_db::{
    SubgroupCompletion, complete_subgroup, create_scan_run, fail_subgroup, finish_scan_run,
    get_scan_run, list_scan_runs, mark_subgroup_running, save_scan_results,
};

fn cipher() -> Cipher {
    Cipher::new(&[5; 32])
}

/// `count` hostów 10.x.y.z, każdy z dwiema usługami (ssh z banerem i http).
fn hosts(count: u32) -> Vec<Host> {
    (0..count)
        .map(|i| {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i));
            let mut host = Host::new(ip, Utc::now());
            let mut ssh = Service::new(22, Protocol::Tcp, ServiceState::Open);
            ssh.banner = Some("SSH-2.0-OpenSSH_9.6".into());
            ssh.cpe = vec!["cpe:/a:openbsd:openssh:9.6".into()];
            let mut http = Service::new(80, Protocol::Tcp, ServiceState::Open);
            http.product = Some("nginx".into());
            host.services = vec![ssh, http];
            host
        })
        .collect()
}

#[tokio::test]
async fn ten_thousand_hosts_are_saved_in_batches_quickly() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let run = create_scan_run(&db.pool, "test", 10_000, &[])
        .await
        .unwrap();
    let hosts = hosts(10_000);

    let begin = Instant::now();
    let summary = save_scan_results(&db.pool, &cipher(), run.run_id, &hosts)
        .await
        .unwrap();
    let elapsed = begin.elapsed();
    eprintln!("zapis 10 000 hostów i 20 000 usług: {elapsed:?}");

    assert_eq!(summary.hosts, 10_000);
    assert_eq!(summary.services, 20_000);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM services")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored, 20_000);
    // Pojedyncze INSERT-y trwałyby kilkadziesiąt sekund; wsadowo to kilka sekund nawet w CI.
    assert!(elapsed.as_secs() < 20, "zapis trwał {elapsed:?}");
    db.drop().await;
}

#[tokio::test]
async fn banner_is_stored_encrypted() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let run = create_scan_run(&db.pool, "test", 1, &[]).await.unwrap();
    save_scan_results(&db.pool, &cipher(), run.run_id, &hosts(1))
        .await
        .unwrap();

    let raw: Vec<u8> = sqlx::query_scalar("SELECT banner FROM services WHERE banner IS NOT NULL")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("OpenSSH"));
    db.drop().await;
}

#[tokio::test]
async fn scan_run_tracks_progress_and_time_per_subgroup() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let subgroups = vec![
        vec!["10.0.0.0/24".to_string()],
        vec!["10.0.1.0/24".to_string()],
    ];
    let run = create_scan_run(&db.pool, "domyślny", 512, &subgroups)
        .await
        .unwrap();
    assert_eq!(run.subgroup_ids.len(), 2);

    let started = Utc::now();
    mark_subgroup_running(&db.pool, run.subgroup_ids[0], started)
        .await
        .unwrap();
    let completion = SubgroupCompletion {
        run_id: run.run_id,
        subgroup_id: run.subgroup_ids[0],
        addresses: 256,
        started_at: started,
        finished_at: started + TimeDelta::seconds(12),
        hosts: &hosts(3),
        raw_xml: "<nmaprun>tajny baner</nmaprun>",
    };
    complete_subgroup(&db.pool, &cipher(), completion)
        .await
        .unwrap();

    let halfway = get_scan_run(&db.pool, run.run_id).await.unwrap().unwrap();
    assert_eq!(halfway.status, ScanStatus::Running);
    assert_eq!(halfway.completed_addresses, 256);
    assert_eq!(halfway.progress_percent(), 50.0);
    assert!(halfway.estimated_remaining(Utc::now()).is_some());

    fail_subgroup(
        &db.pool,
        run.run_id,
        run.subgroup_ids[1],
        256,
        (started, started),
        "nmap padł",
    )
    .await
    .unwrap();
    finish_scan_run(&db.pool, run.run_id, ScanStatus::Failed)
        .await
        .unwrap();

    let done = get_scan_run(&db.pool, run.run_id).await.unwrap().unwrap();
    assert_eq!(done.status, ScanStatus::Failed);
    assert_eq!(done.completed_subgroups, 2);
    assert!(done.finished_at.is_some());
    assert_eq!(done.estimated_remaining(Utc::now()), None);

    let durations: Vec<(String, Option<f64>, Option<String>)> = sqlx::query_as(
        "SELECT status, EXTRACT(EPOCH FROM finished_at - started_at)::float8, error \
         FROM subgroups ORDER BY sequence_no",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(durations[0], ("completed".to_string(), Some(12.0), None));
    assert_eq!(durations[1].2.as_deref(), Some("nmap padł"));

    let xml: Vec<u8> =
        sqlx::query_scalar("SELECT raw_nmap_xml FROM subgroups WHERE sequence_no = 0")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&xml).contains("tajny"));
    db.drop().await;
}

#[tokio::test]
async fn runs_are_listed_newest_first() {
    let Some(db) = TestDatabase::create().await else {
        return;
    };
    let first = create_scan_run(&db.pool, "a", 1, &[]).await.unwrap();
    let second = create_scan_run(&db.pool, "b", 1, &[]).await.unwrap();

    let runs = list_scan_runs(&db.pool, 10).await.unwrap();

    assert_eq!(
        runs.iter().map(|run| run.id).collect::<Vec<_>>(),
        vec![second.run_id, first.run_id]
    );
    assert!(get_scan_run(&db.pool, 999_999).await.unwrap().is_none());
    db.drop().await;
}
