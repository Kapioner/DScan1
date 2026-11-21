//! Test silnika na prawdziwej bazie (pomijany bez `DSCAN_TEST_DATABASE_URL`) z atrapą
//! skanera zamiast nmap. Każdy test działa we własnym schemacie PostgreSQL.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use chrono::Utc;
use dscan_core::models::{Host, Protocol, ScanStatus, Service, ServiceState};
use dscan_crypto::Cipher;
use dscan_db::{PgPool, run_migrations};
use dscan_engine::{
    EngineError, ScanJobSettings, ScanObserver, ScanProgress, SubgroupReport, run_scan_job,
};
use dscan_scanner::ScannerError;
use dscan_scanner::nmap::ScanOutput;
use dscan_scanner::pool::SubgroupScanner;
use ipnet::IpNet;
use sqlx::Executor;
use sqlx::postgres::PgPoolOptions;

/// Atrapa: w każdej podgrupie „znajduje” pierwszy adres z otwartym portem 22;
/// podgrupa 10.0.3.0/24 kończy się błędem.
struct FakeScanner;

impl SubgroupScanner for FakeScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        if targets[0].to_string() == "10.0.3.0/24" {
            return Err(ScannerError::NmapFailed {
                exit_code: Some(1),
                stderr: "awaria".into(),
            });
        }
        let mut host = Host::new(targets[0].network(), Utc::now());
        host.services
            .push(Service::new(22, Protocol::Tcp, ServiceState::Open));
        Ok(ScanOutput {
            hosts: vec![host],
            raw_xml: "<nmaprun/>".into(),
        })
    }
}

/// Obserwator zapisujący zdarzenia.
#[derive(Default)]
struct RecordingObserver {
    events: Mutex<Vec<String>>,
}

impl ScanObserver for RecordingObserver {
    fn scan_started(&self, progress: &ScanProgress) {
        self.events
            .lock()
            .unwrap()
            .push(format!("start {}", progress.total_subgroups));
    }
    fn subgroup_finished(&self, report: &SubgroupReport, progress: &ScanProgress) {
        let state = if report.error.is_some() {
            "błąd"
        } else {
            "ok"
        };
        self.events.lock().unwrap().push(format!(
            "{state} {}/{}",
            progress.finished_subgroups, progress.total_subgroups
        ));
    }
}

async fn test_pool() -> Option<(PgPool, String, String)> {
    let Ok(url) = std::env::var("DSCAN_TEST_DATABASE_URL") else {
        eprintln!("pomijam test: brak zmiennej DSCAN_TEST_DATABASE_URL");
        return None;
    };
    let schema = format!(
        "test_engine_{}_{}",
        std::process::id(),
        Utc::now().timestamp_subsec_nanos()
    );
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
        .max_connections(4)
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
    run_migrations(&pool).await.unwrap();
    Some((pool, schema, url))
}

async fn drop_schema(url: &str, schema: &str) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .unwrap();
    admin
        .execute(format!("DROP SCHEMA {schema} CASCADE").as_str())
        .await
        .unwrap();
}

fn settings(max_addresses: u64) -> ScanJobSettings {
    ScanJobSettings {
        profile: "test".into(),
        mode: "services".into(),
        profile_id: None,
        requested_by: None,
        subgroup_size: 256,
        parallel: 3,
        max_addresses,
        inactive_after_missed_runs: 2,
    }
}

#[tokio::test]
async fn job_saves_every_subgroup_and_reports_progress() {
    let Some((pool, schema, url)) = test_pool().await else {
        return;
    };
    let networks: Vec<IpNet> = vec!["10.0.0.0/22".parse().unwrap()]; // 4 podgrupy po 256
    let observer = RecordingObserver::default();
    let cipher = Cipher::new(&[3; 32]);

    let summary = run_scan_job(
        &pool,
        &cipher,
        &networks,
        Arc::new(FakeScanner),
        &settings(10_000),
        &observer,
    )
    .await
    .unwrap();

    assert_eq!(summary.subgroups, 4);
    assert_eq!(summary.failed_subgroups, 1);
    assert_eq!(summary.status, ScanStatus::Failed);
    assert_eq!(summary.hosts.len(), 3);

    let run = dscan_db::get_scan_run(&pool, summary.run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(run.completed_subgroups, 4);
    assert_eq!(run.completed_addresses, 1024);
    assert!(run.finished_at.is_some());

    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM subgroups ORDER BY sequence_no")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(
        statuses,
        vec!["completed", "completed", "completed", "failed"]
    );
    let services: i64 = sqlx::query_scalar("SELECT count(*) FROM services")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(services, 3);

    let events = observer.events.lock().unwrap().clone();
    assert_eq!(events.first().map(String::as_str), Some("start 4"));
    assert_eq!(events.len(), 5);
    assert!(events.last().unwrap().ends_with("4/4"));

    pool.close().await;
    drop_schema(&url, &schema).await;
}

#[tokio::test]
async fn too_many_addresses_are_refused_before_scanning() {
    let Some((pool, schema, url)) = test_pool().await else {
        return;
    };
    let networks: Vec<IpNet> = vec!["10.0.0.0/16".parse().unwrap()];

    let result = run_scan_job(
        &pool,
        &Cipher::new(&[3; 32]),
        &networks,
        Arc::new(FakeScanner),
        &settings(1000),
        &RecordingObserver::default(),
    )
    .await;

    assert!(matches!(
        result,
        Err(EngineError::TooManyAddresses {
            count: 65_536,
            limit: 1000
        })
    ));
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM scan_runs")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(runs, 0);

    pool.close().await;
    drop_schema(&url, &schema).await;
}

/// Atrapa skanera, która „znajduje” serwer WWW pod podanym adresem lokalnym.
struct LocalWebScanner(std::net::SocketAddr);

impl SubgroupScanner for LocalWebScanner {
    async fn scan(&self, _targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        let mut host = Host::new(self.0.ip(), Utc::now());
        let mut web = Service::new(self.0.port(), Protocol::Tcp, ServiceState::Open);
        web.name = Some("http".into());
        host.services.push(web);
        Ok(ScanOutput {
            hosts: vec![host],
            raw_xml: "<nmaprun/>".into(),
        })
    }
}

#[tokio::test]
async fn web_fingerprint_decorator_adds_http_info() {
    use dscan_engine::WebFingerprintScanner;
    use dscan_fingerprint::signatures::SignatureSet;
    use dscan_fingerprint::{HttpFetcher, HttpOptions, WebAnalysis};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<title>Strona testowa</title><form><input type="password"></form>"#,
                )
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let options = HttpOptions {
        timeout: std::time::Duration::from_secs(5),
        max_redirects: 3,
        max_body_bytes: 10_000,
        user_agent: "test".into(),
    };
    let fetcher = Arc::new(HttpFetcher::new(options, None).unwrap());
    let analysis = Arc::new(WebAnalysis::new(SignatureSet::builtin().unwrap(), &[], 5));
    let scanner = WebFingerprintScanner::new(LocalWebScanner(address), fetcher, analysis);

    let output = scanner
        .scan(&["127.0.0.1/32".parse().unwrap()])
        .await
        .unwrap();

    let http = output.hosts[0].services[0].http.as_ref().unwrap();
    assert_eq!(http.title.as_deref(), Some("Strona testowa"));
    assert_eq!(http.status_code, 200);
    let detections = &output.hosts[0].services[0].detections;
    assert!(
        detections.iter().any(|d| d.technology == "Panel logowania"),
        "{detections:?}"
    );
}

/// Atrapa: jeden host 10.0.0.0 z usługami podanymi jako (port, produkt).
struct FixedScanner(Vec<(u16, &'static str)>);

impl SubgroupScanner for FixedScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        let mut host = Host::new(targets[0].network(), Utc::now());
        for (port, product) in &self.0 {
            let mut service = Service::new(*port, Protocol::Tcp, ServiceState::Open);
            service.product = Some(product.to_string());
            host.services.push(service);
        }
        Ok(ScanOutput {
            hosts: vec![host],
            raw_xml: "<nmaprun/>".into(),
        })
    }
}

#[tokio::test]
async fn second_run_is_compared_with_previous_one() {
    use dscan_core::models::ChangeKind;

    let Some((pool, schema, url)) = test_pool().await else {
        return;
    };
    let networks: Vec<IpNet> = vec!["10.0.0.0/32".parse().unwrap()];
    let cipher = Cipher::new(&[3; 32]);
    let observer = RecordingObserver::default();

    let first = run_scan_job(
        &pool,
        &cipher,
        &networks,
        Arc::new(FixedScanner(vec![(22, "OpenSSH 9.6"), (443, "nginx")])),
        &settings(10),
        &observer,
    )
    .await
    .unwrap();
    assert!(
        first.comparison.is_none(),
        "pierwszy przebieg nie ma z czym się porównać"
    );

    let second = run_scan_job(
        &pool,
        &cipher,
        &networks,
        Arc::new(FixedScanner(vec![(22, "OpenSSH 9.7"), (80, "nginx")])),
        &settings(10),
        &observer,
    )
    .await
    .unwrap();

    let comparison = second.comparison.unwrap();
    assert_eq!(comparison.previous_run_id, first.run_id);
    let kinds: Vec<(u16, ChangeKind)> = comparison
        .changes
        .iter()
        .map(|c| (c.key.port, c.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (22, ChangeKind::Modified),
            (80, ChangeKind::Appeared),
            (443, ChangeKind::Disappeared)
        ]
    );

    let stored = dscan_db::list_changes(&pool, second.run_id).await.unwrap();
    assert_eq!(stored.len(), 3);

    pool.close().await;
    drop_schema(&url, &schema).await;
}

/// Atrapa liczy zeskanowane podgrupy i „skanuje” 200 ms — dość, by zdążyć zatrzymać przebieg.
#[derive(Default)]
struct SlowScanner {
    scanned: std::sync::atomic::AtomicUsize,
}

impl SubgroupScanner for SlowScanner {
    async fn scan(&self, targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        self.scanned
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let host = Host::new(targets[0].network(), Utc::now());
        Ok(ScanOutput {
            hosts: vec![host],
            raw_xml: "<nmaprun/>".into(),
        })
    }
}

#[tokio::test]
async fn stopped_run_is_paused_and_resumes_where_it_left_off() {
    use dscan_engine::{create_job, drive_job, load_job};

    let Some((pool, schema, url)) = test_pool().await else {
        return;
    };
    let cipher = Cipher::new(&[3; 32]);
    let mut job_settings = settings(10_000);
    job_settings.parallel = 1;
    let networks: Vec<IpNet> = vec!["10.0.0.0/22".parse().unwrap()]; // 4 podgrupy

    let plan = create_job(&pool, &networks, &job_settings).await.unwrap();
    let run_id = plan.run_id;
    let (stop_sender, stop) = tokio::sync::watch::channel(false);
    let scanner = Arc::new(SlowScanner::default());
    let stopper = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await; // po 1. podgrupie, w trakcie 2.
        stop_sender.send(true).unwrap();
        stop_sender
    });
    let first = drive_job(
        &pool,
        &cipher,
        plan,
        Arc::clone(&scanner),
        &job_settings,
        &RecordingObserver::default(),
        stop,
    )
    .await
    .unwrap();
    let _sender = stopper.await.unwrap();
    assert_eq!(first.status, ScanStatus::Paused);
    let paused = dscan_db::get_scan_run(&pool, run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(paused.status, ScanStatus::Paused);
    assert_eq!(paused.completed_subgroups, 1);

    let (plan, _) = load_job(&pool, run_id).await.unwrap();
    assert_eq!(
        plan.subgroups.len(),
        3,
        "przerwana podgrupa wróciła do kolejki"
    );
    let resumed = drive_job(
        &pool,
        &cipher,
        plan,
        Arc::clone(&scanner),
        &job_settings,
        &RecordingObserver::default(),
        dscan_scanner::pool::never_stop(),
    )
    .await
    .unwrap();
    assert_eq!(resumed.status, ScanStatus::Completed);
    let done = dscan_db::get_scan_run(&pool, run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (done.completed_subgroups, done.completed_addresses),
        (4, 1024)
    );
    // 1 przed zatrzymaniem + 3 po wznowieniu; przerwana nie została policzona podwójnie.
    assert_eq!(scanner.scanned.load(std::sync::atomic::Ordering::SeqCst), 4);
    assert!(load_job(&pool, run_id).await.is_err());

    pool.close().await;
    drop_schema(&url, &schema).await;
}

#[tokio::test]
async fn host_becomes_inactive_after_k_runs_without_response() {
    use dscan_core::models::HostStatus;

    let Some((pool, schema, url)) = test_pool().await else {
        return;
    };
    let cipher = Cipher::new(&[3; 32]);
    let networks: Vec<IpNet> = vec!["10.0.0.0/32".parse().unwrap()];
    let present = Arc::new(FixedScanner(vec![(22, "OpenSSH")]));
    run_scan_job(
        &pool,
        &cipher,
        &networks,
        present,
        &settings(10),
        &RecordingObserver::default(),
    )
    .await
    .unwrap();

    struct Silent;
    impl SubgroupScanner for Silent {
        async fn scan(&self, _targets: &[IpNet]) -> Result<ScanOutput, ScannerError> {
            Ok(ScanOutput {
                hosts: Vec::new(),
                raw_xml: "<nmaprun/>".into(),
            })
        }
    }
    let mut statuses = Vec::new();
    for _ in 0..2 {
        let summary = run_scan_job(
            &pool,
            &cipher,
            &networks,
            Arc::new(Silent),
            &settings(10),
            &RecordingObserver::default(),
        )
        .await
        .unwrap();
        let presence = dscan_db::load_presence(&pool).await.unwrap();
        statuses.push((
            presence[0].status,
            presence[0].consecutive_misses,
            summary.presence.unwrap().became_inactive.len(),
        ));
    }
    // K = 2 (settings): po 1. braku nadal aktywny, po 2. nieaktywny.
    assert_eq!(
        statuses,
        vec![(HostStatus::Active, 1, 0), (HostStatus::Inactive, 2, 1)]
    );
    let history = dscan_db::response_history(&pool, "10.0.0.0".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(
        history
            .iter()
            .map(|(_, responded)| *responded)
            .collect::<Vec<_>>(),
        vec![false, false, true]
    );

    pool.close().await;
    drop_schema(&url, &schema).await;
}
