//! Testy klienta HTTP na lokalnych serwerach (bez internetu).

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use dscan_fingerprint::{FetchError, HttpFetcher, HttpOptions, HttpRateLimiter, to_http_info};
use tokio::net::TcpListener;

fn localhost() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn options(max_body_bytes: usize) -> HttpOptions {
    HttpOptions {
        timeout: Duration::from_secs(5),
        max_redirects: 3,
        max_body_bytes,
        user_agent: "DScan-test".into(),
    }
}

fn redirect(to: &str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(LOCATION, to.parse().unwrap());
    (StatusCode::FOUND, headers)
}

async fn login_page() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        "sid=abc; Path=/; HttpOnly; SameSite=Strict"
            .parse()
            .unwrap(),
    );
    headers.insert("server", "testowy/1.0".parse().unwrap());
    (
        headers,
        Html("<html><head><title>Panel administracyjny</title></head><body>…</body></html>"),
    )
}

async fn start_server() -> SocketAddr {
    let app = Router::new()
        .route("/", get(|| async { redirect("/app/") }))
        .route("/app/", get(|| async { redirect("login") }))
        .route("/app/login", get(login_page))
        .route(
            "/external",
            get(|| async { redirect("http://example.invalid/") }),
        )
        .route("/loop", get(|| async { redirect("/loop") }))
        .route("/big", get(|| async { "x".repeat(100_000) }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    address
}

#[tokio::test]
async fn redirect_chain_is_followed_and_recorded() {
    let address = start_server().await;
    let fetcher = HttpFetcher::new(options(65_536), None).unwrap();

    let response = fetcher
        .fetch(&format!("http://{address}/"), localhost())
        .await
        .unwrap();
    let info = to_http_info(&response);

    assert_eq!(info.status_code, 200);
    assert_eq!(info.url, format!("http://{address}/app/login"));
    assert_eq!(info.redirect_chain.len(), 2);
    assert_eq!(info.redirect_chain[0].status_code, 302);
    assert_eq!(
        info.redirect_chain[1].to,
        format!("http://{address}/app/login")
    );
    assert_eq!(info.title.as_deref(), Some("Panel administracyjny"));
    assert_eq!(info.header("server"), Some("testowy/1.0"));
    assert_eq!(info.cookies[0].same_site.as_deref(), Some("Strict"));
    assert_eq!(info.tls_verified, None);
}

#[tokio::test]
async fn redirect_to_other_host_is_recorded_but_not_followed() {
    let address = start_server().await;
    let fetcher = HttpFetcher::new(options(65_536), None).unwrap();

    let response = fetcher
        .fetch(&format!("http://{address}/external"), localhost())
        .await
        .unwrap();

    assert_eq!(response.status, 302);
    assert_eq!(response.redirects.len(), 1);
    assert_eq!(response.redirects[0].to, "http://example.invalid/");
}

#[tokio::test]
async fn redirect_loop_is_stopped() {
    let address = start_server().await;
    let fetcher = HttpFetcher::new(options(65_536), None).unwrap();

    let result = fetcher
        .fetch(&format!("http://{address}/loop"), localhost())
        .await;

    assert!(matches!(result, Err(FetchError::TooManyRedirects(3))));
}

#[tokio::test]
async fn body_is_read_only_up_to_limit() {
    let address = start_server().await;
    let fetcher = HttpFetcher::new(options(1000), None).unwrap();

    let response = fetcher
        .fetch(&format!("http://{address}/big"), localhost())
        .await
        .unwrap();

    assert_eq!(response.body.len(), 1000);
}

#[tokio::test]
async fn per_host_budget_stops_requests() {
    let address = start_server().await;
    // Budżet 2 zapytania, a łańcuch z / potrzebuje trzech.
    let limiter = Arc::new(HttpRateLimiter::new(100, 2));
    let fetcher = HttpFetcher::new(options(65_536), Some(limiter)).unwrap();

    let result = fetcher
        .fetch(&format!("http://{address}/"), localhost())
        .await;

    assert!(matches!(result, Err(FetchError::Budget(_))));
}

/// Serwer HTTPS z certyfikatem self-signed (`openssl s_server`), zatrzymywany po teście.
struct SelfSignedServer(Child);

impl Drop for SelfSignedServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn start_self_signed_server(port: u16) -> Option<SelfSignedServer> {
    let dir = std::env::temp_dir().join(format!("dscan-tls-{port}"));
    std::fs::create_dir_all(&dir).ok()?;
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    let generated = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=test.invalid",
            "-addext",
            "subjectAltName=DNS:test.invalid,IP:127.0.0.1",
        ])
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !generated.success() {
        return None;
    }
    let child = Command::new("openssl")
        .args(["s_server", "-www", "-accept", &port.to_string(), "-cert"])
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    Some(SelfSignedServer(child))
}

#[tokio::test]
async fn self_signed_certificate_is_read_but_marked_unverified() {
    let port = 18_443;
    let Some(_server) = start_self_signed_server(port) else {
        eprintln!("pomijam test: brak programu openssl");
        return;
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let fetcher = HttpFetcher::new(options(65_536), None).unwrap();

    let response = fetcher
        .fetch(&format!("https://127.0.0.1:{port}/"), localhost())
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.tls_verified, Some(false));
}

#[tokio::test]
async fn certificate_fields_are_read() {
    let port = 18_444;
    let Some(_server) = start_self_signed_server(port) else {
        eprintln!("pomijam test: brak programu openssl");
        return;
    };
    tokio::time::sleep(Duration::from_millis(500)).await;

    let certificate =
        dscan_fingerprint::fetch_certificate(localhost(), port, Duration::from_secs(5))
            .await
            .unwrap();

    assert_eq!(certificate.common_name.as_deref(), Some("test.invalid"));
    assert_eq!(certificate.alt_names, vec!["test.invalid", "127.0.0.1"]);
    assert!(certificate.self_signed);
    assert!(!certificate.is_expired(chrono::Utc::now()));
    assert_eq!(certificate.days_left(chrono::Utc::now()), 0);
    assert!(
        certificate.signature_algorithm.contains("sha256"),
        "{}",
        certificate.signature_algorithm
    );
    assert_eq!(certificate.sha256.len(), 64);
}

#[tokio::test]
async fn certificate_of_plain_http_port_fails_cleanly() {
    let address = start_server().await;
    let result =
        dscan_fingerprint::fetch_certificate(localhost(), address.port(), Duration::from_secs(2))
            .await;
    assert!(result.is_err());
}
