//! Testy routera bez działającej bazy: pula łączy się leniwie z nieistniejącym
//! adresem, więc endpoint stanu powinien zgłosić bazę jako niedostępną.

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use dscan_api::{AppState, build_router};
use dscan_db::{PoolOptions, connect_lazy};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const MAX_BODY_BYTES: usize = 1024;

fn test_router() -> Router {
    let options = PoolOptions {
        max_connections: 1,
        connect_timeout: Duration::from_millis(300),
    };
    let pool = connect_lazy("postgres://nikt:nic@127.0.0.1:1/brak", options).unwrap();
    build_router(AppState::new(pool), MAX_BODY_BYTES)
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

fn get(uri: &str) -> Request<Body> {
    Request::get(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn health_reports_unavailable_database() {
    let (status, body) = send(test_router(), get("/api/v1/health")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["database"], "unavailable");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn openapi_describes_health_endpoint() {
    let (status, body) = send(test_router(), get("/api/openapi.json")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["info"]["title"], "DScan API");
    assert!(body["paths"]["/api/v1/health"]["get"].is_object());
}

#[tokio::test]
async fn unknown_path_returns_json_404() {
    let (status, body) = send(test_router(), get("/api/v1/nie-ma")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "nie znaleziono zasobu");
}

#[tokio::test]
async fn too_large_body_is_rejected() {
    let request = Request::post("/api/v1/health")
        .header(header::CONTENT_LENGTH, MAX_BODY_BYTES + 1)
        .body(Body::from(vec![b'x'; MAX_BODY_BYTES + 1]))
        .unwrap();

    let (status, _) = send(test_router(), request).await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}
