//! Testy interfejsu WWW bez działającej bazy (pula łączy się leniwie z nieistniejącym adresem).

// Plik testowy: unwrap() w funkcjach pomocniczych jest tu dozwolony.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use dscan_api::{AppState, AuthConfig, build_router_with};
use dscan_crypto::Cipher;
use dscan_db::{PoolOptions, connect_lazy};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn app() -> Router {
    let options = PoolOptions {
        max_connections: 1,
        connect_timeout: Duration::from_millis(300),
    };
    let pool = connect_lazy("postgres://nikt:nic@127.0.0.1:1/brak", options).unwrap();
    let state = AppState::new(
        pool,
        Cipher::new(&[1; 32]),
        AuthConfig {
            session_hours: 1,
            secure_cookies: false,
        },
    );
    build_router_with(state, 1 << 20, dscan_web::web_routes())
}

async fn get(
    path: &str,
    extra: Option<(&str, &str)>,
) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut request = Request::get(path);
    if let Some((name, value)) = extra {
        request = request.header(name, value);
    }
    let response = app()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn pages_without_session_redirect_to_login() {
    for path in ["/", "/targets", "/profiles", "/users"] {
        let (status, headers, _) = get(path, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{path}");
        assert_eq!(headers[header::LOCATION], "/login");
    }
}

#[tokio::test]
async fn htmx_request_without_session_gets_hx_redirect() {
    let (status, headers, _) = get("/ui/partials/scans", Some(("hx-request", "true"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers["hx-redirect"], "/login");
}

#[tokio::test]
async fn login_page_has_form_and_security_headers() {
    let (status, headers, body) = get("/login", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#"<form class="card login" method="post" action="/login">"#));
    assert!(body.contains(r#"name="password" type="password""#));
    let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("default-src 'self'") && csp.contains("frame-ancestors 'none'"));
    assert_eq!(headers["x-frame-options"], "DENY");
}

#[tokio::test]
async fn static_assets_are_served_from_binary() {
    let (status, headers, body) = get("/static/htmx.min.js", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
    assert!(body.starts_with("var htmx="));

    let (status, headers, _) = get("/static/style.css", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/css")
    );
}

#[tokio::test]
async fn api_still_works_next_to_web_routes() {
    let (status, _, body) = get("/api/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains(r#""status":"degraded""#));
}
