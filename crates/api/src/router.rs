use axum::Router;
use axum::http::{HeaderName, HeaderValue};
use axum::routing::{get, post};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::AppState;
use crate::auth::handlers::{login, logout, me};
use crate::openapi::openapi_json;
use crate::routes::profiles::{
    create_profile, delete_profile, get_profile, list_profiles, update_profile,
};
use crate::routes::scans::{get_scan, list_scans};
use crate::routes::targets::{
    create_target, delete_target, get_target, list_groups, list_targets, update_target,
};
use crate::routes::{health::health, not_found};

/// Router samego API (bez interfejsu WWW).
pub fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    build_router_with(state, max_body_bytes, Router::new())
}

/// API razem z dodatkowymi trasami (np. interfejsem WWW) i wspólnymi warstwami.
pub fn build_router_with(
    state: AppState,
    max_body_bytes: usize,
    extra: Router<AppState>,
) -> Router {
    Router::new()
        .merge(api_routes())
        .merge(extra)
        .fallback(not_found)
        // Za duże żądanie kończy się 413 jeszcze przed handlerem.
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        .layer(security_header("x-content-type-options", "nosniff"))
        .layer(security_header("x-frame-options", "DENY"))
        .layer(security_header("referrer-policy", "no-referrer"))
        // Każde żądanie (metoda, ścieżka, status, czas) trafia do logów.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/targets", get(list_targets).post(create_target))
        .route(
            "/api/v1/targets/{id}",
            get(get_target).put(update_target).delete(delete_target),
        )
        .route("/api/v1/groups", get(list_groups))
        .route("/api/v1/profiles", get(list_profiles).post(create_profile))
        .route(
            "/api/v1/profiles/{id}",
            get(get_profile).put(update_profile).delete(delete_profile),
        )
        .route("/api/v1/scans", get(list_scans))
        .route("/api/v1/scans/{id}", get(get_scan))
        .route("/api/openapi.json", get(openapi_json))
}

/// Nagłówek bezpieczeństwa dodawany do każdej odpowiedzi (jeśli handler go nie ustawił).
fn security_header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}
