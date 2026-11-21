use axum::Router;
use axum::routing::get;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::AppState;
use crate::openapi::openapi_json;
use crate::routes::scans::{get_scan, list_scans};
use crate::routes::{health::health, not_found};

/// Składa wszystkie endpointy i warstwy w jeden router.
pub fn build_router(state: AppState, max_body_bytes: usize) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/scans", get(list_scans))
        .route("/api/v1/scans/{id}", get(get_scan))
        .route("/api/openapi.json", get(openapi_json))
        .fallback(not_found)
        // Za duże żądanie kończy się 413 jeszcze przed handlerem.
        .layer(RequestBodyLimitLayer::new(max_body_bytes))
        // Każde żądanie (metoda, ścieżka, status, czas) trafia do logów.
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state)
}
