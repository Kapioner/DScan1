use axum::Router;
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post, put};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer};
use tracing::Level;

use crate::AppState;
use crate::auth::authorize;
use crate::auth::handlers::{login, logout, me};
use crate::openapi::openapi_json;
use crate::routes::dashboard::dashboard;
use crate::routes::exports::export;
use crate::routes::imports::{import_results_handler, import_targets_handler};
use crate::routes::profiles::{
    create_profile, delete_profile, get_profile, list_profiles, update_profile,
};
use crate::routes::results::{delete_override, list_overrides, run_hosts, set_override};
use crate::routes::scan_control::{
    config_profiles, diff, resume_scan, run_changes, start_scan, stop_scan,
};
use crate::routes::scans::{get_scan, list_scans};
use crate::routes::signatures::{list_signatures, test_signature};
use crate::routes::targets::{
    create_target, delete_target, get_target, list_groups, list_targets, update_target,
};
use crate::routes::users::list_users;
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
    // Middleware RBAC na każdej trasie API (route_layer: działa po dopasowaniu trasy,
    // więc zna jej wzorzec, np. /api/v1/targets/{id}).
    let api = api_routes().route_layer(from_fn_with_state(state.clone(), authorize));
    Router::new()
        .merge(api)
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
        .route("/api/v1/scans", get(list_scans).post(start_scan))
        .route("/api/v1/scans/{id}/stop", post(stop_scan))
        .route("/api/v1/scans/{id}/resume", post(resume_scan))
        .route("/api/v1/scans/{id}/changes", get(run_changes))
        .route("/api/v1/diff", get(diff))
        .route("/api/v1/scan-profiles", get(config_profiles))
        .route("/api/v1/imports/targets", post(import_targets_handler))
        .route("/api/v1/imports/results", post(import_results_handler))
        .route("/api/v1/exports/{kind}", get(export))
        .route("/api/v1/signatures", get(list_signatures))
        .route("/api/v1/signatures/test", post(test_signature))
        .route("/api/v1/dashboard", get(dashboard))
        .route("/api/v1/search", get(crate::routes::search::search))
        .route("/api/v1/scans/{id}", get(get_scan))
        .route("/api/v1/scans/{id}/hosts", get(run_hosts))
        .route(
            "/api/v1/overrides",
            get(list_overrides)
                .put(set_override)
                .delete(delete_override),
        )
        .route(
            "/api/v1/users",
            get(list_users).post(crate::routes::accounts::create_user),
        )
        .route(
            "/api/v1/users/{id}",
            put(crate::routes::accounts::update_user),
        )
        .route(
            "/api/v1/users/{id}/password",
            put(crate::routes::accounts::set_password),
        )
        .route(
            "/api/v1/accounts",
            get(crate::routes::accounts::list_accounts),
        )
        .route(
            "/api/v1/roles",
            get(crate::routes::accounts::list_roles).post(crate::routes::accounts::create_role),
        )
        .route(
            "/api/v1/roles/{id}",
            put(crate::routes::accounts::update_role).delete(crate::routes::accounts::delete_role),
        )
        .route(
            "/api/v1/defectdojo/import",
            post(crate::routes::defectdojo::dojo_import),
        )
        .route(
            "/api/v1/defectdojo/findings",
            post(crate::routes::defectdojo::dojo_findings),
        )
        .route("/api/v1/audit", get(crate::routes::audit_log::audit_log))
        .route("/api/openapi.json", get(openapi_json))
}

/// Nagłówek bezpieczeństwa dodawany do każdej odpowiedzi (jeśli handler go nie ustawił).
fn security_header(name: &'static str, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static(name),
        HeaderValue::from_static(value),
    )
}
