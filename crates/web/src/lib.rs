//! Interfejs WWW (zadanie F1): strony renderowane w Ruście szablonami askama,
//! interakcje przez htmx (dołączony do binarki — działa bez internetu).
//!
//! Na tym etapie: układ strony, logowanie i wylogowanie, menu zależne od roli,
//! pulpit z listą przebiegów odświeżaną co 5 s, formularz celów (F3: wpis ręczny, wgranie
//! CSV/JSON z podglądem błędów, usuwanie) oraz listy profili i użytkowników.

mod assets;
mod login;
mod menu;
mod pages;
mod session;
mod targets_form;
mod views;

use axum::Router;
use axum::http::HeaderValue;
use axum::http::header::CONTENT_SECURITY_POLICY;
use axum::routing::{delete, get, post};
use dscan_api::AppState;
use tower_http::set_header::SetResponseHeaderLayer;

pub use menu::{MenuItem, menu_for};

/// Tylko zasoby z własnego serwera; brak skryptów i stylów wstawianych w HTML.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

/// Trasy interfejsu WWW do połączenia z API (`dscan_api::build_router_with`).
pub fn web_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(pages::dashboard))
        .route("/targets", get(pages::targets))
        .route("/profiles", get(pages::profiles))
        .route("/users", get(pages::users))
        .route("/ui/partials/scans", get(pages::scans_partial))
        .route("/ui/targets", post(targets_form::add_target))
        .route("/ui/targets/import", post(targets_form::import_file))
        .route("/ui/targets/{id}", delete(targets_form::delete_target))
        .route("/login", get(login::login_page).post(login::login_submit))
        .route("/logout", post(login::logout))
        .route("/static/htmx.min.js", get(assets::htmx))
        .route("/static/style.css", get(assets::stylesheet))
        .layer(SetResponseHeaderLayer::overriding(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
}
