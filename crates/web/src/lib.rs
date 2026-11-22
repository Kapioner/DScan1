//! Interfejs WWW (zadanie F1): strony renderowane w Ruście szablonami askama,
//! interakcje przez htmx (dołączony do binarki — działa bez internetu).
//!
//! Na tym etapie: układ strony, logowanie i wylogowanie, menu zależne od roli,
//! pulpit (F2: znaleziska, zmiany, technologie, postęp skanów, formularz „Uruchom skan”
//! z wyborem profilu, wstrzymanie i wznowienie), lista przebiegów odświeżana co 5 s, formularz celów (F3: wpis ręczny, wgranie
//! CSV/JSON z podglądem błędów, usuwanie) oraz listy profili i użytkowników.

mod admin;
mod assets;
mod clusters_ui;
mod compare;
mod dashboard;
mod dojo_ui;
mod edits;
mod host_views;
mod hosts;
mod login;
mod menu;
mod pages;
mod profiles_form;
mod service_view;
mod session;
mod signatures_ui;
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
        .route("/hosts", get(hosts::hosts_page))
        .route("/hosts/{ip}", get(hosts::host_page))
        .route("/ui/hosts/{ip}/edit", post(edits::edit_result))
        .route("/ui/hosts/{ip}/dojo", post(dojo_ui::send_to_dojo))
        .route("/signatures", get(signatures_ui::signatures_page))
        .route("/ui/signatures", post(signatures_ui::save_signature))
        .route("/ui/signatures/test", post(signatures_ui::test_signature))
        .route(
            "/ui/signatures/{id}/delete",
            post(signatures_ui::delete_signature),
        )
        .route("/clusters", get(clusters_ui::clusters_page))
        .route("/ui/clusters/tag", post(clusters_ui::tag_cluster))
        .route("/ui/hosts/{ip}/tags", post(clusters_ui::add_tag))
        .route(
            "/ui/hosts/{ip}/tags/{id}/delete",
            post(clusters_ui::delete_tag),
        )
        .route("/compare", get(compare::compare_page))
        .route("/ui/profiles", post(profiles_form::create_profile))
        .route("/ui/profiles/{id}", post(profiles_form::update_profile))
        .route(
            "/ui/profiles/{id}/delete",
            post(profiles_form::delete_profile),
        )
        .route("/users", get(admin::users_page))
        .route("/ui/users", post(admin::create_account))
        .route("/ui/users/{id}", post(admin::update_account))
        .route("/ui/roles", post(admin::save_role))
        .route("/ui/roles/{id}", post(admin::save_role))
        .route("/ui/roles/{id}/delete", post(admin::delete_role))
        .route("/audit", get(admin::audit_page))
        .route("/ui/partials/scans", get(pages::scans_partial))
        .route("/ui/partials/overview", get(dashboard::overview_partial))
        .route("/ui/scans", post(dashboard::start_scan))
        .route("/ui/scans/{id}/{action}", post(dashboard::control_scan))
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
