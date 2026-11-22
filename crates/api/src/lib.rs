//! REST API DScan (axum).
//!
//! Routing, warstwy tower-http (logowanie żądań, limit rozmiaru, nagłówki bezpieczeństwa),
//! wspólna obsługa błędów, uwierzytelnianie (A2), cele, grupy i profile skanów (A5),
//! przebiegi skanów z prognozą czasu (S6) i opis OpenAPI.
//! Uprawnienia sprawdza middleware RBAC (A3); zmiany trafiają do dziennika audytu (A7).

pub mod audit;
pub mod auth;
mod error;
mod openapi;
mod router;
mod routes;
mod server;
mod state;

pub use error::{ApiError, ErrorBody};
pub use openapi::ApiDoc;
pub use router::{build_router, build_router_with};
pub use routes::defectdojo::{
    DojoResponse, ObservationRef, import_run as defectdojo_import_run,
    observations as defectdojo_observations,
};
pub use routes::health::{DatabaseStatus, HealthResponse};
pub use routes::profiles::{ProfileInput, WindowDto};
pub use routes::scans::ScanRunView;
pub use routes::validation::{clean_group, clean_note, validate_profile};
pub use server::serve;
pub use state::{AppState, AuthConfig};
