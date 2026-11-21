//! REST API DScan (axum).
//!
//! Na tym etapie: routing, warstwy tower-http (logowanie żądań, limit rozmiaru),
//! wspólna obsługa błędów, endpoint stanu usługi, przebiegi skanów z prognozą czasu
//! do końca (S6) i opis OpenAPI.
//! Uwierzytelnianie i RBAC dojdą w zadaniach A2/A3.

mod error;
mod openapi;
mod router;
mod routes;
mod server;
mod state;

pub use error::{ApiError, ErrorBody};
pub use openapi::ApiDoc;
pub use router::build_router;
pub use routes::health::{DatabaseStatus, HealthResponse};
pub use routes::scans::ScanRunView;
pub use server::serve;
pub use state::AppState;
