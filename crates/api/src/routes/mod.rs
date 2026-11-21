//! Handlery endpointów, po jednym pliku na obszar.

pub mod health;
pub mod profiles;
pub mod results;
pub mod scans;
pub mod targets;
pub mod validation;

use crate::ApiError;

/// Odpowiedź dla nieistniejących ścieżek (JSON zamiast pustej strony 404).
pub async fn not_found() -> ApiError {
    ApiError::NotFound
}
