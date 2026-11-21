//! Handlery endpointów, po jednym pliku na obszar.

pub mod health;

use crate::ApiError;

/// Odpowiedź dla nieistniejących ścieżek (JSON zamiast pustej strony 404).
pub async fn not_found() -> ApiError {
    ApiError::NotFound
}
