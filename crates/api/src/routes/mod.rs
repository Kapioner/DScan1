//! Handlery endpointów, po jednym pliku na obszar.

pub mod accounts;
pub mod audit_log;
pub mod dashboard;
pub mod defectdojo;
pub mod exports;
pub mod health;
pub mod imports;
pub mod profiles;
pub mod results;
pub mod scan_control;
pub mod scans;
pub mod search;
pub mod signatures;
pub mod targets;
pub mod users;
pub mod validation;

use crate::ApiError;

/// Odpowiedź dla nieistniejących ścieżek (JSON zamiast pustej strony 404).
pub async fn not_found() -> ApiError {
    ApiError::NotFound
}
