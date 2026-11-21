use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use crate::AppState;

/// Stan połączenia z bazą danych.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseStatus {
    Ok,
    Unavailable,
}

/// Odpowiedź endpointu stanu usługi.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    /// `ok`, gdy wszystko działa; `degraded`, gdy baza jest niedostępna.
    pub status: String,
    pub version: String,
    pub database: DatabaseStatus,
}

/// Stan usługi i połączenia z bazą.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "system",
    responses((status = 200, description = "Stan usługi", body = HealthResponse))
)]
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let database = match dscan_db::check_connection(&state.db).await {
        Ok(()) => DatabaseStatus::Ok,
        Err(_) => DatabaseStatus::Unavailable,
    };

    Json(HealthResponse {
        status: overall_status(database).to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        database,
    })
}

/// Ogólny stan usługi wynikający ze stanu bazy.
pub fn overall_status(database: DatabaseStatus) -> &'static str {
    match database {
        DatabaseStatus::Ok => "ok",
        DatabaseStatus::Unavailable => "degraded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overall_status_depends_on_database() {
        assert_eq!(overall_status(DatabaseStatus::Ok), "ok");
        assert_eq!(overall_status(DatabaseStatus::Unavailable), "degraded");
    }
}
