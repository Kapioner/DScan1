//! Odczyt dziennika audytu (A7) — tylko administracja.

use axum::Json;
use axum::extract::{Query, State};
use chrono::{DateTime, Utc};
use dscan_db::AuditFilter;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditParams {
    pub user: Option<String>,
    /// `user`, `role`, `target`, `profile`, `override`, `scan`, `import`, `export`.
    pub entity: Option<String>,
    pub action: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditView {
    pub id: i64,
    pub user: Option<String>,
    pub action: String,
    pub entity: String,
    pub entity_id: Option<String>,
    pub details: String,
    pub at: DateTime<Utc>,
}

/// Najnowsze wpisy dziennika (domyślnie 200, najwyżej 1000).
#[utoipa::path(get, path = "/api/v1/audit", tag = "użytkownicy", params(AuditParams), responses((status = 200, body = [AuditView])))]
pub async fn audit_log(
    State(state): State<AppState>,
    Query(params): Query<AuditParams>,
) -> Result<Json<Vec<AuditView>>, ApiError> {
    let filter = AuditFilter {
        username: params.user,
        entity: params.entity,
        action: params.action,
    };
    let limit = params.limit.unwrap_or(200).clamp(1, 1000);
    let records = dscan_db::list_audit(&state.db, &filter, limit).await?;
    Ok(Json(
        records
            .into_iter()
            .map(|r| AuditView {
                id: r.id,
                user: r.username,
                action: r.action,
                entity: r.entity,
                entity_id: r.entity_id,
                details: r.details,
                at: r.created_at,
            })
            .collect(),
    ))
}
