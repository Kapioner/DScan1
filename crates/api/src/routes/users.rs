//! Lista użytkowników (tylko administracja). Pełne zarządzanie kontami — zadanie A4.

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

use crate::auth::{CurrentUser, permissions};
use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListItem {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_blocked: bool,
    pub created_at: DateTime<Utc>,
}

/// Wszyscy użytkownicy z rolami.
#[utoipa::path(get, path = "/api/v1/users", tag = "użytkownicy",
    responses((status = 200, body = [UserListItem]), (status = 403, body = crate::ErrorBody)))]
pub async fn list_users(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<UserListItem>>, ApiError> {
    user.require(permissions::ADMIN)?;
    let users = dscan_db::list_users(&state.db).await?;
    Ok(Json(
        users
            .into_iter()
            .map(|u| UserListItem {
                id: u.id,
                username: u.username,
                role: u.role,
                is_blocked: u.is_blocked,
                created_at: u.created_at,
            })
            .collect(),
    ))
}
