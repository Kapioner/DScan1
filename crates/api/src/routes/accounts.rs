//! Zarządzanie kontami i rolami (A4) — tylko administracja (wymusza RBAC).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use dscan_auth::{hash_password, validate_password_strength, validate_username};
use dscan_db::{AccountChange, validate_role};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct UserDetailsView {
    pub id: i64,
    pub username: String,
    pub role_id: i64,
    pub role: String,
    pub is_blocked: bool,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleView {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>,
    pub built_in: bool,
    pub users: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewUser {
    pub username: String,
    pub password: String,
    pub role_id: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UserChanges {
    pub role_id: i64,
    pub blocked: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewPassword {
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RoleInput {
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Created {
    pub id: i64,
}

/// Wynik operacji na koncie/roli jako odpowiedź HTTP.
pub fn to_result(change: AccountChange) -> Result<i64, ApiError> {
    match change {
        AccountChange::Done(id) => Ok(id),
        AccountChange::NameTaken => Err(ApiError::Conflict("nazwa jest już zajęta".into())),
        AccountChange::NotFound => Err(ApiError::NotFound),
        AccountChange::Refused(reason) => Err(ApiError::BadRequest(reason.into())),
    }
}

fn bad(error: impl ToString) -> ApiError {
    ApiError::BadRequest(error.to_string())
}

/// Konta z rolami i ostatnim logowaniem.
#[utoipa::path(get, path = "/api/v1/accounts", tag = "użytkownicy", responses((status = 200, body = [UserDetailsView])))]
pub async fn list_accounts(
    State(state): State<AppState>,
) -> Result<Json<Vec<UserDetailsView>>, ApiError> {
    let users = dscan_db::list_user_details(&state.db).await?;
    Ok(Json(
        users
            .into_iter()
            .map(|u| UserDetailsView {
                id: u.id,
                username: u.username,
                role_id: u.role_id,
                role: u.role,
                is_blocked: u.is_blocked,
                last_login_at: u.last_login_at,
            })
            .collect(),
    ))
}

/// Tworzy konto (hasło min. 12 znaków, skrót argon2id).
#[utoipa::path(post, path = "/api/v1/users", tag = "użytkownicy", request_body = NewUser,
    responses((status = 201, body = Created), (status = 400, body = crate::ErrorBody), (status = 409, body = crate::ErrorBody)))]
pub async fn create_user(
    State(state): State<AppState>,
    admin: CurrentUser,
    Json(input): Json<NewUser>,
) -> Result<(StatusCode, Json<Created>), ApiError> {
    validate_username(&input.username).map_err(bad)?;
    validate_password_strength(&input.password).map_err(bad)?;
    let hash = hash_password(&input.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    let id =
        to_result(dscan_db::create_user(&state.db, &input.username, &hash, input.role_id).await?)?;
    crate::audit::record(&state, &admin, "create", "user", id, &input.username).await;
    Ok((StatusCode::CREATED, Json(Created { id })))
}

/// Zmienia rolę i blokadę konta (zablokowanie kończy sesje).
#[utoipa::path(put, path = "/api/v1/users/{id}", tag = "użytkownicy", params(("id" = i64, Path)), request_body = UserChanges,
    responses((status = 204), (status = 400, body = crate::ErrorBody), (status = 404, body = crate::ErrorBody)))]
pub async fn update_user(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(id): Path<i64>,
    Json(input): Json<UserChanges>,
) -> Result<StatusCode, ApiError> {
    to_result(dscan_db::update_user(&state.db, id, input.role_id, input.blocked).await?)?;
    let details = format!("role_id={}, blocked={}", input.role_id, input.blocked);
    crate::audit::record(&state, &admin, "update", "user", id, &details).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Ustawia nowe hasło konta (sesje konta są kończone).
#[utoipa::path(put, path = "/api/v1/users/{id}/password", tag = "użytkownicy", params(("id" = i64, Path)), request_body = NewPassword,
    responses((status = 204), (status = 400, body = crate::ErrorBody)))]
pub async fn set_password(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(id): Path<i64>,
    Json(input): Json<NewPassword>,
) -> Result<StatusCode, ApiError> {
    validate_password_strength(&input.password).map_err(bad)?;
    let hash = hash_password(&input.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    to_result(dscan_db::set_password(&state.db, id, &hash).await?)?;
    crate::audit::record(&state, &admin, "password", "user", id, "").await;
    Ok(StatusCode::NO_CONTENT)
}

/// Role z uprawnieniami i liczbą kont.
#[utoipa::path(get, path = "/api/v1/roles", tag = "użytkownicy", responses((status = 200, body = [RoleView])))]
pub async fn list_roles(State(state): State<AppState>) -> Result<Json<Vec<RoleView>>, ApiError> {
    let roles = dscan_db::list_roles(&state.db).await?;
    Ok(Json(
        roles
            .into_iter()
            .map(|r| RoleView {
                id: r.id,
                name: r.name,
                permissions: r.permissions,
                built_in: r.built_in,
                users: r.users,
            })
            .collect(),
    ))
}

fn clean_role(input: RoleInput) -> Result<(String, Vec<String>), ApiError> {
    let mut permissions = input.permissions;
    permissions.sort();
    permissions.dedup();
    validate_role(&input.name, &permissions).map_err(ApiError::BadRequest)?;
    Ok((input.name.trim().to_string(), permissions))
}

/// Nowa rola z zestawu uprawnień (`admin`, `targets:write`, `results:write`, `read`).
#[utoipa::path(post, path = "/api/v1/roles", tag = "użytkownicy", request_body = RoleInput,
    responses((status = 201, body = Created), (status = 400, body = crate::ErrorBody), (status = 409, body = crate::ErrorBody)))]
pub async fn create_role(
    State(state): State<AppState>,
    admin: CurrentUser,
    Json(input): Json<RoleInput>,
) -> Result<(StatusCode, Json<Created>), ApiError> {
    let (name, permissions) = clean_role(input)?;
    let id = to_result(dscan_db::create_role(&state.db, &name, &permissions).await?)?;
    crate::audit::record(
        &state,
        &admin,
        "create",
        "role",
        id,
        &format!("{name}: {}", permissions.join(",")),
    )
    .await;
    Ok((StatusCode::CREATED, Json(Created { id })))
}

/// Zmienia rolę własną (wbudowanych nie można).
#[utoipa::path(put, path = "/api/v1/roles/{id}", tag = "użytkownicy", params(("id" = i64, Path)), request_body = RoleInput,
    responses((status = 204), (status = 400, body = crate::ErrorBody)))]
pub async fn update_role(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(id): Path<i64>,
    Json(input): Json<RoleInput>,
) -> Result<StatusCode, ApiError> {
    let (name, permissions) = clean_role(input)?;
    to_result(dscan_db::update_role(&state.db, id, &name, &permissions).await?)?;
    crate::audit::record(
        &state,
        &admin,
        "update",
        "role",
        id,
        &format!("{name}: {}", permissions.join(",")),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Usuwa rolę własną bez kont.
#[utoipa::path(delete, path = "/api/v1/roles/{id}", tag = "użytkownicy", params(("id" = i64, Path)),
    responses((status = 204), (status = 400, body = crate::ErrorBody)))]
pub async fn delete_role(
    State(state): State<AppState>,
    admin: CurrentUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    to_result(dscan_db::delete_role(&state.db, id).await?)?;
    crate::audit::record(&state, &admin, "delete", "role", id, "").await;
    Ok(StatusCode::NO_CONTENT)
}
