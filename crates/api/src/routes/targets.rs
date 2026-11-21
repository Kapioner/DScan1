//! Cele i grupy celów (zadanie A5).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use dscan_core::models::Target;
use dscan_db::StoredTarget;
use dscan_scanner::targets::parse_target;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::validation::{clean_group, clean_note};
use crate::auth::{CurrentUser, permissions};
use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct TargetView {
    pub id: i64,
    /// `ip`, `cidr` albo `domain`.
    pub kind: String,
    pub value: String,
    pub group: Option<String>,
    pub note: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<StoredTarget> for TargetView {
    fn from(target: StoredTarget) -> Self {
        TargetView {
            id: target.id,
            kind: target.kind,
            value: target.value,
            group: target.group,
            note: target.note,
            created_at: target.created_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTarget {
    /// Adres IP, sieć CIDR albo domena.
    pub target: String,
    pub group: Option<String>,
    pub note: Option<String>,
}

/// Nowa grupa i notatka celu (obie wartości są zastępowane; `null` czyści pole).
#[derive(Debug, Deserialize, ToSchema)]
pub struct TargetChanges {
    pub group: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct GroupView {
    pub name: String,
    pub targets: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TargetFilter {
    /// Tylko cele z tej grupy.
    pub group: Option<String>,
}

/// Lista celów.
#[utoipa::path(get, path = "/api/v1/targets", tag = "cele", params(TargetFilter),
    responses((status = 200, body = [TargetView]), (status = 401, body = crate::ErrorBody)))]
pub async fn list_targets(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(filter): Query<TargetFilter>,
) -> Result<Json<Vec<TargetView>>, ApiError> {
    user.require(permissions::READ)?;
    let targets = dscan_db::list_targets(&state.db, &state.cipher, filter.group.as_deref()).await?;
    Ok(Json(targets.into_iter().map(TargetView::from).collect()))
}

/// Dodaje cel.
#[utoipa::path(post, path = "/api/v1/targets", tag = "cele", request_body = NewTarget,
    responses((status = 201, body = TargetView), (status = 400, body = crate::ErrorBody),
              (status = 409, description = "Cel już istnieje", body = crate::ErrorBody)))]
pub async fn create_target(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<NewTarget>,
) -> Result<(StatusCode, Json<TargetView>), ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let kind =
        parse_target(&input.target).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let target = Target {
        kind,
        group: clean_group(input.group)?,
        note: clean_note(input.note)?,
    };
    let created = dscan_db::create_target(&state.db, &state.cipher, &target)
        .await?
        .ok_or_else(|| ApiError::Conflict(format!("cel {} już istnieje", target.kind)))?;
    crate::audit::record(
        &state,
        &user,
        "create",
        "target",
        created.id,
        &created.value,
    )
    .await;
    Ok((StatusCode::CREATED, Json(created.into())))
}

/// Jeden cel.
#[utoipa::path(get, path = "/api/v1/targets/{id}", tag = "cele", params(("id" = i64, Path)),
    responses((status = 200, body = TargetView), (status = 404, body = crate::ErrorBody)))]
pub async fn get_target(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<Json<TargetView>, ApiError> {
    user.require(permissions::READ)?;
    let target = dscan_db::get_target(&state.db, &state.cipher, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(target.into()))
}

/// Zmienia grupę i notatkę celu.
#[utoipa::path(put, path = "/api/v1/targets/{id}", tag = "cele", params(("id" = i64, Path)),
    request_body = TargetChanges, responses((status = 200, body = TargetView), (status = 404, body = crate::ErrorBody)))]
pub async fn update_target(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Json(changes): Json<TargetChanges>,
) -> Result<Json<TargetView>, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let group = clean_group(changes.group)?;
    let note = clean_note(changes.note)?;
    let target = dscan_db::update_target(
        &state.db,
        &state.cipher,
        id,
        group.as_deref(),
        note.as_ref(),
    )
    .await?
    .ok_or(ApiError::NotFound)?;
    crate::audit::record(&state, &user, "update", "target", id, "grupa i notatka").await;
    Ok(Json(target.into()))
}

/// Usuwa cel.
#[utoipa::path(delete, path = "/api/v1/targets/{id}", tag = "cele", params(("id" = i64, Path)),
    responses((status = 204), (status = 404, body = crate::ErrorBody)))]
pub async fn delete_target(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    if dscan_db::delete_target(&state.db, id).await? {
        crate::audit::record(&state, &user, "delete", "target", id, "").await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

/// Grupy celów z liczbą celów.
#[utoipa::path(get, path = "/api/v1/groups", tag = "cele", responses((status = 200, body = [GroupView])))]
pub async fn list_groups(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<GroupView>>, ApiError> {
    user.require(permissions::READ)?;
    let groups = dscan_db::list_target_groups(&state.db).await?;
    Ok(Json(
        groups
            .into_iter()
            .map(|group| GroupView {
                name: group.name,
                targets: group.targets,
            })
            .collect(),
    ))
}
