//! Tagi (F11) i klastry podobnych usług (M4) przez API.

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dscan_engine::clusters::{MAX_DISTANCE, service_clusters};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct TagView {
    pub id: i64,
    pub ip: String,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub tag: String,
}

#[utoipa::path(get, path = "/api/v1/tags", tag = "wyniki", responses((status = 200, body = [TagView])))]
pub async fn list_tags(State(state): State<AppState>) -> Result<Json<Vec<TagView>>, ApiError> {
    let tags = dscan_db::list_tags(&state.db).await?;
    Ok(Json(
        tags.into_iter()
            .map(|t| TagView {
                id: t.id,
                ip: t.ip.to_string(),
                port: t.port,
                protocol: t.protocol,
                tag: t.tag,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTag {
    #[schema(value_type = String)]
    pub ip: IpAddr,
    /// Brak = tag całego hosta.
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub tag: String,
}

#[utoipa::path(post, path = "/api/v1/tags", tag = "wyniki", request_body = NewTag,
    responses((status = 204), (status = 400, body = crate::ErrorBody)))]
pub async fn add_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<NewTag>,
) -> Result<StatusCode, ApiError> {
    let tag = dscan_db::normalize_tag(&input.tag)
        .ok_or_else(|| ApiError::BadRequest("tag musi mieć 1–40 znaków".into()))?;
    let protocol = input
        .port
        .map(|_| input.protocol.clone().unwrap_or_else(|| "tcp".into()));
    dscan_db::add_tag(
        &state.db,
        input.ip,
        input.port,
        protocol.as_deref(),
        &tag,
        Some(user.0.id),
    )
    .await?;
    crate::audit::record(&state, &user, "tag", "host", input.ip, &tag).await;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(delete, path = "/api/v1/tags/{id}", tag = "wyniki", params(("id" = i64, Path)),
    responses((status = 204), (status = 404, body = crate::ErrorBody)))]
pub async fn delete_tag(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    if !dscan_db::delete_tag(&state.db, id).await? {
        return Err(ApiError::NotFound);
    }
    crate::audit::record(&state, &user, "untag", "tag", id, "").await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClusterView {
    pub id: usize,
    pub label: String,
    pub technologies: Vec<String>,
    /// `IP:PORT/PROTOKÓŁ`
    pub members: Vec<String>,
}

/// Grupy podobnych usług WWW przebiegu (SimHash, co najmniej 2 usługi).
#[utoipa::path(get, path = "/api/v1/scans/{id}/clusters", tag = "wyniki", params(("id" = i64, Path)),
    responses((status = 200, body = [ClusterView])))]
pub async fn run_clusters(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ClusterView>>, ApiError> {
    dscan_db::get_scan_run(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let hosts = dscan_db::load_run_hosts(&state.db, id).await?;
    Ok(Json(
        service_clusters(&hosts, MAX_DISTANCE, 2)
            .into_iter()
            .map(|c| ClusterView {
                id: c.id,
                label: c.label,
                technologies: c.technologies,
                members: c
                    .members
                    .into_iter()
                    .map(|m| format!("{}:{}/{}", m.ip, m.port, m.protocol))
                    .collect(),
            })
            .collect(),
    ))
}
