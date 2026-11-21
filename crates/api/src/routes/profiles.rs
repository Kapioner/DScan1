//! Profile skanów (zadanie A5): grupa celów, tryb, porty, okna czasowe i częstotliwość.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use dscan_db::{ProfileSaved, ScanProfile};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::validation::validate_profile;
use crate::auth::{CurrentUser, permissions};
use crate::{ApiError, AppState};

/// Okno czasowe skanowania (`HH:MM`; może przechodzić przez północ).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WindowDto {
    pub start: String,
    pub end: String,
}

/// Dane profilu przy tworzeniu i edycji.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ProfileInput {
    pub name: String,
    /// `discovery` (tylko aktywne hosty) albo `services` (porty i usługi).
    pub mode: String,
    /// Grupa celów; brak = wszystkie cele.
    pub target_group: Option<String>,
    /// Porty (np. `"22"`, `"8000-8100"`); puste = `[scope] allowed_ports`.
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub windows: Vec<WindowDto>,
    /// Co ile minut uruchamiać (min. 5); brak = tylko ręcznie.
    pub frequency_minutes: Option<i32>,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProfileView {
    pub id: i64,
    pub name: String,
    pub mode: String,
    pub target_group: Option<String>,
    pub ports: Vec<String>,
    pub windows: Vec<WindowDto>,
    pub frequency_minutes: Option<i32>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ScanProfile> for ProfileView {
    fn from(profile: ScanProfile) -> Self {
        let data = profile.data;
        ProfileView {
            id: profile.id,
            name: data.name,
            mode: data.mode,
            target_group: data.target_group,
            ports: data.ports,
            windows: data
                .windows
                .into_iter()
                .map(|w| WindowDto {
                    start: w.start,
                    end: w.end,
                })
                .collect(),
            frequency_minutes: data.frequency_minutes,
            enabled: data.enabled,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        }
    }
}

fn saved(result: ProfileSaved) -> Result<ProfileView, ApiError> {
    match result {
        ProfileSaved::Saved(profile) => Ok(profile.into()),
        ProfileSaved::NameTaken => Err(ApiError::Conflict(
            "profil o tej nazwie już istnieje".into(),
        )),
        ProfileSaved::NotFound => Err(ApiError::NotFound),
    }
}

/// Lista profili.
#[utoipa::path(get, path = "/api/v1/profiles", tag = "profile", responses((status = 200, body = [ProfileView])))]
pub async fn list_profiles(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<ProfileView>>, ApiError> {
    user.require(permissions::READ)?;
    let profiles = dscan_db::list_profiles(&state.db).await?;
    Ok(Json(profiles.into_iter().map(ProfileView::from).collect()))
}

/// Tworzy profil.
#[utoipa::path(post, path = "/api/v1/profiles", tag = "profile", request_body = ProfileInput,
    responses((status = 201, body = ProfileView), (status = 400, body = crate::ErrorBody), (status = 409, body = crate::ErrorBody)))]
pub async fn create_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<ProfileInput>,
) -> Result<(StatusCode, Json<ProfileView>), ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let data = validate_profile(input)?;
    let view = saved(dscan_db::create_profile(&state.db, &data).await?)?;
    Ok((StatusCode::CREATED, Json(view)))
}

/// Jeden profil.
#[utoipa::path(get, path = "/api/v1/profiles/{id}", tag = "profile", params(("id" = i64, Path)),
    responses((status = 200, body = ProfileView), (status = 404, body = crate::ErrorBody)))]
pub async fn get_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<Json<ProfileView>, ApiError> {
    user.require(permissions::READ)?;
    let profile = dscan_db::get_profile(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(profile.into()))
}

/// Zastępuje wszystkie pola profilu.
#[utoipa::path(put, path = "/api/v1/profiles/{id}", tag = "profile", params(("id" = i64, Path)), request_body = ProfileInput,
    responses((status = 200, body = ProfileView), (status = 404, body = crate::ErrorBody)))]
pub async fn update_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
    Json(input): Json<ProfileInput>,
) -> Result<Json<ProfileView>, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let data = validate_profile(input)?;
    Ok(Json(saved(
        dscan_db::update_profile(&state.db, id, &data).await?,
    )?))
}

/// Usuwa profil.
#[utoipa::path(delete, path = "/api/v1/profiles/{id}", tag = "profile", params(("id" = i64, Path)),
    responses((status = 204), (status = 404, body = crate::ErrorBody)))]
pub async fn delete_profile(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    if dscan_db::delete_profile(&state.db, id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}
