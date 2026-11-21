use axum::Json;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{AppendHeaders, IntoResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{CurrentUser, clear_session_cookie, session_cookie, token_from_headers};
use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Zalogowany użytkownik.
#[derive(Debug, Serialize, ToSchema)]
pub struct UserView {
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    /// Token do nagłówka `Authorization: Bearer …` (przeglądarka używa ciasteczka).
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub user: UserView,
}

impl From<&dscan_db::SessionUser> for UserView {
    fn from(user: &dscan_db::SessionUser) -> Self {
        UserView {
            username: user.username.clone(),
            role: user.role.clone(),
            permissions: user.permissions.clone(),
        }
    }
}

/// Logowanie: ustawia ciasteczko sesji i zwraca token.
#[utoipa::path(post, path = "/api/v1/auth/login", tag = "uwierzytelnianie", request_body = LoginRequest,
    responses((status = 200, body = LoginResponse), (status = 401, description = "Zły login lub hasło", body = crate::ErrorBody)))]
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let outcome = super::login(&state, request.username.trim(), &request.password).await?;
    let max_age = i64::from(state.auth.session_hours) * 3600;
    let cookie = session_cookie(&outcome.token, max_age, state.auth.secure_cookies);
    let body = LoginResponse {
        user: UserView::from(&outcome.user),
        token: outcome.token,
        expires_at: outcome.expires_at,
    };
    Ok((AppendHeaders([(SET_COOKIE, cookie)]), Json(body)))
}

/// Wylogowanie: usuwa sesję i ciasteczko.
#[utoipa::path(post, path = "/api/v1/auth/logout", tag = "uwierzytelnianie", responses((status = 204)))]
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(token) = token_from_headers(&headers) {
        super::logout(&state, &token).await?;
    }
    let cookie = clear_session_cookie(state.auth.secure_cookies);
    Ok((
        StatusCode::NO_CONTENT,
        AppendHeaders([(SET_COOKIE, cookie)]),
    ))
}

/// Dane zalogowanego użytkownika.
#[utoipa::path(get, path = "/api/v1/auth/me", tag = "uwierzytelnianie",
    responses((status = 200, body = UserView), (status = 401, body = crate::ErrorBody)))]
pub async fn me(user: CurrentUser) -> Json<UserView> {
    Json(UserView::from(&user.0))
}
