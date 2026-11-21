use axum::Form;
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use dscan_api::auth::{authenticate, clear_session_cookie, session_cookie, token_from_headers};
use dscan_api::{ApiError, AppState};
use serde::Deserialize;

use crate::pages::render;
use crate::views::LoginPage;

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

/// Formularz logowania; zalogowany użytkownik trafia od razu na pulpit.
pub async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if authenticate(&state, &headers).await?.is_some() {
        return Ok(Redirect::to("/").into_response());
    }
    Ok(render(&LoginPage {
        error: None,
        username: String::new(),
    })?
    .into_response())
}

/// Logowanie z formularza: ciasteczko sesji i przekierowanie na pulpit.
pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Result<Response, ApiError> {
    let username = form.username.trim();
    match dscan_api::auth::login(&state, username, &form.password).await {
        Ok(outcome) => {
            let max_age = i64::from(state.auth.session_hours) * 3600;
            let cookie = session_cookie(&outcome.token, max_age, state.auth.secure_cookies);
            Ok((AppendHeaders([(SET_COOKIE, cookie)]), Redirect::to("/")).into_response())
        }
        Err(ApiError::Unauthorized) => {
            let page = LoginPage {
                error: Some("Nieprawidłowy login lub hasło.".into()),
                username: username.into(),
            };
            Ok((StatusCode::UNAUTHORIZED, render(&page)?).into_response())
        }
        Err(error) => Err(error),
    }
}

/// Wylogowanie: usuwa sesję i wraca do formularza logowania.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = token_from_headers(&headers) {
        dscan_api::auth::logout(&state, &token).await?;
    }
    let cookie = clear_session_cookie(state.auth.secure_cookies);
    Ok((
        AppendHeaders([(SET_COOKIE, cookie)]),
        Redirect::to("/login"),
    )
        .into_response())
}
