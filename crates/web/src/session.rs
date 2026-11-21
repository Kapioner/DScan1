use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use dscan_api::AppState;
use dscan_api::auth::{CurrentUser, authenticate};

/// Zalogowany użytkownik strony WWW. Bez sesji przekierowuje na `/login`
/// (dla żądań htmx: nagłówek `HX-Redirect`, żeby przeładować całą stronę, a nie fragment).
pub struct WebUser(pub CurrentUser);

impl FromRequestParts<AppState> for WebUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        match authenticate(state, &parts.headers).await {
            Ok(Some(user)) => Ok(WebUser(CurrentUser(user))),
            Ok(None) if parts.headers.contains_key("hx-request") => {
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                response
                    .headers_mut()
                    .insert("hx-redirect", HeaderValue::from_static("/login"));
                Err(response)
            }
            Ok(None) => Err(Redirect::to("/login").into_response()),
            Err(error) => Err(error.into_response()),
        }
    }
}
