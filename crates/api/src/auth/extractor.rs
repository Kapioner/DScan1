use axum::extract::FromRequestParts;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use dscan_crypto::hash_token;
use dscan_db::SessionUser;

use super::permissions;
use super::token_from_headers;
use crate::{ApiError, AppState};

/// Zalogowany użytkownik. Handler z parametrem `CurrentUser` odpowiada 401 bez ważnej sesji.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub SessionUser);

impl CurrentUser {
    /// Czy użytkownik ma uprawnienie (rola z `admin` ma wszystkie).
    pub fn has(&self, permission: &str) -> bool {
        self.0
            .permissions
            .iter()
            .any(|granted| granted == permission || granted == permissions::ADMIN)
    }

    /// `Forbidden`, gdy brakuje uprawnienia.
    pub fn require(&self, permission: &str) -> Result<(), ApiError> {
        if self.has(permission) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

/// Użytkownik sesji z nagłówków żądania (`None` = brak lub nieważna sesja).
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<SessionUser>, ApiError> {
    let Some(token) = token_from_headers(headers) else {
        return Ok(None);
    };
    Ok(dscan_db::find_session_user(&state.db, &hash_token(&token)).await?)
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        authenticate(state, &parts.headers)
            .await?
            .map(CurrentUser)
            .ok_or(ApiError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(permissions: &[&str]) -> CurrentUser {
        CurrentUser(SessionUser {
            id: 1,
            username: "jan".into(),
            role: "x".into(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
        })
    }

    #[test]
    fn permission_check() {
        assert!(user(&["read"]).has("read"));
        assert!(!user(&["read"]).has("targets:write"));
        assert!(user(&["admin"]).has("targets:write"));
        assert!(matches!(
            user(&["read"]).require("admin"),
            Err(ApiError::Forbidden)
        ));
    }
}
