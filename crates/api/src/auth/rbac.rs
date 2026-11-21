//! Kontrola dostępu oparta na rolach (zadanie A3).
//!
//! Każda trasa API ma w jednej tabeli ([`required_access`]) przypisany wymóg dostępu,
//! a middleware [`authorize`] sprawdza go dla **każdego** żądania, zanim trafi ono do handlera.
//! Trasa, której nie ma w tabeli, wymaga roli administratora (domyślna odmowa).
//!
//! Role (z migracji 0001):
//! | rola                              | uprawnienia                                |
//! |-----------------------------------|--------------------------------------------|
//! | administracja                     | admin (wszystko)                           |
//! | dodawanie_usuwanie_modyfikacja    | targets:write, results:write, read         |
//! | modyfikacja_odczyt                | results:write, read                        |
//! | odczyt                            | read                                       |

use axum::extract::{MatchedPath, Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::{CurrentUser, authenticate, permissions};
use crate::{ApiError, AppState};

/// Czego wymaga trasa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Bez logowania (stan usługi, logowanie, opis API).
    Public,
    /// Zalogowany użytkownik z danym uprawnieniem.
    Permission(&'static str),
}

/// Trasy publiczne: (metoda, wzorzec ścieżki).
const PUBLIC_ROUTES: [(&str, &str); 4] = [
    ("GET", "/api/v1/health"),
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/openapi.json"),
];

/// Zapis: (prefiks wzorca ścieżki, wymagane uprawnienie). Pierwsze dopasowanie wygrywa.
const WRITE_RULES: [(&str, &str); 7] = [
    ("/api/v1/targets", permissions::TARGETS_WRITE),
    ("/api/v1/profiles", permissions::TARGETS_WRITE),
    ("/api/v1/scans", permissions::TARGETS_WRITE),
    ("/api/v1/imports", permissions::TARGETS_WRITE),
    ("/api/v1/signatures", permissions::TARGETS_WRITE),
    ("/api/v1/overrides", permissions::RESULTS_WRITE),
    ("/api/v1/users", permissions::ADMIN),
];

/// Wymóg dostępu dla metody i wzorca trasy (np. `/api/v1/targets/{id}`).
pub fn required_access(method: &Method, route: &str) -> Access {
    if PUBLIC_ROUTES
        .iter()
        .any(|(m, path)| *m == method.as_str() && *path == route)
    {
        return Access::Public;
    }
    if method == Method::GET || method == Method::HEAD {
        return Access::Permission(if route.starts_with("/api/v1/users") {
            permissions::ADMIN
        } else {
            permissions::READ
        });
    }
    let rule = WRITE_RULES
        .iter()
        .find(|(prefix, _)| route.starts_with(prefix));
    Access::Permission(rule.map_or(permissions::ADMIN, |(_, permission)| permission))
}

/// Middleware: uwierzytelnia, sprawdza uprawnienie i przekazuje użytkownika handlerowi.
pub async fn authorize(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| request.uri().path().to_string());
    let Access::Permission(permission) = required_access(request.method(), &route) else {
        return next.run(request).await;
    };
    let user = match authenticate(&state, request.headers()).await {
        Ok(Some(user)) => CurrentUser(user),
        Ok(None) => return ApiError::Unauthorized.into_response(),
        Err(error) => return error.into_response(),
    };
    if !user.has(permission) {
        tracing::warn!(
            "odmowa dostępu: {} {} {route} (wymaga {permission})",
            user.0.username,
            request.method()
        );
        return ApiError::Forbidden.into_response();
    }
    request.extensions_mut().insert(user);
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(method: Method, route: &str) -> Access {
        required_access(&method, route)
    }

    #[test]
    fn public_routes() {
        assert_eq!(access(Method::GET, "/api/v1/health"), Access::Public);
        assert_eq!(access(Method::POST, "/api/v1/auth/login"), Access::Public);
        assert_eq!(
            access(Method::GET, "/api/v1/auth/login"),
            Access::Permission(permissions::READ)
        );
    }

    #[test]
    fn reads_need_read_permission() {
        for route in [
            "/api/v1/targets",
            "/api/v1/scans/{id}/hosts",
            "/api/v1/dashboard",
            "/api/v1/auth/me",
        ] {
            assert_eq!(
                access(Method::GET, route),
                Access::Permission(permissions::READ),
                "{route}"
            );
        }
    }

    #[test]
    fn writes_need_specific_permissions() {
        assert_eq!(
            access(Method::POST, "/api/v1/targets"),
            Access::Permission(permissions::TARGETS_WRITE)
        );
        assert_eq!(
            access(Method::DELETE, "/api/v1/profiles/{id}"),
            Access::Permission(permissions::TARGETS_WRITE)
        );
        assert_eq!(
            access(Method::PUT, "/api/v1/overrides"),
            Access::Permission(permissions::RESULTS_WRITE)
        );
        assert_eq!(
            access(Method::POST, "/api/v1/users"),
            Access::Permission(permissions::ADMIN)
        );
        assert_eq!(
            access(Method::GET, "/api/v1/users"),
            Access::Permission(permissions::ADMIN)
        );
    }

    #[test]
    fn unknown_write_routes_require_admin() {
        assert_eq!(
            access(Method::POST, "/api/v1/cos-nowego"),
            Access::Permission(permissions::ADMIN)
        );
    }
}
