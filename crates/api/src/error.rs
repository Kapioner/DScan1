use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// Treść odpowiedzi z błędem — taka sama dla wszystkich endpointów.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// Błędy zwracane przez handlery API.
#[derive(Debug)]
pub enum ApiError {
    NotFound,
    BadRequest(String),
    /// Brak ważnej sesji albo złe dane logowania.
    Unauthorized,
    /// Zalogowany, ale bez wymaganego uprawnienia.
    Forbidden,
    Conflict(String),
    /// Szczegóły trafiają tylko do logów — klient dostaje ogólny komunikat.
    Internal(String),
}

impl ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn public_message(&self) -> String {
        match self {
            ApiError::NotFound => "nie znaleziono zasobu".to_string(),
            ApiError::BadRequest(reason) | ApiError::Conflict(reason) => reason.clone(),
            ApiError::Unauthorized => "wymagane zalogowanie".to_string(),
            ApiError::Forbidden => "brak uprawnień do tej operacji".to_string(),
            ApiError::Internal(_) => "wewnętrzny błąd serwera".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(details) = &self {
            tracing::error!("błąd wewnętrzny: {details}");
        }
        let body = ErrorBody {
            error: self.public_message(),
        };
        (self.status_code(), Json(body)).into_response()
    }
}

/// Błąd bazy danych zamieniany na błąd wewnętrzny (szczegóły tylko w logach).
impl From<dscan_db::DbError> for ApiError {
    fn from(error: dscan_db::DbError) -> Self {
        ApiError::Internal(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_error_kinds() {
        assert_eq!(ApiError::NotFound.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::Unauthorized.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(ApiError::Forbidden.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(
            ApiError::Conflict("x".into()).status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::Internal("x".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn internal_error_details_are_not_public() {
        let error = ApiError::Internal("hasło do bazy: tajne".into());
        assert!(!error.public_message().contains("tajne"));
    }
}
