//! Sesje logowania (zadanie A2). Klucz sesji to skrót SHA-256 tokenu z ciasteczka.

use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

/// Zalogowany użytkownik z uprawnieniami jego roli.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub permissions: Vec<String>,
}

/// Zapisuje nową sesję.
pub async fn create_session(
    pool: &PgPool,
    user_id: i64,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Użytkownik ważnej sesji. `None`, gdy sesja nie istnieje, wygasła albo konto jest zablokowane.
pub async fn find_session_user(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<SessionUser>, DbError> {
    sqlx::query_as(
        "SELECT u.id, u.username, r.name AS role, r.permissions \
         FROM sessions s JOIN users u ON u.id = s.user_id JOIN roles r ON r.id = u.role_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.is_blocked",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// Wylogowanie: usuwa sesję.
pub async fn delete_session(pool: &PgPool, token_hash: &[u8]) -> Result<(), DbError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Usuwa wygasłe sesje; zwraca ich liczbę.
pub async fn delete_expired_sessions(pool: &PgPool) -> Result<u64, DbError> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now()")
        .execute(pool)
        .await
        .map(|result| result.rows_affected())
        .map_err(DbError::Query)
}
