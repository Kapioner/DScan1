use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

/// Nazwa wbudowanej roli administratora (z migracji 0001).
pub const ADMIN_ROLE: &str = "administracja";

/// Użytkownik bez hasła — do wyświetlania.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UserSummary {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub is_blocked: bool,
    pub created_at: DateTime<Utc>,
}

/// Tworzy konto z rolą „administracja”. `password_hash` to gotowy skrót argon2.
pub async fn create_admin(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
) -> Result<i64, DbError> {
    let role_id: Option<i64> = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
        .bind(ADMIN_ROLE)
        .fetch_optional(pool)
        .await
        .map_err(DbError::Query)?;
    let role_id = role_id.ok_or(DbError::MissingRole(ADMIN_ROLE))?;

    sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role_id) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(db_error) if db_error.is_unique_violation() => {
            DbError::UserExists(username.to_string())
        }
        _ => DbError::Query(error),
    })
}

/// Wszyscy użytkownicy z nazwami ról, w kolejności utworzenia.
pub async fn list_users(pool: &PgPool) -> Result<Vec<UserSummary>, DbError> {
    sqlx::query_as(
        "SELECT u.id, u.username, r.name AS role, u.is_blocked, u.created_at \
         FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}
