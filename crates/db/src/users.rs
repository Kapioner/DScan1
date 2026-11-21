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

/// Dane potrzebne do sprawdzenia hasła przy logowaniu.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct LoginUser {
    pub id: i64,
    pub password_hash: String,
    pub is_blocked: bool,
}

/// Użytkownik o podanym loginie (do logowania).
pub async fn find_login_user(pool: &PgPool, username: &str) -> Result<Option<LoginUser>, DbError> {
    sqlx::query_as("SELECT id, password_hash, is_blocked FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(DbError::Query)
}

/// Zapamiętuje czas ostatniego logowania.
pub async fn record_login(pool: &PgPool, user_id: i64) -> Result<(), DbError> {
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Liczba kont (0 = pierwszy start — można utworzyć administratora ze zmiennych środowiskowych).
pub async fn count_users(pool: &PgPool) -> Result<i64, DbError> {
    sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await
        .map_err(DbError::Query)
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
