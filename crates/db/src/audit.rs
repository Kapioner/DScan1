//! Dziennik audytu (A7): kto, co i kiedy zmienił. Zasada: w `details` nie zapisujemy
//! wartości pól poufnych — tylko opis operacji (np. nazwę pola, liczbę rekordów).

use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

/// Wpis do zapisania.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry<'a> {
    pub user_id: Option<i64>,
    /// Np. `create`, `update`, `delete`, `import`, `export`, `login`.
    pub action: &'a str,
    /// Np. `user`, `role`, `target`, `profile`, `override`, `scan`.
    pub entity: &'a str,
    pub entity_id: Option<String>,
    pub details: &'a str,
}

pub async fn insert_audit(pool: &PgPool, entry: &AuditEntry<'_>) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, entity, entity_id, details) \
         VALUES ($1, $2, $3, $4, jsonb_build_object('text', $5::text))",
    )
    .bind(entry.user_id)
    .bind(entry.action)
    .bind(entry.entity)
    .bind(&entry.entity_id)
    .bind(entry.details)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::Query)
}

/// Wpis z nazwą użytkownika.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuditRecord {
    pub id: i64,
    pub username: Option<String>,
    pub action: String,
    pub entity: String,
    pub entity_id: Option<String>,
    pub details: String,
    pub created_at: DateTime<Utc>,
}

/// Filtry dziennika (puste = wszystko).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub username: Option<String>,
    pub entity: Option<String>,
    pub action: Option<String>,
}

/// Najnowsze wpisy (najwyżej `limit`).
pub async fn list_audit(
    pool: &PgPool,
    filter: &AuditFilter,
    limit: i64,
) -> Result<Vec<AuditRecord>, DbError> {
    sqlx::query_as(
        "SELECT a.id, u.username, a.action, a.entity, a.entity_id, \
         COALESCE(a.details ->> 'text', a.details::text) AS details, a.created_at \
         FROM audit_log a LEFT JOIN users u ON u.id = a.user_id \
         WHERE ($1::text IS NULL OR u.username = $1) AND ($2::text IS NULL OR a.entity = $2) \
           AND ($3::text IS NULL OR a.action = $3) \
         ORDER BY a.id DESC LIMIT $4",
    )
    .bind(&filter.username)
    .bind(&filter.entity)
    .bind(&filter.action)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}
