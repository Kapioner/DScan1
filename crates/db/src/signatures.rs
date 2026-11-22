//! Własne sygnatury z edytora (F8), zapisane jako YAML pojedynczej sygnatury.

use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct CustomSignature {
    pub id: i64,
    pub name: String,
    pub category: Option<String>,
    pub definition_yaml: String,
    pub enabled: bool,
    pub updated_at: DateTime<Utc>,
}

pub async fn list_custom_signatures(pool: &PgPool) -> Result<Vec<CustomSignature>, DbError> {
    sqlx::query_as("SELECT id, name, category, definition_yaml, enabled, updated_at FROM signatures ORDER BY name")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

/// Zapisuje sygnaturę (nowa albo zmiana po `id`); `None` — nazwa zajęta lub brak rekordu.
pub async fn save_custom_signature(
    pool: &PgPool,
    id: Option<i64>,
    name: &str,
    category: Option<&str>,
    yaml: &str,
    enabled: bool,
) -> Result<Option<i64>, DbError> {
    let result: Result<Option<i64>, sqlx::Error> = match id {
        Some(id) => sqlx::query_scalar(
            "UPDATE signatures SET name = $2, category = $3, definition_yaml = $4, enabled = $5, updated_at = now() \
             WHERE id = $1 RETURNING id",
        )
        .bind(id)
        .bind(name)
        .bind(category)
        .bind(yaml)
        .bind(enabled)
        .fetch_optional(pool)
        .await,
        None => sqlx::query_scalar(
            "INSERT INTO signatures (name, category, definition_yaml, enabled) VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(name)
        .bind(category)
        .bind(yaml)
        .bind(enabled)
        .fetch_optional(pool)
        .await,
    };
    match result {
        Ok(id) => Ok(id),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(None),
        Err(error) => Err(DbError::Query(error)),
    }
}

pub async fn delete_custom_signature(pool: &PgPool, id: i64) -> Result<bool, DbError> {
    sqlx::query("DELETE FROM signatures WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(DbError::Query)
}
