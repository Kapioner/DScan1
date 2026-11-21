//! Pojedyncze operacje na celach dla API (zadanie A5).

use dscan_core::models::Target;
use dscan_crypto::Cipher;

use crate::columns::TARGETS_NOTE;
use crate::targets::{StoredTarget, TargetRow, stored_target_from_row, target_kind_name};
use crate::{DbError, Encrypted, PgPool};

const TARGET_COLUMNS: &str = "id, kind, value, target_group, note, created_at";

/// Grupa celów z liczbą celów.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct TargetGroup {
    pub name: String,
    pub targets: i64,
}

/// Dodaje cel; `None`, gdy taki cel już istnieje.
pub async fn create_target(
    pool: &PgPool,
    cipher: &Cipher,
    target: &Target,
) -> Result<Option<StoredTarget>, DbError> {
    let note = seal_note(cipher, target.note.as_ref())?;
    let row: Option<TargetRow> = sqlx::query_as(&format!(
        "INSERT INTO targets (kind, value, target_group, note) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (kind, value) DO NOTHING RETURNING {TARGET_COLUMNS}"
    ))
    .bind(target_kind_name(&target.kind))
    .bind(target.kind.to_string())
    .bind(&target.group)
    .bind(note)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.map(|row| stored_target_from_row(row, cipher))
        .transpose()
}

pub async fn get_target(
    pool: &PgPool,
    cipher: &Cipher,
    id: i64,
) -> Result<Option<StoredTarget>, DbError> {
    let row: Option<TargetRow> = sqlx::query_as(&format!(
        "SELECT {TARGET_COLUMNS} FROM targets WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.map(|row| stored_target_from_row(row, cipher))
        .transpose()
}

/// Zmienia grupę i notatkę celu (adres celu się nie zmienia). `None`, gdy celu nie ma.
pub async fn update_target(
    pool: &PgPool,
    cipher: &Cipher,
    id: i64,
    group: Option<&str>,
    note: Option<&String>,
) -> Result<Option<StoredTarget>, DbError> {
    let note = seal_note(cipher, note)?;
    let row: Option<TargetRow> = sqlx::query_as(&format!(
        "UPDATE targets SET target_group = $2, note = $3 WHERE id = $1 RETURNING {TARGET_COLUMNS}"
    ))
    .bind(id)
    .bind(group)
    .bind(note)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.map(|row| stored_target_from_row(row, cipher))
        .transpose()
}

/// Usuwa cel; `false`, gdy go nie było.
pub async fn delete_target(pool: &PgPool, id: i64) -> Result<bool, DbError> {
    sqlx::query("DELETE FROM targets WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(DbError::Query)
}

/// Grupy celów (bez celów nieprzypisanych do grupy), alfabetycznie.
pub async fn list_target_groups(pool: &PgPool) -> Result<Vec<TargetGroup>, DbError> {
    sqlx::query_as(
        "SELECT target_group AS name, count(*) AS targets FROM targets \
         WHERE target_group IS NOT NULL GROUP BY target_group ORDER BY target_group",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

fn seal_note(cipher: &Cipher, note: Option<&String>) -> Result<Option<Encrypted<String>>, DbError> {
    note.map(|text| Encrypted::seal(cipher, &TARGETS_NOTE, text))
        .transpose()
}
