//! Profile skanów (zadanie A5): co skanować, jak, w jakich oknach czasowych i jak często.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DbError, PgPool};

/// Okno czasowe `HH:MM`–`HH:MM` zapisane w profilu.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileWindow {
    pub start: String,
    pub end: String,
}

/// Dane profilu przy tworzeniu i edycji (już zwalidowane przez wywołującego).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileData {
    pub name: String,
    /// `discovery` albo `services`.
    pub mode: String,
    /// `None` = wszystkie cele.
    pub target_group: Option<String>,
    /// Puste = porty z `[scope] allowed_ports`.
    pub ports: Vec<String>,
    pub windows: Vec<ProfileWindow>,
    /// `None` = tylko ręczne uruchamianie.
    pub frequency_minutes: Option<i32>,
    pub enabled: bool,
    /// Limit tempa nmap (pakiety/s) dla tego profilu (F4); `None` = `[limits] nmap_max_rate`.
    pub max_rate: Option<i32>,
}

/// Profil zapisany w bazie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProfile {
    pub id: i64,
    pub data: ProfileData,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Wynik zapisu profilu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileSaved {
    Saved(ScanProfile),
    NameTaken,
    NotFound,
}

type ProfileRow = (
    i64,
    String,
    String,
    Option<String>,
    Vec<String>,
    String,
    Option<i32>,
    bool,
    Option<i32>,
    DateTime<Utc>,
    DateTime<Utc>,
);

const PROFILE_COLUMNS: &str = "id, name, mode, target_group, ports, windows::text, \
                               frequency_minutes, enabled, max_rate, created_at, updated_at";

pub async fn list_profiles(pool: &PgPool) -> Result<Vec<ScanProfile>, DbError> {
    let rows: Vec<ProfileRow> = sqlx::query_as(&format!(
        "SELECT {PROFILE_COLUMNS} FROM scan_profiles ORDER BY name"
    ))
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.into_iter().map(profile_from_row).collect()
}

pub async fn get_profile(pool: &PgPool, id: i64) -> Result<Option<ScanProfile>, DbError> {
    let row: Option<ProfileRow> = sqlx::query_as(&format!(
        "SELECT {PROFILE_COLUMNS} FROM scan_profiles WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.map(profile_from_row).transpose()
}

pub async fn create_profile(pool: &PgPool, data: &ProfileData) -> Result<ProfileSaved, DbError> {
    let query = format!(
        "INSERT INTO scan_profiles (name, mode, target_group, ports, windows, frequency_minutes, enabled, max_rate) \
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8) RETURNING {PROFILE_COLUMNS}"
    );
    save(pool, &query, None, data).await
}

/// Zastępuje wszystkie pola profilu.
pub async fn update_profile(
    pool: &PgPool,
    id: i64,
    data: &ProfileData,
) -> Result<ProfileSaved, DbError> {
    let query = format!(
        "UPDATE scan_profiles SET name = $1, mode = $2, target_group = $3, ports = $4, \
         windows = $5::jsonb, frequency_minutes = $6, enabled = $7, max_rate = $8, \
         updated_at = now() WHERE id = $9 RETURNING {PROFILE_COLUMNS}"
    );
    save(pool, &query, Some(id), data).await
}

pub async fn delete_profile(pool: &PgPool, id: i64) -> Result<bool, DbError> {
    sqlx::query("DELETE FROM scan_profiles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(DbError::Query)
}

async fn save(
    pool: &PgPool,
    query: &str,
    id: Option<i64>,
    data: &ProfileData,
) -> Result<ProfileSaved, DbError> {
    let windows = serde_json::to_string(&data.windows)
        .map_err(|error| DbError::Serialization(error.to_string()))?;
    let mut statement = sqlx::query_as::<_, ProfileRow>(query)
        .bind(&data.name)
        .bind(&data.mode)
        .bind(&data.target_group)
        .bind(&data.ports)
        .bind(windows)
        .bind(data.frequency_minutes)
        .bind(data.enabled)
        .bind(data.max_rate);
    if let Some(id) = id {
        statement = statement.bind(id);
    }
    match statement.fetch_optional(pool).await {
        Ok(Some(row)) => Ok(ProfileSaved::Saved(profile_from_row(row)?)),
        Ok(None) => Ok(ProfileSaved::NotFound),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            Ok(ProfileSaved::NameTaken)
        }
        Err(error) => Err(DbError::Query(error)),
    }
}

fn profile_from_row(row: ProfileRow) -> Result<ScanProfile, DbError> {
    let (
        id,
        name,
        mode,
        target_group,
        ports,
        windows,
        frequency_minutes,
        enabled,
        max_rate,
        created_at,
        updated_at,
    ) = row;
    let windows: Vec<ProfileWindow> = serde_json::from_str(&windows)
        .map_err(|error| DbError::Serialization(error.to_string()))?;
    Ok(ScanProfile {
        id,
        data: ProfileData {
            name,
            mode,
            target_group,
            ports,
            windows,
            frequency_minutes,
            enabled,
            max_rate,
        },
        created_at,
        updated_at,
    })
}
