//! Wstrzymywanie i wznawianie przebiegów (zadanie S9).

use crate::{DbError, PgPool};

/// Przebieg do wznowienia: niedokończone podgrupy i dotychczasowy postęp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumableRun {
    pub run_id: i64,
    pub profile: String,
    pub mode: String,
    pub profile_id: Option<i64>,
    pub total_addresses: u64,
    pub completed_addresses: u64,
    pub total_subgroups: u32,
    pub completed_subgroups: u32,
    /// (id podgrupy, sieci) — tylko podgrupy oczekujące lub przerwane w trakcie.
    pub pending: Vec<(i64, Vec<String>)>,
}

/// Podgrupa przerwana końcem okna wraca do kolejki (jakby jeszcze nie startowała).
pub async fn reset_subgroup(pool: &PgPool, subgroup_id: i64) -> Result<(), DbError> {
    sqlx::query("UPDATE subgroups SET status = 'pending', started_at = NULL WHERE id = $1")
        .bind(subgroup_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Zmienia stan przebiegu bez ustawiania czasu zakończenia (np. `paused`, `running`).
pub async fn set_run_status(pool: &PgPool, run_id: i64, status: &str) -> Result<(), DbError> {
    sqlx::query("UPDATE scan_runs SET status = $2 WHERE id = $1")
        .bind(run_id)
        .bind(status)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

type RunRow = (String, String, Option<i64>, i64, i64, i32, i32, String);

/// Wstrzymany przebieg z niedokończonymi podgrupami; `None`, gdy nie istnieje.
pub async fn load_resumable_run(
    pool: &PgPool,
    run_id: i64,
) -> Result<Option<ResumableRun>, DbError> {
    let row: Option<RunRow> = sqlx::query_as(
        "SELECT profile, mode, profile_id, total_addresses, completed_addresses, total_subgroups, \
         completed_subgroups, status FROM scan_runs WHERE id = $1",
    )
    .bind(run_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    let Some((profile, mode, profile_id, total, done, total_groups, done_groups, _status)) = row
    else {
        return Ok(None);
    };
    let pending: Vec<(i64, Vec<String>)> = sqlx::query_as(
        "SELECT id, addresses FROM subgroups WHERE scan_run_id = $1 AND status IN ('pending', 'running') \
         ORDER BY sequence_no",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(Some(ResumableRun {
        run_id,
        profile,
        mode,
        profile_id,
        total_addresses: u64::try_from(total).unwrap_or(0),
        completed_addresses: u64::try_from(done).unwrap_or(0),
        total_subgroups: u32::try_from(total_groups).unwrap_or(0),
        completed_subgroups: u32::try_from(done_groups).unwrap_or(0),
        pending,
    }))
}

/// Wszystkie sieci przebiegu (ze wszystkich podgrup) — do aktualizacji obecności hostów.
pub async fn run_networks(pool: &PgPool, run_id: i64) -> Result<Vec<String>, DbError> {
    let rows: Vec<Vec<String>> =
        sqlx::query_scalar("SELECT addresses FROM subgroups WHERE scan_run_id = $1")
            .bind(run_id)
            .fetch_all(pool)
            .await
            .map_err(DbError::Query)?;
    Ok(rows.into_iter().flatten().collect())
}

/// Ostatni przebieg uruchomiony z profilu (do harmonogramu): (id, stan, start).
pub async fn last_profile_run(
    pool: &PgPool,
    profile_id: i64,
) -> Result<Option<(i64, String, chrono::DateTime<chrono::Utc>)>, DbError> {
    sqlx::query_as(
        "SELECT id, status, started_at FROM scan_runs WHERE profile_id = $1 ORDER BY started_at DESC LIMIT 1",
    )
    .bind(profile_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// Przebiegi, które po restarcie serwera zostały w stanie `running` — oznaczamy je jako wstrzymane,
/// żeby dało się je wznowić (niedokończone podgrupy wracają do kolejki).
pub async fn pause_orphaned_runs(pool: &PgPool) -> Result<u64, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    sqlx::query(
        "UPDATE subgroups SET status = 'pending', started_at = NULL WHERE status = 'running' \
         AND scan_run_id IN (SELECT id FROM scan_runs WHERE status = 'running')",
    )
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    let paused = sqlx::query("UPDATE scan_runs SET status = 'paused' WHERE status = 'running'")
        .execute(&mut *transaction)
        .await
        .map_err(DbError::Query)?
        .rows_affected();
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(paused)
}

/// Pomiary przepustowości (S5): adresy i czas trwania (s) ostatnich ukończonych podgrup
/// przebiegów w danym trybie, od najstarszej do najnowszej.
pub async fn recent_subgroup_timings(
    pool: &PgPool,
    mode: &str,
    limit: i64,
) -> Result<Vec<(Vec<String>, f64)>, DbError> {
    let mut rows: Vec<(Vec<String>, f64)> = sqlx::query_as(
        "SELECT g.addresses, EXTRACT(EPOCH FROM (g.finished_at - g.started_at))::float8 \
         FROM subgroups g JOIN scan_runs r ON r.id = g.scan_run_id \
         WHERE g.status = 'completed' AND r.mode = $1 AND g.started_at IS NOT NULL \
           AND g.finished_at > g.started_at AND g.retry_of IS NULL \
         ORDER BY g.finished_at DESC LIMIT $2",
    )
    .bind(mode)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.reverse();
    Ok(rows)
}

/// Dodaje do przebiegu podgrupę z powtórnym pomiarem (S10). Liczniki przebiegu rosną,
/// żeby postęp nadal sumował się do 100%.
pub async fn add_retry_subgroup(
    pool: &PgPool,
    run_id: i64,
    addresses: &[String],
    attempt: i32,
) -> Result<i64, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO subgroups (scan_run_id, sequence_no, addresses, retry_of) \
         SELECT $1, COALESCE(MAX(sequence_no), -1) + 1, $2, $3 FROM subgroups WHERE scan_run_id = $1 \
         RETURNING id",
    )
    .bind(run_id)
    .bind(addresses)
    .bind(attempt)
    .fetch_one(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    sqlx::query(
        "UPDATE scan_runs SET total_subgroups = total_subgroups + 1, \
         total_addresses = total_addresses + $2 WHERE id = $1",
    )
    .bind(run_id)
    .bind(addresses.len() as i64)
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(id)
}
