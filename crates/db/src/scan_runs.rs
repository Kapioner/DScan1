//! Przebiegi skanów: tworzenie z podgrupami (S4), zakończenie i odczyt z postępem (S6).
//! Zapis stanu poszczególnych podgrup jest w module `subgroups`.

use chrono::{DateTime, Utc};
use dscan_core::models::{ScanRun, ScanStatus};
use sqlx::{Postgres, QueryBuilder};

use crate::{DbError, PgPool};

/// Podgrup w jednym INSERT (3 parametry na wiersz).
const SUBGROUPS_PER_INSERT: usize = 1000;

/// Nowy przebieg: jego id i id podgrup w kolejności podziału.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedScanRun {
    pub run_id: i64,
    pub subgroup_ids: Vec<i64>,
}

/// Metadane nowego przebiegu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewRun {
    pub profile: String,
    /// `discovery` albo `services`.
    pub mode: String,
    pub profile_id: Option<i64>,
    pub requested_by: Option<i64>,
}

/// Tworzy przebieg (tryb `services`, bez profilu z bazy) — skrót dla testów i importu.
pub async fn create_scan_run(
    pool: &PgPool,
    profile: &str,
    total_addresses: u64,
    subgroups: &[Vec<String>],
) -> Result<CreatedScanRun, DbError> {
    let run = NewRun {
        profile: profile.to_string(),
        mode: "services".into(),
        ..NewRun::default()
    };
    create_scan_run_with(pool, &run, total_addresses, subgroups).await
}

/// Tworzy przebieg w stanie `running` i jego podgrupy (każda jako lista sieci CIDR).
pub async fn create_scan_run_with(
    pool: &PgPool,
    run: &NewRun,
    total_addresses: u64,
    subgroups: &[Vec<String>],
) -> Result<CreatedScanRun, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let run_id: i64 = sqlx::query_scalar(
        "INSERT INTO scan_runs (profile, status, total_addresses, total_subgroups, mode, profile_id, requested_by) \
         VALUES ($1, 'running', $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&run.profile)
    .bind(to_db_count(total_addresses))
    .bind(i32::try_from(subgroups.len()).unwrap_or(i32::MAX))
    .bind(&run.mode)
    .bind(run.profile_id)
    .bind(run.requested_by)
    .fetch_one(&mut *transaction)
    .await
    .map_err(DbError::Query)?;

    let numbered: Vec<(i32, &Vec<String>)> = subgroups
        .iter()
        .enumerate()
        .map(|(index, addresses)| (i32::try_from(index).unwrap_or(i32::MAX), addresses))
        .collect();
    let mut ids: Vec<(i32, i64)> = Vec::with_capacity(subgroups.len());
    for chunk in numbered.chunks(SUBGROUPS_PER_INSERT) {
        let mut query: QueryBuilder<Postgres> =
            QueryBuilder::new("INSERT INTO subgroups (scan_run_id, sequence_no, addresses) ");
        query.push_values(chunk, |mut row, (sequence_no, addresses)| {
            row.push_bind(run_id)
                .push_bind(*sequence_no)
                .push_bind(*addresses);
        });
        query.push(" RETURNING sequence_no, id");
        let rows: Vec<(i32, i64)> = query
            .build_query_as()
            .fetch_all(&mut *transaction)
            .await
            .map_err(DbError::Query)?;
        ids.extend(rows);
    }
    transaction.commit().await.map_err(DbError::Query)?;

    // RETURNING nie gwarantuje kolejności — porządkujemy według numeru podgrupy.
    ids.sort_unstable_by_key(|(sequence_no, _)| *sequence_no);
    Ok(CreatedScanRun {
        run_id,
        subgroup_ids: ids.into_iter().map(|(_, id)| id).collect(),
    })
}

/// Kończy przebieg: ustawia stan i czas zakończenia.
pub async fn finish_scan_run(
    pool: &PgPool,
    run_id: i64,
    status: ScanStatus,
) -> Result<(), DbError> {
    sqlx::query("UPDATE scan_runs SET status = $2, finished_at = now() WHERE id = $1")
        .bind(run_id)
        .bind(status.as_str())
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

type ScanRunRow = (
    i64,
    String,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    i64,
    i64,
    i32,
    i32,
);

const SCAN_RUN_COLUMNS: &str = "id, profile, status, started_at, finished_at, total_addresses, \
                                completed_addresses, total_subgroups, completed_subgroups";

/// Jeden przebieg (`None`, gdy nie istnieje).
pub async fn get_scan_run(pool: &PgPool, run_id: i64) -> Result<Option<ScanRun>, DbError> {
    let row: Option<ScanRunRow> = sqlx::query_as(&format!(
        "SELECT {SCAN_RUN_COLUMNS} FROM scan_runs WHERE id = $1"
    ))
    .bind(run_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)?;
    row.map(scan_run_from_row).transpose()
}

/// Ostatnie przebiegi, od najnowszego.
pub async fn list_scan_runs(pool: &PgPool, limit: i64) -> Result<Vec<ScanRun>, DbError> {
    let rows: Vec<ScanRunRow> = sqlx::query_as(&format!(
        "SELECT {SCAN_RUN_COLUMNS} FROM scan_runs ORDER BY started_at DESC, id DESC LIMIT $1"
    ))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.into_iter().map(scan_run_from_row).collect()
}

fn scan_run_from_row(row: ScanRunRow) -> Result<ScanRun, DbError> {
    let (id, profile, status, started_at, finished_at, total, done, total_groups, done_groups) =
        row;
    let status = ScanStatus::parse(&status)
        .ok_or_else(|| DbError::Serialization(format!("nieznany stan przebiegu: {status}")))?;
    Ok(ScanRun {
        id,
        profile,
        status,
        started_at,
        finished_at,
        total_addresses: u64::try_from(total).unwrap_or(0),
        completed_addresses: u64::try_from(done).unwrap_or(0),
        total_subgroups: u32::try_from(total_groups).unwrap_or(0),
        completed_subgroups: u32::try_from(done_groups).unwrap_or(0),
    })
}

/// Liczby adresów trzymamy w kolumnach BIGINT (i64).
pub(crate) fn to_db_count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
