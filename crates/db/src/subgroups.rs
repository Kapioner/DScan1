//! Stan podgrup w trakcie przebiegu (S4) z czasem każdej z nich (S6).

use chrono::{DateTime, Utc};
use dscan_core::models::Host;
use dscan_crypto::Cipher;

use crate::columns::SUBGROUPS_RAW_NMAP_XML;
use crate::results::insert_hosts_with_services;
use crate::scan_runs::to_db_count;
use crate::{DbError, Encrypted, PgPool, SaveSummary};

/// Wynik ukończonej podgrupy do zapisania.
#[derive(Debug, Clone, Copy)]
pub struct SubgroupCompletion<'a> {
    pub run_id: i64,
    pub subgroup_id: i64,
    pub addresses: u64,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub hosts: &'a [Host],
    pub raw_xml: &'a str,
}

/// Podgrupa zaczęła się skanować.
pub async fn mark_subgroup_running(
    pool: &PgPool,
    subgroup_id: i64,
    started_at: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query("UPDATE subgroups SET status = 'running', started_at = $2 WHERE id = $1")
        .bind(subgroup_id)
        .bind(started_at)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

/// Zapisuje wyniki podgrupy, jej czas i surowy XML (zaszyfrowany) oraz zwiększa
/// licznik postępu przebiegu — wszystko w jednej transakcji.
pub async fn complete_subgroup(
    pool: &PgPool,
    cipher: &Cipher,
    completion: SubgroupCompletion<'_>,
) -> Result<SaveSummary, DbError> {
    let raw_xml = Encrypted::seal(
        cipher,
        &SUBGROUPS_RAW_NMAP_XML,
        &completion.raw_xml.to_string(),
    )?;
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;

    let summary = insert_hosts_with_services(
        &mut transaction,
        cipher,
        completion.run_id,
        completion.hosts,
    )
    .await?;
    sqlx::query(
        "UPDATE subgroups SET status = 'completed', started_at = $2, finished_at = $3, \
         raw_nmap_xml = $4 WHERE id = $1",
    )
    .bind(completion.subgroup_id)
    .bind(completion.started_at)
    .bind(completion.finished_at)
    .bind(raw_xml)
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    add_progress(&mut transaction, completion.run_id, completion.addresses).await?;

    transaction.commit().await.map_err(DbError::Query)?;
    Ok(summary)
}

/// Podgrupa zakończyła się błędem (adresy liczą się jako przetworzone, żeby prognoza była rzetelna).
pub async fn fail_subgroup(
    pool: &PgPool,
    run_id: i64,
    subgroup_id: i64,
    addresses: u64,
    times: (DateTime<Utc>, DateTime<Utc>),
    error: &str,
) -> Result<(), DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    sqlx::query(
        "UPDATE subgroups SET status = 'failed', started_at = $2, finished_at = $3, error = $4 \
         WHERE id = $1",
    )
    .bind(subgroup_id)
    .bind(times.0)
    .bind(times.1)
    .bind(error)
    .execute(&mut *transaction)
    .await
    .map_err(DbError::Query)?;
    add_progress(&mut transaction, run_id, addresses).await?;
    transaction.commit().await.map_err(DbError::Query)
}

async fn add_progress(
    connection: &mut sqlx::PgConnection,
    run_id: i64,
    addresses: u64,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE scan_runs SET completed_subgroups = completed_subgroups + 1, \
         completed_addresses = completed_addresses + $2 WHERE id = $1",
    )
    .bind(run_id)
    .bind(to_db_count(addresses))
    .execute(connection)
    .await
    .map(|_| ())
    .map_err(DbError::Query)
}
