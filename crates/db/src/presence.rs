//! Obecność hostów i historia odpowiedzi (zadanie S11).

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dscan_core::models::{HostStatus, Presence, next_presence};
use ipnet::IpNet;
use sqlx::{Postgres, QueryBuilder};

use crate::{DbError, PgPool};

const ROWS_PER_INSERT: usize = 1000;

/// Wynik aktualizacji: ile hostów odpowiedziało, ilu nie, ilu stało się nieaktywnymi teraz.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PresenceUpdate {
    pub responded: usize,
    pub missed: usize,
    pub became_inactive: Vec<IpAddr>,
    /// Hosty, które odpowiedziały dopiero przy powtórnym pomiarze (S10).
    pub unstable: Vec<IpAddr>,
}

/// Oznacza hosty jako niestabilne (odpowiedziały dopiero przy powtórnym pomiarze, S10).
pub async fn mark_unstable(pool: &PgPool, ips: &[IpAddr]) -> Result<(), DbError> {
    if ips.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE host_presence SET status = 'unstable' WHERE ip = ANY($1)")
        .bind(ips.to_vec())
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}

type PresenceRow = (IpAddr, String, i32, DateTime<Utc>, DateTime<Utc>);

/// Aktualizuje obecność po udanym przebiegu: hosty, które odpowiedziały, i znane hosty
/// z przeskanowanych sieci, które nie odpowiedziały. Zapisuje też historię odpowiedzi.
pub async fn update_presence(
    pool: &PgPool,
    run_id: i64,
    scanned: &[IpNet],
    responded: &[IpAddr],
    inactive_after: u32,
) -> Result<PresenceUpdate, DbError> {
    let now = Utc::now();
    let responded_set: HashSet<IpAddr> = responded.iter().copied().collect();
    let known: Vec<Presence> = load_presence(pool).await?;
    let mut update = PresenceUpdate::default();
    let mut rows: Vec<(Presence, bool)> = Vec::new();

    for old in known
        .iter()
        .filter(|p| scanned.iter().any(|net| net.contains(&p.ip)))
    {
        let answered = responded_set.contains(&old.ip);
        let new = next_presence(Some(old), old.ip, answered, inactive_after, now);
        if old.status != HostStatus::Inactive && new.status == HostStatus::Inactive {
            update.became_inactive.push(old.ip);
        }
        rows.push((new, answered));
    }
    let known_ips: HashSet<IpAddr> = known.iter().map(|p| p.ip).collect();
    for ip in responded.iter().filter(|ip| !known_ips.contains(ip)) {
        rows.push((next_presence(None, *ip, true, inactive_after, now), true));
    }
    update.responded = rows.iter().filter(|(_, answered)| *answered).count();
    update.missed = rows.len() - update.responded;
    save(pool, run_id, &rows).await?;
    Ok(update)
}

/// Stan obecności wszystkich znanych hostów.
pub async fn load_presence(pool: &PgPool) -> Result<Vec<Presence>, DbError> {
    let rows: Vec<PresenceRow> = sqlx::query_as(
        "SELECT ip, status, consecutive_misses, first_seen, last_seen FROM host_presence ORDER BY ip",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows
        .into_iter()
        .map(|(ip, status, misses, first_seen, last_seen)| Presence {
            ip,
            status: HostStatus::parse(&status),
            consecutive_misses: u32::try_from(misses).unwrap_or(0),
            first_seen,
            last_seen,
        })
        .collect())
}

/// Historia odpowiedzi hosta: (przebieg, odpowiedział), od najnowszego.
pub async fn response_history(pool: &PgPool, ip: IpAddr) -> Result<Vec<(i64, bool)>, DbError> {
    sqlx::query_as(
        "SELECT scan_run_id, responded FROM host_responses WHERE ip = $1 ORDER BY scan_run_id DESC",
    )
    .bind(ip)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

async fn save(pool: &PgPool, run_id: i64, rows: &[(Presence, bool)]) -> Result<(), DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    for chunk in rows.chunks(ROWS_PER_INSERT) {
        let mut presence: QueryBuilder<Postgres> = QueryBuilder::new(
            "INSERT INTO host_presence (ip, status, consecutive_misses, first_seen, last_seen, last_run_id) ",
        );
        presence.push_values(chunk, |mut row, (p, _)| {
            row.push_bind(p.ip)
                .push_bind(p.status.as_str())
                .push_bind(i32::try_from(p.consecutive_misses).unwrap_or(i32::MAX))
                .push_bind(p.first_seen)
                .push_bind(p.last_seen)
                .push_bind(run_id);
        });
        presence.push(
            " ON CONFLICT (ip) DO UPDATE SET status = EXCLUDED.status, \
             consecutive_misses = EXCLUDED.consecutive_misses, last_seen = EXCLUDED.last_seen, \
             last_run_id = EXCLUDED.last_run_id",
        );
        presence
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(DbError::Query)?;

        let mut history: QueryBuilder<Postgres> =
            QueryBuilder::new("INSERT INTO host_responses (ip, scan_run_id, responded) ");
        history.push_values(chunk, |mut row, (p, answered)| {
            row.push_bind(p.ip).push_bind(run_id).push_bind(*answered);
        });
        history.push(" ON CONFLICT DO NOTHING");
        history
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(DbError::Query)?;
    }
    transaction.commit().await.map_err(DbError::Query)
}

/// Historia odpowiedzi adresu z czasem startu przebiegu (M2, M5), od najstarszej.
pub async fn presence_history(
    pool: &PgPool,
    ip: IpAddr,
) -> Result<Vec<(DateTime<Utc>, bool)>, DbError> {
    sqlx::query_as(
        "SELECT r.started_at, h.responded FROM host_responses h JOIN scan_runs r ON r.id = h.scan_run_id \
         WHERE h.ip = $1 ORDER BY r.started_at",
    )
    .bind(ip)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Historie odpowiedzi wszystkich adresów (lista hostów, M5) — najwyżej `per_host` ostatnich.
pub async fn presence_histories(
    pool: &PgPool,
    per_host: i64,
) -> Result<std::collections::HashMap<IpAddr, Vec<(DateTime<Utc>, bool)>>, DbError> {
    let rows: Vec<(IpAddr, DateTime<Utc>, bool)> = sqlx::query_as(
        "SELECT ip, started_at, responded FROM ( \
           SELECT h.ip, r.started_at, h.responded, \
                  row_number() OVER (PARTITION BY h.ip ORDER BY r.started_at DESC) AS n \
           FROM host_responses h JOIN scan_runs r ON r.id = h.scan_run_id) t \
         WHERE n <= $1 ORDER BY ip, started_at",
    )
    .bind(per_host)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    let mut map: std::collections::HashMap<IpAddr, Vec<(DateTime<Utc>, bool)>> =
        std::collections::HashMap::new();
    for (ip, at, responded) in rows {
        map.entry(ip).or_default().push((at, responded));
    }
    Ok(map)
}
