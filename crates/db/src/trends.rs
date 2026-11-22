//! Dane do wykresów w czasie (F10): liczby hostów i usług w kolejnych przebiegach
//! oraz odpowiedzi hostów w godzinach i dniach tygodnia.

use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

/// Punkt wykresu: zakończony przebieg.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct RunTotals {
    pub run_id: i64,
    pub started_at: DateTime<Utc>,
    pub hosts: i64,
    pub services: i64,
}

/// Ostatnie zakończone przebiegi (najwyżej `limit`), od najstarszego.
pub async fn run_totals(pool: &PgPool, limit: i64) -> Result<Vec<RunTotals>, DbError> {
    let mut rows: Vec<RunTotals> = sqlx::query_as(
        "SELECT r.id AS run_id, r.started_at, \
           (SELECT count(*) FROM hosts h WHERE h.scan_run_id = r.id) AS hosts, \
           (SELECT count(*) FROM services s JOIN hosts h ON h.id = s.host_id \
              WHERE h.scan_run_id = r.id AND s.state = 'open') AS services \
         FROM scan_runs r WHERE r.status = 'completed' ORDER BY r.started_at DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    rows.reverse();
    Ok(rows)
}

/// Odpowiedzi hostów: (czas startu przebiegu, liczba odpowiedzi) dla przebiegów od `since`.
pub async fn responses_by_run(
    pool: &PgPool,
    since: DateTime<Utc>,
) -> Result<Vec<(DateTime<Utc>, i64)>, DbError> {
    sqlx::query_as(
        "SELECT r.started_at, count(*) FILTER (WHERE h.responded) FROM host_responses h \
         JOIN scan_runs r ON r.id = h.scan_run_id WHERE r.started_at >= $1 GROUP BY r.id, r.started_at",
    )
    .bind(since)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}
