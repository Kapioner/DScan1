//! Dane do porównania przebiegów i zapis wykrytych zmian (zadanie M1).

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dscan_core::models::{Change, ChangeKind, Protocol, ServiceKey};
use sqlx::{Postgres, QueryBuilder};

use crate::{DbError, PgPool};

/// Zmian w jednym INSERT (8 parametrów na wiersz).
const CHANGES_PER_INSERT: usize = 1000;

/// Odciski otwartych usług przebiegu według klucza (IP, port, protokół).
pub async fn run_fingerprints(
    pool: &PgPool,
    run_id: i64,
) -> Result<HashMap<ServiceKey, String>, DbError> {
    let rows: Vec<(IpAddr, i32, String, Option<String>)> = sqlx::query_as(
        "SELECT h.ip, s.port, s.protocol, s.fingerprint_hash FROM services s \
         JOIN hosts h ON h.id = s.host_id WHERE h.scan_run_id = $1 AND s.state = 'open'",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(rows
        .into_iter()
        .filter_map(|(ip, port, protocol, hash)| {
            let key = ServiceKey {
                ip,
                port: u16::try_from(port).ok()?,
                protocol: parse_protocol(&protocol),
            };
            Some((key, hash.unwrap_or_default()))
        })
        .collect())
}

/// Ostatni udany przebieg tego samego profilu sprzed `run_id` (punkt odniesienia porównania).
pub async fn previous_completed_run(
    pool: &PgPool,
    run_id: i64,
    profile: &str,
) -> Result<Option<i64>, DbError> {
    sqlx::query_scalar(
        "SELECT id FROM scan_runs WHERE id < $1 AND profile = $2 AND status = 'completed' \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(run_id)
    .bind(profile)
    .fetch_optional(pool)
    .await
    .map_err(DbError::Query)
}

/// Zapisuje zmiany wsadowo.
pub async fn save_changes(pool: &PgPool, changes: &[Change]) -> Result<(), DbError> {
    for chunk in changes.chunks(CHANGES_PER_INSERT) {
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
            "INSERT INTO changes (previous_run_id, current_run_id, ip, port, protocol, kind, \
             previous_fingerprint, current_fingerprint) ",
        );
        query.push_values(chunk, |mut row, change| {
            row.push_bind(change.previous_run_id)
                .push_bind(change.current_run_id)
                .push_bind(change.key.ip)
                .push_bind(i32::from(change.key.port))
                .push_bind(change.key.protocol.as_str())
                .push_bind(change.kind.as_str())
                .push_bind(&change.previous_fingerprint)
                .push_bind(&change.current_fingerprint);
        });
        query.build().execute(pool).await.map_err(DbError::Query)?;
    }
    Ok(())
}

type ChangeRow = (
    i64,
    i64,
    IpAddr,
    i32,
    String,
    String,
    Option<String>,
    Option<String>,
    DateTime<Utc>,
);

/// Zmiany zapisane dla przebiegu (względem jego poprzednika), posortowane po adresie i porcie.
pub async fn list_changes(pool: &PgPool, current_run_id: i64) -> Result<Vec<Change>, DbError> {
    let rows: Vec<ChangeRow> = sqlx::query_as(
        "SELECT previous_run_id, current_run_id, ip, port, protocol, kind, previous_fingerprint, \
         current_fingerprint, detected_at FROM changes WHERE current_run_id = $1 ORDER BY ip, port",
    )
    .bind(current_run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    Ok(rows
        .into_iter()
        .filter_map(
            |(previous, current, ip, port, protocol, kind, old, new, detected_at)| {
                Some(Change {
                    key: ServiceKey {
                        ip,
                        port: u16::try_from(port).ok()?,
                        protocol: parse_protocol(&protocol),
                    },
                    kind: parse_kind(&kind)?,
                    previous_run_id: previous,
                    current_run_id: current,
                    previous_fingerprint: old,
                    current_fingerprint: new,
                    detected_at,
                })
            },
        )
        .collect())
}

fn parse_protocol(text: &str) -> Protocol {
    if text == "udp" {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}

fn parse_kind(text: &str) -> Option<ChangeKind> {
    [
        ChangeKind::Appeared,
        ChangeKind::Disappeared,
        ChangeKind::Modified,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == text)
}
