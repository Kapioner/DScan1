//! Ręczne poprawki wyników (zadanie A6). Wartości są szyfrowane (`overrides.value`).

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dscan_core::models::{Override, OverrideField, Protocol};
use dscan_crypto::Cipher;

use crate::columns::OVERRIDES_VALUE;
use crate::{DbError, Encrypted, PgPool};

/// Adres poprawki: host (`port = None`) albo konkretna usługa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverrideTarget {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
}

/// Zapisuje poprawkę (nowa albo zastępuje istniejącą dla tego samego adresu i pola).
pub async fn set_override(
    pool: &PgPool,
    cipher: &Cipher,
    target: OverrideTarget,
    field: OverrideField,
    value: &str,
    user_id: Option<i64>,
) -> Result<(), DbError> {
    let sealed = Encrypted::seal(cipher, &OVERRIDES_VALUE, &value.to_string())?;
    sqlx::query(
        "INSERT INTO overrides (ip, port, protocol, field, value, created_by) VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (ip, port, protocol, field) \
         DO UPDATE SET value = EXCLUDED.value, created_by = EXCLUDED.created_by, updated_at = now()",
    )
    .bind(target.ip)
    .bind(target.port.map(i32::from))
    .bind(target.protocol.map(|protocol| protocol.as_str()))
    .bind(field.as_str())
    .bind(sealed)
    .bind(user_id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::Query)
}

/// Usuwa poprawkę — od tej chwili znów widać wartość zaobserwowaną przez skaner.
pub async fn delete_override(
    pool: &PgPool,
    target: OverrideTarget,
    field: OverrideField,
) -> Result<bool, DbError> {
    sqlx::query(
        "DELETE FROM overrides WHERE ip = $1 AND port IS NOT DISTINCT FROM $2 \
         AND protocol IS NOT DISTINCT FROM $3 AND field = $4",
    )
    .bind(target.ip)
    .bind(target.port.map(i32::from))
    .bind(target.protocol.map(|protocol| protocol.as_str()))
    .bind(field.as_str())
    .execute(pool)
    .await
    .map(|result| result.rows_affected() == 1)
    .map_err(DbError::Query)
}

type OverrideRow = (
    IpAddr,
    Option<i32>,
    Option<String>,
    String,
    Encrypted<String>,
    DateTime<Utc>,
    Option<String>,
);

/// Wszystkie poprawki z odszyfrowanymi wartościami.
pub async fn list_overrides(pool: &PgPool, cipher: &Cipher) -> Result<Vec<Override>, DbError> {
    let rows: Vec<OverrideRow> = sqlx::query_as(
        "SELECT o.ip, o.port, o.protocol, o.field, o.value, o.updated_at, u.username \
         FROM overrides o LEFT JOIN users u ON u.id = o.created_by ORDER BY o.ip, o.port, o.field",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;

    rows.into_iter()
        .filter_map(
            |(ip, port, protocol, field, value, updated_at, updated_by)| {
                let field = OverrideField::parse(&field)?;
                Some((ip, port, protocol, field, value, updated_at, updated_by))
            },
        )
        .map(
            |(ip, port, protocol, field, value, updated_at, updated_by)| {
                Ok(Override {
                    ip,
                    port: port.and_then(|port| u16::try_from(port).ok()),
                    protocol: protocol.map(|text| {
                        if text == "udp" {
                            Protocol::Udp
                        } else {
                            Protocol::Tcp
                        }
                    }),
                    field,
                    value: value.open(cipher, &OVERRIDES_VALUE)?,
                    updated_at,
                    updated_by,
                })
            },
        )
        .collect()
}
