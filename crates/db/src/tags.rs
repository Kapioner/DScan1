//! Tagi hostów i usług (F11) — niezależne od przebiegu.

use std::net::IpAddr;

use crate::{DbError, PgPool};

/// Tag z adresem (port `None` = cały host).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Tag {
    pub id: i64,
    pub ip: IpAddr,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub tag: String,
}

/// Normalizacja: małe litery, bez spacji na brzegach, spacje → `-`, 1–40 znaków.
pub fn normalize_tag(tag: &str) -> Option<String> {
    let tag: String = tag
        .trim()
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join("-");
    (!tag.is_empty() && tag.chars().count() <= 40).then_some(tag)
}

pub async fn add_tag(
    pool: &PgPool,
    ip: IpAddr,
    port: Option<u16>,
    protocol: Option<&str>,
    tag: &str,
    user_id: Option<i64>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO tags (ip, port, protocol, tag, created_by) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(ip)
    .bind(port.map(i32::from))
    .bind(protocol)
    .bind(tag)
    .bind(user_id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::Query)
}

pub async fn delete_tag(pool: &PgPool, id: i64) -> Result<bool, DbError> {
    sqlx::query("DELETE FROM tags WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map(|r| r.rows_affected() == 1)
        .map_err(DbError::Query)
}

pub async fn list_tags(pool: &PgPool) -> Result<Vec<Tag>, DbError> {
    sqlx::query_as("SELECT id, ip, port, protocol, tag FROM tags ORDER BY tag, ip, port")
        .fetch_all(pool)
        .await
        .map_err(DbError::Query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_normalized() {
        assert_eq!(
            normalize_tag("  Kamery  Biuro "),
            Some("kamery-biuro".into())
        );
        assert_eq!(normalize_tag("   "), None);
        assert_eq!(normalize_tag(&"x".repeat(41)), None);
    }
}
