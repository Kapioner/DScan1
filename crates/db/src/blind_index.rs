//! Ślepy indeks pól szyfrowanych (B3): wyszukiwanie usług po nazwie ciasteczka,
//! nazwie nagłówka albo parze nagłówek=wartość bez odszyfrowywania wszystkich rekordów.

use std::net::IpAddr;

use dscan_core::models::HttpInfo;
use dscan_crypto::Cipher;
use sqlx::{PgConnection, Postgres, QueryBuilder};

use crate::{DbError, PgPool};

/// Rodzaj wpisu indeksu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindKind {
    Cookie,
    Header,
    HeaderValue,
}

impl BlindKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BlindKind::Cookie => "cookie",
            BlindKind::Header => "header",
            BlindKind::HeaderValue => "header_value",
        }
    }
}

/// Wartość wpisu `header_value`: `nazwa=wartość`.
pub fn header_value_key(name: &str, value: &str) -> String {
    format!("{}={}", name.trim(), value.trim())
}

/// Skróty indeksu dla odpowiedzi HTTP (bez duplikatów).
pub fn blind_entries(cipher: &Cipher, http: &HttpInfo) -> Vec<(BlindKind, Vec<u8>)> {
    let mut entries: Vec<(BlindKind, Vec<u8>)> = Vec::new();
    let mut push = |kind: BlindKind, value: &str| {
        let digest = cipher.blind_index(kind.as_str(), value);
        if !entries.iter().any(|(k, d)| *k == kind && *d == digest) {
            entries.push((kind, digest));
        }
    };
    for cookie in &http.cookies {
        push(BlindKind::Cookie, &cookie.name);
    }
    for header in &http.headers {
        push(BlindKind::Header, &header.name);
        push(
            BlindKind::HeaderValue,
            &header_value_key(&header.name, &header.value),
        );
    }
    entries
}

/// Zapisuje indeks dla paczki usług (w tej samej transakcji co http_info).
pub(crate) async fn insert_blind_index(
    connection: &mut PgConnection,
    cipher: &Cipher,
    rows: &[(i64, &HttpInfo)],
) -> Result<(), DbError> {
    let entries: Vec<(i64, BlindKind, Vec<u8>)> = rows
        .iter()
        .flat_map(|(id, http)| {
            blind_entries(cipher, http)
                .into_iter()
                .map(move |(k, d)| (*id, k, d))
        })
        .collect();
    // 3 parametry na wiersz; paczki mieszczą się w limicie PostgreSQL.
    for chunk in entries.chunks(10_000) {
        let mut query: QueryBuilder<Postgres> =
            QueryBuilder::new("INSERT INTO http_blind_index (service_id, kind, digest) ");
        query.push_values(chunk, |mut row, (id, kind, digest)| {
            row.push_bind(*id)
                .push_bind(kind.as_str())
                .push_bind(digest.clone());
        });
        query.push(" ON CONFLICT DO NOTHING");
        query
            .build()
            .execute(&mut *connection)
            .await
            .map_err(DbError::Query)?;
    }
    Ok(())
}

/// Usługa znaleziona w indeksie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindMatch {
    pub run_id: i64,
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: String,
}

/// Usługi przebiegu (albo wszystkich przebiegów), których odpowiedź zawiera daną wartość.
pub async fn search_blind_index(
    pool: &PgPool,
    cipher: &Cipher,
    kind: BlindKind,
    value: &str,
    run_id: Option<i64>,
) -> Result<Vec<BlindMatch>, DbError> {
    let digest = cipher.blind_index(kind.as_str(), value);
    let rows: Vec<(i64, IpAddr, i32, String)> = sqlx::query_as(
        "SELECT h.scan_run_id, h.ip, s.port, s.protocol FROM http_blind_index b \
         JOIN services s ON s.id = b.service_id JOIN hosts h ON h.id = s.host_id \
         WHERE b.kind = $1 AND b.digest = $2 AND ($3::bigint IS NULL OR h.scan_run_id = $3) \
         ORDER BY h.scan_run_id DESC, h.ip, s.port LIMIT 1000",
    )
    .bind(kind.as_str())
    .bind(digest)
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(rows
        .into_iter()
        .map(|(run_id, ip, port, protocol)| BlindMatch {
            run_id,
            ip,
            port: u16::try_from(port).unwrap_or(0),
            protocol,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::{Cookie, HttpHeader};

    #[test]
    fn entries_cover_cookies_headers_and_values() {
        let cipher = Cipher::new(&[7; 32]);
        let http = HttpInfo {
            url: "http://h/".into(),
            status_code: 200,
            title: None,
            headers: vec![HttpHeader {
                name: "X-Debug".into(),
                value: "1".into(),
            }],
            cookies: vec![Cookie {
                name: "PHPSESSID".into(),
                value: "tajne".into(),
                domain: None,
                path: None,
                secure: false,
                http_only: false,
                same_site: None,
            }],
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
            simhash: None,
        };
        let entries = blind_entries(&cipher, &http);
        assert_eq!(entries.len(), 3);
        // Wielkość liter nie ma znaczenia; inny klucz daje inny skrót.
        assert_eq!(entries[0].1, cipher.blind_index("cookie", "phpsessid"));
        assert_ne!(
            entries[0].1,
            Cipher::new(&[8; 32]).blind_index("cookie", "phpsessid")
        );
    }
}
