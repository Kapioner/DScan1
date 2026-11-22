//! Zapis wyników usług WWW w paczkach: informacje HTTP (H1, H2) z szyfrowaniem nagłówków
//! i ciasteczek oraz detekcje technologii (H5).

use dscan_core::models::{Detection, HttpInfo};
use dscan_crypto::Cipher;
use sqlx::{PgConnection, Postgres, QueryBuilder};

use crate::columns::{HTTP_INFO_CERTIFICATE, HTTP_INFO_COOKIES, HTTP_INFO_HEADERS};
use crate::results::POSTGRES_MAX_PARAMETERS;
use crate::{DbError, Encrypted};

/// Wpisów HTTP w jednym INSERT (11 parametrów na wiersz).
pub const HTTP_INFO_PER_INSERT: usize = 1000;
const _: () = assert!(HTTP_INFO_PER_INSERT * 11 <= POSTGRES_MAX_PARAMETERS);
/// Detekcji w jednym INSERT (5 parametrów na wiersz).
pub const DETECTIONS_PER_INSERT: usize = 1000;
const _: () = assert!(DETECTIONS_PER_INSERT * 5 <= POSTGRES_MAX_PARAMETERS);

/// Jeden INSERT dla paczki wyników HTTP. Nagłówki i ciasteczka są szyfrowane,
/// łańcuch przekierowań zapisujemy jako JSON.
pub(crate) async fn insert_http_info(
    connection: &mut PgConnection,
    cipher: &Cipher,
    rows: &[(i64, &HttpInfo)],
) -> Result<(), DbError> {
    let mut prepared = Vec::with_capacity(rows.len());
    for (service_id, http) in rows {
        let headers = Encrypted::seal(cipher, &HTTP_INFO_HEADERS, &http.headers)?;
        let cookies = Encrypted::seal(cipher, &HTTP_INFO_COOKIES, &http.cookies)?;
        let certificate = http
            .certificate
            .as_ref()
            .map(|certificate| Encrypted::seal(cipher, &HTTP_INFO_CERTIFICATE, certificate))
            .transpose()?;
        let chain = serde_json::to_string(&http.redirect_chain)
            .map_err(|error| DbError::Serialization(error.to_string()))?;
        let favicon = http
            .favicon
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| DbError::Serialization(error.to_string()))?;
        prepared.push((
            *service_id,
            *http,
            headers,
            cookies,
            chain,
            certificate,
            favicon,
        ));
    }

    let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO http_info (service_id, url, status_code, title, headers, cookies, redirect_chain, tls_verified, certificate, favicon, simhash) ",
    );
    query.push_values(
        prepared,
        |mut row, (service_id, http, headers, cookies, chain, certificate, favicon)| {
            row.push_bind(service_id)
                .push_bind(http.url.clone())
                .push_bind(i32::from(http.status_code))
                .push_bind(http.title.clone())
                .push_bind(headers)
                .push_bind(cookies)
                .push_bind(chain)
                .push_unseparated("::jsonb")
                .push_bind(http.tls_verified)
                .push_bind(certificate)
                .push_bind(favicon)
                .push_unseparated("::jsonb")
                .push_bind(http.simhash);
        },
    );

    query
        .build()
        .execute(&mut *connection)
        .await
        .map_err(DbError::Query)?;
    crate::blind_index::insert_blind_index(connection, cipher, rows).await
}

/// Detekcje technologii (dowody jako JSON) dla paczki usług.
pub(crate) async fn insert_detections(
    connection: &mut PgConnection,
    rows: &[(i64, &Detection)],
) -> Result<(), DbError> {
    let mut prepared = Vec::with_capacity(rows.len());
    for (service_id, detection) in rows {
        let evidence = serde_json::to_string(&detection.evidence)
            .map_err(|error| DbError::Serialization(error.to_string()))?;
        prepared.push((*service_id, *detection, evidence));
    }
    let mut query: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO detections (service_id, technology, version, confidence, evidence) ",
    );
    query.push_values(prepared, |mut row, (service_id, detection, evidence)| {
        row.push_bind(service_id)
            .push_bind(detection.technology.clone())
            .push_bind(detection.version.clone())
            .push_bind(i16::from(detection.confidence))
            .push_bind(evidence)
            .push_unseparated("::jsonb");
    });
    query
        .build()
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(DbError::Query)
}
