//! Stopniowa rotacja klucza (B6): każdy rekord zawiera identyfikator klucza, więc stare
//! rekordy można przeszyfrowywać partiami (bez jednej długiej transakcji), a w tym czasie
//! aplikacja czyta je starym kluczem z pęku.

use dscan_crypto::Cipher;

use crate::keys::{RotatedColumn, reencrypt};
use crate::{DbError, ENCRYPTED_COLUMNS, PgPool};

/// Liczba rekordów kolumny według identyfikatora klucza (`None` = format bez identyfikatora).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsage {
    pub context: String,
    pub key_id: Option<u8>,
    pub records: i64,
}

/// Ile rekordów każdej kolumny zaszyfrowano którym kluczem.
pub async fn key_usage(pool: &PgPool) -> Result<Vec<KeyUsage>, DbError> {
    let mut usage = Vec::new();
    for column in ENCRYPTED_COLUMNS.iter() {
        // Nazwy z listy stałej ENCRYPTED_COLUMNS — bezpieczne do wstawienia w zapytanie.
        let query = format!(
            "SELECT CASE WHEN get_byte({col}, 0) = 2 THEN get_byte({col}, 1) END AS key_id, count(*) \
             FROM {table} WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY 1",
            col = column.column,
            table = column.table
        );
        let rows: Vec<(Option<i32>, i64)> = sqlx::query_as(&query)
            .fetch_all(pool)
            .await
            .map_err(DbError::Query)?;
        usage.extend(rows.into_iter().map(|(key_id, records)| KeyUsage {
            context: column.context(),
            key_id: key_id.and_then(|id| u8::try_from(id).ok()),
            records,
        }));
    }
    Ok(usage)
}

/// Przeszyfrowuje bieżącym kluczem rekordy zapisane innym kluczem, partiami po `batch`
/// (każda partia w osobnej transakcji). Na koniec przebudowuje ślepy indeks.
pub async fn reencrypt_stale(
    pool: &PgPool,
    cipher: &Cipher,
    batch: i64,
) -> Result<Vec<RotatedColumn>, DbError> {
    let mut report = Vec::new();
    for column in ENCRYPTED_COLUMNS.iter() {
        let select = format!(
            "SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL \
             AND (get_byte({col}, 0) <> 2 OR get_byte({col}, 1) <> $1) LIMIT $2 FOR UPDATE SKIP LOCKED",
            col = column.column,
            table = column.table
        );
        let update = format!(
            "UPDATE {table} SET {col} = $1 WHERE id = $2",
            col = column.column,
            table = column.table
        );
        let mut values = 0u64;
        loop {
            let mut transaction = pool.begin().await.map_err(DbError::Query)?;
            let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(&select)
                .bind(i32::from(cipher.key_id()))
                .bind(batch)
                .fetch_all(&mut *transaction)
                .await
                .map_err(DbError::Query)?;
            if rows.is_empty() {
                break;
            }
            for (id, data) in &rows {
                // Ten sam szyfr odszyfrowuje (pęk kluczy) i szyfruje (bieżący klucz).
                let fresh = reencrypt(cipher, cipher, column, data)?;
                sqlx::query(&update)
                    .bind(fresh)
                    .bind(id)
                    .execute(&mut *transaction)
                    .await
                    .map_err(DbError::Query)?;
            }
            transaction.commit().await.map_err(DbError::Query)?;
            values += rows.len() as u64;
        }
        report.push(RotatedColumn {
            context: column.context(),
            values,
        });
    }
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let rebuilt = crate::keys::rebuild_blind_index(&mut transaction, cipher).await?;
    transaction.commit().await.map_err(DbError::Query)?;
    report.push(RotatedColumn {
        context: "http_blind_index (przebudowa)".into(),
        values: rebuilt,
    });
    Ok(report)
}
