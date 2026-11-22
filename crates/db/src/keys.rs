use dscan_crypto::Cipher;
use sqlx::{Postgres, Transaction};

use crate::{DbError, ENCRYPTED_COLUMNS, EncryptedColumn, PgPool};

/// Liczba przeszyfrowanych wartości w kolumnie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotatedColumn {
    pub context: String,
    pub values: u64,
}

/// Przeszyfrowuje wszystkie pola wrażliwe ze starego klucza na nowy.
/// Całość dzieje się w jednej transakcji: błąd w dowolnym rekordzie (np. zły stary klucz)
/// wycofuje wszystkie zmiany.
pub async fn rotate_encryption_key(
    pool: &PgPool,
    old: &Cipher,
    new: &Cipher,
) -> Result<Vec<RotatedColumn>, DbError> {
    let mut transaction = pool.begin().await.map_err(DbError::Query)?;
    let mut report = Vec::new();
    for column in &ENCRYPTED_COLUMNS {
        let values = rotate_column(&mut transaction, column, old, new).await?;
        report.push(RotatedColumn {
            context: column.context(),
            values,
        });
    }
    let rebuilt = rebuild_blind_index(&mut transaction, new).await?;
    report.push(RotatedColumn {
        context: "http_blind_index (przebudowa)".into(),
        values: rebuilt,
    });
    transaction.commit().await.map_err(DbError::Query)?;
    Ok(report)
}

async fn rotate_column(
    transaction: &mut Transaction<'_, Postgres>,
    column: &EncryptedColumn,
    old: &Cipher,
    new: &Cipher,
) -> Result<u64, DbError> {
    // Nazwy tabel i kolumn pochodzą ze stałej listy ENCRYPTED_COLUMNS, a nie od użytkownika,
    // więc wstawienie ich do tekstu zapytania jest bezpieczne.
    let select = format!(
        "SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL FOR UPDATE",
        col = column.column,
        table = column.table
    );
    let update = format!(
        "UPDATE {table} SET {col} = $1 WHERE id = $2",
        col = column.column,
        table = column.table
    );

    let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(&select)
        .fetch_all(&mut **transaction)
        .await
        .map_err(DbError::Query)?;

    for (id, data) in &rows {
        let reencrypted = reencrypt(old, new, column, data)?;
        sqlx::query(&update)
            .bind(reencrypted)
            .bind(id)
            .execute(&mut **transaction)
            .await
            .map_err(DbError::Query)?;
    }
    Ok(rows.len() as u64)
}

/// Odszyfrowuje wartość starym kluczem i szyfruje nowym (z tym samym kontekstem kolumny).
pub fn reencrypt(
    old: &Cipher,
    new: &Cipher,
    column: &EncryptedColumn,
    data: &[u8],
) -> Result<Vec<u8>, DbError> {
    let context = column.context();
    let plaintext = old
        .decrypt(data, context.as_bytes())
        .map_err(|source| column.crypto_error(source))?;
    new.encrypt(&plaintext, context.as_bytes())
        .map_err(|source| column.crypto_error(source))
}

/// Ślepy indeks zależy od klucza (B3), więc po rotacji liczymy go od nowa
/// z odszyfrowanych (już nowym kluczem) nagłówków i ciasteczek.
async fn rebuild_blind_index(
    transaction: &mut Transaction<'_, Postgres>,
    new: &Cipher,
) -> Result<u64, DbError> {
    use dscan_core::models::{Cookie, HttpHeader, HttpInfo};

    use crate::Encrypted;
    use crate::columns::{HTTP_INFO_COOKIES, HTTP_INFO_HEADERS};

    sqlx::query("DELETE FROM http_blind_index")
        .execute(&mut **transaction)
        .await
        .map_err(DbError::Query)?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT service_id, headers, cookies FROM http_info")
            .fetch_all(&mut **transaction)
            .await
            .map_err(DbError::Query)?;
    let mut infos = Vec::with_capacity(rows.len());
    for (service_id, headers, cookies) in rows {
        let info = HttpInfo {
            url: String::new(),
            status_code: 0,
            title: None,
            headers: Encrypted::<Vec<HttpHeader>>::from_bytes(headers)
                .open(new, &HTTP_INFO_HEADERS)?,
            cookies: Encrypted::<Vec<Cookie>>::from_bytes(cookies).open(new, &HTTP_INFO_COOKIES)?,
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
            simhash: None,
        };
        infos.push((service_id, info));
    }
    let refs: Vec<(i64, &HttpInfo)> = infos.iter().map(|(id, info)| (*id, info)).collect();
    crate::blind_index::insert_blind_index(transaction, new, &refs).await?;
    Ok(refs.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::columns::TARGETS_NOTE;

    #[test]
    fn reencrypted_value_opens_only_with_new_key() {
        let old = Cipher::new(&[1; 32]);
        let new = Cipher::new(&[2; 32]);
        let context = TARGETS_NOTE.context();
        let data = old.encrypt(b"notatka", context.as_bytes()).unwrap();

        let rotated = reencrypt(&old, &new, &TARGETS_NOTE, &data).unwrap();

        assert_eq!(
            new.decrypt(&rotated, context.as_bytes()).unwrap(),
            b"notatka"
        );
        assert!(old.decrypt(&rotated, context.as_bytes()).is_err());
    }

    #[test]
    fn reencrypt_with_wrong_old_key_fails() {
        let real = Cipher::new(&[1; 32]);
        let wrong = Cipher::new(&[3; 32]);
        let data = real
            .encrypt(b"x", TARGETS_NOTE.context().as_bytes())
            .unwrap();

        assert!(reencrypt(&wrong, &real, &TARGETS_NOTE, &data).is_err());
    }
}
