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
