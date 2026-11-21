use std::fmt;

/// Błędy warstwy bazy danych.
#[derive(Debug)]
pub enum DbError {
    /// Nie udało się połączyć z bazą (zły adres, baza nie działa, złe hasło).
    Connect(sqlx::Error),
    Migrate(sqlx::migrate::MigrateError),
    Query(sqlx::Error),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Connect(error) => write!(f, "nie można połączyć się z bazą danych: {error}"),
            DbError::Migrate(error) => write!(f, "błąd migracji bazy danych: {error}"),
            DbError::Query(error) => write!(f, "błąd zapytania do bazy danych: {error}"),
        }
    }
}

impl std::error::Error for DbError {}
