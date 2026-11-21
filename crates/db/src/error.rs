use std::fmt;

use dscan_crypto::CryptoError;

/// Błędy warstwy bazy danych.
#[derive(Debug)]
pub enum DbError {
    /// Nie udało się połączyć z bazą (zły adres, baza nie działa, złe hasło).
    Connect(sqlx::Error),
    Migrate(sqlx::migrate::MigrateError),
    Query(sqlx::Error),
    /// Szyfrowanie lub odszyfrowanie pola wrażliwego nie powiodło się.
    Crypto {
        context: String,
        source: CryptoError,
    },
    /// Wartość pola wrażliwego nie dała się zamienić na JSON lub z JSON.
    Serialization(String),
    UserExists(String),
    /// W bazie brakuje wbudowanej roli (np. nie wykonano migracji).
    MissingRole(&'static str),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbError::Connect(error) => {
                write!(f, "nie można połączyć się z bazą danych: {error}")?;
                if error.to_string().contains("password authentication failed") {
                    write!(
                        f,
                        " — hasło w DSCAN_DATABASE_URL nie pasuje do bazy; uruchom przez ./run.sh \
                         (synchronizuje hasło bazy z Dockera z .env) albo popraw adres w .env"
                    )?;
                }
                Ok(())
            }
            DbError::Migrate(error) => write!(f, "błąd migracji bazy danych: {error}"),
            DbError::Query(error) => write!(f, "błąd zapytania do bazy danych: {error}"),
            DbError::Crypto { context, source } => write!(f, "pole {context}: {source}"),
            DbError::Serialization(reason) => write!(f, "błąd serializacji pola: {reason}"),
            DbError::UserExists(name) => write!(f, "użytkownik '{name}' już istnieje"),
            DbError::MissingRole(name) => {
                write!(f, "brak roli '{name}' w bazie — wykonaj: dscan db migrate")
            }
        }
    }
}

impl std::error::Error for DbError {}
