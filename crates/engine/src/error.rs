use std::fmt;

use dscan_db::DbError;

/// Błędy silnika skanów.
#[derive(Debug)]
pub enum EngineError {
    NoTargets,
    TooManyAddresses { count: u128, limit: u64 },
    Database(DbError),
}

impl fmt::Display for EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineError::NoTargets => write!(f, "brak adresów do skanowania"),
            EngineError::TooManyAddresses { count, limit } => write!(
                f,
                "skan obejmuje {count} adresów, a limit to {limit} (limits.max_addresses_per_scan)"
            ),
            EngineError::Database(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<DbError> for EngineError {
    fn from(error: DbError) -> Self {
        EngineError::Database(error)
    }
}
