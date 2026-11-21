use std::fmt;

use dscan_db::DbError;

/// Błędy silnika skanów.
#[derive(Debug)]
pub enum EngineError {
    NoTargets,
    TooManyAddresses {
        count: u128,
        limit: u64,
    },
    Database(DbError),
    NotResumable(String),
    /// Błąd konfiguracji skanu (profil, sygnatury, klient HTTP).
    Setup(String),
    /// Profil ma okna czasowe, a teraz żadne nie jest otwarte.
    OutsideWindow,
    /// Żaden cel nie jest w dozwolonym zakresie; plan zawiera powody odrzucenia.
    NoTargetsInScope(Box<dscan_scanner::targets::TargetPlan>),
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
            EngineError::NotResumable(reason) => write!(f, "nie można wznowić: {reason}"),
            EngineError::Setup(reason) => write!(f, "{reason}"),
            EngineError::OutsideWindow => write!(
                f,
                "teraz jest poza oknem czasowym profilu — skan nie został uruchomiony"
            ),
            EngineError::NoTargetsInScope(_) => write!(
                f,
                "brak celów do skanowania w dozwolonym zakresie — dodaj sieci do [scope] allowed_networks w dscan.toml"
            ),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<DbError> for EngineError {
    fn from(error: DbError) -> Self {
        EngineError::Database(error)
    }
}
