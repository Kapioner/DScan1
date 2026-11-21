use std::fmt;

/// Błędy haseł i loginów.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    WeakPassword(String),
    InvalidUsername(String),
    /// Błąd biblioteki argon2 (np. uszkodzony zapisany skrót).
    Hashing(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::WeakPassword(reason) => write!(f, "hasło odrzucone: {reason}"),
            AuthError::InvalidUsername(reason) => write!(f, "niepoprawny login: {reason}"),
            AuthError::Hashing(reason) => write!(f, "błąd skrótu hasła: {reason}"),
        }
    }
}

impl std::error::Error for AuthError {}
