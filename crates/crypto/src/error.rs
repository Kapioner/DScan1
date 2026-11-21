use std::fmt;

/// Błędy szyfrowania i odszyfrowania.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Encrypt,
    /// Zły klucz, zły kontekst albo dane zostały zmienione.
    Decrypt,
    UnsupportedVersion(u8),
    TooShort,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Encrypt => write!(f, "nie udało się zaszyfrować danych"),
            CryptoError::Decrypt => write!(
                f,
                "nie udało się odszyfrować danych (zły klucz szyfrowania lub uszkodzone dane)"
            ),
            CryptoError::UnsupportedVersion(version) => {
                write!(f, "nieobsługiwana wersja formatu szyfrowania: {version}")
            }
            CryptoError::TooShort => write!(f, "zaszyfrowane dane są za krótkie"),
        }
    }
}

impl std::error::Error for CryptoError {}
