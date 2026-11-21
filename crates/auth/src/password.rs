use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

use crate::AuthError;

pub const MIN_PASSWORD_LEN: usize = 12;
/// Górny limit chroni przed bardzo długimi hasłami, których haszowanie byłoby kosztowne.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Sprawdza minimalne wymagania wobec hasła (długość liczona w znakach, nie bajtach).
pub fn validate_password_strength(password: &str) -> Result<(), AuthError> {
    let length = password.chars().count();
    if length < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword(format!(
            "musi mieć co najmniej {MIN_PASSWORD_LEN} znaków"
        )));
    }
    if length > MAX_PASSWORD_LEN {
        return Err(AuthError::WeakPassword(format!(
            "może mieć najwyżej {MAX_PASSWORD_LEN} znaków"
        )));
    }
    if password.trim().is_empty() {
        return Err(AuthError::WeakPassword(
            "nie może składać się z samych spacji".into(),
        ));
    }
    Ok(())
}

/// Skrót hasła w formacie PHC (`$argon2id$v=19$m=…`), z losową solą.
/// Parametry domyślne argon2 odpowiadają zaleceniom OWASP.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::Hashing(error.to_string()))
}

/// Czy hasło pasuje do zapisanego skrótu.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, AuthError> {
    let parsed =
        PasswordHash::new(stored_hash).map_err(|error| AuthError::Hashing(error.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_password_is_rejected() {
        assert!(validate_password_strength("krotkie").is_err());
        assert!(validate_password_strength("dokładnie12z").is_ok());
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        // 12 znaków, ale więcej niż 12 bajtów (polskie litery).
        assert!(validate_password_strength("ąęśćżźółńąęś").is_ok());
    }

    #[test]
    fn whitespace_only_password_is_rejected() {
        assert!(validate_password_strength(&" ".repeat(20)).is_err());
    }

    #[test]
    fn too_long_password_is_rejected() {
        assert!(validate_password_strength(&"a".repeat(MAX_PASSWORD_LEN + 1)).is_err());
    }

    #[test]
    fn hash_is_argon2id_and_verifies() {
        let hash = hash_password("poprawne hasło 123").unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("poprawne hasło 123", &hash).unwrap());
        assert!(!verify_password("złe hasło", &hash).unwrap());
    }

    #[test]
    fn same_password_gives_different_hashes() {
        assert_ne!(
            hash_password("hasło-do-testu").unwrap(),
            hash_password("hasło-do-testu").unwrap()
        );
    }

    #[test]
    fn broken_stored_hash_is_an_error() {
        assert!(verify_password("x", "to-nie-jest-skrot").is_err());
    }
}
