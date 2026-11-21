use crate::AuthError;

pub const MIN_USERNAME_LEN: usize = 3;
pub const MAX_USERNAME_LEN: usize = 64;

/// Login: 3–64 znaki, małe litery łacińskie, cyfry oraz `.`, `_`, `-`.
pub fn validate_username(username: &str) -> Result<(), AuthError> {
    let length = username.len();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&length) {
        return Err(AuthError::InvalidUsername(format!(
            "musi mieć od {MIN_USERNAME_LEN} do {MAX_USERNAME_LEN} znaków"
        )));
    }
    let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c);
    if !username.chars().all(allowed) {
        return Err(AuthError::InvalidUsername(
            "dozwolone są tylko małe litery a-z, cyfry oraz . _ -".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        for name in ["admin", "jan.kowalski", "user_01", "a-b"] {
            assert!(validate_username(name).is_ok(), "{name}");
        }
    }

    #[test]
    fn invalid_usernames() {
        for name in [
            "ab",
            "Admin",
            "jan kowalski",
            "łukasz",
            "x;drop",
            &"a".repeat(65),
        ] {
            assert!(validate_username(name).is_err(), "{name}");
        }
    }
}
