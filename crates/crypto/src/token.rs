//! Tokeny sesji (zadanie A2). Użytkownik dostaje losowy token w ciasteczku,
//! a w bazie zapisujemy tylko jego skrót SHA-256 — wyciek bazy nie pozwala przejąć sesji.

use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use sha2::{Digest, Sha256};

use crate::encode_hex;

/// Długość tokenu w bajtach (256 bitów losowości).
pub const TOKEN_LEN: usize = 32;

/// Nowy losowy token jako 64 znaki hex.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_LEN];
    OsRng.fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

/// Skrót SHA-256 tokenu (32 bajty) do zapisania i wyszukiwania w bazie.
pub fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_random_hex() {
        let first = generate_token();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, generate_token());
    }

    #[test]
    fn hash_is_stable_sha256() {
        assert_eq!(hash_token("abc").len(), 32);
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("abd"));
        // Znana wartość SHA-256("abc").
        assert_eq!(
            encode_hex(&hash_token("abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
