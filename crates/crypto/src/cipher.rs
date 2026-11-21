use std::fmt;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::{CryptoError, encode_hex};

/// Bieżąca wersja formatu zaszyfrowanej wartości.
pub const FORMAT_VERSION: u8 = 1;
/// Długość klucza AES-256 w bajtach.
pub const KEY_LEN: usize = 32;
/// Długość nonce AES-GCM w bajtach.
pub const NONCE_LEN: usize = 12;

const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 1 + NONCE_LEN;

/// Szyfr AES-256-GCM z kluczem aplikacji.
#[derive(Clone)]
pub struct Cipher {
    aead: Aes256Gcm,
    /// Klucz ślepego indeksu (B3), wyprowadzony z klucza aplikacji — inny niż klucz AES.
    index_key: [u8; 32],
}

impl Cipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Cipher {
            aead: Aes256Gcm::new(key.into()),
            index_key: crate::hmac::hmac_sha256(key, b"dscan blind index v1"),
        }
    }

    /// Ślepy indeks (B3): HMAC-SHA256 wartości w danej domenie (np. `cookie`). Ta sama
    /// wartość daje zawsze ten sam skrót, więc można po nim wyszukiwać, nie znając wartości.
    /// Wartość jest normalizowana (małe litery, bez spacji na brzegach).
    pub fn blind_index(&self, domain: &str, value: &str) -> Vec<u8> {
        let message = format!("{domain}\0{}", value.trim().to_lowercase());
        crate::hmac::hmac_sha256(&self.index_key, message.as_bytes()).to_vec()
    }

    /// Szyfruje `plaintext`; `context` (np. `"services.banner"`) musi być taki sam przy odszyfrowaniu.
    pub fn encrypt(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad: context,
        };
        let ciphertext = self
            .aead
            .encrypt(&nonce, payload)
            .map_err(|_| CryptoError::Encrypt)?;

        let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        output.push(FORMAT_VERSION);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Odszyfrowuje wartość zapisaną przez [`Cipher::encrypt`].
    pub fn decrypt(&self, data: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < HEADER_LEN + TAG_LEN {
            return Err(CryptoError::TooShort);
        }
        let (version, rest) = (data[0], &data[1..]);
        if version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let payload = Payload {
            msg: ciphertext,
            aad: context,
        };
        self.aead
            .decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| CryptoError::Decrypt)
    }
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cipher(***)")
    }
}

/// Nowy losowy klucz AES-256 jako 64 znaki hex (format zmiennej `DSCAN_ENCRYPTION_KEY`).
pub fn generate_key_hex() -> String {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    encode_hex(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTEXT: &[u8] = b"services.banner";

    fn cipher(byte: u8) -> Cipher {
        Cipher::new(&[byte; KEY_LEN])
    }

    #[test]
    fn round_trip_returns_original_data() {
        let cipher = cipher(1);
        let encrypted = cipher.encrypt(b"SSH-2.0-OpenSSH_9.6", CONTEXT).unwrap();
        assert_eq!(
            cipher.decrypt(&encrypted, CONTEXT).unwrap(),
            b"SSH-2.0-OpenSSH_9.6"
        );
    }

    #[test]
    fn output_has_version_nonce_and_tag() {
        let encrypted = cipher(1).encrypt(b"abc", CONTEXT).unwrap();
        assert_eq!(encrypted[0], FORMAT_VERSION);
        assert_eq!(encrypted.len(), 1 + NONCE_LEN + 3 + TAG_LEN);
    }

    #[test]
    fn same_value_encrypts_differently_each_time() {
        let cipher = cipher(1);
        let first = cipher.encrypt(b"tajne", CONTEXT).unwrap();
        let second = cipher.encrypt(b"tajne", CONTEXT).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn plaintext_is_not_visible_in_output() {
        let encrypted = cipher(1).encrypt(b"Set-Cookie: session", CONTEXT).unwrap();
        let visible = String::from_utf8_lossy(&encrypted);
        assert!(!visible.contains("session"));
    }

    #[test]
    fn wrong_key_fails() {
        let encrypted = cipher(1).encrypt(b"tajne", CONTEXT).unwrap();
        assert_eq!(
            cipher(2).decrypt(&encrypted, CONTEXT),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn wrong_context_fails() {
        let cipher = cipher(1);
        let encrypted = cipher.encrypt(b"tajne", CONTEXT).unwrap();
        assert_eq!(
            cipher.decrypt(&encrypted, b"targets.note"),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn tampered_data_fails() {
        let cipher = cipher(1);
        let mut encrypted = cipher.encrypt(b"tajne", CONTEXT).unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert_eq!(
            cipher.decrypt(&encrypted, CONTEXT),
            Err(CryptoError::Decrypt)
        );
    }

    #[test]
    fn short_or_unknown_format_is_rejected() {
        let cipher = cipher(1);
        assert_eq!(
            cipher.decrypt(&[1, 2, 3], CONTEXT),
            Err(CryptoError::TooShort)
        );

        let mut encrypted = cipher.encrypt(b"x", CONTEXT).unwrap();
        encrypted[0] = 9;
        assert_eq!(
            cipher.decrypt(&encrypted, CONTEXT),
            Err(CryptoError::UnsupportedVersion(9))
        );
    }

    #[test]
    fn generated_key_is_64_hex_chars_and_random() {
        let first = generate_key_hex();
        assert_eq!(first.len(), 64);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, generate_key_hex());
    }

    #[test]
    fn debug_hides_key() {
        assert_eq!(format!("{:?}", cipher(1)), "Cipher(***)");
    }
}
