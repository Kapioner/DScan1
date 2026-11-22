use std::fmt;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::{CryptoError, encode_hex};

/// Bieżąca wersja formatu: `[2][id klucza 1 B][nonce 12 B][szyfrogram + tag]` (B6).
pub const FORMAT_VERSION: u8 = 2;
/// Format bez identyfikatora klucza (`[1][nonce][szyfrogram]`) — nadal odczytywany.
pub const LEGACY_FORMAT_VERSION: u8 = 1;
/// Długość klucza AES-256 w bajtach.
pub const KEY_LEN: usize = 32;
/// Długość nonce AES-GCM w bajtach.
pub const NONCE_LEN: usize = 12;

const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2 + NONCE_LEN;
const LEGACY_HEADER_LEN: usize = 1 + NONCE_LEN;

/// Szyfr AES-256-GCM z kluczem aplikacji.
#[derive(Clone)]
pub struct Cipher {
    aead: Aes256Gcm,
    /// Identyfikator bieżącego klucza zapisywany w każdym rekordzie (B6).
    key_id: u8,
    /// Poprzednie klucze — tylko do odczytu, do czasu `dscan keys reencrypt`.
    previous: Vec<(u8, Aes256Gcm)>,
    /// Klucz ślepego indeksu (B3), wyprowadzony z klucza aplikacji — inny niż klucz AES.
    index_key: [u8; 32],
}

impl Cipher {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Cipher {
            aead: Aes256Gcm::new(key.into()),
            key_id: 1,
            previous: Vec::new(),
            index_key: crate::hmac::hmac_sha256(key, b"dscan blind index v1"),
        }
    }

    /// Bieżący klucz z innym identyfikatorem (1–255).
    pub fn with_key_id(mut self, key_id: u8) -> Self {
        self.key_id = key_id;
        self
    }

    /// Dodaje poprzedni klucz do odczytu starszych rekordów.
    pub fn with_previous_key(mut self, key_id: u8, key: &[u8; KEY_LEN]) -> Self {
        self.previous.push((key_id, Aes256Gcm::new(key.into())));
        self
    }

    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    /// Identyfikator klucza zapisany w rekordzie (`None` dla formatu bez identyfikatora).
    pub fn record_key_id(data: &[u8]) -> Option<u8> {
        (data.first() == Some(&FORMAT_VERSION))
            .then(|| data.get(1).copied())
            .flatten()
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
        output.push(self.key_id);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Odszyfrowuje wartość zapisaną przez [`Cipher::encrypt`] — bieżącym albo poprzednim
    /// kluczem według identyfikatora w rekordzie; format bez identyfikatora próbuje kolejno
    /// wszystkich kluczy.
    pub fn decrypt(&self, data: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let version = *data.first().ok_or(CryptoError::TooShort)?;
        let (candidates, body): (Vec<&Aes256Gcm>, &[u8]) = match version {
            FORMAT_VERSION => {
                if data.len() < HEADER_LEN + TAG_LEN {
                    return Err(CryptoError::TooShort);
                }
                let id = data[1];
                let key = if id == self.key_id {
                    Some(&self.aead)
                } else {
                    self.previous
                        .iter()
                        .find(|(k, _)| *k == id)
                        .map(|(_, aead)| aead)
                };
                (key.into_iter().collect(), &data[2..])
            }
            LEGACY_FORMAT_VERSION => {
                if data.len() < LEGACY_HEADER_LEN + TAG_LEN {
                    return Err(CryptoError::TooShort);
                }
                (
                    std::iter::once(&self.aead)
                        .chain(self.previous.iter().map(|(_, a)| a))
                        .collect(),
                    &data[1..],
                )
            }
            other => return Err(CryptoError::UnsupportedVersion(other)),
        };
        let (nonce, ciphertext) = body.split_at(NONCE_LEN);
        candidates
            .into_iter()
            .find_map(|aead| {
                aead.decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext,
                        aad: context,
                    },
                )
                .ok()
            })
            .ok_or(CryptoError::Decrypt)
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

    #[test]
    fn key_id_is_stored_and_previous_keys_still_decrypt() {
        let old = Cipher::new(&[1; 32]);
        let record = old.encrypt(b"tajne", b"ctx").unwrap();
        assert_eq!(Cipher::record_key_id(&record), Some(1));
        let new = Cipher::new(&[2; 32])
            .with_key_id(2)
            .with_previous_key(1, &[1; 32]);
        assert_eq!(new.decrypt(&record, b"ctx").unwrap(), b"tajne");
        let fresh = new.encrypt(b"x", b"ctx").unwrap();
        assert_eq!(Cipher::record_key_id(&fresh), Some(2));
        // Bez starego klucza stary rekord jest nieczytelny.
        assert!(
            Cipher::new(&[2; 32])
                .with_key_id(2)
                .decrypt(&record, b"ctx")
                .is_err()
        );
    }

    #[test]
    fn legacy_records_without_key_id_are_read() {
        let key = [5u8; 32];
        let cipher = Cipher::new(&key);
        // Ręcznie złożony rekord w formacie v1.
        let nonce = [0u8; NONCE_LEN];
        let aead = Aes256Gcm::new((&key).into());
        let ct = aead
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"stare",
                    aad: b"c",
                },
            )
            .unwrap();
        let mut legacy = vec![LEGACY_FORMAT_VERSION];
        legacy.extend_from_slice(&nonce);
        legacy.extend_from_slice(&ct);
        assert_eq!(cipher.decrypt(&legacy, b"c").unwrap(), b"stare");
        assert_eq!(Cipher::record_key_id(&legacy), None);
    }

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
        assert_eq!(encrypted.len(), 2 + NONCE_LEN + 3 + TAG_LEN);
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
