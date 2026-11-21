use std::fmt;

use crate::ConfigError;

/// Zmienna środowiskowa z kluczem szyfrowania (64 znaki hex = 32 bajty, AES-256).
pub const ENCRYPTION_KEY_ENV: &str = "DSCAN_ENCRYPTION_KEY";

/// Długość klucza AES-256 w bajtach.
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Klucz szyfrowania pól wrażliwych. `Debug` nie ujawnia jego wartości,
/// więc klucz nie wycieknie przypadkiem do logów ani do `config show`.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptionKey([u8; ENCRYPTION_KEY_LEN]);

impl EncryptionKey {
    /// Tworzy klucz z zapisu szesnastkowego (np. wynik `openssl rand -hex 32`).
    pub fn from_hex(text: &str) -> Result<Self, ConfigError> {
        decode_hex_key(text).map(EncryptionKey)
    }

    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptionKey(***)")
    }
}

/// Zamienia 64 znaki szesnastkowe na 32 bajty klucza.
pub fn decode_hex_key(text: &str) -> Result<[u8; ENCRYPTION_KEY_LEN], ConfigError> {
    let text = text.trim();
    let expected_len = ENCRYPTION_KEY_LEN * 2;
    if text.len() != expected_len {
        return Err(ConfigError::InvalidEncryptionKey(format!(
            "oczekiwano {expected_len} znaków hex, otrzymano {}",
            text.len()
        )));
    }

    let mut key = [0u8; ENCRYPTION_KEY_LEN];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        key[index] = decode_hex_byte(pair)?;
    }
    Ok(key)
}

fn decode_hex_byte(pair: &[u8]) -> Result<u8, ConfigError> {
    let invalid = || ConfigError::InvalidEncryptionKey("dozwolone są tylko znaki 0-9 i a-f".into());
    let text = std::str::from_utf8(pair).map_err(|_| invalid())?;
    u8::from_str_radix(text, 16).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn decodes_valid_hex_key() {
        let key = decode_hex_key(VALID_KEY).unwrap();
        assert_eq!(key[0], 0x00);
        assert_eq!(key[10], 0x0a);
        assert_eq!(key[31], 0x1f);
    }

    #[test]
    fn accepts_uppercase_hex() {
        let upper = VALID_KEY.to_uppercase();
        assert_eq!(
            decode_hex_key(&upper).unwrap(),
            decode_hex_key(VALID_KEY).unwrap()
        );
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_hex_key("abcd").is_err());
        assert!(decode_hex_key(&format!("{VALID_KEY}00")).is_err());
    }

    #[test]
    fn rejects_non_hex_characters() {
        let invalid = VALID_KEY.replace('a', "z");
        assert!(decode_hex_key(&invalid).is_err());
    }

    #[test]
    fn rejects_multibyte_characters_without_panic() {
        // 63 znaki ASCII + "ą" (2 bajty) = 64 bajty, ale nie hex.
        let tricky = format!("{}ą", &VALID_KEY[..62]);
        assert!(decode_hex_key(&tricky).is_err());
    }

    #[test]
    fn debug_hides_key_value() {
        let key = EncryptionKey::from_hex(VALID_KEY).unwrap();
        let printed = format!("{key:?}");
        assert_eq!(printed, "EncryptionKey(***)");
    }
}
