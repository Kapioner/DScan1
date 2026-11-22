use std::fmt;

use crate::ConfigError;

/// Zmienna środowiskowa z kluczem szyfrowania (64 znaki hex = 32 bajty, AES-256).
pub const ENCRYPTION_KEY_ENV: &str = "DSCAN_ENCRYPTION_KEY";

/// Login i hasło administratora tworzonego przy pierwszym starcie serwera.
pub const ADMIN_USERNAME_ENV: &str = "DSCAN_ADMIN_USERNAME";
pub const ADMIN_PASSWORD_ENV: &str = "DSCAN_ADMIN_PASSWORD";

/// Nowy klucz używany tylko przez `dscan keys rotate`.
pub const NEW_ENCRYPTION_KEY_ENV: &str = "DSCAN_NEW_ENCRYPTION_KEY";

/// Zmienna środowiskowa z adresem bazy, np. `postgres://dscan:haslo@127.0.0.1:5433/dscan`.
pub const DATABASE_URL_ENV: &str = "DSCAN_DATABASE_URL";

/// Token API DefectDojo (I4, I5) — tylko ze zmiennej środowiskowej.
pub const DEFECTDOJO_TOKEN_ENV: &str = "DSCAN_DEFECTDOJO_TOKEN";

/// Token API DefectDojo; w logach i `Debug` zamaskowany.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken(String);

impl ApiToken {
    /// `None` dla pustej wartości.
    pub fn from_value(value: Option<&str>) -> Option<Self> {
        value
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| ApiToken(v.to_string()))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ApiToken(***)")
    }
}

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

/// Adres bazy danych. Zawiera hasło, więc `Debug` pokazuje go z ukrytym hasłem.
#[derive(Clone, PartialEq, Eq)]
pub struct DatabaseUrl(String);

impl DatabaseUrl {
    pub fn new(url: &str) -> Self {
        DatabaseUrl(url.trim().to_string())
    }

    /// Pełny adres — tylko do nawiązania połączenia, nigdy do wypisywania.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Adres bezpieczny do pokazania użytkownikowi.
    pub fn masked(&self) -> String {
        mask_url_password(&self.0)
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DatabaseUrl({})", self.masked())
    }
}

/// Pierwszy administrator ze zmiennych środowiskowych. `Debug` ukrywa hasło.
#[derive(Clone, PartialEq, Eq)]
pub struct InitialAdmin {
    pub username: String,
    password: String,
}

impl InitialAdmin {
    /// `None`, gdy brakuje loginu albo hasła (puste wartości też oznaczają brak).
    pub fn from_values(username: Option<&str>, password: Option<&str>) -> Option<Self> {
        let username = username.map(str::trim).filter(|value| !value.is_empty())?;
        let password = password.filter(|value| !value.is_empty())?;
        Some(InitialAdmin {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    /// Hasło — tylko do zahaszowania, nigdy do wypisywania.
    pub fn expose_password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for InitialAdmin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InitialAdmin({}, ***)", self.username)
    }
}

/// Zastępuje hasło w adresie `schemat://użytkownik:hasło@host/...` gwiazdkami.
pub fn mask_url_password(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let credentials_start = scheme_end + 3;
    let Some(at_offset) = url[credentials_start..].rfind('@') else {
        return url.to_string();
    };
    let credentials_end = credentials_start + at_offset;

    match url[credentials_start..credentials_end].find(':') {
        Some(colon_offset) => {
            let password_start = credentials_start + colon_offset + 1;
            format!("{}***{}", &url[..password_start], &url[credentials_end..])
        }
        None => url.to_string(),
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
    fn initial_admin_needs_both_values() {
        assert!(InitialAdmin::from_values(Some("admin"), Some("hasło")).is_some());
        assert!(InitialAdmin::from_values(Some("admin"), None).is_none());
        assert!(InitialAdmin::from_values(Some(" "), Some("hasło")).is_none());
        assert!(InitialAdmin::from_values(None, Some("hasło")).is_none());
    }

    #[test]
    fn initial_admin_debug_hides_password() {
        let admin = InitialAdmin::from_values(Some("admin"), Some("tajne-haslo")).unwrap();
        assert_eq!(format!("{admin:?}"), "InitialAdmin(admin, ***)");
        assert_eq!(admin.expose_password(), "tajne-haslo");
    }

    #[test]
    fn mask_hides_password() {
        assert_eq!(
            mask_url_password("postgres://dscan:tajne@127.0.0.1:5433/dscan"),
            "postgres://dscan:***@127.0.0.1:5433/dscan"
        );
    }

    #[test]
    fn mask_handles_at_sign_in_password() {
        assert_eq!(
            mask_url_password("postgres://dscan:a@b@host/db"),
            "postgres://dscan:***@host/db"
        );
    }

    #[test]
    fn mask_leaves_urls_without_password() {
        for url in ["postgres://dscan@host/db", "postgres://host/db", "nie-url"] {
            assert_eq!(mask_url_password(url), url);
        }
    }

    #[test]
    fn database_url_debug_is_masked() {
        let url = DatabaseUrl::new("postgres://dscan:tajne@host/db");
        assert!(!format!("{url:?}").contains("tajne"));
        assert_eq!(url.expose(), "postgres://dscan:tajne@host/db");
    }

    #[test]
    fn debug_hides_key_value() {
        let key = EncryptionKey::from_hex(VALID_KEY).unwrap();
        let printed = format!("{key:?}");
        assert_eq!(printed, "EncryptionKey(***)");
    }
}
