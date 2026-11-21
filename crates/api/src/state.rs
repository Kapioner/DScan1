use dscan_crypto::Cipher;
use dscan_db::PgPool;

/// Ustawienia sesji (z sekcji `[server]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthConfig {
    pub session_hours: u32,
    pub secure_cookies: bool,
}

/// Stan współdzielony przez wszystkie handlery. `PgPool` i `Cipher` są tanie do klonowania,
/// więc cały stan może być `Clone`.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    /// Do odszyfrowania pól poufnych (np. notatek celów).
    pub cipher: Cipher,
    pub auth: AuthConfig,
}

impl AppState {
    pub fn new(db: PgPool, cipher: Cipher, auth: AuthConfig) -> Self {
        AppState { db, cipher, auth }
    }
}
