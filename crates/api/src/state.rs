use std::sync::Arc;

use dscan_crypto::Cipher;
use dscan_db::PgPool;
use dscan_engine::ScanService;

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
    /// Usługa skanów (start/stop/wznowienie, import); `None` w testach bez skanera.
    pub scans: Option<Arc<ScanService>>,
    /// Klient DefectDojo (I4, I5); `None`, gdy integracja wyłączona.
    pub defectdojo: Option<Arc<dscan_integrations::defectdojo::DefectDojoClient>>,
}

impl AppState {
    pub fn new(db: PgPool, cipher: Cipher, auth: AuthConfig) -> Self {
        AppState {
            db,
            cipher,
            auth,
            scans: None,
            defectdojo: None,
        }
    }

    /// Dołącza usługę skanów (serwer).
    pub fn with_scans(mut self, scans: Arc<ScanService>) -> Self {
        self.scans = Some(scans);
        self
    }

    /// Dołącza klienta DefectDojo.
    pub fn with_defectdojo(
        mut self,
        client: Arc<dscan_integrations::defectdojo::DefectDojoClient>,
    ) -> Self {
        self.defectdojo = Some(client);
        self
    }

    /// Usługa skanów albo błąd 503 (np. serwer bez skanera).
    pub fn scan_service(&self) -> Result<&Arc<ScanService>, crate::ApiError> {
        self.scans
            .as_ref()
            .ok_or_else(|| crate::ApiError::Unavailable("usługa skanów nie jest dostępna".into()))
    }
}
