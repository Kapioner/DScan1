use std::future::Future;
use std::net::IpAddr;

use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::error::{ResolveError, ResolveErrorKind};

use crate::ScannerError;

/// Zamiana nazwy domeny na adresy IP (wzorzec Adapter): reszta skanera zależy tylko
/// od tego traitu, a nie od konkretnej biblioteki DNS. W testach podstawiamy prostą atrapę.
pub trait DomainResolver {
    /// Adresy IP domeny; błąd jako tekst do raportu (domena jest wtedy pomijana).
    fn resolve(&self, domain: &str) -> impl Future<Output = Result<Vec<IpAddr>, String>> + Send;
}

/// Resolver systemowy (konfiguracja z `/etc/resolv.conf`) oparty na hickory-resolver.
pub struct SystemResolver {
    inner: TokioAsyncResolver,
}

impl SystemResolver {
    pub fn from_system_config() -> Result<Self, ScannerError> {
        let inner = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|error| ScannerError::Resolver(error.to_string()))?;
        Ok(SystemResolver { inner })
    }
}

impl DomainResolver for SystemResolver {
    async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
        // Kropka na końcu = nazwa pełna; resolver nie dokleja wtedy domen z `search`.
        let lookup = self
            .inner
            .lookup_ip(format!("{domain}."))
            .await
            .map_err(|error| describe_resolve_error(&error))?;
        Ok(lookup.iter().collect())
    }
}

/// Czytelny opis błędu DNS (domyślny opis biblioteki zawiera szczegóły zapytania).
fn describe_resolve_error(error: &ResolveError) -> String {
    match error.kind() {
        ResolveErrorKind::NoRecordsFound { .. } => {
            "domena nie istnieje lub nie ma rekordów A/AAAA".to_string()
        }
        _ => error.to_string(),
    }
}
