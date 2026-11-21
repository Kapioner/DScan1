//! Struktury konfiguracji. `deny_unknown_fields` sprawia, że literówka w nazwie
//! pola (np. `nmap_maxrate`) kończy się błędem, a nie cichym zignorowaniem.

use std::net::{Ipv4Addr, SocketAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Cała konfiguracja aplikacji (bez sekretów).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub scope: ScopeSettings,
    pub limits: RateLimitSettings,
    pub schedule: ScheduleSettings,
    pub stability: StabilitySettings,
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub http: HttpSettings,
    /// Nazwane profile skanów (C4): `[profiles.NAZWA]`.
    pub profiles: std::collections::BTreeMap<String, crate::ScanProfileSettings>,
}

/// Zakres dozwolonego skanowania — wartości od organizatora środowiska testowego.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScopeSettings {
    /// Sieci, które wolno skanować. Pusta lista = żaden cel nie jest dozwolony.
    pub allowed_networks: Vec<IpNet>,
    /// Dozwolone porty, np. `["22", "80", "443", "8000-8100"]`.
    pub allowed_ports: Vec<String>,
    /// Maksymalny łączny ruch generowany przez skaner (kilobity na sekundę).
    pub max_bandwidth_kbps: u32,
}

impl Default for ScopeSettings {
    fn default() -> Self {
        ScopeSettings {
            allowed_networks: Vec::new(),
            allowed_ports: vec!["1-1024".to_string()],
            max_bandwidth_kbps: 1024,
        }
    }
}

/// Limity tempa skanowania.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitSettings {
    /// Przekazywane do nmap jako `--max-rate` (pakiety na sekundę).
    pub nmap_max_rate: u32,
    /// Ile procesów nmap może działać jednocześnie.
    pub max_parallel_nmap: u32,
    /// Globalny limit zapytań HTTP na sekundę.
    pub http_requests_per_second: u32,
    /// Maksymalna liczba zapytań HTTP do jednego hosta w przebiegu.
    pub http_requests_per_host: u32,
    /// Liczba adresów w jednej podgrupie (jeden proces nmap). Musi być potęgą dwójki.
    pub subgroup_size: u32,
    /// Bezpiecznik: skan większej liczby adresów jest odrzucany.
    pub max_addresses_per_scan: u64,
    /// S5: dobieraj rozmiar podgrup do zmierzonej przepustowości (EWMA), najwyżej `subgroup_size`.
    pub adaptive_subgroups: bool,
    /// S5: docelowy czas skanu jednej podgrupy w sekundach (krócej = mniej pracy traconej o końcu okna).
    pub target_subgroup_seconds: u64,
}

impl Default for RateLimitSettings {
    fn default() -> Self {
        RateLimitSettings {
            nmap_max_rate: 100,
            max_parallel_nmap: 4,
            http_requests_per_second: 10,
            http_requests_per_host: 20,
            subgroup_size: 256,
            max_addresses_per_scan: 1_048_576,
            adaptive_subgroups: true,
            target_subgroup_seconds: 300,
        }
    }
}

/// Okna czasowe, w których wolno skanować.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduleSettings {
    /// Pusta lista = skanowanie dozwolone przez całą dobę.
    pub windows: Vec<TimeWindow>,
}

/// Okno czasowe `start`–`end` w formacie `HH:MM`. Okno może przechodzić
/// przez północ (np. `22:00`–`06:00`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    pub start: String,
    pub end: String,
}

/// Progi, od których host uznajemy za niestabilny lub nieaktywny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StabilitySettings {
    /// K — host staje się nieaktywny po tylu kolejnych przebiegach bez odpowiedzi.
    pub inactive_after_missed_runs: u32,
    /// N — ile razy ponowić skan hosta, który nie odpowiedział.
    pub unstable_retries: u32,
    /// Odstęp między ponownymi próbami.
    pub retry_delay_seconds: u64,
}

impl Default for StabilitySettings {
    fn default() -> Self {
        StabilitySettings {
            inactive_after_missed_runs: 3,
            unstable_retries: 2,
            retry_delay_seconds: 30,
        }
    }
}

/// Serwer HTTP (API i interfejs WWW).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerSettings {
    /// Adres i port nasłuchiwania. Domyślnie tylko lokalnie (`127.0.0.1`).
    pub listen: SocketAddr,
    /// Maksymalny rozmiar treści żądania w bajtach (np. wgrywany plik CSV).
    pub max_body_bytes: usize,
    /// Ważność sesji po zalogowaniu (godziny).
    pub session_hours: u32,
    /// Flaga `Secure` ciasteczka sesji — włącz, gdy DScan działa za HTTPS.
    pub secure_cookies: bool,
}

impl Default for ServerSettings {
    fn default() -> Self {
        ServerSettings {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
            max_body_bytes: 2 * 1024 * 1024,
            session_hours: 12,
            secure_cookies: false,
        }
    }
}

/// Parametry połączenia z PostgreSQL. Sam adres bazy (z hasłem) to sekret
/// i podaje się go wyłącznie w zmiennej `DSCAN_DATABASE_URL`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseSettings {
    pub max_connections: u32,
    pub connect_timeout_seconds: u64,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        DatabaseSettings {
            max_connections: 10,
            connect_timeout_seconds: 5,
        }
    }
}

/// Klient HTTP do fingerprintingu usług WWW.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSettings {
    /// Czy po skanie usług odpytywać serwery WWW (tytuł, nagłówki, ciasteczka).
    pub enabled: bool,
    /// Limit czasu całego zapytania (sekundy).
    pub timeout_seconds: u64,
    /// Ile przekierowań maksymalnie śledzić.
    pub max_redirects: u32,
    /// Ile bajtów treści odpowiedzi czytać (wystarczy na tytuł strony).
    pub max_body_bytes: usize,
    pub user_agent: String,
    /// Ścieżki sondowane zapytaniem GET na każdej usłudze WWW (dochodzą ścieżki z sygnatur).
    pub probe_paths: Vec<String>,
    /// Najwyżej tyle sondowanych ścieżek na jedną usługę.
    pub max_probes_per_service: u32,
    /// Detekcje o pewności poniżej progu (0–100) są pomijane.
    pub min_confidence: u8,
    /// Dodatkowy plik sygnatur YAML (np. od organizatora), dodawany do wbudowanych.
    pub signatures_file: Option<String>,
}

impl Default for HttpSettings {
    fn default() -> Self {
        HttpSettings {
            enabled: true,
            timeout_seconds: 10,
            max_redirects: 5,
            max_body_bytes: 256 * 1024,
            user_agent: format!(
                "DScan/{} (skaner bezpieczeństwa)",
                env!("CARGO_PKG_VERSION")
            ),
            probe_paths: vec![
                "/login".into(),
                "/admin".into(),
                "/version".into(),
                "/robots.txt".into(),
            ],
            max_probes_per_service: 12,
            min_confidence: 30,
            signatures_file: None,
        }
    }
}
