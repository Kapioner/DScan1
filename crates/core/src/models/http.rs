use serde::{Deserialize, Serialize};

use super::CertificateInfo;

/// Pojedynczy nagłówek odpowiedzi HTTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// Ciasteczko z atrybutami bezpieczeństwa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
}

/// Jeden krok łańcucha przekierowań.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redirect {
    pub from: String,
    pub to: String,
    pub status_code: u16,
}

/// Ikona strony (H4): skąd pobrana, mmh3 w wariancie Shodana i SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Favicon {
    pub url: String,
    pub mmh3: i32,
    pub sha256: String,
}

/// Informacje zebrane z odpowiedzi HTTP/HTTPS usługi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpInfo {
    /// Adres, pod którym zakończył się łańcuch przekierowań.
    pub url: String,
    pub status_code: u16,
    pub title: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub cookies: Vec<Cookie>,
    pub redirect_chain: Vec<Redirect>,
    /// HTTPS: czy certyfikat przeszedł weryfikację (`Some(false)` = np. self-signed lub
    /// niepasująca nazwa — dane odczytano mimo to). `None` dla zwykłego HTTP.
    #[serde(default)]
    pub tls_verified: Option<bool>,
    /// Certyfikat TLS (tylko HTTPS).
    #[serde(default)]
    pub certificate: Option<CertificateInfo>,
    /// Hash favicony (H4).
    #[serde(default)]
    pub favicon: Option<Favicon>,
    /// SimHash tytułu, nagłówków i struktury HTML (M4) — bity u64 zapisane jako i64.
    #[serde(default)]
    pub simhash: Option<i64>,
    /// Czas odpowiedzi strony głównej w ms (np. opóźnienie wprowadzone przez Toxiproxy).
    #[serde(default)]
    pub response_ms: Option<u32>,
}

impl HttpInfo {
    /// Wartość nagłówka — nazwy nagłówków HTTP nie rozróżniają wielkości liter.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    /// Czy odpowiedź była wynikiem co najmniej jednego przekierowania.
    pub fn was_redirected(&self) -> bool {
        !self.redirect_chain.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> HttpInfo {
        HttpInfo {
            url: "https://example.com/".to_string(),
            status_code: 200,
            title: Some("Example".to_string()),
            headers: vec![HttpHeader {
                name: "Server".to_string(),
                value: "nginx/1.24.0".to_string(),
            }],
            cookies: Vec::new(),
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
            simhash: None,
            response_ms: None,
        }
    }

    #[test]
    fn header_lookup_ignores_case() {
        let info = sample_info();
        assert_eq!(info.header("server"), Some("nginx/1.24.0"));
        assert_eq!(info.header("SERVER"), Some("nginx/1.24.0"));
        assert_eq!(info.header("x-powered-by"), None);
    }

    #[test]
    fn was_redirected_depends_on_chain() {
        let mut info = sample_info();
        assert!(!info.was_redirected());

        info.redirect_chain.push(Redirect {
            from: "http://example.com/".to_string(),
            to: "https://example.com/".to_string(),
            status_code: 301,
        });
        assert!(info.was_redirected());
    }
}
