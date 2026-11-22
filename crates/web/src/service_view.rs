//! Widok usługi na stronie hosta (F5): pola z flagą edycji, HTTP, favicon, certyfikat, detekcje.

use chrono::{DateTime, Utc};
use dscan_core::models::{Detection, Service};

use crate::host_views::{FieldView, field};

pub struct DetectionView {
    /// Nazwa technologii bez wersji (identyfikator obserwacji dla DefectDojo).
    pub name: String,
    pub technology: String,
    pub confidence: u8,
    pub evidence: String,
}

impl From<&Detection> for DetectionView {
    fn from(d: &Detection) -> Self {
        let version = d
            .version
            .as_deref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default();
        DetectionView {
            name: d.technology.clone(),
            technology: format!("{}{version}", d.technology),
            confidence: d.confidence,
            evidence: d
                .evidence
                .iter()
                .map(|e| format!("{} (+{})", e.description, e.weight))
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

/// Ciasteczko bez wartości: `PHPSESSID (Path=/, HttpOnly, bez Secure)`.
fn cookie_label(cookie: &dscan_core::models::Cookie) -> String {
    let mut attributes = Vec::new();
    if let Some(path) = &cookie.path {
        attributes.push(format!("Path={path}"));
    }
    if let Some(domain) = &cookie.domain {
        attributes.push(format!("Domain={domain}"));
    }
    attributes.push(
        if cookie.http_only {
            "HttpOnly"
        } else {
            "bez HttpOnly"
        }
        .to_string(),
    );
    attributes.push(
        if cookie.secure {
            "Secure"
        } else {
            "bez Secure"
        }
        .to_string(),
    );
    if let Some(same_site) = &cookie.same_site {
        attributes.push(format!("SameSite={same_site}"));
    }
    format!("{} ({})", cookie.name, attributes.join(", "))
}

pub struct ServiceView {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub fields: Vec<FieldView>,
    /// Np. `HTTP 200 „Panel” → https://…/login`.
    pub http: Option<String>,
    pub favicon: Option<String>,
    /// Kroki przekierowań, np. `302 http://…/ → http://…/admin/`.
    pub redirects: Vec<String>,
    /// Nagłówki odpowiedzi (nazwa, wartość).
    pub headers: Vec<(String, String)>,
    /// Ciasteczka: nazwa i atrybuty; wartość (identyfikator sesji) nie jest pokazywana.
    pub cookies: Vec<String>,
    pub certificate: Option<String>,
    pub certificate_warning: Option<String>,
    pub detections: Vec<DetectionView>,
}

impl ServiceView {
    pub fn new(service: &Service, now: DateTime<Utc>) -> Self {
        let edited = &service.edited_fields;
        let http = service.http.as_ref();
        let certificate = http.and_then(|h| h.certificate.as_ref());
        ServiceView {
            port: service.port,
            protocol: service.protocol.as_str().to_string(),
            state: service.state.as_str().to_string(),
            fields: vec![
                field("service_name", "Usługa", service.name.as_deref(), edited),
                field("product", "Produkt", service.product.as_deref(), edited),
                field("version", "Wersja", service.version.as_deref(), edited),
                field("service_note", "Notatka", service.note.as_deref(), edited),
            ],
            http: http.map(|h| {
                let title = h
                    .title
                    .as_deref()
                    .map(|t| format!(" „{t}”"))
                    .unwrap_or_default();
                let tls = if h.tls_verified == Some(false) {
                    " · TLS niezweryfikowany"
                } else {
                    ""
                };
                let time = h
                    .response_ms
                    .map(|ms| {
                        if ms == 0 {
                            " · odpowiedź <1 ms".to_string()
                        } else {
                            format!(" · odpowiedź {ms} ms")
                        }
                    })
                    .unwrap_or_default();
                format!("HTTP {}{title} · {}{tls}{time}", h.status_code, h.url)
            }),
            favicon: http
                .and_then(|h| h.favicon.as_ref())
                .map(|f| format!("mmh3 {} · sha256 {}", f.mmh3, f.sha256)),
            redirects: http
                .map(|h| {
                    h.redirect_chain
                        .iter()
                        .map(|r| format!("{} {} → {}", r.status_code, r.from, r.to))
                        .collect()
                })
                .unwrap_or_default(),
            headers: http
                .map(|h| {
                    h.headers
                        .iter()
                        .map(|header| (header.name.clone(), header.value.clone()))
                        .collect()
                })
                .unwrap_or_default(),
            cookies: http
                .map(|h| h.cookies.iter().map(cookie_label).collect())
                .unwrap_or_default(),
            certificate: certificate.map(|c| {
                let names = if c.alt_names.is_empty() {
                    String::new()
                } else {
                    format!(" · SAN: {}", c.alt_names.join(", "))
                };
                format!(
                    "{} · wystawca: {} · ważny do {}{names}",
                    c.subject,
                    c.issuer,
                    c.not_after.format("%Y-%m-%d")
                )
            }),
            certificate_warning: certificate.and_then(|c| {
                let mut warnings = Vec::new();
                if c.is_expired(now) {
                    warnings.push("wygasł".to_string());
                } else if c.days_left(now) <= 30 {
                    warnings.push(format!("wygasa za {} dni", c.days_left(now)));
                }
                if c.self_signed {
                    warnings.push("self-signed".into());
                }
                (!warnings.is_empty()).then(|| warnings.join(", "))
            }),
            detections: service.detections.iter().map(DetectionView::from).collect(),
        }
    }
}
