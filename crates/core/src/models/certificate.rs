use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Certyfikat TLS usługi (zadanie H3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub common_name: Option<String>,
    /// Nazwy z rozszerzenia Subject Alternative Name (DNS i adresy IP).
    pub alt_names: Vec<String>,
    pub issuer: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// Algorytm podpisu, np. `sha256WithRSAEncryption`.
    pub signature_algorithm: String,
    /// SHA-256 całego certyfikatu (DER), hex.
    pub sha256: String,
    /// Wystawca = podmiot (certyfikat podpisany sam przez siebie).
    pub self_signed: bool,
}

impl CertificateInfo {
    /// Czy certyfikat jest już nieważny (po `not_after`).
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.not_after
    }

    /// Czy certyfikat jeszcze nie obowiązuje (przed `not_before`).
    pub fn is_not_yet_valid(&self, now: DateTime<Utc>) -> bool {
        now < self.not_before
    }

    /// Dni do wygaśnięcia (ujemne = po terminie).
    pub fn days_left(&self, now: DateTime<Utc>) -> i64 {
        (self.not_after - now).num_days()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    fn certificate() -> CertificateInfo {
        CertificateInfo {
            subject: "CN=app.lab.local".into(),
            common_name: Some("app.lab.local".into()),
            alt_names: vec!["app.lab.local".into()],
            issuer: "CN=app.lab.local".into(),
            not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
            not_after: "2026-12-31T00:00:00Z".parse().unwrap(),
            signature_algorithm: "sha256WithRSAEncryption".into(),
            sha256: "00".repeat(32),
            self_signed: true,
        }
    }

    #[test]
    fn validity_checks() {
        let cert = certificate();
        assert!(!cert.is_expired("2026-06-01T00:00:00Z".parse().unwrap()));
        assert!(cert.is_expired(cert.not_after + TimeDelta::seconds(1)));
        assert!(cert.is_not_yet_valid("2025-12-31T00:00:00Z".parse().unwrap()));
        assert_eq!(cert.days_left("2026-12-21T00:00:00Z".parse().unwrap()), 10);
    }
}
