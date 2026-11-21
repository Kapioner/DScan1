//! Porównanie przebiegów (zadanie M1).
//!
//! Każda otwarta usługa ma odcisk — skrót SHA-256 z cech, które opisują „co tam działa”:
//! produkt, wersja, nazwa usługi, kod i tytuł HTTP, stabilne nagłówki i stan TLS.
//! Dwa przebiegi porównujemy po kluczu (IP, port, protokół):
//! klucz tylko w nowszym = usługa nowa, tylko w starszym = zniknęła, inny odcisk = zmieniona.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use super::{Change, Service, ServiceKey};

/// Nagłówki brane do odcisku. Zmienne nagłówki (Date, Set-Cookie, ETag…) pominięto,
/// bo zmieniałyby odcisk przy każdym skanie.
const FINGERPRINT_HEADERS: [&str; 3] = ["server", "x-powered-by", "x-generator"];

/// Tekst, z którego liczony jest odcisk (osobno, żeby łatwo go testować i podglądać).
pub fn fingerprint_input(service: &Service) -> String {
    let mut parts = vec![
        format!("name={}", service.name.as_deref().unwrap_or("")),
        format!("product={}", service.product.as_deref().unwrap_or("")),
        format!("version={}", service.version.as_deref().unwrap_or("")),
    ];
    if let Some(http) = &service.http {
        parts.push(format!("http.status={}", http.status_code));
        parts.push(format!(
            "http.title={}",
            http.title.as_deref().unwrap_or("")
        ));
        parts.push(format!("http.tls_verified={:?}", http.tls_verified));
        for name in FINGERPRINT_HEADERS {
            if let Some(value) = http.header(name) {
                parts.push(format!("header.{name}={value}"));
            }
        }
    }
    parts.join("\n")
}

/// Odcisk usługi: SHA-256 (hex) z [`fingerprint_input`].
pub fn service_fingerprint(service: &Service) -> String {
    Sha256::digest(fingerprint_input(service).as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Zmiany między przebiegami `previous_run_id` → `current_run_id`, posortowane po kluczu.
pub fn compare_runs(
    previous: &HashMap<ServiceKey, String>,
    current: &HashMap<ServiceKey, String>,
    run_ids: (i64, i64),
    detected_at: DateTime<Utc>,
) -> Vec<Change> {
    let keys: BTreeSet<SortableKey> = previous
        .keys()
        .chain(current.keys())
        .map(SortableKey::from)
        .collect();
    keys.into_iter()
        .filter_map(|sortable| {
            let key = sortable.0;
            let old = previous.get(&key).map(String::as_str);
            let new = current.get(&key).map(String::as_str);
            Change::classify(old, new).map(|kind| Change {
                key,
                kind,
                previous_run_id: run_ids.0,
                current_run_id: run_ids.1,
                previous_fingerprint: old.map(String::from),
                current_fingerprint: new.map(String::from),
                detected_at,
            })
        })
        .collect()
}

/// Klucz z porządkiem (IP, port, protokół) — żeby raport zmian był stabilny i czytelny.
#[derive(PartialEq, Eq)]
struct SortableKey(ServiceKey);

impl From<&ServiceKey> for SortableKey {
    fn from(key: &ServiceKey) -> Self {
        SortableKey(*key)
    }
}

impl Ord for SortableKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.0.ip, self.0.port, self.0.protocol.as_str()).cmp(&(
            other.0.ip,
            other.0.port,
            other.0.protocol.as_str(),
        ))
    }
}

impl PartialOrd for SortableKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChangeKind, HttpHeader, HttpInfo, Protocol, ServiceState};

    fn service(product: &str, version: &str) -> Service {
        let mut service = Service::new(80, Protocol::Tcp, ServiceState::Open);
        service.name = Some("http".into());
        service.product = Some(product.into());
        service.version = Some(version.into());
        service
    }

    fn key(port: u16) -> ServiceKey {
        ServiceKey {
            ip: "10.0.0.5".parse().unwrap(),
            port,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn fingerprint_changes_with_version_only() {
        let a = service_fingerprint(&service("nginx", "1.24.0"));
        assert_eq!(a, service_fingerprint(&service("nginx", "1.24.0")));
        assert_ne!(a, service_fingerprint(&service("nginx", "1.25.0")));
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn volatile_headers_do_not_change_fingerprint() {
        let with_headers = |date: &str, server: &str| {
            let mut s = service("nginx", "1.24.0");
            s.http = Some(HttpInfo {
                url: "http://10.0.0.5/".into(),
                status_code: 200,
                title: Some("Start".into()),
                headers: vec![
                    HttpHeader {
                        name: "Date".into(),
                        value: date.into(),
                    },
                    HttpHeader {
                        name: "Server".into(),
                        value: server.into(),
                    },
                ],
                cookies: Vec::new(),
                redirect_chain: Vec::new(),
                tls_verified: None,
            });
            service_fingerprint(&s)
        };
        assert_eq!(with_headers("Mon", "nginx"), with_headers("Tue", "nginx"));
        assert_ne!(with_headers("Mon", "nginx"), with_headers("Mon", "Apache"));
    }

    #[test]
    fn comparison_finds_new_gone_and_changed() {
        let previous = HashMap::from([
            (key(22), "a".to_string()),
            (key(80), "b".to_string()),
            (key(443), "c".to_string()),
        ]);
        let current = HashMap::from([
            (key(22), "a".to_string()),
            (key(80), "B".to_string()),
            (key(8080), "d".to_string()),
        ]);

        let changes = compare_runs(&previous, &current, (1, 2), Utc::now());

        let summary: Vec<(u16, ChangeKind)> =
            changes.iter().map(|c| (c.key.port, c.kind)).collect();
        assert_eq!(
            summary,
            vec![
                (80, ChangeKind::Modified),
                (443, ChangeKind::Disappeared),
                (8080, ChangeKind::Appeared)
            ]
        );
        assert_eq!(changes[0].previous_fingerprint.as_deref(), Some("b"));
        assert_eq!(changes[0].current_run_id, 2);
    }

    #[test]
    fn identical_runs_have_no_changes() {
        let run = HashMap::from([(key(22), "a".to_string())]);
        assert!(compare_runs(&run, &run, (1, 2), Utc::now()).is_empty());
    }
}
