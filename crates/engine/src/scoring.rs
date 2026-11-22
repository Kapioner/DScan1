//! Ocena „ciekawości” znaleziska (M3): panel administracyjny, środowisko testowe, stara
//! wersja, nietypowy port, wygasły / self-signed certyfikat, nowa lub zmieniona usługa.
//! Wagi z sekcji `[scoring]`; każdy wynik ma uzasadnienie (lista cech z wagami).

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use dscan_config::ScoringSettings;
use dscan_core::models::{Change, ChangeKind, Host, Service, ServiceKey, ServiceState};
use dscan_fingerprint::environment::{ADMIN_PANEL, DEBUG_MODE, TEST_ENVIRONMENT};

/// Wynik usługi z uzasadnieniem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interest {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub score: u32,
    /// (opis cechy, waga)
    pub reasons: Vec<(String, u32)>,
}

/// Typowe porty usług; usługa na innym porcie jest „nietypowa”.
const USUAL_PORTS: [(&str, &[u16]); 10] = [
    ("http", &[80, 8080, 8000, 8008]),
    ("https", &[443, 8443]),
    ("ssl/http", &[443, 8443]),
    ("ssh", &[22]),
    ("ftp", &[21]),
    ("telnet", &[23]),
    ("smtp", &[25, 587]),
    ("domain", &[53]),
    ("mysql", &[3306]),
    ("postgresql", &[5432]),
];

/// Porównanie wersji po liczbach (`1.24.0` < `1.25`); `None`, gdy nie da się porównać.
pub fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    let numbers = |text: &str| -> Vec<u64> {
        text.split(|c: char| !c.is_ascii_digit())
            .filter(|p| !p.is_empty())
            .filter_map(|p| p.parse().ok())
            .collect()
    };
    let (x, y) = (numbers(a), numbers(b));
    if x.is_empty() || y.is_empty() {
        return None;
    }
    let len = x.len().max(y.len());
    let pad = |v: &[u64]| {
        (0..len)
            .map(|i| v.get(i).copied().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    Some(pad(&x).cmp(&pad(&y)))
}

/// Czy produkt w danej wersji jest starszy niż minimalna wersja z konfiguracji.
pub fn is_old_version(
    product: &str,
    version: &str,
    minimum: &std::collections::BTreeMap<String, String>,
) -> Option<String> {
    let product = product.to_lowercase();
    minimum
        .iter()
        .find(|(name, _)| product.contains(name.as_str()))
        .filter(|(_, min)| compare_versions(version, min) == Some(Ordering::Less))
        .map(|(_, min)| min.clone())
}

fn unusual_port(service: &Service) -> bool {
    let Some(name) = service.name.as_deref() else {
        return false;
    };
    USUAL_PORTS
        .iter()
        .find(|(n, _)| *n == name)
        .is_some_and(|(_, ports)| !ports.contains(&service.port))
}

/// Ocena jednej usługi.
pub fn score_service(
    host: &Host,
    service: &Service,
    weights: &ScoringSettings,
    categories: &HashMap<String, String>,
    changes: &HashMap<ServiceKey, ChangeKind>,
    now: DateTime<Utc>,
) -> Interest {
    let mut reasons: Vec<(String, u32)> = Vec::new();
    let mut add = |text: String, weight: u32| {
        if weight > 0 {
            reasons.push((text, weight));
        }
    };
    let names: Vec<&str> = service
        .detections
        .iter()
        .map(|d| d.technology.as_str())
        .collect();
    if names.contains(&ADMIN_PANEL) {
        add("panel administracyjny".into(), weights.admin_panel);
    }
    if names.contains(&TEST_ENVIRONMENT) {
        add("środowisko testowe/staging".into(), weights.staging);
    }
    if names.contains(&DEBUG_MODE) {
        add("tryb debugowania".into(), weights.debug_mode);
    }
    let sensitive = [
        "panel-admina",
        "iot-kamera",
        "iot-drukarka",
        "ci-cd",
        "baza-danych",
    ];
    if let Some((tech, category)) = service.detections.iter().find_map(|d| {
        categories
            .get(&d.technology)
            .filter(|c| sensitive.contains(&c.as_str()))
            .map(|c| (&d.technology, c))
    }) {
        add(format!("{tech} ({category})"), weights.sensitive_category);
    }
    let versions = service
        .detections
        .iter()
        .filter_map(|d| d.version.as_deref().map(|v| (d.technology.as_str(), v)))
        .chain(service.product.as_deref().zip(service.version.as_deref()));
    if let Some((product, version, minimum)) = versions
        .into_iter()
        .find_map(|(p, v)| is_old_version(p, v, &weights.minimum_versions).map(|m| (p, v, m)))
    {
        add(
            format!("stara wersja {product} {version} (< {minimum})"),
            weights.old_version,
        );
    }
    if unusual_port(service) {
        add(
            format!(
                "nietypowy port {} dla {}",
                service.port,
                service.name.as_deref().unwrap_or("?")
            ),
            weights.unusual_port,
        );
    }
    if let Some(http) = &service.http {
        if let Some(cert) = &http.certificate {
            if cert.is_expired(now) {
                add("wygasły certyfikat TLS".into(), weights.expired_certificate);
            }
            if cert.self_signed {
                add(
                    "certyfikat self-signed".into(),
                    weights.self_signed_certificate,
                );
            }
        }
        if http.tls_verified == Some(false) {
            add("TLS niezweryfikowany".into(), weights.tls_unverified);
        }
    }
    let key = ServiceKey {
        ip: host.ip,
        port: service.port,
        protocol: service.protocol,
    };
    match changes.get(&key) {
        Some(ChangeKind::Appeared) => add(
            "nowa usługa od poprzedniego skanu".into(),
            weights.new_service,
        ),
        Some(ChangeKind::Modified) => add(
            "usługa zmieniona od poprzedniego skanu".into(),
            weights.modified_service,
        ),
        _ => {}
    }
    Interest {
        ip: host.ip.to_string(),
        port: service.port,
        protocol: service.protocol.as_str().to_string(),
        score: reasons.iter().map(|(_, w)| w).sum(),
        reasons,
    }
}

/// Wszystkie otwarte usługi z wynikiem > 0, od najciekawszych.
pub fn rank_interesting(
    hosts: &[Host],
    weights: &ScoringSettings,
    categories: &HashMap<String, String>,
    changes: &[Change],
    now: DateTime<Utc>,
) -> Vec<Interest> {
    let change_map: HashMap<ServiceKey, ChangeKind> =
        changes.iter().map(|c| (c.key, c.kind)).collect();
    let mut ranked: Vec<Interest> = hosts
        .iter()
        .flat_map(|h| {
            h.services
                .iter()
                .filter(|s| s.state == ServiceState::Open)
                .map(move |s| (h, s))
        })
        .map(|(h, s)| score_service(h, s, weights, categories, &change_map, now))
        .filter(|i| i.score > 0)
        .collect();
    ranked.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.ip.cmp(&b.ip))
            .then_with(|| a.port.cmp(&b.port))
    });
    ranked
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::{Detection, Protocol};

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("1.24.0", "1.25"), Some(Ordering::Less));
        assert_eq!(compare_versions("7.4p1", "8.0"), Some(Ordering::Less));
        assert_eq!(
            compare_versions("2.4.58", "2.4.50"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_versions("x", "1"), None);
    }

    #[test]
    fn score_has_reasons() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut service = Service::new(2222, Protocol::Tcp, ServiceState::Open);
        service.name = Some("ssh".into());
        service.product = Some("OpenSSH".into());
        service.version = Some("7.4".into());
        service.detections = vec![Detection::from_evidence(
            TEST_ENVIRONMENT.into(),
            None,
            Vec::new(),
        )];
        host.services.push(service);
        let key = ServiceKey {
            ip: host.ip,
            port: 2222,
            protocol: Protocol::Tcp,
        };
        let change = Change {
            key,
            kind: ChangeKind::Appeared,
            previous_run_id: 1,
            current_run_id: 2,
            previous_fingerprint: None,
            current_fingerprint: None,
            detected_at: Utc::now(),
        };
        let ranked = rank_interesting(
            &[host],
            &ScoringSettings::default(),
            &HashMap::new(),
            &[change],
            Utc::now(),
        );
        let interest = &ranked[0];
        // staging 25 + stara wersja 20 + nietypowy port 10 + nowa usługa 20
        assert_eq!(interest.score, 75, "{:?}", interest.reasons);
        assert!(
            interest
                .reasons
                .iter()
                .any(|(r, _)| r.contains("stara wersja OpenSSH 7.4"))
        );
    }
}
