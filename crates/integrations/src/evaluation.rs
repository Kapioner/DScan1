//! Trafność wykrywania (Q1): porównanie wyników przebiegu z wynikami referencyjnymi
//! organizatora — hosty (po IP) i usługi (IP, port, protokół), precyzja i czułość,
//! oraz zgodność nazwy usługi i produktu dla wspólnych usług.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use dscan_core::models::{Host, Protocol, Service, ServiceState};

/// Liczby trafień dla jednej kategorii (hosty albo usługi).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Score {
    /// Wykryte i obecne w referencji.
    pub true_positives: usize,
    /// Wykryte, ale nieobecne w referencji.
    pub false_positives: Vec<String>,
    /// Obecne w referencji, ale niewykryte.
    pub false_negatives: Vec<String>,
}

impl Score {
    fn from_sets(found: &BTreeSet<String>, reference: &BTreeSet<String>) -> Self {
        Score {
            true_positives: found.intersection(reference).count(),
            false_positives: found.difference(reference).cloned().collect(),
            false_negatives: reference.difference(found).cloned().collect(),
        }
    }

    /// Precyzja: jaka część wykrytych jest prawdziwa (1.0 przy braku wykryć).
    pub fn precision(&self) -> f64 {
        ratio(
            self.true_positives,
            self.true_positives + self.false_positives.len(),
        )
    }

    /// Czułość: jaką część referencji wykryto (1.0 przy pustej referencji).
    pub fn recall(&self) -> f64 {
        ratio(
            self.true_positives,
            self.true_positives + self.false_negatives.len(),
        )
    }

    /// F1 — średnia harmoniczna precyzji i czułości.
    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

fn ratio(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        1.0
    } else {
        part as f64 / whole as f64
    }
}

/// Wynik oceny przebiegu.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Evaluation {
    pub hosts: Score,
    pub services: Score,
    /// (zgodne, porównane) nazwy usług dla wspólnych usług z nazwą w referencji.
    pub service_names: (usize, usize),
    /// (zgodne, porównane) produkty dla wspólnych usług z produktem w referencji.
    pub products: (usize, usize),
}

fn open_services(host: &Host) -> impl Iterator<Item = &Service> {
    host.services
        .iter()
        .filter(|s| s.state == ServiceState::Open)
}

fn service_key(ip: IpAddr, port: u16, protocol: Protocol) -> String {
    format!("{ip}:{port}/{}", protocol.as_str())
}

/// Porównanie bez rozróżniania wielkości liter; referencja może być fragmentem (np. „nginx”
/// wobec „nginx 1.24”).
fn matches(found: Option<&str>, expected: &str) -> bool {
    found.is_some_and(|value| value.to_lowercase().contains(&expected.to_lowercase()))
}

pub fn evaluate(found: &[Host], reference: &[Host]) -> Evaluation {
    let ips = |hosts: &[Host]| {
        hosts
            .iter()
            .map(|h| h.ip.to_string())
            .collect::<BTreeSet<_>>()
    };
    let services = |hosts: &[Host]| {
        hosts
            .iter()
            .flat_map(|h| open_services(h).map(move |s| service_key(h.ip, s.port, s.protocol)))
            .collect::<BTreeSet<_>>()
    };
    let found_by_key: HashMap<String, &Service> = found
        .iter()
        .flat_map(|h| open_services(h).map(move |s| (service_key(h.ip, s.port, s.protocol), s)))
        .collect();
    let mut evaluation = Evaluation {
        hosts: Score::from_sets(&ips(found), &ips(reference)),
        services: Score::from_sets(&services(found), &services(reference)),
        ..Evaluation::default()
    };
    for host in reference {
        for expected in open_services(host) {
            let Some(actual) =
                found_by_key.get(&service_key(host.ip, expected.port, expected.protocol))
            else {
                continue;
            };
            if let Some(name) = expected.name.as_deref().filter(|n| !n.is_empty()) {
                evaluation.service_names.1 += 1;
                evaluation.service_names.0 += usize::from(matches(actual.name.as_deref(), name));
            }
            if let Some(product) = expected.product.as_deref().filter(|p| !p.is_empty()) {
                evaluation.products.1 += 1;
                // Aplikację rozpoznaje nmap (product) albo fingerprinting DScan (detekcje).
                let recognized = matches(actual.product.as_deref(), product)
                    || actual
                        .detections
                        .iter()
                        .any(|d| matches(Some(&d.technology), product));
                evaluation.products.0 += usize::from(recognized);
            }
        }
    }
    evaluation
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn host(ip: &str, services: &[(u16, &str, &str)]) -> Host {
        let mut host = Host::new(ip.parse().unwrap(), Utc::now());
        for (port, name, product) in services {
            let mut service = Service::new(*port, Protocol::Tcp, ServiceState::Open);
            service.name = (!name.is_empty()).then(|| name.to_string());
            service.product = (!product.is_empty()).then(|| product.to_string());
            host.services.push(service);
        }
        host
    }

    #[test]
    fn precision_recall_and_product_accuracy() {
        let found = vec![
            host(
                "10.0.0.1",
                &[(22, "ssh", "OpenSSH"), (80, "http", "nginx 1.24")],
            ),
            host("10.0.0.9", &[(443, "https", "")]),
        ];
        let reference = vec![
            host(
                "10.0.0.1",
                &[(22, "ssh", "OpenSSH"), (80, "http", "Apache")],
            ),
            host("10.0.0.2", &[(3306, "mysql", "MySQL")]),
        ];
        let e = evaluate(&found, &reference);
        assert_eq!(e.hosts.true_positives, 1);
        assert_eq!(e.hosts.false_positives, vec!["10.0.0.9"]);
        assert_eq!(e.hosts.false_negatives, vec!["10.0.0.2"]);
        assert!((e.hosts.precision() - 0.5).abs() < 1e-9);
        assert_eq!(e.services.true_positives, 2);
        assert!((e.services.recall() - 2.0 / 3.0).abs() < 1e-9);
        assert_eq!(e.service_names, (2, 2));
        assert_eq!(e.products, (1, 2));
    }

    #[test]
    fn empty_sets_are_perfect() {
        let e = evaluate(&[], &[]);
        assert_eq!(
            (e.hosts.precision(), e.hosts.recall(), e.hosts.f1()),
            (1.0, 1.0, 1.0)
        );
    }
}
