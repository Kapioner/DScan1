//! Eksport wyników (zadanie I3): hosty (JSON), usługi (JSON/CSV) i zmiany (JSON/CSV) z filtrami.

use dscan_core::models::{Change, Host};
use serde::Serialize;

/// Filtry eksportu (wszystkie opcjonalne).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportFilter {
    pub port: Option<u16>,
    /// `open`, `closed`, `filtered`.
    pub state: Option<String>,
    /// Fragment nazwy technologii (np. `wordpress`), bez rozróżniania wielkości liter.
    pub technology: Option<String>,
    /// Tylko hosty/usługi z ręcznymi poprawkami (A6).
    pub only_edited: bool,
}

/// Jeden wiersz eksportu usług (CSV i JSON) — ten sam układ przyjmuje import (I2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceRow {
    pub ip: String,
    pub hostname: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: String,
    pub product: String,
    pub version: String,
    pub http_title: String,
    pub technologies: String,
    pub edited: String,
}

/// Hosty po filtrach; z hostów zostają tylko pasujące usługi, hosty bez usług po filtrze odpadają
/// (chyba że nie filtrujemy usług w ogóle).
pub fn filter_hosts(hosts: &[Host], filter: &ExportFilter) -> Vec<Host> {
    let filters_services =
        filter.port.is_some() || filter.state.is_some() || filter.technology.is_some();
    hosts
        .iter()
        .filter_map(|host| {
            let mut host = host.clone();
            host.services.retain(|service| {
                filter.port.is_none_or(|port| service.port == port)
                    && filter
                        .state
                        .as_deref()
                        .is_none_or(|state| service.state.as_str() == state)
                    && filter.technology.as_deref().is_none_or(|needle| {
                        let needle = needle.to_lowercase();
                        service
                            .detections
                            .iter()
                            .any(|d| d.technology.to_lowercase().contains(&needle))
                            || service
                                .product
                                .as_deref()
                                .is_some_and(|p| p.to_lowercase().contains(&needle))
                    })
            });
            if filter.only_edited {
                let host_was_edited = !host.edited_fields.is_empty();
                host.services
                    .retain(|service| host_was_edited || !service.edited_fields.is_empty());
                if !host_was_edited && host.services.is_empty() {
                    return None;
                }
            }
            (!filters_services || !host.services.is_empty()).then_some(host)
        })
        .collect()
}

/// Wiersze usług (jeden na usługę).
pub fn service_rows(hosts: &[Host]) -> Vec<ServiceRow> {
    hosts
        .iter()
        .flat_map(|host| {
            host.services.iter().map(move |service| ServiceRow {
                ip: host.ip.to_string(),
                hostname: host.hostnames.first().cloned().unwrap_or_default(),
                port: service.port,
                protocol: service.protocol.as_str().to_string(),
                state: service.state.as_str().to_string(),
                service: service.name.clone().unwrap_or_default(),
                product: service.product.clone().unwrap_or_default(),
                version: service.version.clone().unwrap_or_default(),
                http_title: service
                    .http
                    .as_ref()
                    .and_then(|http| http.title.clone())
                    .unwrap_or_default(),
                technologies: service
                    .detections
                    .iter()
                    .map(|d| format!("{} ({}%)", d.technology, d.confidence))
                    .collect::<Vec<_>>()
                    .join("; "),
                edited: service.edited_fields.join(" "),
            })
        })
        .collect()
}

/// Wiersze zmian.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeRow {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub kind: String,
    pub previous_run_id: i64,
    pub current_run_id: i64,
}

pub fn change_rows(changes: &[Change]) -> Vec<ChangeRow> {
    changes
        .iter()
        .map(|change| ChangeRow {
            ip: change.key.ip.to_string(),
            port: change.key.port,
            protocol: change.key.protocol.as_str().to_string(),
            kind: change.kind.as_str().to_string(),
            previous_run_id: change.previous_run_id,
            current_run_id: change.current_run_id,
        })
        .collect()
}

/// Dowolne wiersze jako CSV z nagłówkiem.
pub fn to_csv<T: Serialize>(rows: &[T]) -> Result<String, String> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    for row in rows {
        writer.serialize(row).map_err(|error| error.to_string())?;
    }
    let bytes = writer.into_inner().map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{Detection, Protocol, Service, ServiceState};

    fn hosts() -> Vec<Host> {
        let mut a = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut web = Service::new(80, Protocol::Tcp, ServiceState::Open);
        web.product = Some("nginx".into());
        web.detections = vec![Detection::from_evidence(
            "WordPress".into(),
            Some("6.4".into()),
            Vec::new(),
        )];
        web.edited_fields = vec!["product".into()];
        a.services = vec![web, Service::new(22, Protocol::Tcp, ServiceState::Open)];
        let mut b = Host::new("10.0.0.6".parse().unwrap(), Utc::now());
        b.services = vec![Service::new(443, Protocol::Tcp, ServiceState::Filtered)];
        vec![a, b]
    }

    #[test]
    fn port_and_state_filters() {
        let by_port = filter_hosts(
            &hosts(),
            &ExportFilter {
                port: Some(22),
                ..Default::default()
            },
        );
        assert_eq!(by_port.len(), 1);
        assert_eq!(by_port[0].services.len(), 1);
        let open = filter_hosts(
            &hosts(),
            &ExportFilter {
                state: Some("open".into()),
                ..Default::default()
            },
        );
        assert_eq!(service_rows(&open).len(), 2);
    }

    #[test]
    fn technology_and_edited_filters() {
        let wp = filter_hosts(
            &hosts(),
            &ExportFilter {
                technology: Some("wordpress".into()),
                ..Default::default()
            },
        );
        assert_eq!(service_rows(&wp).len(), 1);
        let edited = filter_hosts(
            &hosts(),
            &ExportFilter {
                only_edited: true,
                ..Default::default()
            },
        );
        assert_eq!(service_rows(&edited).len(), 1);
        assert_eq!(edited[0].services[0].port, 80);
    }

    #[test]
    fn no_filter_keeps_everything() {
        assert_eq!(
            service_rows(&filter_hosts(&hosts(), &ExportFilter::default())).len(),
            3
        );
    }

    #[test]
    fn csv_has_header_and_rows() {
        let csv = to_csv(&service_rows(&hosts())).unwrap();
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().unwrap(),
            "ip,hostname,port,protocol,state,service,product,version,http_title,technologies,edited"
        );
        assert!(
            lines
                .next()
                .unwrap()
                .starts_with("10.0.0.5,,80,tcp,open,,nginx,,,WordPress (0%),product")
        );
    }

    #[test]
    fn exported_csv_can_be_imported_back() {
        let csv = to_csv(&service_rows(&hosts())).unwrap();
        let parsed = crate::parse_results(&csv, crate::ResultFormat::Csv).unwrap();
        assert_eq!(parsed.hosts.len(), 2);
        assert_eq!(
            parsed.hosts[0].services[0].product.as_deref(),
            Some("nginx")
        );
    }
}
