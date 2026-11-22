//! Źródła pasywne (I6, opcjonalne): adaptery danych zebranych bez skanowania (np. eksport
//! Shodana, wyniki masscan od organizatora) na model hostów DScan. Wzorzec Adapter — każde
//! źródło implementuje [`PassiveSource`], a dalej działa zwykły import wyników (I2):
//! zakres `[scope]`, obecność hostów i porównanie z poprzednim importem.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::Utc;
use dscan_core::models::{Host, Protocol, Service, ServiceState};
use serde::Deserialize;

use crate::ImportError;

/// Źródło pasywne: nazwa i zamiana treści pliku na hosty.
pub trait PassiveSource {
    fn name(&self) -> &'static str;
    fn parse(&self, content: &str) -> Result<Vec<Host>, ImportError>;
}

/// Grupuje usługi po adresie IP.
fn group(services: Vec<(IpAddr, Option<String>, Service)>) -> Vec<Host> {
    let mut hosts: BTreeMap<IpAddr, Host> = BTreeMap::new();
    for (ip, hostname, service) in services {
        let host = hosts.entry(ip).or_insert_with(|| Host::new(ip, Utc::now()));
        if let Some(name) = hostname.filter(|n| !n.is_empty() && !host.hostnames.contains(n)) {
            host.hostnames.push(name);
        }
        if !host
            .services
            .iter()
            .any(|s| s.port == service.port && s.protocol == service.protocol)
        {
            host.services.push(service);
        }
    }
    hosts.into_values().collect()
}

fn protocol(text: Option<&str>) -> Protocol {
    if text.is_some_and(|t| t.eq_ignore_ascii_case("udp")) {
        Protocol::Udp
    } else {
        Protocol::Tcp
    }
}

/// Eksport Shodana: jeden obiekt JSON na linię (`ip_str`, `port`, `transport`, `product`,
/// `version`, `hostnames`, `http.title`).
pub struct ShodanJsonl;

#[derive(Debug, Deserialize)]
struct ShodanBanner {
    ip_str: IpAddr,
    port: u16,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default, rename = "_shodan")]
    meta: Option<ShodanMeta>,
}

#[derive(Debug, Deserialize)]
struct ShodanMeta {
    #[serde(default)]
    module: Option<String>,
}

impl PassiveSource for ShodanJsonl {
    fn name(&self) -> &'static str {
        "shodan"
    }

    fn parse(&self, content: &str) -> Result<Vec<Host>, ImportError> {
        let mut services = Vec::new();
        for (index, line) in content
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
        {
            let banner: ShodanBanner = serde_json::from_str(line)
                .map_err(|e| ImportError::InvalidJson(format!("linia {}: {e}", index + 1)))?;
            let mut service = Service::new(
                banner.port,
                protocol(banner.transport.as_deref()),
                ServiceState::Open,
            );
            service.product = banner.product;
            service.version = banner.version;
            service.name = banner.meta.and_then(|m| m.module);
            services.push((banner.ip_str, banner.hostnames.into_iter().next(), service));
        }
        Ok(group(services))
    }
}

/// Wynik masscan `-oJ`: tablica `{ "ip": "...", "ports": [ { "port": 80, "proto": "tcp", "status": "open" } ] }`.
pub struct MasscanJson;

#[derive(Debug, Deserialize)]
struct MasscanRecord {
    ip: IpAddr,
    #[serde(default)]
    ports: Vec<MasscanPort>,
}

#[derive(Debug, Deserialize)]
struct MasscanPort {
    port: u16,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

impl PassiveSource for MasscanJson {
    fn name(&self) -> &'static str {
        "masscan"
    }

    fn parse(&self, content: &str) -> Result<Vec<Host>, ImportError> {
        // masscan bywa zostawia przecinek po ostatnim elemencie.
        let cleaned = content
            .trim()
            .trim_end_matches(']')
            .trim_end()
            .trim_end_matches(',')
            .to_string()
            + "]";
        let records: Vec<MasscanRecord> =
            serde_json::from_str(&cleaned).map_err(|e| ImportError::InvalidJson(e.to_string()))?;
        let services = records
            .into_iter()
            .flat_map(|r| {
                r.ports
                    .into_iter()
                    .filter(|p| p.status.as_deref().is_none_or(|s| s == "open"))
                    .map(move |p| {
                        (
                            r.ip,
                            None,
                            Service::new(p.port, protocol(p.proto.as_deref()), ServiceState::Open),
                        )
                    })
            })
            .collect();
        Ok(group(services))
    }
}

/// Adapter po nazwie (`shodan`, `masscan`).
pub fn passive_source(name: &str) -> Option<Box<dyn PassiveSource>> {
    match name {
        "shodan" | "shodan-jsonl" => Some(Box::new(ShodanJsonl)),
        "masscan" | "masscan-json" => Some(Box::new(MasscanJson)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shodan_lines_become_hosts() {
        let content = r#"{"ip_str":"10.0.0.5","port":80,"transport":"tcp","product":"nginx","version":"1.24","hostnames":["cam.lab"],"_shodan":{"module":"http"}}
{"ip_str":"10.0.0.5","port":161,"transport":"udp"}
"#;
        let hosts = passive_source("shodan").unwrap().parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostnames, vec!["cam.lab"]);
        assert_eq!(hosts[0].services[0].product.as_deref(), Some("nginx"));
        assert_eq!(hosts[0].services[1].protocol, Protocol::Udp);
    }

    #[test]
    fn masscan_with_trailing_comma() {
        let content = r#"[
{"ip": "10.0.0.7", "ports": [ {"port": 22, "proto": "tcp", "status": "open"} ] },
{"ip": "10.0.0.8", "ports": [ {"port": 443, "proto": "tcp", "status": "closed"} ] },
]"#;
        let hosts = MasscanJson.parse(content).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].services[0].port, 22);
        assert!(passive_source("nieznane").is_none());
    }
}
