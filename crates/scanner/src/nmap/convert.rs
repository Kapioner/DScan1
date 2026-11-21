use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dscan_core::models::{Host, Protocol, Service, ServiceState};

use super::xml::{NmapRun, XmlHost, XmlPort};

/// Stan portu nmap → model. Stany pośrednie (`open|filtered`, `unfiltered`…) traktujemy
/// jak `Filtered`, bo nie potwierdzają działającej usługi.
pub fn map_port_state(state: &str) -> ServiceState {
    match state {
        "open" => ServiceState::Open,
        "closed" => ServiceState::Closed,
        _ => ServiceState::Filtered,
    }
}

/// Protokół nmap → model (`sctp` i inne są pomijane).
pub fn map_protocol(protocol: &str) -> Option<Protocol> {
    match protocol {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

/// Zamienia wynik nmap na hosty modelu domeny. Pomija hosty, które nie odpowiedziały.
pub fn to_hosts(run: &NmapRun, seen_at: DateTime<Utc>) -> Vec<Host> {
    run.hosts
        .iter()
        .filter(|host| host.status.state == "up")
        .filter_map(|host| to_host(host, seen_at))
        .collect()
}

fn to_host(xml_host: &XmlHost, seen_at: DateTime<Utc>) -> Option<Host> {
    let ip = host_ip(xml_host)?;
    let mut host = Host::new(ip, seen_at);
    if let Some(hostnames) = &xml_host.hostnames {
        host.hostnames = hostnames
            .names
            .iter()
            .map(|name| name.name.clone())
            .collect();
    }
    if let Some(ports) = &xml_host.ports {
        host.services = ports.ports.iter().filter_map(to_service).collect();
    }
    Some(host)
}

/// Adres IPv4/IPv6 hosta (nmap podaje też adres MAC, który pomijamy).
fn host_ip(host: &XmlHost) -> Option<IpAddr> {
    host.addresses
        .iter()
        .filter(|address| address.addrtype == "ipv4" || address.addrtype == "ipv6")
        .find_map(|address| address.addr.parse().ok())
}

fn to_service(port: &XmlPort) -> Option<Service> {
    let protocol = map_protocol(&port.protocol)?;
    let mut service = Service::new(port.port, protocol, map_port_state(&port.state.state));
    if let Some(details) = &port.service {
        service.name = details.name.clone();
        service.product = details.product.clone();
        service.version = details.version.clone();
        service.cpe = details.cpe.clone();
    }
    Some(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::parse_nmap_xml;

    const SAMPLE: &str = include_str!("../../tests/fixtures/services_scan.xml");

    #[test]
    fn port_states_are_mapped() {
        assert_eq!(map_port_state("open"), ServiceState::Open);
        assert_eq!(map_port_state("closed"), ServiceState::Closed);
        assert_eq!(map_port_state("filtered"), ServiceState::Filtered);
        assert_eq!(map_port_state("open|filtered"), ServiceState::Filtered);
    }

    #[test]
    fn protocols_are_mapped() {
        assert_eq!(map_protocol("tcp"), Some(Protocol::Tcp));
        assert_eq!(map_protocol("udp"), Some(Protocol::Udp));
        assert_eq!(map_protocol("sctp"), None);
    }

    #[test]
    fn only_hosts_that_are_up_are_returned() {
        let hosts = to_hosts(&parse_nmap_xml(SAMPLE).unwrap(), Utc::now());
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "10.0.0.5".parse::<IpAddr>().unwrap());
        assert_eq!(hosts[0].hostnames, vec!["app.lab.local"]);
    }

    #[test]
    fn services_keep_product_version_and_cpe() {
        let hosts = to_hosts(&parse_nmap_xml(SAMPLE).unwrap(), Utc::now());
        let nginx = &hosts[0].services[1];

        assert_eq!(nginx.port, 80);
        assert_eq!(nginx.name.as_deref(), Some("http"));
        assert_eq!(nginx.product.as_deref(), Some("nginx"));
        assert_eq!(nginx.version.as_deref(), Some("1.24.0"));
        assert_eq!(nginx.cpe, vec!["cpe:/a:igor_sysoev:nginx:1.24.0"]);
        assert_eq!(hosts[0].open_port_count(), 2);
    }
}
