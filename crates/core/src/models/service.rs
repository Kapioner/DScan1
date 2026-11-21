use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::{Detection, HttpInfo};

/// Protokół warstwy transportowej.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Stan portu zgłoszony przez nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Open,
    Closed,
    Filtered,
}

/// Unikalny klucz usługi: (IP, port, protokół). Na nim opiera się porównywanie przebiegów.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ServiceKey {
    pub ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
}

/// Usługa wykryta na porcie hosta.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub protocol: Protocol,
    pub state: ServiceState,
    /// Nazwa usługi wg nmap, np. `http`, `ssh`.
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub cpe: Vec<String>,
    pub banner: Option<String>,
    pub http: Option<HttpInfo>,
    pub detections: Vec<Detection>,
}

impl Service {
    /// Tworzy usługę z samym portem i stanem — pozostałe pola uzupełnia skaner.
    pub fn new(port: u16, protocol: Protocol, state: ServiceState) -> Self {
        Service {
            port,
            protocol,
            state,
            name: None,
            product: None,
            version: None,
            cpe: Vec::new(),
            banner: None,
            http: None,
            detections: Vec::new(),
        }
    }

    /// Klucz usługi na danym hoście.
    pub fn key(&self, ip: IpAddr) -> ServiceKey {
        ServiceKey {
            ip,
            port: self.port,
            protocol: self.protocol,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_combines_host_ip_with_port_and_protocol() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let service = Service::new(443, Protocol::Tcp, ServiceState::Open);

        assert_eq!(
            service.key(ip),
            ServiceKey {
                ip,
                port: 443,
                protocol: Protocol::Tcp
            }
        );
    }

    #[test]
    fn same_port_different_protocol_gives_different_keys() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let tcp = Service::new(53, Protocol::Tcp, ServiceState::Open);
        let udp = Service::new(53, Protocol::Udp, ServiceState::Open);

        assert_ne!(tcp.key(ip), udp.key(ip));
    }
}
