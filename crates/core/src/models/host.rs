use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Service, ServiceState};

/// Stan dostępności hosta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    /// Odpowiada w ostatnim przebiegu.
    Active,
    /// Nie odpowiada od K kolejnych przebiegów (K z konfiguracji).
    Inactive,
    /// Odpowiada nieregularnie — wymaga powtórnych pomiarów.
    Unstable,
}

impl HostStatus {
    /// Odczyt nazwy z bazy (nieznana = aktywny).
    pub fn parse(text: &str) -> HostStatus {
        match text {
            "inactive" => HostStatus::Inactive,
            "unstable" => HostStatus::Unstable,
            _ => HostStatus::Active,
        }
    }

    /// Nazwa zapisywana w bazie (kolumna `hosts.status`).
    pub fn as_str(&self) -> &'static str {
        match self {
            HostStatus::Active => "active",
            HostStatus::Inactive => "inactive",
            HostStatus::Unstable => "unstable",
        }
    }
}

/// Host wykryty w sieci wraz z jego usługami.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub hostnames: Vec<String>,
    pub status: HostStatus,
    pub services: Vec<Service>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Notatka (tylko z ręcznej poprawki, A6).
    #[serde(default)]
    pub note: Option<String>,
    /// Pola poprawione ręcznie (A6), np. `["hostname"]`.
    #[serde(default)]
    pub edited_fields: Vec<String>,
}

impl Host {
    /// Nowy aktywny host widziany po raz pierwszy w chwili `seen_at`.
    pub fn new(ip: IpAddr, seen_at: DateTime<Utc>) -> Self {
        Host {
            ip,
            hostnames: Vec::new(),
            status: HostStatus::Active,
            services: Vec::new(),
            first_seen: seen_at,
            last_seen: seen_at,
            note: None,
            edited_fields: Vec::new(),
        }
    }

    /// Liczba otwartych portów.
    pub fn open_port_count(&self) -> usize {
        self.services
            .iter()
            .filter(|service| service.state == ServiceState::Open)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    #[test]
    fn open_port_count_ignores_closed_and_filtered() {
        let mut host = Host::new("10.0.0.1".parse().unwrap(), Utc::now());
        host.services = vec![
            Service::new(22, Protocol::Tcp, ServiceState::Open),
            Service::new(80, Protocol::Tcp, ServiceState::Open),
            Service::new(81, Protocol::Tcp, ServiceState::Closed),
            Service::new(161, Protocol::Udp, ServiceState::Filtered),
        ];

        assert_eq!(host.open_port_count(), 2);
    }

    #[test]
    fn host_survives_json_round_trip() {
        let mut host = Host::new("10.0.0.1".parse().unwrap(), Utc::now());
        host.services
            .push(Service::new(22, Protocol::Tcp, ServiceState::Open));

        let json = serde_json::to_string(&host).unwrap();
        let restored: Host = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, host);
    }
}
