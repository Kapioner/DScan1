//! Ręczne poprawki wyników (zadanie A6).
//!
//! Poprawki są przechowywane osobno od obserwacji skanera i kluczowane adresem
//! (IP, opcjonalnie port i protokół), a nie przebiegiem. Nakładamy je dopiero przy odczycie,
//! więc działają także w trakcie skanu i przetrwają kolejne przebiegi, a porównanie
//! przebiegów (M1) widzi wyłącznie to, co faktycznie zaobserwował skaner.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{Host, Protocol};

/// Pole, które można poprawić ręcznie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideField {
    /// Nazwa hosta (poziom hosta).
    Hostname,
    /// Notatka do hosta.
    HostNote,
    /// Produkt usługi (np. „nginx”).
    Product,
    /// Wersja produktu.
    Version,
    /// Nazwa usługi (np. „http”).
    ServiceName,
    /// Notatka do usługi.
    ServiceNote,
}

impl OverrideField {
    pub const ALL: [OverrideField; 6] = [
        OverrideField::Hostname,
        OverrideField::HostNote,
        OverrideField::Product,
        OverrideField::Version,
        OverrideField::ServiceName,
        OverrideField::ServiceNote,
    ];

    /// Nazwa zapisywana w bazie i w API.
    pub fn as_str(&self) -> &'static str {
        match self {
            OverrideField::Hostname => "hostname",
            OverrideField::HostNote => "host_note",
            OverrideField::Product => "product",
            OverrideField::Version => "version",
            OverrideField::ServiceName => "service_name",
            OverrideField::ServiceNote => "service_note",
        }
    }

    pub fn parse(text: &str) -> Option<OverrideField> {
        Self::ALL.into_iter().find(|field| field.as_str() == text)
    }

    /// Czy pole dotyczy usługi (wymaga portu i protokołu), a nie całego hosta.
    pub fn is_service_field(&self) -> bool {
        !matches!(self, OverrideField::Hostname | OverrideField::HostNote)
    }
}

/// Jedna ręczna poprawka.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Override {
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub field: OverrideField,
    pub value: String,
    pub updated_at: DateTime<Utc>,
    /// Login autora poprawki (jeśli konto nadal istnieje).
    pub updated_by: Option<String>,
}

/// Nakłada poprawki na hosty i oznacza poprawione pola jako „edytowane ręcznie”.
/// Poprawki dla adresów lub usług, których nie ma w wynikach, są pomijane.
pub fn apply_overrides(hosts: &mut [Host], overrides: &[Override]) {
    for item in overrides {
        let Some(host) = hosts.iter_mut().find(|host| host.ip == item.ip) else {
            continue;
        };
        if !item.field.is_service_field() {
            match item.field {
                OverrideField::Hostname => host.hostnames = vec![item.value.clone()],
                _ => host.note = Some(item.value.clone()),
            }
            host.edited_fields.push(item.field.as_str().to_string());
            continue;
        }
        let Some(service) = host.services.iter_mut().find(|service| {
            Some(service.port) == item.port && Some(service.protocol) == item.protocol
        }) else {
            continue;
        };
        let value = Some(item.value.clone());
        match item.field {
            OverrideField::Product => service.product = value,
            OverrideField::Version => service.version = value,
            OverrideField::ServiceName => service.name = value,
            _ => service.note = value,
        }
        service.edited_fields.push(item.field.as_str().to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Service, ServiceState};

    fn host() -> Host {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut web = Service::new(80, Protocol::Tcp, ServiceState::Open);
        web.product = Some("nginx".into());
        host.services = vec![web];
        host
    }

    fn item(port: Option<u16>, field: OverrideField, value: &str) -> Override {
        Override {
            ip: "10.0.0.5".parse().unwrap(),
            port,
            protocol: port.map(|_| Protocol::Tcp),
            field,
            value: value.into(),
            updated_at: Utc::now(),
            updated_by: Some("admin".into()),
        }
    }

    #[test]
    fn field_names_round_trip() {
        for field in OverrideField::ALL {
            assert_eq!(OverrideField::parse(field.as_str()), Some(field));
        }
        assert!(OverrideField::Product.is_service_field());
        assert!(!OverrideField::HostNote.is_service_field());
    }

    #[test]
    fn overrides_are_applied_and_marked() {
        let mut hosts = vec![host()];
        apply_overrides(
            &mut hosts,
            &[
                item(None, OverrideField::Hostname, "kamera-hala-1"),
                item(Some(80), OverrideField::Product, "Hikvision Web"),
                item(Some(80), OverrideField::ServiceNote, "zgłoszone do IT"),
            ],
        );
        let host = &hosts[0];
        assert_eq!(host.hostnames, vec!["kamera-hala-1"]);
        assert_eq!(host.edited_fields, vec!["hostname"]);
        assert_eq!(host.services[0].product.as_deref(), Some("Hikvision Web"));
        assert_eq!(host.services[0].note.as_deref(), Some("zgłoszone do IT"));
        assert_eq!(
            host.services[0].edited_fields,
            vec!["product", "service_note"]
        );
    }

    #[test]
    fn overrides_for_missing_targets_are_ignored() {
        let mut hosts = vec![host()];
        apply_overrides(
            &mut hosts,
            &[item(Some(443), OverrideField::Version, "1.0")],
        );
        let mut other = item(None, OverrideField::HostNote, "x");
        other.ip = "10.0.0.6".parse().unwrap();
        apply_overrides(&mut hosts, &[other]);
        assert!(hosts[0].edited_fields.is_empty());
        assert!(hosts[0].services[0].edited_fields.is_empty());
    }
}
