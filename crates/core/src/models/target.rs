use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Rodzaj celu skanowania podanego przez użytkownika.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// Pojedynczy adres, np. `10.0.0.5`.
    Ip(IpAddr),
    /// Cała sieć, np. `10.0.0.0/24`.
    Cidr(IpNet),
    /// Nazwa domenowa, rozwiązywana na adresy przed skanem.
    Domain(String),
}

impl fmt::Display for TargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetKind::Ip(ip) => write!(f, "{ip}"),
            TargetKind::Cidr(net) => write!(f, "{net}"),
            TargetKind::Domain(name) => write!(f, "{name}"),
        }
    }
}

/// Cel skanowania wraz z opcjonalną grupą i notatką.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub kind: TargetKind,
    pub group: Option<String>,
    pub note: Option<String>,
}

impl Target {
    /// Tworzy cel bez grupy i notatki.
    pub fn new(kind: TargetKind) -> Self {
        Target {
            kind,
            group: None,
            note: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_shows_value_as_entered() {
        let ip = TargetKind::Ip("10.0.0.5".parse().unwrap());
        let net = TargetKind::Cidr("10.0.0.0/24".parse().unwrap());
        let domain = TargetKind::Domain("example.com".to_string());

        assert_eq!(ip.to_string(), "10.0.0.5");
        assert_eq!(net.to_string(), "10.0.0.0/24");
        assert_eq!(domain.to_string(), "example.com");
    }

    #[test]
    fn target_survives_json_round_trip() {
        let target = Target::new(TargetKind::Cidr("192.168.1.0/24".parse().unwrap()));

        let json = serde_json::to_string(&target).unwrap();
        let restored: Target = serde_json::from_str(&json).unwrap();

        assert_eq!(restored, target);
        assert!(json.contains(r#""cidr":"192.168.1.0/24""#));
    }
}
