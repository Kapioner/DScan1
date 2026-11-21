use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ServiceKey;

/// Rodzaj zmiany usługi między dwoma przebiegami.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Usługa pojawiła się w nowszym przebiegu.
    Appeared,
    /// Usługa zniknęła w nowszym przebiegu.
    Disappeared,
    /// Usługa istnieje w obu przebiegach, ale ma inny odcisk (hash).
    Modified,
}

impl ChangeKind {
    /// Nazwa zapisywana w bazie (kolumna `changes.kind`).
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeKind::Appeared => "appeared",
            ChangeKind::Disappeared => "disappeared",
            ChangeKind::Modified => "modified",
        }
    }

    /// Opis dla użytkownika.
    pub fn label(&self) -> &'static str {
        match self {
            ChangeKind::Appeared => "nowa",
            ChangeKind::Disappeared => "zniknęła",
            ChangeKind::Modified => "zmieniona",
        }
    }
}

/// Zmiana wykryta przy porównaniu przebiegów `previous_run_id` → `current_run_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub key: ServiceKey,
    pub kind: ChangeKind,
    pub previous_run_id: i64,
    pub current_run_id: i64,
    pub previous_fingerprint: Option<String>,
    pub current_fingerprint: Option<String>,
    pub detected_at: DateTime<Utc>,
}

impl Change {
    /// Ustala rodzaj zmiany na podstawie odcisków z obu przebiegów.
    /// Zwraca `None`, gdy usługa się nie zmieniła (lub nie istnieje w żadnym).
    pub fn classify(previous: Option<&str>, current: Option<&str>) -> Option<ChangeKind> {
        match (previous, current) {
            (None, Some(_)) => Some(ChangeKind::Appeared),
            (Some(_), None) => Some(ChangeKind::Disappeared),
            (Some(old), Some(new)) if old != new => Some(ChangeKind::Modified),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    #[test]
    fn classify_detects_all_change_kinds() {
        assert_eq!(
            Change::classify(None, Some("a")),
            Some(ChangeKind::Appeared)
        );
        assert_eq!(
            Change::classify(Some("a"), None),
            Some(ChangeKind::Disappeared)
        );
        assert_eq!(
            Change::classify(Some("a"), Some("b")),
            Some(ChangeKind::Modified)
        );
    }

    #[test]
    fn classify_returns_none_without_change() {
        assert_eq!(Change::classify(Some("a"), Some("a")), None);
        assert_eq!(Change::classify(None, None), None);
    }

    #[test]
    fn change_kind_serializes_as_snake_case() {
        let change = Change {
            key: ServiceKey {
                ip: "10.0.0.1".parse().unwrap(),
                port: 80,
                protocol: Protocol::Tcp,
            },
            kind: ChangeKind::Appeared,
            previous_run_id: 1,
            current_run_id: 2,
            previous_fingerprint: None,
            current_fingerprint: Some("abc".to_string()),
            detected_at: Utc::now(),
        };

        let json = serde_json::to_string(&change).unwrap();
        assert!(json.contains(r#""kind":"appeared""#));
        assert!(json.contains(r#""protocol":"tcp""#));
    }
}
