//! Widoki hosta (F5, F6): wartości sformatowane do szablonów, bez logiki HTTP.

use std::collections::HashMap;
use std::net::IpAddr;

use dscan_core::models::{Change, ChangeKind, Host, HostStatus};

/// Etykieta stanu obecności (S11/S10).
pub fn status_label(status: Option<HostStatus>) -> &'static str {
    match status {
        Some(HostStatus::Active) => "aktywny",
        Some(HostStatus::Inactive) => "nieaktywny",
        Some(HostStatus::Unstable) => "niestabilny",
        None => "—",
    }
}

/// Pozycja listy wyboru (`<option>`).
pub struct SelectOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

impl SelectOption {
    pub fn new(value: impl ToString, label: impl Into<String>, selected: bool) -> Self {
        SelectOption {
            value: value.to_string(),
            label: label.into(),
            selected,
        }
    }
}

/// Odpowiedź hosta w przebiegu (historia S11).
pub struct ResponseEntry {
    pub run: i64,
    pub ok: bool,
}

/// Komórka mapy dostępności w godzinach (M2).
pub struct HourCell {
    pub hour: u32,
    /// `hour-up`, `hour-mixed`, `hour-down`, `hour-none`.
    pub css: &'static str,
    pub title: String,
}

/// 24 komórki profilu godzinowego.
pub fn hour_cells(history: &[(chrono::DateTime<chrono::Utc>, bool)]) -> Vec<HourCell> {
    dscan_core::models::hourly_profile(history)
        .iter()
        .enumerate()
        .map(|(hour, stat)| {
            let css = match stat.rate() {
                None => "hour-none",
                Some(r) if r >= 0.85 => "hour-up",
                Some(r) if r <= 0.15 => "hour-down",
                Some(_) => "hour-mixed",
            };
            HourCell {
                hour: hour as u32,
                css,
                title: format!("{hour}:00 — odpowiedzi {}/{}", stat.responded, stat.total),
            }
        })
        .collect()
}

/// Wiersz listy hostów.
pub struct HostRow {
    pub ip: String,
    pub hostname: String,
    pub status: &'static str,
    /// Klasa stabilności (M5).
    pub stability: String,
    pub ports: String,
    pub technologies: String,
    pub edited: bool,
}

impl HostRow {
    pub fn new(host: &Host, presence: &HashMap<IpAddr, HostStatus>, stability: String) -> Self {
        let mut technologies: Vec<String> = host
            .services
            .iter()
            .flat_map(|s| &s.detections)
            .map(|d| d.technology.clone())
            .collect();
        technologies.sort();
        technologies.dedup();
        HostRow {
            ip: host.ip.to_string(),
            hostname: host.hostnames.first().cloned().unwrap_or_default(),
            status: status_label(presence.get(&host.ip).copied()),
            stability,
            ports: host
                .services
                .iter()
                .map(|s| format!("{}/{}", s.port, s.protocol.as_str()))
                .collect::<Vec<_>>()
                .join(", "),
            technologies: technologies.join(", "),
            edited: !host.edited_fields.is_empty()
                || host.services.iter().any(|s| !s.edited_fields.is_empty()),
        }
    }
}

/// Pole wyniku z informacją, czy jest poprawione ręcznie (F6).
pub struct FieldView {
    /// Nazwa pola poprawki (`hostname`, `product`…).
    pub field: &'static str,
    pub label: &'static str,
    pub value: String,
    pub edited: bool,
}

pub(crate) fn field(
    field: &'static str,
    label: &'static str,
    value: Option<&str>,
    edited: &[String],
) -> FieldView {
    FieldView {
        field,
        label,
        value: value.unwrap_or_default().to_string(),
        edited: edited.iter().any(|f| f == field),
    }
}

/// Wpis historii zmian adresu.
pub struct ChangeEntry {
    pub run: i64,
    pub css: &'static str,
    pub address: String,
    pub label: String,
}

impl From<&Change> for ChangeEntry {
    fn from(change: &Change) -> Self {
        ChangeEntry {
            run: change.current_run_id,
            css: change_css(change.kind),
            address: format!("{}/{}", change.key.port, change.key.protocol.as_str()),
            label: change.kind.label().to_string(),
        }
    }
}

/// Klasa CSS koloru zmiany (F7).
pub fn change_css(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Appeared => "change-new",
        ChangeKind::Disappeared => "change-gone",
        ChangeKind::Modified => "change-mod",
    }
}

/// Pola hosta do edycji.
pub fn host_fields(host: &Host) -> Vec<FieldView> {
    vec![
        field(
            "hostname",
            "Nazwa hosta",
            host.hostnames.first().map(String::as_str),
            &host.edited_fields,
        ),
        field(
            "host_note",
            "Notatka",
            host.note.as_deref(),
            &host.edited_fields,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_view::ServiceView;
    use chrono::Utc;
    use dscan_core::models::{Detection, Protocol, Service, ServiceState};

    #[test]
    fn edited_flags_and_row() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut service = Service::new(80, Protocol::Tcp, ServiceState::Open);
        service.product = Some("nginx".into());
        service.edited_fields = vec!["product".into()];
        service.detections = vec![Detection::from_evidence("nginx".into(), None, Vec::new())];
        host.services.push(service);
        let presence = HashMap::from([(host.ip, HostStatus::Unstable)]);
        let row = HostRow::new(&host, &presence, "stabilny".into());
        assert_eq!(
            (row.status, row.ports.as_str(), row.edited),
            ("niestabilny", "80/tcp", true)
        );
        let view = ServiceView::new(&host.services[0], Utc::now());
        let product = view.fields.iter().find(|f| f.field == "product").unwrap();
        assert!(product.edited && product.value == "nginx");
        assert!(
            !view
                .fields
                .iter()
                .find(|f| f.field == "version")
                .unwrap()
                .edited
        );
    }
}
