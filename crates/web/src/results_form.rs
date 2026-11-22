//! Import wyników skanów z panelu WWW (nmap XML, JSON, CSV): to samo przetwarzanie co
//! `POST /api/v1/imports/results` - zakres `[scope]`, zapis przebiegu, porównanie z poprzednim.

use askama::Template;
use axum::extract::{Multipart, State};
use axum::response::Html;
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_core::models::Host;
use dscan_engine::{ResultImport, import_results, split_by_scope};
use dscan_integrations::{parse_result_format, parse_results};

use crate::pages::render;
use crate::session::WebUser;

/// Wiersz zmiany w raporcie importu.
pub struct ChangeRow {
    pub mark: char,
    pub address: String,
    pub label: &'static str,
}

/// Raport importu wyników (fragment podmieniany przez htmx).
#[derive(Template)]
#[template(path = "results_report.html")]
pub struct ResultsReport {
    pub error: Option<String>,
    pub file_name: String,
    pub run_id: Option<i64>,
    pub hosts: usize,
    pub open_ports: usize,
    pub out_of_scope: Vec<String>,
    pub previous_run_id: Option<i64>,
    pub changes: Vec<ChangeRow>,
}

impl ResultsReport {
    fn error(message: impl Into<String>) -> Self {
        ResultsReport {
            error: Some(message.into()),
            file_name: String::new(),
            run_id: None,
            hosts: 0,
            open_ports: 0,
            out_of_scope: Vec::new(),
            previous_run_id: None,
            changes: Vec::new(),
        }
    }
}

/// Format z rozszerzenia pliku: `.xml` → nmap XML, `.json`, `.csv`.
fn format_name(file_name: &str) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".xml") {
        Some("nmap-xml")
    } else if lower.ends_with(".json") {
        Some("json")
    } else if lower.ends_with(".csv") {
        Some("csv")
    } else {
        None
    }
}

fn open_ports(hosts: &[Host]) -> usize {
    hosts.iter().map(Host::open_port_count).sum()
}

/// Wgranie pliku z wynikami skanu.
pub async fn import_results_file(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    mut multipart: Multipart,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return render(&ResultsReport::error("Brak uprawnień do importu wyników."));
    }
    let (mut file_name, mut content, mut dry_run) = (String::new(), String::new(), false);
    while let Ok(Some(field)) = multipart.next_field().await {
        match field.name() {
            Some("file") => {
                file_name = field.file_name().unwrap_or("").to_string();
                let Ok(bytes) = field.bytes().await else {
                    return render(&ResultsReport::error("Błąd przesyłania pliku."));
                };
                let Ok(text) = String::from_utf8(bytes.to_vec()) else {
                    return render(&ResultsReport::error("Plik musi być tekstem UTF-8."));
                };
                content = text;
            }
            Some("dry_run") => dry_run = true,
            _ => {}
        }
    }
    let Some(format) = format_name(&file_name).and_then(parse_result_format) else {
        return render(&ResultsReport::error(
            "Wybierz plik .xml (nmap -oX), .json albo .csv.",
        ));
    };
    let parsed = match parse_results(&content, format) {
        Ok(parsed) => parsed,
        Err(error) => return render(&ResultsReport::error(error.to_string())),
    };
    let settings = state.scan_service()?.settings().clone();
    if dry_run {
        let (inside, outside) = split_by_scope(parsed.hosts, &settings.scope.allowed_networks);
        return render(&ResultsReport {
            error: None,
            file_name,
            run_id: None,
            hosts: inside.len(),
            open_ports: open_ports(&inside),
            out_of_scope: outside,
            previous_run_id: None,
            changes: Vec::new(),
        });
    }
    let import = ResultImport {
        hosts: parsed.hosts,
        raw_xml: parsed.raw_xml,
        profile: "import".into(),
        requested_by: Some(user.0.id),
    };
    let outcome = match import_results(&state.db, &state.cipher, &settings, import).await {
        Ok(outcome) => outcome,
        Err(error) => return render(&ResultsReport::error(error.to_string())),
    };
    let summary = &outcome.summary;
    let details = format!("wyniki ({file_name}): {} hostów", summary.hosts.len());
    dscan_api::audit::record(&state, &user, "import", "scan", summary.run_id, &details).await;
    let changes = summary
        .comparison
        .iter()
        .flat_map(|c| &c.changes)
        .map(|change| ChangeRow {
            mark: match change.kind.label() {
                "nowa" => '+',
                "zniknęła" => '-',
                _ => '~',
            },
            address: format!(
                "{}:{}/{}",
                change.key.ip,
                change.key.port,
                change.key.protocol.as_str()
            ),
            label: change.kind.label(),
        })
        .collect();
    render(&ResultsReport {
        error: None,
        file_name,
        run_id: Some(summary.run_id),
        hosts: summary.hosts.len(),
        open_ports: open_ports(&summary.hosts),
        out_of_scope: outcome.out_of_scope.clone(),
        previous_run_id: summary.comparison.as_ref().map(|c| c.previous_run_id),
        changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_from_extension() {
        assert_eq!(format_name("przebieg-1.XML"), Some("nmap-xml"));
        assert_eq!(format_name("hosty.json"), Some("json"));
        assert_eq!(format_name("uslugi.csv"), Some("csv"));
        assert_eq!(format_name("notatki.txt"), None);
    }
}
