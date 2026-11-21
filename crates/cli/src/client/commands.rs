//! Polecenia wykonywane przez API (C5).

use std::time::Duration;

use dscan_core::models::Host;
use serde_json::json;

use super::report::{
    format_change_views, format_result_import, format_run_progress, format_signature_test,
    format_signatures, format_started, format_target_import,
};
use super::types::{
    ChangeView, ResultImportResponse, ScanRunView, SignatureTestResponse, SignatureView,
    StartScanResponse, TargetImportResponse, TargetView,
};
use super::{ApiClient, encode_query};
use crate::commands::scan::ScanArgs;
use crate::commands::scan_report::format_hosts;
use crate::error::CliError;

/// Jak często pytamy serwer o postęp skanu.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Zleca skan na serwerze i śledzi postęp aż do końca (albo wstrzymania).
pub async fn scan_via_api(args: &ScanArgs) -> Result<(), CliError> {
    let client = ApiClient::from_saved()?;
    let body = json!({ "targets": args.targets, "profile": args.profile, "mode": args.mode.map(|m| m.name()) });
    let started: StartScanResponse = client.post("/api/v1/scans", &body).await?;
    eprint!("{}", format_started(&started));
    let id = started.run_id;
    // Linia postępu tylko po zmianie (skończona podgrupa, nowy stan) albo co 10 odpytań.
    let (mut last, mut polls) = (None, 0u32);
    let run = loop {
        let run: ScanRunView = client.get(&format!("/api/v1/scans/{id}")).await?;
        let key = (run.completed_subgroups, run.status.clone());
        if last.as_ref() != Some(&key) || polls % 10 == 0 {
            eprintln!("{}", format_run_progress(&run));
            last = Some(key);
        }
        polls += 1;
        if !matches!(run.status.as_str(), "pending" | "running") {
            break run;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    };
    eprintln!("Przebieg #{id} zakończony ze stanem: {}", run.status);
    let changes: Vec<ChangeView> = client.get(&format!("/api/v1/scans/{id}/changes")).await?;
    eprint!(
        "{}",
        format_change_views("Zmiany względem poprzedniego przebiegu", &changes)
    );
    if !args.quiet {
        let hosts: Vec<Host> = client.get(&format!("/api/v1/scans/{id}/hosts")).await?;
        print!("{}", format_hosts(&hosts));
    }
    Ok(())
}

/// Wysyła zawartość pliku do importu celów albo wyników.
pub async fn import_via_api(
    results: bool,
    format: &str,
    content: String,
    dry_run: bool,
) -> Result<(), CliError> {
    let client = ApiClient::from_saved()?;
    let body = json!({ "format": format, "content": content, "dry_run": dry_run });
    if results {
        let response: ResultImportResponse = client.post("/api/v1/imports/results", &body).await?;
        print!("{}", format_result_import(&response));
    } else {
        let response: TargetImportResponse = client.post("/api/v1/imports/targets", &body).await?;
        print!("{}", format_target_import(&response, dry_run));
    }
    Ok(())
}

/// Parametry eksportu jako zapytanie URL.
#[derive(Debug, Default)]
pub struct ExportQuery {
    pub kind: &'static str,
    pub format: &'static str,
    pub run: Option<i64>,
    pub port: Option<u16>,
    pub state: Option<String>,
    pub technology: Option<String>,
    pub edited: bool,
}

impl ExportQuery {
    pub fn path(&self) -> String {
        let mut query = vec![format!("format={}", self.format)];
        query.extend(self.run.map(|run| format!("run={run}")));
        query.extend(self.port.map(|port| format!("port={port}")));
        query.extend(
            self.state
                .as_deref()
                .map(|s| format!("state={}", encode_query(s))),
        );
        query.extend(
            self.technology
                .as_deref()
                .map(|t| format!("technology={}", encode_query(t))),
        );
        if self.edited {
            query.push("edited=true".into());
        }
        format!("/api/v1/exports/{}?{}", self.kind, query.join("&"))
    }
}

pub async fn export_via_api(query: &ExportQuery) -> Result<String, CliError> {
    ApiClient::from_saved()?.get_text(&query.path()).await
}

pub async fn diff_via_api(from: i64, to: i64) -> Result<(), CliError> {
    let changes: Vec<ChangeView> = ApiClient::from_saved()?
        .get(&format!("/api/v1/diff?from={from}&to={to}"))
        .await?;
    print!(
        "{}",
        format_change_views(&format!("Zmiany #{from} → #{to}"), &changes)
    );
    Ok(())
}

pub async fn signatures_via_api() -> Result<(), CliError> {
    let list: Vec<SignatureView> = ApiClient::from_saved()?.get("/api/v1/signatures").await?;
    print!("{}", format_signatures(&list));
    Ok(())
}

pub async fn signature_test_via_api(signature: &str, url: &str) -> Result<(), CliError> {
    let body = json!({ "signature": signature, "url": url });
    let response: SignatureTestResponse = ApiClient::from_saved()?
        .post("/api/v1/signatures/test", &body)
        .await?;
    print!("{}", format_signature_test(&response, signature));
    Ok(())
}

/// Dodaje cele; zwraca raport (dodane i odrzucone z powodem).
pub async fn add_targets_via_api(
    targets: &[String],
    group: Option<&str>,
) -> Result<String, CliError> {
    let client = ApiClient::from_saved()?;
    let mut report = String::new();
    for target in targets {
        let body = json!({ "target": target, "group": group });
        let line = match client.post::<_, TargetView>("/api/v1/targets", &body).await {
            Ok(view) => format!("dodano #{} {}\n", view.id, view.value),
            Err(CliError::Api { message, .. }) => format!("odrzucono {target}: {message}\n"),
            Err(error) => return Err(error),
        };
        report.push_str(&line);
    }
    Ok(report)
}

/// Usuwa cele o podanych wartościach (np. `10.0.0.0/24`).
pub async fn remove_targets_via_api(values: &[String]) -> Result<String, CliError> {
    let client = ApiClient::from_saved()?;
    let stored: Vec<TargetView> = client.get("/api/v1/targets").await?;
    let mut report = String::new();
    for value in values {
        match stored.iter().find(|target| &target.value == value) {
            Some(target) => {
                client
                    .delete(&format!("/api/v1/targets/{}", target.id))
                    .await?;
                report.push_str(&format!("usunięto #{} {value}\n", target.id));
            }
            None => report.push_str(&format!("nie ma celu {value}\n")),
        }
    }
    Ok(report)
}

/// Zatrzymanie i wznowienie skanu na serwerze.
pub async fn control_scan(run_id: i64, action: &str) -> Result<(), CliError> {
    ApiClient::from_saved()?
        .post_empty(&format!("/api/v1/scans/{run_id}/{action}"))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_query_contains_filters() {
        let query = ExportQuery {
            kind: "services",
            format: "csv",
            run: Some(3),
            port: Some(80),
            technology: Some("Word Press".into()),
            edited: true,
            ..ExportQuery::default()
        };
        assert_eq!(
            query.path(),
            "/api/v1/exports/services?format=csv&run=3&port=80&technology=Word%20Press&edited=true"
        );
    }
}
