//! Eksport wyników (I3): hosty (JSON), usługi i zmiany (JSON/CSV) z filtrami.
//! Uprawnienia według roli: eksport wymaga `read`, a notatki i ręczne poprawki (A6)
//! trafiają do eksportu tylko dla ról z `results:write`.

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use dscan_core::models::{Host, ScanStatus, apply_overrides};
use dscan_integrations::{ExportFilter, change_rows, filter_hosts, service_rows, to_csv};
use serde::{Deserialize, Serialize};
use utoipa::IntoParams;

use crate::auth::{CurrentUser, permissions};
use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, IntoParams)]
pub struct ExportParams {
    /// `json` (domyślnie) albo `csv`.
    pub format: Option<String>,
    /// Numer przebiegu (domyślnie ostatni zakończony).
    pub run: Option<i64>,
    pub port: Option<u16>,
    /// `open`, `closed`, `filtered`.
    pub state: Option<String>,
    /// Fragment nazwy technologii.
    pub technology: Option<String>,
    /// Tylko z ręcznymi poprawkami.
    #[serde(default)]
    pub edited: bool,
}

/// Eksport `hosts`, `services` albo `changes`.
#[utoipa::path(get, path = "/api/v1/exports/{kind}", tag = "eksport",
    params(("kind" = String, Path, description = "hosts | services | changes"), ExportParams),
    responses((status = 200, description = "Plik JSON lub CSV"), (status = 400, body = crate::ErrorBody)))]
pub async fn export(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(kind): Path<String>,
    Query(params): Query<ExportParams>,
) -> Result<Response, ApiError> {
    let csv = match params.format.as_deref().unwrap_or("json") {
        "json" => false,
        "csv" => true,
        other => {
            return Err(ApiError::BadRequest(format!(
                "nieznany format eksportu: {other}"
            )));
        }
    };
    let run_id = resolve_run(&state, params.run).await?;
    match kind.as_str() {
        "changes" => {
            let rows = change_rows(&dscan_db::list_changes(&state.db, run_id).await?);
            render(&rows, csv, &format!("dscan-zmiany-{run_id}"))
        }
        "hosts" | "services" => {
            let hosts = export_hosts(&state, &user, run_id, &filter(&params)).await?;
            if kind == "services" {
                return render(
                    &service_rows(&hosts),
                    csv,
                    &format!("dscan-uslugi-{run_id}"),
                );
            }
            if csv {
                return Err(ApiError::BadRequest(
                    "hosty eksportujemy tylko jako JSON (usługi: CSV)".into(),
                ));
            }
            render(&hosts, false, &format!("dscan-hosty-{run_id}"))
        }
        _ => Err(ApiError::NotFound),
    }
}

fn filter(params: &ExportParams) -> ExportFilter {
    ExportFilter {
        port: params.port,
        state: params.state.clone(),
        technology: params.technology.clone(),
        only_edited: params.edited,
    }
}

/// Podany przebieg albo ostatni zakończony.
async fn resolve_run(state: &AppState, run: Option<i64>) -> Result<i64, ApiError> {
    if let Some(id) = run {
        dscan_db::get_scan_run(&state.db, id)
            .await?
            .ok_or(ApiError::NotFound)?;
        return Ok(id);
    }
    let runs = dscan_db::list_scan_runs(&state.db, 100).await?;
    runs.into_iter()
        .find(|run| run.status == ScanStatus::Completed)
        .map(|run| run.id)
        .ok_or_else(|| ApiError::BadRequest("brak zakończonego przebiegu do eksportu".into()))
}

async fn export_hosts(
    state: &AppState,
    user: &CurrentUser,
    run_id: i64,
    filter: &ExportFilter,
) -> Result<Vec<Host>, ApiError> {
    let mut hosts = dscan_db::load_run_hosts(&state.db, run_id).await?;
    let may_see_edits = user.has(permissions::RESULTS_WRITE);
    if may_see_edits {
        let overrides = dscan_db::list_overrides(&state.db, &state.cipher).await?;
        apply_overrides(&mut hosts, &overrides);
    } else if filter.only_edited {
        return Err(ApiError::Forbidden);
    }
    let mut hosts = filter_hosts(&hosts, filter);
    if !may_see_edits {
        strip_notes(&mut hosts);
    }
    Ok(hosts)
}

/// Rola tylko do odczytu nie widzi notatek operatorów.
pub fn strip_notes(hosts: &mut [Host]) {
    for host in hosts {
        host.note = None;
        host.services
            .iter_mut()
            .for_each(|service| service.note = None);
    }
}

fn render<T: Serialize + AsCsv>(rows: &T, csv: bool, name: &str) -> Result<Response, ApiError> {
    let (body, mime, ext) = if csv {
        (
            rows.as_csv().map_err(ApiError::Internal)?,
            "text/csv; charset=utf-8",
            "csv",
        )
    } else {
        (
            serde_json::to_string_pretty(rows).map_err(|e| ApiError::Internal(e.to_string()))?,
            "application/json",
            "json",
        )
    };
    let disposition = format!("attachment; filename=\"{name}.{ext}\"");
    Ok((
        [
            (header::CONTENT_TYPE, mime.to_string()),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        body,
    )
        .into_response())
}

/// Serializacja do CSV dla list wierszy.
pub trait AsCsv {
    fn as_csv(&self) -> Result<String, String>;
}

impl<T: Serialize> AsCsv for Vec<T> {
    fn as_csv(&self) -> Result<String, String> {
        to_csv(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn notes_are_removed_for_read_only_roles() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        host.note = Some("tajne".into());
        let mut hosts = vec![host];
        strip_notes(&mut hosts);
        assert_eq!(hosts[0].note, None);
    }
}
