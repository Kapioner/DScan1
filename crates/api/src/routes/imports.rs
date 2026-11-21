//! Import przez API: cele (I1) i wyniki skanów (I2). Wymaga `targets:write`.

use axum::Json;
use axum::extract::State;
use dscan_engine::{ResultImport, import_results};
use dscan_integrations::{ImportFormat, import_targets, parse_result_format, parse_results};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::routes::scan_control::ChangeView;
use crate::{ApiError, AppState};

/// Treść pliku przesłana w JSON (CLI czyta plik i wysyła jego zawartość).
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportRequest {
    /// Cele: `csv`/`json`. Wyniki: `nmap-xml`/`json`/`csv`.
    pub format: String,
    pub content: String,
    /// Tylko walidacja, bez zapisu.
    #[serde(default)]
    pub dry_run: bool,
    /// Wyniki: nazwa profilu przebiegu (domyślnie `import`).
    pub profile: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RejectedRow {
    pub line: usize,
    pub value: String,
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TargetImportResponse {
    pub accepted: usize,
    pub rejected: Vec<RejectedRow>,
    pub inserted: u64,
    pub duplicates: u64,
}

/// Import celów z CSV/JSON z raportem odrzuconych wierszy.
#[utoipa::path(post, path = "/api/v1/imports/targets", tag = "import", request_body = ImportRequest,
    responses((status = 200, body = TargetImportResponse), (status = 400, body = crate::ErrorBody)))]
pub async fn import_targets_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<ImportRequest>,
) -> Result<Json<TargetImportResponse>, ApiError> {
    let format = match input.format.as_str() {
        "csv" => ImportFormat::Csv,
        "json" => ImportFormat::Json,
        other => {
            return Err(ApiError::BadRequest(format!(
                "nieznany format celów: {other}"
            )));
        }
    };
    let import =
        import_targets(&input.content, format).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let rejected = import
        .rejected
        .iter()
        .map(|row| RejectedRow {
            line: row.row,
            value: row.value.clone(),
            reason: row.reason.clone(),
        })
        .collect();
    let mut response = TargetImportResponse {
        accepted: import.accepted.len(),
        rejected,
        inserted: 0,
        duplicates: 0,
    };
    if !input.dry_run {
        let summary = dscan_db::insert_targets(&state.db, &state.cipher, &import.accepted).await?;
        response.inserted = summary.inserted;
        response.duplicates = summary.already_present;
        let details = format!(
            "cele ({}): {} nowych, {} istniało",
            input.format, summary.inserted, summary.already_present
        );
        crate::audit::record(&state, &user, "import", "target", "", &details).await;
    }
    Ok(Json(response))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResultImportResponse {
    /// Numer przebiegu (`None` w trybie próbnym).
    pub run_id: Option<i64>,
    pub hosts: usize,
    pub open_ports: usize,
    /// Adresy spoza `[scope]` — pominięte.
    pub out_of_scope: Vec<String>,
    /// Z którym przebiegiem porównano (`None`: pierwszy przebieg tego profilu).
    pub previous_run_id: Option<i64>,
    /// Zmiany względem poprzedniego przebiegu tego profilu.
    pub changes: Vec<ChangeView>,
    pub became_inactive: Vec<String>,
}

/// Import wyników (nmap XML, JSON, CSV) — to samo przetwarzanie co skan.
#[utoipa::path(post, path = "/api/v1/imports/results", tag = "import", request_body = ImportRequest,
    responses((status = 200, body = ResultImportResponse), (status = 400, body = crate::ErrorBody)))]
pub async fn import_results_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<ImportRequest>,
) -> Result<Json<ResultImportResponse>, ApiError> {
    let settings = state.scan_service()?.settings().clone();
    let format = parse_result_format(&input.format).ok_or_else(|| {
        ApiError::BadRequest(format!("nieznany format wyników: {}", input.format))
    })?;
    let parsed =
        parse_results(&input.content, format).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    if input.dry_run {
        let (inside, outside) =
            dscan_engine::split_by_scope(parsed.hosts, &settings.scope.allowed_networks);
        return Ok(Json(ResultImportResponse {
            run_id: None,
            hosts: inside.len(),
            open_ports: inside
                .iter()
                .map(dscan_core::models::Host::open_port_count)
                .sum(),
            out_of_scope: outside,
            previous_run_id: None,
            changes: Vec::new(),
            became_inactive: Vec::new(),
        }));
    }
    let import = ResultImport {
        hosts: parsed.hosts,
        raw_xml: parsed.raw_xml,
        profile: input.profile.unwrap_or_else(|| "import".into()),
        requested_by: Some(user.0.id),
    };
    let outcome = import_results(&state.db, &state.cipher, &settings, import).await?;
    let details = format!(
        "wyniki ({}): {} hostów",
        input.format,
        outcome.summary.hosts.len()
    );
    crate::audit::record(
        &state,
        &user,
        "import",
        "scan",
        outcome.summary.run_id,
        &details,
    )
    .await;
    let summary = &outcome.summary;
    Ok(Json(ResultImportResponse {
        run_id: Some(summary.run_id),
        hosts: summary.hosts.len(),
        open_ports: summary
            .hosts
            .iter()
            .map(dscan_core::models::Host::open_port_count)
            .sum(),
        out_of_scope: outcome.out_of_scope.clone(),
        previous_run_id: summary.comparison.as_ref().map(|c| c.previous_run_id),
        changes: summary
            .comparison
            .iter()
            .flat_map(|c| &c.changes)
            .map(ChangeView::from)
            .collect(),
        became_inactive: summary
            .presence
            .iter()
            .flat_map(|p| &p.became_inactive)
            .map(ToString::to_string)
            .collect(),
    }))
}
