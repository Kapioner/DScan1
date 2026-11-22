//! Sterowanie skanami przez API (C5, S9): start, zatrzymanie, wznowienie, zmiany i porównania.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use dscan_core::models::{Change, compare_runs};
use dscan_engine::{EngineError, ScanRequest};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::CurrentUser;
use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct StartScanRequest {
    /// Adresy IP, sieci CIDR lub domeny (tylko z `[scope] allowed_networks`).
    pub targets: Vec<String>,
    /// Nazwany profil z `[profiles]` w konfiguracji serwera.
    pub profile: Option<String>,
    /// `discovery` albo `services`.
    pub mode: Option<String>,
}

/// Odrzucony cel i powód.
#[derive(Debug, Serialize, ToSchema)]
pub struct RejectedTarget {
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StartScanResponse {
    pub run_id: i64,
    pub address_count: String,
    pub networks: Vec<String>,
    pub rejected: Vec<RejectedTarget>,
    /// Kiedy skan zostanie wstrzymany (koniec okna profilu).
    pub stop_at: Option<DateTime<Utc>>,
}

/// Zleca skan (w tle). Wymaga `targets:write`.
#[utoipa::path(post, path = "/api/v1/scans", tag = "skany", request_body = StartScanRequest,
    responses((status = 202, body = StartScanResponse), (status = 400, body = crate::ErrorBody)))]
pub async fn start_scan(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<StartScanRequest>,
) -> Result<(StatusCode, Json<StartScanResponse>), ApiError> {
    let service = state.scan_service()?;
    let request = ScanRequest {
        targets: input.targets,
        profile: input.profile,
        mode: input.mode,
        requested_by: Some(user.0.id),
        ..ScanRequest::default()
    };
    let started = match service.start(request).await {
        Err(EngineError::NoTargetsInScope(plan)) => {
            let reasons = rejected(&plan)
                .into_iter()
                .map(|r| format!("{}: {}", r.target, r.reason))
                .collect::<Vec<_>>();
            return Err(ApiError::BadRequest(format!(
                "brak celów w dozwolonym zakresie [scope]{}",
                if reasons.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", reasons.join("; "))
                }
            )));
        }
        other => other?,
    };
    let plan = &started.plan;
    crate::audit::record(
        &state,
        &user,
        "start",
        "scan",
        started.run_id,
        &plan.address_count.to_string(),
    )
    .await;
    Ok((
        StatusCode::ACCEPTED,
        Json(StartScanResponse {
            run_id: started.run_id,
            address_count: plan.address_count.to_string(),
            networks: plan.networks.iter().map(ToString::to_string).collect(),
            rejected: rejected(plan),
            stop_at: started.stop_at,
        }),
    ))
}

fn rejected(plan: &dscan_scanner::targets::TargetPlan) -> Vec<RejectedTarget> {
    let invalid = plan.invalid.iter().map(|(t, r)| RejectedTarget {
        target: t.clone(),
        reason: r.clone(),
    });
    let unresolved = plan.unresolved.iter().map(|(t, r)| RejectedTarget {
        target: t.clone(),
        reason: r.clone(),
    });
    let outside = plan.out_of_scope.iter().map(|net| RejectedTarget {
        target: net.to_string(),
        reason: "poza zakresem [scope]".into(),
    });
    invalid.chain(unresolved).chain(outside).collect()
}

/// Wstrzymuje trwający skan (niedokończone podgrupy wracają do kolejki).
#[utoipa::path(post, path = "/api/v1/scans/{id}/stop", tag = "skany", params(("id" = i64, Path)),
    responses((status = 202), (status = 404, description = "Skan nie trwa", body = crate::ErrorBody)))]
pub async fn stop_scan(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    if state.scan_service()?.stop(id) {
        Ok(StatusCode::ACCEPTED)
    } else {
        Err(ApiError::NotFound)
    }
}

/// Wznawia wstrzymany skan od niedokończonych podgrup.
#[utoipa::path(post, path = "/api/v1/scans/{id}/resume", tag = "skany", params(("id" = i64, Path)),
    responses((status = 202), (status = 400, body = crate::ErrorBody)))]
pub async fn resume_scan(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.scan_service()?.resume(id, None).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChangeView {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    /// `appeared`, `disappeared` albo `modified`.
    pub kind: String,
    pub label: String,
    pub previous_run_id: i64,
    pub current_run_id: i64,
}

impl From<&Change> for ChangeView {
    fn from(change: &Change) -> Self {
        ChangeView {
            ip: change.key.ip.to_string(),
            port: change.key.port,
            protocol: change.key.protocol.as_str().to_string(),
            kind: change.kind.as_str().to_string(),
            label: change.kind.label().to_string(),
            previous_run_id: change.previous_run_id,
            current_run_id: change.current_run_id,
        }
    }
}

/// Zmiany zapisane dla przebiegu (względem poprzedniego przebiegu tego profilu).
#[utoipa::path(get, path = "/api/v1/scans/{id}/changes", tag = "skany", params(("id" = i64, Path)),
    responses((status = 200, body = [ChangeView])))]
pub async fn run_changes(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<ChangeView>>, ApiError> {
    dscan_db::get_scan_run(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let changes = dscan_db::list_changes(&state.db, id).await?;
    Ok(Json(changes.iter().map(ChangeView::from).collect()))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct DiffParams {
    pub from: i64,
    pub to: i64,
}

/// Porównanie dowolnych dwóch przebiegów (liczone na bieżąco).
#[utoipa::path(get, path = "/api/v1/diff", tag = "skany", params(DiffParams),
    responses((status = 200, body = [ChangeView]), (status = 404, body = crate::ErrorBody)))]
pub async fn diff(
    State(state): State<AppState>,
    Query(params): Query<DiffParams>,
) -> Result<Json<Vec<ChangeView>>, ApiError> {
    for id in [params.from, params.to] {
        dscan_db::get_scan_run(&state.db, id)
            .await?
            .ok_or(ApiError::NotFound)?;
    }
    let previous = dscan_db::run_fingerprints(&state.db, params.from).await?;
    let current = dscan_db::run_fingerprints(&state.db, params.to).await?;
    let changes = compare_runs(&previous, &current, (params.from, params.to), Utc::now());
    Ok(Json(changes.iter().map(ChangeView::from).collect()))
}

/// Nazwy profili z `[profiles]` w konfiguracji serwera (do wyboru w CLI i UI).
#[utoipa::path(get, path = "/api/v1/scan-profiles", tag = "skany", responses((status = 200, body = [String])))]
pub async fn config_profiles(State(state): State<AppState>) -> Result<Json<Vec<String>>, ApiError> {
    Ok(Json(dscan_config::profile_names(
        state.scan_service()?.settings(),
    )))
}
