use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use dscan_core::models::ScanRun;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{ApiError, AppState};

const DEFAULT_LIMIT: i64 = 20;
const MAX_LIMIT: i64 = 200;

/// Przebieg skanu z postępem i prognozą czasu do końca.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScanRunView {
    pub id: i64,
    pub profile: String,
    /// `pending`, `running`, `paused`, `completed` albo `failed`.
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub total_addresses: u64,
    pub completed_addresses: u64,
    pub total_subgroups: u32,
    pub completed_subgroups: u32,
    pub progress_percent: f64,
    /// Czas trwania w sekundach (dla trwającego przebiegu — do teraz).
    pub elapsed_seconds: i64,
    /// Prognoza pozostałego czasu w sekundach; `null` dla zakończonych i na samym początku.
    pub estimated_remaining_seconds: Option<i64>,
}

impl ScanRunView {
    /// Widok przebiegu w chwili `now` (od niej zależą czas trwania i prognoza).
    pub fn from_run(run: &ScanRun, now: DateTime<Utc>) -> Self {
        ScanRunView {
            id: run.id,
            profile: run.profile.clone(),
            status: run.status.as_str().to_string(),
            started_at: run.started_at,
            finished_at: run.finished_at,
            total_addresses: run.total_addresses,
            completed_addresses: run.completed_addresses,
            total_subgroups: run.total_subgroups,
            completed_subgroups: run.completed_subgroups,
            progress_percent: run.progress_percent(),
            elapsed_seconds: run.elapsed(now).num_seconds(),
            estimated_remaining_seconds: run.estimated_remaining(now).map(|eta| eta.num_seconds()),
        }
    }
}

/// Parametry listy przebiegów.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListParams {
    /// Ile ostatnich przebiegów zwrócić (1–200, domyślnie 20).
    pub limit: Option<i64>,
}

/// Ostatnie przebiegi skanów, od najnowszego.
#[utoipa::path(
    get,
    path = "/api/v1/scans",
    tag = "skany",
    params(ListParams),
    responses((status = 200, description = "Lista przebiegów", body = [ScanRunView]))
)]
pub async fn list_scans(
    State(state): State<AppState>,
    Query(params): Query<ListParams>,
) -> Result<Json<Vec<ScanRunView>>, ApiError> {
    let limit = clamp_limit(params.limit);
    let runs = dscan_db::list_scan_runs(&state.db, limit)
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let now = Utc::now();
    Ok(Json(
        runs.iter()
            .map(|run| ScanRunView::from_run(run, now))
            .collect(),
    ))
}

/// Jeden przebieg skanu.
#[utoipa::path(
    get,
    path = "/api/v1/scans/{id}",
    tag = "skany",
    params(("id" = i64, Path, description = "Numer przebiegu")),
    responses(
        (status = 200, description = "Przebieg", body = ScanRunView),
        (status = 404, description = "Nie ma takiego przebiegu", body = crate::ErrorBody)
    )
)]
pub async fn get_scan(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ScanRunView>, ApiError> {
    let run = dscan_db::get_scan_run(&state.db, id)
        .await
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(ScanRunView::from_run(&run, Utc::now())))
}

/// Limit listy w dozwolonym zakresie.
pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use dscan_core::models::ScanStatus;

    fn running_run() -> ScanRun {
        ScanRun {
            id: 7,
            profile: "services".into(),
            status: ScanStatus::Running,
            started_at: "2026-11-21T10:00:00Z".parse().unwrap(),
            finished_at: None,
            total_addresses: 1000,
            completed_addresses: 250,
            total_subgroups: 4,
            completed_subgroups: 1,
        }
    }

    #[test]
    fn view_contains_progress_and_eta() {
        let run = running_run();
        let view = ScanRunView::from_run(&run, run.started_at + TimeDelta::seconds(30));

        assert_eq!(view.status, "running");
        assert_eq!(view.progress_percent, 25.0);
        assert_eq!(view.elapsed_seconds, 30);
        assert_eq!(view.estimated_remaining_seconds, Some(90));
    }

    #[test]
    fn limit_is_clamped() {
        assert_eq!(clamp_limit(None), 20);
        assert_eq!(clamp_limit(Some(0)), 1);
        assert_eq!(clamp_limit(Some(10_000)), 200);
    }
}
