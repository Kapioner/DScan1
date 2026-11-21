//! Dashboard (A8): najważniejsze znaleziska, zmiany od ostatniego skanu,
//! statystyki technologii i stan trwających skanów.

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use dscan_core::models::{ScanRun, estimate_remaining};
use serde::Serialize;
use utoipa::ToSchema;

use crate::routes::scan_control::ChangeView;
use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct RunState {
    pub id: i64,
    pub profile: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub progress_percent: f64,
    pub elapsed_seconds: i64,
    /// Prognoza pozostałego czasu (gdy już coś się skończyło).
    pub remaining_seconds: Option<i64>,
    pub completed_addresses: u64,
    pub total_addresses: u64,
}

impl RunState {
    pub fn from_run(run: &ScanRun, now: DateTime<Utc>) -> Self {
        let elapsed = run.elapsed(now);
        RunState {
            id: run.id,
            profile: run.profile.clone(),
            status: run.status.as_str().to_string(),
            started_at: run.started_at,
            progress_percent: run.progress_percent(),
            elapsed_seconds: elapsed.num_seconds(),
            remaining_seconds: estimate_remaining(
                elapsed,
                run.completed_addresses,
                run.total_addresses,
            )
            .map(|left| left.num_seconds()),
            completed_addresses: run.completed_addresses,
            total_addresses: run.total_addresses,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingView {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub title: String,
    pub category: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TechnologyCount {
    pub technology: String,
    pub services: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DashboardView {
    pub latest_run: Option<RunState>,
    /// Skany trwające i wstrzymane (postęp, czas, prognoza).
    pub active_runs: Vec<RunState>,
    pub findings: Vec<FindingView>,
    pub changes: Vec<ChangeView>,
    pub technologies: Vec<TechnologyCount>,
    pub hosts: usize,
    pub open_services: usize,
    pub active_hosts: usize,
    pub inactive_hosts: usize,
}

/// Dane dashboardu w jednym żądaniu.
#[utoipa::path(get, path = "/api/v1/dashboard", tag = "dashboard", responses((status = 200, body = DashboardView)))]
pub async fn dashboard(State(state): State<AppState>) -> Result<Json<DashboardView>, ApiError> {
    let data = dscan_engine::load_dashboard(&state.db, state.scan_service()?.settings()).await?;
    let now = Utc::now();
    Ok(Json(DashboardView {
        latest_run: data.latest.as_ref().map(|run| RunState::from_run(run, now)),
        active_runs: data
            .active
            .iter()
            .map(|run| RunState::from_run(run, now))
            .collect(),
        findings: data
            .findings
            .into_iter()
            .map(|f| FindingView {
                ip: f.ip,
                port: f.port,
                protocol: f.protocol,
                title: f.title,
                category: f.category,
            })
            .collect(),
        changes: data.changes.iter().map(ChangeView::from).collect(),
        technologies: data
            .technologies
            .into_iter()
            .map(|(technology, services)| TechnologyCount {
                technology,
                services,
            })
            .collect(),
        hosts: data.hosts,
        open_services: data.open_services,
        active_hosts: data.active_hosts,
        inactive_hosts: data.inactive_hosts,
    }))
}
