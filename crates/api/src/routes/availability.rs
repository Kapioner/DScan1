//! Dostępność hosta w godzinach doby (M2) i klasa stabilności (M5).

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, State};
use dscan_core::models::{Stability, classify_stability, hourly_profile};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct HourView {
    pub hour: u32,
    pub responded: u32,
    pub total: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AvailabilityView {
    pub ip: String,
    /// `insufficient`, `stable`, `silent`, `time_dependent`, `unstable`.
    pub class: String,
    pub label: String,
    /// Godziny z odpowiedziami (dla `time_dependent`).
    pub active_hours: Vec<u32>,
    pub samples: usize,
    pub hours: Vec<HourView>,
}

#[utoipa::path(get, path = "/api/v1/hosts/{ip}/availability", tag = "wyniki", params(("ip" = String, Path)),
    responses((status = 200, body = AvailabilityView)))]
pub async fn availability(
    State(state): State<AppState>,
    Path(ip): Path<IpAddr>,
) -> Result<Json<AvailabilityView>, ApiError> {
    let history = dscan_db::presence_history(&state.db, ip).await?;
    let stability = classify_stability(&history);
    let (class, active_hours) = match &stability {
        Stability::Insufficient => ("insufficient", Vec::new()),
        Stability::Stable => ("stable", Vec::new()),
        Stability::Silent => ("silent", Vec::new()),
        Stability::TimeDependent { active_hours } => ("time_dependent", active_hours.clone()),
        Stability::Unstable => ("unstable", Vec::new()),
    };
    Ok(Json(AvailabilityView {
        ip: ip.to_string(),
        class: class.into(),
        label: stability.label(),
        active_hours,
        samples: history.len(),
        hours: hourly_profile(&history)
            .iter()
            .enumerate()
            .map(|(hour, s)| HourView {
                hour: hour as u32,
                responded: s.responded,
                total: s.total,
            })
            .collect(),
    }))
}
