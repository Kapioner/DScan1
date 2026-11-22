//! Wyszukiwanie po polach szyfrowanych przez ślepy indeks (B3).

use axum::Json;
use axum::extract::{Query, State};
use dscan_db::{BlindKind, header_value_key, search_blind_index};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, IntoParams)]
pub struct SearchParams {
    /// Nazwa ciasteczka (np. `PHPSESSID`).
    pub cookie: Option<String>,
    /// Nazwa nagłówka (np. `X-Debug-Token`).
    pub header: Option<String>,
    /// Z `header`: dokładna wartość nagłówka.
    pub value: Option<String>,
    /// Tylko ten przebieg.
    pub run: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SearchHit {
    pub run_id: i64,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
}

/// Usługi z danym ciasteczkiem lub nagłówkiem (wielkość liter bez znaczenia).
#[utoipa::path(get, path = "/api/v1/search", tag = "wyniki", params(SearchParams),
    responses((status = 200, body = [SearchHit]), (status = 400, body = crate::ErrorBody)))]
pub async fn search(
    State(state): State<AppState>,
    Query(params): Query<SearchParams>,
) -> Result<Json<Vec<SearchHit>>, ApiError> {
    let (kind, value) = match (&params.cookie, &params.header, &params.value) {
        (Some(cookie), None, None) => (BlindKind::Cookie, cookie.clone()),
        (None, Some(header), None) => (BlindKind::Header, header.clone()),
        (None, Some(header), Some(value)) => {
            (BlindKind::HeaderValue, header_value_key(header, value))
        }
        _ => {
            return Err(ApiError::BadRequest(
                "podaj cookie=… albo header=… (opcjonalnie z value=…)".into(),
            ));
        }
    };
    let hits = search_blind_index(&state.db, &state.cipher, kind, &value, params.run).await?;
    Ok(Json(
        hits.into_iter()
            .map(|hit| SearchHit {
                run_id: hit.run_id,
                ip: hit.ip.to_string(),
                port: hit.port,
                protocol: hit.protocol,
            })
            .collect(),
    ))
}
