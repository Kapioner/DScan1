//! Sygnatury technologii przez API (C5: `dscan sig` jako klient API).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use dscan_core::models::Detection;
use dscan_engine::{build_analysis, build_fetcher, load_signatures};
use dscan_fingerprint::signatures::WebEvidence;
use dscan_fingerprint::{fetch_favicon, probe_paths, to_http_info};
use dscan_scanner::targets::{is_in_scope, single_address_network};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::{ApiError, AppState};

#[derive(Debug, Serialize, ToSchema)]
pub struct SignatureView {
    pub name: String,
    pub category: Option<String>,
    pub matchers: usize,
}

/// Lista sygnatur (wbudowanych i z `[http] signatures_file` serwera).
#[utoipa::path(get, path = "/api/v1/signatures", tag = "sygnatury", responses((status = 200, body = [SignatureView])))]
pub async fn list_signatures(
    State(state): State<AppState>,
) -> Result<Json<Vec<SignatureView>>, ApiError> {
    let signatures = load_signatures(state.scan_service()?.settings())?;
    Ok(Json(
        signatures
            .summaries()
            .into_iter()
            .map(|(name, category, matchers)| SignatureView {
                name,
                category,
                matchers,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SignatureTestRequest {
    /// Nazwa sygnatury; `*` = wszystkie.
    pub signature: String,
    /// Adres usługi z IP hosta, np. `http://10.0.0.5:80/` (host w `[scope]`).
    pub url: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvidenceView {
    pub description: String,
    pub weight: u8,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionView {
    pub technology: String,
    pub version: Option<String>,
    pub confidence: u8,
    pub evidence: Vec<EvidenceView>,
}

impl From<Detection> for DetectionView {
    fn from(d: Detection) -> Self {
        DetectionView {
            technology: d.technology,
            version: d.version,
            confidence: d.confidence,
            evidence: d
                .evidence
                .into_iter()
                .map(|e| EvidenceView {
                    description: e.description,
                    weight: e.weight,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignatureTestResponse {
    pub status_code: u16,
    pub url: String,
    pub probes: usize,
    pub detections: Vec<DetectionView>,
}

/// Odpytuje usługę tak jak skan i zwraca pasujące detekcje. Wymaga `targets:write`
/// (wysyła żądania do sieci).
#[utoipa::path(post, path = "/api/v1/signatures/test", tag = "sygnatury", request_body = SignatureTestRequest,
    responses((status = 200, body = SignatureTestResponse), (status = 400, body = crate::ErrorBody)))]
pub async fn test_signature(
    State(state): State<AppState>,
    Json(input): Json<SignatureTestRequest>,
) -> Result<Json<SignatureTestResponse>, ApiError> {
    let settings = state.scan_service()?.settings();
    let ip = host_ip(&input.url).ok_or_else(|| {
        ApiError::BadRequest(format!("adres {} musi zawierać IP hosta", input.url))
    })?;
    if !is_in_scope(
        &single_address_network(ip),
        &settings.scope.allowed_networks,
    ) {
        return Err(ApiError::BadRequest(format!(
            "{ip} jest poza zakresem [scope]"
        )));
    }
    let analysis = build_analysis(settings, &[])?;
    let fetcher = Arc::new(build_fetcher(settings)?);
    let response = fetcher
        .fetch(&input.url, ip)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let mut info = to_http_info(&response);
    let body = String::from_utf8_lossy(&response.body);
    info.favicon = fetch_favicon(&fetcher, &info.url, ip, &body).await;
    let probes = probe_paths(
        &fetcher,
        &input.url,
        ip,
        &analysis.probe_paths,
        analysis.max_probes,
    )
    .await;
    let evidence = WebEvidence {
        info: &info,
        body: &body,
        probes: &probes,
        favicon_hash: info.favicon.as_ref().map(|f| f.mmh3),
    };
    let detections = analysis
        .analyze(&evidence, &[])
        .into_iter()
        .filter(|d| input.signature == "*" || d.technology.eq_ignore_ascii_case(&input.signature))
        .map(DetectionView::from)
        .collect();
    Ok(Json(SignatureTestResponse {
        status_code: info.status_code,
        url: info.url,
        probes: probes.len(),
        detections,
    }))
}

/// IP z adresu URL (`http://10.0.0.5:80/` → 10.0.0.5, `http://[::1]/` → ::1).
pub fn host_ip(url: &str) -> Option<std::net::IpAddr> {
    let rest = url.split_once("://")?.1;
    let host = rest.split('/').next()?;
    if let Some(v6) = host.strip_prefix('[') {
        return v6.split(']').next()?.parse().ok();
    }
    host.rsplit_once(':')
        .map_or(host, |(name, _)| name)
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_is_read_from_url() {
        assert_eq!(
            host_ip("http://10.0.0.5:80/").unwrap().to_string(),
            "10.0.0.5"
        );
        assert_eq!(host_ip("http://[::1]:8080/").unwrap().to_string(), "::1");
        assert_eq!(host_ip("http://example.com/"), None);
    }
}
