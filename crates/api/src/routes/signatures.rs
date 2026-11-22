//! Sygnatury technologii przez API (C5: `dscan sig` jako klient API).

use axum::Json;
use axum::extract::State;
use dscan_core::models::Detection;
use dscan_engine::load_signatures;
use dscan_engine::signature_test::test_signature_on;
use dscan_fingerprint::signatures::SignatureSet;
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
    /// Sygnatura z edytora do sprawdzenia przed zapisem (F8).
    pub yaml: Option<String>,
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

/// Odpytuje usługę tak jak skan i zwraca pasujące detekcje. Z polem `yaml` testuje
/// sygnaturę z edytora przed zapisem (F8). Wymaga `targets:write` (wysyła żądania do sieci).
#[utoipa::path(post, path = "/api/v1/signatures/test", tag = "sygnatury", request_body = SignatureTestRequest,
    responses((status = 200, body = SignatureTestResponse), (status = 400, body = crate::ErrorBody)))]
pub async fn test_signature(
    State(state): State<AppState>,
    Json(input): Json<SignatureTestRequest>,
) -> Result<Json<SignatureTestResponse>, ApiError> {
    let settings = state.scan_service()?.settings();
    let candidate = match input.yaml.as_deref() {
        Some(yaml) => Some(
            SignatureSet::from_single_yaml(yaml)
                .map_err(|e| ApiError::BadRequest(e.to_string()))?,
        ),
        None => None,
    };
    let result = test_signature_on(settings, candidate, &input.signature, &input.url).await?;
    Ok(Json(SignatureTestResponse {
        status_code: result.info.status_code,
        url: result.info.url,
        probes: result.probes,
        detections: result
            .detections
            .into_iter()
            .map(DetectionView::from)
            .collect(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CustomSignatureView {
    pub id: i64,
    pub name: String,
    pub category: Option<String>,
    pub yaml: String,
    pub enabled: bool,
}

/// Własne sygnatury z edytora.
#[utoipa::path(get, path = "/api/v1/signatures/custom", tag = "sygnatury", responses((status = 200, body = [CustomSignatureView])))]
pub async fn list_custom(
    State(state): State<AppState>,
) -> Result<Json<Vec<CustomSignatureView>>, ApiError> {
    let list = dscan_db::list_custom_signatures(&state.db).await?;
    Ok(Json(
        list.into_iter()
            .map(|s| CustomSignatureView {
                id: s.id,
                name: s.name,
                category: s.category,
                yaml: s.definition_yaml,
                enabled: s.enabled,
            })
            .collect(),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CustomSignatureInput {
    /// `None` = nowa sygnatura.
    pub id: Option<i64>,
    /// YAML jednej sygnatury (`name`, `category`, `condition`, `matchers`, `version`).
    pub yaml: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
}

fn enabled() -> bool {
    true
}

/// Sprawdza YAML i zapisuje sygnaturę; nazwa i kategoria pochodzą z definicji.
pub async fn save_signature(
    state: &AppState,
    input: &CustomSignatureInput,
) -> Result<i64, ApiError> {
    let set = SignatureSet::from_single_yaml(&input.yaml)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let (name, category, _) = set
        .summaries()
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::BadRequest("pusta sygnatura".into()))?;
    let id = dscan_db::save_custom_signature(
        &state.db,
        input.id,
        &name,
        category.as_deref(),
        &input.yaml,
        input.enabled,
    )
    .await?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "sygnatura „{name}” już istnieje albo nie ma takiego rekordu"
        ))
    })?;
    dscan_engine::custom_signatures::refresh_custom_signatures(&state.db).await?;
    Ok(id)
}

/// Dodaje lub zmienia własną sygnaturę (od razu działa w kolejnych skanach).
#[utoipa::path(post, path = "/api/v1/signatures/custom", tag = "sygnatury", request_body = CustomSignatureInput,
    responses((status = 200, body = i64), (status = 400, body = crate::ErrorBody), (status = 409, body = crate::ErrorBody)))]
pub async fn save_custom(
    State(state): State<AppState>,
    user: crate::auth::CurrentUser,
    Json(input): Json<CustomSignatureInput>,
) -> Result<Json<i64>, ApiError> {
    let id = save_signature(&state, &input).await?;
    crate::audit::record(&state, &user, "save", "signature", id, "").await;
    Ok(Json(id))
}

/// Usuwa własną sygnaturę.
#[utoipa::path(delete, path = "/api/v1/signatures/custom/{id}", tag = "sygnatury", params(("id" = i64, Path)),
    responses((status = 204), (status = 404, body = crate::ErrorBody)))]
pub async fn delete_custom(
    State(state): State<AppState>,
    user: crate::auth::CurrentUser,
    axum::extract::Path(id): axum::extract::Path<i64>,
) -> Result<axum::http::StatusCode, ApiError> {
    if !dscan_db::delete_custom_signature(&state.db, id).await? {
        return Err(ApiError::NotFound);
    }
    dscan_engine::custom_signatures::refresh_custom_signatures(&state.db).await?;
    crate::audit::record(&state, &user, "delete", "signature", id, "").await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
