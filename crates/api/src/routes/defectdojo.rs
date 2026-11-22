//! DefectDojo (I4, I5): import surowego XML nmap przebiegu i eksport wybranych obserwacji.

use axum::Json;
use axum::extract::State;
use dscan_integrations::defectdojo::{DefectDojoClient, ImportResult, Observation, merge_nmap_xml};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::CurrentUser;
use crate::{ApiError, AppState};

#[derive(Debug, Deserialize, ToSchema)]
pub struct DojoImportRequest {
    pub run_id: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DojoResponse {
    pub test_id: Option<i64>,
    pub engagement_id: Option<i64>,
    pub product_id: Option<i64>,
    /// Ile obserwacji wysłano (eksport) albo ile podgrup scalono (import).
    pub items: usize,
}

impl DojoResponse {
    fn new(result: ImportResult, items: usize) -> Self {
        DojoResponse {
            test_id: result.test,
            engagement_id: result.engagement_id,
            product_id: result.product_id,
            items,
        }
    }
}

fn client(state: &AppState) -> Result<&DefectDojoClient, ApiError> {
    state.defectdojo.as_deref().ok_or_else(|| {
        ApiError::Unavailable(
            "DefectDojo nie jest skonfigurowane ([defectdojo] enabled i DSCAN_DEFECTDOJO_TOKEN)"
                .into(),
        )
    })
}

/// Wysyła surowe wyniki nmap przebiegu do DefectDojo (parser „Nmap Scan”).
#[utoipa::path(post, path = "/api/v1/defectdojo/import", tag = "import", request_body = DojoImportRequest,
    responses((status = 200, body = DojoResponse), (status = 503, body = crate::ErrorBody)))]
pub async fn dojo_import(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<DojoImportRequest>,
) -> Result<Json<DojoResponse>, ApiError> {
    let client = client(&state)?;
    let response = import_run(&state, client, input.run_id).await?;
    crate::audit::record(
        &state,
        &user,
        "export",
        "defectdojo",
        input.run_id,
        "import XML nmap",
    )
    .await;
    Ok(Json(response))
}

/// Scala XML podgrup przebiegu i wysyła do DefectDojo.
pub async fn import_run(
    state: &AppState,
    client: &DefectDojoClient,
    run_id: i64,
) -> Result<DojoResponse, ApiError> {
    dscan_db::get_scan_run(&state.db, run_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let documents = dscan_db::run_raw_xml(&state.db, &state.cipher, run_id).await?;
    let xml = merge_nmap_xml(&documents).ok_or_else(|| {
        ApiError::BadRequest(format!("przebieg #{run_id} nie ma surowych wyników nmap"))
    })?;
    let result = client
        .import_nmap(run_id, xml)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(DojoResponse::new(result, documents.len()))
}

/// Obserwacja do wysłania: usługa i technologia (detekcja) w przebiegu.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ObservationRef {
    pub ip: String,
    pub port: u16,
    #[serde(default = "tcp")]
    pub protocol: String,
    pub technology: String,
}

fn tcp() -> String {
    "tcp".into()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DojoFindingsRequest {
    pub run_id: i64,
    pub items: Vec<ObservationRef>,
}

/// Buduje obserwacje z dowodami (dowody detekcji, kod i tytuł HTTP, nagłówki odpowiedzi).
pub async fn observations(
    state: &AppState,
    run_id: i64,
    items: &[ObservationRef],
) -> Result<Vec<Observation>, ApiError> {
    let hosts =
        dscan_db::load_run_hosts_with_certificates(&state.db, &state.cipher, run_id).await?;
    let mut result = Vec::new();
    for item in items {
        let service = hosts
            .iter()
            .filter(|h| h.ip.to_string() == item.ip)
            .flat_map(|h| &h.services)
            .find(|s| s.port == item.port && s.protocol.as_str() == item.protocol);
        let Some(service) = service else { continue };
        let Some(detection) = service
            .detections
            .iter()
            .find(|d| d.technology == item.technology)
        else {
            continue;
        };
        let mut evidence: Vec<String> = detection
            .evidence
            .iter()
            .map(|e| format!("{} (+{})", e.description, e.weight))
            .collect();
        if let Some(http) = &service.http {
            evidence.push(format!(
                "HTTP {} {}{}",
                http.status_code,
                http.url,
                http.title
                    .as_deref()
                    .map(|t| format!(" „{t}”"))
                    .unwrap_or_default()
            ));
            evidence.extend(
                http.headers
                    .iter()
                    .take(20)
                    .map(|h| format!("nagłówek {}: {}", h.name, redact_header(&h.name, &h.value))),
            );
        }
        let title = match &detection.version {
            Some(version) => format!("{} {version}", detection.technology),
            None => detection.technology.clone(),
        };
        result.push(Observation {
            ip: item.ip.clone(),
            port: item.port,
            protocol: item.protocol.clone(),
            title,
            confidence: detection.confidence,
            evidence,
            url: service.http.as_ref().map(|h| h.url.clone()),
        });
    }
    Ok(result)
}

/// Wartości nagłówków z sekretami (ciasteczka sesji, tokeny) nie wychodzą poza DScan —
/// zostaje nazwa ciasteczka i jego atrybuty, wartość jest zastępowana `***`.
pub fn redact_header(name: &str, value: &str) -> String {
    match name.to_ascii_lowercase().as_str() {
        "set-cookie" | "cookie" => value
            .split(';')
            .enumerate()
            .map(|(i, part)| match part.split_once('=') {
                Some((key, _)) if i == 0 || name.eq_ignore_ascii_case("cookie") => {
                    format!("{}=***", key.trim())
                }
                _ => part.trim().to_string(),
            })
            .collect::<Vec<_>>()
            .join("; "),
        "authorization" | "proxy-authorization" | "x-api-key" | "x-auth-token" | "x-csrf-token" => {
            "***".into()
        }
        _ => value.to_string(),
    }
}

/// Wysyła zaznaczone obserwacje jako findingi informacyjne z dowodami.
#[utoipa::path(post, path = "/api/v1/defectdojo/findings", tag = "import", request_body = DojoFindingsRequest,
    responses((status = 200, body = DojoResponse), (status = 400, body = crate::ErrorBody), (status = 503, body = crate::ErrorBody)))]
pub async fn dojo_findings(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<DojoFindingsRequest>,
) -> Result<Json<DojoResponse>, ApiError> {
    let client = client(&state)?;
    let list = observations(&state, input.run_id, &input.items).await?;
    if list.is_empty() {
        return Err(ApiError::BadRequest(
            "żadna z wybranych obserwacji nie istnieje w przebiegu".into(),
        ));
    }
    let result = client
        .export_findings(input.run_id, &list)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let details = format!("{} obserwacji", list.len());
    crate::audit::record(
        &state,
        &user,
        "export",
        "defectdojo",
        input.run_id,
        &details,
    )
    .await;
    Ok(Json(DojoResponse::new(result, list.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_redacted() {
        assert_eq!(
            redact_header("Set-Cookie", "PHPSESSID=35hg9r; path=/; HttpOnly"),
            "PHPSESSID=***; path=/; HttpOnly"
        );
        assert_eq!(redact_header("Authorization", "Bearer abc"), "***");
        assert_eq!(redact_header("Server", "Apache/2.4.25"), "Apache/2.4.25");
    }
}
