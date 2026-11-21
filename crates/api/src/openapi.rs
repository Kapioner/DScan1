use axum::Json;
use utoipa::OpenApi;

use crate::ErrorBody;
use crate::routes::health::{DatabaseStatus, HealthResponse};
use crate::routes::scans::ScanRunView;

/// Opis API w formacie OpenAPI 3, generowany z adnotacji `#[utoipa::path]` przy handlerach.
#[derive(OpenApi)]
#[openapi(
    info(title = "DScan API", description = "API narzędzia DScan (Defect Scan)."),
    paths(
        crate::routes::health::health,
        crate::routes::scans::list_scans,
        crate::routes::scans::get_scan
    ),
    components(schemas(HealthResponse, DatabaseStatus, ErrorBody, ScanRunView)),
    tags(
        (name = "system", description = "Stan usługi"),
        (name = "skany", description = "Przebiegi skanów: postęp, czas, prognoza")
    )
)]
pub struct ApiDoc;

/// `GET /api/openapi.json` — opis API do wczytania np. w Swagger Editor lub Postmanie.
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
