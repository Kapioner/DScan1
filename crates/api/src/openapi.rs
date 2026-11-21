use axum::Json;
use utoipa::OpenApi;

use crate::ErrorBody;
use crate::routes::health::{DatabaseStatus, HealthResponse};

/// Opis API w formacie OpenAPI 3, generowany z adnotacji `#[utoipa::path]` przy handlerach.
#[derive(OpenApi)]
#[openapi(
    info(title = "DScan API", description = "API narzędzia DScan (Defect Scan)."),
    paths(crate::routes::health::health),
    components(schemas(HealthResponse, DatabaseStatus, ErrorBody)),
    tags((name = "system", description = "Stan usługi"))
)]
pub struct ApiDoc;

/// `GET /api/openapi.json` — opis API do wczytania np. w Swagger Editor lub Postmanie.
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
