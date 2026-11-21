use axum::Json;
use utoipa::OpenApi;

use crate::ErrorBody;
use crate::auth::handlers::{LoginRequest, LoginResponse, UserView};
use crate::routes::health::{DatabaseStatus, HealthResponse};
use crate::routes::profiles::{ProfileInput, ProfileView, WindowDto};
use crate::routes::scans::ScanRunView;
use crate::routes::targets::{GroupView, NewTarget, TargetChanges, TargetView};

/// Opis API w formacie OpenAPI 3, generowany z adnotacji `#[utoipa::path]` przy handlerach.
/// Endpointy poza `health` i `auth/login` wymagają sesji (ciasteczko `dscan_session`
/// albo nagłówek `Authorization: Bearer <token>`).
#[derive(OpenApi)]
#[openapi(
    info(title = "DScan API", description = "API narzędzia DScan (Defect Scan)."),
    paths(
        crate::routes::health::health,
        crate::auth::handlers::login,
        crate::auth::handlers::logout,
        crate::auth::handlers::me,
        crate::routes::targets::list_targets,
        crate::routes::targets::create_target,
        crate::routes::targets::get_target,
        crate::routes::targets::update_target,
        crate::routes::targets::delete_target,
        crate::routes::targets::list_groups,
        crate::routes::profiles::list_profiles,
        crate::routes::profiles::create_profile,
        crate::routes::profiles::get_profile,
        crate::routes::profiles::update_profile,
        crate::routes::profiles::delete_profile,
        crate::routes::scans::list_scans,
        crate::routes::scans::get_scan
    ),
    components(schemas(
        HealthResponse, DatabaseStatus, ErrorBody, ScanRunView, LoginRequest, LoginResponse, UserView,
        TargetView, NewTarget, TargetChanges, GroupView, ProfileInput, ProfileView, WindowDto
    )),
    tags(
        (name = "system", description = "Stan usługi"),
        (name = "uwierzytelnianie", description = "Logowanie i sesje"),
        (name = "cele", description = "Cele i grupy celów"),
        (name = "profile", description = "Profile skanów: tryb, porty, okna czasowe, częstotliwość"),
        (name = "skany", description = "Przebiegi skanów: postęp, czas, prognoza")
    )
)]
pub struct ApiDoc;

/// `GET /api/openapi.json` — opis API do wczytania np. w Swagger Editor lub Postmanie.
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
