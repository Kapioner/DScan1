use axum::Json;
use utoipa::OpenApi;

use crate::ErrorBody;
use crate::auth::handlers::{LoginRequest, LoginResponse, UserView};
use crate::routes::dashboard::{DashboardView, FindingView, RunState, TechnologyCount};
use crate::routes::health::{DatabaseStatus, HealthResponse};
use crate::routes::imports::{
    ImportRequest, RejectedRow, ResultImportResponse, TargetImportResponse,
};
use crate::routes::profiles::{ProfileInput, ProfileView, WindowDto};
use crate::routes::results::{OverrideInput, OverrideView};
use crate::routes::scan_control::{
    ChangeView, RejectedTarget, StartScanRequest, StartScanResponse,
};
use crate::routes::scans::ScanRunView;
use crate::routes::signatures::{
    DetectionView, EvidenceView, SignatureTestRequest, SignatureTestResponse, SignatureView,
};
use crate::routes::targets::{GroupView, NewTarget, TargetChanges, TargetView};
use crate::routes::users::UserListItem;

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
        crate::routes::scans::get_scan,
        crate::routes::results::run_hosts,
        crate::routes::results::list_overrides,
        crate::routes::results::set_override,
        crate::routes::results::delete_override,
        crate::routes::users::list_users,
        crate::routes::scan_control::start_scan,
        crate::routes::scan_control::stop_scan,
        crate::routes::scan_control::resume_scan,
        crate::routes::scan_control::run_changes,
        crate::routes::scan_control::diff,
        crate::routes::scan_control::config_profiles,
        crate::routes::imports::import_targets_handler,
        crate::routes::imports::import_results_handler,
        crate::routes::exports::export,
        crate::routes::signatures::list_signatures,
        crate::routes::signatures::test_signature,
        crate::routes::signatures::list_custom,
        crate::routes::signatures::save_custom,
        crate::routes::signatures::delete_custom,
        crate::routes::dashboard::dashboard,
        crate::routes::search::search,
        crate::routes::tags::list_tags,
        crate::routes::tags::add_tag,
        crate::routes::tags::delete_tag,
        crate::routes::tags::run_clusters,
        crate::routes::availability::availability,
        crate::routes::accounts::list_accounts,
        crate::routes::accounts::create_user,
        crate::routes::accounts::update_user,
        crate::routes::accounts::set_password,
        crate::routes::accounts::list_roles,
        crate::routes::accounts::create_role,
        crate::routes::accounts::update_role,
        crate::routes::accounts::delete_role,
        crate::routes::audit_log::audit_log,
        crate::routes::defectdojo::dojo_import,
        crate::routes::defectdojo::dojo_findings
    ),
    components(schemas(
        HealthResponse, DatabaseStatus, ErrorBody, ScanRunView, LoginRequest, LoginResponse, UserView,
        TargetView, NewTarget, TargetChanges, GroupView, ProfileInput, ProfileView, WindowDto, OverrideInput, OverrideView, UserListItem,
        StartScanRequest, StartScanResponse, RejectedTarget, ChangeView, ImportRequest, TargetImportResponse,
        RejectedRow, ResultImportResponse, SignatureView, SignatureTestRequest, SignatureTestResponse,
        DetectionView, EvidenceView, crate::routes::signatures::CustomSignatureView, crate::routes::signatures::CustomSignatureInput, DashboardView, RunState, FindingView, TechnologyCount, crate::routes::dashboard::InterestView, crate::routes::search::SearchHit, crate::routes::tags::TagView, crate::routes::tags::NewTag, crate::routes::tags::ClusterView, crate::routes::availability::AvailabilityView, crate::routes::availability::HourView,
        crate::routes::accounts::UserDetailsView, crate::routes::accounts::RoleView, crate::routes::accounts::NewUser,
        crate::routes::accounts::UserChanges, crate::routes::accounts::NewPassword, crate::routes::accounts::RoleInput,
        crate::routes::accounts::Created, crate::routes::audit_log::AuditView, crate::routes::defectdojo::DojoImportRequest,
        crate::routes::defectdojo::DojoResponse, crate::routes::defectdojo::ObservationRef,
        crate::routes::defectdojo::DojoFindingsRequest
    )),
    tags(
        (name = "system", description = "Stan usługi"),
        (name = "uwierzytelnianie", description = "Logowanie i sesje"),
        (name = "cele", description = "Cele i grupy celów"),
        (name = "profile", description = "Profile skanów: tryb, porty, okna czasowe, częstotliwość"),
        (name = "skany", description = "Przebiegi skanów: postęp, czas, prognoza"),
        (name = "import", description = "Import celów i wyników skanów (nmap XML, JSON, CSV)"),
        (name = "eksport", description = "Eksport hostów, usług i zmian (JSON, CSV)"),
        (name = "sygnatury", description = "Sygnatury technologii i ich testowanie"),
        (name = "dashboard", description = "Znaleziska, zmiany, technologie, stan skanów"),
        (name = "użytkownicy", description = "Konta (tylko administracja)"),
        (name = "wyniki", description = "Hosty i usługi przebiegu, ręczne poprawki wyników")
    )
)]
pub struct ApiDoc;

/// `GET /api/openapi.json` — opis API do wczytania np. w Swagger Editor lub Postmanie.
pub async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}
