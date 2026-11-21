use askama::Template;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;
use dscan_api::auth::{CurrentUser, permissions};
use dscan_api::{ApiError, AppState};

use crate::menu_for;
use crate::session::WebUser;
use crate::views::TargetsSection;
use crate::views::{
    DashboardPage, ForbiddenPage, ProfileRow, ProfilesPage, ScanRow, ScansTable, TargetsPage,
    UserBar, UsersPage,
};

/// Ile ostatnich przebiegów pokazać na pulpicie.
const RECENT_SCANS: i64 = 20;

/// Renderuje szablon do odpowiedzi HTML.
pub fn render(template: &impl Template) -> Result<Html<String>, ApiError> {
    template
        .render()
        .map(Html)
        .map_err(|error| ApiError::Internal(error.to_string()))
}

fn user_bar(user: &CurrentUser) -> UserBar {
    UserBar {
        username: user.0.username.clone(),
        role: user.0.role.clone(),
    }
}

pub async fn dashboard(WebUser(user): WebUser) -> Result<Html<String>, ApiError> {
    render(&DashboardPage {
        menu: menu_for(&user, "/"),
        user: user_bar(&user),
    })
}

/// Fragment HTML z tabelą przebiegów — odświeżany przez htmx co kilka sekund.
pub async fn scans_partial(
    State(state): State<AppState>,
    WebUser(_user): WebUser,
) -> Result<Html<String>, ApiError> {
    let now = Utc::now();
    let runs = dscan_db::list_scan_runs(&state.db, RECENT_SCANS).await?;
    render(&ScansTable {
        scans: runs.iter().map(|run| ScanRow::from_run(run, now)).collect(),
    })
}

pub async fn targets(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Html<String>, ApiError> {
    let targets = dscan_db::list_targets(&state.db, &state.cipher, None).await?;
    let section = TargetsSection {
        targets,
        can_edit: user.has(permissions::TARGETS_WRITE),
        notice: None,
        report: None,
    };
    render(&TargetsPage {
        menu: menu_for(&user, "/targets"),
        user: user_bar(&user),
        section,
    })
}

pub async fn profiles(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Html<String>, ApiError> {
    let profiles = dscan_db::list_profiles(&state.db).await?;
    render(&ProfilesPage {
        menu: menu_for(&user, "/profiles"),
        user: user_bar(&user),
        profiles: profiles.iter().map(ProfileRow::from_profile).collect(),
    })
}

/// Lista użytkowników — tylko dla administratora.
pub async fn users(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Response, ApiError> {
    if !user.has(permissions::ADMIN) {
        let page = render(&ForbiddenPage {
            menu: menu_for(&user, ""),
            user: user_bar(&user),
        })?;
        return Ok((StatusCode::FORBIDDEN, page).into_response());
    }
    let users = dscan_db::list_users(&state.db).await?;
    Ok(render(&UsersPage {
        menu: menu_for(&user, "/users"),
        user: user_bar(&user),
        users,
    })?
    .into_response())
}
