use askama::Template;
use axum::extract::State;
use axum::response::Html;
use chrono::Utc;
use dscan_api::auth::{CurrentUser, permissions};
use dscan_api::{ApiError, AppState};

use crate::menu_for;
use crate::session::WebUser;
use crate::views::TargetsSection;
use crate::views::{
    DashboardPage, ProfileRow, ProfilesPage, ScanRow, ScansTable, TargetsPage, UserBar,
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

pub fn user_bar(user: &CurrentUser) -> UserBar {
    UserBar {
        username: user.0.username.clone(),
        role: user.0.role.clone(),
    }
}

pub async fn dashboard(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Html<String>, ApiError> {
    let profiles = state
        .scans
        .as_ref()
        .map(|service| dscan_config::profile_names(service.settings()))
        .unwrap_or_default();
    render(&DashboardPage {
        menu: menu_for(&user, "/"),
        user: user_bar(&user),
        can_scan: user.has(permissions::TARGETS_WRITE) && state.scans.is_some(),
        profiles,
    })
}

/// Fragment HTML z tabelą przebiegów — odświeżany przez htmx co kilka sekund.
pub async fn scans_partial(
    State(state): State<AppState>,
    WebUser(user): WebUser,
) -> Result<Html<String>, ApiError> {
    let now = Utc::now();
    let runs = dscan_db::list_scan_runs(&state.db, RECENT_SCANS).await?;
    render(&ScansTable {
        scans: runs.iter().map(|run| ScanRow::from_run(run, now)).collect(),
        can_control: user.has(permissions::TARGETS_WRITE) && state.scans.is_some(),
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

#[derive(Debug, Default, serde::Deserialize)]
pub struct MessageParam {
    pub msg: Option<String>,
}

pub async fn profiles(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    axum::extract::Query(param): axum::extract::Query<MessageParam>,
) -> Result<Html<String>, ApiError> {
    let profiles = dscan_db::list_profiles(&state.db).await?;
    let config_profiles = state
        .scans
        .as_ref()
        .map(|service| {
            service
                .settings()
                .profiles
                .iter()
                .map(|(name, p)| (name.clone(), describe_config_profile(p)))
                .collect()
        })
        .unwrap_or_default();
    render(&ProfilesPage {
        menu: menu_for(&user, "/profiles"),
        user: user_bar(&user),
        profiles: profiles.iter().map(ProfileRow::from_profile).collect(),
        can_edit: user.has(permissions::TARGETS_WRITE),
        message: param.msg,
        config_profiles,
    })
}

/// Krótki opis profilu z dscan.toml, np. `tryb services · porty 22, 80 · 50 pakietów/s`.
pub fn describe_config_profile(profile: &dscan_config::ScanProfileSettings) -> String {
    let mut parts = Vec::new();
    if let Some(mode) = &profile.mode {
        parts.push(format!("tryb {mode}"));
    }
    if let Some(ports) = &profile.ports {
        parts.push(format!("porty {}", ports.join(", ")));
    }
    if let Some(rate) = profile.max_rate {
        parts.push(format!("{rate} pakietów/s"));
    }
    if let Some(parallel) = profile.parallel {
        parts.push(format!("{parallel} procesów"));
    }
    if let Some(windows) = &profile.windows {
        let list: Vec<String> = windows
            .iter()
            .map(|w| format!("{}–{}", w.start, w.end))
            .collect();
        parts.push(format!("okna {}", list.join(", ")));
    }
    if parts.is_empty() {
        "ustawienia domyślne".into()
    } else {
        parts.join(" · ")
    }
}
