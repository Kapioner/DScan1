//! Lista i szczegóły hosta (F5).

use std::collections::HashMap;
use std::net::IpAddr;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::Html;
use chrono::Utc;
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_core::models::{HostStatus, ScanStatus, apply_overrides};
use dscan_integrations::{ExportFilter, filter_hosts};
use serde::Deserialize;

use crate::host_views::{
    ChangeEntry, FieldView, HostRow, ResponseEntry, SelectOption, host_fields, status_label,
};
use crate::pages::{render, user_bar};
use crate::service_view::ServiceView;
use crate::session::WebUser;
use crate::views::UserBar;
use crate::{MenuItem, menu_for};

/// Filtry listy (pola formularza — puste napisy = brak filtra).
#[derive(Debug, Default, Deserialize)]
pub struct HostFilter {
    #[serde(default)]
    pub run: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub technology: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub edited: String,
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

#[derive(Template)]
#[template(path = "hosts.html")]
pub struct HostsPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub runs: Vec<SelectOption>,
    pub statuses: Vec<SelectOption>,
    pub run: Option<i64>,
    pub filter: HostFilter,
    pub hosts: Vec<HostRow>,
}

/// Przebieg z parametru albo ostatni zakończony; lista przebiegów do wyboru.
async fn pick_run(
    state: &AppState,
    requested: Option<i64>,
) -> Result<(Option<i64>, Vec<(i64, String)>), ApiError> {
    let runs = dscan_db::list_scan_runs(&state.db, 100).await?;
    let completed: Vec<(i64, String)> = runs
        .iter()
        .filter(|r| r.status == ScanStatus::Completed)
        .map(|r| {
            (
                r.id,
                format!(
                    "#{} {} ({})",
                    r.id,
                    r.profile,
                    r.started_at.format("%Y-%m-%d %H:%M")
                ),
            )
        })
        .collect();
    let run = requested.or_else(|| completed.first().map(|(id, _)| *id));
    Ok((run, completed))
}

async fn presence_map(state: &AppState) -> Result<HashMap<IpAddr, HostStatus>, ApiError> {
    Ok(dscan_db::load_presence(&state.db)
        .await?
        .into_iter()
        .map(|p| (p.ip, p.status))
        .collect())
}

pub async fn hosts_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(filter): Query<HostFilter>,
) -> Result<Html<String>, ApiError> {
    let (run, runs) = pick_run(&state, filter.run.parse().ok()).await?;
    let mut rows = Vec::new();
    if let Some(run_id) = run {
        let mut hosts = dscan_db::load_run_hosts(&state.db, run_id).await?;
        apply_overrides(
            &mut hosts,
            &dscan_db::list_overrides(&state.db, &state.cipher).await?,
        );
        let export_filter = ExportFilter {
            port: filter.port.trim().parse().ok(),
            state: None,
            technology: non_empty(&filter.technology),
            only_edited: !filter.edited.is_empty(),
        };
        let presence = presence_map(&state).await?;
        let needle = filter.q.trim().to_lowercase();
        rows = filter_hosts(&hosts, &export_filter)
            .iter()
            .filter(|h| {
                needle.is_empty()
                    || h.ip.to_string().contains(&needle)
                    || h.hostnames
                        .iter()
                        .any(|n| n.to_lowercase().contains(&needle))
            })
            .map(|h| HostRow::new(h, &presence))
            .filter(|row| filter.status.is_empty() || row.status == filter.status)
            .collect();
    }
    let runs = runs
        .into_iter()
        .map(|(id, label)| SelectOption::new(id, label, Some(id) == run))
        .collect();
    let statuses = ["aktywny", "niestabilny", "nieaktywny"]
        .into_iter()
        .map(|s| SelectOption::new(s, s, filter.status == s))
        .collect();
    render(&HostsPage {
        menu: menu_for(&user, "/hosts"),
        user: user_bar(&user),
        runs,
        statuses,
        run,
        filter,
        hosts: rows,
    })
}

#[derive(Template)]
#[template(path = "host.html")]
pub struct HostPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub ip: String,
    pub run: i64,
    pub status: &'static str,
    pub fields: Vec<FieldView>,
    pub services: Vec<ServiceView>,
    pub changes: Vec<ChangeEntry>,
    pub history: Vec<ResponseEntry>,
    pub can_edit: bool,
}

#[derive(Debug, Deserialize)]
pub struct RunParam {
    #[serde(default)]
    pub run: String,
}

pub async fn host_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(ip): Path<IpAddr>,
    Query(param): Query<RunParam>,
) -> Result<Html<String>, ApiError> {
    let (run, _) = pick_run(&state, param.run.parse().ok()).await?;
    let run = run.ok_or(ApiError::NotFound)?;
    let mut hosts =
        dscan_db::load_run_hosts_with_certificates(&state.db, &state.cipher, run).await?;
    apply_overrides(
        &mut hosts,
        &dscan_db::list_overrides(&state.db, &state.cipher).await?,
    );
    let host = hosts
        .into_iter()
        .find(|h| h.ip == ip)
        .ok_or(ApiError::NotFound)?;
    let presence = presence_map(&state).await?;
    let now = Utc::now();
    render(&HostPage {
        menu: menu_for(&user, "/hosts"),
        user: user_bar(&user),
        ip: ip.to_string(),
        run,
        status: status_label(presence.get(&ip).copied()),
        fields: host_fields(&host),
        services: host
            .services
            .iter()
            .map(|s| ServiceView::new(s, now))
            .collect(),
        changes: dscan_db::changes_for_ip(&state.db, ip, 100)
            .await?
            .iter()
            .map(ChangeEntry::from)
            .collect(),
        history: dscan_db::response_history(&state.db, ip)
            .await?
            .into_iter()
            .map(|(run, ok)| ResponseEntry { run, ok })
            .collect(),
        can_edit: user.has(permissions::RESULTS_WRITE),
    })
}
