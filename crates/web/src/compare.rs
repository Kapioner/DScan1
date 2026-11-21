//! Porównanie dwóch przebiegów (F7): wybór przebiegów i tabela różnic z kolorami.

use std::collections::HashMap;

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Html;
use chrono::Utc;
use dscan_api::{ApiError, AppState};
use dscan_core::models::{Host, ServiceKey, compare_runs};
use serde::Deserialize;

use crate::host_views::{SelectOption, change_css};
use crate::pages::{render, user_bar};
use crate::session::WebUser;
use crate::views::UserBar;
use crate::{MenuItem, menu_for};

#[derive(Debug, Default, Deserialize)]
pub struct CompareQuery {
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub to: String,
}

pub struct DiffRow {
    pub css: &'static str,
    pub address: String,
    pub label: String,
    pub before: String,
    pub after: String,
}

#[derive(Template)]
#[template(path = "compare.html")]
pub struct ComparePage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub from_options: Vec<SelectOption>,
    pub to_options: Vec<SelectOption>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub rows: Vec<DiffRow>,
    pub counts: (usize, usize, usize),
}

/// Opis usługi do kolumn „przed”/„po”, np. `http nginx 1.24 · HTTP 200 „Panel”`.
pub fn describe_services(hosts: &[Host]) -> HashMap<ServiceKey, String> {
    hosts
        .iter()
        .flat_map(|host| {
            host.services.iter().map(move |s| {
                let parts: Vec<&str> = [
                    s.name.as_deref(),
                    s.product.as_deref(),
                    s.version.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect();
                let http = s
                    .http
                    .as_ref()
                    .map(|h| {
                        format!(
                            " · HTTP {}{}",
                            h.status_code,
                            h.title
                                .as_deref()
                                .map(|t| format!(" „{t}”"))
                                .unwrap_or_default()
                        )
                    })
                    .unwrap_or_default();
                (
                    ServiceKey {
                        ip: host.ip,
                        port: s.port,
                        protocol: s.protocol,
                    },
                    format!("{}{http}", parts.join(" ")),
                )
            })
        })
        .collect()
}

pub async fn compare_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(query): Query<CompareQuery>,
) -> Result<Html<String>, ApiError> {
    let runs: Vec<(i64, String)> = dscan_db::list_scan_runs(&state.db, 100)
        .await?
        .iter()
        .map(|r| {
            (
                r.id,
                format!(
                    "#{} {} · {} · {}",
                    r.id,
                    r.profile,
                    r.status.as_str(),
                    r.started_at.format("%Y-%m-%d %H:%M")
                ),
            )
        })
        .collect();
    let (from, to) = (query.from.parse::<i64>().ok(), query.to.parse::<i64>().ok());
    let mut rows = Vec::new();
    let mut counts = (0, 0, 0);
    if let (Some(a), Some(b)) = (from, to) {
        for id in [a, b] {
            dscan_db::get_scan_run(&state.db, id)
                .await?
                .ok_or(ApiError::NotFound)?;
        }
        let previous = dscan_db::run_fingerprints(&state.db, a).await?;
        let current = dscan_db::run_fingerprints(&state.db, b).await?;
        let before = describe_services(&dscan_db::load_run_hosts(&state.db, a).await?);
        let after = describe_services(&dscan_db::load_run_hosts(&state.db, b).await?);
        for change in compare_runs(&previous, &current, (a, b), Utc::now()) {
            match change.kind {
                dscan_core::models::ChangeKind::Appeared => counts.0 += 1,
                dscan_core::models::ChangeKind::Disappeared => counts.1 += 1,
                dscan_core::models::ChangeKind::Modified => counts.2 += 1,
            }
            rows.push(DiffRow {
                css: change_css(change.kind),
                address: format!(
                    "{}:{}/{}",
                    change.key.ip,
                    change.key.port,
                    change.key.protocol.as_str()
                ),
                label: change.kind.label().to_string(),
                before: before.get(&change.key).cloned().unwrap_or_default(),
                after: after.get(&change.key).cloned().unwrap_or_default(),
            });
        }
    }
    let options = |chosen: Option<i64>| -> Vec<SelectOption> {
        runs.iter()
            .map(|(id, label)| SelectOption::new(id, label.clone(), Some(*id) == chosen))
            .collect()
    };
    let (from_options, to_options) = (options(from), options(to));
    render(&ComparePage {
        menu: menu_for(&user, "/compare"),
        user: user_bar(&user),
        from_options,
        to_options,
        from,
        to,
        rows,
        counts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::{Protocol, Service, ServiceState};

    #[test]
    fn services_are_described() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        let mut service = Service::new(80, Protocol::Tcp, ServiceState::Open);
        service.name = Some("http".into());
        service.product = Some("nginx".into());
        host.services.push(service);
        let map = describe_services(&[host]);
        let key = ServiceKey {
            ip: "10.0.0.5".parse().unwrap(),
            port: 80,
            protocol: Protocol::Tcp,
        };
        assert_eq!(map[&key], "http nginx");
    }
}
