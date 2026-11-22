//! Klastry podobnych usług (M4) i tagi (F11): strona klastrów, tagowanie hosta, usługi
//! albo całego klastra.

use std::net::IpAddr;

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_core::models::ScanStatus;
use dscan_engine::clusters::{MAX_DISTANCE, ServiceCluster, service_clusters};
use serde::Deserialize;

use crate::pages::{render, user_bar};
use crate::session::WebUser;
use crate::views::UserBar;
use crate::{MenuItem, menu_for};

#[derive(Debug, Default, Deserialize)]
pub struct RunQuery {
    pub run: Option<i64>,
}

/// Przebieg z parametru albo ostatni zakończony.
pub async fn chosen_run(state: &AppState, run: Option<i64>) -> Result<Option<i64>, ApiError> {
    if run.is_some() {
        return Ok(run);
    }
    let runs = dscan_db::list_scan_runs(&state.db, 100).await?;
    Ok(runs
        .into_iter()
        .find(|r| r.status == ScanStatus::Completed)
        .map(|r| r.id))
}

/// Klastry przebiegu (co najmniej 2 usługi).
pub async fn run_clusters(state: &AppState, run: i64) -> Result<Vec<ServiceCluster>, ApiError> {
    let hosts = dscan_db::load_run_hosts(&state.db, run).await?;
    Ok(service_clusters(&hosts, MAX_DISTANCE, 2))
}

#[derive(Template)]
#[template(path = "clusters.html")]
pub struct ClustersPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub run: Option<i64>,
    pub clusters: Vec<ServiceCluster>,
    pub can_tag: bool,
}

pub async fn clusters_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(query): Query<RunQuery>,
) -> Result<Html<String>, ApiError> {
    let run = chosen_run(&state, query.run).await?;
    let clusters = match run {
        Some(run) => run_clusters(&state, run).await?,
        None => Vec::new(),
    };
    render(&ClustersPage {
        menu: menu_for(&user, "/clusters"),
        user: user_bar(&user),
        run,
        clusters,
        can_tag: user.has(permissions::RESULTS_WRITE),
    })
}

#[derive(Debug, Deserialize)]
pub struct ClusterTagForm {
    pub run: i64,
    pub cluster: usize,
    pub tag: String,
}

/// Taguje wszystkie usługi klastra.
pub async fn tag_cluster(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<ClusterTagForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    let tag = dscan_db::normalize_tag(&form.tag)
        .ok_or_else(|| ApiError::BadRequest("tag: 1–40 znaków".into()))?;
    let clusters = run_clusters(&state, form.run).await?;
    let cluster = clusters
        .iter()
        .find(|c| c.id == form.cluster)
        .ok_or(ApiError::NotFound)?;
    for member in &cluster.members {
        if let Ok(ip) = member.ip.parse::<IpAddr>() {
            dscan_db::add_tag(
                &state.db,
                ip,
                Some(member.port),
                Some(&member.protocol),
                &tag,
                Some(user.0.id),
            )
            .await?;
        }
    }
    let details = format!(
        "klaster {} ({} usług): {tag}",
        cluster.label,
        cluster.members.len()
    );
    dscan_api::audit::record(&state, &user, "tag", "cluster", form.cluster, &details).await;
    Ok(Redirect::to(&format!("/hosts?run={}&tag={tag}", form.run)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct TagForm {
    pub run: i64,
    pub tag: String,
    /// `""` = cały host, inaczej `PORT/PROTOKÓŁ`.
    #[serde(default)]
    pub service: String,
}

/// Dodaje tag hostowi albo usłudze (widok hosta).
pub async fn add_tag(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(ip): Path<IpAddr>,
    Form(form): Form<TagForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    let tag = dscan_db::normalize_tag(&form.tag)
        .ok_or_else(|| ApiError::BadRequest("tag: 1–40 znaków".into()))?;
    let (port, protocol) = match form.service.split_once('/') {
        Some((port, protocol)) => (port.parse().ok(), Some(protocol.to_string())),
        None => (None, None),
    };
    dscan_db::add_tag(
        &state.db,
        ip,
        port,
        protocol.as_deref(),
        &tag,
        Some(user.0.id),
    )
    .await?;
    dscan_api::audit::record(&state, &user, "tag", "host", ip, &tag).await;
    Ok(Redirect::to(&format!("/hosts/{ip}?run={}", form.run)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct DeleteTagForm {
    pub run: i64,
}

pub async fn delete_tag(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path((ip, id)): Path<(IpAddr, i64)>,
    Form(form): Form<DeleteTagForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    if dscan_db::delete_tag(&state.db, id).await? {
        dscan_api::audit::record(&state, &user, "untag", "host", ip, &id.to_string()).await;
    }
    Ok(Redirect::to(&format!("/hosts/{ip}?run={}", form.run)).into_response())
}
