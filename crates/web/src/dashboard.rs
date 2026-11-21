//! Dashboard (F2): podsumowanie ostatniego przebiegu (znaleziska, usługi nowe/znikające/
//! zmienione, technologie), postęp i czas trwających skanów oraz formularz „Uruchom skan”
//! z wyborem profilu z `[profiles]` (C4). Fragmenty odświeża htmx.

use askama::Template;
use axum::Form;
use axum::extract::{Path, State};
use axum::response::Html;
use chrono::Utc;
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_engine::{Dashboard, EngineError, ScanRequest};
use serde::Deserialize;

use crate::pages::render;
use crate::session::WebUser;
use crate::views::{Notice, ScanRow};

/// Wiersz zmiany do wyświetlenia.
pub struct ChangeRow {
    pub mark: &'static str,
    pub address: String,
    pub label: String,
}

#[derive(Template)]
#[template(path = "overview.html")]
pub struct OverviewPartial {
    pub latest: Option<ScanRow>,
    pub active: Vec<ScanRow>,
    pub data: Dashboard,
    pub changes: Vec<ChangeRow>,
    pub appeared: usize,
    pub disappeared: usize,
    pub modified: usize,
}

impl OverviewPartial {
    pub fn new(data: Dashboard) -> Self {
        use dscan_core::models::ChangeKind;
        let now = Utc::now();
        let count = |kind: ChangeKind| data.changes.iter().filter(|c| c.kind == kind).count();
        let changes = data
            .changes
            .iter()
            .map(|change| ChangeRow {
                mark: match change.kind {
                    ChangeKind::Appeared => "+",
                    ChangeKind::Disappeared => "−",
                    ChangeKind::Modified => "~",
                },
                address: format!(
                    "{}:{}/{}",
                    change.key.ip,
                    change.key.port,
                    change.key.protocol.as_str()
                ),
                label: change.kind.label().to_string(),
            })
            .collect();
        OverviewPartial {
            latest: data.latest.as_ref().map(|run| ScanRow::from_run(run, now)),
            active: data
                .active
                .iter()
                .map(|run| ScanRow::from_run(run, now))
                .collect(),
            appeared: count(ChangeKind::Appeared),
            disappeared: count(ChangeKind::Disappeared),
            modified: count(ChangeKind::Modified),
            changes,
            data,
        }
    }
}

/// Fragment z kartami dashboardu (odświeżany co 10 s).
pub async fn overview_partial(
    State(state): State<AppState>,
    WebUser(_user): WebUser,
) -> Result<Html<String>, ApiError> {
    let data = dscan_engine::load_dashboard(&state.db, state.scan_service()?.settings()).await?;
    render(&OverviewPartial::new(data))
}

#[derive(Debug, Deserialize)]
pub struct ScanForm {
    pub targets: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub mode: String,
}

#[derive(Template)]
#[template(path = "notice.html")]
pub struct NoticePartial {
    pub notice: Notice,
}

/// Cele z pola formularza: oddzielone spacjami, przecinkami lub nowymi liniami.
pub fn split_targets(text: &str) -> Vec<String> {
    text.split(|c: char| c.is_whitespace() || c == ',')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn non_empty(text: String) -> Option<String> {
    let text = text.trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Uruchomienie skanu z formularza (wymaga `targets:write`).
pub async fn start_scan(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<ScanForm>,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return render(&NoticePartial {
            notice: Notice::error("Brak uprawnień do uruchamiania skanów."),
        });
    }
    let request = ScanRequest {
        targets: split_targets(&form.targets),
        profile: non_empty(form.profile),
        mode: non_empty(form.mode),
        requested_by: Some(user.0.id),
        ..ScanRequest::default()
    };
    let notice = match state.scan_service()?.start(request).await {
        Ok(started) => {
            let count = started.plan.address_count.to_string();
            dscan_api::audit::record(&state, &user, "start", "scan", started.run_id, &count).await;
            Notice::ok(format!(
                "Uruchomiono przebieg #{} ({} adresów). Postęp widać poniżej.",
                started.run_id, started.plan.address_count
            ))
        }
        Err(EngineError::Database(error)) => return Err(ApiError::Internal(error.to_string())),
        Err(EngineError::NoTargetsInScope(_)) => {
            Notice::error("Brak celów w dozwolonym zakresie [scope].")
        }
        Err(error) => Notice::error(error.to_string()),
    };
    render(&NoticePartial { notice })
}

/// Wstrzymanie albo wznowienie przebiegu z tabeli (S9).
pub async fn control_scan(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path((id, action)): Path<(i64, String)>,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return render(&NoticePartial {
            notice: Notice::error("Brak uprawnień."),
        });
    }
    let service = state.scan_service()?;
    let notice = match action.as_str() {
        "stop" if service.stop(id) => Notice::ok(format!("Wstrzymywanie przebiegu #{id}…")),
        "stop" => Notice::error(format!("Przebieg #{id} nie trwa w tym serwerze.")),
        "resume" => match service.resume(id, None).await {
            Ok(()) => Notice::ok(format!("Wznowiono przebieg #{id}.")),
            Err(error) => Notice::error(error.to_string()),
        },
        _ => return Err(ApiError::NotFound),
    };
    render(&NoticePartial { notice })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_split_on_spaces_commas_and_lines() {
        assert_eq!(
            split_targets("10.0.0.1, 10.0.0.0/30\nlab.local  "),
            vec!["10.0.0.1", "10.0.0.0/30", "lab.local"]
        );
        assert!(split_targets("  ").is_empty());
    }

    #[test]
    fn overview_renders_without_runs() {
        let html = OverviewPartial::new(Dashboard::default()).render().unwrap();
        assert!(html.contains("Brak zakończonych przebiegów"));
    }
}
