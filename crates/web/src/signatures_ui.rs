//! Edytor sygnatur (F8): lista wszystkich sygnatur, dodawanie i edycja własnych (YAML)
//! oraz test na wybranym hoście przed zapisaniem.

use askama::Template;
use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_engine::signature_test::test_signature_on;
use dscan_fingerprint::signatures::SignatureSet;
use serde::Deserialize;

use crate::pages::{render, user_bar};
use crate::session::WebUser;
use crate::views::UserBar;
use crate::{MenuItem, menu_for};

/// Przykład dla pustego edytora.
pub const EXAMPLE_YAML: &str = "name: Moja aplikacja\ncategory: panel-admina\ncondition: any\nmatchers:\n  - { type: body, pattern: 'Moja aplikacja', weight: 60 }\n  - { type: header, name: X-App, weight: 40 }\n";

pub struct SignatureRow {
    pub name: String,
    pub category: String,
    pub matchers: usize,
    /// `Some(id)` dla własnych (do edycji).
    pub custom_id: Option<i64>,
    pub enabled: bool,
}

#[derive(Template)]
#[template(path = "signatures.html")]
pub struct SignaturesPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub rows: Vec<SignatureRow>,
    pub can_edit: bool,
    pub editing_id: Option<i64>,
    pub yaml: String,
    pub enabled: bool,
    pub message: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct EditQuery {
    pub edit: Option<i64>,
    pub msg: Option<String>,
}

pub async fn signatures_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(query): Query<EditQuery>,
) -> Result<Html<String>, ApiError> {
    let settings = state.scan_service()?.settings();
    let custom = dscan_db::list_custom_signatures(&state.db).await?;
    let mut rows: Vec<SignatureRow> = dscan_engine::load_signatures(settings)?
        .summaries()
        .into_iter()
        .filter(|(name, ..)| !custom.iter().any(|c| &c.name == name))
        .map(|(name, category, matchers)| SignatureRow {
            name,
            category: category.unwrap_or_default(),
            matchers,
            custom_id: None,
            enabled: true,
        })
        .collect();
    rows.extend(custom.iter().map(|c| {
        SignatureRow {
            name: c.name.clone(),
            category: c.category.clone().unwrap_or_default(),
            matchers: SignatureSet::from_single_yaml(&c.definition_yaml)
                .ok()
                .and_then(|s| s.summaries().first().map(|x| x.2))
                .unwrap_or(0),
            custom_id: Some(c.id),
            enabled: c.enabled,
        }
    }));
    let editing = query.edit.and_then(|id| custom.iter().find(|c| c.id == id));
    render(&SignaturesPage {
        menu: menu_for(&user, "/signatures"),
        user: user_bar(&user),
        rows,
        can_edit: user.has(permissions::TARGETS_WRITE),
        editing_id: editing.map(|c| c.id),
        yaml: editing.map_or(EXAMPLE_YAML.to_string(), |c| c.definition_yaml.clone()),
        enabled: editing.is_none_or(|c| c.enabled),
        message: query.msg,
    })
}

#[derive(Debug, Deserialize)]
pub struct SignatureForm {
    #[serde(default)]
    pub id: String,
    pub yaml: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub enabled: String,
}

#[derive(Template)]
#[template(path = "signature_test.html")]
pub struct TestResultPartial {
    pub error: Option<String>,
    pub summary: String,
    pub detections: Vec<(String, u8, String)>,
}

/// Test sygnatury z formularza (htmx) — nic nie zapisuje.
pub async fn test_signature(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<SignatureForm>,
) -> Result<Html<String>, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let partial = match SignatureSet::from_single_yaml(&form.yaml) {
        Err(error) => TestResultPartial {
            error: Some(error.to_string()),
            summary: String::new(),
            detections: Vec::new(),
        },
        Ok(set) => match test_signature_on(
            state.scan_service()?.settings(),
            Some(set),
            "*",
            form.url.trim(),
        )
        .await
        {
            Err(error) => TestResultPartial {
                error: Some(error.to_string()),
                summary: String::new(),
                detections: Vec::new(),
            },
            Ok(result) => TestResultPartial {
                error: None,
                summary: format!(
                    "HTTP {} {} (sondy: {})",
                    result.info.status_code, result.info.url, result.probes
                ),
                detections: result
                    .detections
                    .iter()
                    .map(|d| {
                        let evidence = d
                            .evidence
                            .iter()
                            .map(|e| format!("{} (+{})", e.description, e.weight))
                            .collect::<Vec<_>>();
                        (d.technology.clone(), d.confidence, evidence.join("; "))
                    })
                    .collect(),
            },
        },
    };
    render(&partial)
}

fn back(message: &str) -> Response {
    let encoded: String = message
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    Redirect::to(&format!("/signatures?msg={encoded}")).into_response()
}

pub async fn save_signature(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<SignatureForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let input = dscan_api::CustomSignatureInput {
        id: form.id.parse().ok(),
        yaml: form.yaml,
        enabled: !form.enabled.is_empty(),
    };
    match dscan_api::save_custom_signature(&state, &input).await {
        Ok(id) => {
            dscan_api::audit::record(&state, &user, "save", "signature", id, "").await;
            Ok(back("Zapisano sygnaturę — działa w kolejnych skanach."))
        }
        Err(ApiError::BadRequest(message) | ApiError::Conflict(message)) => Ok(back(&message)),
        Err(other) => Err(other),
    }
}

pub async fn delete_signature(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    if dscan_db::delete_custom_signature(&state.db, id).await? {
        dscan_engine::custom_signatures::refresh_custom_signatures(&state.db).await?;
        dscan_api::audit::record(&state, &user, "delete", "signature", id, "").await;
    }
    Ok(back("Usunięto sygnaturę."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_is_valid() {
        assert!(SignatureSet::from_single_yaml(EXAMPLE_YAML).is_ok());
    }
}
