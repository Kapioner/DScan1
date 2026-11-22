//! Edycja wyników w widoku hosta (F6): poprawka zapisana niezależnie od skanu (A6),
//! niedostępna dla roli „odczyt”.

use std::net::IpAddr;

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};
use dscan_core::models::{OverrideField, Protocol};
use dscan_db::OverrideTarget;
use serde::Deserialize;

use crate::session::WebUser;

/// Formularz poprawki (F6): pusta wartość albo „przywróć” usuwa poprawkę.
#[derive(Debug, Deserialize)]
pub struct EditForm {
    pub run: i64,
    pub field: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub reset: String,
}

pub async fn edit_result(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(ip): Path<IpAddr>,
    Form(form): Form<EditForm>,
) -> Result<Response, ApiError> {
    // Rola „odczyt” nie edytuje (sprawdzamy także po stronie serwera, nie tylko ukrywamy formularz).
    user.require(permissions::RESULTS_WRITE)?;
    let field = OverrideField::parse(&form.field)
        .ok_or_else(|| ApiError::BadRequest("nieznane pole".into()))?;
    let port: Option<u16> = form.port.trim().parse().ok();
    if field.is_service_field() != port.is_some() {
        return Err(ApiError::BadRequest(
            "pole usługi wymaga portu, pole hosta — bez portu".into(),
        ));
    }
    let protocol = port.map(|_| {
        if form.protocol == "udp" {
            Protocol::Udp
        } else {
            Protocol::Tcp
        }
    });
    let target = OverrideTarget { ip, port, protocol };
    let value = form.value.trim();
    if !form.reset.is_empty() || value.is_empty() {
        dscan_db::delete_override(&state.db, target, field).await?;
    } else {
        if value.chars().count() > 500 {
            return Err(ApiError::BadRequest(
                "wartość może mieć najwyżej 500 znaków".into(),
            ));
        }
        dscan_db::set_override(
            &state.db,
            &state.cipher,
            target,
            field,
            value,
            Some(user.0.id),
        )
        .await?;
    }
    let action = if !form.reset.is_empty() || value.is_empty() {
        "delete"
    } else {
        "set"
    };
    let address = format!("{ip}:{} {}", form.port, field.as_str());
    dscan_api::audit::record(&state, &user, action, "override", ip, &address).await;
    Ok(Redirect::to(&format!("/hosts/{ip}?run={}", form.run)).into_response())
}
