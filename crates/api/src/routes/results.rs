//! Wyniki przebiegu z nałożonymi ręcznymi poprawkami (A6) i detekcjami z dowodami (H8).

use std::net::IpAddr;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use dscan_core::models::{Host, OverrideField, Protocol, apply_overrides};
use dscan_db::OverrideTarget;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::{CurrentUser, permissions};
use crate::{ApiError, AppState};

const MAX_VALUE_CHARS: usize = 500;

/// Hosty przebiegu z usługami, informacjami HTTP i detekcjami. Pola poprawione ręcznie
/// są wymienione w `edited_fields` hosta lub usługi.
#[utoipa::path(get, path = "/api/v1/scans/{id}/hosts", tag = "wyniki", params(("id" = i64, Path)),
    responses((status = 200, description = "Lista hostów (model Host)"), (status = 404, body = crate::ErrorBody)))]
pub async fn run_hosts(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<Json<Vec<Host>>, ApiError> {
    user.require(permissions::READ)?;
    dscan_db::get_scan_run(&state.db, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let mut hosts = dscan_db::load_run_hosts(&state.db, id).await?;
    let overrides = dscan_db::list_overrides(&state.db, &state.cipher).await?;
    apply_overrides(&mut hosts, &overrides);
    Ok(Json(hosts))
}

/// Poprawka do zapisania. Pola hosta (`hostname`, `host_note`) bez portu; pola usługi
/// (`product`, `version`, `service_name`, `service_note`) z portem i protokołem.
#[derive(Debug, Deserialize, ToSchema)]
pub struct OverrideInput {
    pub ip: String,
    pub port: Option<u16>,
    /// `tcp` albo `udp`.
    pub protocol: Option<String>,
    pub field: String,
    pub value: String,
}

/// Adres poprawki do usunięcia (parametry zapytania).
#[derive(Debug, Deserialize, IntoParams)]
pub struct OverrideAddress {
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub field: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OverrideView {
    pub ip: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub field: String,
    pub value: String,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

/// Lista ręcznych poprawek.
#[utoipa::path(get, path = "/api/v1/overrides", tag = "wyniki", responses((status = 200, body = [OverrideView])))]
pub async fn list_overrides(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Vec<OverrideView>>, ApiError> {
    user.require(permissions::READ)?;
    let overrides = dscan_db::list_overrides(&state.db, &state.cipher).await?;
    Ok(Json(
        overrides
            .into_iter()
            .map(|item| OverrideView {
                ip: item.ip.to_string(),
                port: item.port,
                protocol: item.protocol.map(|p| p.as_str().to_string()),
                field: item.field.as_str().to_string(),
                value: item.value,
                updated_at: item.updated_at,
                updated_by: item.updated_by,
            })
            .collect(),
    ))
}

/// Zapisuje (albo zastępuje) ręczną poprawkę.
#[utoipa::path(put, path = "/api/v1/overrides", tag = "wyniki", request_body = OverrideInput,
    responses((status = 204), (status = 400, body = crate::ErrorBody), (status = 403, body = crate::ErrorBody)))]
pub async fn set_override(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(input): Json<OverrideInput>,
) -> Result<StatusCode, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    let (target, field) = validate_address(
        &input.ip,
        input.port,
        input.protocol.as_deref(),
        &input.field,
    )?;
    let value = validate_value(&input.value)?;
    dscan_db::set_override(
        &state.db,
        &state.cipher,
        target,
        field,
        &value,
        Some(user.0.id),
    )
    .await?;
    // Wartość poprawki bywa poufna — w dzienniku tylko adres i nazwa pola.
    let address = format!("{}:{:?} {}", input.ip, input.port, field.as_str());
    crate::audit::record(&state, &user, "set", "override", &input.ip, &address).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Usuwa ręczną poprawkę (znów widać wartość z ostatniego skanu).
#[utoipa::path(delete, path = "/api/v1/overrides", tag = "wyniki", params(OverrideAddress),
    responses((status = 204), (status = 404, body = crate::ErrorBody)))]
pub async fn delete_override(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(address): Query<OverrideAddress>,
) -> Result<StatusCode, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    let (target, field) = validate_address(
        &address.ip,
        address.port,
        address.protocol.as_deref(),
        &address.field,
    )?;
    if dscan_db::delete_override(&state.db, target, field).await? {
        let address = format!("{}:{:?} {}", address.ip, address.port, field.as_str());
        crate::audit::record(&state, &user, "delete", "override", &address, "").await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

/// Sprawdza adres i pole poprawki: pola usługi wymagają portu i protokołu, pola hosta — ich braku.
pub fn validate_address(
    ip: &str,
    port: Option<u16>,
    protocol: Option<&str>,
    field: &str,
) -> Result<(OverrideTarget, OverrideField), ApiError> {
    let bad = |message: &str| ApiError::BadRequest(message.to_string());
    let ip: IpAddr = ip.trim().parse().map_err(|_| bad("niepoprawny adres IP"))?;
    let field = OverrideField::parse(field).ok_or_else(|| {
        bad("nieznane pole (hostname, host_note, product, version, service_name, service_note)")
    })?;
    let protocol = match protocol {
        None => None,
        Some("tcp") => Some(Protocol::Tcp),
        Some("udp") => Some(Protocol::Udp),
        Some(_) => return Err(bad("protokół musi być tcp albo udp")),
    };
    match (field.is_service_field(), port, protocol) {
        (true, Some(_), Some(_)) | (false, None, None) => {
            Ok((OverrideTarget { ip, port, protocol }, field))
        }
        (true, _, _) => Err(bad("pole usługi wymaga portu i protokołu")),
        (false, _, _) => Err(bad("pole hosta nie może mieć portu ani protokołu")),
    }
}

fn validate_value(value: &str) -> Result<String, ApiError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_VALUE_CHARS {
        return Err(ApiError::BadRequest(format!(
            "wartość musi mieć od 1 do {MAX_VALUE_CHARS} znaków"
        )));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_fields_need_port_and_protocol() {
        assert!(validate_address("10.0.0.5", Some(80), Some("tcp"), "product").is_ok());
        assert!(validate_address("10.0.0.5", None, None, "product").is_err());
        assert!(validate_address("10.0.0.5", Some(80), None, "version").is_err());
    }

    #[test]
    fn host_fields_must_not_have_port() {
        assert!(validate_address("10.0.0.5", None, None, "hostname").is_ok());
        assert!(validate_address("10.0.0.5", Some(80), Some("tcp"), "host_note").is_err());
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        assert!(validate_address("nie-ip", None, None, "hostname").is_err());
        assert!(validate_address("10.0.0.5", None, None, "kolor").is_err());
        assert!(validate_address("10.0.0.5", Some(80), Some("icmp"), "product").is_err());
        assert!(validate_value("   ").is_err());
        assert!(validate_value(&"x".repeat(501)).is_err());
    }
}
