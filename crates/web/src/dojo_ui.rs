//! Wysyłka zaznaczonych obserwacji z widoku hosta do DefectDojo (I5).

use std::net::IpAddr;

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState};

use crate::session::WebUser;

/// Pola formularza: `run` i powtarzane `item=PORT/PROTOKÓŁ=Technologia`.
pub fn parse_items(body: &str) -> (Option<i64>, Vec<(u16, String, String)>) {
    let mut run = None;
    let mut items = Vec::new();
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = crate::admin::decode(value);
        match key {
            "run" => run = value.parse().ok(),
            "item" => {
                let parsed = value.split_once('=').and_then(|(address, technology)| {
                    let (port, protocol) = address.split_once('/')?;
                    Some((
                        port.parse().ok()?,
                        protocol.to_string(),
                        technology.to_string(),
                    ))
                });
                items.extend(parsed);
            }
            _ => {}
        }
    }
    (run, items)
}

pub async fn send_to_dojo(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(ip): Path<IpAddr>,
    body: String,
) -> Result<Response, ApiError> {
    user.require(permissions::RESULTS_WRITE)?;
    let (run, items) = parse_items(&body);
    let run = run.ok_or_else(|| ApiError::BadRequest("brak numeru przebiegu".into()))?;
    let back = |message: &str| {
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
        Redirect::to(&format!("/hosts/{ip}?run={run}&msg={encoded}")).into_response()
    };
    if items.is_empty() {
        return Ok(back("Nie zaznaczono żadnej obserwacji."));
    }
    let Some(client) = state.defectdojo.clone() else {
        return Ok(back("DefectDojo nie jest skonfigurowane."));
    };
    let refs: Vec<dscan_api::ObservationRef> = items
        .into_iter()
        .map(|(port, protocol, technology)| dscan_api::ObservationRef {
            ip: ip.to_string(),
            port,
            protocol,
            technology,
        })
        .collect();
    let observations = dscan_api::defectdojo_observations(&state, run, &refs).await?;
    let message = match client.export_findings(run, &observations).await {
        Ok(result) => {
            let details = format!("{} obserwacji z {ip}", observations.len());
            dscan_api::audit::record(&state, &user, "export", "defectdojo", run, &details).await;
            format!(
                "Wysłano {} obserwacji do DefectDojo (test {:?}).",
                observations.len(),
                result.test
            )
        }
        Err(error) => error.to_string(),
    };
    Ok(back(&message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_from_form() {
        let (run, items) =
            parse_items("run=7&item=8080%2Ftcp%3DJenkins&item=443%2Ftcp%3DPanel+administracyjny");
        assert_eq!(run, Some(7));
        assert_eq!(
            items[1],
            (443, "tcp".into(), "Panel administracyjny".into())
        );
    }
}
