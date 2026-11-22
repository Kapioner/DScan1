//! Konfiguracja skanu w UI (F4): profile z bazy — okno czasowe, częstotliwość, limit tempa,
//! porty — tworzenie, edycja i usuwanie; profile z `dscan.toml` tylko do podglądu.

use axum::Form;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use dscan_api::auth::permissions;
use dscan_api::{ApiError, AppState, ProfileInput, WindowDto, validate_profile};
use dscan_db::ProfileSaved;
use serde::Deserialize;

use crate::session::WebUser;

/// Pola formularza profilu (tekstowe, jak przychodzą z przeglądarki).
#[derive(Debug, Default, Deserialize)]
pub struct ProfileForm {
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub target_group: String,
    /// Porty oddzielone przecinkami, np. `22, 80, 8000-8100`.
    #[serde(default)]
    pub ports: String,
    /// Okna oddzielone przecinkami, np. `22:00-06:00, 12:00-13:00`.
    #[serde(default)]
    pub windows: String,
    #[serde(default)]
    pub frequency_minutes: String,
    #[serde(default)]
    pub max_rate: String,
    #[serde(default)]
    pub enabled: String,
}

/// Zamienia pola formularza na dane API (walidację robi `validate_profile`).
pub fn to_input(form: ProfileForm) -> Result<ProfileInput, String> {
    let list = |text: &str| -> Vec<String> {
        text.split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };
    let windows = list(&form.windows)
        .into_iter()
        .map(|window| {
            let (start, end) = window
                .split_once('-')
                .ok_or_else(|| format!("okno „{window}” musi mieć postać GG:MM-GG:MM"))?;
            Ok(WindowDto {
                start: start.trim().to_string(),
                end: end.trim().to_string(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let number = |text: &str, label: &str| -> Result<Option<i32>, String> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        text.parse()
            .map(Some)
            .map_err(|_| format!("{label}: „{text}” nie jest liczbą"))
    };
    let group = form.target_group.trim();
    Ok(ProfileInput {
        name: form.name,
        mode: form.mode,
        target_group: (!group.is_empty()).then(|| group.to_string()),
        ports: list(&form.ports),
        windows,
        frequency_minutes: number(&form.frequency_minutes, "częstotliwość")?,
        enabled: !form.enabled.is_empty(),
        max_rate: number(&form.max_rate, "limit tempa")?,
    })
}

/// Po zapisie wracamy na listę z komunikatem w adresie (`?msg=`).
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
    Redirect::to(&format!("/profiles?msg={encoded}")).into_response()
}

async fn save(
    state: &AppState,
    user: &dscan_api::auth::CurrentUser,
    id: Option<i64>,
    form: ProfileForm,
) -> Result<Response, ApiError> {
    let input = match to_input(form) {
        Ok(input) => input,
        Err(message) => return Ok(back(&message)),
    };
    let data = match validate_profile(input) {
        Ok(data) => data,
        Err(ApiError::BadRequest(message)) => return Ok(back(&message)),
        Err(other) => return Err(other),
    };
    let saved = match id {
        Some(id) => dscan_db::update_profile(&state.db, id, &data).await?,
        None => dscan_db::create_profile(&state.db, &data).await?,
    };
    if let ProfileSaved::Saved(profile) = &saved {
        let action = if id.is_some() { "update" } else { "create" };
        dscan_api::audit::record(
            state,
            user,
            action,
            "profile",
            profile.id,
            &profile.data.name,
        )
        .await;
    }
    Ok(back(match saved {
        ProfileSaved::Saved(_) => "Zapisano profil.",
        ProfileSaved::NameTaken => "Profil o tej nazwie już istnieje.",
        ProfileSaved::NotFound => "Nie ma takiego profilu.",
    }))
}

pub async fn create_profile(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<ProfileForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    save(&state, &user, None, form).await
}

pub async fn update_profile(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
    Form(form): Form<ProfileForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    save(&state, &user, Some(id), form).await
}

pub async fn delete_profile(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    user.require(permissions::TARGETS_WRITE)?;
    let deleted = dscan_db::delete_profile(&state.db, id).await?;
    if deleted {
        dscan_api::audit::record(&state, &user, "delete", "profile", id, "").await;
    }
    Ok(back(if deleted {
        "Usunięto profil."
    } else {
        "Nie ma takiego profilu."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_fields_are_parsed() {
        let form = ProfileForm {
            name: "nocny".into(),
            mode: "services".into(),
            ports: "22, 80-90,".into(),
            windows: "22:00-06:00, 12:00 - 13:00".into(),
            frequency_minutes: "60".into(),
            max_rate: " ".into(),
            enabled: "on".into(),
            ..ProfileForm::default()
        };
        let input = to_input(form).unwrap();
        assert_eq!(input.ports, vec!["22", "80-90"]);
        assert_eq!(input.windows.len(), 2);
        assert_eq!(input.windows[1].start, "12:00");
        assert_eq!(
            (input.frequency_minutes, input.max_rate, input.enabled),
            (Some(60), None, true)
        );
        assert!(validate_profile(input).is_ok());
    }

    #[test]
    fn bad_values_are_reported() {
        let bad_window = ProfileForm {
            windows: "22:00".into(),
            ..ProfileForm::default()
        };
        assert!(to_input(bad_window).unwrap_err().contains("GG:MM-GG:MM"));
        let bad_rate = ProfileForm {
            max_rate: "dużo".into(),
            ..ProfileForm::default()
        };
        assert!(to_input(bad_rate).unwrap_err().contains("limit tempa"));
    }
}
