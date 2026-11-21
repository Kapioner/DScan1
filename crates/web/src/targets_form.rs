//! Formularz celów (zadanie F3): wpis ręczny, wgranie CSV/JSON z podglądem odrzuconych
//! wierszy i usuwanie. Odpowiedzi to fragmenty HTML podmieniane przez htmx.

use axum::Form;
use axum::extract::{Multipart, Path, State};
use axum::response::Html;
use dscan_api::auth::{CurrentUser, permissions};
use dscan_api::{ApiError, AppState, clean_group, clean_note};
use dscan_core::models::Target;
use dscan_integrations::{detect_format, import_targets};
use dscan_scanner::targets::parse_target;
use serde::Deserialize;

use crate::pages::render;
use crate::session::WebUser;
use crate::views::{ImportReportView, Notice, TargetsSection};

#[derive(Debug, Deserialize)]
pub struct TargetForm {
    pub target: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub note: String,
}

/// Odświeżona sekcja celów z komunikatem i (opcjonalnie) raportem importu.
async fn section(
    state: &AppState,
    user: &CurrentUser,
    notice: Option<Notice>,
    report: Option<ImportReportView>,
) -> Result<Html<String>, ApiError> {
    let targets = dscan_db::list_targets(&state.db, &state.cipher, None).await?;
    render(&TargetsSection {
        targets,
        can_edit: user.has(permissions::TARGETS_WRITE),
        notice,
        report,
    })
}

/// Bez prawa zapisu — sekcja z komunikatem zamiast zmiany.
async fn forbidden(state: &AppState, user: &CurrentUser) -> Result<Html<String>, ApiError> {
    section(
        state,
        user,
        Some(Notice::error("Brak uprawnień do zmiany celów.")),
        None,
    )
    .await
}

/// Ręczne dodanie celu.
pub async fn add_target(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Form(form): Form<TargetForm>,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return forbidden(&state, &user).await;
    }
    let notice = match build_target(form) {
        Err(message) => Notice::error(message),
        Ok(target) => match dscan_db::create_target(&state.db, &state.cipher, &target).await? {
            Some(created) => Notice::ok(format!("Dodano cel {}.", created.value)),
            None => Notice::error(format!("Cel {} już istnieje.", target.kind)),
        },
    };
    section(&state, &user, Some(notice), None).await
}

/// Waliduje pola formularza tak samo jak API.
pub fn build_target(form: TargetForm) -> Result<Target, String> {
    let kind = parse_target(&form.target).map_err(|error| error.to_string())?;
    let group = clean_group(Some(form.group))
        .map_err(|_| "Nazwa grupy jest za długa (max 64 znaki).".to_string())?;
    let note = clean_note(Some(form.note))
        .map_err(|_| "Notatka jest za długa (max 2000 znaków).".to_string())?;
    Ok(Target { kind, group, note })
}

/// Wgranie pliku CSV/JSON: raport odrzuconych wierszy, zapis poprawnych (chyba że „tylko sprawdź”).
pub async fn import_file(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    multipart: Multipart,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return forbidden(&state, &user).await;
    }
    let upload = match read_upload(multipart).await {
        Ok(upload) => upload,
        Err(message) => return section(&state, &user, Some(Notice::error(message)), None).await,
    };
    let format = match detect_format(std::path::Path::new(&upload.file_name)) {
        Ok(format) => format,
        Err(error) => {
            return section(&state, &user, Some(Notice::error(error.to_string())), None).await;
        }
    };
    let import = match import_targets(&upload.content, format) {
        Ok(import) => import,
        Err(error) => {
            return section(&state, &user, Some(Notice::error(error.to_string())), None).await;
        }
    };

    let mut report = ImportReportView::new(&upload.file_name, &import, upload.dry_run);
    if !upload.dry_run {
        let summary = dscan_db::insert_targets(&state.db, &state.cipher, &import.accepted).await?;
        report.saved = Some((summary.inserted, summary.already_present));
    }
    section(&state, &user, None, Some(report)).await
}

/// Usunięcie celu.
pub async fn delete_target(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
) -> Result<Html<String>, ApiError> {
    if !user.has(permissions::TARGETS_WRITE) {
        return forbidden(&state, &user).await;
    }
    let notice = if dscan_db::delete_target(&state.db, id).await? {
        Notice::ok("Usunięto cel.")
    } else {
        Notice::error("Cel już nie istnieje.")
    };
    section(&state, &user, Some(notice), None).await
}

/// Zawartość formularza z plikiem.
struct Upload {
    file_name: String,
    content: String,
    dry_run: bool,
}

async fn read_upload(mut multipart: Multipart) -> Result<Upload, String> {
    let mut upload = Upload {
        file_name: String::new(),
        content: String::new(),
        dry_run: false,
    };
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| format!("Błąd przesyłania: {error}"))?
    {
        match field.name() {
            Some("file") => {
                upload.file_name = field.file_name().unwrap_or("").to_string();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|error| format!("Błąd przesyłania: {error}"))?;
                upload.content = String::from_utf8(bytes.to_vec())
                    .map_err(|_| "Plik musi być tekstem UTF-8.".to_string())?;
            }
            Some("dry_run") => upload.dry_run = true,
            _ => {}
        }
    }
    if upload.file_name.is_empty() {
        return Err("Wybierz plik CSV lub JSON.".into());
    }
    Ok(upload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(target: &str, group: &str) -> TargetForm {
        TargetForm {
            target: target.into(),
            group: group.into(),
            note: String::new(),
        }
    }

    #[test]
    fn valid_form_gives_normalized_target() {
        let target = build_target(form("10.0.0.7/24", " lab ")).unwrap();
        assert_eq!(target.kind.to_string(), "10.0.0.0/24");
        assert_eq!(target.group.as_deref(), Some("lab"));
        assert_eq!(target.note, None);
    }

    #[test]
    fn invalid_form_gives_message() {
        assert!(
            build_target(form("zły cel", ""))
                .unwrap_err()
                .contains("niepoprawny cel")
        );
        assert!(
            build_target(form("10.0.0.1", &"g".repeat(65)))
                .unwrap_err()
                .contains("za długa")
        );
    }
}
