//! Panel użytkowników i ról (F9) oraz dziennik audytu (A7) — tylko administracja.

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use dscan_api::auth::{CurrentUser, permissions};
use dscan_api::{ApiError, AppState};
use dscan_auth::{hash_password, validate_password_strength, validate_username};
use dscan_db::{ALL_PERMISSIONS, AccountChange, AuditFilter, validate_role};
use serde::Deserialize;

use crate::host_views::SelectOption;
use crate::pages::{MessageParam, render, user_bar};
use crate::session::WebUser;
use crate::views::{ForbiddenPage, UserBar};
use crate::{MenuItem, menu_for};

/// Konto w tabeli panelu.
pub struct AccountRow {
    pub id: i64,
    pub username: String,
    pub blocked: bool,
    pub last_login: String,
    pub roles: Vec<SelectOption>,
}

/// Rola w tabeli panelu: uprawnienia jako pola wyboru.
pub struct RoleRow {
    pub id: i64,
    pub name: String,
    pub built_in: bool,
    pub users: i64,
    pub permissions: Vec<SelectOption>,
}

#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub message: Option<String>,
    pub accounts: Vec<AccountRow>,
    pub roles: Vec<RoleRow>,
    pub role_options: Vec<SelectOption>,
    pub all_permissions: Vec<SelectOption>,
}

fn forbidden(user: &CurrentUser) -> Result<Response, ApiError> {
    let page = render(&ForbiddenPage {
        menu: menu_for(user, ""),
        user: user_bar(user),
    })?;
    Ok((StatusCode::FORBIDDEN, page).into_response())
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
    Redirect::to(&format!("/users?msg={encoded}")).into_response()
}

fn outcome(change: AccountChange, ok: &str) -> Response {
    back(match change {
        AccountChange::Done(_) => ok,
        AccountChange::NameTaken => "Ta nazwa jest już zajęta.",
        AccountChange::NotFound => "Nie znaleziono.",
        AccountChange::Refused(reason) => reason,
    })
}

pub async fn users_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(param): Query<MessageParam>,
) -> Result<Response, ApiError> {
    if !user.has(permissions::ADMIN) {
        return forbidden(&user);
    }
    let roles = dscan_db::list_roles(&state.db).await?;
    let accounts = dscan_db::list_user_details(&state.db)
        .await?
        .into_iter()
        .map(|a| AccountRow {
            id: a.id,
            username: a.username,
            blocked: a.is_blocked,
            last_login: a
                .last_login_at
                .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "—".into()),
            roles: roles
                .iter()
                .map(|r| SelectOption::new(r.id, r.name.clone(), r.id == a.role_id))
                .collect(),
        })
        .collect();
    let role_rows = roles
        .iter()
        .map(|r| RoleRow {
            id: r.id,
            name: r.name.clone(),
            built_in: r.built_in,
            users: r.users,
            permissions: ALL_PERMISSIONS
                .iter()
                .map(|p| SelectOption::new(p, *p, r.permissions.iter().any(|x| x == p)))
                .collect(),
        })
        .collect();
    let page = UsersPage {
        menu: menu_for(&user, "/users"),
        user: user_bar(&user),
        message: param.msg,
        accounts,
        role_options: roles
            .iter()
            .map(|r| SelectOption::new(r.id, r.name.clone(), r.name == "odczyt"))
            .collect(),
        roles: role_rows,
        all_permissions: ALL_PERMISSIONS
            .iter()
            .map(|p| SelectOption::new(p, *p, *p == "read"))
            .collect(),
    };
    Ok(render(&page)?.into_response())
}

#[derive(Debug, Deserialize)]
pub struct NewAccountForm {
    pub username: String,
    pub password: String,
    pub role_id: i64,
}

pub async fn create_account(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    axum::Form(form): axum::Form<NewAccountForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::ADMIN)?;
    if let Err(error) =
        validate_username(&form.username).and_then(|()| validate_password_strength(&form.password))
    {
        return Ok(back(&error.to_string()));
    }
    let hash = hash_password(&form.password).map_err(|e| ApiError::Internal(e.to_string()))?;
    let change =
        dscan_db::create_user(&state.db, form.username.trim(), &hash, form.role_id).await?;
    if let AccountChange::Done(id) = change {
        dscan_api::audit::record(&state, &user, "create", "user", id, &form.username).await;
    }
    Ok(outcome(change, "Utworzono konto."))
}

#[derive(Debug, Deserialize)]
pub struct AccountForm {
    pub role_id: i64,
    #[serde(default)]
    pub blocked: String,
    #[serde(default)]
    pub password: String,
}

pub async fn update_account(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
    axum::Form(form): axum::Form<AccountForm>,
) -> Result<Response, ApiError> {
    user.require(permissions::ADMIN)?;
    let blocked = !form.blocked.is_empty();
    let change = dscan_db::update_user(&state.db, id, form.role_id, blocked).await?;
    if !matches!(change, AccountChange::Done(_)) {
        return Ok(outcome(change, ""));
    }
    let details = format!("role_id={}, blocked={blocked}", form.role_id);
    dscan_api::audit::record(&state, &user, "update", "user", id, &details).await;
    if !form.password.is_empty() {
        if let Err(error) = validate_password_strength(&form.password) {
            return Ok(back(&error.to_string()));
        }
        let hash = hash_password(&form.password).map_err(|e| ApiError::Internal(e.to_string()))?;
        dscan_db::set_password(&state.db, id, &hash).await?;
        dscan_api::audit::record(&state, &user, "password", "user", id, "").await;
    }
    Ok(back("Zapisano konto."))
}

/// Formularz roli: nazwa i zaznaczone uprawnienia (pole `permissions` powtarzane).
pub fn parse_role_form(body: &str) -> (String, Vec<String>) {
    let mut name = String::new();
    let mut permissions = Vec::new();
    for pair in body.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = decode(value);
        match key {
            "name" => name = value,
            "permissions" => permissions.push(value),
            _ => {}
        }
    }
    permissions.sort();
    permissions.dedup();
    (name.trim().to_string(), permissions)
}

/// Dekodowanie `application/x-www-form-urlencoded` (`+` = spacja, `%XX`).
pub(crate) fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub async fn save_role(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    id: Option<Path<i64>>,
    body: String,
) -> Result<Response, ApiError> {
    user.require(permissions::ADMIN)?;
    let (name, permissions) = parse_role_form(&body);
    if let Err(message) = validate_role(&name, &permissions) {
        return Ok(back(&message));
    }
    let change = match &id {
        Some(Path(id)) => dscan_db::update_role(&state.db, *id, &name, &permissions).await?,
        None => dscan_db::create_role(&state.db, &name, &permissions).await?,
    };
    if let AccountChange::Done(role_id) = change {
        let action = if id.is_some() { "update" } else { "create" };
        dscan_api::audit::record(
            &state,
            &user,
            action,
            "role",
            role_id,
            &format!("{name}: {}", permissions.join(",")),
        )
        .await;
    }
    Ok(outcome(change, "Zapisano rolę."))
}

pub async fn delete_role(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    user.require(permissions::ADMIN)?;
    let change = dscan_db::delete_role(&state.db, id).await?;
    if let AccountChange::Done(_) = change {
        dscan_api::audit::record(&state, &user, "delete", "role", id, "").await;
    }
    Ok(outcome(change, "Usunięto rolę."))
}

/// Wpis dziennika do wyświetlenia.
pub struct AuditRow {
    pub at: String,
    pub user: String,
    pub action: String,
    pub entity: String,
    pub entity_id: String,
    pub details: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditPage {
    pub user: UserBar,
    pub menu: Vec<MenuItem>,
    pub entries: Vec<AuditRow>,
    pub entity: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub entity: String,
}

pub async fn audit_page(
    State(state): State<AppState>,
    WebUser(user): WebUser,
    Query(query): Query<AuditQuery>,
) -> Result<Response, ApiError> {
    if !user.has(permissions::ADMIN) {
        return forbidden(&user);
    }
    let filter = AuditFilter {
        entity: (!query.entity.is_empty()).then(|| query.entity.clone()),
        ..AuditFilter::default()
    };
    let entries = dscan_db::list_audit(&state.db, &filter, 300)
        .await?
        .into_iter()
        .map(|r| AuditRow {
            at: r.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            user: r.username.unwrap_or_else(|| "—".into()),
            action: r.action,
            entity: r.entity,
            entity_id: r.entity_id.unwrap_or_default(),
            details: r.details,
        })
        .collect();
    Ok(render(&AuditPage {
        menu: menu_for(&user, "/audit"),
        user: user_bar(&user),
        entries,
        entity: query.entity,
    })?
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_form_with_repeated_permissions() {
        let (name, permissions) = parse_role_form(
            "name=Audytor+zewn%C4%99trzny&permissions=read&permissions=results%3Awrite&permissions=read",
        );
        assert_eq!(name, "Audytor zewnętrzny");
        assert_eq!(permissions, vec!["read", "results:write"]);
    }
}
