//! Zarządzanie kontami i rolami (A4): tworzenie, edycja i blokowanie kont, przypisywanie ról,
//! własne role z zestawu uprawnień. Role wbudowane (`built_in`) są tylko do odczytu.

use chrono::{DateTime, Utc};

use crate::{DbError, PgPool};

/// Wszystkie uprawnienia, z których można złożyć rolę.
pub const ALL_PERMISSIONS: [&str; 4] = ["admin", "targets:write", "results:write", "read"];

/// Rola z liczbą przypisanych kont.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Role {
    pub id: i64,
    pub name: String,
    pub permissions: Vec<String>,
    pub built_in: bool,
    pub users: i64,
}

/// Wynik operacji na koncie lub roli.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChange {
    Done(i64),
    NameTaken,
    NotFound,
    /// Np. edycja roli wbudowanej, usunięcie roli z kontami, odebranie ostatniego administratora.
    Refused(&'static str),
}

pub async fn list_roles(pool: &PgPool) -> Result<Vec<Role>, DbError> {
    sqlx::query_as(
        "SELECT r.id, r.name, r.permissions, r.built_in, count(u.id) AS users \
         FROM roles r LEFT JOIN users u ON u.role_id = r.id GROUP BY r.id ORDER BY r.id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

fn unique_or(error: sqlx::Error) -> Result<AccountChange, DbError> {
    match &error {
        sqlx::Error::Database(db) if db.is_unique_violation() => Ok(AccountChange::NameTaken),
        _ => Err(DbError::Query(error)),
    }
}

/// Nowa rola z podanych uprawnień (już zwalidowanych).
pub async fn create_role(
    pool: &PgPool,
    name: &str,
    permissions: &[String],
) -> Result<AccountChange, DbError> {
    let result: Result<i64, sqlx::Error> =
        sqlx::query_scalar("INSERT INTO roles (name, permissions) VALUES ($1, $2) RETURNING id")
            .bind(name)
            .bind(permissions)
            .fetch_one(pool)
            .await;
    result.map(AccountChange::Done).or_else(unique_or)
}

/// Zmiana nazwy i uprawnień roli własnej.
pub async fn update_role(
    pool: &PgPool,
    id: i64,
    name: &str,
    permissions: &[String],
) -> Result<AccountChange, DbError> {
    let built_in: Option<bool> = sqlx::query_scalar("SELECT built_in FROM roles WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::Query)?;
    match built_in {
        None => return Ok(AccountChange::NotFound),
        Some(true) => return Ok(AccountChange::Refused("ról wbudowanych nie można zmieniać")),
        Some(false) => {}
    }
    if !permissions.iter().any(|p| p == "admin") && admins_left_without_role(pool, id).await? == 0 {
        return Ok(AccountChange::Refused(
            "musi zostać co najmniej jeden aktywny administrator",
        ));
    }
    let result = sqlx::query("UPDATE roles SET name = $2, permissions = $3 WHERE id = $1")
        .bind(id)
        .bind(name)
        .bind(permissions)
        .execute(pool)
        .await;
    result.map(|_| AccountChange::Done(id)).or_else(unique_or)
}

/// Usuwa rolę własną bez przypisanych kont.
pub async fn delete_role(pool: &PgPool, id: i64) -> Result<AccountChange, DbError> {
    let roles = list_roles(pool).await?;
    let Some(role) = roles.iter().find(|r| r.id == id) else {
        return Ok(AccountChange::NotFound);
    };
    if role.built_in {
        return Ok(AccountChange::Refused("ról wbudowanych nie można usuwać"));
    }
    if role.users > 0 {
        return Ok(AccountChange::Refused("rola ma przypisane konta"));
    }
    sqlx::query("DELETE FROM roles WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(AccountChange::Done(id))
}

/// Konto z rolą (skrót hasła argon2 przygotowuje wywołujący).
pub async fn create_user(
    pool: &PgPool,
    username: &str,
    password_hash: &str,
    role_id: i64,
) -> Result<AccountChange, DbError> {
    let result: Result<Option<i64>, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO users (username, password_hash, role_id) SELECT $1, $2, id FROM roles WHERE id = $3 RETURNING id",
    )
    .bind(username)
    .bind(password_hash)
    .bind(role_id)
    .fetch_optional(pool)
    .await;
    match result {
        Ok(Some(id)) => Ok(AccountChange::Done(id)),
        Ok(None) => Ok(AccountChange::NotFound),
        Err(error) => unique_or(error),
    }
}

/// Liczba aktywnych administratorów poza kontem `except_user` (−1 = bez wyjątku).
async fn active_admins_except(pool: &PgPool, except_user: i64) -> Result<i64, DbError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id \
         WHERE 'admin' = ANY(r.permissions) AND NOT u.is_blocked AND u.id <> $1",
    )
    .bind(except_user)
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)
}

/// Aktywni administratorzy, którzy nie mają roli `role_id`.
async fn admins_left_without_role(pool: &PgPool, role_id: i64) -> Result<i64, DbError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM users u JOIN roles r ON r.id = u.role_id \
         WHERE 'admin' = ANY(r.permissions) AND NOT u.is_blocked AND r.id <> $1",
    )
    .bind(role_id)
    .fetch_one(pool)
    .await
    .map_err(DbError::Query)
}

/// Zmienia rolę i blokadę konta. Zablokowanie kończy jego sesje. Nie pozwala odebrać
/// uprawnień ostatniemu aktywnemu administratorowi.
pub async fn update_user(
    pool: &PgPool,
    id: i64,
    role_id: i64,
    blocked: bool,
) -> Result<AccountChange, DbError> {
    let role_is_admin: Option<bool> =
        sqlx::query_scalar("SELECT 'admin' = ANY(permissions) FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(pool)
            .await
            .map_err(DbError::Query)?;
    let Some(role_is_admin) = role_is_admin else {
        return Ok(AccountChange::NotFound);
    };
    if (blocked || !role_is_admin) && active_admins_except(pool, id).await? == 0 {
        return Ok(AccountChange::Refused(
            "musi zostać co najmniej jeden aktywny administrator",
        ));
    }
    let updated = sqlx::query(
        "UPDATE users SET role_id = $2, is_blocked = $3, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(role_id)
    .bind(blocked)
    .execute(pool)
    .await
    .map_err(DbError::Query)?;
    if updated.rows_affected() == 0 {
        return Ok(AccountChange::NotFound);
    }
    if blocked {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(DbError::Query)?;
    }
    Ok(AccountChange::Done(id))
}

/// Nowe hasło (skrót argon2); dotychczasowe sesje konta są kończone.
pub async fn set_password(
    pool: &PgPool,
    id: i64,
    password_hash: &str,
) -> Result<AccountChange, DbError> {
    let updated =
        sqlx::query("UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(password_hash)
            .execute(pool)
            .await
            .map_err(DbError::Query)?;
    if updated.rows_affected() == 0 {
        return Ok(AccountChange::NotFound);
    }
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(DbError::Query)?;
    Ok(AccountChange::Done(id))
}

/// Konto z datą ostatniego logowania (panel F9).
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct UserDetails {
    pub id: i64,
    pub username: String,
    pub role_id: i64,
    pub role: String,
    pub is_blocked: bool,
    pub last_login_at: Option<DateTime<Utc>>,
}

pub async fn list_user_details(pool: &PgPool) -> Result<Vec<UserDetails>, DbError> {
    sqlx::query_as(
        "SELECT u.id, u.username, u.role_id, r.name AS role, u.is_blocked, u.last_login_at \
         FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.id",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)
}

/// Sprawdza nazwę roli i listę uprawnień (tylko znane, bez powtórzeń, co najmniej `read`).
pub fn validate_role(name: &str, permissions: &[String]) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 {
        return Err("nazwa roli musi mieć od 1 do 64 znaków".into());
    }
    if let Some(unknown) = permissions
        .iter()
        .find(|p| !ALL_PERMISSIONS.contains(&p.as_str()))
    {
        return Err(format!("nieznane uprawnienie: {unknown}"));
    }
    if !permissions.iter().any(|p| p == "read") {
        return Err("rola musi mieć uprawnienie read".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_validation() {
        let perms = |list: &[&str]| list.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert!(validate_role("audytor", &perms(&["read"])).is_ok());
        assert!(validate_role("", &perms(&["read"])).is_err());
        assert!(validate_role("x", &perms(&["targets:write"])).is_err());
        assert!(
            validate_role("x", &perms(&["read", "root"]))
                .unwrap_err()
                .contains("root")
        );
    }
}
