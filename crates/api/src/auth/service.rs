use std::sync::OnceLock;

use chrono::{DateTime, TimeDelta, Utc};
use dscan_auth::{hash_password, verify_password};
use dscan_crypto::{generate_token, hash_token};
use dscan_db::SessionUser;

use crate::{ApiError, AppState};

/// Wynik udanego logowania.
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub token: String,
    pub user: SessionUser,
    pub expires_at: DateTime<Utc>,
}

/// Sprawdza login i hasło i tworzy sesję. Błąd jest zawsze ten sam (`Unauthorized`),
/// żeby nie zdradzać, czy dany login istnieje.
pub async fn login(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<LoginOutcome, ApiError> {
    let account = dscan_db::find_login_user(&state.db, username).await?;
    // Dla nieistniejącego konta też liczymy argon2 — czas odpowiedzi jest wtedy podobny.
    let stored_hash = account
        .as_ref()
        .map_or(dummy_hash(), |account| account.password_hash.as_str());
    let password_ok = verify_password(password, stored_hash).unwrap_or(false);

    let account = match account {
        Some(account) if password_ok && !account.is_blocked => account,
        _ => return Err(ApiError::Unauthorized),
    };

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + TimeDelta::hours(i64::from(state.auth.session_hours));
    dscan_db::create_session(&state.db, account.id, &token_hash, expires_at).await?;
    dscan_db::record_login(&state.db, account.id).await?;
    let user = dscan_db::find_session_user(&state.db, &token_hash)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    Ok(LoginOutcome {
        token,
        user,
        expires_at,
    })
}

/// Usuwa sesję o podanym tokenie.
pub async fn logout(state: &AppState, token: &str) -> Result<(), ApiError> {
    dscan_db::delete_session(&state.db, &hash_token(token)).await?;
    Ok(())
}

/// Skrót argon2 nieistniejącego hasła, liczony raz (wzorzec Singleton przez `OnceLock`).
fn dummy_hash() -> &'static str {
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    DUMMY_HASH.get_or_init(|| hash_password("dscan-konto-nie-istnieje").unwrap_or_default())
}
