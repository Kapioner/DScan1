//! Zapis do dziennika audytu z handlerów (A7). Błąd zapisu nie przerywa operacji —
//! trafia do logów serwera.

use crate::AppState;
use crate::auth::CurrentUser;

/// Zapisuje wpis: użytkownik, akcja, rodzaj obiektu, jego identyfikator i opis (bez danych poufnych).
pub async fn record(
    state: &AppState,
    user: &CurrentUser,
    action: &str,
    entity: &str,
    entity_id: impl ToString,
    details: &str,
) {
    let id = entity_id.to_string();
    let entry = dscan_db::AuditEntry {
        user_id: Some(user.0.id),
        action,
        entity,
        entity_id: (!id.is_empty()).then_some(id),
        details,
    };
    if let Err(error) = dscan_db::insert_audit(&state.db, &entry).await {
        tracing::warn!("dziennik audytu: {error}");
    }
}
