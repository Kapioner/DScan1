//! Uwierzytelnianie (zadanie A2): logowanie hasłem, sesje w ciasteczku lub nagłówku
//! `Authorization: Bearer`, odczyt zalogowanego użytkownika w handlerach.
//!
//! Sesje są przechowywane w PostgreSQL (tabela `sessions`, tylko skrót tokenu), dzięki czemu
//! przetrwają restart serwera, da się je unieważnić, a ten sam token posłuży klientowi CLI (C5).

mod cookie;
mod extractor;
pub mod handlers;
mod service;

pub use cookie::{SESSION_COOKIE, clear_session_cookie, session_cookie, token_from_headers};
pub use extractor::{CurrentUser, authenticate};
pub use service::{LoginOutcome, login, logout};

/// Uprawnienia ról (z migracji 0001). Rola z `admin` ma wszystkie uprawnienia.
pub mod permissions {
    pub const ADMIN: &str = "admin";
    pub const TARGETS_WRITE: &str = "targets:write";
    pub const RESULTS_WRITE: &str = "results:write";
    pub const READ: &str = "read";
}
