//! Szyfrowanie pól wrażliwych (zadanie B2) i tokeny sesji (A2).
//!
//! Format zaszyfrowanej wartości: `[wersja: 1 B][nonce: 12 B][szyfrogram + tag: n + 16 B]`.
//! - nonce jest losowany dla każdego rekordu, więc ta sama wartość daje za każdym razem inny szyfrogram,
//! - „kontekst” (np. `services.banner`) jest uwierzytelniany razem z danymi (AAD), więc
//!   zaszyfrowanej wartości nie da się po cichu przenieść do innej kolumny,
//! - bajt wersji pozwoli w przyszłości zmienić format bez psucia starych danych.

mod cipher;
mod error;
mod hex;
mod token;

pub use cipher::{Cipher, FORMAT_VERSION, KEY_LEN, NONCE_LEN, generate_key_hex};
pub use error::CryptoError;
pub use hex::encode_hex;
pub use token::{TOKEN_LEN, generate_token, hash_token};
