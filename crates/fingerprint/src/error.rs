use std::fmt;

use crate::BudgetExceeded;

/// Błędy pobierania strony.
#[derive(Debug)]
pub enum FetchError {
    InvalidUrl(String),
    /// Błąd połączenia, limitu czasu albo protokołu HTTP.
    Request(reqwest::Error),
    TooManyRedirects(u32),
    Budget(BudgetExceeded),
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchError::InvalidUrl(url) => write!(f, "niepoprawny adres URL: {url}"),
            FetchError::Request(error) => write!(f, "zapytanie HTTP nie powiodło się: {error}"),
            FetchError::TooManyRedirects(limit) => {
                write!(f, "przekroczono limit {limit} przekierowań")
            }
            FetchError::Budget(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FetchError {}
