//! Fingerprinting usług WWW.
//!
//! - [`HttpFetcher`] — klient HTTP/HTTPS z własną obsługą przekierowań (zadanie H1),
//! - [`to_http_info`] — tytuł, nagłówki, ciasteczka i łańcuch przekierowań (zadanie H2),
//! - [`HttpRateLimiter`] — globalne tempo i budżet zapytań na host (zadanie S7),
//! - [`fingerprint_hosts`] — odpytanie wszystkich usług WWW znalezionych przez nmap.

mod client;
mod error;
mod extract;
mod hosts;
mod rate_limit;
mod redirect;
mod web_service;

pub use client::{HttpFetcher, HttpOptions, RawResponse};
pub use error::FetchError;
pub use extract::{extract_title, parse_set_cookie, to_http_info};
pub use hosts::fingerprint_hosts;
pub use rate_limit::{BudgetExceeded, HttpRateLimiter};
pub use redirect::{is_same_host, resolve_location};
pub use web_service::{WebScheme, service_url, web_scheme};
