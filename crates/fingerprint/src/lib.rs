//! Fingerprinting usług WWW.
//!
//! - [`HttpFetcher`] — klient HTTP/HTTPS z własną obsługą przekierowań (zadanie H1),
//! - [`to_http_info`] — tytuł, nagłówki, ciasteczka i łańcuch przekierowań (zadanie H2),
//! - [`HttpRateLimiter`] — globalne tempo i budżet zapytań na host (zadanie S7),
//! - [`signatures`] — silnik sygnatur YAML (zadanie H5),
//! - [`probe_paths`] — bezpieczne sondowanie ścieżek GET (zadanie H6),
//! - [`fingerprint_hosts`] — odpytanie wszystkich usług WWW znalezionych przez nmap.

mod client;
mod error;
mod extract;
mod hosts;
mod probe;
mod rate_limit;
mod redirect;
pub mod signatures;
mod web_service;

pub use client::{HttpFetcher, HttpOptions, RawResponse};
pub use error::FetchError;
pub use extract::{extract_title, parse_set_cookie, to_http_info};
pub use hosts::{WebAnalysis, fingerprint_hosts};
pub use probe::{ProbeResult, is_safe_probe_path, merge_probe_paths, probe_paths};
pub use rate_limit::{BudgetExceeded, HttpRateLimiter};
pub use redirect::{is_same_host, resolve_location};
pub use web_service::{WebScheme, service_url, web_scheme};
