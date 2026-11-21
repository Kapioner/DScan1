//! Fingerprinting usług WWW.
//!
//! - [`HttpFetcher`] — klient HTTP/HTTPS z własną obsługą przekierowań (zadanie H1),
//! - [`to_http_info`] — tytuł, nagłówki, ciasteczka i łańcuch przekierowań (zadanie H2),
//! - [`HttpRateLimiter`] — globalne tempo i budżet zapytań na host (zadanie S7),
//! - [`signatures`] — silnik sygnatur YAML (zadanie H5),
//! - [`probe_paths`] — bezpieczne sondowanie ścieżek GET (zadanie H6),
//! - [`fingerprint_hosts`] — odpytanie wszystkich usług WWW znalezionych przez nmap.

mod client;
pub mod environment;
mod error;
mod extract;
mod favicon;
mod hosts;
mod nmap_evidence;
mod probe;
mod rate_limit;
mod redirect;
mod robots;
pub mod signatures;
mod tls;
mod web_service;

pub use client::{HttpFetcher, HttpOptions, RawResponse};
pub use error::FetchError;
pub use extract::{extract_title, parse_set_cookie, to_http_info};
pub use favicon::{
    base64_lines, favicon_candidates, favicon_hashes, fetch_favicon, icon_link, mmh3_32,
};
pub use hosts::{WebAnalysis, fingerprint_hosts};
pub use nmap_evidence::{
    merge_nmap_evidence, merge_nmap_evidence_hosts, same_technology, technology_name,
};
pub use probe::{ProbeResult, is_safe_probe_path, merge_probe_paths, probe_paths};
pub use rate_limit::{BudgetExceeded, HttpRateLimiter};
pub use redirect::{is_same_host, resolve_location};
pub use tls::{fetch_certificate, parse_certificate};
pub use web_service::{WebScheme, service_url, web_scheme};

/// Bajty jako małe znaki hex (np. odcisk SHA-256 certyfikatu).
pub(crate) fn encode_hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
