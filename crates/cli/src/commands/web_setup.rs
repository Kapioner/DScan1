//! Przygotowanie fingerprintingu WWW z konfiguracji (wspólne dla `scan` i `sig`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use dscan_config::AppConfig;
use dscan_fingerprint::signatures::SignatureSet;
use dscan_fingerprint::{HttpFetcher, HttpOptions, HttpRateLimiter, WebAnalysis};

use crate::error::CliError;

/// Analiza WWW z konfiguracji: sygnatury (wbudowane i z `http.signatures_file`), ścieżki do
/// sondowania, próg pewności i nazwy domen celów (do heurystyk M6).
pub fn build_analysis(
    config: &AppConfig,
    hostnames: &[(IpAddr, String)],
) -> Result<WebAnalysis, CliError> {
    let http = &config.settings.http;
    let mut by_ip: HashMap<IpAddr, Vec<String>> = HashMap::new();
    for (ip, name) in hostnames {
        by_ip.entry(*ip).or_default().push(name.clone());
    }
    Ok(WebAnalysis::new(
        load_signatures(config)?,
        &http.probe_paths,
        http.max_probes_per_service as usize,
    )
    .with_min_confidence(http.min_confidence)
    .with_hostnames(by_ip))
}

/// Wbudowane sygnatury + opcjonalny plik z `[http] signatures_file`.
pub fn load_signatures(config: &AppConfig) -> Result<SignatureSet, CliError> {
    let extra = match &config.settings.http.signatures_file {
        Some(path) => Some(
            std::fs::read_to_string(path).map_err(|source| CliError::File {
                path: path.into(),
                source,
            })?,
        ),
        None => None,
    };
    SignatureSet::builtin_with(extra.as_deref()).map_err(|error| CliError::Http(error.to_string()))
}

/// Klient HTTP z limitami z konfiguracji (`[http]` i `[limits]`).
pub fn build_fetcher(config: &AppConfig) -> Result<HttpFetcher, CliError> {
    let http = &config.settings.http;
    let limits = &config.settings.limits;
    let options = HttpOptions {
        timeout: std::time::Duration::from_secs(http.timeout_seconds),
        max_redirects: http.max_redirects,
        max_body_bytes: http.max_body_bytes,
        user_agent: http.user_agent.clone(),
    };
    let limiter = Arc::new(HttpRateLimiter::new(
        limits.http_requests_per_second,
        limits.http_requests_per_host,
    ));
    HttpFetcher::new(options, Some(limiter)).map_err(|error| CliError::Http(error.to_string()))
}
