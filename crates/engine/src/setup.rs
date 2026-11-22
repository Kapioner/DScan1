//! Fingerprinting WWW z konfiguracji: klient HTTP z limitami, sygnatury, analiza.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use dscan_config::Settings;
use dscan_fingerprint::signatures::SignatureSet;
use dscan_fingerprint::{HttpFetcher, HttpOptions, HttpRateLimiter, WebAnalysis};

use crate::EngineError;

/// Klient HTTP z limitami z `[http]` i `[limits]`.
pub fn build_fetcher(settings: &Settings) -> Result<HttpFetcher, EngineError> {
    let http = &settings.http;
    let limits = &settings.limits;
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
    HttpFetcher::new(options, Some(limiter)).map_err(|error| EngineError::Setup(error.to_string()))
}

/// Wbudowane sygnatury + opcjonalny plik z `[http] signatures_file` + własne z edytora (F8).
pub fn load_signatures(settings: &Settings) -> Result<SignatureSet, EngineError> {
    let extra = match &settings.http.signatures_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|error| EngineError::Setup(format!("plik sygnatur {path}: {error}")))?,
        ),
        None => None,
    };
    let mut set = SignatureSet::builtin_with(extra.as_deref())
        .map_err(|error| EngineError::Setup(error.to_string()))?;
    crate::custom_signatures::append_custom_signatures(&mut set);
    Ok(set)
}

/// Analiza WWW: sygnatury, ścieżki do sondowania, próg pewności i nazwy domen celów (M6).
pub fn build_analysis(
    settings: &Settings,
    hostnames: &[(IpAddr, String)],
) -> Result<WebAnalysis, EngineError> {
    let http = &settings.http;
    let mut by_ip: HashMap<IpAddr, Vec<String>> = HashMap::new();
    for (ip, name) in hostnames {
        by_ip.entry(*ip).or_default().push(name.clone());
    }
    Ok(WebAnalysis::new(
        load_signatures(settings)?,
        &http.probe_paths,
        http.max_probes_per_service as usize,
    )
    .with_min_confidence(http.min_confidence)
    .with_hostnames(by_ip))
}
