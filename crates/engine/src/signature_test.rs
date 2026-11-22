//! Test sygnatury na usłudze WWW (F8, `dscan sig test`): odpytanie jak przy skanie
//! i dopasowanie wybranych sygnatur — bez zapisu czegokolwiek.

use std::net::IpAddr;
use std::sync::Arc;

use dscan_config::Settings;
use dscan_core::models::{Detection, HttpInfo};
use dscan_fingerprint::signatures::{SignatureSet, WebEvidence};
use dscan_fingerprint::{fetch_favicon, probe_paths, to_http_info};
use dscan_scanner::targets::{is_in_scope, single_address_network};

use crate::{EngineError, build_analysis, build_fetcher};

/// Wynik testu.
#[derive(Debug, Clone)]
pub struct SignatureTestResult {
    pub info: HttpInfo,
    pub probes: usize,
    pub detections: Vec<Detection>,
}

/// IP z adresu URL (`http://10.0.0.5:80/` → 10.0.0.5, `http://[::1]/` → ::1).
pub fn host_ip(url: &str) -> Option<IpAddr> {
    let rest = url.split_once("://")?.1;
    let host = rest.split('/').next()?;
    if let Some(v6) = host.strip_prefix('[') {
        return v6.split(']').next()?.parse().ok();
    }
    host.rsplit_once(':')
        .map_or(host, |(name, _)| name)
        .parse()
        .ok()
}

/// Odpytuje `url` (host z `[scope]`) i dopasowuje sygnatury: `candidate` (edytor) albo
/// wszystkie skonfigurowane; `name` filtruje wynik (`*` = wszystkie).
pub async fn test_signature_on(
    settings: &Settings,
    candidate: Option<SignatureSet>,
    name: &str,
    url: &str,
) -> Result<SignatureTestResult, EngineError> {
    let ip = host_ip(url)
        .ok_or_else(|| EngineError::Setup(format!("adres {url} musi zawierać IP hosta")))?;
    if !is_in_scope(
        &single_address_network(ip),
        &settings.scope.allowed_networks,
    ) {
        return Err(EngineError::Setup(format!(
            "{ip} jest poza zakresem [scope]"
        )));
    }
    let mut analysis = build_analysis(settings, &[])?;
    if let Some(set) = candidate {
        analysis = dscan_fingerprint::WebAnalysis::new(
            set,
            &settings.http.probe_paths,
            settings.http.max_probes_per_service as usize,
        );
    }
    let fetcher = Arc::new(build_fetcher(settings)?);
    let response = fetcher
        .fetch(url, ip)
        .await
        .map_err(|e| EngineError::Setup(e.to_string()))?;
    let mut info = to_http_info(&response);
    let body = String::from_utf8_lossy(&response.body);
    info.favicon = fetch_favicon(&fetcher, &info.url, ip, &body).await;
    let probes = probe_paths(
        &fetcher,
        url,
        ip,
        &analysis.probe_paths,
        analysis.max_probes,
    )
    .await;
    let evidence = WebEvidence {
        info: &info,
        body: &body,
        probes: &probes,
        favicon_hash: info.favicon.as_ref().map(|f| f.mmh3),
    };
    let detections = analysis
        .analyze(&evidence, &[])
        .into_iter()
        .filter(|d| name == "*" || d.technology.eq_ignore_ascii_case(name))
        .collect();
    Ok(SignatureTestResult {
        info,
        probes: probes.len(),
        detections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ip_is_read_from_url() {
        assert_eq!(
            host_ip("http://10.0.0.5:80/").unwrap().to_string(),
            "10.0.0.5"
        );
        assert_eq!(host_ip("http://[::1]:8080/").unwrap().to_string(), "::1");
        assert_eq!(host_ip("http://example.com/"), None);
    }
}
