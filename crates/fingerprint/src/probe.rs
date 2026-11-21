//! Bezpieczne sondowanie ścieżek (zadanie H6).
//!
//! - wyłącznie zapytania GET (bez formularzy, bez haseł, bez ciasteczek),
//! - ścieżki tylko z listy: konfiguracja `[http] probe_paths` + ścieżki z sygnatur,
//! - najwyżej `max_probes` ścieżek na usługę, a ponad to obowiązuje budżet zapytań
//!   na host (`limits.http_requests_per_host`) i globalne tempo z limitera HTTP.

use std::net::IpAddr;

use reqwest::Url;

use crate::{FetchError, HttpFetcher};

/// Ile znaków treści odpowiedzi zachować do dopasowania sygnatur.
const MAX_PROBE_BODY_CHARS: usize = 64 * 1024;

/// Wynik sondy jednej ścieżki.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub path: String,
    pub status: u16,
    pub body: String,
}

/// Czy ścieżka nadaje się do sondowania: zaczyna się od `/`, bez `..`, bez parametrów zapytania
/// i bez schematu/hosta (żeby nie dało się wyjść poza skanowany host).
pub fn is_safe_probe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("..")
        && !path.contains('?')
        && !path.contains('#')
}

/// Łączy listy ścieżek (bez powtórzeń, z zachowaniem kolejności) i odrzuca niebezpieczne.
pub fn merge_probe_paths(configured: &[String], from_signatures: &[String]) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for path in configured.iter().chain(from_signatures) {
        if is_safe_probe_path(path) && !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    paths
}

/// Sonduje ścieżki usługi pod `base_url` (np. `http://10.0.0.5:80/`), najwyżej `max_probes`.
/// Ścieżki, które nie odpowiedziały, są pomijane; wyczerpany budżet hosta kończy sondowanie.
pub async fn probe_paths(
    fetcher: &HttpFetcher,
    base_url: &str,
    ip: IpAddr,
    paths: &[String],
    max_probes: usize,
) -> Vec<ProbeResult> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for path in paths
        .iter()
        .filter(|path| is_safe_probe_path(path))
        .take(max_probes)
    {
        let Ok(url) = base.join(path) else {
            continue;
        };
        match fetcher.fetch(url.as_str(), ip).await {
            Ok(response) => results.push(ProbeResult {
                path: path.clone(),
                status: response.status,
                body: String::from_utf8_lossy(&response.body)
                    .chars()
                    .take(MAX_PROBE_BODY_CHARS)
                    .collect(),
            }),
            Err(FetchError::Budget(_)) => break,
            Err(_) => continue,
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_absolute_paths_are_safe() {
        assert!(is_safe_probe_path("/admin"));
        assert!(is_safe_probe_path("/wp-login.php"));
        for path in [
            "admin",
            "//evil.example/",
            "/../etc/passwd",
            "/login?user=admin",
            "http://x/",
            "/a#b",
        ] {
            assert!(!is_safe_probe_path(path), "{path}");
        }
    }

    #[test]
    fn paths_are_merged_without_duplicates() {
        let configured = vec![
            "/login".to_string(),
            "/admin".to_string(),
            "zła".to_string(),
        ];
        let signatures = vec!["/admin".to_string(), "/wp-login.php".to_string()];
        assert_eq!(
            merge_probe_paths(&configured, &signatures),
            vec!["/login", "/admin", "/wp-login.php"]
        );
    }
}
