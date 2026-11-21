use dscan_core::models::Host;

use crate::probe::{merge_probe_paths, probe_paths};
use crate::signatures::{SignatureSet, WebEvidence};
use crate::{HttpFetcher, WebScheme, fetch_certificate, service_url, to_http_info, web_scheme};

/// Analiza usług WWW: sygnatury i lista ścieżek do sondowania.
pub struct WebAnalysis {
    pub signatures: SignatureSet,
    /// Ścieżki z konfiguracji i sygnatur (już połączone i sprawdzone).
    pub probe_paths: Vec<String>,
    pub max_probes: usize,
}

impl WebAnalysis {
    /// Łączy ścieżki z konfiguracji ze ścieżkami potrzebnymi sygnaturom.
    pub fn new(signatures: SignatureSet, configured_paths: &[String], max_probes: usize) -> Self {
        let probe_paths = merge_probe_paths(configured_paths, &signatures.probe_paths());
        WebAnalysis {
            signatures,
            probe_paths,
            max_probes,
        }
    }
}

/// Odpytuje każdą otwartą usługę WWW na hostach: strona główna (H1, H2), certyfikat TLS (H3),
/// sondy ścieżek (H6)
/// i dopasowanie sygnatur (H5). Wynik trafia do `service.http` i `service.detections`.
/// Usługa, której nie udało się odpytać, zostaje bez tych informacji (skan trwa dalej).
/// Zwraca liczbę usług z odczytanymi informacjami.
pub async fn fingerprint_hosts(
    fetcher: &HttpFetcher,
    analysis: &WebAnalysis,
    hosts: &mut [Host],
) -> usize {
    let mut fetched = 0;
    for host in hosts.iter_mut() {
        let ip = host.ip;
        for service in host.services.iter_mut() {
            let Some(scheme) = web_scheme(service) else {
                continue;
            };
            let url = service_url(ip, service.port, scheme);
            let Ok(response) = fetcher.fetch(&url, ip).await else {
                continue;
            };
            let mut info = to_http_info(&response);
            if scheme == WebScheme::Https {
                info.certificate = fetch_certificate(ip, service.port, fetcher.timeout())
                    .await
                    .ok();
            }
            let body = String::from_utf8_lossy(&response.body);
            let probes = probe_paths(
                fetcher,
                &url,
                ip,
                &analysis.probe_paths,
                analysis.max_probes,
            )
            .await;
            let evidence = WebEvidence {
                info: &info,
                body: &body,
                probes: &probes,
                favicon_hash: None,
            };
            service.detections = analysis.signatures.detect(&evidence);
            service.http = Some(info);
            fetched += 1;
        }
    }
    fetched
}
