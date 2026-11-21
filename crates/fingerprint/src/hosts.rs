use std::collections::HashMap;
use std::net::IpAddr;

use dscan_core::models::{Detection, Host};

use crate::environment::environment_findings;
use crate::probe::{merge_probe_paths, probe_paths};
use crate::signatures::{SignatureSet, WebEvidence};
use crate::{HttpFetcher, WebScheme, fetch_certificate, service_url, to_http_info, web_scheme};

/// Analiza usług WWW: sygnatury, heurystyki, ścieżki do sondowania i próg pewności.
pub struct WebAnalysis {
    pub signatures: SignatureSet,
    /// Ścieżki z konfiguracji i sygnatur (już połączone i sprawdzone).
    pub probe_paths: Vec<String>,
    pub max_probes: usize,
    /// Detekcje słabsze niż ten próg są pomijane (H8), żeby nie zaśmiecać wyników poszlakami.
    pub min_confidence: u8,
    /// Nazwy domenowe celów według adresu (z rozwiązywania DNS) — do heurystyk M6.
    pub hostnames: HashMap<IpAddr, Vec<String>>,
}

impl WebAnalysis {
    /// Łączy ścieżki z konfiguracji ze ścieżkami potrzebnymi sygnaturom.
    pub fn new(signatures: SignatureSet, configured_paths: &[String], max_probes: usize) -> Self {
        let probe_paths = merge_probe_paths(configured_paths, &signatures.probe_paths());
        WebAnalysis {
            signatures,
            probe_paths,
            max_probes,
            min_confidence: 0,
            hostnames: HashMap::new(),
        }
    }

    /// Ustawia próg pewności detekcji.
    pub fn with_min_confidence(mut self, min_confidence: u8) -> Self {
        self.min_confidence = min_confidence;
        self
    }

    /// Dodaje znane nazwy hostów (np. domeny podane jako cele).
    pub fn with_hostnames(mut self, hostnames: HashMap<IpAddr, Vec<String>>) -> Self {
        self.hostnames = hostnames;
        self
    }

    /// Detekcje z sygnatur i heurystyk M6, bez tych poniżej progu, od najpewniejszej.
    pub fn analyze(&self, evidence: &WebEvidence<'_>, hostnames: &[String]) -> Vec<Detection> {
        let mut detections = self.signatures.detect(evidence);
        detections.extend(environment_findings(
            hostnames,
            evidence.info,
            evidence.probes,
        ));
        detections.retain(|detection| detection.confidence >= self.min_confidence);
        detections.sort_by(|a, b| {
            b.confidence
                .cmp(&a.confidence)
                .then_with(|| a.technology.cmp(&b.technology))
        });
        detections
    }
}

/// Odpytuje każdą otwartą usługę WWW na hostach: strona główna (H1, H2), certyfikat TLS (H3),
/// sondy ścieżek (H6)
/// dopasowanie sygnatur (H5) i heurystyki środowisk/paneli (M6) z progiem pewności (H8).
/// Wynik trafia do `service.http` i `service.detections`.
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
        if host.hostnames.is_empty() {
            host.hostnames = analysis.hostnames.get(&ip).cloned().unwrap_or_default();
        }
        let hostnames = host.hostnames.clone();
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
            service.detections = analysis.analyze(&evidence, &hostnames);
            service.http = Some(info);
            fetched += 1;
        }
    }
    fetched
}
