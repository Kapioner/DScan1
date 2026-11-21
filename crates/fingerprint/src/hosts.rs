use dscan_core::models::Host;

use crate::{HttpFetcher, service_url, to_http_info, web_scheme};

/// Odpytuje każdą otwartą usługę WWW na hostach i zapisuje wynik w `service.http`.
/// Usługa, której nie udało się odpytać, zostaje bez informacji HTTP (to nie przerywa skanu).
/// Zwraca liczbę usług z odczytanymi informacjami.
pub async fn fingerprint_hosts(fetcher: &HttpFetcher, hosts: &mut [Host]) -> usize {
    let mut fetched = 0;
    for host in hosts.iter_mut() {
        let ip = host.ip;
        for service in host.services.iter_mut() {
            let Some(scheme) = web_scheme(service) else {
                continue;
            };
            let url = service_url(ip, service.port, scheme);
            if let Ok(response) = fetcher.fetch(&url, ip).await {
                service.http = Some(to_http_info(&response));
                fetched += 1;
            }
        }
    }
    fetched
}
