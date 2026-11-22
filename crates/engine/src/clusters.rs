//! Klastry podobnych usług WWW (M4): SimHash odległy o najwyżej kilka bitów → ta sama grupa,
//! np. „te same 40 kamer”. Etykieta klastra: najczęstszy tytuł albo technologia.

use std::collections::HashMap;

use dscan_core::models::Host;
use dscan_fingerprint::simhash::cluster;

/// Domyślna maksymalna odległość Hamminga w klastrze.
pub const MAX_DISTANCE: u32 = 4;

/// Członek klastra.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMember {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCluster {
    /// Kolejny numer (1 = największy) — stabilny w obrębie przebiegu.
    pub id: usize,
    pub label: String,
    pub technologies: Vec<String>,
    pub members: Vec<ClusterMember>,
}

/// Najczęstsza wartość (przy remisie — pierwsza alfabetycznie).
fn most_common<'a>(values: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        .map(|(v, _)| v.to_string())
}

/// Klastry co najmniej `min_size` usług z SimHash.
pub fn service_clusters(hosts: &[Host], max_distance: u32, min_size: usize) -> Vec<ServiceCluster> {
    let mut items = Vec::new();
    for host in hosts {
        for service in &host.services {
            if let Some(hash) = service.http.as_ref().and_then(|h| h.simhash) {
                items.push((host, service, hash as u64));
            }
        }
    }
    let hashes: Vec<u64> = items.iter().map(|(_, _, h)| *h).collect();
    cluster(&hashes, max_distance)
        .into_iter()
        .filter(|group| group.len() >= min_size)
        .enumerate()
        .map(|(index, group)| {
            let members: Vec<ClusterMember> = group
                .iter()
                .map(|&i| {
                    let (host, service, _) = items[i];
                    ClusterMember {
                        ip: host.ip.to_string(),
                        port: service.port,
                        protocol: service.protocol.as_str().to_string(),
                        title: service.http.as_ref().and_then(|h| h.title.clone()),
                    }
                })
                .collect();
            let mut technologies: Vec<String> = group
                .iter()
                .flat_map(|&i| items[i].1.detections.iter().map(|d| d.technology.clone()))
                .collect();
            technologies.sort();
            technologies.dedup();
            let label = most_common(members.iter().filter_map(|m| m.title.as_deref()))
                .or_else(|| technologies.first().cloned())
                .unwrap_or_else(|| "bez tytułu".into());
            ServiceCluster {
                id: index + 1,
                label,
                technologies,
                members,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{HttpInfo, Protocol, Service, ServiceState};

    fn web(ip: &str, title: &str, hash: u64) -> Host {
        let mut host = Host::new(ip.parse().unwrap(), Utc::now());
        let mut service = Service::new(80, Protocol::Tcp, ServiceState::Open);
        service.http = Some(HttpInfo {
            url: format!("http://{ip}/"),
            status_code: 200,
            title: Some(title.into()),
            headers: Vec::new(),
            cookies: Vec::new(),
            redirect_chain: Vec::new(),
            tls_verified: None,
            certificate: None,
            favicon: None,
            simhash: Some(hash as i64),
        });
        host.services.push(service);
        host
    }

    #[test]
    fn similar_services_form_labelled_cluster() {
        let hosts = vec![
            web("10.0.0.1", "IP Camera", 0b1111_0000),
            web("10.0.0.2", "IP Camera", 0b1111_0001),
            web("10.0.0.3", "IP Camera", 0b1111_0011),
            web("10.0.0.9", "Blog", u64::MAX),
        ];
        let clusters = service_clusters(&hosts, MAX_DISTANCE, 2);
        assert_eq!(clusters.len(), 1);
        assert_eq!(clusters[0].label, "IP Camera");
        assert_eq!(clusters[0].members.len(), 3);
    }
}
