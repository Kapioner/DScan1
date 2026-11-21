//! Odczyt wyników przebiegu: hosty z usługami, podstawowymi informacjami HTTP i detekcjami.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use dscan_core::models::{
    Detection, Evidence, Host, HostStatus, HttpInfo, Protocol, Service, ServiceState,
};

use crate::{DbError, PgPool};

type HostRow = (
    i64,
    IpAddr,
    Vec<String>,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
);
type ServiceRow = (
    i64,
    i64,
    i32,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Vec<String>,
);
type HttpRow = (i64, String, i32, Option<String>, Option<bool>);
type DetectionRow = (i64, String, Option<String>, i16, String);

/// Hosty przebiegu (bez pól szyfrowanych — banerów, nagłówków, ciasteczek, certyfikatów).
pub async fn load_run_hosts(pool: &PgPool, run_id: i64) -> Result<Vec<Host>, DbError> {
    let hosts: Vec<HostRow> = sqlx::query_as(
        "SELECT id, ip, hostnames, status, first_seen, last_seen FROM hosts WHERE scan_run_id = $1 ORDER BY ip",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    let services: Vec<ServiceRow> = sqlx::query_as(
        "SELECT s.id, s.host_id, s.port, s.protocol, s.state, s.name, s.product, s.version, s.cpe \
         FROM services s JOIN hosts h ON h.id = s.host_id WHERE h.scan_run_id = $1 ORDER BY s.port",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    let http: Vec<HttpRow> = sqlx::query_as(
        "SELECT i.service_id, i.url, i.status_code, i.title, i.tls_verified FROM http_info i \
         JOIN services s ON s.id = i.service_id JOIN hosts h ON h.id = s.host_id WHERE h.scan_run_id = $1",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    let detections: Vec<DetectionRow> = sqlx::query_as(
        "SELECT d.service_id, d.technology, d.version, d.confidence, d.evidence::text FROM detections d \
         JOIN services s ON s.id = d.service_id JOIN hosts h ON h.id = s.host_id \
         WHERE h.scan_run_id = $1 ORDER BY d.confidence DESC",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::Query)?;
    Ok(assemble(hosts, services, http, detections))
}

/// Składa wiersze z czterech zapytań w hosty z usługami.
fn assemble(
    hosts: Vec<HostRow>,
    services: Vec<ServiceRow>,
    http: Vec<HttpRow>,
    detections: Vec<DetectionRow>,
) -> Vec<Host> {
    let mut http_by_service: HashMap<i64, HttpInfo> = http
        .into_iter()
        .map(|(id, url, status, title, tls_verified)| {
            let status_code = u16::try_from(status).unwrap_or(0);
            let info = HttpInfo {
                url,
                status_code,
                title,
                headers: Vec::new(),
                cookies: Vec::new(),
                redirect_chain: Vec::new(),
                tls_verified,
                certificate: None,
            };
            (id, info)
        })
        .collect();
    let mut detections_by_service: HashMap<i64, Vec<Detection>> = HashMap::new();
    for (service_id, technology, version, confidence, evidence) in detections {
        let evidence: Vec<Evidence> = serde_json::from_str(&evidence).unwrap_or_default();
        detections_by_service
            .entry(service_id)
            .or_default()
            .push(Detection {
                technology,
                version,
                confidence: u8::try_from(confidence).unwrap_or(0),
                evidence,
            });
    }
    let mut services_by_host: HashMap<i64, Vec<Service>> = HashMap::new();
    for (id, host_id, port, protocol, state, name, product, version, cpe) in services {
        let Ok(port) = u16::try_from(port) else {
            continue;
        };
        let protocol = if protocol == "udp" {
            Protocol::Udp
        } else {
            Protocol::Tcp
        };
        let state = match state.as_str() {
            "open" => ServiceState::Open,
            "closed" => ServiceState::Closed,
            _ => ServiceState::Filtered,
        };
        let mut service = Service::new(port, protocol, state);
        service.name = name;
        service.product = product;
        service.version = version;
        service.cpe = cpe;
        service.http = http_by_service.remove(&id);
        service.detections = detections_by_service.remove(&id).unwrap_or_default();
        services_by_host.entry(host_id).or_default().push(service);
    }
    hosts
        .into_iter()
        .map(|(id, ip, hostnames, status, first_seen, last_seen)| {
            let mut host = Host::new(ip, first_seen);
            host.last_seen = last_seen;
            host.hostnames = hostnames;
            host.status = match status.as_str() {
                "inactive" => HostStatus::Inactive,
                "unstable" => HostStatus::Unstable,
                _ => HostStatus::Active,
            };
            host.services = services_by_host.remove(&id).unwrap_or_default();
            host
        })
        .collect()
}
