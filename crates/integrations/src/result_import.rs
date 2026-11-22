//! Import wyników skanów (zadanie I2): nmap XML, JSON (format eksportu hostów DScan)
//! i CSV (jeden wiersz na usługę, ten sam układ co eksport usług).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

use chrono::Utc;
use dscan_core::models::{Host, Protocol, Service, ServiceState};
use dscan_scanner::nmap::{map_port_state, map_protocol, parse_nmap_xml, to_hosts};
use serde::Deserialize;

use crate::{ImportError, PassiveSource};

/// Format pliku z wynikami.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFormat {
    NmapXml,
    Json,
    Csv,
    /// Źródło pasywne (I6): eksport Shodana (JSON w liniach).
    Shodan,
    /// Źródło pasywne (I6): wynik masscan `-oJ`.
    Masscan,
}

/// Wczytane wyniki: hosty i (dla nmap) surowy XML do zachowania.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedResults {
    pub hosts: Vec<Host>,
    pub raw_xml: Option<String>,
}

/// Format po rozszerzeniu: `.xml` → nmap, `.json`, `.csv`.
pub fn detect_result_format(path: &Path) -> Result<ResultFormat, ImportError> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("xml") => Ok(ResultFormat::NmapXml),
        Some("json") => Ok(ResultFormat::Json),
        Some("csv") => Ok(ResultFormat::Csv),
        _ => Err(ImportError::UnknownFormat(path.display().to_string())),
    }
}

/// Nazwa formatu w API: `nmap-xml`, `json`, `csv`.
pub fn parse_result_format(name: &str) -> Option<ResultFormat> {
    match name {
        "nmap-xml" | "xml" => Some(ResultFormat::NmapXml),
        "json" => Some(ResultFormat::Json),
        "csv" => Some(ResultFormat::Csv),
        "shodan" | "shodan-jsonl" => Some(ResultFormat::Shodan),
        "masscan" | "masscan-json" => Some(ResultFormat::Masscan),
        _ => None,
    }
}

/// Wczytuje wyniki z treści pliku.
pub fn parse_results(content: &str, format: ResultFormat) -> Result<ParsedResults, ImportError> {
    match format {
        ResultFormat::NmapXml => {
            let run = parse_nmap_xml(content)
                .map_err(|error| ImportError::InvalidResults(error.to_string()))?;
            Ok(ParsedResults {
                hosts: to_hosts(&run, Utc::now()),
                raw_xml: Some(content.to_string()),
            })
        }
        ResultFormat::Json => {
            let hosts: Vec<Host> = serde_json::from_str(content)
                .map_err(|error| ImportError::InvalidJson(error.to_string()))?;
            Ok(ParsedResults {
                hosts: clean_imported(hosts),
                raw_xml: None,
            })
        }
        ResultFormat::Csv => Ok(ParsedResults {
            hosts: hosts_from_csv(content)?,
            raw_xml: None,
        }),
        ResultFormat::Shodan => Ok(ParsedResults {
            hosts: crate::ShodanJsonl.parse(content)?,
            raw_xml: None,
        }),
        ResultFormat::Masscan => Ok(ParsedResults {
            hosts: crate::MasscanJson.parse(content)?,
            raw_xml: None,
        }),
    }
}

/// Z importu JSON bierzemy obserwacje, a nie poprawki ręczne ani informacje HTTP —
/// poprawki żyją osobno (A6), a HTTP i detekcje policzy ponownie fingerprinting.
fn clean_imported(hosts: Vec<Host>) -> Vec<Host> {
    hosts
        .into_iter()
        .map(|mut host| {
            host.note = None;
            host.edited_fields.clear();
            for service in &mut host.services {
                service.note = None;
                service.edited_fields.clear();
                service.http = None;
                service.detections.clear();
            }
            host
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct CsvRow {
    ip: IpAddr,
    #[serde(default)]
    hostname: String,
    port: u16,
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    version: String,
}

fn hosts_from_csv(content: &str) -> Result<Vec<Host>, ImportError> {
    let mut reader = csv::ReaderBuilder::new()
        .trim(csv::Trim::All)
        .flexible(true)
        .from_reader(content.as_bytes());
    let mut hosts: BTreeMap<IpAddr, Host> = BTreeMap::new();
    for (index, row) in reader.deserialize::<CsvRow>().enumerate() {
        let row =
            row.map_err(|error| ImportError::InvalidCsv(format!("wiersz {}: {error}", index + 2)))?;
        let host = hosts
            .entry(row.ip)
            .or_insert_with(|| Host::new(row.ip, Utc::now()));
        if !row.hostname.is_empty() && !host.hostnames.contains(&row.hostname) {
            host.hostnames.push(row.hostname.clone());
        }
        let protocol = map_protocol(&row.protocol).unwrap_or(Protocol::Tcp);
        let state = if row.state.is_empty() {
            ServiceState::Open
        } else {
            map_port_state(&row.state)
        };
        let mut service = Service::new(row.port, protocol, state);
        let non_empty = |text: String| (!text.is_empty()).then_some(text);
        service.name = non_empty(row.service);
        service.product = non_empty(row.product);
        service.version = non_empty(row.version);
        host.services.push(service);
    }
    Ok(hosts.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_are_detected() {
        assert_eq!(
            detect_result_format(Path::new("wynik.XML")),
            Ok(ResultFormat::NmapXml)
        );
        assert_eq!(parse_result_format("nmap-xml"), Some(ResultFormat::NmapXml));
        assert!(detect_result_format(Path::new("a.txt")).is_err());
    }

    #[test]
    fn csv_rows_are_grouped_by_host() {
        let csv = "ip,hostname,port,protocol,state,service,product,version\n\
                   10.0.0.5,app.lab,22,tcp,open,ssh,OpenSSH,9.6\n10.0.0.5,,80,tcp,open,http,nginx,1.24\n10.0.0.6,,53,udp,,domain,,\n";
        let hosts = parse_results(csv, ResultFormat::Csv).unwrap().hosts;
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].hostnames, vec!["app.lab"]);
        assert_eq!(hosts[0].services.len(), 2);
        assert_eq!(hosts[1].services[0].protocol, Protocol::Udp);
        assert_eq!(hosts[1].services[0].product, None);
    }

    #[test]
    fn invalid_csv_row_is_reported() {
        let error = parse_results("ip,port\nnie-ip,80\n", ResultFormat::Csv).unwrap_err();
        assert!(error.to_string().contains("wiersz 2"), "{error}");
    }

    #[test]
    fn json_round_trip_drops_manual_edits() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        host.note = Some("notatka".into());
        let mut service = Service::new(80, Protocol::Tcp, ServiceState::Open);
        service.edited_fields = vec!["product".into()];
        host.services.push(service);
        let json = serde_json::to_string(&vec![host]).unwrap();

        let hosts = parse_results(&json, ResultFormat::Json).unwrap().hosts;
        assert_eq!(hosts[0].note, None);
        assert!(hosts[0].services[0].edited_fields.is_empty());
    }

    #[test]
    fn nmap_xml_keeps_raw_document() {
        let xml = r#"<nmaprun version="7.94"><host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/></host></nmaprun>"#;
        let parsed = parse_results(xml, ResultFormat::NmapXml).unwrap();
        assert_eq!(parsed.hosts.len(), 1);
        assert_eq!(parsed.raw_xml.as_deref(), Some(xml));
    }
}
