//! Struktury odpowiadające formatowi XML nmap (`-oX`). Zawierają tylko pola, których
//! używamy — pozostałe elementy i atrybuty są pomijane. Atrybuty mają w serde prefiks `@`.

use serde::Deserialize;

use crate::ScannerError;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct NmapRun {
    #[serde(rename = "@version", default)]
    pub version: String,
    #[serde(rename = "host", default)]
    pub hosts: Vec<XmlHost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlHost {
    pub status: XmlStatus,
    #[serde(rename = "address", default)]
    pub addresses: Vec<XmlAddress>,
    pub hostnames: Option<XmlHostnames>,
    pub ports: Option<XmlPorts>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlStatus {
    #[serde(rename = "@state")]
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlAddress {
    #[serde(rename = "@addr")]
    pub addr: String,
    #[serde(rename = "@addrtype")]
    pub addrtype: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlHostnames {
    #[serde(rename = "hostname", default)]
    pub names: Vec<XmlHostname>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlHostname {
    #[serde(rename = "@name")]
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlPorts {
    #[serde(rename = "port", default)]
    pub ports: Vec<XmlPort>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlPort {
    #[serde(rename = "@protocol")]
    pub protocol: String,
    #[serde(rename = "@portid")]
    pub port: u16,
    pub state: XmlPortState,
    pub service: Option<XmlService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlPortState {
    #[serde(rename = "@state")]
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct XmlService {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@product")]
    pub product: Option<String>,
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "cpe", default)]
    pub cpe: Vec<String>,
}

/// Parsuje wynik `nmap -oX`.
pub fn parse_nmap_xml(xml: &str) -> Result<NmapRun, ScannerError> {
    quick_xml::de::from_str(xml).map_err(|error| ScannerError::InvalidNmapOutput(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = include_str!("../../tests/fixtures/services_scan.xml");

    #[test]
    fn parses_hosts_including_down_ones() {
        let run = parse_nmap_xml(SAMPLE).unwrap();
        assert_eq!(run.version, "7.94SVN");
        assert_eq!(run.hosts.len(), 2);
        assert_eq!(run.hosts[1].status.state, "down");
    }

    #[test]
    fn parses_ports_services_and_cpe() {
        let run = parse_nmap_xml(SAMPLE).unwrap();
        let ports = &run.hosts[0].ports.as_ref().unwrap().ports;

        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 22);
        let ssh = ports[0].service.as_ref().unwrap();
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(
            ssh.cpe,
            vec!["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]
        );
    }

    #[test]
    fn hostnames_are_parsed() {
        let run = parse_nmap_xml(SAMPLE).unwrap();
        let names = &run.hosts[0].hostnames.as_ref().unwrap().names;
        assert_eq!(names[0].name, "app.lab.local");
    }

    #[test]
    fn invalid_xml_is_an_error() {
        assert!(parse_nmap_xml("<nmaprun><host>").is_err());
    }

    #[test]
    fn empty_scan_has_no_hosts() {
        let run = parse_nmap_xml(r#"<nmaprun version="7.94"><runstats/></nmaprun>"#).unwrap();
        assert!(run.hosts.is_empty());
    }
}
