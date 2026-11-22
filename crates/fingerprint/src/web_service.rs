use std::net::IpAddr;

use dscan_core::models::{Service, ServiceState};

/// Protokół, którym łączymy się z usługą WWW.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebScheme {
    Http,
    Https,
}

impl WebScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            WebScheme::Http => "http",
            WebScheme::Https => "https",
        }
    }
}

/// Czy usługa jest serwerem WWW i jak się z nią łączyć. Decyduje nazwa z nmap
/// (`http`, `http-proxy`, `ssl/http`, `https`…), a gdy jej brak — typowe porty.
pub fn web_scheme(service: &Service) -> Option<WebScheme> {
    if service.state != ServiceState::Open {
        return None;
    }
    match service.name.as_deref() {
        Some(name) if name.starts_with("ssl/http") || name.starts_with("https") => {
            Some(WebScheme::Https)
        }
        Some(name) if name.starts_with("http") => Some(WebScheme::Http),
        Some(_) => None,
        None => match service.port {
            443 | 8443 => Some(WebScheme::Https),
            80 | 8000 | 8080 => Some(WebScheme::Http),
            _ => None,
        },
    }
}

/// Usługi, których nazwa z nmap na pewno nie oznacza HTTP (nie próbujemy ich odpytywać).
const NON_WEB_SERVICES: [&str; 22] = [
    "ssh",
    "ftp",
    "ftp-data",
    "telnet",
    "smtp",
    "submission",
    "domain",
    "pop3",
    "imap",
    "ldap",
    "mysql",
    "postgresql",
    "redis",
    "amqp",
    "mongodb",
    "microsoft-ds",
    "netbios-ssn",
    "ms-sql-s",
    "rdp",
    "ms-wbt-server",
    "vnc",
    "rtsp",
];

/// Schematy do sprawdzenia dla usługi, od najbardziej prawdopodobnego. Oprócz usług
/// nazwanych przez nmap „http/https” próbujemy też usług niejednoznacznych (np. `tcpwrapped`,
/// nierozpoznanych albo rozpoznanych bez produktu — w laboratorium Gitea nmap nazwał „nessus”),
/// a dla HTTPS zapasowo zwykłe HTTP (np. dashboard Traefika odpowiada na obu).
pub fn web_candidates(service: &Service) -> Vec<WebScheme> {
    if service.state != ServiceState::Open || service.protocol != dscan_core::models::Protocol::Tcp
    {
        return Vec::new();
    }
    match web_scheme(service) {
        Some(WebScheme::Https) => vec![WebScheme::Https, WebScheme::Http],
        Some(WebScheme::Http) => vec![WebScheme::Http],
        None => {
            let name = service.name.as_deref().unwrap_or("").trim_end_matches('?');
            let known_other = NON_WEB_SERVICES.contains(&name)
                || name.starts_with("ssl/") && name != "ssl/unknown";
            let ambiguous = name.is_empty()
                || name == "tcpwrapped"
                || name == "unknown"
                || service.product.is_none();
            if !known_other && ambiguous {
                vec![WebScheme::Http, WebScheme::Https]
            } else {
                Vec::new()
            }
        }
    }
}

/// Adres strony głównej usługi, np. `https://[::1]:8443/`.
pub fn service_url(ip: IpAddr, port: u16, scheme: WebScheme) -> String {
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    format!("{}://{host}:{port}/", scheme.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dscan_core::models::Protocol;

    fn service(port: u16, name: Option<&str>) -> Service {
        let mut service = Service::new(port, Protocol::Tcp, ServiceState::Open);
        service.name = name.map(String::from);
        service
    }

    #[test]
    fn nmap_names_decide_scheme() {
        assert_eq!(
            web_scheme(&service(8080, Some("http-proxy"))),
            Some(WebScheme::Http)
        );
        assert_eq!(
            web_scheme(&service(443, Some("ssl/http"))),
            Some(WebScheme::Https)
        );
        assert_eq!(
            web_scheme(&service(9443, Some("https-alt"))),
            Some(WebScheme::Https)
        );
        assert_eq!(web_scheme(&service(22, Some("ssh"))), None);
    }

    #[test]
    fn well_known_ports_are_used_without_name() {
        assert_eq!(web_scheme(&service(443, None)), Some(WebScheme::Https));
        assert_eq!(web_scheme(&service(80, None)), Some(WebScheme::Http));
        assert_eq!(web_scheme(&service(5432, None)), None);
    }

    #[test]
    fn closed_ports_are_skipped() {
        let mut closed = service(80, Some("http"));
        closed.state = ServiceState::Closed;
        assert_eq!(web_scheme(&closed), None);
    }

    #[test]
    fn urls_for_ipv4_and_ipv6() {
        assert_eq!(
            service_url("10.0.0.5".parse().unwrap(), 80, WebScheme::Http),
            "http://10.0.0.5:80/"
        );
        assert_eq!(
            service_url("::1".parse().unwrap(), 8443, WebScheme::Https),
            "https://[::1]:8443/"
        );
    }
}
