use std::net::IpAddr;

use dscan_core::models::TargetKind;
use ipnet::IpNet;

use crate::ScannerError;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Rozpoznaje cel: adres IP, sieć CIDR albo nazwę domenową.
///
/// Sieć jest normalizowana do adresu sieci (`10.0.0.7/24` → `10.0.0.0/24`),
/// a domena do małych liter bez kropki na końcu.
pub fn parse_target(text: &str) -> Result<TargetKind, ScannerError> {
    let text = text.trim();
    let invalid = |reason: &str| ScannerError::InvalidTarget {
        input: text.to_string(),
        reason: reason.to_string(),
    };

    if text.is_empty() {
        return Err(invalid("pusty cel"));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(TargetKind::Ip(ip));
    }
    if text.contains('/') {
        return text
            .parse::<IpNet>()
            .map(|net| TargetKind::Cidr(net.trunc()))
            .map_err(|_| invalid("niepoprawna sieć CIDR (przykład: 10.0.0.0/24)"));
    }
    if is_valid_domain(text) {
        let domain = text.trim_end_matches('.').to_ascii_lowercase();
        return Ok(TargetKind::Domain(domain));
    }
    Err(invalid(
        "to nie jest adres IP, sieć CIDR ani poprawna nazwa domeny",
    ))
}

/// Nazwa domeny wg RFC 1123: etykiety 1–63 znaki (litery, cyfry, `-`, bez `-` na brzegach),
/// całość do 253 znaków. Ostatnia etykieta nie może być liczbą, żeby zły adres IP
/// (np. `300.1.1.1`) nie został uznany za domenę.
pub fn is_valid_domain(text: &str) -> bool {
    let name = text.strip_suffix('.').unwrap_or(text);
    if name.is_empty() || name.len() > MAX_DOMAIN_LEN {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let last_is_numeric = labels
        .last()
        .is_some_and(|label| label.chars().all(|c| c.is_ascii_digit()));
    !last_is_numeric && labels.iter().all(|label| is_valid_label(label))
}

fn is_valid_label(label: &str) -> bool {
    let allowed = |c: char| c.is_ascii_alphanumeric() || c == '-';
    !label.is_empty()
        && label.len() <= MAX_LABEL_LEN
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(allowed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6() {
        assert_eq!(
            parse_target("10.0.0.5").unwrap(),
            TargetKind::Ip("10.0.0.5".parse().unwrap())
        );
        assert_eq!(
            parse_target(" ::1 ").unwrap(),
            TargetKind::Ip("::1".parse().unwrap())
        );
    }

    #[test]
    fn parses_and_normalizes_cidr() {
        assert_eq!(
            parse_target("10.0.0.7/24").unwrap(),
            TargetKind::Cidr("10.0.0.0/24".parse().unwrap())
        );
    }

    #[test]
    fn parses_and_normalizes_domain() {
        assert_eq!(
            parse_target("Staging.Example.COM.").unwrap(),
            TargetKind::Domain("staging.example.com".to_string())
        );
    }

    #[test]
    fn rejects_invalid_input() {
        for text in [
            "",
            "   ",
            "10.0.0.0/33",
            "300.1.1.1",
            "-zly.pl",
            "a..b",
            "spacja w.pl",
            "x_y.pl",
        ] {
            assert!(parse_target(text).is_err(), "powinno odrzucić: {text:?}");
        }
    }

    #[test]
    fn domain_label_length_limits() {
        assert!(is_valid_domain(&format!("{}.pl", "a".repeat(63))));
        assert!(!is_valid_domain(&format!("{}.pl", "a".repeat(64))));
        assert!(!is_valid_domain(&format!("{}.pl", "a.".repeat(130))));
    }

    #[test]
    fn single_label_hostname_is_allowed() {
        assert!(is_valid_domain("intranet"));
    }
}
