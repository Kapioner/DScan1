use std::fmt;

use serde::{Deserialize, Serialize};

/// Zakres portów `start..=end` (obie granice włącznie).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    /// Czy port należy do zakresu.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// Liczba portów w zakresie.
    pub fn port_count(&self) -> u32 {
        u32::from(self.end) - u32::from(self.start) + 1
    }
}

/// Błąd parsowania zakresu portów — zawiera tekst, którego nie udało się odczytać.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRangeError(pub String);

impl fmt::Display for PortRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "niepoprawny zakres portów '{}' (oczekiwano np. \"443\" lub \"8000-8100\", porty 1-65535)",
            self.0
        )
    }
}

impl std::error::Error for PortRangeError {}

/// Parsuje zapis `"443"` albo `"8000-8100"`. Port 0 jest odrzucany.
pub fn parse_port_range(text: &str) -> Result<PortRange, PortRangeError> {
    let error = || PortRangeError(text.to_string());
    let trimmed = text.trim();

    let (start, end) = match trimmed.split_once('-') {
        Some((start, end)) => (parse_port(start), parse_port(end)),
        None => (parse_port(trimmed), parse_port(trimmed)),
    };

    match (start, end) {
        (Some(start), Some(end)) if start <= end => Ok(PortRange { start, end }),
        _ => Err(error()),
    }
}

fn parse_port(text: &str) -> Option<u16> {
    match text.trim().parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(port) => Some(port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        assert_eq!(
            parse_port_range("443"),
            Ok(PortRange {
                start: 443,
                end: 443
            })
        );
    }

    #[test]
    fn parses_range_with_spaces() {
        assert_eq!(
            parse_port_range(" 8000 - 8100 "),
            Ok(PortRange {
                start: 8000,
                end: 8100
            })
        );
    }

    #[test]
    fn rejects_invalid_ranges() {
        for text in ["", "0", "abc", "100-50", "1-70000", "80-", "-80"] {
            assert!(parse_port_range(text).is_err(), "powinno odrzucić: {text}");
        }
    }

    #[test]
    fn contains_checks_both_bounds() {
        let range = PortRange { start: 80, end: 90 };
        assert!(range.contains(80));
        assert!(range.contains(90));
        assert!(!range.contains(79));
        assert!(!range.contains(91));
    }

    #[test]
    fn port_count_includes_both_ends() {
        assert_eq!(PortRange { start: 1, end: 1 }.port_count(), 1);
        assert_eq!(
            PortRange {
                start: 1,
                end: 65535
            }
            .port_count(),
            65535
        );
    }
}
