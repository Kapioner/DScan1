use dscan_scanner::nmap::{NmapCommand, NmapOptions, NmapProfile};
use dscan_scanner::pool::NmapScanner;
use dscan_scanner::rate::{effective_packet_rate, per_process_rate};

/// Limity tempa z konfiguracji (`[limits]` i `[scope]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateSettings {
    /// Łączny limit pakietów/s (`limits.nmap_max_rate`).
    pub max_rate: u32,
    /// Przepustowość od organizatora (`scope.max_bandwidth_kbps`).
    pub bandwidth_kbps: u32,
    /// Liczba równoległych procesów nmap (`limits.max_parallel_nmap`).
    pub parallel: u32,
}

/// Tempo jednego procesu nmap: łączny limit (nie większy niż wynika z przepustowości)
/// podzielony przez liczbę równoległych procesów (zadanie S7).
pub fn rate_per_process(rate: RateSettings) -> u32 {
    let total = effective_packet_rate(rate.max_rate, rate.bandwidth_kbps);
    per_process_rate(total, rate.parallel)
}

/// Skaner podgrup nmap z tempem ustawionym tak, by suma procesów nie przekroczyła limitu.
pub fn nmap_scanner(profile: NmapProfile, ports: String, rate: RateSettings) -> NmapScanner {
    NmapScanner {
        command: NmapCommand::default(),
        options: NmapOptions {
            profile,
            ports,
            max_rate: rate_per_process(rate),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_rate_is_divided_between_processes() {
        let rate = RateSettings {
            max_rate: 100,
            bandwidth_kbps: 10_000,
            parallel: 4,
        };
        assert_eq!(rate_per_process(rate), 25);
    }

    #[test]
    fn bandwidth_limit_applies_before_division() {
        // 64 kbit/s ≈ 108 pakietów/s → 2 procesy po 54.
        let rate = RateSettings {
            max_rate: 1000,
            bandwidth_kbps: 64,
            parallel: 2,
        };
        assert_eq!(rate_per_process(rate), 54);
    }

    #[test]
    fn scanner_uses_per_process_rate() {
        let rate = RateSettings {
            max_rate: 100,
            bandwidth_kbps: 10_000,
            parallel: 2,
        };
        let scanner = nmap_scanner(NmapProfile::Discovery, String::new(), rate);
        assert_eq!(scanner.options.max_rate, 50);
    }
}
