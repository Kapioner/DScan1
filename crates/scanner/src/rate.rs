//! Ograniczanie tempa skanów nmap (zadanie S7).
//!
//! `limits.nmap_max_rate` to limit **łączny** dla wszystkich procesów nmap, więc przy kilku
//! równoległych podgrupach każdy proces dostaje swoją część. Dodatkowo tempo nie może
//! przekroczyć przepustowości z `scope.max_bandwidth_kbps`.

/// Przybliżony rozmiar pakietu sondy nmap w bajtach (SYN z opcjami TCP w ramce Ethernet).
/// Sondy `-sV` bywają większe, więc limit z przepustowości jest szacunkiem.
pub const PROBE_PACKET_BYTES: u64 = 74;

/// Ile pakietów na sekundę mieści się w przepustowości `bandwidth_kbps` (co najmniej 1).
pub fn bandwidth_packet_rate(bandwidth_kbps: u32) -> u32 {
    let bytes_per_second = u64::from(bandwidth_kbps) * 1000 / 8;
    let packets = (bytes_per_second / PROBE_PACKET_BYTES).max(1);
    u32::try_from(packets).unwrap_or(u32::MAX)
}

/// Łączne tempo: mniejsza z wartości `max_rate` i limitu wynikającego z przepustowości.
pub fn effective_packet_rate(max_rate: u32, bandwidth_kbps: u32) -> u32 {
    max_rate.min(bandwidth_packet_rate(bandwidth_kbps))
}

/// Tempo jednego procesu przy `processes` równoległych procesach (co najmniej 1 pakiet/s).
pub fn per_process_rate(total_rate: u32, processes: u32) -> u32 {
    (total_rate / processes.max(1)).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_is_converted_to_packets() {
        // 512 kbit/s = 64 000 B/s → 864 pakiety po 74 B.
        assert_eq!(bandwidth_packet_rate(512), 864);
        assert_eq!(bandwidth_packet_rate(0), 1);
    }

    #[test]
    fn effective_rate_takes_the_stricter_limit() {
        assert_eq!(effective_packet_rate(100, 512), 100);
        assert_eq!(effective_packet_rate(5000, 512), 864);
    }

    #[test]
    fn total_rate_is_shared_between_processes() {
        assert_eq!(per_process_rate(100, 4), 25);
        assert_eq!(per_process_rate(100, 1), 100);
        assert_eq!(per_process_rate(3, 4), 1);
        assert_eq!(per_process_rate(100, 0), 100);
    }
}
