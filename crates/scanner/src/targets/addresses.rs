use std::net::IpAddr;

use ipnet::{IpAddrRange, IpNet};

/// Sieć zawierająca dokładnie jeden adres (`/32` dla IPv4, `/128` dla IPv6).
pub fn single_address_network(ip: IpAddr) -> IpNet {
    IpNet::from(ip)
}

/// Scala nakładające się i sąsiednie sieci w najmniejszy możliwy zbiór
/// (np. `10.0.0.0/25` + `10.0.0.128/25` → `10.0.0.0/24`). To jest deduplikacja adresów
/// bez trzymania ich w pamięci. Wynik jest posortowany.
pub fn aggregate_networks(networks: &[IpNet]) -> Vec<IpNet> {
    IpNet::aggregate(&networks.to_vec())
}

/// Łączna liczba adresów w sieciach (nmap skanuje też adres sieci i rozgłoszeniowy).
/// Sieci powinny być wcześniej scalone, inaczej wspólne adresy zostaną policzone kilka razy.
pub fn count_addresses(networks: &[IpNet]) -> u128 {
    networks
        .iter()
        .map(|net| {
            let host_bits = u32::from(net.max_prefix_len() - net.prefix_len());
            1u128.checked_shl(host_bits).unwrap_or(u128::MAX)
        })
        .fold(0u128, u128::saturating_add)
}

/// Iterator po wszystkich adresach z listy sieci — kolejne adresy są wyliczane
/// na bieżąco, więc nawet duże zakresy nie zajmują pamięci.
#[derive(Debug, Clone)]
pub struct AddressIterator {
    networks: Vec<IpNet>,
    next_network: usize,
    current: Option<IpAddrRange>,
}

impl AddressIterator {
    /// Przyjmuje sieci już scalone przez [`aggregate_networks`] (bez powtórzeń adresów).
    pub fn new(networks: Vec<IpNet>) -> Self {
        AddressIterator {
            networks,
            next_network: 0,
            current: None,
        }
    }
}

impl Iterator for AddressIterator {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        loop {
            if let Some(address) = self.current.as_mut().and_then(Iterator::next) {
                return Some(address);
            }
            let network = self.networks.get(self.next_network)?;
            self.next_network += 1;
            self.current = Some(network_range(network));
        }
    }
}

/// Pełny zakres adresów sieci: od adresu sieci do rozgłoszeniowego włącznie.
fn network_range(network: &IpNet) -> IpAddrRange {
    match network {
        IpNet::V4(net) => {
            IpAddrRange::from(ipnet::Ipv4AddrRange::new(net.network(), net.broadcast()))
        }
        IpNet::V6(net) => {
            IpAddrRange::from(ipnet::Ipv6AddrRange::new(net.network(), net.broadcast()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(texts: &[&str]) -> Vec<IpNet> {
        texts.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn overlapping_networks_are_merged() {
        let merged = aggregate_networks(&nets(&["10.0.0.0/24", "10.0.0.5/32", "10.0.0.0/25"]));
        assert_eq!(merged, nets(&["10.0.0.0/24"]));
    }

    #[test]
    fn adjacent_networks_are_merged() {
        let merged = aggregate_networks(&nets(&["10.0.0.128/25", "10.0.0.0/25"]));
        assert_eq!(merged, nets(&["10.0.0.0/24"]));
    }

    #[test]
    fn count_includes_network_and_broadcast() {
        assert_eq!(count_addresses(&nets(&["10.0.0.0/24"])), 256);
        assert_eq!(count_addresses(&nets(&["10.0.0.1/32", "10.0.1.0/30"])), 5);
        assert_eq!(count_addresses(&nets(&["::/0"])), u128::MAX);
    }

    #[test]
    fn iterator_yields_every_address_once() {
        let addresses: Vec<IpAddr> =
            AddressIterator::new(nets(&["10.0.0.0/30", "10.0.0.9/32"])).collect();
        let expected: Vec<IpAddr> = ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.9"]
            .iter()
            .map(|text| text.parse().unwrap())
            .collect();
        assert_eq!(addresses, expected);
    }

    #[test]
    fn iterator_handles_large_ranges_lazily() {
        // /12 = ponad milion adresów; bierzemy tylko kilka, nic nie jest alokowane z góry.
        let mut iterator = AddressIterator::new(nets(&["10.0.0.0/12"]));
        assert_eq!(iterator.next(), Some("10.0.0.0".parse().unwrap()));
        assert_eq!(iterator.nth(65_535), Some("10.1.0.0".parse().unwrap()));
    }

    #[test]
    fn iterator_count_matches_count_addresses_for_20k() {
        let networks = aggregate_networks(&nets(&["10.0.0.0/18", "10.0.64.0/20"]));
        assert_eq!(
            AddressIterator::new(networks.clone()).count() as u128,
            count_addresses(&networks)
        );
        assert_eq!(count_addresses(&networks), 20_480);
    }

    #[test]
    fn single_address_network_has_full_prefix() {
        assert_eq!(
            single_address_network("10.0.0.1".parse().unwrap()).prefix_len(),
            32
        );
        assert_eq!(
            single_address_network("::1".parse().unwrap()).prefix_len(),
            128
        );
    }
}
