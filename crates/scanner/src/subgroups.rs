//! Podział celów na podgrupy (zadanie S4). Jedna podgrupa = jeden proces nmap.
//! Podgrupy są sieciami CIDR, więc zajmują mało miejsca i nmap przyjmuje je bezpośrednio.

use ipnet::IpNet;

use crate::targets::count_addresses;

/// Dzieli scalone sieci na podgrupy po najwyżej `size` adresów.
///
/// - sieć większa niż `size` jest cięta na podsieci tej wielkości (np. /16 → 256 × /24 dla 256),
/// - mniejsze sieci i pojedyncze adresy są łączone w jedną podgrupę, dopóki się mieszczą.
///
/// `size` jest zaokrąglane w dół do potęgi dwójki (konfiguracja i tak tego wymaga).
pub fn split_into_subgroups(networks: &[IpNet], size: u32) -> Vec<Vec<IpNet>> {
    let block = largest_power_of_two_at_most(size);
    let block_bits = block.trailing_zeros() as u8;
    let mut groups = Vec::new();
    let mut current: Vec<IpNet> = Vec::new();
    let mut current_count: u128 = 0;

    for network in networks {
        let count = count_addresses(std::slice::from_ref(network));
        if count > u128::from(block) {
            flush(&mut groups, &mut current, &mut current_count);
            let prefix = network.max_prefix_len() - block_bits;
            if let Ok(subnets) = network.subnets(prefix) {
                groups.extend(subnets.map(|subnet| vec![subnet]));
            }
            continue;
        }
        if current_count + count > u128::from(block) {
            flush(&mut groups, &mut current, &mut current_count);
        }
        current.push(*network);
        current_count += count;
    }
    flush(&mut groups, &mut current, &mut current_count);
    groups
}

fn flush(groups: &mut Vec<Vec<IpNet>>, current: &mut Vec<IpNet>, count: &mut u128) {
    if !current.is_empty() {
        groups.push(std::mem::take(current));
        *count = 0;
    }
}

fn largest_power_of_two_at_most(value: u32) -> u32 {
    1 << (31 - value.max(1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(texts: &[&str]) -> Vec<IpNet> {
        texts.iter().map(|text| text.parse().unwrap()).collect()
    }

    #[test]
    fn large_network_is_cut_into_blocks() {
        let groups = split_into_subgroups(&nets(&["10.0.0.0/22"]), 256);
        assert_eq!(
            groups,
            vec![
                nets(&["10.0.0.0/24"]),
                nets(&["10.0.1.0/24"]),
                nets(&["10.0.2.0/24"]),
                nets(&["10.0.3.0/24"])
            ]
        );
    }

    #[test]
    fn small_targets_are_packed_together() {
        let groups =
            split_into_subgroups(&nets(&["10.0.0.1/32", "10.0.0.8/30", "10.0.1.0/25"]), 256);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 3);
    }

    #[test]
    fn group_never_exceeds_size() {
        let groups =
            split_into_subgroups(&nets(&["10.0.0.0/25", "10.0.1.0/25", "10.0.2.0/25"]), 256);
        assert_eq!(groups.len(), 2);
        for group in &groups {
            assert!(count_addresses(group) <= 256);
        }
    }

    #[test]
    fn every_address_is_in_exactly_one_group() {
        let input = nets(&["10.0.0.0/20", "10.1.0.5/32", "10.2.0.0/26"]);
        let groups = split_into_subgroups(&input, 512);
        let total: u128 = groups.iter().map(|group| count_addresses(group)).sum();
        assert_eq!(total, count_addresses(&input));
    }

    #[test]
    fn size_is_rounded_down_to_power_of_two() {
        assert_eq!(largest_power_of_two_at_most(300), 256);
        assert_eq!(largest_power_of_two_at_most(0), 1);
        assert_eq!(split_into_subgroups(&nets(&["10.0.0.0/24"]), 200).len(), 2);
    }

    #[test]
    fn empty_input_gives_no_groups() {
        assert!(split_into_subgroups(&[], 256).is_empty());
    }
}
