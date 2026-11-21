use ipnet::IpNet;

/// Czy cała sieć `target` mieści się w którejś z dozwolonych sieci.
/// Sieć tylko częściowo dozwolona jest traktowana jako niedozwolona (bezpieczniej).
pub fn is_in_scope(target: &IpNet, allowed: &[IpNet]) -> bool {
    allowed
        .iter()
        .any(|allowed_net| allowed_net.contains(target))
}

/// Dzieli sieci na dozwolone i spoza zakresu `[scope] allowed_networks`.
pub fn partition_by_scope(targets: Vec<IpNet>, allowed: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    targets
        .into_iter()
        .partition(|target| is_in_scope(target, allowed))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    #[test]
    fn target_inside_allowed_network_is_in_scope() {
        let allowed = [net("10.0.0.0/16")];
        assert!(is_in_scope(&net("10.0.5.0/24"), &allowed));
        assert!(is_in_scope(&net("10.0.0.1/32"), &allowed));
    }

    #[test]
    fn partially_overlapping_target_is_out_of_scope() {
        assert!(!is_in_scope(&net("10.0.0.0/8"), &[net("10.0.0.0/16")]));
    }

    #[test]
    fn empty_allowed_list_rejects_everything() {
        assert!(!is_in_scope(&net("10.0.0.1/32"), &[]));
    }

    #[test]
    fn partition_splits_targets() {
        let (inside, outside) = partition_by_scope(
            vec![net("10.0.0.1/32"), net("192.168.1.1/32")],
            &[net("10.0.0.0/8")],
        );
        assert_eq!(inside, vec![net("10.0.0.1/32")]);
        assert_eq!(outside, vec![net("192.168.1.1/32")]);
    }
}
