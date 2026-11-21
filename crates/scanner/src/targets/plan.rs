use dscan_core::models::TargetKind;
use ipnet::IpNet;

use super::{
    DomainResolver, aggregate_networks, count_addresses, parse_target, partition_by_scope,
    single_address_network,
};

/// Wynik przygotowania celów: co zeskanujemy i co odrzuciliśmy (z powodem).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetPlan {
    /// Scalone sieci w zakresie — gotowe do skanu.
    pub networks: Vec<IpNet>,
    pub address_count: u128,
    /// (wpis użytkownika, powód odrzucenia)
    pub invalid: Vec<(String, String)>,
    /// (domena, błąd DNS)
    pub unresolved: Vec<(String, String)>,
    /// Sieci poza `[scope] allowed_networks`.
    pub out_of_scope: Vec<IpNet>,
    /// Adresy rozwiązane z domen: (IP, domena) — nazwy przydają się w analizie (np. „staging.”).
    pub hostnames: Vec<(std::net::IpAddr, String)>,
}

/// Parsuje cele, rozwiązuje domeny, scala sieci i odrzuca cele spoza zakresu.
/// Pojedyncze błędne wpisy nie przerywają całości — trafiają do raportu.
pub async fn prepare_targets(
    inputs: &[String],
    resolver: &impl DomainResolver,
    allowed: &[IpNet],
) -> TargetPlan {
    let mut plan = TargetPlan::default();
    let mut networks = Vec::new();

    for input in inputs {
        match parse_target(input) {
            Ok(TargetKind::Ip(ip)) => networks.push(single_address_network(ip)),
            Ok(TargetKind::Cidr(net)) => networks.push(net),
            Ok(TargetKind::Domain(domain)) => match resolver.resolve(&domain).await {
                Ok(ips) if ips.is_empty() => {
                    plan.unresolved
                        .push((domain, "brak adresów IP".to_string()));
                }
                Ok(ips) => {
                    plan.hostnames
                        .extend(ips.iter().map(|ip| (*ip, domain.clone())));
                    networks.extend(ips.into_iter().map(single_address_network));
                }
                Err(reason) => plan.unresolved.push((domain, reason)),
            },
            Err(error) => plan.invalid.push((input.clone(), error.to_string())),
        }
    }

    let (in_scope, out_of_scope) = partition_by_scope(aggregate_networks(&networks), allowed);
    plan.address_count = count_addresses(&in_scope);
    plan.networks = in_scope;
    plan.out_of_scope = out_of_scope;
    plan
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::IpAddr;

    use super::*;

    /// Atrapa DNS: stała tablica domena → adresy.
    struct FakeResolver(HashMap<&'static str, Vec<IpAddr>>);

    impl DomainResolver for FakeResolver {
        async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, String> {
            self.0
                .get(domain)
                .cloned()
                .ok_or_else(|| "NXDOMAIN".to_string())
        }
    }

    fn resolver() -> FakeResolver {
        let mut map = HashMap::new();
        map.insert("app.lab.local", vec!["10.0.0.5".parse().unwrap()]);
        map.insert("outside.example", vec!["8.8.8.8".parse().unwrap()]);
        FakeResolver(map)
    }

    fn inputs(texts: &[&str]) -> Vec<String> {
        texts.iter().map(|text| text.to_string()).collect()
    }

    fn allowed() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().unwrap()]
    }

    #[tokio::test]
    async fn duplicates_and_overlaps_are_merged() {
        let plan = prepare_targets(
            &inputs(&["10.0.0.0/24", "10.0.0.5", "app.lab.local", "10.0.0.5"]),
            &resolver(),
            &allowed(),
        )
        .await;

        assert_eq!(plan.networks, vec!["10.0.0.0/24".parse::<IpNet>().unwrap()]);
        assert_eq!(plan.address_count, 256);
        assert_eq!(
            plan.hostnames,
            vec![("10.0.0.5".parse().unwrap(), "app.lab.local".to_string())]
        );
    }

    #[tokio::test]
    async fn problems_are_reported_not_fatal() {
        let plan = prepare_targets(
            &inputs(&["10.0.0.1", "zly cel", "nie-ma.lab.local", "outside.example"]),
            &resolver(),
            &allowed(),
        )
        .await;

        assert_eq!(plan.address_count, 1);
        assert_eq!(plan.invalid.len(), 1);
        assert_eq!(plan.unresolved[0].0, "nie-ma.lab.local");
        assert_eq!(
            plan.out_of_scope,
            vec!["8.8.8.8/32".parse::<IpNet>().unwrap()]
        );
    }
}
