/// Rodzaj skanu nmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmapProfile {
    /// Wykrywanie aktywnych hostów bez skanowania portów (`-sn`).
    Discovery,
    /// Skan portów z rozpoznawaniem usług i wersji (`-sV`).
    Services,
}

/// Parametry jednego uruchomienia nmap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapOptions {
    pub profile: NmapProfile,
    /// Porty w składni nmap, np. `22,80,8000-8100` (używane tylko w profilu `Services`).
    pub ports: String,
    /// Limit pakietów na sekundę (`--max-rate`).
    pub max_rate: u32,
}

/// Argumenty nmap dla podanych opcji. Cele nie są w argumentach — `-iL -` czyta je
/// ze standardowego wejścia, dzięki czemu długa lista nie przekroczy limitu linii poleceń.
pub fn build_nmap_args(options: &NmapOptions) -> Vec<String> {
    let mut args: Vec<String> = match options.profile {
        NmapProfile::Discovery => vec!["-sn".into()],
        NmapProfile::Services => vec!["-sV".into(), "-p".into(), options.ports.clone()],
    };
    args.extend([
        // Bez odwrotnego DNS: szybciej i bez dodatkowego ruchu (domeny rozwiązujemy sami).
        "-n".to_string(),
        "--max-rate".to_string(),
        options.max_rate.to_string(),
        // Wynik XML na standardowe wyjście.
        "-oX".to_string(),
        "-".to_string(),
        "-iL".to_string(),
        "-".to_string(),
    ]);
    args
}

/// Porty z konfiguracji (`["22", "8000-8100"]`) w składni nmap (`22,8000-8100`).
pub fn ports_argument(allowed_ports: &[String]) -> String {
    allowed_ports
        .iter()
        .map(|port| port.trim())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(profile: NmapProfile) -> NmapOptions {
        NmapOptions {
            profile,
            ports: "22,80".to_string(),
            max_rate: 50,
        }
    }

    #[test]
    fn discovery_uses_ping_scan_without_ports() {
        let args = build_nmap_args(&options(NmapProfile::Discovery));
        assert_eq!(args[0], "-sn");
        assert!(!args.contains(&"-p".to_string()));
    }

    #[test]
    fn services_scan_versions_on_given_ports() {
        let args = build_nmap_args(&options(NmapProfile::Services));
        assert_eq!(&args[..3], ["-sV", "-p", "22,80"]);
    }

    #[test]
    fn rate_limit_xml_output_and_stdin_targets_are_always_set() {
        for profile in [NmapProfile::Discovery, NmapProfile::Services] {
            let args = build_nmap_args(&options(profile)).join(" ");
            assert!(args.contains("--max-rate 50"));
            assert!(args.contains("-oX -"));
            assert!(args.ends_with("-iL -"));
            assert!(args.contains("-n"));
        }
    }

    #[test]
    fn ports_are_joined_with_commas() {
        let ports = vec![
            "22".to_string(),
            " 80 ".to_string(),
            "8000-8100".to_string(),
        ];
        assert_eq!(ports_argument(&ports), "22,80,8000-8100");
    }
}
