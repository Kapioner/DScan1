//! Zabezpieczenia skanera (Q5): nmap uruchamiamy wyłącznie z wykrywaniem hostów i usług —
//! bez skryptów NSE (exploity, brute force, próby logowania), zawsze z limitem tempa
//! i tylko na portach z `[scope] allowed_ports`.

use dscan_core::models::parse_port_range;

use crate::ScannerError;

/// Opcje nmap, których DScan nigdy nie przekazuje: skrypty NSE (w tym kategorie exploit,
/// brute, intrusive, vuln, auth), skan agresywny (`-A` = m.in. skrypty domyślne), fałszowanie
/// źródła i omijanie zapór.
pub const FORBIDDEN_NMAP_OPTIONS: [&str; 10] =
    ["--script", "-sC", "-A", "--script-args", "-S", "-D", "--spoof-mac", "--data", "-f", "--badsum"];

/// Sprawdza argumenty nmap przed uruchomieniem procesu.
pub fn check_nmap_args(args: &[String]) -> Result<(), ScannerError> {
    if let Some(bad) = args.iter().find(|arg| {
        FORBIDDEN_NMAP_OPTIONS.iter().any(|forbidden| arg.as_str() == *forbidden || arg.starts_with(&format!("{forbidden}=")))
    }) {
        return Err(ScannerError::Forbidden(format!("niedozwolona opcja nmap: {bad}")));
    }
    if !args.iter().any(|arg| arg == "--max-rate") {
        return Err(ScannerError::Forbidden("brak limitu tempa (--max-rate)".into()));
    }
    Ok(())
}

/// Czy wszystkie porty `requested` mieszczą się w zakresach `allowed` (np. profil vs `[scope]`).
pub fn ports_within(requested: &[String], allowed: &[String]) -> bool {
    let allowed: Vec<_> = allowed.iter().filter_map(|p| parse_port_range(p).ok()).collect();
    requested.iter().all(|port| {
        parse_port_range(port).is_ok_and(|range| {
            // Każdy port zakresu musi być w którymś dozwolonym zakresie.
            (range.start..=range.end).all(|p| allowed.iter().any(|a| a.start <= p && p <= a.end))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nmap::{NmapOptions, NmapProfile, build_nmap_args};

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn generated_arguments_are_safe() {
        for profile in [NmapProfile::Discovery, NmapProfile::Services] {
            let options = NmapOptions {
                profile,
                ports: "22,80".into(),
                max_rate: 10,
                host_timeout_seconds: Some(60),
                max_retries: Some(1),
            };
            assert!(check_nmap_args(&build_nmap_args(&options)).is_ok());
        }
    }

    #[test]
    fn scripts_and_missing_rate_are_rejected() {
        assert!(check_nmap_args(&strings(&["-sV", "--script", "ssh-brute", "--max-rate", "5"])).is_err());
        assert!(check_nmap_args(&strings(&["-sV", "--script=vuln", "--max-rate", "5"])).is_err());
        assert!(check_nmap_args(&strings(&["-A", "--max-rate", "5"])).is_err());
        assert!(check_nmap_args(&strings(&["-sV"])).is_err());
    }

    #[test]
    fn ports_must_be_inside_scope() {
        let scope = strings(&["1-1024", "8080"]);
        assert!(ports_within(&strings(&["22", "80-90", "8080"]), &scope));
        assert!(!ports_within(&strings(&["8081"]), &scope));
        assert!(!ports_within(&strings(&["1000-2000"]), &scope));
    }
}
