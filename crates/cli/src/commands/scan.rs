use std::fmt::Write;
use std::path::PathBuf;

use clap::{Args, ValueEnum};
use dscan_core::models::{Host, Service};
use dscan_scanner::nmap::{NmapCommand, NmapOptions, NmapProfile, ports_argument, run_scan};

use super::targets::{build_plan, format_plan};
use super::{Command, Context, OverrideArgs};
use crate::error::CliError;

/// Rodzaj skanu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScanMode {
    /// Tylko wykrywanie aktywnych hostów (nmap -sn).
    Discovery,
    /// Porty z [scope] allowed_ports i rozpoznawanie usług (nmap -sV).
    Services,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Cele: adresy IP, sieci CIDR lub domeny. Skanowane są tylko cele z [scope] allowed_networks.
    #[arg(required = true, value_name = "CEL")]
    pub targets: Vec<String>,
    /// Rodzaj skanu.
    #[arg(long, value_enum, default_value_t = ScanMode::Services)]
    pub mode: ScanMode,
    /// Zapisuje surowy wynik XML nmap do pliku (np. do importu w DefectDojo).
    #[arg(long, value_name = "PLIK")]
    pub xml: Option<PathBuf>,
    #[command(flatten)]
    pub overrides: OverrideArgs,
}

impl Command for ScanArgs {
    /// Skan lokalny: nmap uruchamiany bezpośrednio z tej binarki. Po wdrożeniu RBAC (C5)
    /// polecenie będzie zlecać skan przez API, a wyniki trafią do bazy (S4, B5).
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let config = context.load_config(self.overrides.to_overrides())?;
        let plan = build_plan(&config, &self.targets).await?;
        eprint!("{}", format_plan(&plan));
        if plan.networks.is_empty() {
            return Err(CliError::NoTargetsInScope);
        }

        let options = NmapOptions {
            profile: match self.mode {
                ScanMode::Discovery => NmapProfile::Discovery,
                ScanMode::Services => NmapProfile::Services,
            },
            ports: ports_argument(&config.settings.scope.allowed_ports),
            max_rate: config.settings.limits.nmap_max_rate,
        };
        eprintln!("Uruchamiam nmap (--max-rate {})…", options.max_rate);
        let output = run_scan(&NmapCommand::default(), &options, &plan.networks).await?;

        if let Some(path) = &self.xml {
            std::fs::write(path, &output.raw_xml).map_err(|source| CliError::File {
                path: path.clone(),
                source,
            })?;
            eprintln!("Surowy XML zapisano w {}", path.display());
        }
        print!("{}", format_hosts(&output.hosts));
        Ok(())
    }
}

/// Wynik skanu: hosty z usługami i podsumowanie.
pub fn format_hosts(hosts: &[Host]) -> String {
    let mut text = String::new();
    // Zapis do String nie może się nie udać, więc wyniki writeln! są pomijane.
    for host in hosts {
        let names = if host.hostnames.is_empty() {
            String::new()
        } else {
            format!(" ({})", host.hostnames.join(", "))
        };
        let _ = writeln!(text, "{}{names}", host.ip);
        for service in &host.services {
            let _ = writeln!(text, "  {}", format_service(service));
        }
    }
    let open_ports: usize = hosts.iter().map(Host::open_port_count).sum();
    let _ = writeln!(
        text,
        "Aktywne hosty: {}, otwarte porty: {open_ports}",
        hosts.len()
    );
    text
}

/// Jedna usługa, np. `22/tcp    open      ssh        OpenSSH 9.6p1`.
pub fn format_service(service: &Service) -> String {
    let port = format!("{}/{}", service.port, protocol_name(service));
    let state = format!("{:?}", service.state).to_lowercase();
    let product = [service.product.as_deref(), service.version.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{port:<9} {state:<9} {:<10} {product}",
        service.name.as_deref().unwrap_or("?")
    )
    .trim_end()
    .to_string()
}

fn protocol_name(service: &Service) -> &'static str {
    match service.protocol {
        dscan_core::models::Protocol::Tcp => "tcp",
        dscan_core::models::Protocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{Protocol, ServiceState};

    fn ssh() -> Service {
        let mut service = Service::new(22, Protocol::Tcp, ServiceState::Open);
        service.name = Some("ssh".into());
        service.product = Some("OpenSSH".into());
        service.version = Some("9.6p1".into());
        service
    }

    #[test]
    fn service_line_shows_port_state_and_product() {
        assert_eq!(
            format_service(&ssh()),
            "22/tcp    open      ssh        OpenSSH 9.6p1"
        );
    }

    #[test]
    fn service_without_details_has_question_mark() {
        let service = Service::new(53, Protocol::Udp, ServiceState::Filtered);
        assert_eq!(format_service(&service), "53/udp    filtered  ?");
    }

    #[test]
    fn hosts_report_has_summary() {
        let mut host = Host::new("10.0.0.5".parse().unwrap(), Utc::now());
        host.hostnames = vec!["app.lab.local".into()];
        host.services = vec![ssh()];

        let report = format_hosts(&[host]);

        assert!(report.starts_with("10.0.0.5 (app.lab.local)\n"));
        assert!(report.ends_with("Aktywne hosty: 1, otwarte porty: 1\n"));
    }
}
