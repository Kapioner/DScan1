//! Teksty wyświetlane przez `dscan scan`: postęp, podsumowanie i lista hostów.

use std::fmt::Write;

use chrono::TimeDelta;
use dscan_core::models::{Host, Service};
use dscan_engine::{ScanJobSummary, ScanProgress, SubgroupReport};

/// Np. `[2/4] podgrupa 3: 256 adresów, 2 hosty, 12.3 s | 50% | pozostało ok. 0:24`.
pub fn format_progress_line(
    report: &SubgroupReport,
    progress: &ScanProgress,
    elapsed: TimeDelta,
) -> String {
    let outcome = match &report.error {
        Some(error) => format!("BŁĄD: {error}"),
        None => format!(
            "{} hostów, {} otwartych portów",
            report.hosts, report.open_ports
        ),
    };
    let remaining = match progress.estimated_remaining(progress.started_at + elapsed) {
        Some(eta) if progress.finished_subgroups < progress.total_subgroups => {
            format!(" | pozostało ok. {}", format_duration(eta))
        }
        _ => String::new(),
    };
    format!(
        "[{}/{}] podgrupa {}: {} adresów, {}, {:.1} s | {:.0}%{remaining}",
        progress.finished_subgroups,
        progress.total_subgroups,
        report.index + 1,
        report.addresses,
        outcome,
        report.duration.num_milliseconds() as f64 / 1000.0,
        progress.percent()
    )
}

/// Czas w formacie `m:ss` albo `h:mm:ss`.
pub fn format_duration(duration: TimeDelta) -> String {
    let total = duration.num_seconds().max(0);
    let (hours, minutes, seconds) = (total / 3600, total / 60 % 60, total % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// Podsumowanie przebiegu.
pub fn format_summary(summary: &ScanJobSummary) -> String {
    let failed = if summary.failed_subgroups > 0 {
        format!(", nieudane podgrupy: {}", summary.failed_subgroups)
    } else {
        String::new()
    };
    format!(
        "Przebieg #{} zakończony ({}) w {}: {} podgrup{failed}. Wyniki zapisano w bazie.\n",
        summary.run_id,
        summary.status.as_str(),
        format_duration(summary.duration),
        summary.subgroups
    )
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
    let port = format!("{}/{}", service.port, service.protocol.as_str());
    let product = [service.product.as_deref(), service.version.as_deref()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "{port:<9} {:<9} {:<10} {product}",
        service.state.as_str(),
        service.name.as_deref().unwrap_or("?")
    )
    .trim_end()
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{Protocol, ScanStatus, ServiceState};

    fn ssh() -> Service {
        let mut service = Service::new(22, Protocol::Tcp, ServiceState::Open);
        service.name = Some("ssh".into());
        service.product = Some("OpenSSH".into());
        service.version = Some("9.6p1".into());
        service
    }

    fn progress_after_first_of_four() -> ScanProgress {
        let mut progress = ScanProgress::new(5, Utc::now(), 4, 1024);
        progress.record(256, false);
        progress
    }

    fn report(error: Option<&str>) -> SubgroupReport {
        SubgroupReport {
            index: 0,
            addresses: 256,
            hosts: 2,
            open_ports: 3,
            duration: TimeDelta::milliseconds(12_300),
            error: error.map(String::from),
        }
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

    #[test]
    fn durations_are_formatted() {
        assert_eq!(format_duration(TimeDelta::seconds(5)), "0:05");
        assert_eq!(format_duration(TimeDelta::seconds(125)), "2:05");
        assert_eq!(format_duration(TimeDelta::seconds(3725)), "1:02:05");
        assert_eq!(format_duration(TimeDelta::seconds(-3)), "0:00");
    }

    #[test]
    fn progress_line_has_counts_percent_and_eta() {
        let line = format_progress_line(
            &report(None),
            &progress_after_first_of_four(),
            TimeDelta::seconds(20),
        );
        assert_eq!(
            line,
            "[1/4] podgrupa 1: 256 adresów, 2 hostów, 3 otwartych portów, 12.3 s | 25% | pozostało ok. 1:00"
        );
    }

    #[test]
    fn progress_line_shows_error() {
        let line = format_progress_line(
            &report(Some("nmap padł")),
            &progress_after_first_of_four(),
            TimeDelta::seconds(20),
        );
        assert!(line.contains("BŁĄD: nmap padł"));
    }

    #[test]
    fn summary_mentions_failures() {
        let summary = ScanJobSummary {
            run_id: 3,
            status: ScanStatus::Failed,
            duration: TimeDelta::seconds(65),
            subgroups: 4,
            failed_subgroups: 1,
            hosts: Vec::new(),
        };
        assert_eq!(
            format_summary(&summary),
            "Przebieg #3 zakończony (failed) w 1:05: 4 podgrup, nieudane podgrupy: 1. Wyniki zapisano w bazie.\n"
        );
    }
}
