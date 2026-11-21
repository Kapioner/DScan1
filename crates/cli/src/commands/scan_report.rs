//! Teksty wyświetlane przez `dscan scan`: postęp, podsumowanie i lista hostów.

use std::fmt::Write;

use chrono::TimeDelta;
use chrono::{DateTime, Utc};
use dscan_core::format::format_duration;
use dscan_core::models::{CertificateInfo, Detection, Host, HttpInfo, Service};
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

/// Podsumowanie przebiegu.
pub fn format_summary(summary: &ScanJobSummary) -> String {
    let failed = if summary.failed_subgroups > 0 {
        format!(", nieudane podgrupy: {}", summary.failed_subgroups)
    } else {
        String::new()
    };
    let mut text = format!(
        "Przebieg #{} zakończony ({}) w {}: {} podgrup{failed}. Wyniki zapisano w bazie.\n",
        summary.run_id,
        summary.status.as_str(),
        format_duration(summary.duration),
        summary.subgroups
    );
    if summary.status == dscan_core::models::ScanStatus::Paused {
        text.push_str(&format!(
            "Przebieg wstrzymany — wznowienie od niedokończonych podgrup: dscan resume {}\n",
            summary.run_id
        ));
    }
    if let Some(presence) = &summary.presence {
        text.push_str(&format!(
            "Obecność hostów: odpowiedziało {}, bez odpowiedzi {}",
            presence.responded, presence.missed
        ));
        if !presence.became_inactive.is_empty() {
            let ips: Vec<String> = presence
                .became_inactive
                .iter()
                .map(ToString::to_string)
                .collect();
            text.push_str(&format!(", nieaktywne od teraz: {}", ips.join(", ")));
        }
        if !presence.unstable.is_empty() {
            let ips: Vec<String> = presence.unstable.iter().map(ToString::to_string).collect();
            text.push_str(&format!(
                ", niestabilne (odpowiedziały przy powtórce): {}",
                ips.join(", ")
            ));
        }
        text.push('\n');
    }
    if let Some(comparison) = &summary.comparison {
        text.push_str(&crate::commands::diff::format_changes(
            comparison.previous_run_id,
            summary.run_id,
            &comparison.changes,
        ));
    }
    text
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
            if let Some(http) = &service.http {
                let _ = writeln!(text, "      {}", format_http(http));
            }
            if let Some(certificate) = service
                .http
                .as_ref()
                .and_then(|http| http.certificate.as_ref())
            {
                let _ = writeln!(
                    text,
                    "      {}",
                    format_certificate(certificate, Utc::now())
                );
            }
            for detection in &service.detections {
                let _ = writeln!(text, "      {}", format_detection(detection));
            }
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

/// Wynik HTTP pod usługą, np. `HTTP 200 „Panel logowania” (2 przekierowania, TLS niezweryfikowany)`.
pub fn format_http(http: &HttpInfo) -> String {
    let title = http
        .title
        .as_deref()
        .map(|title| format!(" „{title}”"))
        .unwrap_or_default();
    let mut notes = Vec::new();
    if !http.redirect_chain.is_empty() {
        notes.push(format!("przekierowania: {}", http.redirect_chain.len()));
    }
    if http.tls_verified == Some(false) {
        notes.push("TLS niezweryfikowany".to_string());
    }
    if let Some(server) = http.header("server") {
        notes.push(format!("Server: {server}"));
    }
    if let Some(favicon) = &http.favicon {
        notes.push(format!("favicon mmh3 {}", favicon.mmh3));
    }
    let notes = if notes.is_empty() {
        String::new()
    } else {
        format!(" ({})", notes.join(", "))
    };
    format!("HTTP {}{title}{notes}", http.status_code)
}

/// Np. `⚑ nginx 1.24.0 (90%: nagłówek server: nginx/1.24.0)` — z dowodami (H8).
pub fn format_detection(detection: &Detection) -> String {
    let version = detection
        .version
        .as_deref()
        .map(|v| format!(" {v}"))
        .unwrap_or_default();
    let evidence: Vec<&str> = detection
        .evidence
        .iter()
        .map(|e| e.description.as_str())
        .collect();
    format!(
        "⚑ {}{version} ({}%: {})",
        detection.technology,
        detection.confidence,
        evidence.join("; ")
    )
}

/// Np. `TLS: CN=app.lab.local, ważny do 2027-01-01, self-signed`.
pub fn format_certificate(certificate: &CertificateInfo, now: DateTime<Utc>) -> String {
    let name = certificate
        .common_name
        .as_deref()
        .unwrap_or(&certificate.subject);
    let mut notes = vec![format!(
        "ważny do {}",
        certificate.not_after.format("%Y-%m-%d")
    )];
    if certificate.is_expired(now) {
        notes.push("WYGASŁY".into());
    } else if certificate.days_left(now) < 30 {
        notes.push(format!("wygasa za {} dni", certificate.days_left(now)));
    }
    if certificate.self_signed {
        notes.push("self-signed".into());
    }
    format!(
        "TLS: CN={name}, {}, {}",
        notes.join(", "),
        certificate.signature_algorithm
    )
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
    fn http_line_shows_title_and_notes() {
        let http = HttpInfo {
            url: "https://10.0.0.5/".into(),
            status_code: 200,
            title: Some("Panel".into()),
            headers: vec![dscan_core::models::HttpHeader {
                name: "Server".into(),
                value: "nginx".into(),
            }],
            cookies: Vec::new(),
            redirect_chain: Vec::new(),
            tls_verified: Some(false),
            certificate: None,
            favicon: None,
        };
        assert_eq!(
            format_http(&http),
            "HTTP 200 „Panel” (TLS niezweryfikowany, Server: nginx)"
        );
    }

    #[test]
    fn certificate_line_flags_problems() {
        let certificate = CertificateInfo {
            subject: "CN=app".into(),
            common_name: Some("app.lab.local".into()),
            alt_names: Vec::new(),
            issuer: "CN=app".into(),
            not_before: "2026-01-01T00:00:00Z".parse().unwrap(),
            not_after: "2026-06-01T00:00:00Z".parse().unwrap(),
            signature_algorithm: "sha256WithRSAEncryption".into(),
            sha256: String::new(),
            self_signed: true,
        };
        let line = format_certificate(&certificate, "2026-11-21T00:00:00Z".parse().unwrap());
        assert_eq!(
            line,
            "TLS: CN=app.lab.local, ważny do 2026-06-01, WYGASŁY, self-signed, sha256WithRSAEncryption"
        );
    }

    #[test]
    fn detection_line_lists_evidence() {
        let detection = Detection::from_evidence(
            "nginx".into(),
            Some("1.24.0".into()),
            vec![dscan_core::models::Evidence {
                kind: dscan_core::models::EvidenceKind::Header,
                description: "nagłówek server: nginx/1.24.0".into(),
                weight: 90,
            }],
        );
        assert_eq!(
            format_detection(&detection),
            "⚑ nginx 1.24.0 (90%: nagłówek server: nginx/1.24.0)"
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
            comparison: None,
            presence: None,
        };
        assert_eq!(
            format_summary(&summary),
            "Przebieg #3 zakończony (failed) w 1:05: 4 podgrup, nieudane podgrupy: 1. Wyniki zapisano w bazie.\n"
        );
    }
}
