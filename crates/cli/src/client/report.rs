//! Formatowanie odpowiedzi API w terminalu.

use std::fmt::Write;

use super::types::{
    ChangeView, ResultImportResponse, ScanRunView, SignatureTestResponse, SignatureView,
    StartScanResponse, TargetImportResponse,
};

/// Plan skanu zwrócony przez serwer.
pub fn format_started(started: &StartScanResponse) -> String {
    let mut text = format!(
        "Przebieg #{}: {} adresów w sieciach {}\n",
        started.run_id,
        started.address_count,
        started.networks.join(", ")
    );
    for rejected in &started.rejected {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(text, "  pominięto {}: {}", rejected.target, rejected.reason);
    }
    if let Some(at) = started.stop_at {
        let _ = writeln!(
            text,
            "Koniec okna czasowego: {at} — wtedy skan zostanie wstrzymany."
        );
    }
    text
}

/// Linia postępu, np. `[ 40.0%] 2/5 podgrup, 12 s, zostało ~18 s`.
pub fn format_run_progress(run: &ScanRunView) -> String {
    let remaining = run
        .estimated_remaining_seconds
        .map(|s| format!(", zostało ~{s} s"))
        .unwrap_or_default();
    format!(
        "[{:>5.1}%] {}/{} podgrup, {} s{remaining}",
        run.progress_percent, run.completed_subgroups, run.total_subgroups, run.elapsed_seconds
    )
}

/// Zmiany, np. `+ 10.0.0.5:8080/tcp  nowa usługa`.
pub fn format_change_views(title: &str, changes: &[ChangeView]) -> String {
    let count = |kind: &str| changes.iter().filter(|c| c.kind == kind).count();
    let summary = if changes.is_empty() {
        "brak zmian".to_string()
    } else {
        format!(
            "nowe: {}, zniknęły: {}, zmienione: {}",
            count("appeared"),
            count("disappeared"),
            count("modified")
        )
    };
    let mut text = format!("{title}: {summary}\n");
    for change in changes {
        let mark = match change.kind.as_str() {
            "appeared" => '+',
            "disappeared" => '-',
            _ => '~',
        };
        let address = format!("{}:{}/{}", change.ip, change.port, change.protocol);
        let _ = writeln!(text, "  {mark} {address:<28} {}", change.label);
    }
    text
}

pub fn format_target_import(response: &TargetImportResponse, dry_run: bool) -> String {
    let mut text = format!(
        "Poprawne cele: {}, odrzucone wiersze: {}\n",
        response.accepted,
        response.rejected.len()
    );
    for row in &response.rejected {
        let _ = writeln!(
            text,
            "  wiersz {}: '{}' — {}",
            row.line, row.value, row.reason
        );
    }
    if dry_run {
        text.push_str("Tryb próbny — nic nie zapisano.\n");
    } else {
        let _ = writeln!(
            text,
            "Zapisano w bazie: {} nowych, {} już istniało.",
            response.inserted, response.duplicates
        );
    }
    text
}

pub fn format_result_import(response: &ResultImportResponse) -> String {
    let mut text = match response.run_id {
        Some(id) => format!(
            "Przebieg #{id}: {} hostów, {} otwartych portów\n",
            response.hosts, response.open_ports
        ),
        None => format!(
            "Tryb próbny: {} hostów, {} otwartych portów — nic nie zapisano\n",
            response.hosts, response.open_ports
        ),
    };
    if !response.out_of_scope.is_empty() {
        let _ = writeln!(
            text,
            "Poza zakresem [scope] (pominięte): {}",
            response.out_of_scope.join(", ")
        );
    }
    if !response.became_inactive.is_empty() {
        let _ = writeln!(
            text,
            "Hosty nieaktywne: {}",
            response.became_inactive.join(", ")
        );
    }
    if response.run_id.is_some() {
        text.push_str(&format_change_views(
            "Zmiany względem poprzedniego importu/skanu",
            &response.changes,
        ));
    }
    text
}

pub fn format_signatures(signatures: &[SignatureView]) -> String {
    let mut text = format!("{:<24} {:<16} {}\n", "SYGNATURA", "KATEGORIA", "MATCHERY");
    for s in signatures {
        let _ = writeln!(
            text,
            "{:<24} {:<16} {}",
            s.name,
            s.category.as_deref().unwrap_or_default(),
            s.matchers
        );
    }
    text
}

pub fn format_signature_test(response: &SignatureTestResponse, name: &str) -> String {
    let mut text = format!(
        "HTTP {} {} (sondy: {})\n",
        response.status_code, response.url, response.probes
    );
    if response.detections.is_empty() {
        let _ = writeln!(text, "Sygnatura „{name}” nie pasuje.");
    }
    for d in &response.detections {
        let version = d
            .version
            .as_deref()
            .map(|v| format!(" {v}"))
            .unwrap_or_default();
        let _ = writeln!(
            text,
            "{}{version} — pewność {}%",
            d.technology, d.confidence
        );
        for e in &d.evidence {
            let _ = writeln!(text, "  • {} (+{})", e.description, e.weight);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(kind: &str, port: u16) -> ChangeView {
        ChangeView {
            ip: "10.0.0.5".into(),
            port,
            protocol: "tcp".into(),
            kind: kind.into(),
            label: "x".into(),
        }
    }

    #[test]
    fn changes_have_marks_and_summary() {
        let text = format_change_views(
            "Zmiany #1 → #2",
            &[change("appeared", 8080), change("modified", 80)],
        );
        assert!(text.starts_with("Zmiany #1 → #2: nowe: 1, zniknęły: 0, zmienione: 1"));
        assert!(text.contains("+ 10.0.0.5:8080/tcp") && text.contains("~ 10.0.0.5:80/tcp"));
        assert!(format_change_views("Z", &[]).contains("brak zmian"));
    }

    #[test]
    fn progress_line_shows_estimate() {
        let run = ScanRunView {
            id: 1,
            status: "running".into(),
            progress_percent: 40.0,
            completed_subgroups: 2,
            total_subgroups: 5,
            elapsed_seconds: 12,
            estimated_remaining_seconds: Some(18),
        };
        assert_eq!(
            format_run_progress(&run),
            "[ 40.0%] 2/5 podgrup, 12 s, zostało ~18 s"
        );
    }
}
