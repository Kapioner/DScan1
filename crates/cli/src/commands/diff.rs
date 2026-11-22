use std::fmt::Write;

use clap::Args;
use dscan_core::models::Change;

use super::output::OutputFormat;
use super::{Command, Context};
use crate::client::commands::diff_via_api;
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Numer starszego przebiegu.
    #[arg(value_name = "PRZEBIEG_A")]
    pub previous_run: i64,
    /// Numer nowszego przebiegu.
    #[arg(value_name = "PRZEBIEG_B")]
    pub current_run: i64,
    /// Format wyniku. Kod wyjścia: 0 — brak zmian, 2 — są zmiany, 1 — błąd.
    #[arg(long, value_enum, default_value_t)]
    pub output: OutputFormat,
}

impl Command for DiffArgs {
    /// Porównanie dwóch dowolnych przebiegów (M1) przez API — liczone na bieżąco, bez zapisu.
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        diff_via_api(self.previous_run, self.current_run, self.output).await
    }
}

/// Raport zmian, np. `+ 10.0.0.5:8080/tcp  nowa`.
pub fn format_changes(previous_run: i64, current_run: i64, changes: &[Change]) -> String {
    let mut text = format!(
        "Zmiany #{previous_run} → #{current_run}: {}\n",
        summarize(changes)
    );
    for change in changes {
        let mark = match change.kind {
            dscan_core::models::ChangeKind::Appeared => '+',
            dscan_core::models::ChangeKind::Disappeared => '-',
            dscan_core::models::ChangeKind::Modified => '~',
        };
        let address = format!(
            "{}:{}/{}",
            change.key.ip,
            change.key.port,
            change.key.protocol.as_str()
        );
        // Zapis do String nie może się nie udać.
        let _ = writeln!(text, "  {mark} {address:<28} {}", change.kind.label());
    }
    text
}

/// Np. `1 nowa, 0 zniknęło, 2 zmienione` albo `brak zmian`.
pub fn summarize(changes: &[Change]) -> String {
    use dscan_core::models::ChangeKind;
    if changes.is_empty() {
        return "brak zmian".into();
    }
    let count = |kind: ChangeKind| changes.iter().filter(|change| change.kind == kind).count();
    format!(
        "nowe: {}, zniknęły: {}, zmienione: {}",
        count(ChangeKind::Appeared),
        count(ChangeKind::Disappeared),
        count(ChangeKind::Modified)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use dscan_core::models::{ChangeKind, Protocol, ServiceKey};

    fn change(port: u16, kind: ChangeKind) -> Change {
        Change {
            key: ServiceKey {
                ip: "10.0.0.5".parse().unwrap(),
                port,
                protocol: Protocol::Tcp,
            },
            kind,
            previous_run_id: 1,
            current_run_id: 2,
            previous_fingerprint: None,
            current_fingerprint: None,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn report_lists_changes_with_marks() {
        let text = format_changes(
            1,
            2,
            &[
                change(80, ChangeKind::Modified),
                change(8080, ChangeKind::Appeared),
            ],
        );
        assert!(text.starts_with("Zmiany #1 → #2: nowe: 1, zniknęły: 0, zmienione: 1\n"));
        assert!(text.contains("~ 10.0.0.5:80/tcp"));
        assert!(text.contains("+ 10.0.0.5:8080/tcp"));
    }

    #[test]
    fn no_changes_is_stated() {
        assert_eq!(format_changes(1, 2, &[]), "Zmiany #1 → #2: brak zmian\n");
    }
}
