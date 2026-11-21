use std::fmt::Write;

use chrono::Utc;
use clap::Args;
use dscan_config::CliOverrides;
use dscan_core::models::{Change, compare_runs};

use super::{Command, Context, connect_database};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Numer starszego przebiegu.
    #[arg(value_name = "PRZEBIEG_A")]
    pub previous_run: i64,
    /// Numer nowszego przebiegu.
    #[arg(value_name = "PRZEBIEG_B")]
    pub current_run: i64,
}

impl Command for DiffArgs {
    /// Porównanie dwóch dowolnych przebiegów (M1) — liczone na bieżąco, bez zapisu.
    /// Zmiany względem poprzedniego przebiegu zapisuje sam skan.
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let config = context.load_config(CliOverrides::default())?;
        let pool = connect_database(&config).await?;
        for run_id in [self.previous_run, self.current_run] {
            if dscan_db::get_scan_run(&pool, run_id).await?.is_none() {
                return Err(CliError::RunNotFound(run_id));
            }
        }
        let previous = dscan_db::run_fingerprints(&pool, self.previous_run).await?;
        let current = dscan_db::run_fingerprints(&pool, self.current_run).await?;
        let changes = compare_runs(
            &previous,
            &current,
            (self.previous_run, self.current_run),
            Utc::now(),
        );
        print!(
            "{}",
            format_changes(self.previous_run, self.current_run, &changes)
        );
        Ok(())
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
