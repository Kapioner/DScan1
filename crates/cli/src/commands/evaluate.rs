//! `dscan evaluate REFERENCJA` (Q1): trafność wykrywania hostów i usług względem wyników
//! referencyjnych (nmap XML, JSON lub CSV — te same formaty co import wyników).
//! Domyślnie ocenia dwa ostatnie zakończone przebiegi; wyniki pobiera przez API.

use std::fmt::Write;
use std::path::PathBuf;

use clap::Args;
use dscan_core::models::Host;
use dscan_integrations::{Evaluation, Score, detect_result_format, evaluate, parse_results};

use super::{Command, Context};
use crate::client::ApiClient;
use crate::client::types::ScanRunView;
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct EvaluateArgs {
    /// Plik z wynikami referencyjnymi (.xml z nmap, .json, .csv).
    #[arg(value_name = "PLIK")]
    pub reference: PathBuf,
    /// Przebiegi do oceny (można powtórzyć); domyślnie dwa ostatnie zakończone.
    #[arg(long = "run", value_name = "PRZEBIEG")]
    pub runs: Vec<i64>,
    /// Pokaż listy pominiętych i nadmiarowych hostów i usług.
    #[arg(long)]
    pub details: bool,
}

impl Command for EvaluateArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        let content =
            std::fs::read_to_string(&self.reference).map_err(|source| CliError::File {
                path: self.reference.clone(),
                source,
            })?;
        let reference = parse_results(&content, detect_result_format(&self.reference)?)?.hosts;
        let client = ApiClient::from_saved()?;
        let runs = if self.runs.is_empty() {
            let all: Vec<ScanRunView> = client.get("/api/v1/scans?limit=100").await?;
            all.iter()
                .filter(|r| r.status == "completed")
                .take(2)
                .map(|r| r.id)
                .collect()
        } else {
            self.runs.clone()
        };
        if runs.is_empty() {
            return Err(CliError::Http(
                "brak zakończonych przebiegów do oceny".into(),
            ));
        }
        println!(
            "Referencja: {} hostów, {} otwartych usług",
            reference.len(),
            open_count(&reference)
        );
        for run in runs {
            let hosts: Vec<Host> = client.get(&format!("/api/v1/scans/{run}/hosts")).await?;
            print!(
                "{}",
                format_evaluation(run, &evaluate(&hosts, &reference), self.details)
            );
        }
        Ok(())
    }
}

fn open_count(hosts: &[Host]) -> usize {
    hosts.iter().map(Host::open_port_count).sum()
}

fn score_line(label: &str, score: &Score) -> String {
    format!(
        "  {label:<8} TP {:>4}  FP {:>4}  FN {:>4}  precyzja {:>5.1}%  czułość {:>5.1}%  F1 {:>5.1}%\n",
        score.true_positives,
        score.false_positives.len(),
        score.false_negatives.len(),
        score.precision() * 100.0,
        score.recall() * 100.0,
        score.f1() * 100.0
    )
}

fn percent((matched, total): (usize, usize)) -> String {
    if total == 0 {
        "—".into()
    } else {
        format!(
            "{matched}/{total} ({:.1}%)",
            matched as f64 * 100.0 / total as f64
        )
    }
}

pub fn format_evaluation(run: i64, evaluation: &Evaluation, details: bool) -> String {
    let mut text = format!("Przebieg #{run}\n");
    text.push_str(&score_line("hosty", &evaluation.hosts));
    text.push_str(&score_line("usługi", &evaluation.services));
    // Zapis do String nie może się nie udać.
    let _ = writeln!(
        text,
        "  zgodne nazwy usług: {}, zgodne produkty: {}",
        percent(evaluation.service_names),
        percent(evaluation.products)
    );
    if details {
        for (label, list) in [
            ("niewykryte hosty", &evaluation.hosts.false_negatives),
            ("nadmiarowe hosty", &evaluation.hosts.false_positives),
            ("niewykryte usługi", &evaluation.services.false_negatives),
            ("nadmiarowe usługi", &evaluation.services.false_positives),
        ] {
            if !list.is_empty() {
                let _ = writeln!(text, "  {label}: {}", list.join(", "));
            }
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_shows_metrics() {
        let mut evaluation = Evaluation::default();
        evaluation.hosts.true_positives = 3;
        evaluation.hosts.false_negatives = vec!["10.0.0.9".into()];
        evaluation.products = (1, 2);
        let text = format_evaluation(7, &evaluation, true);
        assert!(text.contains("Przebieg #7"));
        assert!(text.contains("czułość  75.0%"), "{text}");
        assert!(text.contains("zgodne produkty: 1/2 (50.0%)"));
        assert!(text.contains("niewykryte hosty: 10.0.0.9"));
    }
}
