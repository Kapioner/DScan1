use std::fmt::Write;

use clap::{Args, Subcommand};
use dscan_config::{AppConfig, CliOverrides};
use dscan_db::StoredTarget;
use dscan_scanner::targets::{AddressIterator, SystemResolver, TargetPlan, prepare_targets};

use super::{Command, Context, cipher_from_config, connect_database};
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct TargetsArgs {
    #[command(subcommand)]
    pub action: TargetsAction,
}

#[derive(Debug, Subcommand)]
pub enum TargetsAction {
    /// Wyświetla cele zapisane w bazie (wymaga klucza szyfrowania — notatki są szyfrowane).
    List,
    /// Sprawdza cele bez skanowania: poprawność, DNS, duplikaty, zakres [scope].
    Check {
        #[arg(required = true, value_name = "CEL")]
        targets: Vec<String>,
        /// Ile pierwszych adresów pokazać.
        #[arg(long, default_value_t = 10, value_name = "LICZBA")]
        show: usize,
    },
    /// Dodaje cele (IP, CIDR, domeny).
    Add {
        #[arg(required = true, value_name = "CEL")]
        targets: Vec<String>,
        /// Grupa, do której trafią cele.
        #[arg(long, value_name = "NAZWA")]
        group: Option<String>,
    },
    /// Usuwa cele.
    Remove {
        #[arg(required = true, value_name = "CEL")]
        targets: Vec<String>,
    },
}

impl Command for TargetsArgs {
    async fn execute(&self, context: &Context) -> Result<(), CliError> {
        let config = context.load_config(CliOverrides::default())?;
        match &self.action {
            TargetsAction::List => {
                let cipher = cipher_from_config(&config)?;
                let pool = connect_database(&config).await?;
                print!(
                    "{}",
                    format_targets_table(&dscan_db::list_targets(&pool, &cipher).await?)
                );
            }
            TargetsAction::Check { targets, show } => {
                let plan = build_plan(&config, targets).await?;
                print!("{}", format_plan(&plan));
                print!("{}", format_address_preview(&plan, *show));
            }
            TargetsAction::Add { .. } | TargetsAction::Remove { .. } => {
                return Err(CliError::NotImplemented {
                    command: "targets add/remove",
                    tasks: "A5, C5",
                });
            }
        }
        Ok(())
    }
}

/// Przygotowuje cele z uwzględnieniem DNS i zakresu z konfiguracji.
pub async fn build_plan(config: &AppConfig, inputs: &[String]) -> Result<TargetPlan, CliError> {
    let resolver = SystemResolver::from_system_config()?;
    let allowed = &config.settings.scope.allowed_networks;
    Ok(prepare_targets(inputs, &resolver, allowed).await)
}

/// Raport z przygotowania celów: co zeskanujemy, co odrzucono i dlaczego.
pub fn format_plan(plan: &TargetPlan) -> String {
    let mut text = format!(
        "Do skanowania: {} adresów w {} zakresach\n",
        plan.address_count,
        plan.networks.len()
    );
    // Zapis do String nie może się nie udać, więc wyniki writeln! są pomijane.
    for network in &plan.networks {
        let _ = writeln!(text, "  {network}");
    }
    if !plan.invalid.is_empty() {
        text.push_str("Odrzucone (niepoprawne):\n");
        for (input, reason) in &plan.invalid {
            let _ = writeln!(text, "  '{input}': {reason}");
        }
    }
    if !plan.unresolved.is_empty() {
        text.push_str("Nierozwiązane domeny:\n");
        for (domain, reason) in &plan.unresolved {
            let _ = writeln!(text, "  {domain}: {reason}");
        }
    }
    if !plan.out_of_scope.is_empty() {
        text.push_str("Poza zakresem [scope] allowed_networks (pominięte):\n");
        for network in &plan.out_of_scope {
            let _ = writeln!(text, "  {network}");
        }
    }
    text
}

/// Pierwsze `limit` adresów z planu (wyliczane leniwie, bez rozwijania całego zakresu).
pub fn format_address_preview(plan: &TargetPlan, limit: usize) -> String {
    if limit == 0 || plan.networks.is_empty() {
        return String::new();
    }
    let addresses: Vec<String> = AddressIterator::new(plan.networks.clone())
        .take(limit)
        .map(|address| address.to_string())
        .collect();
    let more = if plan.address_count > limit as u128 {
        ", …"
    } else {
        ""
    };
    format!("Pierwsze adresy: {}{more}\n", addresses.join(", "))
}

/// Tabela celów z bazy.
pub fn format_targets_table(targets: &[StoredTarget]) -> String {
    if targets.is_empty() {
        return "Brak celów. Zaimportuj je: dscan import cele.csv\n".into();
    }
    let mut text = format!(
        "{:<5} {:<7} {:<40} {:<12} {}\n",
        "ID", "RODZAJ", "CEL", "GRUPA", "NOTATKA"
    );
    for target in targets {
        // Zapis do String nie może się nie udać.
        let _ = writeln!(
            text,
            "{:<5} {:<7} {:<40} {:<12} {}",
            target.id,
            target.kind,
            target.value,
            target.group.as_deref().unwrap_or("-"),
            target.note.as_deref().unwrap_or("")
        );
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> TargetPlan {
        TargetPlan {
            networks: vec!["10.0.0.0/30".parse().unwrap()],
            address_count: 4,
            invalid: vec![("zły".into(), "niepoprawny cel".into())],
            unresolved: vec![("x.lab".into(), "NXDOMAIN".into())],
            out_of_scope: vec!["8.8.8.8/32".parse().unwrap()],
        }
    }

    #[test]
    fn plan_report_lists_every_section() {
        let report = format_plan(&plan());
        assert!(report.contains("Do skanowania: 4 adresów w 1 zakresach"));
        assert!(report.contains("'zły': niepoprawny cel"));
        assert!(report.contains("x.lab: NXDOMAIN"));
        assert!(report.contains("8.8.8.8/32"));
    }

    #[test]
    fn preview_is_limited() {
        assert_eq!(
            format_address_preview(&plan(), 2),
            "Pierwsze adresy: 10.0.0.0, 10.0.0.1, …\n"
        );
        assert_eq!(
            format_address_preview(&plan(), 10),
            "Pierwsze adresy: 10.0.0.0, 10.0.0.1, 10.0.0.2, 10.0.0.3\n"
        );
        assert_eq!(format_address_preview(&plan(), 0), "");
    }

    #[test]
    fn empty_targets_table_suggests_import() {
        assert!(format_targets_table(&[]).contains("dscan import"));
    }
}
