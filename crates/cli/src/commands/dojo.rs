//! `dscan dojo` (I4, I5): wysyłka do DefectDojo przez serwer API.

use clap::{Args, Subcommand};
use serde::Deserialize;
use serde_json::json;

use super::{Command, Context};
use crate::client::ApiClient;
use crate::error::CliError;

#[derive(Debug, Args)]
pub struct DojoArgs {
    #[command(subcommand)]
    pub action: DojoAction,
}

#[derive(Debug, Subcommand)]
pub enum DojoAction {
    /// Wysyła surowe wyniki nmap przebiegu (parser „Nmap Scan”).
    Import {
        #[arg(value_name = "PRZEBIEG")]
        run_id: i64,
    },
    /// Wysyła wybrane obserwacje jako findingi informacyjne z dowodami.
    Export {
        #[arg(value_name = "PRZEBIEG")]
        run_id: i64,
        /// Obserwacja `IP:PORT/PROTOKÓŁ=Technologia`, np. `10.0.0.5:8080/tcp=Jenkins` (można powtórzyć).
        #[arg(long = "item", value_name = "OBSERWACJA", required = true)]
        items: Vec<String>,
    },
}

#[derive(Debug, Deserialize)]
struct DojoResponse {
    test_id: Option<i64>,
    items: usize,
}

/// `10.0.0.5:8080/tcp=Jenkins` → obiekt JSON obserwacji.
pub fn parse_item(text: &str) -> Result<serde_json::Value, CliError> {
    let bad = || {
        CliError::Http(format!(
            "obserwacja „{text}” — oczekiwano IP:PORT/PROTOKÓŁ=Technologia"
        ))
    };
    let (address, technology) = text.split_once('=').ok_or_else(bad)?;
    let (host_port, protocol) = address.split_once('/').unwrap_or((address, "tcp"));
    let (ip, port) = host_port.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    Ok(
        json!({ "ip": ip.trim_matches(['[', ']']), "port": port, "protocol": protocol, "technology": technology }),
    )
}

impl Command for DojoArgs {
    async fn execute(&self, _context: &Context) -> Result<(), CliError> {
        let client = ApiClient::from_saved()?;
        let response: DojoResponse = match &self.action {
            DojoAction::Import { run_id } => {
                client
                    .post("/api/v1/defectdojo/import", &json!({ "run_id": run_id }))
                    .await?
            }
            DojoAction::Export { run_id, items } => {
                let items = items
                    .iter()
                    .map(|item| parse_item(item))
                    .collect::<Result<Vec<_>, _>>()?;
                client
                    .post(
                        "/api/v1/defectdojo/findings",
                        &json!({ "run_id": run_id, "items": items }),
                    )
                    .await?
            }
        };
        println!(
            "Wysłano do DefectDojo ({} pozycji), test: {:?}",
            response.items, response.test_id
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_are_parsed() {
        let item = parse_item("10.0.0.5:8080/tcp=Jenkins").unwrap();
        assert_eq!(item["port"], 8080);
        assert_eq!(item["technology"], "Jenkins");
        assert_eq!(parse_item("[::1]:443=nginx").unwrap()["ip"], "::1");
        assert!(parse_item("10.0.0.5=Jenkins").is_err());
    }
}
