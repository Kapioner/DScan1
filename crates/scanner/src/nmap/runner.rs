use std::path::PathBuf;
use std::process::Stdio;

use chrono::Utc;
use dscan_core::models::Host;
use ipnet::IpNet;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::{NmapOptions, build_nmap_args, parse_nmap_xml, to_hosts};
use crate::ScannerError;

/// Wynik skanu: hosty w modelu domeny i surowy XML (np. do DefectDojo).
#[derive(Debug, Clone)]
pub struct ScanOutput {
    pub hosts: Vec<Host>,
    pub raw_xml: String,
}

/// Program nmap do uruchomienia (domyślnie `nmap` z PATH).
#[derive(Debug, Clone)]
pub struct NmapCommand {
    binary: PathBuf,
}

impl Default for NmapCommand {
    fn default() -> Self {
        NmapCommand {
            binary: PathBuf::from("nmap"),
        }
    }
}

impl NmapCommand {
    pub fn new(binary: impl Into<PathBuf>) -> Self {
        NmapCommand {
            binary: binary.into(),
        }
    }

    /// Uruchamia nmap z argumentami, podaje cele przez stdin i zwraca XML ze stdout.
    pub async fn run(&self, args: &[String], targets: &[IpNet]) -> Result<String, ScannerError> {
        let mut child = Command::new(&self.binary)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Przerwanie skanu (np. Ctrl+C) zabija też proces nmap.
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ScannerError::NmapNotFound,
                _ => ScannerError::Io(error),
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(targets_as_lines(targets).as_bytes())
                .await?;
            // Zamknięcie stdin (drop) sygnalizuje nmapowi koniec listy celów.
        }

        let output = child.wait_with_output().await?;
        if !output.status.success() {
            return Err(ScannerError::NmapFailed {
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        String::from_utf8(output.stdout)
            .map_err(|error| ScannerError::InvalidNmapOutput(error.to_string()))
    }
}

/// Uruchamia skan i zamienia wynik na model domeny.
pub async fn run_scan(
    command: &NmapCommand,
    options: &NmapOptions,
    targets: &[IpNet],
) -> Result<ScanOutput, ScannerError> {
    let raw_xml = command.run(&build_nmap_args(options), targets).await?;
    let hosts = to_hosts(&parse_nmap_xml(&raw_xml)?, Utc::now());
    Ok(ScanOutput { hosts, raw_xml })
}

/// Cele w formacie listy dla `nmap -iL`: jeden zakres w linii.
/// Pojedyncze adresy bez `/32`, żeby wynik był czytelniejszy.
fn targets_as_lines(targets: &[IpNet]) -> String {
    targets
        .iter()
        .map(|net| {
            if net.prefix_len() == net.max_prefix_len() {
                format!("{}\n", net.addr())
            } else {
                format!("{net}\n")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_are_one_per_line() {
        let targets: Vec<IpNet> = vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.1.5/32".parse().unwrap(),
        ];
        assert_eq!(targets_as_lines(&targets), "10.0.0.0/24\n10.0.1.5\n");
    }

    #[tokio::test]
    async fn missing_binary_is_reported() {
        let command = NmapCommand::new("/nie/ma/takiego/nmap");
        let result = command.run(&[], &[]).await;
        assert!(matches!(result, Err(ScannerError::NmapNotFound)));
    }
}
